//! Static finite-language preparation and a platform-owned execution adapter.
use std::{io, sync::Arc};

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
mod apple;
#[cfg(feature = "inbound-http")]
mod frontend;
#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
mod tests;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(not(feature = "inbound-http"), allow(dead_code))]
pub(crate) enum OutputBound {
    #[default]
    Maximum,
    InputOrConstant {
        maximum_literal_bytes: usize,
    },
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CompiledSource {
    #[cfg_attr(
        not(all(feature = "inbound-http", target_vendor = "apple")),
        allow(dead_code)
    )]
    pub(crate) code: Arc<str>,
    #[cfg_attr(not(feature = "inbound-http"), allow(dead_code))]
    pub(crate) output_bound: OutputBound,
}

#[cfg(feature = "inbound-http")]
impl CompiledSource {
    // This proof bounds the Rust result; independent API/input owners remain.
    // This hint
    // never pays for API input/view copies or a retained engine backing.
    pub(crate) fn maximum_output_bytes(&self, input_bytes: usize) -> usize {
        let maximum = super::body_budget::MAX_BODY;
        match self.output_bound {
            OutputBound::Maximum => maximum,
            OutputBound::InputOrConstant {
                maximum_literal_bytes,
            } => input_bytes.max(maximum_literal_bytes).min(maximum),
        }
    }
}

pub(crate) fn validate_source(source: &str) -> io::Result<CompiledSource> {
    #[cfg(feature = "inbound-http")]
    {
        let (code, output_bound) = frontend::compile_with_output_bound(source)?;
        Ok(CompiledSource {
            code: code.into(),
            output_bound,
        })
    }
    #[cfg(not(feature = "inbound-http"))]
    {
        let _ = source;
        Err(unsupported())
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTP JavaScript execution backend is unavailable",
    )
}

pub(crate) fn ensure_available() -> io::Result<()> {
    if cfg!(all(feature = "inbound-http", target_vendor = "apple")) {
        Ok(())
    } else {
        Err(unsupported())
    }
}

#[cfg(all(test, feature = "inbound-http"))]
pub(crate) async fn evaluate(
    program: &CompiledSource,
    metadata: &serde_json::Value,
    input_body: Option<&[u8]>,
    output_body: &mut super::body_budget::BudgetedBytes,
    cancellation: &tokio_util::sync::CancellationToken,
) -> io::Result<serde_json::Value> {
    evaluate_until(
        program,
        metadata,
        input_body,
        output_body,
        None,
        cancellation,
        std::time::Instant::now() + std::time::Duration::from_millis(100),
    )
    .await
}

#[cfg(feature = "inbound-http")]
pub(crate) async fn evaluate_until(
    program: &CompiledSource,
    metadata: &serde_json::Value,
    input_body: Option<&[u8]>,
    output_body: &mut super::body_budget::BudgetedBytes,
    bridge_workspace: Option<&super::body_budget::Reservation>,
    cancellation: &tokio_util::sync::CancellationToken,
    phase_deadline: std::time::Instant,
) -> io::Result<serde_json::Value> {
    #[cfg(target_vendor = "apple")]
    {
        // This is an execution lane, not a limit on HTTP connections. Waiting
        // inherits this invocation's deadline and never runs on a TUN callback.
        static LANE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let started = std::time::Instant::now();
        let mut queue = super::diagnostics::QueueGuard::new();
        let deadline = phase_deadline.min(started + std::time::Duration::from_millis(100));
        let mut lane_error = |kind, cause| {
            queue.failed(kind);
            let elapsed_us = started.elapsed().as_micros().min(u128::from(u32::MAX));
            let remaining_us = deadline
                .saturating_duration_since(started)
                .as_micros()
                .min(u128::from(u32::MAX));
            io::Error::new(
                kind,
                format!(
                    "js f=lane-acquire c={cause} p=queue t=0 e={elapsed_us} pe={elapsed_us} o=lane-acquire k={cause} a={elapsed_us} r={remaining_us} stage_us=0,0,0,0,0,0",
                ),
            )
        };
        if std::time::Instant::now() >= deadline {
            return Err(lane_error(io::ErrorKind::TimedOut, "deadline"));
        }
        let _permit = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(lane_error(io::ErrorKind::Interrupted, "cancel")),
            permit = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), LANE.acquire()) => {
                permit.map_err(|_| lane_error(io::ErrorKind::TimedOut, "deadline"))?
                    .map_err(|_| lane_error(io::ErrorKind::BrokenPipe, "closed"))?
            }
        };
        queue.acquired();
        let mut operation = || {
            super::diagnostics::increment(super::diagnostics::Counter::EvaluationEntered);
            let result = apple::evaluate(
                program,
                metadata,
                input_body,
                output_body,
                bridge_workspace,
                cancellation,
                deadline,
            );
            let counter = match result.as_ref().map_err(io::Error::kind) {
                Ok(_) => super::diagnostics::Counter::EvaluationSucceeded,
                Err(io::ErrorKind::TimedOut) => super::diagnostics::Counter::EvaluationTimedOut,
                Err(io::ErrorKind::Interrupted) => super::diagnostics::Counter::EvaluationCancelled,
                Err(_) => super::diagnostics::Counter::EvaluationFailed,
            };
            super::diagnostics::increment(counter);
            result
        };
        if tokio::runtime::Handle::current().runtime_flavor()
            == tokio::runtime::RuntimeFlavor::MultiThread
        {
            tokio::task::block_in_place(|| run_on_scoped_thread(operation))
        } else {
            operation()
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let _ = (
            program,
            metadata,
            input_body,
            output_body,
            bridge_workspace,
            cancellation,
            phase_deadline,
        );
        Err(unsupported())
    }
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
fn run_on_scoped_thread<T: Send>(
    operation: impl FnOnce() -> io::Result<T> + Send,
) -> io::Result<T> {
    // Keep JSC pointers on their owner and join before releasing borrowed
    // buffers or the execution lane. Capture tracing in the blocking parent.
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let span = tracing::Span::current();
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("vole-http-js".into())
            .spawn_scoped(scope, move || {
                tracing::dispatcher::with_default(&dispatch, || span.in_scope(operation))
            })?;
        match worker.join() {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}
