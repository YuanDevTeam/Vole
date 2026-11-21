//! Static finite-language preparation and a platform-owned execution adapter.
use std::{io, sync::Arc};

#[cfg(all(feature = "inbound-http", feature = "ffi", target_os = "android"))]
mod android_engine;
#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
mod apple;
#[cfg(feature = "inbound-http")]
mod frontend;
#[cfg(all(feature = "inbound-http", any(target_vendor = "apple", test)))]
mod platform_init;
#[cfg(all(feature = "http-js-quickjs", any(target_os = "linux", windows)))]
mod quickjs_engine;
#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
mod scoped_qos;
#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
mod tests;

#[cfg(all(
    feature = "inbound-http",
    feature = "http-diagnostics",
    target_os = "tvos"
))]
pub(crate) mod plan_validation;
#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
mod static_literal_plan;

#[cfg(feature = "inbound-http")]
static EXECUTION_LANE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

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
        not(any(
            all(feature = "inbound-http", target_vendor = "apple"),
            all(feature = "inbound-http", feature = "ffi", target_os = "android"),
            all(feature = "http-js-quickjs", any(target_os = "linux", windows))
        )),
        allow(dead_code)
    )]
    pub(crate) code: Arc<str>,
    #[cfg_attr(not(feature = "inbound-http"), allow(dead_code))]
    pub(crate) output_bound: OutputBound,
    #[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
    plan: Option<Arc<static_literal_plan::Plan>>,
}

impl CompiledSource {
    /// Only a complete proof for this actual business declaration can remove
    /// eager JSC preparation. Source acceptance and platform availability are
    /// separate; unknown source, body modes and metadata keep the JSC path.
    #[cfg(any(test, not(all(feature = "ffi", target_os = "android"))))]
    pub(crate) fn needs_jsc_for_business(
        &self,
        body: super::script_config::BodyMode,
        phase: super::rules::Phase,
    ) -> bool {
        #[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
        {
            body != super::script_config::BodyMode::Text
                || !self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| plan.covers_business_text_phase(phase))
        }
        #[cfg(not(all(feature = "inbound-http", target_vendor = "apple")))]
        {
            let _ = (self, body, phase);
            true
        }
    }
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
        let prepared = frontend::compile_prepared(source)?;
        Ok(CompiledSource {
            code: prepared.code.into(),
            output_bound: prepared.output_bound,
            #[cfg(target_vendor = "apple")]
            plan: prepared.plan.map(Arc::new),
        })
    }
    #[cfg(not(feature = "inbound-http"))]
    {
        let _ = source;
        Err(unsupported())
    }
}

#[cfg(feature = "inbound-http")]
#[derive(Clone, Copy)]
pub(crate) enum Backend<'a> {
    Engine(&'a CompiledSource),
    #[cfg(target_vendor = "apple")]
    Plan(&'a static_literal_plan::Plan),
}
#[cfg(feature = "inbound-http")]
impl CompiledSource {
    pub(crate) fn backend(
        &self,
        metadata: &serde_json::Value,
        input: Option<super::body::BorrowedBody<'_>>,
    ) -> Backend<'_> {
        #[cfg(target_vendor = "apple")]
        if let Some(plan) = &self.plan {
            if plan.accepts_input(metadata, input) {
                super::diagnostics::increment(super::diagnostics::Counter::PlanSelected);
                return Backend::Plan(plan);
            }
            super::diagnostics::increment(super::diagnostics::Counter::PlanInputFallback);
        } else {
            super::diagnostics::increment(super::diagnostics::Counter::PlanAstFallback);
        }
        #[cfg(not(target_vendor = "apple"))]
        let _ = (metadata, input);
        #[cfg(target_vendor = "apple")]
        super::diagnostics::increment(super::diagnostics::Counter::JscSelected);
        Backend::Engine(self)
    }
}
#[cfg(feature = "inbound-http")]
impl Backend<'_> {
    pub(crate) fn is_plan(self) -> bool {
        match self {
            Self::Engine(_) => false,
            #[cfg(target_vendor = "apple")]
            Self::Plan(_) => true,
        }
    }
    pub(crate) fn output_bound(self, input: usize) -> usize {
        match self {
            Self::Engine(program) => program.maximum_output_bytes(input),
            #[cfg(target_vendor = "apple")]
            Self::Plan(plan) => plan
                .maximum_output_bytes(input)
                .unwrap_or(super::body_budget::MAX_BODY),
        }
    }
}
#[cfg(feature = "inbound-http")]
#[derive(Clone, Copy)]
enum InvocationInput<'a> {
    #[cfg(all(test, target_vendor = "apple"))]
    EngineOnly(Option<&'a [u8]>),
    Borrowed(Option<super::body::BorrowedBody<'a>>),
}
#[cfg(feature = "inbound-http")]
impl<'a> InvocationInput<'a> {
    fn bytes(self) -> Option<&'a [u8]> {
        match self {
            #[cfg(all(test, target_vendor = "apple"))]
            Self::EngineOnly(bytes) => bytes,
            Self::Borrowed(body) => body.map(|body| body.as_bytes()),
        }
    }
    #[cfg(target_vendor = "apple")]
    fn witness(self) -> Option<super::body::BorrowedBody<'a>> {
        match self {
            #[cfg(test)]
            Self::EngineOnly(_) => None,
            Self::Borrowed(body) => body,
        }
    }
}

#[allow(dead_code)]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTP JavaScript execution backend is unavailable",
    )
}

pub(crate) fn ensure_available() -> io::Result<()> {
    #[cfg(all(feature = "inbound-http", feature = "ffi", target_os = "android"))]
    return android_engine::ensure_available();
    #[cfg(not(all(feature = "inbound-http", feature = "ffi", target_os = "android")))]
    if cfg!(any(
        all(feature = "inbound-http", target_vendor = "apple"),
        all(
            feature = "http-js-quickjs",
            any(target_os = "linux", windows)
        )
    )) {
        Ok(())
    } else {
        Err(unsupported())
    }
}

/// Actual resource preparation only; source validation and capability checks
/// must not call this. The process retains only successful initialization state.
pub(crate) fn prepare_platform(
    cancellation: &tokio_util::sync::CancellationToken,
) -> io::Result<()> {
    ensure_available()?;
    #[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
    {
        use super::diagnostics::{Counter, increment};
        static INITIALIZATION: platform_init::Initialization = platform_init::Initialization::new();
        if cancellation.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        increment(Counter::PlatformWarmupRequested);
        #[cfg(test)]
        PLATFORM_PREPARE_REQUESTS.with(|count| count.set(count.get() + 1));
        INITIALIZATION.ensure(cancellation, || {
            // Count thread-creation errors and unwinding as failed attempts too.
            struct Attempt(bool);
            impl Drop for Attempt {
                fn drop(&mut self) {
                    if !self.0 {
                        increment(Counter::PlatformWarmupFailed);
                    }
                }
            }
            increment(Counter::PlatformWarmupStarted);
            let mut attempt = Attempt(false);
            let result =
                run_on_scoped_thread_named("vole-http-js-init", apple::initialize_platform);
            if result.is_ok() {
                increment(Counter::PlatformWarmupSucceeded);
                attempt.0 = true;
            }
            result
        })
    }
    #[cfg(not(all(feature = "inbound-http", target_vendor = "apple")))]
    {
        if cancellation.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        #[cfg(all(feature = "inbound-http", feature = "ffi", target_os = "android"))]
        android_engine::initialize_platform()?;
        if cancellation.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

#[cfg(all(feature = "inbound-http", feature = "ffi", target_os = "android"))]
pub(crate) struct AndroidSession {
    open: bool,
}

#[cfg(all(feature = "inbound-http", feature = "ffi", target_os = "android"))]
impl AndroidSession {
    pub(crate) fn open() -> io::Result<Self> {
        android_engine::initialize_platform()?;
        Ok(Self { open: true })
    }

    pub(crate) fn close(mut self) -> io::Result<()> {
        self.open = false;
        android_engine::shutdown_platform()
    }
}

#[cfg(all(feature = "inbound-http", feature = "ffi", target_os = "android"))]
impl Drop for AndroidSession {
    fn drop(&mut self) {
        if self.open {
            let _ = android_engine::shutdown_platform();
        }
    }
}

#[cfg(feature = "inbound-http")]
pub(super) fn bridge_cost(input: Option<usize>, text: bool, output: usize) -> Option<usize> {
    #[cfg(all(feature = "ffi", target_os = "android"))]
    return android_engine::bridge_cost(input.unwrap_or(0), text, output);
    #[cfg(not(all(feature = "ffi", target_os = "android")))]
    match input {
        Some(input) => super::body_budget::BridgePlan::new(input, text, output)?.cost(),
        None => Some(0),
    }
}

#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
std::thread_local! {
    // A current-thread prepare-path witness; independent of process-global
    // diagnostic counters and other tests' initialization order.
    static PLATFORM_PREPARE_REQUESTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
pub(crate) fn platform_prepare_requests_for_test() -> usize {
    PLATFORM_PREPARE_REQUESTS.with(std::cell::Cell::get)
}

#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
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

// Bypass the static plan in direct backend tests.
#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
pub(crate) async fn evaluate_until(
    program: &CompiledSource,
    metadata: &serde_json::Value,
    input_body: Option<&[u8]>,
    output_body: &mut super::body_budget::BudgetedBytes,
    bridge_workspace: Option<&super::body_budget::Reservation>,
    cancellation: &tokio_util::sync::CancellationToken,
    phase_deadline: std::time::Instant,
) -> io::Result<serde_json::Value> {
    evaluate_internal(
        Backend::Engine(program),
        metadata,
        InvocationInput::EngineOnly(input_body),
        output_body,
        bridge_workspace,
        cancellation,
        phase_deadline,
    )
    .await
}

#[cfg(feature = "inbound-http")]
pub(crate) async fn evaluate_backend_until(
    backend: Backend<'_>,
    metadata: &serde_json::Value,
    input_body: Option<super::body::BorrowedBody<'_>>,
    output_body: &mut super::body_budget::BudgetedBytes,
    bridge_workspace: Option<&super::body_budget::Reservation>,
    cancellation: &tokio_util::sync::CancellationToken,
    phase_deadline: std::time::Instant,
) -> io::Result<serde_json::Value> {
    evaluate_internal(
        backend,
        metadata,
        InvocationInput::Borrowed(input_body),
        output_body,
        bridge_workspace,
        cancellation,
        phase_deadline,
    )
    .await
}

#[cfg(feature = "inbound-http")]
pub(crate) struct InvocationLane {
    _permit: tokio::sync::SemaphorePermit<'static>,
    deadline: std::time::Instant,
}
#[cfg(feature = "inbound-http")]
impl InvocationLane {
    #[cfg(not(target_vendor = "apple"))]
    pub(super) async fn acquire_engine(
        cancellation: &tokio_util::sync::CancellationToken,
        phase_deadline: std::time::Instant,
    ) -> io::Result<Self> {
        ensure_available()?;
        Self::acquire(cancellation, phase_deadline).await
    }

    // Only cancellation and the original phase bound enter this future. No
    // mutable message/output is held by the lane acquisition helper.
    pub(crate) async fn acquire(
        cancellation: &tokio_util::sync::CancellationToken,
        phase_deadline: std::time::Instant,
    ) -> io::Result<Self> {
        // This is an execution lane, not a limit on HTTP connections. Waiting
        // inherits this invocation's deadline and never runs on a TUN callback.
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
        let permit = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(lane_error(io::ErrorKind::Interrupted, "cancel")),
            permit = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), EXECUTION_LANE.acquire()) => {
                permit.map_err(|_| lane_error(io::ErrorKind::TimedOut, "deadline"))?
                    .map_err(|_| lane_error(io::ErrorKind::BrokenPipe, "closed"))?
            }
        };
        queue.acquired();
        Ok(Self {
            _permit: permit,
            deadline,
        })
    }
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
pub(crate) fn evaluate_plan_in_lane(
    backend: Backend<'_>,
    metadata: &serde_json::Value,
    input_body: Option<super::body::BorrowedBody<'_>>,
    output_body: &mut super::body_budget::BudgetedBytes,
    cancellation: &tokio_util::sync::CancellationToken,
    lane: InvocationLane,
) -> io::Result<serde_json::Value> {
    if !backend.is_plan() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    evaluate_acquired(
        backend,
        metadata,
        InvocationInput::Borrowed(input_body),
        output_body,
        None,
        cancellation,
        lane,
    )
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
fn evaluate_acquired(
    backend: Backend<'_>,
    metadata: &serde_json::Value,
    input_body: InvocationInput<'_>,
    output_body: &mut super::body_budget::BudgetedBytes,
    bridge_workspace: Option<&super::body_budget::Reservation>,
    cancellation: &tokio_util::sync::CancellationToken,
    lane: InvocationLane,
) -> io::Result<serde_json::Value> {
    let deadline = lane.deadline;
    let _lane = lane; // Keep the exact permit through real return/unwind/join.
    let mut operation = || match backend {
        Backend::Engine(program) => {
            super::diagnostics::increment(super::diagnostics::Counter::EvaluationEntered);
            let result = apple::evaluate(
                program,
                metadata,
                input_body.bytes(),
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
        }
        Backend::Plan(plan) => {
            super::diagnostics::increment(super::diagnostics::Counter::PlanEntered);
            let result = match plan.try_execute(
                metadata,
                input_body.witness(),
                output_body,
                cancellation,
                deadline,
            ) {
                Some(attempt) => {
                    tracing::trace!(target: "vole::http_processing::script", backend = attempt.backend, ticks = attempt.ticks, allocation_work = attempt.allocation_work, "HTTP script backend completed");
                    attempt.result
                }
                // Selection was already fixed before any output admission.
                // A failed invariant is a rollback, never another backend.
                None => Err(io::ErrorKind::InvalidInput.into()),
            };
            let counter = match result.as_ref().map_err(io::Error::kind) {
                Ok(_) => super::diagnostics::Counter::PlanSucceeded,
                Err(io::ErrorKind::TimedOut) => super::diagnostics::Counter::PlanTimedOut,
                Err(io::ErrorKind::Interrupted) => super::diagnostics::Counter::PlanCancelled,
                Err(_) => super::diagnostics::Counter::PlanFailed,
            };
            super::diagnostics::increment(counter);
            result
        }
    };
    if tokio::runtime::Handle::current().runtime_flavor()
        == tokio::runtime::RuntimeFlavor::MultiThread
    {
        if backend.is_plan() {
            run_plan_inline(operation)
        } else {
            // JSC still lives only on its fresh scoped owner, with its
            // original QoS request, context/TLS teardown and actual join.
            tokio::task::block_in_place(|| run_on_script_thread(OwnerBackend::Jsc, operation))
        }
    } else {
        operation()
    }
}

#[cfg(feature = "inbound-http")]
async fn evaluate_internal(
    backend: Backend<'_>,
    metadata: &serde_json::Value,
    input_body: InvocationInput<'_>,
    output_body: &mut super::body_budget::BudgetedBytes,
    bridge_workspace: Option<&super::body_budget::Reservation>,
    cancellation: &tokio_util::sync::CancellationToken,
    phase_deadline: std::time::Instant,
) -> io::Result<serde_json::Value> {
    #[cfg(target_vendor = "apple")]
    {
        let lane = InvocationLane::acquire(cancellation, phase_deadline).await?;
        evaluate_acquired(
            backend,
            metadata,
            input_body,
            output_body,
            bridge_workspace,
            cancellation,
            lane,
        )
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let lane = InvocationLane::acquire_engine(cancellation, phase_deadline).await?;
        evaluate_engine_in_lane(
            backend,
            metadata,
            input_body.bytes(),
            output_body,
            bridge_workspace,
            cancellation,
            &lane,
        )
    }
}

#[cfg(all(feature = "inbound-http", not(target_vendor = "apple")))]
pub(super) fn evaluate_engine_in_lane(
    backend: Backend<'_>,
    metadata: &serde_json::Value,
    input: Option<&[u8]>,
    output_body: &mut super::body_budget::BudgetedBytes,
    bridge_workspace: Option<&super::body_budget::Reservation>,
    cancellation: &tokio_util::sync::CancellationToken,
    lane: &InvocationLane,
) -> io::Result<serde_json::Value> {
    let Backend::Engine(program) = backend;
    let deadline = lane.deadline;
    let mut operation = || {
        #[cfg(all(feature = "ffi", target_os = "android"))]
        let (name, evaluate) = ("android-javascriptengine", android_engine::evaluate);
        #[cfg(all(feature = "http-js-quickjs", any(target_os = "linux", windows)))]
        let (name, evaluate) = ("quickjs-ng", quickjs_engine::evaluate);
        #[cfg(not(any(
            all(feature = "ffi", target_os = "android"),
            all(feature = "http-js-quickjs", any(target_os = "linux", windows))
        )))]
        let (name, evaluate) = ("unavailable", no_engine);
        use super::diagnostics::{Counter, increment};
        increment(Counter::EvaluationEntered);
        let result = evaluate(
            program,
            metadata,
            input,
            output_body,
            bridge_workspace,
            cancellation,
            deadline,
        );
        let status = result.as_ref().map(|_| ()).map_err(io::Error::kind);
        increment(match status {
            Ok(()) => Counter::EvaluationSucceeded,
            Err(io::ErrorKind::TimedOut) => Counter::EvaluationTimedOut,
            Err(io::ErrorKind::Interrupted) => Counter::EvaluationCancelled,
            Err(_) => Counter::EvaluationFailed,
        });
        tracing::trace!(target: "vole::http_processing::script", backend = name, result = ?status, "HTTP script backend completed");
        result
    };
    // A borrowed message and the lane outlive the actual backend return.
    // A dropped HTTP future never detaches a backend execution.
    if tokio::runtime::Handle::current().runtime_flavor()
        == tokio::runtime::RuntimeFlavor::MultiThread
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

#[cfg(all(
    feature = "inbound-http",
    not(any(
        target_vendor = "apple",
        all(feature = "ffi", target_os = "android"),
        all(feature = "http-js-quickjs", any(target_os = "linux", windows))
    ))
))]
fn no_engine(
    _: &CompiledSource,
    _: &serde_json::Value,
    _: Option<&[u8]>,
    _: &mut super::body_budget::BudgetedBytes,
    _: Option<&super::body_budget::Reservation>,
    _: &tokio_util::sync::CancellationToken,
    _: std::time::Instant,
) -> io::Result<serde_json::Value> {
    Err(unsupported())
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
#[derive(Clone, Copy)]
enum OwnerBackend {
    Jsc,
    #[cfg_attr(
        not(any(test, all(feature = "http-diagnostics", target_os = "tvos"))),
        allow(dead_code)
    )]
    Plan,
}

#[cfg(all(
    feature = "inbound-http",
    target_vendor = "apple",
    any(test, all(feature = "http-diagnostics", target_os = "tvos"))
))]
fn run_on_scoped_thread<T: Send>(
    operation: impl FnOnce() -> io::Result<T> + Send,
) -> io::Result<T> {
    run_on_script_thread(OwnerBackend::Jsc, operation)
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
fn run_on_script_thread<T: Send>(
    owner: OwnerBackend,
    operation: impl FnOnce() -> io::Result<T> + Send,
) -> io::Result<T> {
    #[cfg(feature = "http-diagnostics")]
    let started = std::sync::atomic::AtomicBool::new(false);
    #[cfg(feature = "http-diagnostics")]
    struct ParentWall<'a> {
        begin: std::time::Instant,
        started: &'a std::sync::atomic::AtomicBool,
        owner: OwnerBackend,
    }
    #[cfg(feature = "http-diagnostics")]
    impl Drop for ParentWall<'_> {
        fn drop(&mut self) {
            use super::diagnostics::{Counter, Timing, increment, timing};
            let elapsed = self.begin.elapsed().as_micros();
            timing(Timing::ScopedOwner, elapsed);
            timing(
                match self.owner {
                    OwnerBackend::Jsc => Timing::JscScopedOwner,
                    OwnerBackend::Plan => Timing::PlanScopedOwner,
                },
                elapsed,
            );
            if self.started.load(std::sync::atomic::Ordering::Acquire) {
                increment(match self.owner {
                    OwnerBackend::Jsc => Counter::JscOwnerJoined,
                    OwnerBackend::Plan => Counter::PlanOwnerJoined,
                });
            }
        }
    }
    // This guard encloses named-helper return/unwind and therefore actual
    // thread/TLS join. A failed spawn never claims an owner started or joined.
    #[cfg(feature = "http-diagnostics")]
    let _parent_wall = ParentWall {
        begin: std::time::Instant::now(),
        started: &started,
        owner,
    };
    #[cfg(feature = "http-diagnostics")]
    let started = &started;
    let name = match owner {
        OwnerBackend::Jsc => "vole-http-js",
        OwnerBackend::Plan => "vole-http-plan",
    };
    run_on_scoped_thread_named(name, move || {
        #[cfg(feature = "http-diagnostics")]
        {
            started.store(true, std::sync::atomic::Ordering::Release);
            super::diagnostics::increment(match owner {
                OwnerBackend::Jsc => super::diagnostics::Counter::JscOwnerStarted,
                OwnerBackend::Plan => super::diagnostics::Counter::PlanOwnerStarted,
            });
        }
        // Same public QoS request and real scoped owner for both backends.
        scoped_qos::run(operation)
    })
}

#[cfg(all(
    feature = "inbound-http",
    feature = "http-diagnostics",
    target_vendor = "apple"
))]
pub(crate) fn scoped_owner_qos_snapshot() -> serde_json::Value {
    scoped_qos::snapshot()
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
fn run_on_scoped_thread_named<T: Send>(
    name: &str,
    operation: impl FnOnce() -> io::Result<T> + Send,
) -> io::Result<T> {
    // Keep backend state on its owner and join before releasing borrowed
    // buffers or the execution lane. Capture tracing in the blocking parent.
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let span = tracing::Span::current();
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name(name.into())
            .spawn_scoped(scope, move || {
                tracing::dispatcher::with_default(&dispatch, || span.in_scope(operation))
            })?;
        match worker.join() {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
mod borrowed_input_owner_tests;

/// Same capability check for the Message yield and synchronous Plan policy.
/// A query only: no worker/CPU/affinity override or availability guarantee.
#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
pub(crate) fn plan_can_run_direct() -> bool {
    tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            && handle.metrics().num_workers() > 1
    })
}

/// Multi-thread Plan only, on the same caller stack and held lane/borrows.
/// Multiple configured workers allow direct execution; one retains BIP.
/// No JSC object, scoped owner, QoS setter, detached Future or new deadline.
#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
fn run_plan_inline<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(feature = "http-diagnostics")]
    struct DispatchWall(std::time::Instant);
    #[cfg(feature = "http-diagnostics")]
    impl Drop for DispatchWall {
        fn drop(&mut self) {
            super::diagnostics::timing(
                super::diagnostics::Timing::PlanInlineDispatchWall,
                self.0.elapsed().as_micros(),
            );
        }
    }
    #[cfg(feature = "http-diagnostics")]
    struct Operation {
        clock: scoped_qos::OperationClock,
    }
    #[cfg(feature = "http-diagnostics")]
    impl Operation {
        fn enter() -> Self {
            super::diagnostics::increment(super::diagnostics::Counter::PlanInlineEntered);
            Self {
                clock: scoped_qos::OperationClock::start(),
            }
        }
    }
    #[cfg(feature = "http-diagnostics")]
    impl Drop for Operation {
        fn drop(&mut self) {
            use super::diagnostics::{Counter, Timing, increment, timing};
            let (wall, cpu) = self.clock.elapsed();
            timing(Timing::PlanInlineWall, wall);
            if let Some(cpu) = cpu {
                timing(Timing::PlanInlineThreadCpu, u128::from(cpu));
            } else {
                increment(Counter::PlanInlineCpuUnavailable);
            }
            increment(if std::thread::panicking() {
                Counter::PlanInlinePanicked
            } else {
                Counter::PlanInlineReturned
            });
        }
    }
    #[cfg(feature = "http-diagnostics")]
    let _dispatch = DispatchWall(std::time::Instant::now());
    let operation = || {
        #[cfg(feature = "http-diagnostics")]
        let _operation = Operation::enter();
        operation()
    };
    if plan_can_run_direct() {
        operation()
    } else {
        tokio::task::block_in_place(operation)
    }
}

#[cfg(all(test, feature = "inbound-http", target_vendor = "apple"))]
mod multi_worker_plan_tests;
