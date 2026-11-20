//! Actual Plan/owner/lane probes; worker_threads(1/2) are only test fixtures.
use super::*;
use crate::http_processing::{
    body::Entity,
    body_budget::{Budget, BudgetedBytes},
};
use std::{
    future::Future,
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::{Builder, Runtime},
};
use tokio_util::sync::CancellationToken;

const N: usize = 65536;
const CLEANUP: Duration = Duration::from_secs(5);
#[derive(Clone, Copy, Debug)]
struct Seen {
    error: Option<io::ErrorKind>,
    length: usize,
    correct: bool,
}
struct Release(mpsc::SyncSender<()>);
impl Release {
    fn now(&self) {
        let _ = self.0.try_send(());
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.now();
    }
}
struct Probe {
    task: tokio::task::JoinHandle<()>,
    entered: mpsc::Receiver<Instant>,
    waiting: mpsc::Receiver<()>,
    release: Release,
    cancel: CancellationToken,
    seen: Arc<Mutex<Option<Seen>>>,
    budget: Budget,
    last: Option<bytes::Bytes>,
    cost: usize,
}
fn runtime(workers: usize) -> Runtime {
    let runtime = Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(
        runtime.handle().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    );
    assert_eq!(runtime.handle().metrics().num_workers(), workers);
    runtime
}
impl Probe {
    fn spawn(runtime: &Runtime, panic_after_release: bool) -> Self {
        let budget = Budget::default();
        let source = Entity::identity(BudgetedBytes::copy(&budget, &vec![b'a'; N]).unwrap());
        let last = Some(source.wire().slice(0..1));
        let mut output = BudgetedBytes::new_fixed_output(&budget, N).unwrap();
        let cost = BudgetedBytes::allocation_cost(N).unwrap();
        assert_eq!(budget.used(), 2 * cost);
        let (entered_tx, entered) = mpsc::channel();
        let (waiting_tx, waiting) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let seen = Arc::new(Mutex::new(None));
        let observed = seen.clone();
        let workers = runtime.handle().metrics().num_workers();
        let task = runtime.spawn(async move {
            assert_eq!(tokio::runtime::Handle::current().metrics().num_workers(), workers);
            let plan = static_literal_plan::compile(
                "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b').replaceAll('b','c')}};}"
            ).unwrap();
            let acquire = InvocationLane::acquire(&token, Instant::now() + Duration::from_secs(1));
            tokio::pin!(acquire);
            let mut waiting_tx = Some(waiting_tx);
            let lane = std::future::poll_fn(|cx| {
                let result = acquire.as_mut().poll(cx);
                if result.is_pending()
                    && let Some(sender) = waiting_tx.take()
                {
                    let _ = sender.send(());
                }
                result
            })
            .await
            .unwrap();
            let deadline = lane.deadline; // Original 100ms limit, never replaced by CLEANUP.
            let _lane = lane;
            let mut entered_tx = Some(entered_tx);
            let mut hook = move |filled| {
                if filled == 256 {
                    if let Some(sender) = entered_tx.take() { let _ = sender.send(deadline); }
                    assert!(release_rx.recv_timeout(CLEANUP).is_ok(), "cleanup watchdog released no gate");
                    assert!(!panic_after_release, "fixed actual Plan unwind");
                }
            };
            let attempt = run_plan_inline(|| {
                plan.try_execute_for_validation(
                    &serde_json::json!({"body":{"kind":"text"}}),
                    source.borrowed_body(), &mut output, &token, deadline,
                    static_literal_plan::Validation { force_dag: false, after_chunk: Some(&mut hook) },
                ).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
            }).unwrap();
            let expected = serde_json::json!({"type":"modify","body":{"kind":"text"}});
            let correct = attempt.result.as_ref().is_ok_and(|value| value == &expected)
                && output.as_ref().len() == N && output.as_ref().iter().all(|byte| *byte == b'c');
            *observed.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Seen {
                error: attempt.result.as_ref().err().map(io::Error::kind),
                length: output.as_ref().len(), correct,
            });
            // Source/output/Workspace and the actual permit end with this poll.
        });
        Self {
            task,
            entered,
            waiting,
            release: Release(release_tx),
            cancel,
            seen,
            budget,
            last,
            cost,
        }
    }
    fn seen(&self) -> Option<Seen> {
        *self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn held(&self) -> bool {
        !self.task.is_finished() && self.seen().is_none()
            && self.budget.used() > 2 * self.cost // Actual Plan Workspace is still owned.
            && EXECUTION_LANE.try_acquire().is_err()
    }
    fn refunded(&mut self) {
        assert!(self.task.is_finished());
        assert_eq!(
            self.budget.used(),
            self.cost,
            "actual last source slice retains its charge"
        );
        assert_eq!(self.last.as_ref().unwrap().as_ref(), b"a");
        drop(self.last.take());
        assert_eq!(self.budget.used(), 0);
    }
}

fn check_plan_progress(workers: usize) {
    let runtime = runtime(workers);
    let (mut reader, mut writer) = tokio::io::duplex(1);
    let (io_tx, io_rx) = mpsc::channel();
    let (start_tx, start_rx) = tokio::sync::oneshot::channel();
    let read = runtime.spawn(async move {
        let mut value = [0; 4];
        reader.read_exact(&mut value).await.unwrap();
        let _ = io_tx.send(value);
    });
    let write = runtime.spawn(async move {
        start_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        writer.write_all(b"flow").await.unwrap();
    });
    let mut first = Probe::spawn(&runtime, false);
    let deadline = first.entered.recv_timeout(CLEANUP).unwrap();
    let mut second = Probe::spawn(&runtime, false);
    // This gate is ready only after the second real task acquires the same lane.
    second.release.now();
    let waiting = second.waiting.recv_timeout(CLEANUP).is_ok();
    let _ = start_tx.send(());
    let progress = io_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let lane_and_owners = first.held();
    let second_blocked = second.entered.try_recv().is_err()
        && second.seen().is_none()
        && second.budget.used() == 2 * second.cost;
    first.release.now(); // Always release before assertions or runtime joins.
    let (a, b, r, w) = runtime.block_on(async {
        (
            (&mut first.task).await,
            (&mut second.task).await,
            read.await,
            write.await,
        )
    });
    drop(runtime); // Normal drop joins workers, not shutdown_timeout/background.
    assert!(waiting && lane_and_owners && second_blocked);
    assert_eq!(progress.unwrap(), *b"flow");
    assert!(a.is_ok() && b.is_ok() && r.is_ok() && w.is_ok());
    assert!(first.seen().unwrap().correct && second.seen().unwrap().correct);
    first.refunded();
    second.refunded();
}

#[test]
fn multi_worker_plan_keeps_same_lane_and_allows_real_timer_and_duplex_progress() {
    check_plan_progress(2);
}

#[test]
fn single_worker_plan_bip_keeps_same_lane_and_allows_real_timer_and_duplex_progress() {
    check_plan_progress(1);
}

#[test]
fn multi_worker_plan_abort_cancel_and_panic_keep_real_owners_until_completion() {
    for (abort, cancel, panic) in [
        (true, false, false),
        (true, true, false),
        (false, false, true),
    ] {
        let runtime = runtime(2);
        let mut probe = Probe::spawn(&runtime, panic);
        let entered = probe.entered.recv_timeout(CLEANUP).is_ok();
        if abort {
            probe.task.abort();
        }
        if cancel {
            probe.cancel.cancel();
        }
        let held = entered && probe.held();
        probe.release.now();
        let result = runtime.block_on(&mut probe.task);
        drop(runtime);
        assert!(held);
        if panic {
            assert!(result.as_ref().is_err_and(tokio::task::JoinError::is_panic));
            assert!(probe.seen().is_none());
        } else {
            assert!(
                result.is_ok()
                    || result
                        .as_ref()
                        .is_err_and(tokio::task::JoinError::is_cancelled)
            );
            let actual = probe.seen().unwrap();
            if cancel {
                assert_eq!(actual.error, Some(io::ErrorKind::Interrupted));
                assert_eq!(
                    actual.length, 0,
                    "partial scratch is not a committed result"
                );
            } else {
                assert!(actual.correct);
            }
        }
        probe.refunded();
    }
}

#[test]
fn multi_worker_plan_runtime_drop_is_a_real_owner_and_lane_barrier() {
    let runtime = runtime(2);
    let mut probe = Probe::spawn(&runtime, false);
    let entered = probe.entered.recv_timeout(CLEANUP).is_ok();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (started, returned_early, held, joined) = std::thread::scope(|scope| {
        let dropper = scope.spawn(move || {
            // About-to-drop signal, not proof the destructor was scheduled yet.
            let _ = started_tx.send(());
            drop(runtime);
            let _ = done_tx.send(());
        });
        let started = started_rx.recv_timeout(CLEANUP).is_ok();
        let early = done_rx.recv_timeout(Duration::from_millis(2)).is_ok();
        let held = probe.held();
        probe.release.now();
        (started, early, held, dropper.join().is_ok())
    });
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let result = match std::pin::Pin::new(&mut probe.task).poll(&mut context) {
        std::task::Poll::Ready(result) => Some(result),
        std::task::Poll::Pending => None,
    };
    assert!(entered && started && !returned_early && held && joined);
    assert!(
        result.is_some(),
        "normal Runtime drop must finish the actual task"
    );
    let result = result.unwrap();
    assert!(
        result.is_ok()
            || result
                .as_ref()
                .is_err_and(tokio::task::JoinError::is_cancelled)
    );
    assert!(probe.seen().unwrap().correct);
    probe.refunded();
}
