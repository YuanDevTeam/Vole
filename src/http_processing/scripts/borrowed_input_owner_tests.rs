//! Actual fresh-JSC/scoped-thread/TLS teardown test; never a detached worker.
use super::*;
use crate::http_processing::{
    body::BudgetedBytes,
    body_budget::{BridgePlan, Budget, MAX_BODY, WORKSPACE},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct TlsGate {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    exited: Arc<AtomicBool>,
    released_normally: Arc<AtomicBool>,
}
impl Drop for TlsGate {
    fn drop(&mut self) {
        let _ = self.entered.send(());
        self.released_normally.store(
            self.release.recv_timeout(Duration::from_secs(5)).is_ok(),
            Ordering::Release,
        );
        self.exited.store(true, Ordering::Release);
    }
}
thread_local! {
    static TLS_GATE: std::cell::RefCell<Option<TlsGate>> = const { std::cell::RefCell::new(None) };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn borrowed_input_cancel_keeps_source_and_bridge_until_real_tls_join() {
    let code = validate_source("function rewrite(input){while(true){}}").unwrap();
    let budget = Budget::default();
    let original = BudgetedBytes::copy(&budget, &vec![b'a'; 4096])
        .unwrap()
        .into_bytes();
    let last_slice = original.slice(0..1);
    let original_cost = budget.used();
    let mut output = BudgetedBytes::new(&budget, MAX_BODY).unwrap();
    let bridge_cost = BridgePlan::new(original.len(), true, MAX_BODY)
        .unwrap()
        .cost()
        .unwrap();
    let bridge = budget.reserve(bridge_cost).unwrap();
    let pressure = budget.reserve(WORKSPACE - budget.used()).unwrap();
    let cancellation = CancellationToken::new();
    let exited = Arc::new(AtomicBool::new(false));
    let released_normally = Arc::new(AtomicBool::new(false));
    let returned = Arc::new(AtomicBool::new(false));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    // The controller always releases the TLS gate before any assertions.
    // A watchdog failure is reported only after the real worker has joined.
    let (result, proof) = tokio::task::block_in_place(|| {
        std::thread::scope(|scope| {
            let observed_budget = budget.clone();
            let observed_returned = returned.clone();
            let observed_exited = exited.clone();
            let controller = scope.spawn(move || {
                let entered = entered_rx.recv_timeout(Duration::from_secs(5)).is_ok();
                let still_full = observed_budget.reserve(1).is_none();
                let prematurely_returned = observed_returned.load(Ordering::Acquire);
                let prematurely_exited = observed_exited.load(Ordering::Acquire);
                let released = release_tx.send(()).is_ok();
                (
                    entered,
                    still_full,
                    prematurely_returned,
                    prematurely_exited,
                    released,
                )
            });
            let source = original.as_ref();
            let token = cancellation.clone();
            let exited = exited.clone();
            let released_normally = released_normally.clone();
            let result = run_on_scoped_thread(|| {
                TLS_GATE.with(|slot| {
                    *slot.borrow_mut() = Some(TlsGate {
                        entered: entered_tx,
                        release: release_rx,
                        exited,
                        released_normally,
                    });
                });
                let cancel_at_tick = token.clone();
                // No assertion or panic crosses the extern-C tick callback.
                apple::on_first_tick_for_test(move || cancel_at_tick.cancel());
                apple::evaluate(
                    &code,
                    &serde_json::json!({"phase":"request","body":{"kind":"text"}}),
                    Some(source),
                    &mut output,
                    Some(&bridge),
                    &token,
                    Instant::now() + Duration::from_millis(100),
                )
            });
            returned.store(true, Ordering::Release);
            let proof = controller
                .join()
                .expect("controller panicked after gate release");
            (result, proof)
        })
    });
    assert_eq!(proof, (true, true, false, false, true));
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
    assert!(exited.load(Ordering::Acquire));
    assert!(released_normally.load(Ordering::Acquire));
    assert!(output.as_ref().is_empty());
    assert_eq!(budget.used(), WORKSPACE);
    drop(pressure);
    drop(bridge);
    drop(output);
    assert_eq!(budget.used(), original_cost);
    drop(original);
    assert_eq!(budget.used(), original_cost);
    assert_eq!(last_slice.as_ref(), b"a");
    drop(last_slice);
    assert_eq!(budget.used(), 0);
}
