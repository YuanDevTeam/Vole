use super::pin_tun_send_generation;
use crate::dispatch::{TunPendingSend, TunSendToken};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Lease(Arc<AtomicUsize>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn assert_same(actual: &TunSendToken, expected: &TunSendToken) {
    assert!(
        actual.same(expected),
        "lease wrapper changed completion identity"
    );
}

#[tokio::test]
async fn tun_owned_operation_keeps_generation_lease_through_completion() {
    let drops = Arc::new(AtomicUsize::new(0));
    let lease = Arc::new(Lease(drops.clone()));
    let weak = Arc::downgrade(&lease);
    let original = TunPendingSend::new(Box::pin(async { Ok(()) }));
    let token = original.completion.clone();
    let pending = pin_tun_send_generation(original, lease.clone());
    assert_same(&pending.completion, &token);
    drop(lease);
    assert!(weak.upgrade().is_some());
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    pending.operation.await.unwrap();
    assert!(weak.upgrade().is_none());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn tun_owned_cancel_drops_generation_lease_without_poll_or_task() {
    let drops = Arc::new(AtomicUsize::new(0));
    let lease = Arc::new(Lease(drops.clone()));
    let weak = Arc::downgrade(&lease);
    let original = TunPendingSend::new(Box::pin(std::future::pending()));
    let token = original.completion.clone();
    let pending = pin_tun_send_generation(original, lease.clone());
    assert_same(&pending.completion, &token);
    drop(lease);
    assert!(weak.upgrade().is_some());
    drop(pending.operation);
    assert!(weak.upgrade().is_none());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
