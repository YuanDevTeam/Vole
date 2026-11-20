use super::*;
use crate::dispatch::{TunPendingSend, TunSendOutcome, TunSendToken};
use std::{
    pin::Pin,
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};

struct PendingIo(Arc<AtomicBool>);
impl std::future::Future for PendingIo {
    type Output = Result<(), DispatchError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
impl Drop for PendingIo {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct CompletionProbe {
    dropped: Arc<AtomicBool>,
    pinned: Arc<AtomicBool>,
    lease: Arc<AtomicBool>,
    park_close: bool,
}
struct CloseLease(Arc<AtomicBool>);
impl Drop for CloseLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
#[async_trait::async_trait]
impl DatagramTransport for CompletionProbe {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
        unreachable!()
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        unreachable!()
    }
    async fn finish_tun_send(
        &mut self,
        _: TunSendToken,
        outcome: TunSendOutcome,
    ) -> Result<(), DispatchError> {
        assert!(
            self.dropped.load(Ordering::Acquire),
            "IO must drop before route completion"
        );
        assert!(
            self.pinned.swap(false, Ordering::AcqRel),
            "one completion pin"
        );
        let _lease = CloseLease(self.lease.clone());
        if self.park_close {
            std::future::pending::<()>().await;
        }
        outcome.into_result()
    }
}

#[tokio::test(start_paused = true)]
async fn expired_send_deadline_releases_pin_before_pending_close_is_cancelled() {
    let dropped = Arc::new(AtomicBool::new(false));
    let pinned = Arc::new(AtomicBool::new(true));
    let lease = Arc::new(AtomicBool::new(true));
    let mut transport = CompletionProbe {
        dropped: dropped.clone(),
        pinned: pinned.clone(),
        lease: lease.clone(),
        park_close: true,
    };
    let deadline = TokioInstant::now();
    let pending = PendingTunOperation {
        send: TunPendingSend::new(Box::pin(PendingIo(dropped.clone()))),
        deadline,
    };
    let result = complete_tun_send(&mut transport, pending, TunSendOutcome::TimedOut).await;
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    assert!(dropped.load(Ordering::Acquire));
    assert!(!pinned.load(Ordering::Acquire));
    assert!(!lease.load(Ordering::Acquire));
    assert!(TokioInstant::now() - deadline < Duration::from_millis(10));
}

#[tokio::test(start_paused = true)]
async fn parent_cancel_drops_io_and_bounds_pending_completion_without_failure_result() {
    let dropped = Arc::new(AtomicBool::new(false));
    let pinned = Arc::new(AtomicBool::new(true));
    let lease = Arc::new(AtomicBool::new(true));
    let mut transport = CompletionProbe {
        dropped: dropped.clone(),
        pinned: pinned.clone(),
        lease: lease.clone(),
        park_close: true,
    };
    let start = TokioInstant::now();
    let pending = PendingTunOperation {
        send: TunPendingSend::new(Box::pin(PendingIo(dropped.clone()))),
        deadline: start + OUTBOUND_SEND_TIMEOUT,
    };
    assert!(
        complete_tun_send(&mut transport, pending, TunSendOutcome::Cancelled)
            .await
            .is_ok()
    );
    assert!(dropped.load(Ordering::Acquire));
    assert!(!pinned.load(Ordering::Acquire));
    assert!(!lease.load(Ordering::Acquire));
    assert!(TokioInstant::now() - start >= UDP_CLOSE_TIMEOUT);
    assert!(TokioInstant::now() - start < UDP_CLOSE_TIMEOUT + Duration::from_millis(10));
}
