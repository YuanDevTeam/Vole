use super::*;
use bytes::Bytes;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct PhysicalBoundary {
    calls: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl DatagramTransport for PhysicalBoundary {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1400, 1400)
    }
    fn send_batch_owned(
        &mut self,
        packets: Vec<Datagram>,
    ) -> Result<super::super::OwnedDatagramBatchSend, Vec<Datagram>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Box::pin(async move { Ok(packets.len()) }))
    }
    async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
        panic!("batch boundary only")
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        panic!("batch boundary only")
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
fn packets(length: usize) -> Vec<Datagram> {
    (0..2)
        .map(|_| Datagram {
            remote: "192.0.2.1:443"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            payload: Bytes::from(vec![7; length]),
            sniffed_domain: None,
        })
        .collect()
}

#[tokio::test]
async fn macos_quic_batch_memory_nested_bounds_enforce_peer_budget_and_close_before_forwarding() {
    let calls = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let inner = bounded(
        Box::new(PhysicalBoundary {
            calls: calls.clone(),
            closes: closes.clone(),
        }),
        DatagramBudget::new(1350, 1350),
    );
    let mut path = bounded(inner, DatagramBudget::new(1250, 1300));
    let oversized = path.send_batch_owned(packets(1251)).is_err();
    let mut wrong_peer = packets(1200);
    wrong_peer[1].remote = "192.0.2.2:443"
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into();
    let mismatched = path.send_batch_owned(wrong_peer).is_err();
    let rejected_calls = calls.load(Ordering::Relaxed);
    let accepted = path.send_batch_owned(packets(1200)).ok();
    let count = match accepted {
        Some(operation) => operation.await,
        None => Err(io::ErrorKind::Unsupported.into()),
    };
    path.close().await.unwrap();
    path.close().await.unwrap();
    let closed = path.send_batch_owned(packets(1200)).is_err();
    assert!(oversized && mismatched && closed);
    assert_eq!(rejected_calls, 0);
    assert_eq!(count.unwrap(), 2);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(closes.load(Ordering::Relaxed), 1);
}
