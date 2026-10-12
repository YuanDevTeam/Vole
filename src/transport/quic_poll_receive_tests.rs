//! Bounded channels exercise the actual shared adapter, without socket peers.
use super::*;
use futures_util::FutureExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{future::poll_fn, panic::AssertUnwindSafe, time::Duration};
use tokio::sync::mpsc;

#[derive(Default)]
struct Counts {
    capability: AtomicUsize,
    polls: AtomicUsize,
    receives: AtomicUsize,
    ready: AtomicUsize,
    pending: AtomicUsize,
    scratch_initializations: AtomicUsize,
    closed: AtomicUsize,
    dropped: AtomicUsize,
    entered_pending: Notify,
}

struct MemoryTransport {
    polled: bool,
    incoming: mpsc::Receiver<Datagram>,
    outgoing: mpsc::Sender<Datagram>,
    counts: Arc<Counts>,
}

impl MemoryTransport {
    fn receive_one(&mut self, cx: &mut Context<'_>) -> Poll<Result<Datagram, DispatchError>> {
        match self.incoming.poll_recv(cx) {
            Poll::Pending => {
                self.counts.pending.fetch_add(1, Ordering::AcqRel);
                self.counts.entered_pending.notify_one();
                Poll::Pending
            }
            Poll::Ready(Some(packet)) => {
                self.counts.ready.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(Ok(packet))
            }
            Poll::Ready(None) => Poll::Ready(Err(DispatchError::NotAllowed)),
        }
    }
}

#[async_trait::async_trait]
impl DatagramTransport for MemoryTransport {
    fn supports_poll_receive(&self) -> bool {
        self.counts.capability.fetch_add(1, Ordering::AcqRel);
        self.polled
    }

    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        assert!(
            self.polled,
            "unsupported transport must stay on the async seam"
        );
        self.counts.polls.fetch_add(1, Ordering::AcqRel);
        if scratch.is_empty() {
            // Exercise the caller-owned scratch contract without retaining it.
            scratch.resize(1401, 0);
            self.counts
                .scratch_initializations
                .fetch_add(1, Ordering::AcqRel);
        }
        self.receive_one(cx)
    }

    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        self.outgoing
            .send(packet)
            .await
            .map_err(|_| DispatchError::NotAllowed)
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.counts.receives.fetch_add(1, Ordering::AcqRel);
        poll_fn(|cx| self.receive_one(cx)).await
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.incoming.close();
        self.counts.closed.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

impl Drop for MemoryTransport {
    fn drop(&mut self) {
        self.counts.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

fn memory(
    polled: bool,
) -> (
    Box<dyn DatagramTransport>,
    mpsc::Sender<Datagram>,
    mpsc::Receiver<Datagram>,
    Arc<Counts>,
) {
    let (incoming, rx) = mpsc::channel(QUEUE_LIMIT + 4);
    let (tx, outgoing) = mpsc::channel(QUEUE_LIMIT + 4);
    let counts = Arc::new(Counts::default());
    (
        Box::new(MemoryTransport {
            polled,
            incoming: rx,
            outgoing: tx,
            counts: counts.clone(),
        }),
        incoming,
        outgoing,
        counts,
    )
}

fn packet(peer: SocketAddr, payload: Bytes) -> Datagram {
    Datagram {
        remote: Destination::Ip(peer),
        payload,
        sniffed_domain: None,
    }
}

fn activate(socket: &DatagramSocket, peer: SocketAddr) -> io::Result<()> {
    socket.try_send(&quinn::udp::Transmit {
        destination: peer,
        ecn: None,
        contents: b"activate",
        segment_size: None,
        src_ip: None,
    })
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn fifo_bounds(polled: bool) {
    let (transport, incoming, mut outgoing, counts) = memory(polled);
    let logical = "192.0.2.1:443".parse().unwrap();
    let physical = "192.0.2.2:8443".parse().unwrap();
    let (socket, driver) = attach_mapped(
        transport,
        logical,
        physical,
        DatagramBudget::new(1400, 1400),
    )
    .unwrap();
    // Every assert in the IO body is caught so Stop still joins a failing test.
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        AssertUnwindSafe(async {
            incoming
                .send(packet(logical, Bytes::from_static(b"wrong-source")))
                .await
                .unwrap();
            incoming
                .send(packet(physical, Bytes::from(vec![0; 1401])))
                .await
                .unwrap();
            for n in 0..=QUEUE_LIMIT {
                incoming
                    .send(packet(physical, Bytes::from(vec![n as u8, 0x5a])))
                    .await
                    .unwrap();
            }
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                counts.ready.load(Ordering::Acquire),
                0,
                "no receive before the first completed send"
            );
            activate(&socket, logical).unwrap();
            let sent = outgoing.recv().await.unwrap();
            assert_eq!(sent.remote, Destination::Ip(physical));
            assert_eq!(sent.payload, b"activate"[..]);
            wait_for(|| socket.stats().received == QUEUE_LIMIT).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            // The 33rd valid datagram remains in the bounded transport until space
            // is freed. Wrong source/oversize were rejected, not delivered.
            assert_eq!(counts.ready.load(Ordering::Acquire), QUEUE_LIMIT + 2);
            for n in 0..=QUEUE_LIMIT {
                let mut bytes = [0; 1401];
                let mut buffers = [IoSliceMut::new(&mut bytes)];
                let mut meta = [quinn::udp::RecvMeta::default()];
                assert_eq!(
                    poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
                        .await
                        .unwrap(),
                    1
                );
                assert_eq!(&buffers[0][..meta[0].len], &[n as u8, 0x5a]);
                assert_eq!(meta[0].addr, logical);
            }
            let stats = socket.stats();
            assert_eq!(stats.received, QUEUE_LIMIT + 1);
            assert_eq!(stats.rejected_source, 1);
            assert_eq!(stats.rejected_oversize, 1);
            assert_eq!(stats.dropped_full, 0);
            assert_eq!(stats.peak_incoming, QUEUE_LIMIT);
            assert_eq!(stats.sent, 1);
        })
        .catch_unwind(),
    )
    .await;
    let stopped = tokio::time::timeout(Duration::from_secs(1), driver.stop()).await;
    assert!(stopped.unwrap().is_ok());
    assert_eq!(counts.closed.load(Ordering::Acquire), 1);
    assert_eq!(counts.dropped.load(Ordering::Acquire), 1);
    assert!(activate(&socket, logical).is_err());
    let mut bytes = [0; 1401];
    let mut buffers = [IoSliceMut::new(&mut bytes)];
    let mut meta = [quinn::udp::RecvMeta::default()];
    assert!(
        poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
            .await
            .is_err()
    );
    outcome.unwrap().unwrap();
    assert_eq!(counts.capability.load(Ordering::Acquire), 1);
    if polled {
        assert!(counts.polls.load(Ordering::Acquire) > 0);
        assert_eq!(counts.receives.load(Ordering::Acquire), 0);
        assert_eq!(counts.scratch_initializations.load(Ordering::Acquire), 1);
    } else {
        assert_eq!(counts.polls.load(Ordering::Acquire), 0);
        assert!(counts.receives.load(Ordering::Acquire) > 0);
        assert_eq!(counts.scratch_initializations.load(Ordering::Acquire), 0);
    }
}

#[tokio::test]
async fn quic_memory_polled_receive_fifo_bounds_and_stop() {
    fifo_bounds(true).await;
}

#[tokio::test]
async fn quic_memory_async_receive_fallback_fifo_bounds_and_stop() {
    fifo_bounds(false).await;
}

#[tokio::test]
async fn quic_memory_receive_pending_cancel_joins_both_seams() {
    for polled in [true, false] {
        let (transport, _incoming, mut outgoing, counts) = memory(polled);
        let peer = "192.0.2.1:443".parse().unwrap();
        let (socket, driver) = attach(transport, peer, DatagramBudget::new(1400, 1400)).unwrap();
        let entered = tokio::time::timeout(
            Duration::from_secs(1),
            AssertUnwindSafe(async {
                activate(&socket, peer).unwrap();
                assert_eq!(outgoing.recv().await.unwrap().payload, b"activate"[..]);
                counts.entered_pending.notified().await;
                assert!(counts.pending.load(Ordering::Acquire) > 0);
            })
            .catch_unwind(),
        )
        .await;
        let stopped = tokio::time::timeout(Duration::from_secs(1), driver.stop()).await;
        assert!(stopped.unwrap().is_ok());
        assert_eq!(counts.closed.load(Ordering::Acquire), 1);
        assert_eq!(counts.dropped.load(Ordering::Acquire), 1);
        assert!(activate(&socket, peer).is_err());
        entered.unwrap().unwrap();
        assert_eq!(counts.capability.load(Ordering::Acquire), 1);
        assert_eq!(counts.ready.load(Ordering::Acquire), 0);
        if polled {
            assert!(counts.polls.load(Ordering::Acquire) > 0);
            assert_eq!(counts.receives.load(Ordering::Acquire), 0);
        } else {
            assert_eq!(counts.polls.load(Ordering::Acquire), 0);
            assert!(counts.receives.load(Ordering::Acquire) > 0);
        }
    }
}
