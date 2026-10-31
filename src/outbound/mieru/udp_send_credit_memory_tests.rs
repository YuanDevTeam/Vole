//! Actual Client::create over an owned in-memory DatagramTransport, then RawStream.
//! No server/framing implementation, sockets, DNS, listeners or network resources.
use super::super::tests::{Peer, config, session};
use super::*;
use crate::{
    dispatch::{DatagramTransport, DispatchError},
    outbound::{ConnectedStream, DatagramRequest, OutboundConnector},
    resources::observation::ResourceProbe,
    session::Datagram,
};
use async_trait::async_trait;

#[derive(Default)]
struct Counts {
    opened: AtomicUsize,
    closed: AtomicUsize,
    dropped: AtomicUsize,
}
#[derive(Default)]
struct MemoryPeer {
    counts: Arc<Counts>,
}
struct MemoryDatagram {
    counts: Arc<Counts>,
    closed: bool,
}
#[async_trait]
impl DatagramTransport for MemoryDatagram {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        assert!(
            !self.closed,
            "the actual carrier must close its transport once"
        );
        self.closed = true;
        self.counts.closed.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}
impl Drop for MemoryDatagram {
    fn drop(&mut self) {
        self.counts.dropped.fetch_add(1, Ordering::AcqRel);
    }
}
#[async_trait]
impl OutboundConnector for MemoryPeer {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.counts.opened.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(MemoryDatagram {
            counts: self.counts.clone(),
            closed: false,
        }))
    }
}
fn settings(multiplexing: MieruMultiplexing) -> MieruOutboundConfig {
    let mut settings = config(crate::config::MieruHandshake::Standard);
    settings.address = "192.0.2.1".into(); // Actual setup resolves this literal locally.
    settings.transport = MieruTransport::Udp;
    settings.multiplexing = multiplexing;
    settings
}
fn assert_joined(counts: &Counts, expected: usize) {
    assert_eq!(counts.opened.load(Ordering::Acquire), expected);
    assert_eq!(counts.closed.load(Ordering::Acquire), expected);
    assert_eq!(counts.dropped.load(Ordering::Acquire), expected);
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_send_credit96_actual_factory_preserves_scope_and_nondefault_budgets() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            assert!(98304 <= Semaphore::MAX_PERMITS);
            for (mode, business, capacity, expected) in [
                (MieruMultiplexing::Low, Business::UdpAssociate, 32768, 98304),
                (MieruMultiplexing::Low, Business::TcpConnect, 32768, 32768),
                (MieruMultiplexing::Low, Business::UdpAssociate, 1, 1),
                (MieruMultiplexing::Low, Business::UdpAssociate, 16, 16),
                (MieruMultiplexing::Low, Business::UdpAssociate, 32767, 32767),
                (MieruMultiplexing::Low, Business::UdpAssociate, 32769, 32769),
                (MieruMultiplexing::Low, Business::UdpAssociate, 65536, 65536),
                (MieruMultiplexing::Off, Business::UdpAssociate, 32768, 32768),
                (
                    MieruMultiplexing::Middle,
                    Business::UdpAssociate,
                    32768,
                    32768,
                ),
                (
                    MieruMultiplexing::High,
                    Business::UdpAssociate,
                    32768,
                    32768,
                ),
            ] {
                let peer = Arc::new(MemoryPeer::default());
                let client =
                    Client::new(&settings(mode), UpstreamPath::proxy(peer.clone()), capacity)
                        .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(1));
                let reservation = client.create(session(), business, &context).await.unwrap();
                let carrier = reservation.0.clone();
                assert_eq!(carrier.bytes.available_permits(), expected);
                assert_eq!(carrier.writer.max_capacity(), 2);
                assert_eq!(
                    client.capacity, capacity,
                    "the original SID/chunk budget is retained"
                );
                drop(reservation);
                client.shutdown().await;
                assert!(client.registry.lock().unwrap().carriers.is_empty());
                drop((carrier, client));
                assert_joined(&peer.counts, 1);
            }
            // Physical TCP creates its real original memory stream carrier as a control.
            for business in [Business::TcpConnect, Business::UdpAssociate] {
                let peer = Peer::new(false);
                let mut settings = config(crate::config::MieruHandshake::Standard);
                settings.multiplexing = MieruMultiplexing::Low;
                let client =
                    Client::new(&settings, UpstreamPath::proxy(peer.clone()), 32768).unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(1));
                let reservation = client.create(session(), business, &context).await.unwrap();
                let carrier = reservation.0.clone();
                assert_eq!(carrier.bytes.available_permits(), 32768);
                drop(reservation);
                client.shutdown().await;
                drop((carrier, client));
                peer.stop().await;
            }
        })
        .await;
    assert!(probe.snapshot().is_idle());
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_send_credit96_actual_carrier_two_sids_share_credit_fifo_and_stop() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let peer = Arc::new(MemoryPeer::default());
            let client = Client::new(
                &settings(MieruMultiplexing::Low),
                UpstreamPath::proxy(peer.clone()),
                32768,
            )
            .unwrap();
            let context = EstablishContext::with_timeout(Duration::from_secs(1));
            let reservation = client
                .create(session(), Business::UdpAssociate, &context)
                .await
                .unwrap();
            let carrier = reservation.0.clone();
            let credit = carrier.bytes.clone();
            drop(reservation);
            let mut streams = Vec::new();
            let mut states = Vec::new();
            for id in [7, 8] {
                // Assemble the exact post-reservation State/RawStream ownership from open().
                let state = State::new_for_business(
                    id,
                    client.capacity,
                    Business::UdpAssociate,
                    &carrier.shared.cancel,
                    carrier.shared.activity.clone(),
                );
                carrier
                    .shared
                    .sessions
                    .lock()
                    .unwrap()
                    .insert(id, state.clone());
                streams.push(
                    RawStream::new(carrier.clone(), state.clone(), client.capacity)
                        .with_queued_writes(true),
                );
                states.push(state);
            }
            let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
            let first = vec![b'A'; 32768];
            let second = vec![b'B'; 32768];
            // No await between setup and Stop: the single-thread executor cannot consume
            // these two FIFO entries before the shared-credit assertions below.
            assert!(matches!(
                Pin::new(&mut streams[0]).poll_write(&mut cx, &first),
                Poll::Ready(Ok(32768))
            ));
            assert!(
                matches!(
                    Pin::new(&mut streams[1]).poll_write(&mut cx, &second),
                    Poll::Ready(Ok(32768))
                ),
                "a second SID must use the same carrier's shared credit"
            );
            assert_eq!(credit.available_permits(), 32768);
            assert_eq!(carrier.writer.max_capacity(), 2);
            assert_eq!(carrier.writer.capacity(), 0);
            assert_eq!(states[0].receive_bytes.available_permits(), 32768);
            assert_eq!(states[1].receive_bytes.available_permits(), 32768);
            assert!(
                Pin::new(&mut streams[1])
                    .poll_write(&mut cx, b"C")
                    .is_pending()
            );
            // FIFO2, not byte-credit exhaustion, blocks this third write.
            // Its one-byte permit remains owned inside the original pending send.
            assert_eq!(credit.available_permits(), 32767);
            assert!(Pin::new(&mut streams[0]).poll_flush(&mut cx).is_pending());
            let selected = client
                .reserve_reusable(Business::UdpAssociate, |_| 0)
                .unwrap()
                .unwrap();
            assert!(Arc::ptr_eq(&selected.0, &carrier));
            drop(selected);
            assert!(
                client
                    .reserve_reusable(Business::TcpConnect, |_| 0)
                    .unwrap()
                    .is_none()
            );
            client.begin_shutdown();
            client.shutdown().await;
            for stream in &mut streams {
                assert!(matches!(Pin::new(stream).poll_flush(&mut cx),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe));
            }
            drop((streams, states, carrier, client));
            assert_eq!(credit.available_permits(), 98304);
            assert_joined(&peer.counts, 1);
        })
        .await;
    assert!(probe.snapshot().is_idle());
}
