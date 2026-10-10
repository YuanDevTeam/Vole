use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    resources::{ResourceActivity, ResourceActivityGuard, RuntimeResourceStats},
    session::{Datagram, DatagramSession, StreamSession},
};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("connection is not allowed")]
    NotAllowed,
    #[error("network is unreachable")]
    NetworkUnreachable,
    #[error("host is unreachable")]
    HostUnreachable,
    #[error("connection was refused")]
    ConnectionRefused,
    #[error("operation timed out")]
    TimedOut,
    #[error("dispatcher error: {0}")]
    Other(String),
}

impl DispatchError {
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::NetworkUnreachable => "network_unreachable",
            Self::HostUnreachable => "host_unreachable",
            Self::ConnectionRefused => "connection_refused",
            Self::TimedOut => "timed_out",
            Self::Other(_) => "other",
        }
    }

    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::TimedOut => 504,
            _ => 502,
        }
    }
}

impl From<io::Error> for DispatchError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::NotAllowed,
            io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::TimedOut => Self::TimedOut,
            _ => Self::Other(error.to_string()),
        }
    }
}

#[async_trait]
pub trait DatagramTransport: Send {
    /// Payload budget for packets sent to and received from this logical peer.
    /// Encapsulating transports subtract their headers from the upstream cap.
    /// The default is the u16 wire ceiling; narrower paths must override it.
    /// This never resolves a domain or opens IO.
    fn payload_budget(&self, _peer: &crate::session::Destination) -> DatagramBudget {
        DatagramBudget::new(u16::MAX, u16::MAX)
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError>;

    /// Sends the first packet of an authenticated logical connection.
    ///
    /// The routing layer may replace this peer's fixed action when this exact
    /// opaque identity changes. Replays with the same identity preserve it.
    /// IDs are at most 25 bytes and are never forwarded to an outbound or logged.
    /// Ordinary outbounds ignore the metadata; this does not reopen transport IO.
    async fn send_with_flow_id(
        &mut self,
        datagram: Datagram,
        _flow_id: &[u8],
    ) -> Result<(), DispatchError> {
        self.send(datagram).await
    }

    /// Receives one complete datagram.
    ///
    /// Implementations must be cancellation-safe: inbound relays and the
    /// router poll this future in `select!` and may drop it before completion
    /// when another datagram path becomes ready.
    async fn receive(&mut self) -> Result<Datagram, DispatchError>;

    /// Optional cancellation-safe receive seam for readiness multiplexers.
    /// The caller owns one reusable scratch buffer; it must never be retained
    /// across polls. Returned datagrams own only their complete payload.
    fn supports_poll_receive(&self) -> bool {
        false
    }

    fn poll_receive(
        &mut self,
        _context: &mut Context<'_>,
        _scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        Poll::Ready(Err(DispatchError::NotAllowed))
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[async_trait]
pub trait Dispatcher: Send + Sync {
    /// Configured datagram capability, independent of reachability or health.
    fn supports_udp(&self) -> bool {
        true
    }

    async fn sniff_plan(
        &self,
        _source: std::net::SocketAddr,
        _destination: &crate::session::Destination,
    ) -> Option<crate::sniffing::Plan> {
        None
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError>;

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError>;
}

/// Pure session-lifetime observation around a dispatcher.
///
/// The wrapper never rejects or delays work. A TCP/UDP activity guard begins
/// after establishment succeeds and remains attached to the returned object.
struct SessionObservedDispatcher {
    inner: Arc<dyn Dispatcher>,
    resource_stats: RuntimeResourceStats,
}

impl SessionObservedDispatcher {
    fn with_stats(inner: Arc<dyn Dispatcher>, resource_stats: RuntimeResourceStats) -> Self {
        Self {
            inner,
            resource_stats,
        }
    }
}

#[async_trait]
impl Dispatcher for SessionObservedDispatcher {
    fn supports_udp(&self) -> bool {
        self.inner.supports_udp()
    }

    async fn sniff_plan(
        &self,
        source: std::net::SocketAddr,
        destination: &crate::session::Destination,
    ) -> Option<crate::sniffing::Plan> {
        self.inner.sniff_plan(source, destination).await
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let stream = self.inner.connect_tcp(session).await?;
        Ok(Box::new(ObservedStream {
            inner: stream,
            _activity: self.resource_stats.begin(ResourceActivity::TcpSession),
        }))
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let transport = self.inner.open_datagram(session).await?;
        Ok(Box::new(ObservedDatagramTransport {
            inner: transport,
            _activity: self.resource_stats.begin(ResourceActivity::UdpAssociation),
        }))
    }
}

/// Pure establishment observation shared by DIRECT, proxy and DNS paths.
///
/// Its guard exists only while the inner dispatcher is opening the backend.
/// No semaphore or other admission state is involved.
struct HandshakeObservedDispatcher {
    inner: Arc<dyn Dispatcher>,
    resource_stats: RuntimeResourceStats,
}

impl HandshakeObservedDispatcher {
    fn with_stats(inner: Arc<dyn Dispatcher>, resource_stats: RuntimeResourceStats) -> Self {
        Self {
            inner,
            resource_stats,
        }
    }
}

#[async_trait]
impl Dispatcher for HandshakeObservedDispatcher {
    fn supports_udp(&self) -> bool {
        self.inner.supports_udp()
    }

    async fn sniff_plan(
        &self,
        source: std::net::SocketAddr,
        destination: &crate::session::Destination,
    ) -> Option<crate::sniffing::Plan> {
        self.inner.sniff_plan(source, destination).await
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let _activity = self.resource_stats.begin(ResourceActivity::Handshake);
        self.inner.connect_tcp(session).await
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let _activity = self.resource_stats.begin(ResourceActivity::Handshake);
        self.inner.open_datagram(session).await
    }
}

#[must_use]
pub(crate) fn observe_sessions_with_stats(
    inner: Arc<dyn Dispatcher>,
    resource_stats: RuntimeResourceStats,
) -> Arc<dyn Dispatcher> {
    Arc::new(SessionObservedDispatcher::with_stats(inner, resource_stats))
}

#[must_use]
pub(crate) fn observe_handshakes_with_stats(
    inner: Arc<dyn Dispatcher>,
    resource_stats: RuntimeResourceStats,
) -> Arc<dyn Dispatcher> {
    Arc::new(HandshakeObservedDispatcher::with_stats(
        inner,
        resource_stats,
    ))
}

struct ObservedStream {
    inner: BoxStream,
    _activity: ResourceActivityGuard,
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }
}

struct ObservedDatagramTransport {
    inner: Box<dyn DatagramTransport>,
    _activity: ResourceActivityGuard,
}

#[async_trait]
impl DatagramTransport for ObservedDatagramTransport {
    fn supports_poll_receive(&self) -> bool {
        self.inner.supports_poll_receive()
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        self.inner.poll_receive(context, scratch)
    }

    fn payload_budget(&self, peer: &crate::session::Destination) -> DatagramBudget {
        self.inner.payload_budget(peer)
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.inner.send(datagram).await
    }

    async fn send_with_flow_id(
        &mut self,
        datagram: Datagram,
        flow_id: &[u8],
    ) -> Result<(), DispatchError> {
        self.inner.send_with_flow_id(datagram, flow_id).await
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.inner.receive().await
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.inner.close().await
    }
}

// Assert object safety in normal builds rather than discovering it in an FFI adapter.
const _: Option<Pin<Box<dyn Dispatcher>>> = None;

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::Semaphore;

    use super::*;
    use crate::session::{Destination, InboundKind};

    #[derive(Default)]
    struct CountingDispatcher {
        tcp_calls: AtomicUsize,
        udp_calls: AtomicUsize,
    }

    #[async_trait]
    impl Dispatcher for CountingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.tcp_calls.fetch_add(1, Ordering::AcqRel);
            let (stream, _peer) = tokio::io::duplex(64);
            Ok(Box::new(stream))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_calls.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(NullDatagrams))
        }
    }

    struct NullDatagrams;

    #[async_trait]
    impl DatagramTransport for NullDatagrams {
        async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
    }

    struct BlockingDispatcher {
        entered: AtomicUsize,
        release: Semaphore,
    }

    #[async_trait]
    impl Dispatcher for BlockingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.entered.fetch_add(1, Ordering::AcqRel);
            let permit = self.release.acquire().await.unwrap();
            permit.forget();
            let (stream, _peer) = tokio::io::duplex(64);
            Ok(Box::new(stream))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            unreachable!()
        }
    }

    fn stream_session(port: u16) -> StreamSession {
        StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Tun,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::Ip(format!("192.0.2.1:{port}").parse().unwrap()),
            sniffed_domain: None,
        }
    }

    fn datagram_session(port: u16) -> DatagramSession {
        DatagramSession::new(
            InboundKind::Tun,
            format!("127.0.0.1:{port}").parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn session_observer_preserves_authenticated_flow_identity() {
        struct InitialTransport(Arc<AtomicUsize>);
        #[async_trait]
        impl DatagramTransport for InitialTransport {
            async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
                panic!("observer must preserve first-flow metadata");
            }
            async fn send_with_flow_id(
                &mut self,
                _datagram: Datagram,
                flow_id: &[u8],
            ) -> Result<(), DispatchError> {
                assert_eq!(flow_id, b"authenticated");
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            async fn receive(&mut self) -> Result<Datagram, DispatchError> {
                std::future::pending().await
            }
        }
        let sends = Arc::new(AtomicUsize::new(0));
        let stats = RuntimeResourceStats::new("flow_metadata_test");
        let mut observed = ObservedDatagramTransport {
            inner: Box::new(InitialTransport(sends.clone())),
            _activity: stats.begin(ResourceActivity::UdpAssociation),
        };
        observed
            .send_with_flow_id(
                Datagram {
                    remote: Destination::Ip("192.0.2.1:443".parse().unwrap()),
                    payload: bytes::Bytes::from_static(b"initial"),
                    sniffed_domain: None,
                },
                b"authenticated",
            )
            .await
            .unwrap();
        assert_eq!(sends.load(Ordering::Relaxed), 1);
        drop(observed);
        assert_eq!(stats.snapshot().udp_current, 0);
    }

    #[test]
    fn polled_datagram_observer_forwards_scratch_readiness_and_retains_activity() {
        struct PolledTransport {
            scratch_pointer: usize,
            parent: std::task::Waker,
            polls: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl DatagramTransport for PolledTransport {
            fn supports_poll_receive(&self) -> bool {
                true
            }
            fn poll_receive(
                &mut self,
                context: &mut Context<'_>,
                scratch: &mut Vec<u8>,
            ) -> Poll<Result<Datagram, DispatchError>> {
                assert!(context.waker().will_wake(&self.parent));
                assert_eq!(scratch.as_ptr() as usize, self.scratch_pointer);
                assert_eq!(scratch.as_slice(), b"supplied");
                scratch.clear();
                scratch.extend_from_slice(b"used");
                self.polls.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(Datagram {
                    remote: Destination::Ip("198.51.100.1:443".parse().unwrap()),
                    payload: bytes::Bytes::from_static(b"ready"),
                    sniffed_domain: None,
                }))
            }
            async fn send(&mut self, _datagram: Datagram) -> Result<(), DispatchError> {
                Ok(())
            }
            async fn receive(&mut self) -> Result<Datagram, DispatchError> {
                panic!("polled observer must not use asynchronous receive")
            }
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let stats = RuntimeResourceStats::new("polled_observer_test");
        let parent = futures_util::task::noop_waker();
        let mut scratch = b"supplied".to_vec();
        let mut observed = ObservedDatagramTransport {
            inner: Box::new(PolledTransport {
                scratch_pointer: scratch.as_ptr() as usize,
                parent: parent.clone(),
                polls: polls.clone(),
            }),
            _activity: stats.begin(ResourceActivity::UdpAssociation),
        };
        assert_eq!(stats.snapshot().udp_current, 1);
        assert!(observed.supports_poll_receive());
        let mut context = Context::from_waker(&parent);
        let Poll::Ready(Ok(datagram)) = observed.poll_receive(&mut context, &mut scratch) else {
            panic!("observer must forward the ready datagram")
        };
        assert_eq!(datagram.payload, bytes::Bytes::from_static(b"ready"));
        assert_eq!(scratch.as_slice(), b"used");
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(stats.snapshot().udp_current, 1);
        drop(observed);
        assert_eq!(stats.snapshot().udp_current, 0);
    }

    #[tokio::test]
    async fn session_observation_does_not_reject_former_tcp_or_udp_boundaries() {
        const TCP_SESSIONS: usize = 160;
        const UDP_ASSOCIATIONS: usize = 96;

        let inner = Arc::new(CountingDispatcher::default());
        let stats = RuntimeResourceStats::new("session_observation_test");
        let dispatcher = observe_sessions_with_stats(inner.clone(), stats.clone());

        let mut streams = Vec::with_capacity(TCP_SESSIONS);
        for index in 0..TCP_SESSIONS {
            streams.push(
                dispatcher
                    .connect_tcp(stream_session(u16::try_from(index + 1).unwrap()))
                    .await
                    .unwrap(),
            );
        }
        let mut transports = Vec::with_capacity(UDP_ASSOCIATIONS);
        for index in 0..UDP_ASSOCIATIONS {
            transports.push(
                dispatcher
                    .open_datagram(datagram_session(u16::try_from(index + 1).unwrap()))
                    .await
                    .unwrap(),
            );
        }

        assert_eq!(inner.tcp_calls.load(Ordering::Acquire), TCP_SESSIONS);
        assert_eq!(inner.udp_calls.load(Ordering::Acquire), UDP_ASSOCIATIONS);
        let active = stats.snapshot();
        assert_eq!(active.tcp_current, TCP_SESSIONS);
        assert_eq!(active.tcp_peak, TCP_SESSIONS);
        assert_eq!(active.udp_current, UDP_ASSOCIATIONS);
        assert_eq!(active.udp_peak, UDP_ASSOCIATIONS);

        drop((streams, transports));
        let released = stats.snapshot();
        assert_eq!(released.tcp_current, 0);
        assert_eq!(released.udp_current, 0);
    }

    #[tokio::test]
    async fn handshake_observation_allows_more_than_the_former_limit() {
        const CONCURRENT: usize = 24;

        let inner = Arc::new(BlockingDispatcher {
            entered: AtomicUsize::new(0),
            release: Semaphore::new(0),
        });
        let stats = RuntimeResourceStats::new("handshake_observation_test");
        let dispatcher = observe_handshakes_with_stats(inner.clone(), stats.clone());
        let tasks = (0..CONCURRENT)
            .map(|index| {
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    dispatcher
                        .connect_tcp(stream_session(u16::try_from(index + 1).unwrap()))
                        .await
                })
            })
            .collect::<Vec<_>>();

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while inner.entered.load(Ordering::Acquire) != CONCURRENT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all handshake attempts must reach the inner dispatcher");
        let active = stats.snapshot();
        assert_eq!(active.handshake_current, CONCURRENT);
        assert_eq!(active.handshake_peak, CONCURRENT);

        inner.release.add_permits(CONCURRENT);
        for task in tasks {
            drop(task.await.unwrap().unwrap());
        }
        assert_eq!(stats.snapshot().handshake_current, 0);
    }
}
mod datagram;
pub(crate) use datagram::bounded as bound_datagram;
pub use datagram::{DatagramBudget, QUIC_MIN_PAYLOAD_BYTES};
