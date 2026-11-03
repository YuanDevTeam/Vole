//! TrustTunnel UDP frames over an owned reliable CONNECT stream.
//! The wire layout follows Mihomo's TrustTunnel packet protocol; this module
//! creates no sockets and keeps parsing independent of receive-future lifetime.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::future::BoxFuture;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, WriteHalf},
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    dns::resolution::ResolutionContext,
    outbound::{DEFAULT_ESTABLISH_TIMEOUT, DatagramRequest, EstablishContext},
    resources::observation::{Guard, ResourceKind, track},
    session::{Datagram, Destination},
};

const ADDRESS_BYTES: usize = 36;
const APP_NAME: &[u8] = b"Vole";
const RESPONSE_QUEUE_CAPACITY: usize = 1;
const DRAIN_BUFFER_BYTES: usize = 2_048;

pub(super) struct PacketTransport {
    writer: Option<WriteHalf<BoxStream>>,
    responses: mpsc::Receiver<io::Result<Datagram>>,
    cancellation: CancellationToken,
    reader: Option<JoinHandle<()>>,
    reader_alive: Arc<AtomicBool>,
    resolution: ResolutionContext,
    initial_deadline: Option<Instant>,
    budget: DatagramBudget,
    closed: bool,
    _observation: Guard,
}

impl PacketTransport {
    /// `spawn` is the node's synchronous admission seam. It rejects work after
    /// shutdown begins and includes the reader in the node's stop barrier.
    pub(super) fn new<F>(
        io: BoxStream,
        request: &DatagramRequest,
        context: &EstablishContext,
        parent_cancellation: CancellationToken,
        spawn: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(BoxFuture<'static, ()>) -> io::Result<JoinHandle<()>>,
    {
        if parent_cancellation.is_cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let cancellation = parent_cancellation.child_token();
        let (reader, writer) = tokio::io::split(io);
        let (responses, receiver) = mpsc::channel(RESPONSE_QUEUE_CAPACITY);
        let reader_alive = Arc::new(AtomicBool::new(true));
        // The guard also runs when admission rejects and drops the future.
        let lifetime = ReaderLifetime(reader_alive.clone());
        let reader = spawn(Box::pin(read_loop(
            reader,
            responses,
            request.budget().receive(),
            cancellation.clone(),
            lifetime,
        )))?;
        Ok(Self {
            writer: Some(writer),
            responses: receiver,
            cancellation,
            reader: Some(reader),
            reader_alive,
            resolution: context.resolution(),
            initial_deadline: Some(context.deadline()),
            budget: request.budget(),
            closed: false,
            _observation: track(ResourceKind::Association),
        })
    }

    fn check_open(&mut self) -> Result<(), DispatchError> {
        if self.closed || self.cancellation.is_cancelled() || self.writer.is_none() {
            self.writer.take();
            self.closed = true;
            return Err(DispatchError::NotAllowed);
        }
        Ok(())
    }
}

struct ReaderLifetime(Arc<AtomicBool>);

impl Drop for ReaderLifetime {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A cancelled or failed partial write cannot be retried as a fresh UDP frame.
struct SendGuard<'a> {
    writer: &'a mut Option<WriteHalf<BoxStream>>,
    cancellation: CancellationToken,
    committed: bool,
}

impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.cancellation.cancel();
            self.writer.take();
        }
    }
}

#[async_trait]
impl DatagramTransport for PacketTransport {
    fn supports_shared_destinations(&self) -> bool {
        // The _udp2 stream encodes and returns an address on every frame.
        true
    }

    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        self.budget
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.check_open()?;
        if !self.reader_alive.load(Ordering::Acquire) {
            self.writer.take();
            self.closed = true;
            return Err(DispatchError::NotAllowed);
        }
        if datagram.payload.len() > usize::from(self.budget.transmit()) {
            return Err(DispatchError::from(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TrustTunnel UDP payload exceeds its send budget",
            )));
        }
        let deadline = self
            .initial_deadline
            .unwrap_or_else(|| Instant::now() + DEFAULT_ESTABLISH_TIMEOUT);
        if Instant::now() >= deadline {
            self.cancellation.cancel();
            self.writer.take();
            self.closed = true;
            return Err(DispatchError::TimedOut);
        }
        let address = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(DispatchError::NotAllowed),
            result = self.resolution.resolve_ip(&datagram.remote, deadline) => result?,
        };
        let packet = encode_packet(address, &datagram.payload);
        let mut guard = SendGuard {
            writer: &mut self.writer,
            cancellation: self.cancellation.clone(),
            committed: false,
        };
        let initial_deadline = self.initial_deadline;
        tokio::select! {
            biased;
            () = guard.cancellation.cancelled() => return Err(DispatchError::NotAllowed),
            result = async {
                let writing = async {
                    let writer = guard.writer.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
                    writer.write_all(&packet).await?;
                    writer.flush().await
                };
                if let Some(deadline) = initial_deadline {
                    timeout_at(deadline, writing).await
                        .map_err(|_| DispatchError::TimedOut)?
                        .map_err(DispatchError::from)
                } else {
                    writing.await.map_err(DispatchError::from)
                }
            } => result?,
        }
        guard.committed = true;
        drop(guard);
        self.initial_deadline = None;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.check_open()?;
        let response = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(DispatchError::NotAllowed),
            response = self.responses.recv() => response,
        };
        match response {
            Some(Ok(datagram)) => Ok(datagram),
            Some(Err(error)) => {
                self.closed = true;
                self.cancellation.cancel();
                self.writer.take();
                Err(DispatchError::from(error))
            }
            None => {
                self.closed = true;
                self.cancellation.cancel();
                self.writer.take();
                Err(DispatchError::from(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TrustTunnel UDP response stream ended",
                )))
            }
        }
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed = true;
        self.cancellation.cancel();
        let result = match self.reader.take() {
            Some(reader) => reader.await.map_err(|_| {
                DispatchError::from(io::Error::other("TrustTunnel UDP reader stopped"))
            }),
            None => Ok(()),
        };
        // Every successful send was flushed. Failed/cancelled partial writes
        // are unusable; releasing both halves closes the whole CONNECT stream
        // without waiting for a stalled peer to supply additional flow credit.
        self.writer.take();
        self.responses.close();
        while self.responses.try_recv().is_ok() {}
        result
    }
}

impl Drop for PacketTransport {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.writer.take();
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
    }
}

fn encode_packet(address: SocketAddr, payload: &[u8]) -> Bytes {
    let metadata_length = ADDRESS_BYTES + 1 + APP_NAME.len();
    let mut packet = BytesMut::with_capacity(4 + metadata_length + payload.len());
    packet.put_u32((metadata_length + payload.len()) as u32);
    packet.extend_from_slice(&[0; 18]); // Unknown local source IP and port.
    packet.extend_from_slice(&padded_ip(address.ip()));
    packet.put_u16(address.port());
    packet.put_u8(APP_NAME.len() as u8);
    packet.extend_from_slice(APP_NAME);
    packet.extend_from_slice(payload);
    packet.freeze()
}

fn padded_ip(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(address) => {
            let mut padded = [0; 16];
            padded[12..].copy_from_slice(&address.octets());
            padded
        }
        IpAddr::V6(address) => address.octets(),
    }
}

fn parse_ip(address: [u8; 16]) -> IpAddr {
    // The reference reserves ::1 for IPv6 despite the zero-padded IPv4 layout.
    if address[..12] == [0; 12] && address != Ipv6Addr::LOCALHOST.octets() {
        IpAddr::V4(Ipv4Addr::new(
            address[12],
            address[13],
            address[14],
            address[15],
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(address))
    }
}

async fn read_loop<R>(
    mut reader: R,
    responses: mpsc::Sender<io::Result<Datagram>>,
    budget: u16,
    cancellation: CancellationToken,
    lifetime: ReaderLifetime,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            result = read_packet(&mut reader, budget) => result,
        };
        let response = match response {
            Ok(Some(datagram)) => Ok(datagram),
            Ok(None) => {
                tokio::task::yield_now().await;
                continue;
            }
            Err(error) => {
                lifetime.0.store(false, Ordering::Release);
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => {},
                    _ = responses.send(Err(error)) => {},
                }
                return;
            }
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            result = responses.send(response) => {
                if result.is_err() { return; }
            },
        }
    }
}

async fn read_packet<R>(reader: &mut R, budget: u16) -> io::Result<Option<Datagram>>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u32().await? as usize;
    let payload_length = length
        .checked_sub(ADDRESS_BYTES)
        .filter(|length| *length <= usize::from(u16::MAX))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid TrustTunnel UDP length")
        })?;
    let mut addresses = [0; ADDRESS_BYTES];
    reader.read_exact(&mut addresses).await?;
    if payload_length > usize::from(budget) {
        let mut remaining = payload_length;
        let mut buffer = [0; DRAIN_BUFFER_BYTES];
        while remaining > 0 {
            let length = remaining.min(buffer.len());
            reader.read_exact(&mut buffer[..length]).await?;
            remaining -= length;
        }
        return Ok(None);
    }
    let mut payload = vec![0; payload_length];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Datagram {
        remote: Destination::Ip(SocketAddr::new(
            parse_ip(addresses[..16].try_into().expect("fixed IP field")),
            u16::from_be_bytes(addresses[16..18].try_into().expect("fixed port field")),
        )),
        payload: Bytes::from(payload),
        sniffed_domain: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dialer::{ResolvedEndpoint, Resolver},
        resources::observation::ResourceProbe,
        session::{DatagramSession, InboundKind},
    };
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::oneshot;
    use tokio_util::task::TaskTracker;

    struct FixedResolver(AtomicUsize);

    #[async_trait]
    impl Resolver for FixedResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(ResolvedEndpoint {
                logical_host: host.into(),
                port,
                addresses: vec![SocketAddr::from(([192, 0, 2, 10], port))],
            })
        }
    }

    fn request(budget: u16) -> DatagramRequest {
        DatagramRequest::new(DatagramSession::new(
            InboundKind::InternalDns,
            "127.0.0.1:10000".parse().unwrap(),
        ))
        .with_budget(DatagramBudget::new(budget, budget))
    }

    fn datagram(payload: &'static [u8]) -> Datagram {
        Datagram {
            remote: Destination::Domain {
                host: "example.invalid".into(),
                port: 53,
            },
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }

    fn server_packet(address: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&((ADDRESS_BYTES + payload.len()) as u32).to_be_bytes());
        wire.extend_from_slice(&padded_ip(address.ip()));
        wire.extend_from_slice(&address.port().to_be_bytes());
        wire.extend_from_slice(&[0; 18]);
        wire.extend_from_slice(payload);
        wire
    }

    async fn assert_client_packet<R: AsyncRead + Unpin>(reader: &mut R, payload: &[u8]) {
        assert_client_packet_to(reader, "192.0.2.10:53".parse().unwrap(), payload).await;
    }

    async fn assert_client_packet_to<R: AsyncRead + Unpin>(
        reader: &mut R,
        remote: SocketAddr,
        payload: &[u8],
    ) {
        let length = reader.read_u32().await.unwrap() as usize;
        assert_eq!(length, 37 + APP_NAME.len() + payload.len());
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await.unwrap();
        assert_eq!(&body[..18], &[0; 18]);
        assert_eq!(&body[18..34], &padded_ip(remote.ip()));
        assert_eq!(&body[34..36], &remote.port().to_be_bytes());
        assert_eq!(body[36] as usize, APP_NAME.len());
        assert_eq!(&body[37..37 + APP_NAME.len()], APP_NAME);
        assert_eq!(&body[37 + APP_NAME.len()..], payload);
    }

    #[tokio::test]
    async fn trusttunnel_udp_shared_stream_preserves_targets_and_independent_close() {
        let probe = ResourceProbe::default();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            probe.scope(async {
                let tasks = TaskTracker::new();
                let context = EstablishContext::default();
                let parent = CancellationToken::new();
                let (first, mut peer) = tokio::io::duplex(4096);
                let mut shared = PacketTransport::new(
                    Box::new(first),
                    &request(128),
                    &context,
                    parent.clone(),
                    |future| Ok(tasks.spawn(crate::resources::observation::task(future))),
                )
                .unwrap();
                let targets: [SocketAddr; 2] = [
                    "198.51.100.1:53".parse().unwrap(),
                    "[2001:db8::1]:5353".parse().unwrap(),
                ];
                let (resume, resumed) = oneshot::channel();
                let remote = tokio::spawn(async move {
                    for target in targets {
                        assert_client_packet_to(&mut peer, target, b"request").await;
                    }
                    resumed.await.unwrap();
                    // Responses need not arrive in send order.
                    for target in targets.into_iter().rev() {
                        peer.write_all(&server_packet(target, b"reply"))
                            .await
                            .unwrap();
                    }
                    let mut remaining = Vec::new();
                    peer.read_to_end(&mut remaining).await.unwrap();
                    assert!(remaining.is_empty());
                });
                assert!(shared.supports_shared_destinations());
                for target in targets {
                    shared
                        .send(Datagram {
                            remote: Destination::Ip(target),
                            payload: Bytes::from_static(b"request"),
                            sniffed_domain: None,
                        })
                        .await
                        .unwrap();
                }
                // Dropping a pending read cannot lose either addressed response.
                let mut waiting = Box::pin(shared.receive());
                assert!(futures_util::poll!(&mut waiting).is_pending());
                drop(waiting);
                resume.send(()).unwrap();
                for target in targets.into_iter().rev() {
                    let response = shared.receive().await.unwrap();
                    assert_eq!(response.remote, Destination::Ip(target));
                    assert_eq!(response.payload, Bytes::from_static(b"reply"));
                }
                shared.close().await.unwrap();
                assert!(
                    shared
                        .send(Datagram {
                            remote: Destination::Ip(targets[0]),
                            payload: Bytes::from_static(b"closed"),
                            sniffed_domain: None,
                        })
                        .await
                        .is_err()
                );
                drop(shared);
                remote.await.unwrap();
                assert!(!parent.is_cancelled());

                // Closing one association must not revoke the node's parent or a
                // new association, even when it uses exactly the same target.
                let (second, mut peer) = tokio::io::duplex(4096);
                let mut sibling = PacketTransport::new(
                    Box::new(second),
                    &request(128),
                    &context,
                    parent.clone(),
                    |future| Ok(tasks.spawn(crate::resources::observation::task(future))),
                )
                .unwrap();
                sibling
                    .send(Datagram {
                        remote: Destination::Ip(targets[0]),
                        payload: Bytes::from_static(b"sibling"),
                        sniffed_domain: None,
                    })
                    .await
                    .unwrap();
                assert_client_packet_to(&mut peer, targets[0], b"sibling").await;
                peer.write_all(&server_packet(targets[0], b"live"))
                    .await
                    .unwrap();
                let response = sibling.receive().await.unwrap();
                assert_eq!(response.remote, Destination::Ip(targets[0]));
                assert_eq!(response.payload, Bytes::from_static(b"live"));
                sibling.close().await.unwrap();
                drop((sibling, peer));
                tasks.close();
                tasks.wait().await;
            }),
        )
        .await
        .expect("TrustTunnel multi-target memory operation must finish");
        assert!(probe.snapshot().is_idle());
    }

    #[tokio::test(start_paused = true)]
    async fn trusttunnel_udp_cancelled_receive_keeps_frames_and_refreshes_dns_deadline() {
        let probe = ResourceProbe::default();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            probe.scope(async {
                let tasks = TaskTracker::new();
                let resolver = Arc::new(FixedResolver(AtomicUsize::new(0)));
                let context = EstablishContext::with_resolution(
                    std::time::Duration::from_secs(1),
                    ResolutionContext::measurement(resolver.clone(), true),
                );
                let cancellation = CancellationToken::new();
                let (io, mut peer) = tokio::io::duplex(4_096);
                let mut transport = PacketTransport::new(
                    Box::new(io),
                    &request(3),
                    &context,
                    cancellation.clone(),
                    |future| Ok(tasks.spawn(crate::resources::observation::task(future))),
                )
                .unwrap();
                let (partial_sent, partial_ready) = oneshot::channel();
                let (resume, resumed) = oneshot::channel();
                let remote = tokio::spawn(async move {
                    assert_client_packet(&mut peer, b"one").await;
                    let mut wire = server_packet("198.51.100.8:53".parse().unwrap(), b"discard");
                    wire.extend(server_packet("[::1]:54".parse().unwrap(), b""));
                    wire.extend(server_packet("198.51.100.9:55".parse().unwrap(), b"one"));
                    peer.write_all(&wire[..13]).await.unwrap();
                    partial_sent.send(()).unwrap();
                    resumed.await.unwrap();
                    peer.write_all(&wire[13..]).await.unwrap();
                    assert_client_packet(&mut peer, b"two").await;
                });
                assert!(transport.send(datagram(b"four")).await.is_err());
                assert_eq!(resolver.0.load(Ordering::Relaxed), 0);
                transport.send(datagram(b"one")).await.unwrap();
                partial_ready.await.unwrap();
                let mut receive = Box::pin(transport.receive());
                assert!(futures_util::poll!(&mut receive).is_pending());
                drop(receive);
                resume.send(()).unwrap();
                let empty = transport.receive().await.unwrap();
                assert_eq!(empty.remote, Destination::Ip("[::1]:54".parse().unwrap()));
                assert!(empty.payload.is_empty());
                let response = transport.receive().await.unwrap();
                assert_eq!(
                    response.remote,
                    Destination::Ip("198.51.100.9:55".parse().unwrap())
                );
                assert_eq!(response.payload.as_ref(), b"one");
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
                transport.send(datagram(b"two")).await.unwrap();
                assert_eq!(resolver.0.load(Ordering::Relaxed), 2);
                remote.await.unwrap();
                transport.close().await.unwrap();
                transport.close().await.unwrap();
                assert!(!cancellation.is_cancelled());
                drop(transport);
                tasks.close();
                tasks.wait().await;
            }),
        )
        .await
        .expect("TrustTunnel UDP memory operation must finish");
        assert!(probe.snapshot().is_idle());
    }

    #[tokio::test]
    async fn trusttunnel_udp_invalid_length_and_partial_send_release_owned_io() {
        let probe = ResourceProbe::default();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            probe.scope(async {
                let tasks = TaskTracker::new();
                let context = EstablishContext::default();
                let parent = CancellationToken::new();
                let (io, mut peer) = tokio::io::duplex(64);
                let mut malformed = PacketTransport::new(
                    Box::new(io),
                    &request(3),
                    &context,
                    parent.clone(),
                    |future| Ok(tasks.spawn(crate::resources::observation::task(future))),
                )
                .unwrap();
                // A huge length is rejected immediately, without waiting for or
                // allocating the claimed body.
                peer.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
                assert!(malformed.receive().await.is_err());
                malformed.close().await.unwrap();
                drop(malformed);

                let (io, mut peer) = tokio::io::duplex(1);
                let mut cancelled = PacketTransport::new(
                    Box::new(io),
                    &request(3),
                    &context,
                    parent.clone(),
                    |future| Ok(tasks.spawn(crate::resources::observation::task(future))),
                )
                .unwrap();
                let mut packet = datagram(b"one");
                packet.remote = Destination::Ip("192.0.2.10:53".parse().unwrap());
                let mut send = Box::pin(cancelled.send(packet.clone()));
                assert!(futures_util::poll!(&mut send).is_pending());
                drop(send);
                let mut partial = Vec::new();
                peer.read_to_end(&mut partial).await.unwrap();
                assert_eq!(partial.len(), 1);
                assert!(cancelled.send(packet).await.is_err());
                cancelled.close().await.unwrap();
                drop(cancelled);
                assert!(!parent.is_cancelled());
                tasks.close();
                tasks.wait().await;
            }),
        )
        .await
        .expect("TrustTunnel UDP memory operation must finish");
        assert!(probe.snapshot().is_idle());
    }
}
