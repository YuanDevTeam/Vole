use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional_with_sizes},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval_at, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Socks5InboundConfig,
    dispatch::{DispatchError, Dispatcher},
    inbound::listen::{bind_proxy_tcp, bind_udp},
    session::{
        Datagram, Destination, InboundKind, InboundMetadata, SOCKS5_UDP_PACKET_LIMIT, StreamSession,
    },
    socks5::{COMMAND_CONNECT, encode_udp_packet},
};

use super::{
    association::{Associations, CLEANUP_INTERVAL, Lease},
    handshake,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const RELAY_BUFFER_SIZE: usize = 4 * 1024;

pub struct Socks5Server {
    listeners: Vec<TcpListener>,
    sockets: Vec<Arc<UdpSocket>>,
    config: Socks5InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
}

impl Socks5Server {
    pub fn bind(config: Socks5InboundConfig, dispatcher: Arc<dyn Dispatcher>) -> io::Result<Self> {
        let listeners = bind_proxy_tcp(config.port, config.access)?;
        // UDP must bind every successfully acquired TCP family. Failure drops
        // all sockets, before either protocol can accept application traffic.
        let sockets = listeners
            .iter()
            .map(|listener| bind_udp(listener.local_addr()?).map(Arc::new))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            listeners,
            sockets,
            config,
            dispatcher,
        })
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.listeners.iter().map(TcpListener::local_addr).collect()
    }

    async fn accept(&self) -> io::Result<(usize, TcpStream, SocketAddr)> {
        let (index, accepted) = match self.listeners.as_slice() {
            [one] => (0, one.accept().await),
            [v4, v6] => {
                tokio::select! { result = v4.accept() => (0, result), result = v6.accept() => (1, result) }
            }
            _ => unreachable!("one or two listener families"),
        };
        accepted.map(|(stream, peer)| (index, stream, peer))
    }

    pub async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let handler = Socks5Handler::new(self.config.clone(), self.dispatcher.clone());
        let mut receivers = JoinSet::new();
        for socket in &self.sockets {
            let socket = socket.clone();
            let handler = handler.clone();
            let child = cancellation.clone();
            receivers.spawn(crate::resources::observation::task(async move {
                handler.receive_udp(socket, child).await
            }));
        }
        let mut connections = JoinSet::new();
        let mut cleanup = interval_at(Instant::now() + CLEANUP_INTERVAL, CLEANUP_INTERVAL);
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break Ok(()),
                ended = receivers.join_next() => break match ended {
                    Some(Ok(Err(error))) => Err(error),
                    _ => Err(io::Error::other("SOCKS5 UDP receiver stopped")),
                },
                joined = connections.join_next(), if !connections.is_empty() => { let _ = joined; },
                _ = cleanup.tick() => handler.cleanup(Instant::now()),
                accepted = self.accept() => {
                    let (index, stream, peer) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                    let socket = self.sockets[index].clone();
                    let handler = handler.clone();
                    let child = cancellation.clone();
                    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
                    connections.spawn(crate::resources::observation::task(async move {
                        let Ok(relay) = stream.local_addr() else { return; };
                        tokio::select! {
                            biased;
                            () = child.cancelled() => {},
                            _ = handler.handle_connection(stream, peer, relay, Some(socket), child.clone(), deadline) => {},
                        }
                    }));
                }
            }
        };
        cancellation.cancel();
        while connections.join_next().await.is_some() {}
        while receivers.join_next().await.is_some() {}
        result
    }
}

async fn timed<F, T>(future: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    timeout(IO_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 operation timed out"))?
}

#[derive(Clone)]
pub(crate) struct Socks5Handler {
    config: Socks5InboundConfig,
    dispatcher: Arc<dyn Dispatcher>,
    registry: Arc<Associations>,
}

#[cfg(all(feature = "inbound-http", feature = "inbound-socks5"))]
pub(crate) const UDP_CLEANUP_INTERVAL: Duration = CLEANUP_INTERVAL;

impl Socks5Handler {
    pub(crate) fn without_auth(mut self) -> Self {
        self.config.auth = None;
        self
    }

    pub(crate) fn new(config: Socks5InboundConfig, dispatcher: Arc<dyn Dispatcher>) -> Self {
        Self {
            config,
            dispatcher,
            registry: Arc::new(Associations::default()),
        }
    }

    pub(crate) fn cleanup(&self, now: Instant) {
        self.registry.cleanup(now);
    }

    pub(crate) async fn receive_udp(
        &self,
        socket: Arc<UdpSocket>,
        cancellation: CancellationToken,
    ) -> io::Result<()> {
        // The sentinel rejects oversized/truncated packets before authorization.
        let mut buffer = vec![0; SOCKS5_UDP_PACKET_LIMIT + 1];
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Ok(()),
                received = socket.recv_from(&mut buffer) => {
                    let (length, source) = received?;
                    self.registry.enqueue(source, &buffer[..length], Instant::now());
                }
            }
        }
    }

    pub(crate) async fn handle_connection<S>(
        &self,
        mut stream: S,
        peer: SocketAddr,
        relay: SocketAddr,
        socket: Option<Arc<UdpSocket>>,
        cancellation: CancellationToken,
        deadline: Instant,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let config = &self.config;
        let dispatcher = self.dispatcher.clone();
        let registry = self.registry.clone();
        let handshake::Negotiated {
            command,
            destination,
            user,
        } = timeout_at(
            deadline,
            handshake::negotiate(&mut stream, config.auth.as_ref()),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))??;
        if !config.access.ipv6
            && matches!(&destination, Destination::Ip(address) if address.is_ipv6())
        {
            timed(handshake::reply(&mut stream, 8, None)).await?;
            return Ok(());
        }
        if command == COMMAND_CONNECT {
            let mut session = StreamSession {
                metadata: InboundMetadata {
                    local_port: relay.port(),
                    user,
                },
                inbound: InboundKind::Socks5,
                source: peer,
                destination,
                sniffed_domain: None,
            };
            let sniff = dispatcher
                .sniff_plan(peer, &session.destination)
                .await
                .map_err(|_| io::Error::other("sniffer rule evaluation failed"))?
                .filter(|plan| plan.tcp_enabled());
            let acknowledged = sniff.is_some();
            let prefix = if let Some(plan) = sniff {
                timed(handshake::reply(&mut stream, 0, None)).await?;
                plan.sniff(&mut stream, &mut session)
                    .await
                    .map_err(|_| io::Error::other("sniffer rule evaluation failed"))?
            } else {
                Vec::new()
            };
            let connected = timeout(IO_TIMEOUT, dispatcher.connect_tcp(session))
                .await
                .unwrap_or(Err(DispatchError::TimedOut));
            match connected {
                Ok(mut upstream) => {
                    if !acknowledged {
                        timed(handshake::reply(&mut stream, 0, None)).await?;
                    }
                    if !prefix.is_empty() {
                        timed(upstream.write_all(&prefix)).await?;
                    }
                    copy_bidirectional_with_sizes(
                        &mut stream,
                        &mut upstream,
                        RELAY_BUFFER_SIZE,
                        RELAY_BUFFER_SIZE,
                    )
                    .await?;
                }
                Err(error) => {
                    if acknowledged {
                        return Err(io::Error::other(error));
                    }
                    timed(handshake::reply(
                        &mut stream,
                        handshake::status(&error),
                        None,
                    ))
                    .await?;
                }
            }
            return Ok(());
        }
        let Some(socket) = socket else {
            timed(handshake::reply(&mut stream, 7, None)).await?;
            return Ok(());
        };
        let requested = match destination {
            Destination::Ip(address)
                if address.ip().is_unspecified() || address.ip() == peer.ip() =>
            {
                address
            }
            _ => {
                timed(handshake::reply(&mut stream, 2, None)).await?;
                return Ok(());
            }
        };
        let (mut lease, receiver) = match registry.register(peer, requested.port(), &cancellation) {
            Ok(value) => value,
            Err(_) => {
                timed(handshake::reply(&mut stream, 2, None)).await?;
                return Ok(());
            }
        };
        lease.metadata = InboundMetadata {
            local_port: socket.local_addr()?.port(),
            user,
        };
        // The accepted socket's concrete local IP is reachable even when the
        // listener was bound to a wildcard. TCP and UDP share this exact port.
        timed(handshake::reply(&mut stream, 0, Some(relay))).await?;
        tokio::select! {
            biased;
            () = lease.cancellation.cancelled() => {},
            _ = read_control(&mut stream) => {},
            _ = relay_datagrams(&lease, receiver, socket, dispatcher, registry) => {},
        }
        // Dropping the lease revokes authorization before the control socket.
        Ok(())
    }
}

async fn read_control<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut buffer = [0; 1024];
    while stream.read(&mut buffer).await? != 0 {}
    Ok(())
}

async fn relay_datagrams(
    lease: &Lease,
    mut receiver: mpsc::Receiver<Datagram>,
    socket: Arc<UdpSocket>,
    dispatcher: Arc<dyn Dispatcher>,
    registry: Arc<Associations>,
) -> io::Result<()> {
    let Some(first) = receiver.recv().await else {
        return Ok(());
    };
    let session = lease.session();
    let response_limit = usize::from(session.max_response_payload_size());
    let mut transport = timeout(IO_TIMEOUT, dispatcher.open_datagram(session))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 UDP open timed out"))?
        .map_err(|_| io::Error::other("SOCKS5 UDP open failed"))?;
    timeout(IO_TIMEOUT, transport.send(first))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(|_| io::Error::other("SOCKS5 UDP send failed"))?;
    loop {
        tokio::select! {
            datagram = receiver.recv() => {
                let Some(datagram) = datagram else { return Ok(()); };
                timeout(IO_TIMEOUT, transport.send(datagram)).await.map_err(|_| io::ErrorKind::TimedOut)?
                    .map_err(|_| io::Error::other("SOCKS5 UDP send failed"))?;
            }
            response = transport.receive() => {
                let response = response.map_err(|_| io::Error::other("SOCKS5 UDP receive failed"))?;
                if response.payload.len() > response_limit { continue; }
                let Ok(packet) = encode_udp_packet(&response.remote, &response.payload, SOCKS5_UDP_PACKET_LIMIT) else { continue; };
                timed(async {
                    loop {
                        socket.writable().await?;
                        match registry.try_reply(lease, &socket, &packet) {
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                            result => return result,
                        }
                    }
                }).await?;
            }
        }
    }
}
