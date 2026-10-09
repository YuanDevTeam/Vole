//! One client port for HTTP and SOCKS5, including TCP-authorized SOCKS5 UDP.
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval_at, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{MixedInboundConfig, Socks5InboundConfig},
    dispatch::Dispatcher,
};

use super::{
    http::{HttpServerConfig, handle_connection_with_deadline},
    listen::{bind_proxy_tcp, bind_udp},
    socks5::{Socks5Handler, UDP_CLEANUP_INTERVAL},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct MixedServer {
    connections: crate::config::ConnectionSettings,
    access_rules: Arc<crate::config::ProxyAccessRules>,
    listeners: Vec<TcpListener>,
    sockets: Vec<Arc<UdpSocket>>,
    http: HttpServerConfig,
    socks: Socks5Handler,
    dispatcher: Arc<dyn Dispatcher>,
}

impl MixedServer {
    pub(crate) fn with_connections(mut self, settings: crate::config::ConnectionSettings) -> Self {
        self.connections = settings;
        self
    }
    pub fn bind(config: MixedInboundConfig, dispatcher: Arc<dyn Dispatcher>) -> io::Result<Self> {
        let http = HttpServerConfig::proxy(config.port, config.access, config.auth.clone())?;
        let listeners = bind_proxy_tcp(config.port, config.access)?;
        // Acquire every TCP/UDP family before accepting either protocol. Any
        // bind failure drops the entire acquired prefix, including TCP.
        let sockets = listeners
            .iter()
            .map(|listener| bind_udp(listener.local_addr()?).map(Arc::new))
            .collect::<io::Result<_>>()?;
        let socks = Socks5Handler::new(
            Socks5InboundConfig {
                tag: config.tag,
                port: config.port,
                access: config.access,
                auth: config.auth,
            },
            dispatcher.clone(),
        );
        Ok(Self {
            connections: crate::config::ConnectionSettings::default(),
            access_rules: config.access_rules,
            listeners,
            sockets,
            http,
            socks,
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
        let mut receivers = JoinSet::new();
        for socket in &self.sockets {
            let socket = socket.clone();
            let socks = self.socks.clone();
            let child = cancellation.clone();
            receivers.spawn(crate::resources::observation::task(async move {
                socks.receive_udp(socket, child).await
            }));
        }
        let mut connections = JoinSet::new();
        let mut cleanup = interval_at(Instant::now() + UDP_CLEANUP_INTERVAL, UDP_CLEANUP_INTERVAL);
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break Ok(()),
                ended = receivers.join_next() => break match ended {
                    Some(Ok(Err(error))) => Err(error),
                    _ => Err(io::Error::other("mixed SOCKS5 UDP receiver stopped")),
                },
                joined = connections.join_next(), if !connections.is_empty() => { let _ = joined; },
                _ = cleanup.tick() => self.socks.cleanup(Instant::now()),
                accepted = self.accept() => {
                    let (index, stream, peer) = match accepted {
                        Ok(value) => value,
                        Err(error) => break Err(error),
                    };
                    if self.connections.apply(&socket2::SockRef::from(&stream)).is_err() { continue; }
                    let relay = match stream.local_addr() {
                        Ok(address) => address,
                        Err(error) => break Err(error),
                    };
                    let connection = MixedConnection {
                        access_rules:self.access_rules.clone(),
                        peer,
                        relay,
                        udp: Some(self.sockets[index].clone()),
                        http: self.http.clone(),
                        socks: self.socks.clone(),
                        dispatcher: self.dispatcher.clone(),
                        cancellation: cancellation.clone(),
                        deadline: Instant::now() + HANDSHAKE_TIMEOUT,
                    };
                    connections.spawn(crate::resources::observation::task(async move {
                        let _ = connection.serve(stream).await;
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

struct MixedConnection {
    access_rules: Arc<crate::config::ProxyAccessRules>,
    peer: SocketAddr,
    relay: SocketAddr,
    udp: Option<Arc<UdpSocket>>,
    http: HttpServerConfig,
    socks: Socks5Handler,
    dispatcher: Arc<dyn Dispatcher>,
    cancellation: CancellationToken,
    deadline: Instant,
}

impl MixedConnection {
    async fn serve<S>(self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let cancellation = self.cancellation.clone();
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Ok(()),
            result = self.serve_inner(stream) => result,
        }
    }

    async fn serve_inner<S>(mut self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.access_rules.permits(self.peer.ip()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if self.access_rules.skips_auth(self.peer.ip()) {
            self.http.auth = None;
            self.socks = self.socks.without_auth();
        }
        // Keep the probed byte in the reader. Both real protocol handlers
        // consume this same reader, so fragmented and pipelined bytes survive.
        let mut stream = BufReader::with_capacity(1, stream);
        let first = timeout_at(self.deadline, stream.fill_buf())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mixed handshake timed out"))??
            .first()
            .copied();
        match first {
            None => Ok(()),
            Some(5) => {
                self.socks
                    .handle_connection(
                        stream,
                        self.peer,
                        self.relay,
                        self.udp,
                        self.cancellation,
                        self.deadline,
                    )
                    .await
            }
            Some(_) => {
                handle_connection_with_deadline(
                    stream,
                    self.peer,
                    self.dispatcher,
                    self.http,
                    self.cancellation,
                    self.deadline,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests;
