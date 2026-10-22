use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::Socks5Server;
#[cfg(feature = "inbound-http")]
use crate::{config::MixedInboundConfig, inbound::mixed::MixedServer};
use crate::{
    config::{ProxyAccess, ProxyCredentials, Socks5InboundConfig},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
    socks5,
};

const WAIT: Duration = Duration::from_secs(3);

#[derive(Default)]
struct Peers {
    streams: Mutex<VecDeque<DuplexStream>>,
    destinations: Mutex<Vec<Destination>>,
    sessions: Mutex<Vec<DatagramSession>>,
    live: Arc<AtomicUsize>,
    blocked_source: Mutex<Option<SocketAddr>>,
    blocked_open: Arc<AtomicUsize>,
    block_send: AtomicBool,
}

struct Live(Arc<AtomicUsize>);
impl Live {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Echo {
    pending: VecDeque<Datagram>,
    _live: Live,
    block_send: bool,
    blocked: Arc<AtomicUsize>,
}

#[async_trait]
impl DatagramTransport for Echo {
    fn supports_shared_destinations(&self) -> bool {
        false
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.block_send {
            self.blocked.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        self.pending.push_back(datagram);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        match self.pending.pop_front() {
            Some(value) => Ok(value),
            None => std::future::pending().await,
        }
    }
}

#[async_trait]
impl Dispatcher for Peers {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        assert_eq!(session.inbound, InboundKind::Socks5);
        self.destinations.lock().unwrap().push(session.destination);
        self.streams
            .lock()
            .unwrap()
            .pop_front()
            .map(|stream| Box::new(stream) as BoxStream)
            .ok_or(DispatchError::ConnectionRefused)
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        assert_eq!(session.inbound, InboundKind::Socks5);
        let source = session.source;
        self.sessions.lock().unwrap().push(session);
        let live = Live::new(self.live.clone());
        let blocked = *self.blocked_source.lock().unwrap() == Some(source);
        let block_send = self.block_send.load(Ordering::SeqCst);
        if blocked && !block_send {
            self.blocked_open.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        Ok(Box::new(Echo {
            pending: VecDeque::new(),
            _live: live,
            block_send: blocked && block_send,
            blocked: self.blocked_open.clone(),
        }))
    }
}

struct Fixture {
    addresses: Vec<SocketAddr>,
    peers: Arc<Peers>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    auth: bool,
}

impl Fixture {
    async fn new(authenticated: bool, ipv6: bool, lan: bool) -> Self {
        let peers = Arc::new(Peers::default());
        let config = Socks5InboundConfig {
            tag: "socks".into(),
            port: 0,
            access: ProxyAccess {
                bind_address: None,
                allow_lan: lan,
                ipv6,
            },
            auth: authenticated.then(auth),
        };
        #[cfg(feature = "inbound-http")]
        let server = MixedServer::bind(
            MixedInboundConfig {
                access_rules: Default::default(),
                tag: config.tag,
                port: config.port,
                access: config.access,
                auth: config.auth,
            },
            peers.clone(),
        )
        .unwrap();
        #[cfg(not(feature = "inbound-http"))]
        let server = Socks5Server::bind(config, peers.clone()).unwrap();
        let addresses = server.local_addrs().unwrap();
        let cancellation = CancellationToken::new();
        let task = Some(tokio::spawn(server.serve(cancellation.clone())));
        Self {
            addresses,
            peers,
            cancellation,
            task,
            auth: authenticated,
        }
    }
    fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.addresses[0].port()))
    }
    async fn client(&self) -> TcpStream {
        timeout(WAIT, TcpStream::connect(self.address()))
            .await
            .unwrap()
            .unwrap()
    }
    async fn associate(&self, requested: SocketAddr) -> (TcpStream, u8, SocketAddr) {
        let mut stream = self.client().await;
        login(&mut stream, self.auth).await;
        command(&mut stream, 3, &Destination::Ip(requested)).await;
        let (status, bound) = response(&mut stream).await;
        (stream, status, bound)
    }
    async fn stop(mut self) {
        self.cancellation.cancel();
        timeout(WAIT, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(self.peers.live.load(Ordering::SeqCst), 0);
        for address in &self.addresses {
            drop(crate::inbound::listen::bind_tcp(*address).unwrap());
            drop(crate::inbound::listen::bind_udp(*address).unwrap());
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn auth() -> ProxyCredentials {
    ProxyCredentials::new("fixture", "password").unwrap()
}

async fn exact(stream: &mut TcpStream, expected: &[u8]) {
    let mut buffer = vec![0; expected.len()];
    timeout(WAIT, stream.read_exact(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(buffer, expected);
}

async fn login(stream: &mut TcpStream, authenticated: bool) {
    // Deliberately split every byte, including the method and credentials.
    let method = if authenticated { 2 } else { 0 };
    for byte in [5, 1, method] {
        stream.write_all(&[byte]).await.unwrap();
        tokio::task::yield_now().await;
    }
    exact(stream, &[5, method]).await;
    if authenticated {
        for byte in b"\x01\x07fixture\x08password" {
            stream.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        exact(stream, &[1, 0]).await;
    }
}

async fn command(stream: &mut TcpStream, command: u8, target: &Destination) {
    let mut request = vec![5, command, 0];
    socks5::encode_address(target, &mut request).unwrap();
    stream.write_all(&request).await.unwrap();
}

async fn response(stream: &mut TcpStream) -> (u8, SocketAddr) {
    let mut head = [0; 3];
    timeout(WAIT, stream.read_exact(&mut head))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((head[0], head[2]), (5, 0));
    let Destination::Ip(address) = timeout(WAIT, socks5::read_destination(stream, true))
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("IP reply required")
    };
    (head[1], address)
}

async fn udp_echo(
    socket: &UdpSocket,
    relay: SocketAddr,
    destination: &Destination,
    payload: &[u8],
) {
    let packet = socks5::encode_udp_packet(destination, payload, 65507).unwrap();
    socket.send_to(&packet, relay).await.unwrap();
    let mut buffer = vec![0; 65508];
    let (length, from) = timeout(WAIT, socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, relay);
    let (actual, body) = socks5::decode_udp_packet(&buffer[..length], 65507).unwrap();
    assert_eq!(&actual, destination);
    assert_eq!(body, payload);
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    timeout(WAIT, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_preserves_all_addresses_early_bytes_and_half_close() {
    for authenticated in [false, true] {
        let fixture = Fixture::new(authenticated, true, false).await;
        for target in [
            Destination::from("127.0.0.1:80".parse::<SocketAddr>().unwrap()),
            Destination::from("[::1]:443".parse::<SocketAddr>().unwrap()),
            Destination::domain("unresolved.invalid", 443).unwrap(),
        ] {
            let (local, mut remote) = tokio::io::duplex(64);
            fixture.peers.streams.lock().unwrap().push_back(local);
            let mut client = fixture.client().await;
            login(&mut client, authenticated).await;
            command(&mut client, 1, &target).await;
            client.write_all(b"early").await.unwrap();
            assert_eq!(response(&mut client).await.0, 0);
            client.shutdown().await.unwrap();
            let mut request = Vec::new();
            timeout(WAIT, remote.read_to_end(&mut request))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request, b"early");
            remote.write_all(b"after-half-close").await.unwrap();
            remote.shutdown().await.unwrap();
            let mut reply = Vec::new();
            timeout(WAIT, client.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, b"after-half-close");
            assert_eq!(
                fixture.peers.destinations.lock().unwrap().last(),
                Some(&target)
            );
        }
        fixture.stop().await;
    }
}

#[tokio::test]
async fn auth_methods_wrong_password_and_commands_fail_without_upstream() {
    for authenticated in [false, true] {
        let fixture = Fixture::new(authenticated, false, false).await;
        let mut client = fixture.client().await;
        client
            .write_all(&[5, 1, if authenticated { 0 } else { 2 }])
            .await
            .unwrap();
        exact(&mut client, &[5, 255]).await;
        if authenticated {
            let mut client = fixture.client().await;
            client.write_all(&[5, 1, 2]).await.unwrap();
            exact(&mut client, &[5, 2]).await;
            client.write_all(b"\x01\x07fixture\x05wrong").await.unwrap();
            exact(&mut client, &[1, 1]).await;
        }
        let mut client = fixture.client().await;
        login(&mut client, authenticated).await;
        client.write_all(&[5, 2, 0]).await.unwrap();
        assert_eq!(response(&mut client).await.0, 7);
        assert!(fixture.peers.destinations.lock().unwrap().is_empty());
        assert!(fixture.peers.sessions.lock().unwrap().is_empty());
        let mut client = fixture.client().await;
        login(&mut client, authenticated).await;
        command(
            &mut client,
            1,
            &Destination::from("127.0.0.1:1".parse::<SocketAddr>().unwrap()),
        )
        .await;
        assert_eq!(response(&mut client).await.0, 5);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn udp_learns_one_source_routes_multiple_targets_and_revokes_at_control_eof() {
    let fixture = Fixture::new(true, false, true).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (control, status, relay) = fixture.associate("0.0.0.0:0".parse().unwrap()).await;
    assert_eq!(status, 0);
    assert_eq!(relay, fixture.address());
    let (ambiguous, status, _) = fixture.associate("0.0.0.0:0".parse().unwrap()).await;
    assert_eq!(status, 2);
    drop(ambiguous);
    for target in [
        Destination::from("127.0.0.1:53".parse::<SocketAddr>().unwrap()),
        Destination::domain("route-only.invalid", 123).unwrap(),
    ] {
        udp_echo(&socket, relay, &target, b"udp-payload").await;
    }
    assert_eq!(
        fixture.peers.sessions.lock().unwrap()[0].source,
        socket.local_addr().unwrap()
    );
    drop(control);
    eventually(|| fixture.peers.live.load(Ordering::SeqCst) == 0).await;
    let target = Destination::domain("route-only.invalid", 53).unwrap();
    let packet = socks5::encode_udp_packet(&target, b"revoked", 65507).unwrap();
    socket.send_to(&packet, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(50), socket.recv(&mut [0; 512]))
            .await
            .is_err()
    );
    let (new_control, status, _) = fixture.associate(socket.local_addr().unwrap()).await;
    assert_eq!(status, 0);
    udp_echo(&socket, relay, &target, b"new-generation").await;
    assert_eq!(fixture.peers.sessions.lock().unwrap().len(), 2);
    fixture.stop().await;
    drop(new_control);
}

#[tokio::test]
async fn unauthorized_malformed_wrong_source_and_third_party_requests_are_rejected() {
    let fixture = Fixture::new(false, false, false).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::domain("fixture.invalid", 80).unwrap();
    let packet = socks5::encode_udp_packet(&target, b"unauthorized", 65507).unwrap();
    socket.send_to(&packet, fixture.address()).await.unwrap();
    let (_, status, _) = fixture.associate("192.0.2.1:1234".parse().unwrap()).await;
    assert_eq!(status, 2);
    let (control, status, relay) = fixture.associate(socket.local_addr().unwrap()).await;
    assert_eq!(status, 0);
    let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    foreign.send_to(&packet, relay).await.unwrap();
    for malformed in [
        vec![0],
        vec![0, 0, 1, 1],
        vec![1, 0, 0, 1],
        vec![0, 0, 0, 99],
    ] {
        socket.send_to(&malformed, relay).await.unwrap();
    }
    assert!(
        timeout(Duration::from_millis(50), socket.recv(&mut [0; 512]))
            .await
            .is_err()
    );
    assert!(fixture.peers.sessions.lock().unwrap().is_empty());
    udp_echo(&socket, relay, &target, b"authorized").await;
    drop(control);
    fixture.stop().await;
}

#[tokio::test]
async fn bound_ports_are_isolated_and_slow_open_cannot_block_global_udp_or_stop() {
    for block_send in [false, true] {
        let fixture = Fixture::new(false, false, false).await;
        fixture.peers.block_send.store(block_send, Ordering::SeqCst);
        let blocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ready = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (control_a, status, relay) = fixture.associate(blocked.local_addr().unwrap()).await;
        assert_eq!(status, 0);
        let (control_b, status, _) = fixture.associate(ready.local_addr().unwrap()).await;
        assert_eq!(status, 0);
        *fixture.peers.blocked_source.lock().unwrap() = Some(blocked.local_addr().unwrap());
        let target = Destination::domain("fixture.invalid", 80).unwrap();
        let packet = socks5::encode_udp_packet(&target, b"slow", 65507).unwrap();
        for _ in 0..64 {
            blocked.send_to(&packet, relay).await.unwrap();
        }
        eventually(|| fixture.peers.blocked_open.load(Ordering::SeqCst) == 1).await;
        udp_echo(&ready, relay, &target, b"independent").await;
        drop(control_a);
        eventually(|| fixture.peers.live.load(Ordering::SeqCst) == 1).await;
        // Stop owns pending handshakes, active transports and both TCP controls.
        fixture.stop().await;
        drop(control_b);
    }
}

#[tokio::test]
async fn dual_stack_udp_and_tcp_share_port_and_failed_udp_bind_releases_tcp() {
    let fixture = Fixture::new(false, true, false).await;
    if let Some(address) = fixture.addresses.iter().find(|address| address.is_ipv6()) {
        let mut control = TcpStream::connect(address).await.unwrap();
        login(&mut control, false).await;
        command(&mut control, 3, &Destination::Ip("[::]:0".parse().unwrap())).await;
        let (status, relay) = response(&mut control).await;
        assert_eq!(status, 0);
        assert_eq!(&relay, address);
        let socket = UdpSocket::bind("[::1]:0").await.unwrap();
        udp_echo(
            &socket,
            relay,
            &Destination::Ip("[::1]:53".parse().unwrap()),
            b"v6",
        )
        .await;
    }
    fixture.stop().await;
    let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let config = Socks5InboundConfig {
        tag: "test".into(),
        port: address.port(),
        access: ProxyAccess {
            bind_address: None,
            allow_lan: false,
            ipv6: false,
        },
        auth: None,
    };
    assert_eq!(
        Socks5Server::bind(config, Arc::new(Peers::default()))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::AddrInUse
    );
    drop(crate::inbound::listen::bind_tcp(address).unwrap());
}
