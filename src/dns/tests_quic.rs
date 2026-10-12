//! Actual DoQ/H3 over bounded memory datagrams; no OS sockets or DNS sources.
use super::*;
use crate::{
    dispatch::{DatagramBudget, DatagramTransport},
    transport::quic::OwnedRuntime,
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::{
    io::IoSliceMut,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    sync::{Notify, mpsc},
    task::JoinSet,
};

struct Packets {
    sender: mpsc::Sender<Bytes>,
    receiver: mpsc::Receiver<Bytes>,
    peer: SocketAddr,
    silent: bool,
    live: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    budget: DatagramBudget,
    largest_sent: Arc<AtomicUsize>,
}
#[async_trait]
impl DatagramTransport for Packets {
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        self.budget
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        assert_eq!(packet.remote, Destination::Ip(self.peer));
        self.largest_sent
            .fetch_max(packet.payload.len(), Ordering::AcqRel);
        self.sender
            .send(packet.payload)
            .await
            .map_err(|_| DispatchError::NotAllowed)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.silent {
            std::future::pending::<()>().await;
        }
        Ok(Datagram {
            remote: self.peer.into(),
            payload: self
                .receiver
                .recv()
                .await
                .ok_or(DispatchError::NotAllowed)?,
            sniffed_domain: None,
        })
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed.fetch_add(1, Ordering::AcqRel);
        self.receiver.close();
        Ok(())
    }
}
impl Drop for Packets {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct PeerSocket {
    sender: mpsc::Sender<Bytes>,
    receiver: StdMutex<mpsc::Receiver<Bytes>>,
    local: SocketAddr,
    peer: SocketAddr,
    largest_sent: Arc<AtomicUsize>,
}
#[derive(Debug)]
struct Writable(StdMutex<tokio_util::sync::PollSender<Bytes>>);
impl quinn::UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut sender = self.0.lock().unwrap();
        if ready!(sender.poll_reserve(cx)).is_ok() {
            sender.abort_send();
        }
        Poll::Ready(Ok(()))
    }
}
impl quinn::AsyncUdpSocket for PeerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(Writable(StdMutex::new(tokio_util::sync::PollSender::new(
            self.sender.clone(),
        ))))
    }
    fn try_send(&self, packet: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        assert_eq!(packet.destination, self.peer);
        self.largest_sent
            .fetch_max(packet.contents.len(), Ordering::AcqRel);
        match self
            .sender
            .try_send(Bytes::copy_from_slice(packet.contents))
        {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(packet) = ready!(self.receiver.lock().unwrap().poll_recv(cx)) else {
            return Poll::Pending;
        };
        buffers[0][..packet.len()].copy_from_slice(&packet);
        metadata[0] = quinn::udp::RecvMeta {
            addr: self.peer,
            len: packet.len(),
            stride: packet.len(),
            ecn: None,
            dst_ip: Some(self.local.ip()),
        };
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

#[derive(Clone, Copy)]
enum Tcp {
    Http,
    Pending,
}
#[derive(Clone, Copy)]
enum Udp {
    Ready,
    Silent,
    Unavailable,
}
#[derive(Clone, Copy)]
enum H3Reply {
    Normal,
    HoldHeaders,
    HoldBody,
    LargeHeaders,
    Goaway,
}

struct Peer {
    h1: encrypted_tests::Peer,
    tls: rustls::ServerConfig,
    protocol: super::super::quic::Kind,
    tcp: Tcp,
    udp: Udp,
    tcp_calls: AtomicUsize,
    tls_hello: Arc<AtomicUsize>,
    udp_calls: AtomicUsize,
    live: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    udp_budget: DatagramBudget,
    initial_udp_payload: u16,
    h3_reply: H3Reply,
    response_ready: Arc<Notify>,
    response_release: Arc<Notify>,
    rejected: Arc<AtomicUsize>,
    largest_client_sent: Arc<AtomicUsize>,
    largest_server_sent: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    cancel: CancellationToken,
    tasks: StdMutex<Vec<tokio::task::JoinHandle<()>>>,
}
#[async_trait]
impl Dispatcher for Peer {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.tcp_calls.fetch_add(1, Ordering::AcqRel);
        if matches!(self.tcp, Tcp::Http) {
            return self.h1.connect_tcp(session).await;
        }
        let (client, mut peer) = tokio::io::duplex(64 * 1024);
        let hello = self.tls_hello.clone();
        let cancel = self.cancel.clone();
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            if peer.read_u8().await.is_ok() { hello.fetch_add(1, Ordering::AcqRel); }
            let mut sink = tokio::io::sink();
            let _ = tokio::select! { ()=cancel.cancelled()=>Ok(0), result=tokio::io::copy(&mut peer, &mut sink)=>result };
        }));
        Ok(Box::new(client))
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.udp_calls.fetch_add(1, Ordering::AcqRel);
        if matches!(self.udp, Udp::Unavailable) {
            return Err(DispatchError::NotAllowed);
        }
        let peer_address: SocketAddr = "192.0.2.1:853".parse().unwrap();
        let client_address: SocketAddr = "192.0.2.2:1234".parse().unwrap();
        let (to_peer, from_client) = mpsc::channel(32);
        let (to_client, from_peer) = mpsc::channel(32);
        let socket = Arc::new(PeerSocket {
            sender: to_client,
            receiver: StdMutex::new(from_client),
            local: peer_address,
            peer: client_address,
            largest_sent: self.largest_server_sent.clone(),
        });
        let mut tls = self.tls.clone();
        tls.alpn_protocols = vec![if matches!(self.protocol, super::super::quic::Kind::Doq) {
            b"doq".to_vec()
        } else {
            b"h3".to_vec()
        }];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        Arc::get_mut(&mut config.transport)
            .unwrap()
            .initial_mtu(self.initial_udp_payload)
            .min_mtu(self.initial_udp_payload)
            .mtu_discovery_config(None);
        let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
        let mut endpoint_config = quinn::EndpointConfig::default();
        if u64::from(self.udp_budget.transmit()) > endpoint_config.get_max_udp_payload_size() {
            endpoint_config
                .max_udp_payload_size(self.udp_budget.transmit())
                .unwrap();
        }
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(config),
            socket,
            runtime.clone(),
        )
        .unwrap();
        let cancel = self.cancel.clone();
        let protocol = self.protocol;
        let requests = self.requests.clone();
        let reply = self.h3_reply;
        let response_ready = self.response_ready.clone();
        let response_release = self.response_release.clone();
        let rejected = self.rejected.clone();
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            let mut responses = JoinSet::new();
            let serve = async {
                let Ok(connection) = endpoint.accept().await.unwrap().await else {
                    return;
                };
                if matches!(protocol, super::super::quic::Kind::Doq) {
                    while let Ok((mut send, mut receive)) = connection.accept_bi().await {
                        let length = receive.read_u16().await.unwrap() as usize;
                        assert!(length <= MAX_MESSAGE_SIZE);
                        let mut query = vec![0; length];
                        receive.read_exact(&mut query).await.unwrap();
                        assert!(receive.read(&mut [0; 1]).await.unwrap().is_none());
                        let response = response(&query);
                        requests.fetch_add(1, Ordering::AcqRel);
                        send.write_all(&(response.len() as u16).to_be_bytes())
                            .await
                            .unwrap();
                        send.write_all(&response).await.unwrap();
                        send.finish().unwrap();
                    }
                } else {
                    let mut h3 = h3::server::builder()
                        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                    while let Ok(Some(request)) = h3.accept().await {
                        let (request, mut stream) = request.resolve_request().await.unwrap();
                        assert_eq!(request.method(), http::Method::GET);
                        assert_eq!(request.uri().path(), "/dns-query");
                        assert_eq!(request.headers()["authorization"], "Basic YWxpY2U6cHc=");
                        assert!(stream.recv_data().await.unwrap().is_none());
                        use base64::Engine as _;
                        let query = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(request.uri().query().unwrap().strip_prefix("dns=").unwrap())
                            .unwrap();
                        let wire = response(&query);
                        let first = requests.fetch_add(1, Ordering::AcqRel) == 0;
                        if matches!(reply, H3Reply::Goaway) {
                            h3.shutdown(0).await.unwrap();
                        }
                        let response_ready = response_ready.clone();
                        let response_release = response_release.clone();
                        let rejected = rejected.clone();
                        responses.spawn(async move {
                            let held = first && matches!(reply,
                                H3Reply::HoldHeaders | H3Reply::HoldBody | H3Reply::Goaway);
                            if held && matches!(reply, H3Reply::HoldHeaders) {
                                response_ready.notify_one();
                                response_release.notified().await;
                            }
                            let mut headers = http::Response::builder()
                                .status(200)
                                .header("content-type", "application/dns-message");
                            if matches!(reply, H3Reply::LargeHeaders) {
                                headers = headers.header("x-fixture", "x".repeat(8192));
                            }
                            let outcome = async {
                                stream.send_response(headers.body(()).unwrap()).await?;
                                if held && !matches!(reply, H3Reply::HoldHeaders) {
                                    response_ready.notify_one();
                                    response_release.notified().await;
                                }
                                if held && !matches!(reply, H3Reply::Goaway) {
                                    // Exceed one receive window so the peer must
                                    // observe STOP rather than enqueueing a tiny response.
                                    stream.send_data(Bytes::from(vec![0; 128 * 1024])).await?;
                                } else {
                                    stream.send_data(Bytes::from(wire)).await?;
                                }
                                stream.finish().await
                            }.await;
                            if held && !matches!(reply, H3Reply::Goaway) {
                                assert!(matches!(&outcome,
                                    Err(h3::error::StreamError::RemoteTerminate { code })
                                    if code.value() == 0),
                                    "query receive Drop must stop only this peer response: {outcome:?}");
                                rejected.fetch_add(1, Ordering::AcqRel);
                            } else {
                                outcome.unwrap();
                            }
                        });
                    }
                }
            };
            tokio::select! { biased; ()=cancel.cancelled()=>{}, ()=serve=>{} }
            responses.abort_all();
            let mut failure = None;
            while let Some(result) = responses.join_next().await {
                if let Err(error) = result && error.is_panic() && failure.is_none() {
                    failure = Some(error.into_panic());
                }
            }
            endpoint.close(0_u8.into(), b"");
            runtime.stop().await;
            if let Some(failure) = failure { resume_unwind(failure); }
        }));
        self.live.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(Packets {
            sender: to_peer,
            receiver: from_peer,
            peer: peer_address,
            silent: matches!(self.udp, Udp::Silent),
            live: self.live.clone(),
            closed: self.closed.clone(),
            budget: self.udp_budget,
            largest_sent: self.largest_client_sent.clone(),
        }))
    }
}
fn response(query: &[u8]) -> Vec<u8> {
    assert_eq!(&query[..2], &[0, 0]);
    assert_eq!(
        u16::from_be_bytes([query[10], query[11]]),
        1,
        "ECS wrapper survives ID normalization"
    );
    super::super::synthesize_empty_response(&classify_query(query).unwrap(), 0).unwrap()
}
impl Peer {
    fn new(
        protocol: super::super::quic::Kind,
        tcp: Tcp,
        udp: Udp,
    ) -> (Arc<Self>, rustls::RootCertStore) {
        let certificate = rcgen::generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certificate.signing_key.serialize_der().into()),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        (
            Arc::new(Self {
                h1: encrypted_tests::Peer {
                    tls: Arc::new(tls.clone()),
                    https: true,
                    opens: AtomicUsize::new(0),
                    tasks: StdMutex::new(Vec::new()),
                },
                tls,
                protocol,
                tcp,
                udp,
                tcp_calls: AtomicUsize::new(0),
                tls_hello: Arc::new(AtomicUsize::new(0)),
                udp_calls: AtomicUsize::new(0),
                live: Arc::new(AtomicUsize::new(0)),
                closed: Arc::new(AtomicUsize::new(0)),
                udp_budget: DatagramBudget::new(1400, 1400),
                initial_udp_payload: 1200,
                h3_reply: H3Reply::Normal,
                response_ready: Arc::new(Notify::new()),
                response_release: Arc::new(Notify::new()),
                rejected: Arc::new(AtomicUsize::new(0)),
                largest_client_sent: Arc::new(AtomicUsize::new(0)),
                largest_server_sent: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(AtomicUsize::new(0)),
                cancel: CancellationToken::new(),
                tasks: StdMutex::new(Vec::new()),
            }),
            roots,
        )
    }
    async fn stop(&self) {
        self.cancel.cancel();
        let mut failure = None;
        for task in std::mem::take(&mut *self.tasks.lock().unwrap()) {
            if let Err(error) = task.await {
                if error.is_panic() && failure.is_none() {
                    failure = Some(error.into_panic());
                }
            }
        }
        self.h1.join().await;
        if let Some(failure) = failure {
            resume_unwind(failure);
        }
    }
}
fn resolver(
    peer: Arc<Peer>,
    roots: rustls::RootCertStore,
    upstream: &str,
    prefer: bool,
) -> Arc<RuntimeDns> {
    let config = crate::config::Config::parse_yaml(format!("mixed-port: 1080\ndns:\n  enable: true\n  prefer-h3: {prefer}\n  use-system-hosts: false\n  nameserver: ['{upstream}']\n").as_bytes()).unwrap();
    let mut dns = RuntimeDns::new(&config.dns, peer);
    Arc::get_mut(&mut dns.tcp_pool).unwrap().security =
        crate::security::SecurityContext::with_tls_roots(roots);
    Arc::new(dns)
}
async fn two_queries(dns: &RuntimeDns) {
    for (id, name) in [(0x1234, "first.example"), (0x2345, "second.example")] {
        let query = build_query(id, name, QueryType::A).unwrap();
        let wire = dns.exchange(&query).await.unwrap();
        assert_eq!(&wire[..2], &query[..2]);
        validate_response_identity(&parse_query(&query).unwrap(), &wire).unwrap();
    }
}

// Always join both owners before rethrowing a primary assertion or timeout.
async fn checked(peer: &Peer, dns: &RuntimeDns, future: impl Future<Output = ()>) {
    let result = AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(5), future))
        .catch_unwind()
        .await;
    let cleanup = AssertUnwindSafe(async {
        let dns_stopped = tokio::time::timeout(Duration::from_secs(3), dns.shutdown()).await;
        let peer_stopped = tokio::time::timeout(Duration::from_secs(3), peer.stop()).await;
        dns_stopped.unwrap();
        peer_stopped.unwrap();
        assert_eq!(dns.tcp_pool.quic.task_count(), 0);
        assert_eq!(peer.live.load(Ordering::Acquire), 0);
    })
    .catch_unwind()
    .await;
    match result {
        Err(error) => resume_unwind(error),
        Ok(Err(error)) => panic!("DNS memory exchange exceeded its bound: {error}"),
        Ok(Ok(())) => {}
    }
    if let Err(error) = cleanup {
        resume_unwind(error);
    }
}

fn literal_server(dns: &RuntimeDns) -> ResolvedNameserver {
    let config = dns.nameservers[0].clone();
    ResolvedNameserver {
        endpoint: config.endpoint(),
        config,
        physical: None,
        source_generation: 0,
        source_binding: None,
    }
}

async fn wait_until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dns_quic_doq_and_forced_h3_exchange_real_frames_reuse_and_stop() {
    for (kind, endpoint) in [
        (
            super::super::quic::Kind::Doq,
            "quic://192.0.2.1:853#name-cert-verify=dns.example&ecs=192.0.2.1",
        ),
        (
            super::super::quic::Kind::H3,
            "https://alice:pw@192.0.2.1:853/dns-query?discard=value#h3=true&name-cert-verify=dns.example&ecs=192.0.2.1",
        ),
    ] {
        let (peer, roots) = Peer::new(kind, Tcp::Pending, Udp::Ready);
        let dns = resolver(peer.clone(), roots, endpoint, false);
        two_queries(&dns).await;
        assert_eq!(peer.requests.load(Ordering::Acquire), 2);
        assert_eq!(peer.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(peer.tcp_calls.load(Ordering::Acquire), 0);
        dns.shutdown().await;
        assert_eq!(dns.tcp_pool.quic.task_count(), 0);
        assert_eq!(peer.live.load(Ordering::Acquire), 0);
        assert_eq!(peer.closed.load(Ordering::Acquire), 1);
        peer.stop().await;
    }
}

#[tokio::test]
async fn dns_quic_directional_mtu_keeps_initial_small_and_receives_larger_peer_packets() {
    for (kind, upstream) in [
        (
            super::super::quic::Kind::Doq,
            "quic://192.0.2.1:853#name-cert-verify=dns.example&ecs=192.0.2.1",
        ),
        (
            super::super::quic::Kind::H3,
            "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example&ecs=192.0.2.1",
        ),
    ] {
        let (mut peer, roots) = Peer::new(kind, Tcp::Pending, Udp::Ready);
        let config = Arc::get_mut(&mut peer).unwrap();
        config.udp_budget = DatagramBudget::new(1200, 4096);
        config.initial_udp_payload = 1280;
        let dns = resolver(peer.clone(), roots, upstream, false);
        checked(&peer, &dns, async {
            two_queries(&dns).await;
            assert_eq!(peer.requests.load(Ordering::Acquire), 2);
            assert_eq!(peer.udp_calls.load(Ordering::Acquire), 1);
            let client_payload = peer.largest_client_sent.load(Ordering::Acquire);
            assert!((1..=1200).contains(&client_payload));
            assert!(peer.largest_server_sent.load(Ordering::Acquire) >= 1280);
        })
        .await;
    }
}

#[cfg(feature = "outbound-wireguard")]
#[tokio::test]
async fn dns_quic_private_node_preserves_forced_h3_wrappers_and_stop() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let config = crate::config::Config::parse_yaml(format!(
        "mixed-port: 1080\ndns: {{prefer-h3: true}}\nproxies: [{{name: wg, type: wireguard, server: 198.51.100.1, port: 51820, ip: 10.0.0.2, private-key: '{}', public-key: '{}', remote-dns-resolve: true, dns: ['https://alice:pw@192.0.2.1:853/dns-query#undeclared%26h3=true%26name-cert-verify=dns.example%26ecs=192.0.2.1%26disable-ipv6=true']}}]",
        STANDARD.encode([1; 32]), STANDARD.encode([2; 32])
    ).as_bytes()).unwrap();
    assert!(config.dns.prefer_h3);
    let crate::config::ProxyProtocol::WireGuard(node) = &config.proxies[0].protocol else {
        panic!("expected WireGuard")
    };
    // Match the production private-resolver construction; global DNS options
    // are not copied into this node's independently owned configuration.
    let private = crate::config::DnsConfig {
        enable: true,
        ipv6: true,
        nameservers: node.dns.clone(),
        use_hosts: false,
        use_system_hosts: false,
        ..Default::default()
    };
    let (peer, roots) = Peer::new(super::super::quic::Kind::H3, Tcp::Pending, Udp::Ready);
    let dns = RuntimeDns::new_for_node(
        &private,
        peer.clone(),
        super::super::resolution::ResolutionContext::default(),
        crate::security::SecurityContext::with_tls_roots(roots),
    );
    assert!(!dns.prefer_h3);
    let blocked = build_query(9, "blocked.example", QueryType::Aaaa).unwrap();
    let blocked = dns.exchange(&blocked).await.unwrap();
    assert_eq!(&blocked[6..12], &[0; 6]);
    assert_eq!(peer.udp_calls.load(Ordering::Acquire), 0);
    two_queries(&dns).await;
    assert_eq!(peer.requests.load(Ordering::Acquire), 2);
    assert_eq!(peer.tcp_calls.load(Ordering::Acquire), 0);
    dns.shutdown().await;
    assert_eq!(dns.tcp_pool.quic.task_count(), 0);
    assert_eq!(peer.live.load(Ordering::Acquire), 0);
    peer.stop().await;
}

#[tokio::test]
async fn dns_quic_prefer_h3_races_success_and_cleans_losers_without_reprobing() {
    for (tcp, udp, expects_h3) in [
        (Tcp::Pending, Udp::Ready, true),
        (Tcp::Http, Udp::Silent, false),
        (Tcp::Http, Udp::Unavailable, false),
    ] {
        let (peer, roots) = Peer::new(super::super::quic::Kind::H3, tcp, udp);
        let dns = resolver(
            peer.clone(),
            roots,
            "https://alice:pw@192.0.2.1:853/dns-query#name-cert-verify=dns.example&ecs=192.0.2.1",
            true,
        );
        two_queries(&dns).await;
        assert_eq!(peer.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(peer.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            peer.requests.load(Ordering::Acquire),
            if expects_h3 { 2 } else { 0 }
        );
        if expects_h3 {
            assert_eq!(peer.tls_hello.load(Ordering::Acquire), 1);
        }
        dns.shutdown().await;
        assert_eq!(peer.live.load(Ordering::Acquire), 0);
        assert_eq!(dns.tcp_pool.quic.task_count(), 0);
        peer.stop().await;
    }
}

#[tokio::test]
async fn dns_quic_forced_failure_does_not_fallback_and_stop_joins_canceled_handshake() {
    let (peer, roots) = Peer::new(super::super::quic::Kind::H3, Tcp::Http, Udp::Unavailable);
    let dns = resolver(
        peer.clone(),
        roots,
        "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example",
        true,
    );
    assert!(dns.resolve("first.example").await.is_err());
    assert_eq!(peer.tcp_calls.load(Ordering::Acquire), 0);
    dns.shutdown().await;
    peer.stop().await;
    for (kind, upstream) in [
        (
            super::super::quic::Kind::Doq,
            "quic://192.0.2.1:853#name-cert-verify=dns.example",
        ),
        (
            super::super::quic::Kind::H3,
            "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example",
        ),
    ] {
        let (peer, roots) = Peer::new(kind, Tcp::Pending, Udp::Silent);
        let dns = resolver(peer.clone(), roots, upstream, false);
        checked(&peer, &dns, async {
            let request_dns = dns.clone();
            let request = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                request_dns.resolve("first.example").await
            }));
            wait_until(|| peer.udp_calls.load(Ordering::Acquire) != 0).await;
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
        })
        .await;
        assert_eq!(peer.closed.load(Ordering::Acquire), 1);
        assert_eq!(peer.requests.load(Ordering::Acquire), 0);
    }
}

#[tokio::test]
async fn dns_quic_h3_canceled_response_preserves_sibling_and_connection() {
    for reply in [H3Reply::HoldHeaders, H3Reply::HoldBody] {
        let (mut peer, roots) = Peer::new(super::super::quic::Kind::H3, Tcp::Pending, Udp::Ready);
        Arc::get_mut(&mut peer).unwrap().h3_reply = reply;
        let dns = resolver(
            peer.clone(),
            roots,
            "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example&ecs=192.0.2.1",
            false,
        );
        checked(&peer, &dns, async {
            let request_dns = dns.clone();
            let query = build_query(1, "cancel.example", QueryType::A).unwrap();
            let request = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                request_dns.exchange(&query).await
            }));
            peer.response_ready.notified().await;
            assert!(
                !request.is_finished(),
                "the peer has withheld the selected response phase"
            );
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
            two_queries(&dns).await;
            assert_eq!(peer.udp_calls.load(Ordering::Acquire), 1);
            assert_eq!(peer.requests.load(Ordering::Acquire), 3);
            peer.response_release.notify_one();
            wait_until(|| peer.rejected.load(Ordering::Acquire) == 1).await;
        })
        .await;
        assert_eq!(peer.closed.load(Ordering::Acquire), 1);
    }
}

#[tokio::test]
async fn dns_quic_h3_large_headers_progress_with_small_stream_credit() {
    let (mut peer, roots) = Peer::new(super::super::quic::Kind::H3, Tcp::Pending, Udp::Ready);
    Arc::get_mut(&mut peer).unwrap().h3_reply = H3Reply::LargeHeaders;
    let dns = resolver(
        peer.clone(),
        roots,
        "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example&ecs=192.0.2.1",
        false,
    );
    checked(&peer, &dns, async {
        // The peer sends an 8192-byte field within the 16KiB header limit,
        // while each native receive stream starts with only 4098-byte credit.
        // Normal SETTINGS/control and two complete response frames must progress.
        two_queries(&dns).await;
        assert_eq!(peer.requests.load(Ordering::Acquire), 2);
        assert_eq!(peer.udp_calls.load(Ordering::Acquire), 1);
    })
    .await;
}

#[tokio::test]
async fn dns_quic_h3_goaway_drains_existing_query_and_opens_new_connection() {
    let (mut peer, roots) = Peer::new(super::super::quic::Kind::H3, Tcp::Pending, Udp::Ready);
    Arc::get_mut(&mut peer).unwrap().h3_reply = H3Reply::Goaway;
    let dns = resolver(
        peer.clone(),
        roots,
        "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example&ecs=192.0.2.1",
        false,
    );
    checked(&peer, &dns, async {
        let server = literal_server(&dns);
        let (key, _) = dns.quic_route(&server).unwrap();
        let old_lease = dns
            .start_quic(&server, super::super::quic::Kind::H3)
            .unwrap()
            .finish()
            .await
            .unwrap();
        let request_dns = dns.clone();
        let first_query = build_query(11, "first.example", QueryType::A).unwrap();
        let request = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            request_dns.exchange(&first_query).await
        }));
        peer.response_ready.notified().await;
        wait_until(|| !dns.tcp_pool.quic.has(&key)).await;
        assert!(
            !request.is_finished(),
            "GOAWAY must not complete or cancel the existing query"
        );
        let query = build_query(12, "second.example", QueryType::A).unwrap();
        let wire = dns.exchange(&query).await.unwrap();
        validate_response_identity(&parse_query(&query).unwrap(), &wire).unwrap();
        assert_eq!(peer.udp_calls.load(Ordering::Acquire), 2);
        peer.response_release.notify_one();
        let wire = request.await.unwrap().unwrap();
        assert_eq!(&wire[..2], &11_u16.to_be_bytes());
        assert_eq!(peer.requests.load(Ordering::Acquire), 2);
        drop(old_lease);
    })
    .await;
    assert_eq!(peer.closed.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn dns_quic_unpublished_h3_initialization_cancel_joins_without_query() {
    let (peer, roots) = Peer::new(super::super::quic::Kind::H3, Tcp::Pending, Udp::Ready);
    let dns = resolver(
        peer.clone(),
        roots,
        "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example",
        false,
    );
    checked(&peer, &dns, async {
        let server = literal_server(&dns);
        let mut pending = dns
            .start_quic(&server, super::super::quic::Kind::H3)
            .unwrap();
        pending.wait_ready().await.unwrap();
        // It has completed TLS/H3 setup, but no lease or query was published.
        pending.cancel().await;
        assert!(dns.cached_quic(&server).unwrap().is_none());
        assert_eq!(peer.live.load(Ordering::Acquire), 0);
        assert_eq!(peer.closed.load(Ordering::Acquire), 1);
        assert_eq!(peer.requests.load(Ordering::Acquire), 0);
    })
    .await;
}

#[tokio::test]
async fn dns_quic_invalid_prepare_budget_closes_unattached_transport() {
    for kind in [super::super::quic::Kind::Doq, super::super::quic::Kind::H3] {
        let (mut peer, roots) = Peer::new(kind, Tcp::Pending, Udp::Ready);
        Arc::get_mut(&mut peer).unwrap().udp_budget = DatagramBudget::new(1199, 1400);
        let upstream = if matches!(kind, super::super::quic::Kind::Doq) {
            "quic://192.0.2.1:853#name-cert-verify=dns.example"
        } else {
            "https://alice:pw@192.0.2.1:853/dns-query#h3=true&name-cert-verify=dns.example"
        };
        let dns = resolver(peer.clone(), roots, upstream, false);
        checked(&peer, &dns, async {
            assert!(dns.resolve("first.example").await.is_err());
            assert_eq!(peer.closed.load(Ordering::Acquire), 1);
            assert_eq!(peer.live.load(Ordering::Acquire), 0);
            assert_eq!(peer.requests.load(Ordering::Acquire), 0);
        })
        .await;
    }
}
