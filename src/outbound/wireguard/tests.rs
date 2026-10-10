//! Actual Noise handshake and raw TCP/UDP over bounded memory IO.
use super::*;
use crate::{
    dispatch::DatagramBudget,
    resources::observation::{ResourceKind, ResourceProbe},
    session::{Datagram, InboundKind, InboundMetadata},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519,
};
use bytes::Bytes;
use std::{
    collections::VecDeque,
    future::pending,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};
use vole_netstack::{
    NetStack, NetStackConfig, NetStackControl, Packet, PacketSink, PacketStream, TcpNetStackParts,
    UdpDatagram, encode_udp_packet_into, parse_udp_packet_view,
};

const ENDPOINT: &str = "198.51.100.1:51820";
const SECOND: &str = "198.51.100.2:51820";
fn config() -> WireGuardOutboundConfig {
    config_with_peer(2)
}
fn config_with_peer(peer_secret: u8) -> WireGuardOutboundConfig {
    let client = STANDARD.encode([1u8; 32]);
    let peer = STANDARD
        .encode(x25519::PublicKey::from(&x25519::StaticSecret::from([peer_secret; 32])).as_bytes());
    let yaml = format!(
        "mixed-port: 1080\nproxies: [{{name: wg, type: wireguard, server: 198.51.100.1, port: 51820, ip: 10.0.0.2/24, ipv6: 'fd00::2/64', private-key: '{client}', public-key: '{peer}', udp: true}}]\nrules: ['MATCH,wg']"
    );
    let parsed = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
    let crate::config::ProxyProtocol::WireGuard(config) = parsed.proxies[0].protocol.clone() else {
        panic!()
    };
    config
}
fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(1080),
        inbound: InboundKind::Https,
        source: "192.0.2.1:20000".parse().unwrap(),
        destination: Destination::Ip("10.0.0.1:80".parse().unwrap()),
        sniffed_domain: None,
    }
}

struct Peer {
    multi: bool,
    reserved: bool,
    records: Arc<Mutex<Vec<Destination>>>,
    dns_queries: Arc<AtomicUsize>,
    silent: bool,
    silent_first: bool,
    sends: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}
#[async_trait]
impl OutboundConnector for Peer {
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
        let TcpNetStackParts {
            packet_sink,
            packet_stream,
            mut tcp_listener,
            control,
            ..
        } = NetStack::start_tcp(NetStackConfig {
            mtu: 1408,
            ..Default::default()
        })
        .unwrap();
        let echo = observation::spawn(async move {
            if let Some(mut stream) = tcp_listener.accept().await {
                let mut bytes = [0; 4];
                if stream.read_exact(&mut bytes).await.is_ok() {
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            }
        });
        Ok(Box::new(MemoryPeer {
            endpoint: None,
            multi: self.multi,
            reserved: self.reserved,
            records: self.records.clone(),
            dns_queries: self.dns_queries.clone(),
            tunn: Tunn::new(
                x25519::StaticSecret::from([2; 32]),
                x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32])),
                None,
                None,
                2,
                None,
            ),
            sink: packet_sink,
            packets: packet_stream,
            control,
            echo: Some(echo),
            network: VecDeque::new(),
            silent: self.silent,
            silent_first: self.silent_first,
            sends: self.sends.clone(),
            closes: self.closes.clone(),
            scratch: vec![0; 1440],
        }))
    }
}
struct MemoryPeer {
    endpoint: Option<Destination>,
    multi: bool,
    reserved: bool,
    records: Arc<Mutex<Vec<Destination>>>,
    dns_queries: Arc<AtomicUsize>,
    tunn: Tunn,
    sink: PacketSink,
    packets: PacketStream,
    control: NetStackControl,
    echo: Option<JoinHandle<()>>,
    network: VecDeque<Bytes>,
    silent: bool,
    silent_first: bool,
    sends: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
    scratch: Vec<u8>,
}
impl MemoryPeer {
    fn network(&mut self, result: TunnResult<'_>) -> Option<Vec<u8>> {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                let mut packet = packet.to_vec();
                if self.reserved {
                    packet[1..4].copy_from_slice(&[7, 8, 9]);
                }
                self.network.push_back(Bytes::from(packet));
                None
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                Some(packet.to_vec())
            }
            TunnResult::Done => None,
            TunnResult::Err(error) => panic!("memory peer rejected protocol: {error:?}"),
        }
    }
    async fn decrypt(&mut self, packet: &[u8]) -> Result<(), DispatchError> {
        // Separate scratch permits the result borrow while updating fixture queues.
        let mut scratch = std::mem::take(&mut self.scratch);
        let result = self.tunn.decapsulate(None, packet, &mut scratch);
        let raw = self.network(result);
        self.scratch = scratch;
        if let Some(raw) = raw {
            if let Some(udp) = parse_udp_packet_view(&raw) {
                let payload = if self.multi && udp.destination.port() == 53 {
                    self.dns_queries.fetch_add(1, Ordering::Relaxed);
                    let query = crate::dns::parse_query(udp.payload).unwrap();
                    assert_eq!(query.question.name, "remote.example");
                    let mut wire = udp.payload.to_vec();
                    wire[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                    wire[6..8].copy_from_slice(&1u16.to_be_bytes());
                    wire.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 1, 0, 1,
                    ]);
                    Bytes::from(wire)
                } else {
                    Bytes::copy_from_slice(udp.payload)
                };
                let datagram = UdpDatagram::new(udp.destination, udp.source, payload);
                let mut response = Vec::with_capacity(1408);
                encode_udp_packet_into(&datagram, 1408, &mut response).unwrap();
                self.encrypt(&response);
            } else {
                self.sink
                    .send(Packet::new(raw))
                    .await
                    .map_err(|_| DispatchError::ConnectionRefused)?;
            }
        }
        loop {
            let mut scratch = std::mem::take(&mut self.scratch);
            let result = self.tunn.decapsulate(None, &[], &mut scratch);
            let done = matches!(result, TunnResult::Done);
            let _ = self.network(result);
            self.scratch = scratch;
            if done {
                break;
            }
        }
        Ok(())
    }
    fn encrypt(&mut self, packet: &[u8]) {
        let mut scratch = std::mem::take(&mut self.scratch);
        let result = self.tunn.encapsulate(packet, &mut scratch);
        let _ = self.network(result);
        self.scratch = scratch;
    }
}
#[async_trait]
impl DatagramTransport for MemoryPeer {
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1440, 1440)
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.endpoint.is_none() {
            assert!(
                datagram.remote == Destination::Ip(ENDPOINT.parse().unwrap())
                    || datagram.remote == Destination::Ip(SECOND.parse().unwrap())
            );
            self.endpoint = Some(datagram.remote.clone());
            if self.multi && datagram.remote == Destination::Ip(SECOND.parse().unwrap()) {
                self.tunn = Tunn::new(
                    x25519::StaticSecret::from([3; 32]),
                    x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32])),
                    None,
                    None,
                    3,
                    None,
                );
            }
        }
        assert_eq!(self.endpoint.as_ref(), Some(&datagram.remote));
        if self.reserved {
            assert_eq!(
                &datagram.payload[1..4],
                if self.multi && datagram.remote == Destination::Ip(SECOND.parse().unwrap()) {
                    &[4, 5, 6]
                } else {
                    &[1, 2, 3]
                }
            );
        }
        self.records.lock().unwrap().push(datagram.remote.clone());
        self.sends.fetch_add(1, Ordering::Relaxed);
        if !self.silent
            && !(self.silent_first && datagram.remote == Destination::Ip(ENDPOINT.parse().unwrap()))
        {
            let mut wire = datagram.payload.to_vec();
            wire[1..4].fill(0);
            self.decrypt(&wire).await?;
        }
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            if let Some(payload) = self.network.pop_front() {
                return Ok(Datagram {
                    remote: self.endpoint.clone().unwrap(),
                    payload,
                    sniffed_domain: None,
                });
            }
            if self.silent
                || (self.silent_first
                    && self.endpoint == Some(Destination::Ip(ENDPOINT.parse().unwrap())))
            {
                return pending().await;
            }
            let packet = self
                .packets
                .recv()
                .await
                .ok_or(DispatchError::ConnectionRefused)?;
            self.encrypt(packet.data());
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.control.stop().await;
        if let Some(echo) = self.echo.take() {
            let _ = echo.await;
        }
        self.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
impl Drop for MemoryPeer {
    fn drop(&mut self) {
        self.control.cancel();
        if let Some(echo) = self.echo.take() {
            echo.abort();
        }
    }
}

fn outbound(silent: bool) -> (Arc<WireGuardOutbound>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let sends = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let peer = Arc::new(Peer {
        multi: false,
        reserved: false,
        records: Arc::default(),
        dns_queries: Arc::default(),
        silent,
        silent_first: false,
        sends: sends.clone(),
        closes: closes.clone(),
    });
    (
        Arc::new(WireGuardOutbound::new_with_path(&config(), UpstreamPath::Proxy(peer)).unwrap()),
        sends,
        closes,
    )
}

#[tokio::test]
async fn wireguard_memory_noise_tcp_dual_stack_udp_and_stop_release() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let (outbound, _, closes) = outbound(false);
            let context = EstablishContext::with_timeout(Duration::from_secs(2));
            let mut connected = outbound.connect_stream(session(), &context).await.unwrap();
            connected.io.write_all(b"test").await.unwrap();
            let mut echoed = [0; 4];
            tokio::time::timeout(Duration::from_secs(2), connected.io.read_exact(&mut echoed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&echoed, b"test");
            assert_eq!(connected.effective_peer, session().destination);
            let request =
                DatagramRequest::new(DatagramSession::new(InboundKind::Socks5, session().source))
                    .with_max_response_payload_size(1200);
            let mut udp = outbound.open_datagram(request, &context).await.unwrap();
            assert_eq!(udp.payload_budget(&session().destination).receive(), 1200);
            for remote in ["10.0.0.1:53", "[fd00::1]:53"] {
                let remote = Destination::Ip(remote.parse().unwrap());
                udp.send(Datagram {
                    remote: remote.clone(),
                    payload: Bytes::from_static(b"udp"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                let reply = tokio::time::timeout(Duration::from_secs(2), udp.receive())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply.remote, remote);
                assert_eq!(reply.payload.as_ref(), b"udp");
            }
            udp.close().await.unwrap();
            drop(udp);
            drop(connected);
            let weak = Arc::downgrade(outbound.current.lock().await.as_ref().unwrap());
            outbound.shutdown().await;
            assert_eq!(closes.load(Ordering::Relaxed), 1);
            assert!(weak.upgrade().is_none());
            assert_eq!(probe.snapshot().current(ResourceKind::Task), 0);
            assert!(probe.snapshot().is_idle());
        })
        .await;
}

#[tokio::test]
async fn wireguard_memory_unanswered_handshake_deadline_drop_and_stop() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let (outbound, sends, closes) = outbound(true);
            let result = outbound
                .connect_stream(
                    session(),
                    &EstablishContext::with_timeout(Duration::from_millis(30)),
                )
                .await;
            assert!(matches!(
                result,
                Err(DispatchError::TimedOut) | Err(DispatchError::ConnectionRefused)
            ));
            assert!(sends.load(Ordering::Relaxed) >= 1);
            // A new generation is published and owned even if its caller disappears.
            tokio::time::sleep(Duration::from_millis(5)).await;
            let second = outbound.clone();
            let task = tokio::spawn(async move {
                second
                    .connect_stream(
                        session(),
                        &EstablishContext::with_timeout(Duration::from_secs(30)),
                    )
                    .await
            });
            // Boringtun uses a real monotonic clock: witness one actual timer retry.
            tokio::time::timeout(Duration::from_secs(7), async {
                while sends.load(Ordering::Relaxed) < 3 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            task.abort();
            let _ = task.await;
            assert!(outbound.current.lock().await.is_some());
            tokio::time::timeout(Duration::from_secs(1), outbound.shutdown())
                .await
                .unwrap();
            assert_eq!(closes.load(Ordering::Relaxed), 2);
            assert!(probe.snapshot().is_idle());
        })
        .await;
}

#[test]
fn wireguard_configuration_keys_prefixes_defaults_and_redaction() {
    let config = config();
    assert_eq!(config.ipv4, Some("10.0.0.2".parse().unwrap()));
    assert_eq!(config.ipv6, Some("fd00::2".parse().unwrap()));
    assert_eq!(config.mtu, 1408);
    assert_eq!(config.refresh_server_ip_interval, 0);
    assert!(config.dns.is_empty());
    let first_key = STANDARD.encode([2; 32]);
    let second_key = STANDARD.encode([3; 32]);
    let shared_key = STANDARD.encode([4; 32]);
    let private_key = STANDARD.encode([1; 32]);
    let yaml = format!(
        "mixed-port: 1080\nproxies:\n  - name: wg\n    type: wireguard\n    ip: 10.0.0.2\n    private-key: '{private_key}'\n    reserved: [1, 2, 3]\n    remote-dns-resolve: true\n    dns: ['dns.example#unused-route']\n    refresh-server-ip-interval: -1\n    peers:\n      - {{server: 198.51.100.1, port: 51820, public-key: '{first_key}', pre-shared-key: '{shared_key}', allowed-ips: ['0.0.0.0/0']}}\n      - {{server: 198.51.100.2, port: 51820, public-key: '{second_key}', reserved: [4, 5, 6], allowed-ips: ['10.1.0.0/16']}}\n      - {{server: 198.51.100.3, port: 51821, public-key: '{first_key}', allowed-ips: ['10.1.7.9/16']}}\nrules: ['MATCH,wg']"
    );
    let parse = |yaml: &str| {
        let parsed = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
        let crate::config::ProxyProtocol::WireGuard(config) = parsed.proxies[0].protocol.clone()
        else {
            panic!()
        };
        config
    };
    let peers = parse(&yaml);
    assert_eq!(peers.peers.len(), 2);
    assert_eq!(peers.address, "198.51.100.3");
    assert_eq!(peers.port, 51821);
    assert_eq!(
        peers.peers[0].pre_shared_key.as_ref().unwrap().bytes(),
        [4; 32]
    );
    assert_eq!(peers.peers[0].reserved, [1, 2, 3]);
    assert_eq!(peers.peers[1].reserved, [4, 5, 6]);
    assert_eq!(peers.refresh_server_ip_interval, -1);
    assert_eq!(peers.dns[0].route, crate::config::DnsRoute::Direct);
    let routes = super::routes::Routes::new(&peers);
    assert_eq!(routes.select("10.1.0.1".parse().unwrap()), Some(0));
    assert_eq!(routes.select("10.2.0.1".parse().unwrap()), Some(0));
    let disabled = parse(
        &yaml
            .replace("remote-dns-resolve: true", "remote-dns-resolve: false")
            .replace("dns.example#unused-route", "invalid://ignored"),
    );
    assert!(disabled.dns.is_empty());
    assert!(!format!("{config:?}").contains(&STANDARD.encode([1u8; 32])));
    let yaml = "mixed-port: 1080\nproxies: [{name: wg, type: wireguard, server: 198.51.100.1, port: 51820, ip: 10.0.0.2, private-key: secret-sentinel, public-key: secret-sentinel}]";
    let error = crate::config::Config::parse_yaml(yaml.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("secret-sentinel"));
}

struct Bootstrap {
    calls: Arc<AtomicUsize>,
    rotating: bool,
}
#[async_trait]
impl crate::dialer::Resolver for Bootstrap {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<crate::dialer::ResolvedEndpoint> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let ip = if self.rotating {
            assert_eq!(host, "rotate.example");
            if self.calls.load(Ordering::Relaxed) == 1 {
                "198.51.100.1"
            } else {
                "198.51.100.2"
            }
        } else {
            assert_eq!(host, "dns.example");
            "10.0.0.1"
        };
        Ok(crate::dialer::ResolvedEndpoint {
            logical_host: host.into(),
            port,
            addresses: vec![std::net::SocketAddr::new(ip.parse().unwrap(), port)],
        })
    }
}
#[tokio::test]
async fn wireguard_peers_longest_prefix_reserved_and_remote_dns_have_owned_io() {
    let probe = ResourceProbe::default();
    probe.scope(async {
        let mut config = config();
        config.ipv6 = None;
        config.peers[0].allowed_ips.retain(|p| p.network.is_ipv4());
        config.routes.retain(|(p, _)| p.network.is_ipv4());
        config.peers[0].reserved = [1, 2, 3];
        let private = STANDARD.encode([1; 32]);
        let public = STANDARD.encode(x25519::PublicKey::from(&x25519::StaticSecret::from([3; 32])).as_bytes());
        let yaml = format!(
            "mixed-port: 1080\nproxies: [{{name: wg, type: wireguard, server: 198.51.100.2, port: 51820, ip: 10.0.0.2, private-key: '{private}', public-key: '{public}'}}]\nrules: ['MATCH,wg']"
        );
        let second = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
        let crate::config::ProxyProtocol::WireGuard(mut second) = second.proxies[0].protocol.clone() else { panic!() };
        let mut peer = second.peers.remove(0);
        peer.reserved = [4, 5, 6];
        peer.allowed_ips = vec![crate::config::IpCidr {
            network: "10.1.0.0".parse().unwrap(), prefix_len: 16,
        }];
        config.routes.push((peer.allowed_ips[0], 1));
        config.peers.push(peer);
        config.dns = vec![crate::config::DnsNameserver {
            transport: crate::config::DnsTransport::Udp,
            address: crate::config::DnsAddress::Domain("dns.example".into()),
            port: 53, route: crate::config::DnsRoute::Direct, path: None,
        }];
        let records = Arc::<Mutex<Vec<Destination>>>::default();
        let closes = Arc::<AtomicUsize>::default();
        let queries = Arc::<AtomicUsize>::default();
        let carrier = Arc::new(Peer {
            multi: true, reserved: true, records: records.clone(),
            dns_queries: queries.clone(), silent: false, silent_first: false,
            sends: Arc::default(), closes: closes.clone(),
        });
        let outbound = WireGuardOutbound::new_with_path(&config, UpstreamPath::Proxy(carrier)).unwrap();
        let calls = Arc::<AtomicUsize>::default();
        let resolution = crate::dns::resolution::ResolutionContext::measurement(
            Arc::new(Bootstrap { calls: calls.clone(), rotating: false }), true,
        );
        let context = EstablishContext::with_resolution(Duration::from_secs(3), resolution);
        let mut request = session();
        request.destination = Destination::domain("remote.example", 80).unwrap();
        let mut connected = outbound.connect_stream(request, &context).await.unwrap();
        connected.io.write_all(b"peer").await.unwrap();
        let mut echoed = [0; 4];
        tokio::time::timeout(Duration::from_secs(2), connected.io.read_exact(&mut echoed)).await.unwrap().unwrap();
        assert_eq!(&echoed, b"peer");
        assert_eq!(connected.effective_peer, Destination::Ip("10.1.0.1:80".parse().unwrap()));
        assert_eq!(queries.load(Ordering::Relaxed), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(records.lock().unwrap().contains(&Destination::Ip(ENDPOINT.parse().unwrap())));
        assert!(records.lock().unwrap().contains(&Destination::Ip(SECOND.parse().unwrap())));
        drop(connected);
        outbound.shutdown().await;
        assert_eq!(closes.load(Ordering::Relaxed), 2);
        assert!(probe.snapshot().is_idle());
    }).await;
}
#[tokio::test]
async fn wireguard_endpoint_refresh_keeps_the_stack_and_releases_old_peer_io() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut config = config();
            config.address = "rotate.example".into();
            config.peers[0].address = config.address.clone();
            config.peers[0].reserved = [1, 2, 3];
            config.refresh_server_ip_interval = 1;
            let records = Arc::<Mutex<Vec<Destination>>>::default();
            let closes = Arc::<AtomicUsize>::default();
            let carrier = Arc::new(Peer {
                multi: false,
                reserved: true,
                records: records.clone(),
                dns_queries: Arc::default(),
                silent: false,
                silent_first: false,
                sends: Arc::default(),
                closes: closes.clone(),
            });
            let outbound =
                WireGuardOutbound::new_with_path(&config, UpstreamPath::Proxy(carrier)).unwrap();
            let calls = Arc::<AtomicUsize>::default();
            let resolution = crate::dns::resolution::ResolutionContext::measurement(
                Arc::new(Bootstrap {
                    calls: calls.clone(),
                    rotating: true,
                }),
                true,
            );
            let context = EstablishContext::with_resolution(Duration::from_secs(4), resolution);
            let request = DatagramRequest::new(DatagramSession::new(
                InboundKind::Socks5,
                "192.0.2.1:23000".parse().unwrap(),
            ));
            let mut udp = outbound.open_datagram(request, &context).await.unwrap();
            let engine = Arc::downgrade(outbound.current.lock().await.as_ref().unwrap());
            let remote = Destination::Ip("10.0.0.1:53".parse().unwrap());
            for payload in [b"old", b"new"] {
                if payload == b"new" {
                    tokio::time::sleep(Duration::from_millis(1010)).await;
                }
                udp.send(Datagram {
                    remote: remote.clone(),
                    payload: Bytes::copy_from_slice(payload),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                let reply = tokio::time::timeout(Duration::from_secs(2), udp.receive())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply.payload.as_ref(), payload);
            }
            assert!(engine.ptr_eq(&Arc::downgrade(
                outbound.current.lock().await.as_ref().unwrap()
            )));
            assert_eq!(calls.load(Ordering::Relaxed), 2);
            assert_eq!(closes.load(Ordering::Relaxed), 1);
            assert!(
                records
                    .lock()
                    .unwrap()
                    .contains(&Destination::Ip(SECOND.parse().unwrap()))
            );
            udp.close().await.unwrap();
            drop(udp);
            outbound.shutdown().await;
            assert_eq!(closes.load(Ordering::Relaxed), 2);
            assert!(probe.snapshot().is_idle());
        })
        .await;
}

#[tokio::test]
async fn wireguard_failed_peer_keeps_other_peer_and_shared_stack_live() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut config = config();
            let mut second = config_with_peer(3).peers.remove(0);
            second.address = "198.51.100.2".into();
            second.allowed_ips = vec![crate::config::IpCidr {
                network: "10.1.0.0".parse().unwrap(),
                prefix_len: 16,
            }];
            config.routes.push((second.allowed_ips[0], 1));
            config.peers.push(second);
            let closes = Arc::<AtomicUsize>::default();
            let carrier = Arc::new(Peer {
                multi: true,
                reserved: false,
                records: Arc::default(),
                dns_queries: Arc::default(),
                silent: false,
                silent_first: true,
                sends: Arc::default(),
                closes: closes.clone(),
            });
            let outbound =
                WireGuardOutbound::new_with_path(&config, UpstreamPath::Proxy(carrier)).unwrap();
            let failed = outbound
                .connect_stream(
                    session(),
                    &EstablishContext::with_timeout(Duration::from_millis(30)),
                )
                .await;
            assert!(matches!(
                failed,
                Err(DispatchError::TimedOut) | Err(DispatchError::ConnectionRefused)
            ));
            let engine = Arc::downgrade(outbound.current.lock().await.as_ref().unwrap());
            let mut request = session();
            request.destination = Destination::Ip("10.1.0.1:80".parse().unwrap());
            let mut stream = outbound
                .connect_stream(
                    request,
                    &EstablishContext::with_timeout(Duration::from_secs(2)),
                )
                .await
                .unwrap();
            stream.io.write_all(b"live").await.unwrap();
            let mut reply = [0; 4];
            tokio::time::timeout(Duration::from_secs(2), stream.io.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply, b"live");
            assert!(engine.ptr_eq(&Arc::downgrade(
                outbound.current.lock().await.as_ref().unwrap()
            )));
            assert!(
                !outbound
                    .current
                    .lock()
                    .await
                    .as_ref()
                    .unwrap()
                    .cancel
                    .is_cancelled()
            );
            drop(stream);
            outbound.shutdown().await;
            assert_eq!(closes.load(Ordering::Relaxed), 2);
            assert!(probe.snapshot().is_idle());
        })
        .await;
}
