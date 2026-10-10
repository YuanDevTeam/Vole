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
fn config() -> WireGuardOutboundConfig {
    let client = STANDARD.encode([1u8; 32]);
    let peer =
        STANDARD.encode(x25519::PublicKey::from(&x25519::StaticSecret::from([2u8; 32])).as_bytes());
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
    silent: bool,
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
            sends: self.sends.clone(),
            closes: self.closes.clone(),
            scratch: vec![0; 1440],
        }))
    }
}
struct MemoryPeer {
    tunn: Tunn,
    sink: PacketSink,
    packets: PacketStream,
    control: NetStackControl,
    echo: Option<JoinHandle<()>>,
    network: VecDeque<Bytes>,
    silent: bool,
    sends: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
    scratch: Vec<u8>,
}
impl MemoryPeer {
    fn network(&mut self, result: TunnResult<'_>) -> Option<Vec<u8>> {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                self.network.push_back(Bytes::copy_from_slice(packet));
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
                let datagram = UdpDatagram::new(
                    udp.destination,
                    udp.source,
                    Bytes::copy_from_slice(udp.payload),
                );
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
        assert_eq!(datagram.remote, Destination::Ip(ENDPOINT.parse().unwrap()));
        self.sends.fetch_add(1, Ordering::Relaxed);
        if !self.silent {
            self.decrypt(&datagram.payload).await?;
        }
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            if let Some(payload) = self.network.pop_front() {
                return Ok(Datagram {
                    remote: Destination::Ip(ENDPOINT.parse().unwrap()),
                    payload,
                    sniffed_domain: None,
                });
            }
            if self.silent {
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
        silent,
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
    assert!(!format!("{config:?}").contains(&STANDARD.encode([1u8; 32])));
    let yaml = "mixed-port: 1080\nproxies: [{name: wg, type: wireguard, server: 198.51.100.1, port: 51820, ip: 10.0.0.2, private-key: secret-sentinel, public-key: secret-sentinel}]";
    let error = crate::config::Config::parse_yaml(yaml.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("secret-sentinel"));
}
