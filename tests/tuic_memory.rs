#![cfg(all(feature = "outbound-tuic", feature = "interop-test"))]
//! Real Quinn over bounded memory packets, never a host network server.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use vole::{
    config::{Config, ProxyProtocol, TuicCongestion, TuicOutboundConfig},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        tuic::TuicOutbound,
    },
    resources::observation::{ResourceKind, ResourceProbe},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};
#[path = "support/memory_quic.rs"]
mod memory_quic;
use memory_quic::{MemoryPackets, MemoryUpstream, PeerSocket};

struct BudgetPackets(MemoryPackets, u16);
#[async_trait::async_trait]
impl DatagramTransport for BudgetPackets {
    fn supports_shared_destinations(&self) -> bool {
        false
    }

    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(self.1, self.1)
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        assert!(packet.payload.len() <= self.1 as usize);
        self.0.send(packet).await
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.0.receive().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.0.close().await
    }
}

fn fixture(
    budget: u16,
    datagrams: bool,
    credit: u32,
    congestion: &str,
) -> (Arc<TuicOutbound>, quinn::Endpoint) {
    fixture_mode(budget, datagrams, credit, congestion, "native")
}

fn fixture_mode(
    budget: u16,
    datagrams: bool,
    credit: u32,
    congestion: &str,
    mode: &str,
) -> (Arc<TuicOutbound>, quinn::Endpoint) {
    let (mut config, packets, endpoint) =
        fixture_parts(budget, datagrams, credit, congestion, mode);
    // These existing pressure/credit fixtures intentionally use small fixed
    // receive credit; the fixed-window policies behave identically here.
    config.stream_window = vole::config::QuicReceiveWindow {
        initial: 256 * 1024,
        maximum: 256 * 1024,
    };
    config.connection_window = vole::config::QuicReceiveWindow {
        initial: 1024 * 1024,
        maximum: 1024 * 1024,
    };
    config.disable_mtu_discovery = true;
    let outbound = TuicOutbound::new_with_path(
        &config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(packets))))),
    )
    .unwrap();
    (Arc::new(outbound), endpoint)
}

fn fixture_parts(
    budget: u16,
    datagrams: bool,
    credit: u32,
    congestion: &str,
    mode: &str,
) -> (TuicOutboundConfig, BudgetPackets, quinn::Endpoint) {
    let server_address = "192.0.2.1:443".parse().unwrap();
    let client_address = "192.0.2.2:1234".parse().unwrap();
    let (to_server, from_client) = mpsc::channel(32);
    let (to_client, from_server) = mpsc::channel(32);
    let packets = BudgetPackets(
        MemoryPackets {
            send: to_server,
            receive: from_server,
            remote: server_address,
        },
        budget,
    );
    let socket = Arc::new(PeerSocket {
        send: to_client,
        receive: Mutex::new(from_client),
        local: server_address,
        remote: client_address,
    });
    let cert = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key.into())
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    Arc::get_mut(&mut config.transport)
        .unwrap()
        .datagram_receive_buffer_size(datagrams.then_some(256 * 1024))
        .send_window(64 * 1024)
        .initial_mtu(budget.max(1200))
        .min_mtu(budget.max(1200))
        .max_concurrent_bidi_streams(credit.into())
        .max_concurrent_uni_streams(2_u32.into())
        .mtu_discovery_config(None);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let yaml = serde_json::json!({"mixed-port":1080,"proxies":[{"name":"peer","type":"tuic","server":"192.0.2.1","port":443,"uuid":"07070707-0707-0707-0707-070707070707","password":" raw\u{0000}context ","sni":"fixture.invalid","skip-cert-verify":true,"congestion-controller":congestion,"udp":true,"udp-relay-mode":mode}],"rules":["MATCH,peer"]});
    let parsed = Config::parse_yaml(yaml.to_string().as_bytes()).unwrap();
    let ProxyProtocol::Tuic(config) = &parsed.proxies[0].protocol else {
        panic!("TUIC");
    };
    (config.clone(), packets, endpoint)
}

fn request() -> StreamSession {
    StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::Socks5,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: Destination::domain("x", 80).unwrap(),
        sniffed_domain: None,
    }
}

async fn authenticated(endpoint: &quinn::Endpoint) -> quinn::Connection {
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    let auth = connection
        .accept_uni()
        .await
        .unwrap()
        .read_to_end(50)
        .await
        .unwrap();
    assert_eq!(auth.len(), 50);
    assert_eq!(
        &auth[..18],
        &[5, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]
    );
    let mut expected = [0; 32];
    connection
        .export_keying_material(&mut expected, &[7; 16], b" raw\0context ")
        .unwrap();
    assert_eq!(&auth[18..], &expected);
    connection
}

async fn finish(endpoint: quinn::Endpoint, peer: tokio::task::JoinHandle<()>) {
    endpoint.close(0_u8.into(), b"");
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
        .await
        .unwrap();
}

#[tokio::test]
async fn authenticates_current_session_without_ack_and_preserves_stream_isolation() {
    for (algorithm, expected) in [
        ("cubic", TuicCongestion::Cubic),
        ("new_reno", TuicCongestion::NewReno),
        ("bbr", TuicCongestion::Bbr),
    ] {
        let probe = ResourceProbe::default();
        let (outbound, endpoint) = fixture(1200, true, 8, algorithm);
        assert_eq!(outbound.congestion_observation().await, None);
        let ep = endpoint.clone();
        let peer = tokio::spawn(async move {
            let connection = authenticated(&ep).await;
            let mut streams = Vec::new();
            for _ in 0..2 {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut connect = [0; 7];
                recv.read_exact(&mut connect).await.unwrap();
                assert_eq!(&connect, b"\x05\x01\x00\x01x\x00\x50");
                send.write_all(b"hello").await.unwrap();
                streams.push((send, recv));
            }
            let (mut send, mut recv) = streams.pop().unwrap();
            let mut payload = [0; 7];
            recv.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"sibling");
            send.write_all(&payload).await.unwrap();
            connection.closed().await;
        });
        probe
            .scope(async {
                let mut a = outbound
                    .connect_stream(request(), &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                let mut b = outbound
                    .connect_stream(request(), &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                assert_eq!(outbound.congestion_observation().await, Some(expected));
                for stream in [&mut a, &mut b] {
                    let mut hello = [0; 5];
                    stream.read_exact(&mut hello).await.unwrap();
                    assert_eq!(&hello, b"hello");
                }
                a.shutdown().await.unwrap();
                drop(a);
                b.write_all(b"sibling").await.unwrap();
                let mut response = [0; 7];
                b.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"sibling");
                let now = tokio::time::Instant::now();
                outbound.shutdown().await;
                assert!(now.elapsed() < Duration::from_secs(3));
                assert!(b.read_u8().await.is_err());
                drop(b);
                assert!(
                    outbound
                        .connect_stream(request(), &EstablishContext::default())
                        .await
                        .is_err()
                );
            })
            .await;
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        finish(endpoint, peer).await;
    }
}

#[tokio::test]
async fn stream_credit_wait_keeps_original_deadline_and_leaves_sibling_alive() {
    let (outbound, endpoint) = fixture(1400, true, 1, "cubic");
    let ep = endpoint.clone();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut header = [0; 7];
        recv.read_exact(&mut header).await.unwrap();
        let mut payload = [0; 1];
        recv.read_exact(&mut payload).await.unwrap();
        send.write_all(&payload).await.unwrap();
        connection.closed().await;
    });
    let mut first = outbound
        .connect_stream(request(), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    let context = EstablishContext::with_timeout(Duration::from_millis(60));
    tokio::time::sleep(Duration::from_millis(40)).await;
    let before = tokio::time::Instant::now();
    assert!(matches!(
        outbound.connect_stream(request(), &context).await,
        Err(DispatchError::TimedOut)
    ));
    assert!(before.elapsed() < Duration::from_millis(55));
    first.write_all(b"a").await.unwrap();
    assert_eq!(first.read_u8().await.unwrap(), b'a');
    drop(first);
    outbound.shutdown().await;
    finish(endpoint, peer).await;
}

#[tokio::test]
async fn insufficient_path_budget_and_missing_datagrams_never_fall_back() {
    for (budget, datagrams) in [(1199, true), (1400, false)] {
        let (outbound, endpoint) = fixture(budget, datagrams, 8, "cubic");
        let ep = endpoint.clone();
        let peer = tokio::spawn(async move {
            if let Some(incoming) = ep.accept().await
                && let Ok(connection) = incoming.await
            {
                connection.closed().await;
            }
        });
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                assert!(
                    outbound
                        .connect_stream(
                            request(),
                            &EstablishContext::with_timeout(Duration::from_secs(1))
                        )
                        .await
                        .is_err()
                );
                outbound.shutdown().await;
            })
            .await;
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        finish(endpoint, peer).await;
    }
}

#[tokio::test]
async fn stalled_quic_handshake_obeys_setup_deadline_and_stop_barrier() {
    for stop in [false, true] {
        // Do not accept the QUIC handshake. It can never reach TUIC auth.
        let (outbound, endpoint) = fixture(1400, true, 8, "cubic");
        let probe = ResourceProbe::default();
        probe.scope(async {
            let context = EstablishContext::with_timeout(Duration::from_millis(if stop {1000} else {40}));
            let connect = outbound.connect_stream(request(), &context);
            tokio::pin!(connect);
            if stop {
                tokio::select! { _ = &mut connect => panic!("unexpected handshake"), _ = tokio::time::sleep(Duration::from_millis(20)) => {} }
                outbound.begin_shutdown();
            }
            let result = connect.await;
            assert!(matches!(result,Err(DispatchError::NotAllowed | DispatchError::TimedOut)));
            outbound.shutdown().await;
        }).await;
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        endpoint.close(0_u8.into(), b"");
        tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
            .await
            .unwrap();
    }
}

fn udp_wire_target(index: usize) -> (Destination, &'static [u8]) {
    match index % 3 {
        0 => (Destination::domain("x", 80).unwrap(), b"\0\x01x\0\x50"),
        1 => (
            Destination::Ip("198.51.100.7:443".parse().unwrap()),
            &[1, 198, 51, 100, 7, 1, 187],
        ),
        _ => (
            Destination::Ip("[2001:db8::7]:8443".parse().unwrap()),
            &[
                2, 32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 32, 251,
            ],
        ),
    }
}

#[tokio::test]
async fn both_udp_modes_preserve_empty_and_u16_packets_and_dissociate() {
    const SIZES: &[usize] = &[0, 1, 1400, 4096, 65535];
    for mode in ["native", "quic"] {
        let (outbound, endpoint) = fixture_mode(1400, true, 8, "cubic", mode);
        let ep = endpoint.clone();
        let peer = tokio::spawn(async move {
            let connection = authenticated(&ep).await;
            for (packet, size) in SIZES.iter().copied().enumerate() {
                let mut received = Vec::new();
                let mut payload = Vec::new();
                loop {
                    let raw = if mode == "native" {
                        connection.read_datagram().await.unwrap()
                    } else {
                        connection
                            .accept_uni()
                            .await
                            .unwrap()
                            .read_to_end(66000)
                            .await
                            .unwrap()
                            .into()
                    };
                    assert_eq!(&raw[..4], &[5, 2, 0, 0]);
                    assert_eq!(u16::from_be_bytes([raw[4], raw[5]]), packet as u16);
                    let start = if raw[7] == 0 {
                        let (_, address) = udp_wire_target(packet);
                        assert_eq!(&raw[10..10 + address.len()], address);
                        10 + address.len()
                    } else {
                        assert_eq!(raw[10], 255);
                        11
                    };
                    assert_eq!(
                        u16::from_be_bytes([raw[8], raw[9]]) as usize,
                        raw.len() - start
                    );
                    payload.extend_from_slice(&raw[start..]);
                    let total = raw[6];
                    received.push(raw);
                    if received.len() == total as usize {
                        break;
                    }
                }
                assert_eq!(payload, vec![packet as u8; size]);
                // Unknown local association must never allocate delivery/reassembly state.
                let mut unknown = received[0].to_vec();
                unknown[2..4].copy_from_slice(&65535_u16.to_be_bytes());
                if mode == "native" {
                    connection.send_datagram_wait(unknown.into()).await.unwrap();
                }
                for raw in received.iter().rev() {
                    if mode == "native" {
                        connection.send_datagram_wait(raw.clone()).await.unwrap();
                        if raw[7] == 1 {
                            connection.send_datagram_wait(raw.clone()).await.unwrap();
                        }
                    } else {
                        let mut send = connection.open_uni().await.unwrap();
                        send.write_all(raw).await.unwrap();
                        send.finish().unwrap();
                    }
                }
            }
            let dissociate = connection
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(4)
                .await
                .unwrap();
            assert_eq!(&dissociate, &[5, 3, 0, 0]);
            connection.closed().await;
        });
        let probe = ResourceProbe::default();
        let outcome = probe
            .scope(async {
                let mut udp = outbound
                    .open_datagram(
                        vole::outbound::DatagramRequest::new(DatagramSession::new(
                            InboundKind::Socks5,
                            "127.0.0.1:1".parse().unwrap(),
                        ))
                        .with_budget(DatagramBudget::new(u16::MAX, u16::MAX)),
                        &EstablishContext::default(),
                    )
                    .await?;
                assert!(udp.supports_shared_destinations());
                assert!(
                    udp.send(Datagram {
                        remote: Destination::domain("x", 80).unwrap(),
                        payload: vec![9; 65536].into(),
                        sniffed_domain: None
                    })
                    .await
                    .is_err()
                );
                assert!(
                    tokio::time::timeout(Duration::from_millis(1), udp.receive())
                        .await
                        .is_err()
                );
                let result = tokio::time::timeout(Duration::from_secs(5), async {
                    for (packet, size) in SIZES.iter().copied().enumerate() {
                        let request = Datagram {
                            remote: udp_wire_target(packet).0,
                            payload: vec![packet as u8; size].into(),
                            sniffed_domain: None,
                        };
                        udp.send(request.clone()).await.unwrap();
                        let response = udp.receive().await.unwrap();
                        assert_eq!(response.remote, request.remote);
                        assert_eq!(response.payload, request.payload);
                    }
                    udp.close().await.unwrap();
                })
                .await;
                drop(udp);
                Ok::<_, DispatchError>(result)
            })
            .await;
        outbound.shutdown().await;
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        assert!(
            matches!(outcome, Ok(Ok(()))),
            "{mode} u16 datagram outcome: {outcome:?}"
        );
        finish(endpoint, peer).await;
        outcome.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn quic_declared_payload_peeks_only_ready_fin_and_never_waits_for_it() {
    let mut observed = Vec::new();
    for finish_before_send in [true, false] {
        let (outbound, endpoint) = fixture_mode(1400, true, 8, "cubic", "quic");
        let ep = endpoint.clone();
        let (reported, report) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = authenticated(&ep).await;
            // Echo the actual production encoder's Packet, not a test codec.
            let response = connection
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(64)
                .await
                .unwrap();
            assert_eq!(&response[response.len() - 1..], b"a");
            let before = connection.stats().frame_rx.stop_sending;
            let mut send = connection.open_uni().await.unwrap();
            let sent = connection.stats().frame_tx.stream;
            send.write_all(&response).await.unwrap();
            if finish_before_send {
                send.finish().unwrap();
            }
            // This current-thread task has not let the endpoint driver send
            // a STREAM frame before the small body and optional FIN are ready.
            assert_eq!(connection.stats().frame_tx.stream, sent);
            // A second production Packet is a return-path barrier: the first
            // payload has already reached its owner before we inspect frames.
            let barrier = connection
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(64)
                .await
                .unwrap();
            assert!(barrier.ends_with(b"barrier"));
            let stopped = if finish_before_send {
                None
            } else {
                // Keep FIN absent until payload delivery and the barrier. The
                // original Drop must still request cancellation in this case.
                Some(
                    tokio::time::timeout(Duration::from_secs(2), send.stopped())
                        .await
                        .unwrap()
                        .unwrap(),
                )
            };
            let stops = connection.stats().frame_rx.stop_sending - before;
            drop(send);
            reported.send((stops, stopped)).unwrap();
            connection.closed().await;
        });
        let probe = ResourceProbe::default();
        let result = probe
            .scope(async {
                let mut udp = outbound
                    .open_datagram(udp_request(), &EstablishContext::default())
                    .await
                    .unwrap();
                udp.send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"a"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                let response = tokio::time::timeout(Duration::from_secs(2), udp.receive())
                    .await
                    .expect("complete payload waited for FIN")
                    .unwrap();
                assert_eq!(response.remote, request().destination);
                assert_eq!(response.payload, b"a"[..]);
                udp.send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"barrier"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                let result = tokio::time::timeout(Duration::from_secs(2), report)
                    .await
                    .unwrap()
                    .unwrap();
                udp.close().await.unwrap();
                drop(udp);
                outbound.shutdown().await;
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
                result
            })
            .await;
        finish(endpoint, peer).await;
        observed.push(result);
    }
    // Check the candidate's control-frame benefit only after both fixtures
    // have shut down and joined, including the expected old-code RED run.
    assert_eq!(observed[0].0, 0, "ready FIN still caused STOP_SENDING");
    assert!(
        observed[1].0 > 0,
        "missing FIN bypassed the original stop path"
    );
    assert_eq!(observed[1].1, Some(Some(0_u8.into())));
}

#[tokio::test]
async fn unused_association_close_does_not_create_peer_state_or_control_tasks() {
    let (outbound, endpoint) = fixture(1400, true, 8, "cubic");
    let ep = endpoint.clone();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.accept_uni())
                .await
                .is_err()
        );
        connection.closed().await;
    });
    let mut unused = outbound
        .open_datagram(
            vole::outbound::DatagramRequest::new(DatagramSession::new(
                InboundKind::Socks5,
                "127.0.0.1:1".parse().unwrap(),
            )),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
    unused.close().await.unwrap();
    drop(unused);
    tokio::time::sleep(Duration::from_millis(120)).await;
    outbound.shutdown().await;
    finish(endpoint, peer).await;
}

struct Paths(Mutex<VecDeque<BudgetPackets>>);
#[async_trait::async_trait]
impl OutboundConnector for Paths {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("TUIC must not fall back to TCP");
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .expect("one upstream per physical session"),
        ))
    }
}
fn udp_request() -> DatagramRequest {
    DatagramRequest::new(DatagramSession::new(
        InboundKind::Socks5,
        "127.0.0.1:1".parse().unwrap(),
    ))
}

#[tokio::test]
async fn native_source_stripes_hold_64_owners_reuse_source_and_stop_both_paths() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // 65 held business owners fit the old configured threshold and these
    // peer credits. RED must be actual path count, not blocked stream credit.
    let (config, first_path, first_ep) = fixture_parts(1400, true, 128, "cubic", "native");
    let (_, next_path, next_ep) = fixture_parts(1400, true, 128, "cubic", "native");
    assert!(config.max_open_streams > 65);
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([first_path, next_path]))));
    let outbound =
        TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths.clone())).unwrap();
    let counts = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let (done, stop) = tokio::sync::watch::channel(false);
    let serve = |endpoint: quinn::Endpoint,
                 count: Arc<AtomicUsize>,
                 tag: u8,
                 mut stop: tokio::sync::watch::Receiver<bool>| {
        tokio::spawn(async move {
            let connection = tokio::select! {
                biased;
                _ = stop.wait_for(|done| *done) => return,
                connection = authenticated(&endpoint) => connection,
            };
            let mut streams = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = connection.closed() => break,
                    _ = stop.wait_for(|done| *done) => break,
                    stream = connection.accept_bi() => {
                        let Ok((mut send, mut recv)) = stream else { break; };
                        assert!(count.fetch_add(1, Ordering::Relaxed) < 65);
                        streams.spawn(async move {
                            let mut header = [0; 7];
                            if recv.read_exact(&mut header).await.is_err() { return; }
                            assert_eq!(&header, b"\x05\x01\x00\x01x\x00\x50");
                            let mut byte = [0; 1];
                            while let Ok(Some(1)) = recv.read(&mut byte).await {
                                if send.write_all(&[tag, byte[0]]).await.is_err() { break; }
                            }
                        });
                    }
                }
            }
            while let Some(result) = streams.join_next().await {
                result.unwrap();
            }
        })
    };
    let first_peer = serve(first_ep.clone(), counts[0].clone(), 0, stop.clone());
    let next_peer = serve(next_ep.clone(), counts[1].clone(), 1, stop);
    let probe = ResourceProbe::default();
    let evidence = probe
        .scope(async {
            let mut held = Vec::new();
            let mut tags = Vec::new();
            for index in 0..64_u8 {
                let mut owner = request();
                owner.source.set_port(10000 + u16::from(index));
                let mut stream = outbound
                    .connect_stream(
                        owner,
                        &EstablishContext::with_timeout(Duration::from_secs(2)),
                    )
                    .await
                    .unwrap()
                    .io;
                stream.write_all(&[index]).await.unwrap();
                let mut echo = [0; 2];
                tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echo))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(echo[1], index);
                assert!(echo[0] < 2);
                tags.push(echo[0]);
                held.push(stream);
            }
            let opened_before_reuse = 2 - paths.0.lock().unwrap().len();
            let mut same_source = request();
            same_source.source.set_port(10000);
            let mut reused = outbound
                .connect_stream(
                    same_source,
                    &EstablishContext::with_timeout(Duration::from_secs(2)),
                )
                .await
                .unwrap()
                .io;
            reused.write_all(b"r").await.unwrap();
            let mut echo = [0; 2];
            tokio::time::timeout(Duration::from_secs(2), reused.read_exact(&mut echo))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(echo, [tags[0], b'r']);
            held.push(reused);
            // Held old and new owners keep their actual peer and byte identity.
            for index in [0, 63] {
                held[index].write_all(b"z").await.unwrap();
                tokio::time::timeout(Duration::from_secs(2), held[index].read_exact(&mut echo))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(echo, [tags[index], b'z']);
            }
            let evidence = (
                opened_before_reuse,
                2 - paths.0.lock().unwrap().len(),
                counts[0].load(Ordering::Relaxed),
                counts[1].load(Ordering::Relaxed),
                probe.snapshot().current(ResourceKind::Pool),
            );
            outbound.shutdown().await;
            assert!(held[0].read_u8().await.is_err());
            assert!(held[64].read_u8().await.is_err());
            drop(held);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            evidence
        })
        .await;
    let _ = done.send(true); // Release the unused second endpoint in old-code RED.
    finish(first_ep, first_peer).await;
    finish(next_ep, next_peer).await;
    // All owners and both endpoint tasks are clean before the intended RED.
    assert_eq!(
        evidence.0, 2,
        "native default kept all distinct sources on one path"
    );
    assert_eq!(
        evidence.1, 2,
        "same source opened an additional physical path"
    );
    assert!(evidence.2 > 0 && evidence.3 > 0);
    assert_eq!(evidence.2 + evidence.3, 65);
    assert_eq!(evidence.4, 2);
}

#[tokio::test]
async fn association_id_exhaustion_retires_without_reuse_or_migrating_old_streams() {
    let (config, first_path, first_ep) = fixture_parts(1400, true, 8, "cubic", "native");
    let (_, next_path, next_ep) = fixture_parts(1400, true, 8, "cubic", "native");
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([first_path, next_path]))));
    let outbound =
        TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths.clone())).unwrap();
    let ep = first_ep.clone();
    let first_peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut header = [0; 7];
        recv.read_exact(&mut header).await.unwrap();
        assert_eq!(&header, b"\x05\x01\x00\x01x\x00\x50");
        assert_eq!(recv.read_u8().await.unwrap(), b'a');
        send.write_all(b"a").await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), b'b');
        // Late association 0 on the retired physical session cannot enter new
        // association 0 on the replacement connection.
        connection
            .send_datagram_wait(bytes::Bytes::from_static(
                b"\x05\x02\x00\x00\x00\x00\x01\x00\x00\x05\x00\x01x\x00\x50stale",
            ))
            .await
            .unwrap();
        send.write_all(b"b").await.unwrap();
        // Retirement must not close the physical connection before a final
        // accepted upload and FIN have arrived on its last logical stream.
        let trailer = recv.read_to_end(1024 * 1024).await.unwrap();
        assert_eq!(trailer, vec![23; 1024 * 1024]);
        connection.closed().await;
    });
    let ep = next_ep.clone();
    let next_peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let raw = connection.read_datagram().await.unwrap();
        assert_eq!(&raw[..4], &[5, 2, 0, 0]);
        assert_eq!(&raw[15..], b"fresh");
        connection.send_datagram_wait(raw).await.unwrap();
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut old = outbound
                .connect_stream(request(), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            old.write_all(b"a").await.unwrap();
            assert_eq!(old.read_u8().await.unwrap(), b'a');
            for id in 0..=u16::MAX {
                drop(
                    outbound
                        .open_datagram(udp_request(), &EstablishContext::default())
                        .await
                        .unwrap(),
                );
                if id % 256 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            let mut fresh = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            assert!(paths.0.lock().unwrap().is_empty());
            old.write_all(b"b").await.unwrap();
            assert_eq!(old.read_u8().await.unwrap(), b'b');
            fresh
                .send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"fresh"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), fresh.receive())
                    .await
                    .unwrap()
                    .unwrap()
                    .payload,
                b"fresh"[..]
            );
            assert_eq!(probe.snapshot().current(ResourceKind::Pool), 2);
            old.write_all(&vec![23; 1024 * 1024]).await.unwrap();
            old.shutdown().await.unwrap();
            drop(old);
            tokio::time::timeout(Duration::from_secs(2), async {
                while probe.snapshot().current(ResourceKind::Pool) != 1 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            outbound.shutdown().await;
            assert!(fresh.receive().await.is_err());
            drop(fresh);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        })
        .await;
    finish(first_ep, first_peer).await;
    finish(next_ep, next_peer).await;
}

#[tokio::test]
async fn quic_partial_control_streams_have_a_credit_bound_and_expire_without_blocking_tcp() {
    let (mut config, udp_path, endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    let (_, tcp_path, tcp_endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    config.stream_window = vole::config::QuicReceiveWindow {
        initial: 256 * 1024,
        maximum: 256 * 1024,
    };
    config.connection_window = vole::config::QuicReceiveWindow {
        initial: 1024 * 1024,
        maximum: 1024 * 1024,
    };
    config.disable_mtu_discovery = true;
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([udp_path, tcp_path]))));
    let outbound = TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths)).unwrap();
    let ep = endpoint.clone();
    let (ready, wait) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        connection
            .accept_uni()
            .await
            .unwrap()
            .read_to_end(64)
            .await
            .unwrap();
        let mut partial = Vec::new();
        for _ in 0..32 {
            let mut stream = connection.open_uni().await.unwrap();
            stream
                .write_all(&[5, 2, 0, 0, 0, 0, 1, 0, 0, 1])
                .await
                .unwrap();
            partial.push(stream);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), connection.open_uni())
                .await
                .is_err()
        );
        ready.send(()).unwrap();
        for stream in &partial {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(6), stream.stopped())
                    .await
                    .unwrap()
                    .unwrap(),
                Some(0_u8.into())
            );
        }
        // STOP_SENDING requests cancellation. Quinn correctly retains the
        // receive credit until this peer supplies FIN/RESET_STREAM; respond to
        // the request instead of treating local timeout as peer acknowledgement.
        drop(partial);
        let mut available = tokio::time::timeout(Duration::from_secs(6), connection.open_uni())
            .await
            .unwrap()
            .unwrap();
        available
            .write_all(b"\x05\x02\x00\x00\x00\x00\x01\x00\x00\x01\x00\x01x\x00\x50z")
            .await
            .unwrap();
        available.finish().unwrap();
        connection.closed().await;
    });
    let tcp_ep = tcp_endpoint.clone();
    let tcp_peer = tokio::spawn(async move {
        let connection = authenticated(&tcp_ep).await;
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut request = [0; 8];
        recv.read_exact(&mut request).await.unwrap();
        assert_eq!(request[7], b'a');
        send.write_all(b"a").await.unwrap();
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut udp = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            udp.send(Datagram {
                remote: request().destination,
                payload: bytes::Bytes::from_static(b"start"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
            wait.await.unwrap();
            let mut tcp = outbound
                .connect_stream(
                    request(),
                    &EstablishContext::with_timeout(Duration::from_secs(1)),
                )
                .await
                .unwrap()
                .io;
            tcp.write_all(b"a").await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), tcp.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
                b'a'
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(6), udp.receive())
                    .await
                    .unwrap()
                    .unwrap()
                    .payload,
                b"z"[..]
            );
            outbound.shutdown().await;
            drop(udp);
            drop(tcp);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        })
        .await;
    finish(endpoint, peer).await;
    finish(tcp_endpoint, tcp_peer).await;
}

#[tokio::test]
async fn cancelled_uni_credit_wait_does_not_replay_or_close_sibling_tcp() {
    let (mut config, udp_path, endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    let (_, tcp_path, tcp_endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    // Keep the original fixed windows, MTU policy and two unread uni credits.
    config.stream_window = vole::config::QuicReceiveWindow {
        initial: 256 * 1024,
        maximum: 256 * 1024,
    };
    config.connection_window = vole::config::QuicReceiveWindow {
        initial: 1024 * 1024,
        maximum: 1024 * 1024,
    };
    config.disable_mtu_discovery = true;
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([udp_path, tcp_path]))));
    let outbound =
        TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths.clone())).unwrap();
    let ep = endpoint.clone();
    let (ready, wait) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let mut unread = Vec::new();
        // Explicit fixture credit is two; leave both bodies unread.
        for _ in 0..2 {
            unread.push(connection.accept_uni().await.unwrap());
        }
        ready.send(()).unwrap();
        connection.closed().await;
        drop(unread);
    });
    let tcp_ep = tcp_endpoint.clone();
    let tcp_peer = tokio::spawn(async move {
        let connection = authenticated(&tcp_ep).await;
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut request = [0; 8];
        recv.read_exact(&mut request).await.unwrap();
        assert_eq!(request[7], b'a');
        send.write_all(b"a").await.unwrap();
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut udp = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            let packet = Datagram {
                remote: request().destination,
                payload: bytes::Bytes::from_static(b"x"),
                sniffed_domain: None,
            };
            for _ in 0..2 {
                tokio::time::timeout(Duration::from_secs(1), udp.send(packet.clone()))
                    .await
                    .unwrap()
                    .unwrap();
            }
            tokio::time::timeout(Duration::from_secs(1), wait)
                .await
                .unwrap()
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(40), udp.send(packet))
                    .await
                    .is_err()
            );
            let mut tcp = outbound
                .connect_stream(request(), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            tcp.write_all(b"a").await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), tcp.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
                b'a'
            );
            // Both business lanes were established; the cancelled third UDP
            // send must not redirect TCP to the old UDP peer.
            assert!(paths.0.lock().unwrap().is_empty());
            let before = tokio::time::Instant::now();
            outbound.shutdown().await;
            assert!(before.elapsed() < Duration::from_secs(2));
            drop(tcp);
            drop(udp);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        })
        .await;
    finish(endpoint, peer).await;
    finish(tcp_endpoint, tcp_peer).await;
}

#[cfg(unix)]
#[tokio::test]
async fn physical_protection_failure_stops_before_udp_or_tcp_fallback() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vole::dialer::{Dialer, ResolvedEndpoint, SocketProtector};
    struct Reject(AtomicUsize);
    impl SocketProtector for Reject {
        fn protect(&self, _: i32) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied",
            ))
        }
    }
    let (config, _, endpoint) = fixture_parts(1400, true, 8, "cubic", "native");
    let reject = Arc::new(Reject(AtomicUsize::new(0)));
    let path = UpstreamPath::direct(
        ResolvedEndpoint {
            logical_host: "192.0.2.1".into(),
            port: 443,
            addresses: vec!["192.0.2.1:443".parse().unwrap()],
        },
        Dialer::default().with_protector(reject.clone()),
    );
    let outbound = TuicOutbound::new_with_path(&config, path).unwrap();
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            assert!(
                outbound
                    .connect_stream(request(), &EstablishContext::default())
                    .await
                    .is_err()
            );
            assert_eq!(reject.0.load(Ordering::Relaxed), 1);
            outbound.shutdown().await;
        })
        .await;
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    endpoint.close(0_u8.into(), b"");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn heartbeat_and_full_delivery_queue_remain_owned_until_synchronous_stop() {
    for mode in ["native", "quic"] {
        let (outbound, endpoint) = fixture_mode(1400, true, 8, "cubic", mode);
        let ep = endpoint.clone();
        let (ready, wait) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = authenticated(&ep).await;
            let first = if mode == "native" {
                connection.read_datagram().await.unwrap()
            } else {
                connection
                    .accept_uni()
                    .await
                    .unwrap()
                    .read_to_end(64)
                    .await
                    .unwrap()
                    .into()
            };
            assert_eq!(&first[..4], &[5, 2, 0, 0]);
            for id in 0..33_u16 {
                let mut packet =
                    b"\x05\x02\x00\x00\x00\x00\x01\x00\x00\x01\x00\x01x\x00\x50z".to_vec();
                packet[4..6].copy_from_slice(&id.to_be_bytes());
                if mode == "native" {
                    connection.send_datagram_wait(packet.into()).await.unwrap();
                } else {
                    let mut stream = connection.open_uni().await.unwrap();
                    stream.write_all(&packet).await.unwrap();
                    stream.finish().unwrap();
                }
            }
            // TUIC heartbeat uses a DATAGRAM even in quic UDP relay mode.
            let heartbeat =
                tokio::time::timeout(Duration::from_secs(12), connection.read_datagram())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(heartbeat, b"\x05\x04"[..]);
            ready.send(()).unwrap();
            connection.closed().await;
        });
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut udp = outbound
                    .open_datagram(udp_request(), &EstablishContext::default())
                    .await
                    .unwrap();
                udp.send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"start"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                tokio::time::timeout(Duration::from_secs(13), wait)
                    .await
                    .unwrap()
                    .unwrap();
                let queue = probe
                    .queues()
                    .into_iter()
                    .find(|q| q.kind == vole::resources::observation::QueueKind::TuicUdp)
                    .unwrap();
                assert_eq!((queue.peak, queue.capacity), (32, 32));
                let before = tokio::time::Instant::now();
                outbound.shutdown().await;
                assert!(before.elapsed() < Duration::from_secs(2));
                drop(udp);
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            })
            .await;
        finish(endpoint, peer).await;
    }
}

#[tokio::test]
async fn receive_flow_control_bounds_unread_streams_and_connection_then_stop_releases_them() {
    for streams in [1, 8] {
        let (outbound, endpoint) = fixture(1400, true, 8, "cubic");
        let ep = endpoint.clone();
        let (ready, wait) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = authenticated(&ep).await;
            let mut writes = tokio::task::JoinSet::new();
            for _ in 0..streams {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut header = [0; 7];
                recv.read_exact(&mut header).await.unwrap();
                writes.spawn(async move {
                    let mut accepted = 0;
                    let data = [0; 4096];
                    while let Ok(n) =
                        tokio::time::timeout(Duration::from_millis(500), send.write(&data)).await
                    {
                        accepted += n.unwrap();
                        assert!(accepted <= 2 * 1024 * 1024, "unbounded unread stream");
                    }
                    (accepted, send, recv)
                });
            }
            let mut stalled = Vec::new();
            while let Some(result) = writes.join_next().await {
                stalled.push(result.unwrap());
            }
            let accepted: usize = stalled.iter().map(|s| s.0).sum();
            let window = if streams == 1 {
                256 * 1024
            } else {
                1024 * 1024
            };
            // Successful peer writes include its bounded 64 KiB send buffer,
            // not just acknowledged bytes retained in the Vole receive window.
            assert!(
                accepted >= window && accepted <= window + 64 * 1024,
                "{streams} streams accepted {accepted}"
            );
            assert!(stalled.iter().all(|s| s.0 <= 256 * 1024 + 64 * 1024));
            ready.send(()).unwrap();
            connection.closed().await;
        });
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut unread = Vec::new();
                for _ in 0..streams {
                    unread.push(
                        outbound
                            .connect_stream(request(), &EstablishContext::default())
                            .await
                            .unwrap()
                            .io,
                    );
                }
                tokio::time::timeout(Duration::from_secs(5), wait)
                    .await
                    .unwrap()
                    .unwrap();
                let before = tokio::time::Instant::now();
                outbound.shutdown().await;
                assert!(before.elapsed() < Duration::from_secs(2));
                drop(unread);
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            })
            .await;
        finish(endpoint, peer).await;
    }
}

#[tokio::test]
async fn blocked_outer_path_bounds_stream_and_datagram_send_buffers_and_stop() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Blockable(BudgetPackets, Arc<AtomicBool>);
    #[async_trait::async_trait]
    impl DatagramTransport for Blockable {
        fn supports_shared_destinations(&self) -> bool {
            false
        }

        fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
            self.0.payload_budget(peer)
        }
        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            if self.1.load(Ordering::Acquire) {
                std::future::pending::<()>().await;
            }
            self.0.send(packet).await
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.0.receive().await
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.0.close().await
        }
    }
    let (config, packets, endpoint) = fixture_parts(1400, true, 8, "cubic", "native");
    let blocked = Arc::new(AtomicBool::new(false));
    let outbound = TuicOutbound::new_with_path(
        &config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Blockable(
            packets,
            blocked.clone(),
        )))))),
    )
    .unwrap();
    let ep = endpoint.clone();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut header = [0; 7];
        recv.read_exact(&mut header).await.unwrap();
        send.write_all(b"ready").await.unwrap();
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut tcp = outbound
                .connect_stream(request(), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            let mut ready = [0; 5];
            tcp.read_exact(&mut ready).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut udp = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            // Quinn includes each queued Datagram's Bytes metadata in this
            // buffer and reserves one metadata slot in its space query.
            assert_eq!(
                outbound.datagram_buffer_space().await,
                Some(256 * 1024 - size_of::<bytes::Bytes>())
            );
            blocked.store(true, Ordering::Release);
            let mut accepted = 0;
            while let Ok(n) =
                tokio::time::timeout(Duration::from_millis(50), tcp.write(&[0; 4096])).await
            {
                accepted += n.unwrap();
                assert!(accepted <= 1024 * 1024);
            }
            assert_eq!(accepted, 1024 * 1024);
            let packet = Datagram {
                remote: request().destination,
                payload: vec![0; 1000].into(),
                sniffed_domain: None,
            };
            let mut sent = 0;
            while let Ok(result) =
                tokio::time::timeout(Duration::from_millis(50), udp.send(packet.clone())).await
            {
                result.unwrap();
                sent += 1;
                assert!(sent < 400, "unbounded datagram buffering");
            }
            assert!(sent >= 250);
            assert!(outbound.datagram_buffer_space().await.unwrap() < 1015);
            // Pending graceful FIN ownership must not delay the node Stop.
            tcp.shutdown().await.unwrap();
            let before = tokio::time::Instant::now();
            outbound.shutdown().await;
            assert!(before.elapsed() < Duration::from_secs(2));
            drop((tcp, udp));
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        })
        .await;
    finish(endpoint, peer).await;
}

#[tokio::test]
async fn configured_ip_sni_millisecond_heartbeat_and_uot_v2_are_consumed() {
    let (mut config, packets, endpoint) = fixture_parts(1400, true, 8, "cubic", "native");
    config.address = "logical.invalid".into();
    config.ip = Some("192.0.2.1".into());
    config.heartbeat_interval = Duration::from_millis(12);
    config.udp_over_stream = true;
    config.disable_mtu_discovery = true;
    let outbound = Arc::new(
        TuicOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(packets))))),
        )
        .unwrap(),
    );
    let ep = endpoint.clone();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let handshake = connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(handshake.server_name.as_deref(), Some("fixture.invalid"));
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let magic = "sp.v2.udp-over-tcp.arpa";
        let mut header = vec![0; 4 + magic.len() + 2];
        recv.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, magic.len() as u8]);
        assert_eq!(&header[4..4 + magic.len()], magic.as_bytes());
        assert_eq!(&header[4 + magic.len()..], &[0, 0]);
        let expected: &[u8] = &[0, 1, 1, 2, 3, 4, 0, 53, 0, 1, 2, 3, 4, 0, 53, 0, 1, b'q'];
        let mut packet = vec![0; expected.len()];
        recv.read_exact(&mut packet).await.unwrap();
        assert_eq!(packet, expected);
        send.write_all(&[0, 8, 8, 8, 8, 0, 53, 0, 1, b'a'])
            .await
            .unwrap();
        let heartbeat =
            tokio::time::timeout(Duration::from_millis(250), connection.read_datagram())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(heartbeat.as_ref(), &[5, 4]);
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut transport = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            transport
                .send(Datagram {
                    remote: Destination::Ip("1.2.3.4:53".parse().unwrap()),
                    payload: bytes::Bytes::from_static(b"q"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            assert_eq!(transport.receive().await.unwrap().payload.as_ref(), b"a");
            tokio::time::sleep(Duration::from_millis(15)).await;
            outbound.shutdown().await;
            assert!(transport.receive().await.is_err());
            drop(transport);
        })
        .await;
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    finish(endpoint, peer).await;
}

#[tokio::test(start_paused = true)]
async fn configured_mtu_discovery_changes_native_probes_and_path_mtu() {
    for disabled in [false, true] {
        let (mut config, packets, endpoint) = fixture_parts(1400, true, 8, "cubic", "native");
        config.disable_mtu_discovery = disabled;
        let outbound = TuicOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(packets))))),
        )
        .unwrap();
        let ep = endpoint.clone();
        let peer = tokio::spawn(async move {
            let connection = authenticated(&ep).await;
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut header = [0; 7];
            recv.read_exact(&mut header).await.unwrap();
            assert_eq!(&header, b"\x05\x01\x00\x01x\x00\x50");
            send.write_all(b"ready").await.unwrap();
            let payload = recv.read_u8().await.unwrap();
            send.write_all(&[payload]).await.unwrap();
            connection.closed().await;
        });
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut stream = outbound
                    .connect_stream(request(), &EstablishContext::default())
                    .await
                    .unwrap()
                    .io;
                let mut ready = [0; 5];
                stream.read_exact(&mut ready).await.unwrap();
                if disabled {
                    // Same observation interval as enabled, long before the
                    // default ten-second keepalive or discovery re-run.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    tokio::time::timeout(Duration::from_secs(1), async {
                        loop {
                            let path = outbound.path_observation().await.unwrap();
                            if path.sent_plpmtud_probes > 0 && path.current_mtu > 1200 {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .expect("real native probe ACK must increase the current path MTU");
                }
                let path = outbound.path_observation().await.unwrap();
                if disabled {
                    assert_eq!(path.sent_plpmtud_probes, 0);
                    assert_eq!(path.current_mtu, 1400);
                } else {
                    assert!(path.sent_plpmtud_probes > 0);
                    assert_eq!(path.lost_plpmtud_probes, 0);
                    assert!(1200 < path.current_mtu && path.current_mtu <= 1400);
                }
                // Real business still traverses the measured path after its
                // probe result, rather than only inspecting construction.
                stream.write_all(b"a").await.unwrap();
                assert_eq!(stream.read_u8().await.unwrap(), b'a');
                outbound.shutdown().await;
                drop(stream);
            })
            .await;
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        finish(endpoint, peer).await;
    }
}

#[tokio::test]
async fn official_quinn_credit_is_bounded_and_replenished_independent_of_owner_threshold() {
    let (mut config, packets, endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    config.max_open_streams = i64::MAX as usize - 1;
    let outbound = TuicOutbound::new_with_path(
        &config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(packets))))),
    )
    .unwrap();
    let ep = endpoint.clone();
    let (ready, wait) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), connection.open_bi())
                .await
                .is_err()
        );
        let mut held = VecDeque::new();
        for _ in 0..32 {
            let send = connection.open_uni().await.unwrap();
            held.push_back(send);
        }
        // Receiving the highest permitted ID implicitly opens the preceding
        // gaps. They must fit the same 32 slots even without their own data.
        held.back_mut().unwrap().write_all(&[5]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.open_uni())
                .await
                .is_err()
        );
        // EOF ends each partial decoder. Official Quinn batches MAX_STREAMS
        // updates until more than 1/8 of the 32-slot window has been released;
        // a single completed stream need not immediately grant peer credit.
        for _ in 0..4 {
            held.pop_front().unwrap().finish().unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.open_uni())
                .await
                .is_err()
        );
        held.pop_front().unwrap().finish().unwrap();
        for _ in 0..5 {
            let mut next = tokio::time::timeout(Duration::from_secs(2), connection.open_uni())
                .await
                .unwrap()
                .unwrap();
            next.write_all(&[5]).await.unwrap();
            held.push_back(next);
        }
        for _ in 0..8 {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), connection.open_uni())
                    .await
                    .is_err()
            );
            for _ in 0..5 {
                held.pop_front().unwrap().finish().unwrap();
            }
            for _ in 0..5 {
                let mut next = tokio::time::timeout(Duration::from_secs(2), connection.open_uni())
                    .await
                    .unwrap()
                    .unwrap();
                next.write_all(&[5]).await.unwrap();
                held.push_back(next);
            }
        }
        // Stream IDs above the first concurrency window work through automatic
        // recycling; cumulative accepts do not increase concurrent permission.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.open_uni())
                .await
                .is_err()
        );
        ready.send(()).unwrap();
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let udp = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(4), wait)
                .await
                .unwrap()
                .unwrap();
            outbound.shutdown().await;
            drop(udp);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        })
        .await;
    finish(endpoint, peer).await;
}

#[tokio::test]
async fn official_quinn_receive_budget_is_independent_of_send_frame_limit() {
    for receive_budget in [60, 64] {
        let (mut config, packets, endpoint) = fixture_parts(1400, true, 8, "cubic", "native");
        config.max_datagram_frame_size = 80;
        config.max_udp_relay_packet_size = 51;
        let outbound = TuicOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(packets))))),
        )
        .unwrap();
        let ep = endpoint.clone();
        let peer = tokio::spawn(async move {
            let connection = authenticated(&ep).await;
            // An outbound packet proves association registration completed before
            // the peer sends its responses; authentication alone precedes it.
            connection.read_datagram().await.unwrap();
            // These peer messages fit the physical path. The 61-byte response
            // exceeds our configured send frame limit but fits a 64-byte source
            // receive budget; a 60-byte receive budget must reject it.
            for size in [61_u16, 60] {
                let mut raw = vec![5, 2, 0, 0, 0, 0, 1, 0];
                raw.extend_from_slice(&size.to_be_bytes());
                raw.extend_from_slice(&[1, 192, 0, 2, 1, 0, 53]);
                raw.resize(raw.len() + usize::from(size), size as u8);
                connection.send_datagram_wait(raw.into()).await.unwrap();
            }
            connection.closed().await;
        });
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut udp = outbound
                    .open_datagram(
                        udp_request().with_budget(DatagramBudget::new(u16::MAX, receive_budget)),
                        &EstablishContext::default(),
                    )
                    .await
                    .unwrap();
                udp.send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"start"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
                let packet = tokio::time::timeout(Duration::from_secs(2), udp.receive())
                    .await
                    .unwrap()
                    .unwrap();
                if receive_budget == 64 {
                    assert_eq!(packet.payload, vec![61; 61]);
                    let packet = tokio::time::timeout(Duration::from_secs(2), udp.receive())
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(packet.payload, vec![60; 60]);
                } else {
                    assert_eq!(packet.payload, vec![60; 60]);
                }
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), udp.receive())
                        .await
                        .is_err()
                );
                outbound.shutdown().await;
                drop(udp);
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
            })
            .await;
        finish(endpoint, peer).await;
    }
}

async fn echo_lane_udp(connection: &quinn::Connection, native: bool, payload: &[u8]) {
    let raw = if native {
        connection.read_datagram().await.unwrap().to_vec()
    } else {
        connection
            .accept_uni()
            .await
            .unwrap()
            .read_to_end(65535)
            .await
            .unwrap()
    };
    assert_eq!(&raw[raw.len() - payload.len()..], payload);
    if native {
        connection.send_datagram_wait(raw.into()).await.unwrap();
    } else {
        let mut send = connection.open_uni().await.unwrap();
        send.write_all(&raw).await.unwrap();
        send.finish().unwrap();
    }
}

#[tokio::test]
async fn native_tcp_and_udp_keep_one_physical_session_and_stop() {
    let (config, path, endpoint) = fixture_parts(1400, true, 8, "cubic", "native");
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([path]))));
    let outbound =
        TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths.clone())).unwrap();
    let ep = endpoint.clone();
    let peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut header = [0; 7];
        recv.read_exact(&mut header).await.unwrap();
        assert_eq!(&header, b"\x05\x01\x00\x01x\x00\x50");
        assert_eq!(recv.read_u8().await.unwrap(), b'a');
        send.write_all(b"a").await.unwrap();
        echo_lane_udp(&connection, true, b"u").await;
        assert_eq!(recv.read_u8().await.unwrap(), b'b');
        send.write_all(b"b").await.unwrap();
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut tcp = outbound
                .connect_stream(request(), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            tcp.write_all(b"a").await.unwrap();
            assert_eq!(tcp.read_u8().await.unwrap(), b'a');
            let mut udp = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            udp.send(Datagram {
                remote: request().destination,
                payload: bytes::Bytes::from_static(b"u"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
            assert_eq!(udp.receive().await.unwrap().payload, b"u"[..]);
            assert!(paths.0.lock().unwrap().is_empty());
            assert_eq!(probe.snapshot().current(ResourceKind::Pool), 1);
            udp.close().await.unwrap();
            drop(udp);
            tcp.write_all(b"b").await.unwrap();
            assert_eq!(tcp.read_u8().await.unwrap(), b'b');
            outbound.shutdown().await;
            assert!(tcp.read_u8().await.is_err());
            drop(tcp);
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        })
        .await;
    finish(endpoint, peer).await;
}

#[tokio::test]
async fn quic_business_lanes_retire_only_udp_while_tcp_is_held_and_stop_all() {
    let (mut config, tcp_path, tcp_endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    let (_, udp_path, udp_endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    let (_, fresh_path, fresh_endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    config.max_open_streams = 2;
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([
        tcp_path, udp_path, fresh_path,
    ]))));
    let outbound =
        TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths.clone())).unwrap();
    let ep = tcp_endpoint.clone();
    let tcp_peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut header = [0; 7];
        recv.read_exact(&mut header).await.unwrap();
        assert_eq!(&header, b"\x05\x01\x00\x01x\x00\x50");
        assert_eq!(recv.read_u8().await.unwrap(), b'a');
        send.write_all(b"a").await.unwrap();
        // The second stream must reuse this original TCP lane after UDP retires.
        let (mut sibling_send, mut sibling_recv) = connection.accept_bi().await.unwrap();
        sibling_recv.read_exact(&mut header).await.unwrap();
        assert_eq!(sibling_recv.read_u8().await.unwrap(), b'x');
        sibling_send.write_all(b"x").await.unwrap();
        for expected in [b'b', b'c'] {
            assert_eq!(recv.read_u8().await.unwrap(), expected);
            send.write_all(&[expected]).await.unwrap();
        }
        connection.closed().await;
    });
    let ep = udp_endpoint.clone();
    let udp_peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        for payload in [b"p".as_slice(), b"q".as_slice(), b"s".as_slice()] {
            echo_lane_udp(&connection, false, payload).await;
        }
        connection.closed().await;
    });
    let ep = fresh_endpoint.clone();
    let fresh_peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        echo_lane_udp(&connection, false, b"r").await;
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut tcp = outbound
                .connect_stream(request(), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            tcp.write_all(b"a").await.unwrap();
            assert_eq!(tcp.read_u8().await.unwrap(), b'a');
            assert_eq!(outbound.datagram_buffer_space().await, None);
            assert!(outbound.congestion_observation().await.is_some());
            assert!(outbound.path_observation().await.is_some());
            let mut first = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            first
                .send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"p"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            assert_eq!(first.receive().await.unwrap().payload, b"p"[..]);
            assert!(outbound.datagram_buffer_space().await.is_some());
            assert_eq!(probe.snapshot().current(ResourceKind::Pool), 2);
            let mut held = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            held.send(Datagram {
                remote: request().destination,
                payload: bytes::Bytes::from_static(b"q"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
            assert_eq!(held.receive().await.unwrap().payload, b"q"[..]);
            assert_eq!(paths.0.lock().unwrap().len(), 1);
            let mut fresh = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .unwrap();
            fresh
                .send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"r"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            assert_eq!(fresh.receive().await.unwrap().payload, b"r"[..]);
            assert_eq!(probe.snapshot().current(ResourceKind::Pool), 3);
            assert!(paths.0.lock().unwrap().is_empty());
            let mut sibling = outbound
                .connect_stream(request(), &EstablishContext::default())
                .await
                .unwrap()
                .io;
            sibling.write_all(b"x").await.unwrap();
            assert_eq!(sibling.read_u8().await.unwrap(), b'x');
            drop(sibling);
            tcp.write_all(b"b").await.unwrap();
            assert_eq!(tcp.read_u8().await.unwrap(), b'b');
            first
                .send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"s"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
            assert_eq!(first.receive().await.unwrap().payload, b"s"[..]);
            held.close().await.unwrap();
            drop(held);
            assert_eq!(probe.snapshot().current(ResourceKind::Pool), 3);
            first.close().await.unwrap();
            drop(first);
            tokio::time::timeout(Duration::from_secs(2), async {
                while probe.snapshot().current(ResourceKind::Pool) != 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            tcp.write_all(b"c").await.unwrap();
            assert_eq!(tcp.read_u8().await.unwrap(), b'c');
            let before = tokio::time::Instant::now();
            outbound.shutdown().await;
            assert!(before.elapsed() < Duration::from_secs(2));
            assert!(fresh.receive().await.is_err());
            assert!(tcp.read_u8().await.is_err());
            drop((tcp, fresh));
            assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        })
        .await;
    finish(tcp_endpoint, tcp_peer).await;
    finish(udp_endpoint, udp_peer).await;
    finish(fresh_endpoint, fresh_peer).await;
}
