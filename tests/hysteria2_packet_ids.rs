#![cfg(feature = "outbound-hysteria2")]
//! Public connector over memory-only QUIC IO; no host sockets or native-peer claim.
use bytes::Bytes;
use std::{
    io::IoSliceMut,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use vole::{
    config::{Config, ProxyProtocol},
    outbound::{
        DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        hysteria2::Hysteria2Outbound,
    },
    session::{Datagram, DatagramSession, Destination, InboundKind},
};

#[path = "support/memory_quic.rs"]
mod memory_quic;
use memory_quic::{MemoryPackets, MemoryUpstream, PeerSocket};

#[test]
fn memory_udp_peer_shutdown_is_not_a_local_socket_failure() {
    let (send, remote_receive) = mpsc::channel(1);
    let (remote_send, receive) = mpsc::channel(1);
    remote_send
        .try_send(Bytes::from_static(b"last packet"))
        .unwrap();
    drop(remote_send);
    drop(remote_receive);
    let socket = Arc::new(PeerSocket {
        send,
        receive: Mutex::new(receive),
        local: "192.0.2.1:443".parse().unwrap(),
        remote: "192.0.2.2:1234".parse().unwrap(),
    });
    use quinn::AsyncUdpSocket;
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut bytes = [0; 64];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let mut meta = [quinn::udp::RecvMeta::default()];
    assert!(matches!(
        socket.poll_recv(&mut cx, &mut bufs, &mut meta),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(&bufs[0][..meta[0].len], b"last packet");
    assert!(socket.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
    socket
        .try_send(&quinn::udp::Transmit {
            destination: socket.remote,
            ecn: None,
            contents: b"late close",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let mut poller = socket.create_io_poller();
    assert!(matches!(
        poller.as_mut().poll_writable(&mut cx),
        Poll::Ready(Ok(()))
    ));
}

fn memory_fixture() -> (MemoryPackets, quinn::Endpoint, mpsc::Sender<Bytes>) {
    let server_address: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let client_address: SocketAddr = "192.0.2.2:1234".parse().unwrap();
    let (to_server, from_client) = mpsc::channel(32);
    let (to_client, from_server) = mpsc::channel(32);
    let client_link = to_client.clone();
    let client_io = MemoryPackets {
        send: to_server,
        receive: from_server,
        remote: server_address,
    };
    let socket = Arc::new(PeerSocket {
        send: to_client,
        receive: Mutex::new(from_client),
        local: server_address,
        remote: client_address,
    });
    let certificate = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.cert.der().clone()], key.into())
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .datagram_receive_buffer_size(Some(64 * 1024))
        .mtu_discovery_config(None);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    (client_io, endpoint, client_link)
}

#[tokio::test]
async fn completed_fragment_id_can_be_reused_without_losing_the_next_datagram() {
    let client_address = "192.0.2.2:1234".parse().unwrap();
    let (client_io, endpoint, _) = memory_fixture();
    let queued_packets = Arc::new(AtomicUsize::new(0));
    let peer_queued_packets = queued_packets.clone();
    let peer = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let (request, mut response) = h3
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        assert_eq!(request.uri().path(), "/auth");
        response
            .send_response(
                http::Response::builder()
                    .status(233)
                    .header("Hysteria-UDP", "true")
                    .header("Hysteria-CC-RX", "0")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        response.finish().await.unwrap();
        // Native Hysteria randomizes its 16-bit Packet ID. A completed ID can
        // recur, including immediately; Mihomo releases the completed pieces.
        let mut sibling_packet_ids = Vec::new();
        for (sequence, id) in [17_u16, 18, 17, 17].into_iter().enumerate() {
            let request = loop {
                let Ok(request) = connection.read_datagram().await else {
                    break None;
                };
                if request[..4] != [0; 4] {
                    sibling_packet_ids.push(u16::from_be_bytes([request[4], request[5]]));
                    continue;
                }
                // Saturation traffic is deliberately fragmented. The
                // cancelled admission must not consume another Packet ID.
                if request[7] > 1 {
                    continue;
                }
                break Some(request);
            };
            let Some(request) = request else { break };
            let target = format!("192.0.2.{}:53", sequence + 10);
            assert_eq!(
                u16::from_be_bytes([request[4], request[5]]),
                (sequence
                    + if sequence > 0 {
                        peer_queued_packets.load(Ordering::Relaxed)
                    } else {
                        0
                    }) as u16
            );
            assert_eq!(&request[6..8], &[0, 1]);
            assert_eq!(usize::from(request[8]), target.len());
            assert_eq!(&request[9..request.len() - 1], target.as_bytes());
            assert_eq!(request[request.len() - 1], sequence as u8);
            // Literal protocol fixtures, independent of Vole's wire encoder.
            // Out of order plus a duplicate within the unfinished assembly.
            for index in [1, 1, 0] {
                let mut frame = request[..4].to_vec();
                frame.extend_from_slice(&id.to_be_bytes());
                frame.extend_from_slice(&[index, 2, target.len() as u8]);
                frame.extend_from_slice(target.as_bytes());
                frame.extend_from_slice(&[sequence as u8; 50]);
                connection.send_datagram_wait(frame.into()).await.unwrap();
            }
        }
        connection.closed().await;
        drop(h3);
        endpoint.close(0_u32.into(), b"");
        endpoint.wait_idle().await;
        sibling_packet_ids
    });
    let config = Config::parse_yaml(br#"{"mixed-port":1080,"proxies":[{"name":"peer","type":"hysteria2","server":"192.0.2.1","port":443,"udp":true,"udp-mtu":64,"skip-cert-verify":true,"sni":"fixture.invalid"}],"rules":["MATCH,peer"]}"#).unwrap();
    let ProxyProtocol::Hysteria2(config) = &config.proxies[0].protocol else {
        panic!("protocol")
    };
    let outbound = Hysteria2Outbound::new_with_path(
        config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(client_io))))),
    )
    .unwrap();
    let mut udp = tokio::time::timeout(
        Duration::from_secs(2),
        outbound.open_datagram(
            DatagramRequest::new(DatagramSession::new(
                InboundKind::InternalMeasure,
                client_address,
            )),
            &EstablishContext::default(),
        ),
    )
    .await
    .expect("memory peer must authenticate")
    .unwrap();
    let mut sibling = outbound
        .open_datagram(
            DatagramRequest::new(DatagramSession::new(
                InboundKind::InternalMeasure,
                client_address,
            )),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
    let shareable = udp.supports_shared_destinations();
    let mut delivered = Vec::new();
    let mut shared_sender_blocked = false;
    let mut shutdown_rejected_admission = false;
    let mut shutdown_queued = 0;
    let outcome = tokio::time::timeout(Duration::from_secs(2), async {
        for sequence in 0..4 {
            assert!(futures_util::poll!(udp.receive()).is_pending());
            let target = Destination::Ip(format!("192.0.2.{}:53", sequence + 10).parse().unwrap());
            let request = Datagram {
                remote: target.clone(),
                payload: vec![sequence].into(),
                sniffed_domain: None,
            };
            if sequence == 1 {
                let large = Datagram {
                    payload: vec![sequence; 4096].into(),
                    ..request.clone()
                };
                loop {
                    let mut pending = Box::pin(tokio::task::unconstrained(udp.send(large.clone())));
                    if let Poll::Ready(result) = futures_util::poll!(pending.as_mut()) {
                        result.unwrap();
                        drop(pending);
                        let accepted = queued_packets.fetch_add(1, Ordering::Relaxed) + 1;
                        assert!(accepted <= vole::limits::HY2_SUBMISSION_QUEUE);
                        continue;
                    }
                    let probe = Datagram {
                        remote: target.clone(),
                        payload: vec![255].into(),
                        sniffed_domain: None,
                    };
                    let mut waiting =
                        Box::pin(tokio::task::unconstrained(sibling.send(probe.clone())));
                    shared_sender_blocked = match futures_util::poll!(waiting.as_mut()) {
                        Poll::Pending => true,
                        Poll::Ready(result) => {
                            result.unwrap();
                            false
                        }
                    };
                    drop(waiting);
                    drop(pending);
                    if shared_sender_blocked {
                        sibling.send(probe).await.unwrap();
                    }
                    break;
                }
            }
            udp.send(request).await.unwrap();
            let reply = udp.receive().await.unwrap();
            assert_eq!(reply.remote, target);
            assert_eq!(reply.payload, vec![sequence; 100]);
            delivered.push(sequence);
        }
        let mut admitted = 0;
        loop {
            let mut pending = Box::pin(tokio::task::unconstrained(udp.send(Datagram {
                remote: Destination::Ip("192.0.2.13:53".parse().unwrap()),
                payload: vec![0; 4096].into(),
                sniffed_domain: None,
            })));
            if let Poll::Ready(result) = futures_util::poll!(pending.as_mut()) {
                result.unwrap();
                drop(pending);
                admitted += 1;
                assert!(admitted <= vole::limits::HY2_SUBMISSION_QUEUE);
                continue;
            }
            outbound.begin_shutdown();
            shutdown_queued = admitted;
            shutdown_rejected_admission = matches!(
                pending.await,
                Err(vole::dispatch::DispatchError::NotAllowed)
            );
            break;
        }
        sibling.close().await.unwrap();
        udp.close().await.unwrap();
    })
    .await;
    outbound.shutdown().await;
    let sibling_packet_ids = tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    assert!(
        shared_sender_blocked,
        "a sibling bypassed the saturated connection queue"
    );
    assert_eq!(
        queued_packets.load(Ordering::Relaxed),
        vole::limits::HY2_SUBMISSION_QUEUE
    );
    assert_eq!(shutdown_queued, vole::limits::HY2_SUBMISSION_QUEUE);
    assert!(
        shutdown_rejected_admission,
        "Stop admitted a queued UDP send"
    );
    assert_eq!(
        sibling_packet_ids,
        [0],
        "a cancelled writer reserved a Packet ID"
    );
    assert_eq!(
        delivered,
        [0, 1, 2, 3],
        "completed Packet IDs are not replay nonces"
    );
    outcome.expect("all legal replies, including completed ID reuse, must be delivered");
    assert!(
        shareable,
        "multi-target HY2 must not allocate a receiver per IP target"
    );
}

#[tokio::test(start_paused = true)]
async fn configured_handshake_timeout_bounds_quic_and_auth_but_not_ready_sessions() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio_util::sync::CancellationToken;
    use vole::dispatch::DispatchError;

    // Field seconds are parsed from actual configuration. Tokio and Quinn use
    // the same controlled monotonic clock; no socket or alternate TLS provider.
    for (phase, timeout, parent_ms, expected_ms) in [
        ("quic", 0, 2000, 1800),
        ("quic", 1, 3000, 1000),
        ("quic", 1, 500, 300),
        ("auth", 1, 3000, 1000),
        ("ready", 1, 3000, 0),
    ] {
        let (client_io, endpoint, client_link) = memory_fixture();
        let initial_observed = Arc::new(AtomicBool::new(false));
        let auth_observed = Arc::new(AtomicBool::new(false));
        let stop_peer = CancellationToken::new();
        let peer = {
            let endpoint = endpoint.clone();
            let initial_observed = initial_observed.clone();
            let auth_observed = auth_observed.clone();
            let stop = stop_peer.clone();
            tokio::spawn(async move {
                let initial = endpoint.accept().await.unwrap();
                initial_observed.store(true, Ordering::Release);
                if phase == "quic" {
                    // A real parsed QUIC Initial is retained without accepting
                    // its handshake. The configured field must end this wait.
                    stop.cancelled().await;
                    drop(initial);
                    return;
                }
                let connection = initial.await.unwrap();
                let mut h3 = h3::server::builder()
                    .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
                let (request, mut response) = h3
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.method(), http::Method::POST);
                assert_eq!(request.uri().path(), "/auth");
                auth_observed.store(true, Ordering::Release);
                if phase == "ready" {
                    response
                        .send_response(
                            http::Response::builder()
                                .status(233)
                                .header("Hysteria-UDP", "true")
                                .header("Hysteria-CC-RX", "0")
                                .body(())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    response.finish().await.unwrap();
                    let packet = connection.read_datagram().await.unwrap();
                    connection.send_datagram_wait(packet).await.unwrap();
                }
                // In the auth case no response is sent: QUIC/TLS succeeded,
                // but this second real establishment stage is still bounded.
                connection.closed().await;
                drop((h3, response));
            })
        };
        let raw = serde_json::json!({
            "proxies": [{"name":"peer", "type":"hysteria2", "server":"192.0.2.1",
                "port":443, "udp":true, "skip-cert-verify":true, "sni":"fixture.invalid",
                "handshake-timeout":timeout}],
            "rules":["MATCH,peer"]
        });
        let parsed = Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
        let ProxyProtocol::Hysteria2(config) = &parsed.proxies[0].protocol else {
            panic!("Hysteria2")
        };
        let outbound = Hysteria2Outbound::new_with_path(
            config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(client_io))))),
        )
        .unwrap();
        let context = EstablishContext::with_timeout(Duration::from_millis(parent_ms));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = tokio::time::Instant::now();
        let request = || {
            DatagramRequest::new(DatagramSession::new(
                InboundKind::InternalMeasure,
                "192.0.2.2:1234".parse().unwrap(),
            ))
        };
        let result = outbound.open_datagram(request(), &context).await;
        let elapsed = started.elapsed();
        assert!(initial_observed.load(Ordering::Acquire));
        if phase == "ready" {
            let first = result.unwrap();
            assert!(auth_observed.load(Ordering::Acquire));
            tokio::time::sleep(Duration::from_secs(2)).await;
            // A new logical UDP owner reuses the ready physical connection
            // after its one-second handshake-only deadline has elapsed.
            let mut reused = outbound
                .open_datagram(request(), &EstablishContext::default())
                .await
                .unwrap();
            let payload = Datagram {
                remote: Destination::domain("x", 1).unwrap(),
                payload: Bytes::from_static(b"after-handshake-deadline"),
                sniffed_domain: None,
            };
            reused.send(payload.clone()).await.unwrap();
            let echo = reused.receive().await.unwrap();
            assert_eq!(echo.remote, payload.remote);
            assert_eq!(echo.payload, payload.payload);
            outbound.shutdown().await;
            assert!(reused.receive().await.is_err());
            drop((first, reused));
        } else {
            assert!(matches!(result, Err(DispatchError::TimedOut)));
            assert_eq!(elapsed, Duration::from_millis(expected_ms));
            assert_eq!(auth_observed.load(Ordering::Acquire), phase == "auth");
            outbound.shutdown().await;
        }
        assert!(
            client_link.is_closed(),
            "Stop must join the controlled raw path"
        );
        stop_peer.cancel();
        endpoint.close(0_u8.into(), b"");
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn authenticated_sessions_preserve_source_budget_and_join_together() {
    use futures_util::FutureExt;
    use std::{collections::VecDeque, panic::AssertUnwindSafe};
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport, DispatchError},
        outbound::ConnectedStream,
        session::StreamSession,
    };
    struct Links(Mutex<VecDeque<MemoryPackets>>);
    #[async_trait::async_trait]
    impl OutboundConnector for Links {
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
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .map(|link| Box::new(link) as Box<dyn DatagramTransport>)
                .ok_or(DispatchError::NotAllowed)
        }
    }
    for (down, expected) in [(0, vec![0_u64, 0]), (5, vec![2, 3]), (1, vec![1])] {
        let rates = if down == 0 {
            String::new()
        } else {
            format!(r#", "up":"1 Mbps", "down":"{down} Bps""#)
        };
        let yaml = format!(
            r#"{{"proxies":[{{"name":"peer","type":"hysteria2","server":"192.0.2.1","port":443,"udp":true{rates},"skip-cert-verify":true,"sni":"fixture.invalid"}}],"rules":["MATCH,peer"]}}"#
        );
        // Parse before starting peers, including the actual omitted-field auto case.
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let ProxyProtocol::Hysteria2(config) = &config.proxies[0].protocol else {
            panic!("protocol")
        };
        let mut links = VecDeque::new();
        let mut servers = Vec::new();
        let mut client_links = Vec::new();
        for _ in &expected {
            let (link, endpoint, client_link) = memory_fixture();
            links.push_back(link);
            servers.push(endpoint);
            client_links.push(client_link);
        }
        let upstream = Arc::new(Links(Mutex::new(links)));
        let outbound =
            Hysteria2Outbound::new_with_path(config, UpstreamPath::proxy(upstream.clone()))
                .unwrap();
        let mut peers = Vec::new();
        for (slot, endpoint) in servers.iter().cloned().enumerate() {
            peers.push(tokio::spawn(async move {
                // Closing an unused peer after a RED must also terminate accept.
                let Some(incoming) = endpoint.accept().await else {
                    return None;
                };
                let connection = incoming.await.unwrap();
                let mut h3 = h3::server::builder()
                    .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
                let (request, mut response) = h3
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                let declared: u64 = request.headers()["Hysteria-CC-RX"]
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                response
                    .send_response(
                        http::Response::builder()
                            .status(233)
                            .header("Hysteria-UDP", "true")
                            .header("Hysteria-CC-RX", "0")
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                response.finish().await.unwrap();
                while let Ok(packet) = connection.read_datagram().await {
                    // A label from the actual authenticated peer, not a copy of
                    // the production source hash or slot-count formula.
                    let mut reply = packet.to_vec();
                    reply.push(slot as u8);
                    if connection.send_datagram_wait(reply.into()).await.is_err() {
                        break;
                    }
                }
                drop(h3);
                endpoint.close(0_u32.into(), b"");
                endpoint.wait_idle().await;
                Some(declared)
            }));
        }
        let budget = DatagramBudget::new(1, 2);
        let remote = Destination::Ip("192.0.2.10:53".parse().unwrap());
        let mut assignment = [None; 32];
        let mut retained: Vec<Option<Box<dyn DatagramTransport>>> =
            expected.iter().map(|_| None).collect();
        let mut correct = Vec::new();
        let outcome = AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(3), async {
            for _ in 0..2 {
                for index in 0..32_u8 {
                    let mut udp = outbound
                        .open_datagram(
                            DatagramRequest::new(DatagramSession::new(
                                InboundKind::InternalMeasure,
                                SocketAddr::from(([192, 0, 2, 2], 20000 + u16::from(index))),
                            ))
                            .with_budget(budget),
                            &EstablishContext::default(),
                        )
                        .await?;
                    let oversized = udp
                        .send(Datagram {
                            remote: remote.clone(),
                            payload: Bytes::from_static(&[0, 0]),
                            sniffed_domain: None,
                        })
                        .await
                        .is_err();
                    udp.send(Datagram {
                        remote: remote.clone(),
                        payload: vec![index].into(),
                        sniffed_domain: None,
                    })
                    .await?;
                    let reply = udp.receive().await?;
                    let slot = reply
                        .payload
                        .get(1)
                        .copied()
                        .filter(|slot| usize::from(*slot) < retained.len());
                    correct.push(
                        oversized
                            && udp.supports_shared_destinations()
                            && udp.payload_budget(&remote) == budget
                            && reply.remote == remote
                            && reply.payload.first() == Some(&index)
                            && reply.payload.len() == 2
                            && slot.is_some()
                            && assignment[usize::from(index)].is_none_or(|old| Some(old) == slot),
                    );
                    if let Some(slot) = slot {
                        assignment[usize::from(index)] = Some(slot);
                        if retained[usize::from(slot)].is_none() {
                            retained[usize::from(slot)] = Some(udp);
                            continue;
                        }
                    }
                    udp.close().await?;
                }
            }
            // Closing sibling associations did not close their shared carrier.
            for (slot, udp) in retained.iter_mut().enumerate() {
                let Some(udp) = udp else { continue };
                udp.send(Datagram {
                    remote: remote.clone(),
                    payload: Bytes::from_static(&[0xa5]),
                    sniffed_domain: None,
                })
                .await?;
                let reply = udp.receive().await?;
                correct.push(reply.remote == remote && reply.payload == [0xa5, slot as u8][..]);
            }
            Ok::<_, DispatchError>(())
        }))
        .catch_unwind()
        .await;
        let owners = retained.len();
        let all_used = retained.iter().all(Option::is_some);
        let stop = AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(3), async {
            outbound.shutdown().await;
            let mut closed = true;
            for udp in retained.iter_mut().flatten() {
                closed &= udp.receive().await.is_err();
            }
            closed
        }))
        .catch_unwind()
        .await;
        let physical_closed = client_links.iter().all(mpsc::Sender::is_closed);
        let all_opened = upstream.0.lock().unwrap().is_empty();
        // Cleanup is unconditional, including an unused auto slot on the RED,
        // a business panic/error, and every individual peer's failed join.
        retained.clear();
        for server in &servers {
            server.close(0_u32.into(), b"");
        }
        upstream.0.lock().unwrap().clear();
        let mut declared = Vec::new();
        let mut peer_ok = true;
        for mut peer in peers {
            match tokio::time::timeout(Duration::from_secs(2), &mut peer).await {
                Ok(Ok(value)) => declared.push(value),
                Ok(Err(_)) => peer_ok = false,
                Err(_) => {
                    peer.abort();
                    let _ = peer.await;
                    peer_ok = false;
                }
            }
        }
        let mut drained = true;
        for server in &servers {
            drained &= tokio::time::timeout(Duration::from_secs(2), server.wait_idle())
                .await
                .is_ok();
        }
        // If the first bounded Stop failed, closing all peer paths above gives
        // its cancelled drivers a final chance to join before any assertion.
        let cleanup = AssertUnwindSafe(tokio::time::timeout(
            Duration::from_secs(3),
            outbound.shutdown(),
        ))
        .catch_unwind()
        .await;
        drop(servers);
        drop(outbound);
        drop(upstream);
        declared.sort_unstable();
        assert!(peer_ok && drained, "every memory peer must join and drain");
        assert!(matches!(cleanup, Ok(Ok(()))), "node cleanup must join");
        assert_eq!(declared, expected.into_iter().map(Some).collect::<Vec<_>>());
        outcome.unwrap().unwrap().unwrap();
        assert_eq!(correct, vec![true; 64 + owners]);
        assert!(all_used && all_opened, "every real carrier must be used");
        assert!(
            matches!(stop, Ok(Ok(true))),
            "Stop must terminate logical owners"
        );
        assert!(
            physical_closed,
            "Stop must close every controlled physical receiver"
        );
    }
}
