#![cfg(feature = "outbound-vless")]
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        VlessOutbound,
    },
    session::{Destination, InboundKind, StreamSession},
};

#[cfg(feature = "interop-test")]
#[tokio::test(start_paused = true)]
async fn grpc_unresponsive_peer_keeps_original_setup_deadline() {
    use std::io;
    use vole::resources::observation::ResourceProbe;

    fn preface_only(wire: &[u8]) -> bool {
        if !wire.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            return false;
        }
        let mut offset = 24;
        while offset + 9 <= wire.len() {
            let length = (usize::from(wire[offset]) << 16)
                | (usize::from(wire[offset + 1]) << 8)
                | usize::from(wire[offset + 2]);
            let end = offset + 9 + length;
            if end > wire.len() || matches!(wire[offset + 3], 0 | 1) {
                return false;
            }
            offset = end;
        }
        offset == wire.len()
    }

    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "grpc_unresponsive_peer_keeps_original_setup_deadline",
    );
    for first_operation in ["flush", "read"] {
        let probe = ResourceProbe::default();
        let (outcome, elapsed, deadline, stopped, joined) = probe
            .scope(async {
                let (io, mut peer) = tokio::io::duplex(4096);
                let outbound = node(
                    Box::new(io),
                    serde_json::json!({"network":"grpc","grpc-opts":{"grpc-service-name":"service"}}),
                );
                // Consume continuously, but never send peer SETTINGS or EOF.
                // Write backpressure cannot stand in for the H2 setup gate.
                let mut remote = tokio::spawn(async move {
                    let mut wire = Vec::new();
                    let mut first_preface = None;
                    let mut input = [0; 1024];
                    loop {
                        let count = peer.read(&mut input).await?;
                        if count == 0 {
                            return Ok::<_, io::Error>((wire, first_preface));
                        }
                        if wire.len() + count > 16 * 1024 {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        wire.extend_from_slice(&input[..count]);
                        if wire.len() >= 24 && first_preface.is_none() {
                            first_preface = Some(tokio::time::Instant::now());
                        }
                    }
                });
                let start = tokio::time::Instant::now();
                let context = EstablishContext::with_timeout(Duration::from_secs(2));
                let deadline = context.deadline();
                let outcome = tokio::time::timeout(Duration::from_secs(3), async {
                    match outbound.connect_stream(session(), &context).await {
                        Err(error) => (
                            "connect",
                            matches!(error, DispatchError::TimedOut),
                            format!("{error:?}"),
                        ),
                        Ok(mut connected) => {
                            let result = if first_operation == "flush" {
                                connected.io.flush().await
                            } else {
                                connected.io.read(&mut [0; 1]).await.map(|_| ())
                            };
                            (
                                first_operation,
                                result.as_ref().is_err_and(|error| error.kind() == io::ErrorKind::TimedOut),
                                format!("{result:?}"),
                            )
                        }
                    }
                })
                .await;
                let elapsed = start.elapsed();
                let stopped = tokio::time::timeout(Duration::from_secs(1), outbound.shutdown()).await;
                let joined = match tokio::time::timeout(Duration::from_secs(1), &mut remote).await {
                    Ok(result) => Some(result),
                    Err(_) => {
                        remote.abort();
                        let _ = remote.await;
                        None
                    }
                };
                drop(outbound);
                (outcome, elapsed, deadline, stopped, joined)
            })
            .await;
        assert!(
            stopped.is_ok(),
            "{first_operation}: Core Stop watchdog expired"
        );
        assert!(
            probe.snapshot().is_idle(),
            "{first_operation}: resources retained after Stop: {:?}",
            probe.snapshot()
        );
        assert!(
            matches!(&joined, Some(Ok(Ok(_)))),
            "{first_operation}: memory peer did not join naturally: {joined:?}"
        );
        let (wire, preface_at) = joined.unwrap().unwrap().unwrap();
        assert!(
            preface_at.is_some_and(|at| at < deadline),
            "{first_operation}: peer did not drain the client preface before the deadline"
        );
        assert!(
            preface_only(&wire),
            "{first_operation}: logical request was sent without peer SETTINGS"
        );
        let (stage, timed_out, detail) =
            outcome.expect("no-SETTINGS scenario reached its three-second watchdog");
        assert!(
            timed_out,
            "{first_operation}: {stage} did not report the original setup timeout: {detail}"
        );
        assert_eq!(
            elapsed,
            Duration::from_secs(2),
            "{first_operation}: setup deadline was changed; stage={stage}, outcome={detail}"
        );
    }
}

struct Supplied(Mutex<Option<BoxStream>>);
#[async_trait::async_trait]
impl OutboundConnector for Supplied {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: self.0.lock().unwrap().take().unwrap(),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn node(io: BoxStream, extra: serde_json::Value) -> VlessOutbound {
    let mut node = serde_json::json!({"name":"edge","type":"vless","server":"example.com","port":443,"uuid":"07070707-0707-0707-0707-070707070707"});
    node.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let config = Config::parse_yaml(
        &serde_json::to_vec(
            &serde_json::json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]}),
        )
        .unwrap(),
    )
    .unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    VlessOutbound::new_with_path(
        node,
        UpstreamPath::proxy(Arc::new(Supplied(Mutex::new(Some(io))))),
    )
    .unwrap()
}
fn session() -> StreamSession {
    StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:1".parse().unwrap(),
        destination: Destination::Ip("192.0.2.1:80".parse().unwrap()),
        sniffed_domain: None,
    }
}

#[tokio::test]
async fn http_camouflage_shutdown_releases_both_directions_without_waiting_for_peer_eof() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "http_camouflage_shutdown_releases_both_directions_without_waiting_for_peer_eof",
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let node = node(Box::new(io), serde_json::json!({"network":"http"}));
        let remote = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(peer.read_u8().await.unwrap());
            }
            let header = vole::outbound::encode_request_header(
                uuid::Uuid::from_bytes([7; 16]),
                vole::outbound::VlessCommand::Tcp,
                Some(&session().destination),
            )
            .unwrap();
            let mut received = vec![0; header.len()];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, header);
            peer.write_all(b"HTTP/1.1 200 OK\r\n\r\n\0\0hello")
                .await
                .unwrap();
            peer
        });
        let mut io = node
            .connect_stream(session(), &EstablishContext::default())
            .await
            .unwrap()
            .io;
        let mut hello = [0; 5];
        io.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        let mut peer = remote.await.unwrap();
        io.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(
            peer.write_all(b"late").await.is_err(),
            "HTTP close retained the read direction"
        );
        assert!(!matches!(io.read(&mut [0;1]).await, Ok(n) if n>0));
        drop(io);
        node.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grpc_server_first_flushes_vless_request_without_an_application_write() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "grpc_server_first_flushes_vless_request_without_an_application_write",
    );
    let (io, peer) = tokio::io::duplex(4096);
    let node = node(
        Box::new(io),
        serde_json::json!({"network":"grpc","grpc-opts":{"grpc-service-name":"service"}}),
    );
    let tasks = tokio_util::task::TaskTracker::new();
    let sessions = tasks.clone();
    tasks.spawn(async move {
        let mut connection = h2::server::handshake(peer).await.unwrap();
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            sessions.spawn(async move {
                let mut receive = request.into_body();
                let Some(Ok(data)) = receive.data().await else {
                    return;
                };
                assert!(!data.is_empty());
                let mut send = respond
                    .send_response(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                send.send_data(
                    bytes::Bytes::from_static(b"\0\0\0\0\x09\x0a\x07\0\0hello"),
                    false,
                )
                .unwrap();
                let _ = receive.data().await;
            });
        }
    });
    let result = async {
        let mut stream = node
            .connect_stream(
                session(),
                &EstablishContext::with_timeout(Duration::from_millis(100)),
            )
            .await
            .unwrap()
            .io;
        let mut answer = [0; 5];
        let result = stream.read_exact(&mut answer).await;
        (result, answer)
    }
    .await;
    node.shutdown().await;
    tasks.close();
    tasks.wait().await;
    result
        .0
        .expect("VLESS request was not flushed before waiting for the response");
    assert_eq!(&result.1, b"hello");
}
#[cfg(feature = "interop-test")]
#[tokio::test(start_paused = true)]
async fn grpc_committed_vless_request_outlives_delayed_http_response() {
    use std::{
        io,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Wake, Waker},
    };
    use vole::resources::observation::ResourceProbe;

    #[derive(Default)]
    struct ReadWake(AtomicUsize);
    impl Wake for ReadWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "grpc_committed_vless_request_outlives_delayed_http_response",
    );
    let probe = ResourceProbe::default();
    let (result, core_stopped, peer_joined) = probe
        .scope(async {
            let (io, peer) = tokio::io::duplex(4096);
            let outbound = node(
                Box::new(io),
                serde_json::json!({"network":"grpc","grpc-opts":{"grpc-service-name":"service"}}),
            );
            let (records, mut observed) = tokio::sync::mpsc::unbounded_channel();
            let mut remote = tokio::spawn(async move {
                let mut connection = h2::server::handshake(peer)
                    .await
                    .map_err(io::Error::other)?;
                let (request, response) = connection
                    .accept()
                    .await
                    .ok_or(io::ErrorKind::UnexpectedEof)?
                    .map_err(io::Error::other)?;
                let receive = async move {
                    // Hold the HTTP response open without sending headers.
                    let _response = response;
                    let mut receive = request.into_body();
                    let mut wire = Vec::new();
                    while let Some(Ok(data)) = receive.data().await {
                        receive
                            .flow_control()
                            .release_capacity(data.len())
                            .map_err(io::Error::other)?;
                        wire.extend_from_slice(&data);
                        while wire.len() >= 5 {
                            let length =
                                u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize;
                            // This fixture sends only small, one-byte protobuf lengths.
                            if wire[0] != 0 || !(2..=256).contains(&length) {
                                return Err(io::ErrorKind::InvalidData.into());
                            }
                            if wire.len() < 5 + length {
                                break;
                            }
                            if wire[5] != 0x0a || wire[6] >= 128 || wire[6] as usize + 2 != length {
                                return Err(io::ErrorKind::InvalidData.into());
                            }
                            records
                                .send(wire[7..5 + length].to_vec())
                                .map_err(|_| io::ErrorKind::BrokenPipe)?;
                            wire.drain(..5 + length);
                        }
                    }
                    Ok::<_, io::Error>(())
                };
                tokio::pin!(receive);
                // accept() drives H2 DATA while the handler waits for uploads.
                tokio::select! {
                    result = &mut receive => result,
                    extra = connection.accept() => match extra {
                        None | Some(Err(_)) => Ok(()),
                        Some(Ok(_)) => Err(io::ErrorKind::InvalidData.into()),
                    },
                }
            });
            let context = EstablishContext::with_timeout(Duration::from_secs(2));
            let result = tokio::time::timeout(Duration::from_secs(30), async {
                let mut stream = outbound
                    .connect_stream(session(), &context)
                    .await
                    .map_err(io::Error::other)?
                    .io;
                // The first operation commits the request, with no application payload.
                stream.flush().await?;
                let header = observed.recv().await.ok_or(io::ErrorKind::UnexpectedEof)?;
                let expected = [
                    b"\0".as_slice(),
                    &[7; 16],
                    b"\0\x01\0\x50\x01\xc0\0\x02\x01",
                ]
                .concat();
                if header != expected {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let (mut reader, mut writer) = tokio::io::split(stream);
                writer.write_all(b"before").await?;
                writer.flush().await?;
                if observed.recv().await.as_deref() != Some(b"before".as_slice()) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let before_deadline = tokio::time::Instant::now() < context.deadline();
                let mut byte = [0; 1];
                let read = reader.read(&mut byte);
                tokio::pin!(read);
                let first = futures_util::poll!(read.as_mut());
                let pending_before = matches!(first, Poll::Pending);
                let after = if pending_before {
                    tokio::time::advance(
                        context
                            .deadline()
                            .saturating_duration_since(tokio::time::Instant::now())
                            + Duration::from_millis(1),
                    )
                    .await;
                    futures_util::poll!(read.as_mut())
                } else {
                    first
                };
                let pending_after = after.is_pending();
                let boundary = format!("{after:?}");
                let continued = if pending_after {
                    writer.write_all(b"after").await?;
                    writer.flush().await?;
                    observed.recv().await.as_deref() == Some(b"after".as_slice())
                } else {
                    false
                };
                // Retain this exact read future across Stop. A separate waker
                // distinguishes notification from a fresh post-Stop poll.
                let wakes = Arc::new(ReadWake::default());
                let stop_pending = pending_after && {
                    let wake = Waker::from(wakes.clone());
                    let mut cx = Context::from_waker(&wake);
                    std::future::Future::poll(read.as_mut(), &mut cx).is_pending()
                };
                let wake_before = wakes.0.load(Ordering::SeqCst);
                // Run Stop before assertions, including the expected RED path.
                outbound.shutdown().await;
                let read_woken = wakes.0.load(Ordering::SeqCst) > wake_before;
                // Never poll a future that already completed on the RED path.
                let stopped_read = if stop_pending {
                    matches!(read.as_mut().await, Ok(0) | Err(_))
                } else {
                    !pending_after
                };
                let stopped_write = writer.write_all(b"after Stop").await.is_err();
                Ok::<_, io::Error>((
                    before_deadline,
                    pending_before,
                    pending_after,
                    continued,
                    stop_pending,
                    read_woken,
                    stopped_read,
                    stopped_write,
                    boundary,
                ))
            })
            .await;
            let core_stopped = tokio::time::timeout(Duration::from_secs(1), outbound.shutdown())
                .await
                .is_ok();
            let peer_joined = match tokio::time::timeout(Duration::from_secs(1), &mut remote).await
            {
                Ok(result) => Some(result),
                Err(_) => {
                    remote.abort();
                    let _ = remote.await;
                    None
                }
            };
            drop(outbound);
            (result, core_stopped, peer_joined)
        })
        .await;
    assert!(core_stopped, "Core Stop did not join its drivers");
    assert!(
        matches!(peer_joined, Some(Ok(Ok(())))),
        "memory H2 peer did not join naturally: {peer_joined:?}"
    );
    assert!(
        probe.snapshot().is_idle(),
        "resources retained after cleanup: {:?}",
        probe.snapshot()
    );
    let (
        before_deadline,
        pending_before,
        pending_after,
        continued,
        stop_pending,
        read_woken,
        stopped_read,
        stopped_write,
        boundary,
    ) = result
        .expect("memory exchange timed out")
        .expect("memory exchange failed");
    assert!(stopped_read && stopped_write, "Stop left active gRPC IO");
    assert!(
        !pending_after || stop_pending,
        "gRPC read completed before Stop"
    );
    assert!(
        !pending_after || read_woken,
        "Stop did not notify the pending gRPC read"
    );
    assert!(
        before_deadline && pending_before,
        "request was not established before the original deadline"
    );
    assert!(
        pending_after && continued,
        "committed VLESS gRPC expired at delayed response: {boundary}"
    );
}

#[tokio::test]
async fn http_upgrade_consumes_early_prefix_and_requires_valid_101_even_fast_open() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "http_upgrade_consumes_early_prefix_and_requires_valid_101_even_fast_open",
    );
    use base64::Engine as _;
    for fast in [false, true] {
        for accept in [false, true] {
            let (io, mut peer) = tokio::io::duplex(4096);
            let node = node(
                Box::new(io),
                serde_json::json!({"network":"ws","ws-opts":{"path":"/upgrade","headers":{"Host":"cover.invalid:443"},"v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":fast,"max-early-data":1}}),
            );
            let remote = tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(peer.read_u8().await.unwrap());
                }
                let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
                assert!(head.starts_with("get /upgrade http/1.1\r\n"));
                assert!(head.contains("host: cover.invalid:443\r\n"));
                assert!(!head.contains("sec-websocket-key"));
                let encoded = head
                    .lines()
                    .find_map(|line| line.strip_prefix("sec-websocket-protocol: "))
                    .unwrap();
                assert_eq!(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(encoded.to_ascii_uppercase())
                        .unwrap(),
                    [0]
                );
                let expected = vole::outbound::encode_request_header(
                    uuid::Uuid::from_bytes([7; 16]),
                    vole::outbound::VlessCommand::Tcp,
                    Some(&session().destination),
                )
                .unwrap();
                let mut rest = vec![0; expected.len() - 1];
                if fast {
                    peer.read_exact(&mut rest).await.unwrap();
                    assert_eq!(rest, &expected[1..]);
                }
                let status = if accept {
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\0\0answer".as_slice()
                } else {
                    b"HTTP/1.1 403 Forbidden\r\n\r\n".as_slice()
                };
                peer.write_all(status).await.unwrap();
                if accept {
                    if !fast {
                        peer.read_exact(&mut rest).await.unwrap();
                        assert_eq!(rest, &expected[1..]);
                    }
                    let mut data = [0; 4];
                    peer.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"body");
                } else {
                    let mut tail = Vec::new();
                    peer.read_to_end(&mut tail).await.unwrap();
                }
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                let result = node
                    .connect_stream(session(), &EstablishContext::default())
                    .await;
                if accept {
                    let mut stream = result.unwrap().io;
                    stream.write_all(b"body").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut answer = [0; 6];
                    stream.read_exact(&mut answer).await.unwrap();
                    assert_eq!(&answer, b"answer");
                } else {
                    assert!(result.is_err(), "failed upgrade reported success");
                }
                remote.await.unwrap();
                node.shutdown().await;
            })
            .await
            .unwrap();
        }
    }
}
