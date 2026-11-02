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

mod packetaddr_xhttp_memory {
    use super::*;
    use std::{future::Future, io, pin::Pin, task::Poll};
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::sync::CancellationToken;
    use vole::session::{Datagram, DatagramSession};

    struct Post {
        body: Vec<u8>,
        acknowledge: oneshot::Sender<()>,
    }

    // Actual H2 request/response bodies drive the production PacketUp writer.
    // Delaying this response is stronger than mocking poll_flush or a bool.
    async fn peer(
        raw: tokio::io::DuplexStream,
        posts: mpsc::Sender<Post>,
        mut replies: mpsc::Receiver<bytes::Bytes>,
        mut stop: oneshot::Receiver<()>,
    ) -> io::Result<()> {
        let mut connection = h2::server::handshake(raw).await.map_err(io::Error::other)?;
        let cancel = CancellationToken::new();
        let mut handlers = tokio::task::JoinSet::new();
        let mut download: Option<h2::SendStream<bytes::Bytes>> = None;
        let result = async {
            loop {
                tokio::select! {
                    _ = &mut stop => break,
                    reply = replies.recv() => {
                        let Some(reply) = reply else { break; };
                        download.as_mut()
                            .ok_or(io::ErrorKind::NotConnected)?
                            .send_data(reply, false)
                            .map_err(io::Error::other)?;
                    }
                    incoming = connection.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let (request, mut response) = incoming.map_err(io::Error::other)?;
                        if request.method() == http::Method::GET {
                            if download.is_some() {
                                return Err(io::ErrorKind::InvalidData.into());
                            }
                            download = Some(response
                                .send_response(http::Response::new(()), false)
                                .map_err(io::Error::other)?);
                            continue;
                        }
                        if request.method() != http::Method::POST {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        let posts = posts.clone();
                        let cancel = cancel.clone();
                        handlers.spawn(async move {
                            let mut input = request.into_body();
                            let mut body = Vec::new();
                            loop {
                                let next = tokio::select! {
                                    _ = cancel.cancelled() => return Ok::<(), io::Error>(()),
                                    next = input.data() => next,
                                };
                                let Some(next) = next else { break; };
                                let next = next.map_err(io::Error::other)?;
                                if body.len() + next.len() > 8192 {
                                    return Err(io::ErrorKind::InvalidData.into());
                                }
                                body.extend_from_slice(&next);
                                input.flow_control().release_capacity(next.len())
                                    .map_err(io::Error::other)?;
                            }
                            let (acknowledge, accepted) = oneshot::channel();
                            tokio::select! {
                                _ = cancel.cancelled() => return Ok(()),
                                result = posts.send(Post {body, acknowledge}) => {
                                    result.map_err(|_| io::ErrorKind::BrokenPipe)?;
                                }
                            }
                            tokio::select! {
                                _ = cancel.cancelled() => return Ok(()),
                                result = accepted => {
                                    if result.is_err() { return Ok(()); }
                                }
                            }
                            response.send_response(http::Response::new(()), true)
                                .map_err(io::Error::other)?;
                            Ok(())
                        });
                    }
                }
            }
            Ok::<(), io::Error>(())
        }
        .await;
        cancel.cancel();
        drop(download);
        drop(connection);
        while let Some(joined) = handlers.join_next().await {
            joined.map_err(io::Error::other)??;
        }
        result
    }

    async fn next_post<F>(
        send: &mut Pin<Box<F>>,
        completed: &mut Option<Result<(), DispatchError>>,
        posts: &mut mpsc::Receiver<Post>,
    ) -> Result<Post, String>
    where
        F: Future<Output = Result<(), DispatchError>>,
    {
        tokio::time::timeout(Duration::from_secs(2), async {
            if completed.is_none() {
                tokio::select! {
                    result = send.as_mut() => {
                        *completed = Some(result);
                        posts.recv().await
                    }
                    post = posts.recv() => post,
                }
            } else {
                posts.recv().await
            }
        })
        .await
        .map_err(|_| "actual packet-up POST did not arrive".to_owned())?
        .ok_or_else(|| "memory HTTP peer ended".to_owned())
    }

    fn packet(port: u16, data: &'static [u8]) -> Datagram {
        Datagram {
            remote: Destination::Ip(std::net::SocketAddr::from(([192, 0, 2, 1], port))),
            payload: bytes::Bytes::from_static(data),
            sniffed_domain: None,
        }
    }

    fn wire(packet: &Datagram) -> Vec<u8> {
        use bytes::BufMut;
        let mut frame = bytes::BytesMut::new();
        frame.put_u16(0);
        vole::outbound::address::encode_packet_addr(&packet.remote, &mut frame).unwrap();
        frame.extend_from_slice(&packet.payload);
        let length = (frame.len() - 2) as u16;
        frame[..2].copy_from_slice(&length.to_be_bytes());
        frame.to_vec()
    }

    #[tokio::test(start_paused = true)]
    async fn packetaddr_xhttp_keeps_first_flush_and_drives_last_datagram_without_post_ack() {
        let (io, raw_peer) = tokio::io::duplex(64 * 1024);
        let outbound = node(
            Box::new(io),
            serde_json::json!({
                "network":"xhttp", "packet-encoding":"packetaddr",
                "xhttp-opts":{
                    "path":"/packetaddr-memory", "mode":"packet-up",
                    "sc-min-posts-interval-ms":"10", "x-padding-bytes":"64"
                }
            }),
        );
        let (post_tx, mut posts) = mpsc::channel(4);
        let (replies, reply_rx) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let mut remote = tokio::spawn(peer(raw_peer, post_tx, reply_rx, stopped));
        let mut transport = None;
        let observed = async {
            let request = DatagramRequest::new(DatagramSession::new(
                InboundKind::InternalMeasure,
                "127.0.0.1:1".parse().unwrap(),
            ));
            transport = Some(
                outbound
                    .open_datagram(
                        request,
                        &EstablishContext::with_timeout(Duration::from_secs(30)),
                    )
                    .await
                    .map_err(|error| format!("open_datagram: {error:?}"))?,
            );
            let client = transport.as_mut().unwrap();
            let first = packet(53, b"first");
            let last = packet(54, b"last");
            let mut first_send = Box::pin(client.send(first.clone()));
            let mut first_done = None;
            let header = next_post(&mut first_send, &mut first_done, &mut posts).await?;
            let expected_header = vole::outbound::encode_request_header(
                uuid::Uuid::from_bytes([7; 16]),
                vole::outbound::VlessCommand::Udp,
                Some(&Destination::domain("sp.packet-addr.v2fly.arpa", 443).unwrap()),
            )
            .unwrap();
            let header_exact = header.body.as_slice() == expected_header.as_ref();
            let waits_for_header_ack = first_done.is_none();
            header
                .acknowledge
                .send(())
                .map_err(|_| "header POST disappeared")?;

            let first_data = next_post(&mut first_send, &mut first_done, &mut posts).await?;
            if first_done.is_none()
                && let Poll::Ready(done) = futures_util::poll!(first_send.as_mut())
            {
                first_done = Some(done);
            }
            let first_exact = first_data.body == wire(&first);
            let waits_for_first_data_ack = first_done.is_none();
            first_data
                .acknowledge
                .send(())
                .map_err(|_| "first data POST disappeared")?;
            if first_done.is_none() {
                first_done = Some(first_send.as_mut().await);
            }
            first_done
                .unwrap()
                .map_err(|error| format!("first send: {error:?}"))?;
            drop(first_send);

            // Exactly one final datagram follows the established first frame.
            // No subsequent send/flush may accidentally drive its last bytes.
            let mut last_send = Box::pin(client.send(last.clone()));
            let mut last_done = None;
            let final_post = next_post(&mut last_send, &mut last_done, &mut posts).await?;
            if last_done.is_none()
                && let Poll::Ready(done) = futures_util::poll!(last_send.as_mut())
            {
                last_done = Some(done);
            }
            let last_admitted_before_ack = matches!(&last_done, Some(Ok(())));
            let last_exact = final_post.body == wire(&last);
            drop(last_send);

            // The synthetic server replies on the real GET response only after
            // its actual POST body has arrived, while withholding that POST's
            // HTTP acknowledgement. This detects a receive-side flush stall.
            let mut response = vec![0, 0];
            response.extend(wire(&last));
            replies
                .send(bytes::Bytes::from(response))
                .await
                .map_err(|_| "download stream disappeared")?;
            let received = tokio::time::timeout(Duration::from_millis(100), client.receive()).await;
            let reply_before_post_ack = matches!(&received, Ok(Ok(packet))
                if packet.remote == last.remote && packet.payload == last.payload);
            // A cancelled send must resume its pending frame and consume
            // the already-present reply after the acknowledgement.
            final_post
                .acknowledge
                .send(())
                .map_err(|_| "final POST disappeared")?;
            let recovered = match received {
                Ok(Ok(packet)) => Some(packet),
                Ok(Err(error)) => return Err(format!("receive: {error:?}")),
                Err(_) => Some(
                    tokio::time::timeout(Duration::from_secs(1), client.receive())
                        .await
                        .map_err(|_| "pending frame could not resume after POST ack")?
                        .map_err(|error| format!("resumed receive: {error:?}"))?,
                ),
            };
            let recovery_exact = recovered.is_some_and(|packet| {
                packet.remote == last.remote && packet.payload == last.payload
            });
            Ok::<_, String>((
                header_exact,
                waits_for_header_ack,
                first_exact,
                waits_for_first_data_ack,
                last_exact,
                last_admitted_before_ack,
                reply_before_post_ack,
                recovery_exact,
            ))
        }
        .await;

        // Finish owned tasks before asserting the observed IO guarantees.
        let core_stopped = tokio::time::timeout(Duration::from_secs(1), outbound.shutdown()).await;
        drop(transport);
        let _ = stop.send(());
        let joined = match tokio::time::timeout(Duration::from_secs(1), &mut remote).await {
            Ok(result) => Some(result),
            Err(_) => {
                remote.abort();
                let _ = remote.await;
                None
            }
        };
        assert!(
            core_stopped.is_ok(),
            "Core Stop did not join its real PacketUp tasks"
        );
        assert!(
            matches!(joined, Some(Ok(Ok(())))),
            "owned memory HTTP peer failed/joined late"
        );
        let (header, header_flush, first, first_flush, last, admitted, reply, recovered) =
            observed.unwrap();
        assert!(
            header && first && last && recovered,
            "actual packetaddr bytes/source changed"
        );
        assert!(
            header_flush && first_flush,
            "setup/first frame bypassed real POST acknowledgement"
        );
        assert!(
            admitted && reply,
            "real POST body was received; send_before_ack={admitted}, reply_before_ack={reply}; established packetaddr still waits for POST acknowledgement"
        );
    }
}
