//! Packet-up scheduling against a memory HTTP/2 peer with paused Tokio time.
use super::*;
use crate::config::xhttp::XHttpRequestOptions;
use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{Instant, advance, timeout},
};

struct Packet {
    arrived: Instant,
    path: String,
    body: Vec<u8>,
    response: h2::server::SendResponse<Bytes>,
}

struct Fixture {
    writer: Writer,
    owner: Arc<DriverOwner>,
    connection: Arc<ConnectionGuard>,
    packets: mpsc::Receiver<Packet>,
    server: JoinHandle<()>,
}

impl Fixture {
    async fn new(interval_ms: usize) -> Self {
        Self::with_limit(interval_ms, 4).await
    }

    async fn with_limit(interval_ms: usize, post_bytes: usize) -> Self {
        Self::with_request_options(normalized_packet_options(
            Some(&interval_ms.to_string()),
            post_bytes,
            false,
        ))
        .await
    }

    async fn with_request_options(options: XHttpRequestOptions) -> Self {
        let chunk = options.post_bytes.max.min(crate::limits::XHTTP_BODY_CHUNK);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (packets, receiver) = mpsc::channel(2);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let mut handlers = JoinSet::new();
            while let Some(incoming) = connection.accept().await {
                let Ok((request, response)) = incoming else {
                    break;
                };
                let arrived = Instant::now();
                let packets = packets.clone();
                handlers.spawn(async move {
                    assert_eq!(request.method(), Method::POST);
                    let path = request.uri().path().to_owned();
                    let mut incoming = request.into_body();
                    let mut body = Vec::new();
                    while let Some(data) = incoming.data().await {
                        let data = data.unwrap();
                        body.extend_from_slice(&data);
                        incoming
                            .flow_control()
                            .release_capacity(data.len())
                            .unwrap();
                    }
                    packets
                        .send(Packet {
                            arrived,
                            path,
                            body,
                            response,
                        })
                        .await
                        .unwrap();
                });
            }
            while let Some(handler) = handlers.join_next().await {
                handler.unwrap();
            }
        });
        let owner = Arc::new(DriverOwner::default());
        let (sender, connection) =
            super::super::h2_driver::connect(Box::new(client_io), 64 * 1024, -1, &owner, false)
                .await
                .unwrap();
        let request = RequestTemplate {
            host: Arc::from("example.com"),
            path: Arc::from("/x"),
            headers: Default::default(),
            options: Arc::new(options),
        };
        let writer = Writer::new(sender, request, Arc::from("session"), chunk, &owner).unwrap();
        Self {
            writer,
            owner,
            connection,
            packets: receiver,
            server,
        }
    }

    async fn next(&mut self) -> Packet {
        timeout(Duration::from_secs(2), self.packets.recv())
            .await
            .expect("packet-up driver did not submit its owned POST")
            .expect("memory HTTP peer exited")
    }

    async fn close(self) {
        self.owner.cancellation.cancel();
        self.owner.tasks.close();
        self.owner.tasks.wait().await;
        assert!(self.owner.tasks.is_empty());
        drop(self.writer);
        drop(self.connection);
        drop(self.packets);
        timeout(Duration::from_secs(1), self.server)
            .await
            .expect("owned memory HTTP peer survived Stop")
            .unwrap();
    }
}

fn acknowledge(packet: &mut Packet, status: StatusCode) {
    packet
        .response
        .send_response(Response::builder().status(status).body(()).unwrap(), true)
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn irregular_writes_keep_allocation_within_the_batch_limit() {
    for limit in [crate::limits::XHTTP_PACKET_BATCH_BYTES, 5000] {
        let mut fixture = Fixture::with_limit(100, limit).await;
        assert_eq!(
            fixture
                .writer
                .shared
                .state
                .lock()
                .unwrap()
                .buffer
                .capacity(),
            0
        );
        let mut expected = Vec::new();
        while expected.len() < limit {
            let count = if expected.is_empty() { 17 } else { 1431 }.min(limit - expected.len());
            let bytes = vec![(expected.len() % 251) as u8; count];
            fixture.writer.write_all(&bytes).await.unwrap();
            expected.extend_from_slice(&bytes);
            let allocated = fixture
                .writer
                .shared
                .state
                .lock()
                .unwrap()
                .buffer
                .capacity();
            assert!(
                allocated <= limit,
                "allocated {allocated} bytes for a {limit}-byte batch",
            );
        }
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(
                Pin::new(&mut fixture.writer)
                    .poll_write(cx, b"full")
                    .is_pending()
            ))
            .await
        );
        let mut packet = fixture.next().await;
        assert_eq!(packet.body, expected);
        acknowledge(&mut packet, StatusCode::OK);
        fixture.writer.flush().await.unwrap();
        fixture.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn post_start_interval_credits_request_time_and_idle_time() {
    // All scenarios use the actual production Writer and actual HTTP response.
    // The memory fixture has no delayed send admission; frame-arrival times
    // identify the scheduler's start deadline here, not a global wire guarantee.
    for (request_ms, idle_ms) in [(80, 0), (150, 0), (80, 200)] {
        let mut fixture = Fixture::new(100).await;
        let began = Instant::now();
        fixture.writer.write_all(b"one1").await.unwrap();
        let mut first = fixture.next().await;
        assert_eq!(first.arrived - began, Duration::from_millis(100));
        assert_eq!(first.path, "/x/session/0");
        assert_eq!(first.body, b"one1");
        assert_eq!(fixture.writer.shared.state.lock().unwrap().committed, 0);

        advance(Duration::from_millis(request_ms)).await;
        acknowledge(&mut first, StatusCode::OK);
        fixture.writer.flush().await.unwrap();
        assert_eq!(fixture.writer.shared.state.lock().unwrap().committed, 4);
        advance(Duration::from_millis(idle_ms)).await;
        fixture.writer.write_all(b"two2").await.unwrap();
        let mut second = fixture.next().await;
        assert_eq!(
            second.arrived - first.arrived,
            Duration::from_millis((request_ms + idle_ms).max(100)),
        );
        assert_eq!(second.path, "/x/session/1");
        assert_eq!(second.body, b"two2");
        acknowledge(&mut second, StatusCode::OK);
        fixture.writer.flush().await.unwrap();
        assert_eq!(fixture.writer.shared.state.lock().unwrap().committed, 8);
        fixture.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn pending_post_backpressures_writes_and_failure_does_not_acknowledge() {
    let mut fixture = Fixture::new(100).await;
    fixture.writer.write_all(b"one1").await.unwrap();
    let mut first = fixture.next().await;
    assert_eq!(first.path, "/x/session/0");
    assert_eq!(first.body, b"one1");
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(
            Pin::new(&mut fixture.writer)
                .poll_write(cx, b"two2")
                .is_pending()
        ))
        .await
    );
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(
            Pin::new(&mut fixture.writer).poll_flush(cx).is_pending()
        ))
        .await
    );
    advance(Duration::from_millis(150)).await;
    assert!(matches!(
        fixture.packets.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(fixture.writer.shared.state.lock().unwrap().committed, 0);

    acknowledge(&mut first, StatusCode::INTERNAL_SERVER_ERROR);
    fixture.writer.flush().await.unwrap_err();
    assert_eq!(fixture.writer.shared.state.lock().unwrap().committed, 0);
    fixture.writer.write_all(b"late").await.unwrap_err();
    std::future::poll_fn(|cx| Poll::Ready(fixture.writer.check_read(cx)))
        .await
        .unwrap_err();
    assert!(matches!(
        fixture.packets.try_recv(),
        Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
    ));
    fixture.close().await;
}

#[tokio::test(start_paused = true)]
async fn acknowledged_post_reuses_its_batch_and_wakes_the_waiting_writer() {
    let mut fixture = Fixture::with_limit(100, crate::limits::XHTTP_PACKET_BATCH_BYTES).await;
    let body = vec![0xa5; crate::limits::XHTTP_PACKET_BATCH_BYTES];
    fixture.writer.write_all(&body).await.unwrap();
    let shared = fixture.writer.shared.clone();
    let original = shared.state.lock().unwrap().buffer.as_ptr() as usize;
    let mut first = fixture.next().await;
    assert_eq!(first.body, body);

    let mut waiting = Box::pin(fixture.writer.write_all(b"next"));
    assert!(std::future::poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
    acknowledge(&mut first, StatusCode::OK);
    timeout(Duration::from_secs(2), &mut waiting)
        .await
        .expect("POST completion did not wake the pending writer")
        .unwrap();
    drop(waiting);
    let recycled = shared.state.lock().unwrap().buffer.as_ptr() as usize;
    assert_eq!(recycled, original, "POST body storage was not reused");

    let mut second = fixture.next().await;
    assert_eq!(second.path, "/x/session/1");
    assert_eq!(second.body, b"next");
    acknowledge(&mut second, StatusCode::OK);
    fixture.writer.flush().await.unwrap();
    fixture.close().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_skips_first_delay_and_stop_joins_pending_post() {
    let mut fixture = Fixture::new(60_000).await;
    let began = Instant::now();
    fixture.writer.write_all(b"one1").await.unwrap();
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(
            Pin::new(&mut fixture.writer).poll_shutdown(cx).is_pending()
        ))
        .await
    );
    let first = fixture.next().await;
    assert_eq!(first.arrived, began);
    assert_eq!(first.path, "/x/session/0");
    assert_eq!(first.body, b"one1");
    fixture.writer.write_all(b"late").await.unwrap_err();
    // Keep the real response unresolved. Cancellation must join the driver and
    // wake its actual pending flush, without waiting for a new network event.
    let owner = fixture.owner.clone();
    let stop = tokio::spawn(async move {
        owner.cancellation.cancel();
        owner.tasks.close();
        owner.tasks.wait().await;
        assert!(owner.tasks.is_empty());
    });
    fixture.writer.flush().await.unwrap_err();
    stop.await.unwrap();
    assert_eq!(fixture.writer.shared.state.lock().unwrap().committed, 0);
    drop(first);
    fixture.close().await;
}

fn normalized_packet_options(
    interval: Option<&str>,
    post_bytes: usize,
    download: bool,
) -> XHttpRequestOptions {
    let interval = interval
        .map(|value| format!("      sc-min-posts-interval-ms: {value:?}\n"))
        .unwrap_or_default();
    let download = if download {
        "      download-settings: {}\n"
    } else {
        ""
    };
    let yaml = format!(
        "proxies:\n  - name: fixture\n    type: vless\n    server: 192.0.2.1\n    port: 443\n    uuid: 00000000-0000-0000-0000-000000000001\n    network: xhttp\n    xhttp-opts:\n      mode: packet-up\n      sc-max-each-post-bytes: {post_bytes}\n{interval}{download}rules: ['MATCH,DIRECT']\n"
    );
    let config = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
    let crate::config::ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        panic!("fixture is not VLESS")
    };
    let xhttp = node.xhttp().unwrap();
    if let Some(download) = &xhttp.download {
        assert!(Arc::ptr_eq(&download.request, &xhttp.request));
    }
    (*xhttp.request).clone()
}

#[tokio::test(start_paused = true)]
async fn default_full_batch_submits_without_timer_or_extra_buffer() {
    const CAPACITY: usize = crate::limits::XHTTP_PACKET_BATCH_BYTES;
    for interval in [None, Some("")] {
        let options = normalized_packet_options(interval, 1_000_000, true);
        let mut fixture = Fixture::with_request_options(options).await;
        let began = Instant::now();
        let payload = vec![0xa5; CAPACITY];
        fixture.writer.write_all(&payload).await.unwrap();
        let capacity = fixture
            .writer
            .shared
            .state
            .lock()
            .unwrap()
            .buffer
            .capacity();
        let mut first = fixture.next().await;
        let first_arrived = first.arrived;
        let first_payload = first.body == payload;
        let committed_before_response = fixture.writer.shared.state.lock().unwrap().committed;
        let blocked = std::future::poll_fn(|cx| {
            Poll::Ready(
                Pin::new(&mut fixture.writer)
                    .poll_write(cx, b"next")
                    .is_pending(),
            )
        })
        .await;
        acknowledge(&mut first, StatusCode::OK);
        fixture.writer.flush().await.unwrap();
        let committed_after_response = fixture.writer.shared.state.lock().unwrap().committed;
        fixture.writer.write_all(&payload).await.unwrap();
        let mut second = fixture.next().await;
        let second_arrived = second.arrived;
        let second_payload = second.body == payload;
        acknowledge(&mut second, StatusCode::OK);
        fixture.writer.flush().await.unwrap();
        fixture.close().await;
        assert_eq!(
            first_arrived, began,
            "a full default batch paid the aggregation timer"
        );
        assert_eq!(
            second_arrived, first_arrived,
            "consecutive full default batches were timer-limited"
        );
        assert!(first_payload && second_payload, "full POST payload changed");
        assert!(
            capacity <= CAPACITY,
            "batch allocation exceeded the existing cap"
        );
        assert!(blocked, "an unresolved POST admitted a second batch");
        assert_eq!(
            committed_before_response, 0,
            "admission was mistaken for a POST receipt"
        );
        assert_eq!(committed_after_response, CAPACITY as u64);
    }
}

#[tokio::test(start_paused = true)]
async fn default_partial_and_explicit_full_batches_keep_their_original_interval() {
    for (interval, length, minimum_ms, maximum_ms) in [
        (None, 3, 10, 10),
        (Some(""), 3, 10, 10),
        (Some("10"), crate::limits::XHTTP_PACKET_BATCH_BYTES, 10, 10),
        (
            Some("100-101"),
            crate::limits::XHTTP_PACKET_BATCH_BYTES,
            100,
            101,
        ),
    ] {
        let options = normalized_packet_options(interval, 1_000_000, true);
        let mut fixture = Fixture::with_request_options(options).await;
        let began = Instant::now();
        let payload = vec![0x5a; length];
        fixture.writer.write_all(&payload).await.unwrap();
        let mut packet = fixture.next().await;
        let elapsed = packet.arrived - began;
        let correct = packet.body == payload;
        acknowledge(&mut packet, StatusCode::OK);
        fixture.writer.flush().await.unwrap();
        fixture.close().await;
        assert!(elapsed >= Duration::from_millis(minimum_ms));
        assert!(elapsed <= Duration::from_millis(maximum_ms));
        assert!(correct, "scheduled POST changed accepted bytes");
    }
}

// Actual smux writes into the production PacketUp writer. Read remains pending:
// this test observes upload scheduling, not a second protocol implementation.
struct PacketUploadOnly(Writer);
impl tokio::io::AsyncRead for PacketUploadOnly {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for PacketUploadOnly {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn autonomous_smux_really_fills_default_packet_batch_and_preserves_every_frame() {
    let options = normalized_packet_options(None, 1_000_000, false);
    let Fixture {
        writer,
        owner,
        connection,
        mut packets,
        server,
    } = Fixture::with_request_options(options).await;
    let shared = writer.shared.clone();
    let (client, driver) = crate::transport::smux::new_with_autonomous_writes(
        Box::new(PacketUploadOnly(writer)),
        true,
    );
    let driver = tokio::spawn(driver);
    let mut opening = Box::pin(client.open());
    assert!(futures_util::poll!(opening.as_mut()).is_pending());
    let mut syn = timeout(Duration::from_secs(2), packets.recv())
        .await
        .unwrap()
        .unwrap();
    let stream_id = syn.body[4..8].to_vec();
    assert_eq!(&syn.body[..4], &[1, 0, 0, 0]);
    acknowledge(&mut syn, StatusCode::OK);
    let mut stream = opening.await.unwrap();
    let began = Instant::now();
    let payload = vec![0x3c; crate::limits::XHTTP_PACKET_BATCH_BYTES];
    stream.write_all(&payload).await.unwrap();
    let mut flush = Box::pin(stream.flush());
    assert!(futures_util::poll!(flush.as_mut()).is_pending());
    let mut first = timeout(Duration::from_secs(2), packets.recv())
        .await
        .unwrap()
        .unwrap();
    let first_arrived = first.arrived;
    let first_length = first.body.len();
    let first_backpressure = shared.state.lock().unwrap().in_flight;
    let mut wire = std::mem::take(&mut first.body);
    acknowledge(&mut first, StatusCode::OK);
    let mut tail = timeout(Duration::from_secs(2), packets.recv())
        .await
        .unwrap()
        .unwrap();
    wire.append(&mut tail.body);
    acknowledge(&mut tail, StatusCode::OK);
    flush.await.unwrap();
    let committed = shared.state.lock().unwrap().committed;
    // Stop owns every task. Do not add a FIN contract to this throughput test.
    drop(stream);
    driver.abort();
    let _ = driver.await;
    owner.cancellation.cancel();
    owner.tasks.close();
    owner.tasks.wait().await;
    assert!(owner.tasks.is_empty());
    drop(client);
    drop(connection);
    drop(packets);
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        first_length,
        crate::limits::XHTTP_PACKET_BATCH_BYTES,
        "smux never filled the real batch"
    );
    assert_eq!(
        first_arrived, began,
        "a full smux batch still waited for the default timer"
    );
    assert!(
        first_backpressure,
        "the full POST lost single-batch backpressure"
    );
    let mut decoded = Vec::new();
    let mut input = wire.as_slice();
    while !input.is_empty() {
        assert!(input.len() >= 8, "partial smux frame header");
        assert_eq!(&input[..2], &[1, 2]);
        assert_eq!(&input[4..8], stream_id.as_slice());
        let length = u16::from_le_bytes(input[2..4].try_into().unwrap()) as usize;
        assert!(input.len() >= 8 + length, "partial smux frame payload");
        decoded.extend_from_slice(&input[8..8 + length]);
        input = &input[8 + length..];
    }
    assert_eq!(
        decoded, payload,
        "smux accepted bytes were not fully committed"
    );
    assert_eq!(
        committed as usize,
        8 + wire.len(),
        "POST accounting lost SYN or DATA"
    );
}

#[tokio::test]
async fn h3_batch_boundary_keeps_eager_progress_receipts_and_owner_stop() {
    use crate::transport::quinn_h3::tests::Pair;

    for (post_limit, expected) in [
        (1_000_000, crate::limits::XHTTP_H3_PACKET_BATCH_BYTES),
        (5000, 5000),
    ] {
        let mut pair = Pair::new(128 * 1024).await;
        let (requests, mut server) = pair.h3().await;
        let (posts, mut packets) = mpsc::channel(2);
        pair.spawn(async move {
            while let Some(request) = server.accept().await.unwrap() {
                let (headers, mut stream) = request.resolve_request().await.unwrap();
                assert_eq!(headers.method(), Method::POST);
                let path = headers.uri().path().to_owned();
                let mut body = Vec::new();
                while let Some(mut data) = stream.recv_data().await.unwrap() {
                    body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                posts.send((path, body, stream)).await.unwrap();
            }
        });
        let owner = Arc::new(DriverOwner::default());
        let sender = SendRequest::H3(super::super::h3_driver::Sender {
            requests,
            runtime: pair.client_runtime.clone(),
            #[cfg(feature = "interop-test")]
            observation: pair.client.clone(),
        });
        let request = RequestTemplate {
            host: Arc::from("example.com"),
            path: Arc::from("/x"),
            headers: Default::default(),
            options: Arc::new(normalized_packet_options(None, post_limit, false)),
        };
        let mut writer = Writer::new(
            sender,
            request,
            Arc::from("session"),
            crate::limits::XHTTP_BODY_CHUNK,
            &owner,
        )
        .unwrap();
        assert_eq!(writer.capacity, expected);
        let payload = vec![0xa5; expected];
        // Pause only after the actual QUIC/H3 fixture exists. Observe the
        // production aggregation boundary before letting native timers run.
        tokio::time::pause();
        let began = Instant::now();
        writer.write_all(&payload).await.unwrap();
        let allocated = writer.shared.state.lock().unwrap().buffer.capacity();
        for _ in 0..64 {
            if writer.shared.state.lock().unwrap().in_flight {
                break;
            }
            tokio::task::yield_now().await;
        }
        let eager = writer.shared.state.lock().unwrap().in_flight;
        let no_aggregation_tick = Instant::now() == began;
        tokio::time::resume();
        assert!(
            eager && no_aggregation_tick,
            "full H3 batch paid the aggregation timer"
        );
        assert!(
            allocated <= expected,
            "H3 backing exceeded its selected cap"
        );
        let (path, body, mut first) = timeout(Duration::from_secs(5), packets.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(path, "/x/session/0");
        assert_eq!(body, payload);
        assert_eq!(writer.shared.state.lock().unwrap().committed, 0);
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut writer).poll_write(cx, b"tail")))
                .await
                .is_pending()
        );
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut writer).poll_flush(cx)))
                .await
                .is_pending()
        );
        first.send_response(Response::new(())).await.unwrap();
        first.finish().await.unwrap();
        timeout(Duration::from_secs(5), writer.flush())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            writer.shared.state.lock().unwrap().committed,
            expected as u64
        );
        writer.write_all(&payload).await.unwrap();
        let (path, body, second) = timeout(Duration::from_secs(5), packets.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(path, "/x/session/1");
        assert_eq!(body, payload);
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut writer).poll_shutdown(cx)))
                .await
                .is_pending()
        );
        writer.write_all(b"late").await.unwrap_err();
        owner.cancellation.cancel();
        owner.tasks.close();
        timeout(Duration::from_secs(2), owner.tasks.wait())
            .await
            .unwrap();
        assert!(owner.tasks.is_empty());
        timeout(Duration::from_secs(5), writer.flush())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            writer.shared.state.lock().unwrap().committed,
            expected as u64
        );
        drop(second);
        drop(first);
        drop(writer);
        drop(packets);
        pair.stop().await;
    }
}
