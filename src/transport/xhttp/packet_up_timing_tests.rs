//! Packet-up scheduling against a memory HTTP/2 peer with paused Tokio time.
use super::*;
use crate::config::xhttp::{IntegerRange, XHttpRequestOptions};
use bytes::Bytes;
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
            super::super::h2_driver::connect(Box::new(client_io), 64 * 1024, -1, &owner)
                .await
                .unwrap();
        let request = RequestTemplate {
            host: Arc::from("example.com"),
            path: Arc::from("/x"),
            headers: Default::default(),
            options: Arc::new(XHttpRequestOptions {
                post_bytes: IntegerRange {
                    min: post_bytes,
                    max: post_bytes,
                },
                post_interval_ms: IntegerRange {
                    min: interval_ms,
                    max: interval_ms,
                },
                ..Default::default()
            }),
        };
        let writer = Writer::new(
            sender,
            request,
            Arc::from("session"),
            post_bytes.min(crate::limits::XHTTP_BODY_CHUNK),
            &owner,
        )
        .unwrap();
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
async fn pending_post_keeps_one_filling_batch_and_failure_does_not_acknowledge() {
    let mut fixture = Fixture::new(100).await;
    fixture.writer.write_all(b"one1").await.unwrap();
    let mut first = fixture.next().await;
    assert_eq!(first.path, "/x/session/0");
    assert_eq!(first.body, b"one1");
    fixture.writer.write_all(b"two2").await.unwrap();
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(
            Pin::new(&mut fixture.writer)
                .poll_write(cx, b"last")
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
