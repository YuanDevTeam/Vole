#![cfg(feature = "stream-transport")]
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::task::TaskTracker;
use vole::{config::GrpcOptions, dispatch::BoxStream, transport::GrpcPool};

struct ObservedIo {
    io: tokio::io::DuplexStream,
    read: Arc<std::sync::Mutex<Vec<u8>>>,
}
impl tokio::io::AsyncRead for ObservedIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let start = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.io).poll_read(cx, buf);
        let mut read = self.read.lock().unwrap();
        read.extend_from_slice(&buf.filled()[start..]);
        assert!(read.len() < 65536);
        result
    }
}
impl tokio::io::AsyncWrite for ObservedIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
fn ping_count(wire: &[u8]) -> usize {
    assert!(wire.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    let mut pos = 24;
    let mut pings = 0;
    while pos + 9 <= wire.len() {
        let len =
            ((wire[pos] as usize) << 16) | ((wire[pos + 1] as usize) << 8) | wire[pos + 2] as usize;
        assert!(pos + 9 + len <= wire.len(), "partial observed frame");
        if wire[pos + 3] == 6 && wire[pos + 4] & 1 == 0 {
            pings += 1;
        }
        pos += 9 + len;
    }
    pings
}
#[tokio::test]
async fn grpc_idle_ping_is_observable_disabled_by_zero_and_joined_at_stop() {
    for interval in [0, 1] {
        let (io, peer) = tokio::io::duplex(65536);
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let peer = ObservedIo {
            io: peer,
            read: observed.clone(),
        };
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            while let Some(Ok((_request, mut respond))) = connection.accept().await {
                let _ = respond.send_response(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap(),
                    true,
                );
            }
        });
        let pool = GrpcPool::new(GrpcOptions {
            ping_interval: interval,
            ..Default::default()
        });
        let stream = pool
            .open(
                "http://example.com/service/Tun",
                tokio::time::Instant::now() + Duration::from_secs(2),
                || async { Ok(Box::new(io) as BoxStream) },
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1250)).await;
        let pings = ping_count(&observed.lock().unwrap());
        assert_eq!(pings > 0, interval > 0);
        pool.shutdown().await;
        drop(stream);
        server.await.unwrap();
        let length = observed.lock().unwrap().len();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(observed.lock().unwrap().len(), length);
    }
}

async fn memory_peer(count: Arc<AtomicUsize>, tasks: TaskTracker) -> io::Result<BoxStream> {
    count.fetch_add(1, Ordering::SeqCst);
    let (io, peer) = tokio::io::duplex(64 * 1024);
    let sessions = tasks.clone();
    tasks.spawn(async move {
        let mut connection = h2::server::handshake(peer).await.unwrap();
        while let Some(Ok((request, mut response))) = connection.accept().await {
            assert_eq!(request.method(), "POST");
            assert_eq!(request.uri().path(), "/service/Tun");
            assert_eq!(request.headers()["user-agent"], "vless-observer");
            let mut send = response
                .send_response(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let mut receive = request.into_body();
            sessions.spawn(async move {
                while let Some(Ok(data)) = receive.data().await {
                    receive.flow_control().release_capacity(data.len()).unwrap();
                    if send.send_data(data, false).is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(Box::new(io))
}
#[tokio::test]
async fn grpc_pool_matches_both_threshold_policies_and_keeps_other_streams_alive() {
    tokio::time::timeout(Duration::from_secs(8), async {
        for (max, min, streams, expected) in [
            (1, 0, 0, vec![1, 1, 1, 1]),
            (2, 2, 0, vec![1, 1, 2, 2]),
            (2, 2, 1, vec![1, 1, 2, 2]),
            (2, 0, 0, vec![1, 2, 2, 2]),
            (0, 0, 2, vec![1, 1, 2, 2, 3]),
            (0, 2, 0, vec![1, 2, 3, 4]),
        ] {
            let tasks = TaskTracker::new();
            let count = Arc::new(AtomicUsize::new(0));
            let pool = GrpcPool::new(GrpcOptions {
                user_agent: "vless-observer".into(),
                max_connections: max,
                min_streams: min,
                max_streams: streams,
                ..Default::default()
            });
            let mut open = Vec::new();
            for expected in expected {
                let mut stream = pool
                    .open(
                        "http://example.com/service/Tun",
                        tokio::time::Instant::now() + Duration::from_secs(2),
                        || memory_peer(count.clone(), tasks.clone()),
                    )
                    .await
                    .unwrap();
                stream.write_all(b"roundtrip").await.unwrap();
                stream.flush().await.unwrap();
                let mut data = [0; 9];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"roundtrip");
                assert_eq!(count.load(Ordering::SeqCst), expected);
                open.push(stream);
            }
            open[0].shutdown().await.unwrap();
            open.last_mut()
                .unwrap()
                .write_all(b"still-open")
                .await
                .unwrap();
            open.last_mut().unwrap().flush().await.unwrap();
            let mut data = [0; 10];
            open.last_mut()
                .unwrap()
                .read_exact(&mut data)
                .await
                .unwrap();
            assert_eq!(&data, b"still-open");
            open.clear();
            let before = count.load(Ordering::SeqCst);
            let mut stream = pool
                .open(
                    "http://example.com/service/Tun",
                    tokio::time::Instant::now() + Duration::from_secs(2),
                    || memory_peer(count.clone(), tasks.clone()),
                )
                .await
                .unwrap();
            assert_eq!(
                before,
                count.load(Ordering::SeqCst),
                "idle connection must always be reused"
            );
            pool.shutdown().await;
            assert!(
                stream.write_all(b"after-stop").await.is_err(),
                "stopped pool accepted a write"
            );
            drop(stream);
            tasks.close();
            tasks.wait().await;
        }
    })
    .await
    .unwrap();
}
