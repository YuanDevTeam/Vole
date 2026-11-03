#![cfg(all(feature = "outbound-vless", feature = "interop-test"))]

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::task::TaskTracker;
use vole::transport::xhttp::{XHttpClient, XHttpConfig, XHttpMode};

fn config(reuse: serde_json::Value) -> XHttpConfig {
    let raw = serde_json::json!({"mixed-port":1080,"proxies":[{"name":"peer","type":"vless","server":"example.com","port":443,"uuid":"07070707-0707-0707-0707-070707070707","network":"xhttp","tls":true,"xhttp-opts":{"mode":"stream-one","reuse-settings":reuse}}],"rules":["MATCH,peer"]});
    let raw = vole::config::Config::parse_yaml(raw.to_string().as_bytes()).unwrap();
    let vole::config::ProxyProtocol::Vless(node) = &raw.proxies[0].protocol else {
        unreachable!()
    };
    let mut config = XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap();
    config.reuse = node.xhttp().unwrap().reuse.clone();
    config
}

async fn ready(stream: &mut vole::dispatch::BoxStream) {
    let mut greeting = [0; 5];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"ready");
}

async fn peer(
    calls: &AtomicUsize,
    tasks: &TaskTracker,
) -> std::io::Result<vole::dispatch::BoxStream> {
    calls.fetch_add(1, Ordering::Relaxed);
    let (io, remote) = tokio::io::duplex(16384);
    tasks.spawn(async move {
        let mut connection = h2::server::handshake(remote).await.unwrap();
        let exchanges = TaskTracker::new();
        let mut downloads = Vec::new();
        while let Some(Ok((request, mut reply))) = connection.accept().await {
            if request.method() == http::Method::GET {
                let mut response = reply.send_response(http::Response::new(()), false).unwrap();
                response
                    .send_data(bytes::Bytes::from_static(b"ready"), false)
                    .unwrap();
                downloads.push(response);
                continue;
            }
            exchanges.spawn(async move {
                let mut body = request.into_body();
                let mut response = reply.send_response(http::Response::new(()), false).unwrap();
                response
                    .send_data(bytes::Bytes::from_static(b"ready"), false)
                    .unwrap();
                while let Some(Ok(data)) = body.data().await {
                    if body.flow_control().release_capacity(data.len()).is_err()
                        || response.send_data(data, false).is_err()
                    {
                        break;
                    }
                }
            });
        }
        exchanges.close();
        exchanges.wait().await;
    });
    Ok(Box::new(io))
}

#[tokio::test]
async fn enabled_reuse_shares_physical_h2_without_one_close_killing_its_sibling() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let probe = vole::resources::observation::ResourceProbe::default();
        probe
            .scope(async {
                let tasks = TaskTracker::new();
                let calls = AtomicUsize::new(0);
                let mut config =
                    XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap();
                config.reuse = Some(Default::default());
                let client = XHttpClient::new(config);
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                let mut first = client
                    .open(deadline, || peer(&calls, &tasks))
                    .await
                    .unwrap();
                let mut second = client
                    .open(deadline, || peer(&calls, &tasks))
                    .await
                    .unwrap();
                for stream in [&mut first, &mut second] {
                    let mut greeting = [0; 5];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(&greeting, b"ready");
                }
                assert_eq!(calls.load(Ordering::Relaxed), 1);
                first.shutdown().await.unwrap();
                second.write_all(b"alive").await.unwrap();
                let mut reply = [0; 5];
                second.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"alive");
                client.stop().await;
                assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
                assert!(second.read(&mut [0; 1]).await.is_err());
                tasks.close();
                tasks.wait().await;
            })
            .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reuse_thresholds_expand_and_retire_without_closing_active_sessions() {
    use serde_json::json;
    tokio::time::timeout(Duration::from_secs(5), async {
        for (settings, counts) in [
            (json!({}), [1, 1, 1]),
            (json!({"max-connections":"2"}), [1, 2, 2]),
            (
                json!({"max-connections":"1","max-concurrency":"1"}),
                [1, 2, 3],
            ),
            (json!({"h-max-request-times":"1"}), [1, 2, 3]),
            (json!({"c-max-reuse-times":"1"}), [1, 1, 2]),
        ] {
            let tasks = TaskTracker::new();
            let calls = AtomicUsize::new(0);
            let client = XHttpClient::new(config(settings.clone()));
            let mut streams = Vec::new();
            for count in counts {
                let mut stream = client
                    .open(tokio::time::Instant::now() + Duration::from_secs(1), || {
                        peer(&calls, &tasks)
                    })
                    .await
                    .unwrap();
                ready(&mut stream).await;
                assert_eq!(calls.load(Ordering::Relaxed), count, "{settings}");
                streams.push(stream);
            }
            for mut stream in streams {
                stream.write_all(b"live").await.unwrap();
                let mut reply = [0; 4];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"live");
                stream.shutdown().await.unwrap();
            }
            client.stop().await;
            tasks.close();
            tasks.wait().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn expired_transport_is_not_assigned_again_while_old_session_stays_live() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let tasks = TaskTracker::new();
        let calls = AtomicUsize::new(0);
        let client = XHttpClient::new(config(serde_json::json!({"h-max-reusable-secs":"1"})));
        let mut first = client
            .open(tokio::time::Instant::now() + Duration::from_secs(1), || {
                peer(&calls, &tasks)
            })
            .await
            .unwrap();
        ready(&mut first).await;
        tokio::time::sleep(Duration::from_millis(1050)).await;
        let mut second = client
            .open(tokio::time::Instant::now() + Duration::from_secs(1), || {
                peer(&calls, &tasks)
            })
            .await
            .unwrap();
        ready(&mut second).await;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        first.write_all(b"a").await.unwrap();
        assert_eq!(first.read_u8().await.unwrap(), b'a');
        first.shutdown().await.unwrap();
        second.shutdown().await.unwrap();
        client.stop().await;
        tasks.close();
        tasks.wait().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pooled_packet_posts_do_not_each_consume_a_transport_lease() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let tasks = TaskTracker::new();
        let calls = AtomicUsize::new(0);
        let posts = std::sync::Arc::new(AtomicUsize::new(0));
        let factory = || {
            calls.fetch_add(1, Ordering::Relaxed);
            let (io, remote) = tokio::io::duplex(16384);
            let posts = posts.clone();
            tasks.spawn(async move {
                let mut connection = h2::server::handshake(remote).await.unwrap();
                let requests = TaskTracker::new();
                let mut downloads = Vec::new();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    if request.method() == http::Method::GET {
                        let mut body = respond
                            .send_response(http::Response::new(()), false)
                            .unwrap();
                        body.send_data(bytes::Bytes::from_static(b"ready"), false)
                            .unwrap();
                        downloads.push(body);
                    } else {
                        let posts = posts.clone();
                        requests.spawn(async move {
                            let mut body = request.into_body();
                            let mut total = 0;
                            while let Some(Ok(data)) = body.data().await {
                                total += data.len();
                                body.flow_control().release_capacity(data.len()).unwrap();
                            }
                            assert_eq!(total, 6);
                            posts.fetch_add(1, Ordering::Relaxed);
                            respond
                                .send_response(http::Response::new(()), true)
                                .unwrap();
                        });
                    }
                }
                requests.close();
                requests.wait().await;
            });
            async { Ok(Box::new(io) as vole::dispatch::BoxStream) }
        };
        let mut options = config(serde_json::json!({"h-max-request-times":"1"}));
        options.mode = XHttpMode::PacketUp;
        let client = XHttpClient::new(options);
        let mut stream = client
            .open(
                tokio::time::Instant::now() + Duration::from_secs(2),
                factory,
            )
            .await
            .unwrap();
        ready(&mut stream).await;
        for _ in 0..3 {
            stream.write_all(b"packet").await.unwrap();
            stream.flush().await.unwrap();
        }
        assert_eq!(posts.load(Ordering::Relaxed), 3);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let mut second = client
            .open(
                tokio::time::Instant::now() + Duration::from_secs(1),
                factory,
            )
            .await
            .unwrap();
        ready(&mut second).await;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        stream.shutdown().await.unwrap();
        second.shutdown().await.unwrap();
        client.stop().await;
        tasks.close();
        tasks.wait().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn h2_keepalive_uses_default_explicit_and_disabled_idle_periods() {
    for (seconds, expected) in [(0, Some(45)), (2, Some(2)), (-1, None)] {
        let (io, mut remote) = tokio::io::duplex(16384);
        let (sent, received) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut preface = [0; 24];
            remote.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            remote
                .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut sent = Some(sent);
            loop {
                let mut head = [0; 9];
                if remote.read_exact(&mut head).await.is_err() {
                    break;
                }
                let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                assert!(length <= 16384);
                let mut payload = vec![0; length];
                remote.read_exact(&mut payload).await.unwrap();
                if head[3] == 4 && head[4] & 1 == 0 {
                    remote
                        .write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0])
                        .await
                        .unwrap();
                }
                if head[3] == 6 && head[4] & 1 == 0 {
                    assert_eq!(length, 8);
                    if let Some(sent) = sent.take() {
                        let _ = sent.send(tokio::time::Instant::now());
                    }
                    head[4] = 1;
                    remote.write_all(&head).await.unwrap();
                    remote.write_all(&payload).await.unwrap();
                }
            }
        });
        let client = XHttpClient::new(config(serde_json::json!({"h-keep-alive-period":seconds})));
        let start = tokio::time::Instant::now();
        let _stream = client.connect(Box::new(io)).await.unwrap();
        let observed = tokio::time::timeout(Duration::from_secs(51), received).await;
        if let Some(seconds) = expected {
            let elapsed = observed.expect("idle PING absent").unwrap() - start;
            assert_eq!(elapsed, Duration::from_secs(seconds));
        } else {
            assert!(observed.is_err(), "disabled keepalive sent a PING");
        }
        client.stop().await;
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn download_uses_its_own_reuse_counters_and_keeps_shared_sessions_alive() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let tasks = TaskTracker::new();
        let uploads = AtomicUsize::new(0);
        let downloads = AtomicUsize::new(0);
        let mut options = config(serde_json::json!({"h-max-request-times":"1"}));
        options.mode = XHttpMode::StreamUp;
        let client = XHttpClient::new(options);
        let download = XHttpClient::new(config(serde_json::json!({})));
        let mut streams = Vec::new();
        for _ in 0..3 {
            let mut stream = client
                .open_with_download(
                    tokio::time::Instant::now() + Duration::from_secs(1),
                    &download,
                    || peer(&uploads, &tasks),
                    || peer(&downloads, &tasks),
                )
                .await
                .unwrap();
            ready(&mut stream).await;
            streams.push(stream);
        }
        assert_eq!(uploads.load(Ordering::Relaxed), 3);
        assert_eq!(downloads.load(Ordering::Relaxed), 1);
        for mut stream in streams {
            stream.shutdown().await.unwrap();
        }
        client.stop().await;
        download.stop().await;
        tasks.close();
        tasks.wait().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h1_packet_upload_reuses_its_idle_connection_but_reopens_the_cancelled_get() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let tasks = TaskTracker::new();
        let calls = AtomicUsize::new(0);
        let factory = || {
            calls.fetch_add(1, Ordering::Relaxed);
            let (io, mut peer) = tokio::io::duplex(16384);
            tasks.spawn(async move {
                loop {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = peer.read_u8().await else {
                            return;
                        };
                        head.push(byte);
                        assert!(head.len() < 16384);
                    }
                    if head.starts_with(b"GET ") {
                        peer.write_all(
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nready\r\n",
                        )
                        .await
                        .unwrap();
                        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
                        return;
                    }
                    let mut bytes = Vec::new();
                    loop {
                        let mut line = Vec::new();
                        while !line.ends_with(b"\r\n") {
                            line.push(peer.read_u8().await.unwrap());
                        }
                        let count = usize::from_str_radix(
                            std::str::from_utf8(&line[..line.len() - 2]).unwrap(),
                            16,
                        )
                        .unwrap();
                        let mut chunk = vec![0; count + 2];
                        peer.read_exact(&mut chunk).await.unwrap();
                        assert_eq!(&chunk[count..], b"\r\n");
                        if count == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&chunk[..count]);
                    }
                    assert_eq!(&bytes, b"packet");
                    peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                }
            });
            async { Ok(Box::new(io) as vole::dispatch::BoxStream) }
        };
        let mut options = config(serde_json::json!({}));
        options.mode = XHttpMode::PacketUp;
        options.http_version = vole::config::XHttpVersion::Http1;
        let client = XHttpClient::new(options);
        for _ in 0..2 {
            let mut stream = client
                .open(
                    tokio::time::Instant::now() + Duration::from_secs(1),
                    factory,
                )
                .await
                .unwrap();
            ready(&mut stream).await;
            stream.write_all(b"packet").await.unwrap();
            stream.shutdown().await.unwrap();
        }
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        client.stop().await;
        tasks.close();
        tasks.wait().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stopping_during_handshake_prevents_late_driver_admission() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let client =
            XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap());
        let (io, mut remote) = tokio::io::duplex(1);
        let connecting = client.connect(Box::new(io));
        tokio::pin!(connecting);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut connecting)
                .await
                .is_err()
        );
        client.stop().await;
        let peer = tokio::spawn(async move {
            let mut preface = Vec::new();
            remote.read_to_end(&mut preface).await.unwrap();
            assert!(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".starts_with(&preface));
            remote
        });
        let result = connecting.await;
        assert!(
            result.is_err(),
            "stopped client admitted a new logical stream"
        );
        drop(peer.await.unwrap());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stop_wakes_a_handshake_even_when_the_peer_never_responds() {
    let client =
        XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap());
    let (io, _remote) = tokio::io::duplex(1);
    let connecting = client.connect(Box::new(io));
    tokio::pin!(connecting);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut connecting)
            .await
            .is_err()
    );
    client.stop().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), connecting)
            .await
            .expect("Stop left the handshake pending")
            .is_err()
    );
}
