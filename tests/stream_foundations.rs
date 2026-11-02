#![cfg(feature = "stream-transport")]

#[test]
fn transport_options_reject_ambiguous_headers_before_io() {
    use vole::transport::{HttpObfsOptions, WebSocketEarlyData, WebSocketOptions};
    for name in ["host", "x-custom"] {
        let mut headers = http::HeaderMap::new();
        headers.append(name, "example.com".parse().unwrap());
        headers.append(name, "other.example".parse().unwrap());
        assert!(WebSocketOptions::new("ws://example.com/", headers.clone(), None).is_err());
        assert!(HttpObfsOptions::new(http::Method::GET, "http://example.com/", headers).is_err());
    }
    for maximum in [0] {
        assert!(
            WebSocketOptions::new(
                "ws://example.com/",
                Default::default(),
                Some(WebSocketEarlyData::Path { max_bytes: maximum })
            )
            .is_err()
        );
    }
    for uri in [
        "ws://user:password@example.com/",
        "http://example.com/",
        "ws://example.com/path?query=1",
    ] {
        assert!(
            WebSocketOptions::new(
                uri,
                Default::default(),
                Some(WebSocketEarlyData::Path { max_bytes: 1 })
            )
            .is_err()
        );
    }
    for name in ["content-length", "transfer-encoding"] {
        let mut headers = http::HeaderMap::new();
        headers.insert(name, "1".parse().unwrap());
        assert!(WebSocketOptions::new("ws://example.com/", headers.clone(), None).is_err());
        assert!(HttpObfsOptions::new(http::Method::GET, "http://example.com/", headers).is_err());
    }
}

#[tokio::test]
async fn http_first_header_preserves_prefix_raw_continuation_and_half_close_tail() {
    timeout(Duration::from_secs(3), async {
        let (client, mut peer) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(peer.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("POST /cover?q=1 HTTP/1.1\r\n"));
            assert!(request.contains("host: cover.example:8080\r\n"));
            assert!(request.contains("content-length: 6\r\n"));
            assert!(request.contains("x-custom: value\r\n"));
            let mut prefix = [0; 6];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"prefix");
            peer.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nhello",
            )
            .await
            .unwrap();
            let mut data = Vec::new();
            peer.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, vec![42; 65536]);
            peer.write_all(b"tail").await.unwrap();
        });
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", "value".parse().unwrap());
        let options = vole::transport::HttpObfsOptions::new(
            http::Method::POST,
            "http://cover.example:8080/cover?q=1",
            headers,
        )
        .unwrap();
        let mut stream = vole::transport::http_obfs(
            Box::new(client),
            &options,
            b"prefix",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        let mut hello = [0; 5];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        stream.write_all(&vec![42; 65536]).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn legacy_h2_keeps_unframed_bytes_server_first_and_owned_whole_close() {
    timeout(Duration::from_secs(3), async {
        let (client, peer) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(128)
                .handshake::<_, bytes::Bytes>(peer)
                .await
                .unwrap();
            let (request, mut reply) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), "PUT");
            assert_eq!(request.uri().authority().unwrap().as_str(), "cover.example");
            assert_eq!(request.uri().path(), "/h2");
            assert_eq!(request.headers()["accept-encoding"], "identity");
            let mut receive = request.into_body();
            let mut send = reply.send_response(http::Response::new(()), false).unwrap();
            send.send_data(bytes::Bytes::from_static(b"hello"), false)
                .unwrap();
            let work = tokio::spawn(async move {
                let mut input = Vec::new();
                while input.len() < 65536 {
                    let data = receive.data().await.unwrap().unwrap();
                    receive.flow_control().release_capacity(data.len()).unwrap();
                    input.extend_from_slice(&data);
                }
                assert_eq!(input, vec![42; 65536]);
                send.send_data(bytes::Bytes::from_static(b"done"), false)
                    .unwrap();
                assert!(receive.data().await.unwrap().is_err());
            });
            while connection.accept().await.is_some() {}
            work.await.unwrap();
        });
        let (mut stream, owner) = vole::transport::legacy_h2(
            Box::new(client),
            "https://cover.example/h2",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        let mut hello = [0; 5];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        stream.write_all(&vec![42; 65536]).await.unwrap();
        stream.flush().await.unwrap();
        let mut done = [0; 4];
        stream.read_exact(&mut done).await.unwrap();
        assert_eq!(&done, b"done");
        stream.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(
            stream.write(b"x").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        owner.stop().await.unwrap();
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn websocket_rejects_invalid_upgrade_responses_and_bounded_header_overflows() {
    for change in [
        "version",
        "accept",
        "duplicate",
        "extension",
        "subprotocol",
        "size",
        "count",
        "truncated",
    ] {
        let (client, mut peer) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(peer.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            let key = request
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
                })
                .unwrap()
                .1
                .trim();
            let accept =
                tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
            let version = if change == "version" {
                "HTTP/1.0"
            } else {
                "HTTP/1.1"
            };
            let accept = if change == "accept" {
                "invalid"
            } else {
                &accept
            };
            let mut response = format!(
                "{version} 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
            );
            match change {
                "duplicate" => response.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n")),
                "extension" => {
                    response.push_str("Sec-WebSocket-Extensions: permessage-deflate\r\n")
                }
                "subprotocol" => response.push_str("Sec-WebSocket-Protocol: unsolicited\r\n"),
                "size" => response.push_str(&format!("X-Padding: {}\r\n", "x".repeat(16384))),
                "count" => response.push_str(&"X-Many: x\r\n".repeat(101)),
                _ => {}
            }
            if change != "truncated" {
                response.push_str("\r\n");
            }
            let _ = peer.write_all(response.as_bytes()).await;
        });
        let result = websocket(
            Box::new(client),
            "ws://example.com/",
            Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err(), "accepted invalid {change}");
        peer.await.unwrap();
    }
}
#[tokio::test]
// The official handshake callback fixes its error type to Response<Option<String>>.
#[allow(clippy::result_large_err)]
async fn websocket_early_data_and_remaining_frames_keep_the_original_byte_order() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use vole::transport::{WebSocketEarlyData, WebSocketOptions, connect_websocket};
    for maximum in [1, 2048, 4096] {
        timeout(Duration::from_secs(3), async {
            let (client, peer) = tokio::io::duplex(128);
            let input: Vec<u8> = (0..6000).map(|value| (value % 251) as u8).collect();
            let expected = input.clone();
            let peer = tokio::spawn(async move {
                let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
                let header_bytes = observed.clone();
                let mut ws = tokio_tungstenite::accept_hdr_async(
                    peer,
                    move |request: &http::Request<()>, response: http::Response<()>| {
                        assert_eq!(
                            request.uri().path_and_query().unwrap().as_str(),
                            "/hello?mode=1"
                        );
                        assert_eq!(request.headers()["host"], "cover.example:8443");
                        *header_bytes.lock().unwrap() = URL_SAFE_NO_PAD
                            .decode(request.headers()["sec-websocket-protocol"].as_bytes())
                            .unwrap();
                        Ok(response) // Mihomo's ED is not an echoed WS subprotocol.
                    },
                )
                .await
                .unwrap();
                let mut received = observed.lock().unwrap().clone();
                assert_eq!(received.len(), maximum);
                while received.len() < 6000 {
                    if let Message::Binary(data) = ws.next().await.unwrap().unwrap() {
                        received.extend_from_slice(&data);
                    }
                }
                assert_eq!(received, expected);
                ws.send(Message::Binary("ok".into())).await.unwrap();
            });
            let mut headers = http::HeaderMap::new();
            headers.insert("host", "cover.example:8443".parse().unwrap());
            let options = WebSocketOptions::new(
                "ws://example.com/hello?mode=1",
                headers,
                Some(WebSocketEarlyData::Header {
                    name: http::HeaderName::from_static("sec-websocket-protocol"),
                    max_bytes: maximum,
                }),
            )
            .unwrap();
            let mut stream = connect_websocket(
                Box::new(client),
                &options,
                &input,
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
            assert_eq!(stream.read_u16().await.unwrap(), 0x6f6b);
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }
}
async fn stalled_handshake(kind: &str, raw: Observed, deadline: Instant) -> io::Result<()> {
    match kind {
        "ws" => {
            websocket(Box::new(raw), "ws://fixture.invalid/stream", deadline).await?;
        }
        "grpc" => {
            let (mut stream, owner) = grpc(
                Box::new(raw),
                "https://fixture.invalid/stream/Tun",
                deadline,
            )
            .await?;
            let result = stream.read_u8().await;
            drop(stream);
            owner.stop().await?;
            result?;
        }
        "h2" => {
            let (mut stream, owner) =
                vole::transport::legacy_h2(Box::new(raw), "https://fixture.invalid/h2", deadline)
                    .await?;
            let result = stream.read_u8().await;
            drop(stream);
            owner.stop().await?;
            result?;
        }
        "http" => {
            let options = vole::transport::HttpObfsOptions::new(
                http::Method::GET,
                "http://fixture.invalid/",
                Default::default(),
            )?;
            // This fixture tests incomplete request submission, not a valid
            // one-way upload whose first HTTP response legitimately arrives late.
            let mut stream =
                vole::transport::http_obfs(Box::new(raw), &options, &[0; 4096], deadline).await?;
            stream.read_u8().await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[tokio::test]
async fn setup_deadline_releases_supplied_io_in_stream_adapters() {
    for kind in ["ws", "grpc", "h2", "http"] {
        let (outgoing, mut incoming) = tokio::io::duplex(128);
        let dropped = Arc::new(AtomicBool::new(false));
        let raw = Observed {
            io: outgoing,
            shutdown: Arc::new(AtomicBool::new(false)),
            dropped: dropped.clone(),
        };
        let (release, released) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            if kind == "http" {
                // Hold the bounded pipe full until setup expires, then drain
                // naturally to EOF so deadline ownership remains observable.
                released.await.unwrap();
            }
            let mut sink = Vec::new();
            incoming.read_to_end(&mut sink).await.unwrap();
            assert!(sink.len() < 4096);
        });
        let result = timeout(
            Duration::from_secs(2),
            stalled_handshake(kind, raw, Instant::now() + Duration::from_millis(30)),
        )
        .await
        .unwrap();
        let _ = release.send(());
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::TimedOut,
            "{kind}"
        );
        timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst), "{kind}");
    }
}

#[tokio::test(start_paused = true)]
async fn http2_lazy_response_obeys_setup_deadline_but_established_reads_do_not() {
    for kind in ["grpc", "duplex", "h2", "pooled"] {
        for timing in ["late-first-poll", "late-after-pending", "established"] {
            let (client, peer) = tokio::io::duplex(65536);
            let (release, released) = tokio::sync::oneshot::channel();
            let (ready, observed) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(peer).await.unwrap();
                let (_request, mut reply) = connection.accept().await.unwrap().unwrap();
                released.await.unwrap();
                let mut send = reply
                    .send_response(
                        http::Response::builder()
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                send.send_data(
                    bytes::Bytes::from_static(if kind == "h2" {
                        b"ab"
                    } else {
                        b"\x00\x00\x00\x00\x04\x0a\x02ab"
                    }),
                    false,
                )
                .unwrap();
                // Flush HEADERS/DATA before queuing PING. Its ACK proves that
                // the client driver parsed the response, without polling the
                // lazy application reader or depending on a scheduling sleep.
                futures_util::future::poll_fn(|cx| {
                    assert!(connection.poll_closed(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let mut ping = connection.ping_pong().unwrap();
                let barrier = async move {
                    ping.ping(h2::Ping::opaque()).await.unwrap();
                    ready.send(()).unwrap();
                    std::future::pending::<()>().await;
                };
                tokio::select! {
                    () = barrier => unreachable!(),
                    _ = futures_util::future::poll_fn(|cx| connection.poll_closed(cx)) => {},
                }
                drop(send);
            });
            let deadline = Instant::now() + Duration::from_secs(1);
            let uri = "https://fixture.invalid/stream/Tun";
            let pool = vole::transport::GrpcPool::new(Default::default());
            let (mut stream, owner) = if kind == "pooled" {
                (
                    pool.open(uri, deadline, || async { Ok(Box::new(client) as _) })
                        .await
                        .unwrap(),
                    None,
                )
            } else {
                let pair = match kind {
                    "grpc" => grpc(Box::new(client), uri, deadline).await,
                    "duplex" => vole::transport::grpc_duplex(Box::new(client), uri, deadline).await,
                    "h2" => vole::transport::legacy_h2(Box::new(client), uri, deadline).await,
                    _ => unreachable!(),
                }
                .unwrap();
                (pair.0, Some(pair.1))
            };
            if timing == "late-after-pending" {
                assert!(futures_util::poll!(std::pin::pin!(stream.read_u8())).is_pending());
                tokio::time::advance(Duration::from_secs(2)).await;
            }
            release.send(()).unwrap();
            timeout(Duration::from_secs(1), observed)
                .await
                .unwrap()
                .unwrap();
            if timing == "established" {
                assert_eq!(stream.read_u8().await.unwrap(), b'a');
            }
            if timing != "late-after-pending" {
                tokio::time::advance(Duration::from_secs(2)).await;
            }
            let result = stream.read_u8().await;
            drop(stream);
            if let Some(owner) = owner {
                owner.stop().await.unwrap();
            }
            pool.shutdown().await;
            timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap();
            if timing == "established" {
                assert_eq!(result.unwrap(), b'b', "{kind}");
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    io::ErrorKind::TimedOut,
                    "{kind}: {timing}"
                );
            }
        }
    }
}

#[tokio::test]
async fn cancelled_setup_releases_supplied_io_without_a_detached_task() {
    for kind in ["ws", "grpc", "h2", "http"] {
        let (outgoing, mut incoming) = tokio::io::duplex(128);
        let dropped = Arc::new(AtomicBool::new(false));
        let raw = Observed {
            io: outgoing,
            shutdown: Arc::new(AtomicBool::new(false)),
            dropped: dropped.clone(),
        };
        let peer = tokio::spawn(async move {
            let mut sink = Vec::new();
            incoming.read_to_end(&mut sink).await.unwrap();
        });
        assert!(
            timeout(
                Duration::from_millis(20),
                stalled_handshake(kind, raw, Instant::now() + Duration::from_secs(10))
            )
            .await
            .is_err()
        );
        timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst), "{kind}");
    }
}

#[tokio::test]
async fn ws_rejects_oversized_and_truncated_frames_instead_of_reporting_eof() {
    for frame in [
        vec![0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 1],
        vec![0x82, 3, b'x'],
        vec![0x02, 1, b'x'],
        vec![0x82],
    ] {
        let (outgoing, incoming) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
            ws.get_mut().write_all(&frame).await.unwrap();
            ws.get_mut().shutdown().await.unwrap();
        });
        let mut stream = websocket(
            Box::new(outgoing),
            "ws://fixture.invalid/stream",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), stream.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(stream);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn ws_accepts_mihomo_clean_underlay_eof_only_at_complete_message_boundaries() {
    for frame in [
        b"\x82\x04tail".as_slice(),
        b"\x02\x02ta\x80\x02il".as_slice(),
    ] {
        let (outgoing, incoming) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
            ws.get_mut().write_all(frame).await.unwrap();
            ws.get_mut().shutdown().await.unwrap();
        });
        let mut stream = websocket(
            Box::new(outgoing),
            "ws://fixture.invalid/stream",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        let mut tail = Vec::new();
        timeout(Duration::from_secs(1), stream.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, b"tail");
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn dropping_an_established_ws_releases_its_only_io_owner() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let dropped = Arc::new(AtomicBool::new(false));
    let raw = Observed {
        io: outgoing,
        shutdown: Arc::new(AtomicBool::new(false)),
        dropped: dropped.clone(),
    };
    let peer = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
        assert_eq!(ws.get_mut().read(&mut [0; 1]).await.unwrap(), 0);
    });
    let mut stream = websocket(
        Box::new(raw),
        "ws://fixture.invalid/stream",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_millis(20), stream.read_u8())
            .await
            .is_err()
    );
    drop(stream);
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn grpc_rejects_oversized_truncated_and_invalid_records() {
    for (wire, prefix) in [
        (b"\x00\x00\x10\x00\x00".to_vec(), &b""[..]),
        (b"\x00\x00\x00\x00\x06\x0a\x04x".to_vec(), &b"x"[..]),
        (b"\x01\x00\x00\x00\x02\x0a\x00".to_vec(), &b""[..]),
        (b"\x00\x00\x00\x00\x02\x0b\x00".to_vec(), &b""[..]),
    ] {
        let (outgoing, incoming) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(incoming).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(wire.into(), true).unwrap();
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let (mut stream, owner) = grpc(
            Box::new(outgoing),
            "https://fixture.invalid/stream/Tun",
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        let mut received = Vec::new();
        assert_eq!(
            timeout(Duration::from_secs(1), stream.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(received, prefix);
        drop(stream);
        owner.stop().await.unwrap();
        timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn grpc_large_writes_obey_small_http2_windows_and_keep_byte_integrity() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let expected: Vec<_> = (0..65536).map(|n| (n % 251) as u8).collect();
    let peer = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(128)
            .max_send_buffer_size(128)
            .handshake(incoming)
            .await
            .unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let exchange = async move {
            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let mut receive = request.into_body();
            while let Some(data) = receive.data().await {
                let mut data = data.unwrap();
                let consumed = data.len();
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                    let count = capacity.min(data.len());
                    if count > 0 {
                        send.send_data(data.split_to(count), false).unwrap();
                    }
                }
                receive.flow_control().release_capacity(consumed).unwrap();
            }
        };
        tokio::pin!(exchange);
        loop {
            tokio::select! {
                _ = &mut exchange => break,
                result = connection.accept() => if result.is_none() || result.is_some_and(|r| r.is_err()) { break; },
            }
        }
    });
    let (stream, owner) = grpc(
        Box::new(outgoing),
        "https://fixture.invalid/stream/Tun",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let upload = async {
        write.write_all(&expected).await.unwrap();
        write.flush().await.unwrap();
    };
    let download = async {
        let mut received = vec![0; expected.len()];
        read.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(upload, download);
    })
    .await
    .unwrap();
    drop(read);
    drop(write);
    owner.stop().await.unwrap();
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ws_partial_writes_empty_frames_ping_and_half_close_preserve_every_byte() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let expected: Vec<_> = (0..65536).map(|n| (n % 251) as u8).collect();
    let request = expected.clone();
    let peer = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_async(incoming).await.unwrap();
        ws.send(Message::Binary(bytes::Bytes::new())).await.unwrap();
        ws.send(Message::Ping(b"ping".as_slice().into()))
            .await
            .unwrap();
        ws.send(Message::Text("ready".into())).await.unwrap();
        let mut received = Vec::new();
        while received.len() < request.len() {
            match ws.next().await.unwrap().unwrap() {
                Message::Binary(data) => received.extend_from_slice(&data),
                Message::Pong(_) => {}
                message => panic!("unexpected fixture message type: {}", message.is_close()),
            }
        }
        assert_eq!(received, request);
        let mut byte = [0];
        // Read raw EOF, not a WS Close frame. The public server library marks
        // itself terminated on that EOF, so leave its WS state intact to reply.
        assert_eq!(ws.get_mut().read(&mut byte).await.unwrap(), 0);
        ws.send(Message::Binary(received.into())).await.unwrap();
        ws.send(Message::Close(None)).await.unwrap();
    });
    let mut stream = websocket(
        Box::new(outgoing),
        "ws://fixture.invalid/stream",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    let mut greeting = [0; 5];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"ready");
    stream.write_all(&expected).await.unwrap();
    stream.shutdown().await.unwrap();
    assert!(stream.write_all(b"forbidden").await.is_err());
    let mut reply = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, expected);
    drop(stream);
    peer.await.unwrap();
}
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    time::{Instant, timeout},
};
use vole::transport::{grpc, websocket};

struct Observed {
    io: DuplexStream,
    shutdown: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Observed {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for Observed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Observed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown.store(true, Ordering::SeqCst);
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn grpc_handles_response_after_upload_fragmented_records_and_owned_stop() {
    let (outgoing, incoming) = tokio::io::duplex(128);
    let dropped = Arc::new(AtomicBool::new(false));
    let raw = Observed {
        io: outgoing,
        shutdown: Arc::new(AtomicBool::new(false)),
        dropped: dropped.clone(),
    };
    let peer = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(128)
            .handshake(incoming)
            .await
            .unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), "/stream/Tun");
        let session = async move {
            let mut body = request.into_body();
            let mut wire = Vec::new();
            // Sending response headers only after request bytes is deliberate:
            // eagerly awaiting the response in the connector would deadlock.
            while wire.len() < 11 {
                let data = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                wire.extend_from_slice(&data);
            }
            assert_eq!(&wire, b"\x00\x00\x00\x00\x06\x0a\x04ping");
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut tx = respond.send_response(response, false).unwrap();
            for byte in b"\x00\x00\x00\x00\x06\x0a\x04pong" {
                tx.send_data(bytes::Bytes::copy_from_slice(&[*byte]), false)
                    .unwrap();
            }
            // Keep the response open: local shutdown must wake a pending read.
            std::future::pending::<()>().await;
        };
        tokio::pin!(session);
        loop {
            tokio::select! {
                _ = &mut session => break,
                result = connection.accept() => if result.is_none() || result.is_some_and(|r| r.is_err()) { break; },
            }
        }
    });
    let (mut stream, owner) = grpc(
        Box::new(raw),
        "https://fixture.invalid/stream/Tun",
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 4];
    timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"pong");
    let (mut read, mut write) = tokio::io::split(stream);
    let waiting = tokio::spawn(async move { read.read_u8().await });
    tokio::task::yield_now().await;
    write.shutdown().await.unwrap();
    assert!(
        timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    owner.stop().await.unwrap();
    assert!(
        dropped.load(Ordering::SeqCst),
        "Stop must join the task which owns IO"
    );
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn websocket_supplied_io_preserves_server_first_and_partial_writes() {
    let (client, peer) = tokio::io::duplex(128);
    let task = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_async(peer).await.unwrap();
        ws.send(Message::Binary("hello".into())).await.unwrap();
        let mut received = Vec::new();
        while received.len() < 65_536 {
            if let Message::Binary(data) = ws.next().await.unwrap().unwrap() {
                received.extend_from_slice(&data);
            }
        }
        assert_eq!(received, vec![42; 65_536]);
        ws.send(Message::Binary("done".into())).await.unwrap();
    });
    let mut ws = vole::transport::websocket(
        Box::new(client),
        "ws://example.com/tunnel",
        tokio::time::Instant::now() + Duration::from_secs(3),
    )
    .await
    .unwrap();
    let mut hello = [0; 5];
    ws.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    ws.write_all(&vec![42; 65_536]).await.unwrap();
    ws.flush().await.unwrap();
    let mut done = [0; 4];
    ws.read_exact(&mut done).await.unwrap();
    assert_eq!(&done, b"done");
    drop(ws);
    task.await.unwrap();
}
