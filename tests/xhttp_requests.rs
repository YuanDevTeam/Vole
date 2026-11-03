#![cfg(feature = "outbound-vless")]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol},
    transport::xhttp::{XHttpClient, XHttpConfig, XHttpMode},
};

#[tokio::test(start_paused = true)]
async fn packet_up_coalesces_small_writes_and_flushes_without_more_caller_io() {
    use std::{pin::Pin, task::Poll};
    use tokio::io::AsyncWrite;
    let client =
        XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap());
    let (io, remote) = tokio::io::duplex(16384);
    let (posted, mut received) = tokio::sync::mpsc::channel(2);
    let peer = tokio::spawn(async move {
        let mut connection = h2::server::handshake(remote).await.unwrap();
        let tasks = tokio_util::task::TaskTracker::new();
        let mut downloads = Vec::new();
        while let Some(Ok((request, mut reply))) = connection.accept().await {
            if request.method() == http::Method::GET {
                downloads.push(reply.send_response(http::Response::new(()), false).unwrap());
            } else {
                let posted = posted.clone();
                tasks.spawn(async move {
                    let mut input = request.into_body();
                    let mut payload = Vec::new();
                    while let Some(data) = input.data().await {
                        let data = data.unwrap();
                        input.flow_control().release_capacity(data.len()).unwrap();
                        payload.extend_from_slice(&data);
                    }
                    reply.send_response(http::Response::new(()), true).unwrap();
                    posted.send(payload).await.unwrap();
                });
            }
        }
        tasks.close();
        tasks.wait().await;
    });
    let mut stream = client.connect(Box::new(io)).await.unwrap();
    let started = tokio::time::Instant::now();
    for fragment in [b"abc", b"def", b"ghi", b"jkl"] {
        futures_util::future::poll_fn(|cx| {
            assert!(
                matches!(
                    Pin::new(&mut stream).poll_write(cx, fragment),
                    Poll::Ready(Ok(3))
                ),
                "a small write waited for its own POST instead of joining the batch"
            );
            Poll::Ready(())
        })
        .await;
    }
    // No further poll on the stream: its owned timer must flush the batch.
    let payload = tokio::time::timeout(Duration::from_secs(1), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(payload, b"abcdefghijkl");
    assert!(started.elapsed() >= Duration::from_millis(30));
    stream.flush().await.unwrap();
    stream.write_all(b"tail").await.unwrap();
    let closing = tokio::time::Instant::now();
    stream.shutdown().await.unwrap();
    assert_eq!(received.recv().await.unwrap(), b"tail");
    assert!(
        closing.elapsed() < Duration::from_millis(30),
        "close must flush without waiting for the normal batching timer"
    );
    drop(stream);
    client.stop().await;
    peer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn packet_up_backpressures_bounded_batches_and_stop_cancels_the_timer() {
    use std::{pin::Pin, task::Poll};
    use tokio::io::AsyncWrite;
    let client =
        XHttpClient::new(XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap());
    let (io, remote) = tokio::io::duplex(16384);
    let peer = tokio::spawn(async move {
        if let Ok(mut connection) = h2::server::handshake(remote).await {
            while connection.accept().await.is_some() {}
        }
    });
    let mut stream = client.connect(Box::new(io)).await.unwrap();
    let accepted = futures_util::future::poll_fn(|cx| {
        let mut accepted = 0;
        // Do not advance the timer or poll the HTTP peer. A full batch must
        // backpressure before accepting unbounded caller data.
        loop {
            match Pin::new(&mut stream).poll_write(cx, &[0x5a; 4096]) {
                Poll::Ready(Ok(n)) => {
                    assert!(n > 0 && n <= 4096);
                    accepted += n;
                    assert!(accepted <= 65536);
                }
                Poll::Pending => break,
                Poll::Ready(Err(error)) => panic!("{error}"),
            }
        }
        assert!(Pin::new(&mut stream).poll_flush(cx).is_pending());
        Poll::Ready(accepted)
    })
    .await;
    assert_eq!(accepted, 65536);
    tokio::time::timeout(Duration::from_secs(1), client.stop())
        .await
        .unwrap();
    assert!(stream.write_all(b"late").await.is_err());
    assert!(stream.flush().await.is_err());
    assert!(stream.read_u8().await.is_err());
    drop(stream);
    peer.await.unwrap();
}

#[tokio::test]
async fn first_vless_read_never_acknowledges_or_replays_a_concurrent_packet_write() {
    use std::{pin::Pin, task::Poll};
    use tokio::io::AsyncWrite;
    tokio::time::timeout(Duration::from_secs(3), async {
        for explicit_flush in [false, true] {
            let client = XHttpClient::new(
                XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap(),
            );
            let (io, remote) = tokio::io::duplex(16384);
            let peer = tokio::spawn(async move {
                let mut connection = h2::server::handshake(remote).await.unwrap();
                let mut downloads = Vec::new();
                let tasks = tokio_util::task::TaskTracker::new();
                let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                while let Some(Ok((request, mut reply))) = connection.accept().await {
                    if request.method() == http::Method::GET {
                        let mut send = reply.send_response(http::Response::new(()), false).unwrap();
                        send.send_data(bytes::Bytes::from_static(b"\0\0r"), false)
                            .unwrap();
                        downloads.push(send);
                    } else {
                        let received = received.clone();
                        tasks.spawn(async move {
                            let mut input = request.into_body();
                            let mut payload = Vec::new();
                            while let Some(Ok(data)) = input.data().await {
                                input.flow_control().release_capacity(data.len()).unwrap();
                                payload.extend_from_slice(&data);
                            }
                            received.lock().unwrap().extend(payload);
                            reply.send_response(http::Response::new(()), true).unwrap();
                        });
                    }
                }
                tasks.close();
                tasks.wait().await;
                received.lock().unwrap().clone()
            });
            let raw = client.connect(Box::new(io)).await.unwrap();
            let mut stream =
                vole::outbound::VlessStream::new(raw, bytes::Bytes::from_static(b"header"));
            stream.write_all(b"preface").await.unwrap();
            if explicit_flush {
                stream.flush().await.unwrap();
            }
            // Interleave the first read with a write. Buffered acceptance is
            // allowed, but neither accepted nor pending bytes may be replayed.
            let accepted = futures_util::future::poll_fn(|cx| {
                Poll::Ready(match Pin::new(&mut stream).poll_write(cx, b"packet") {
                    Poll::Ready(result) => result.unwrap(),
                    Poll::Pending => 0,
                })
            })
            .await;
            assert_eq!(stream.read_u8().await.unwrap(), b'r');
            stream.write_all(&b"packet"[accepted..]).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            drop(stream);
            client.stop().await;
            assert_eq!(
                peer.await.unwrap(),
                b"headerprefacepacket",
                "explicit_flush={explicit_flush}"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn response_codes_follow_mihomo_streaming_and_packet_rules() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for (mode, get_status, post_status, read_ok, write_ok) in [
            (XHttpMode::StreamOne, 200, 201, true, true),
            (XHttpMode::StreamUp, 200, 201, true, true),
            (XHttpMode::StreamUp, 201, 200, false, true),
            (XHttpMode::PacketUp, 201, 200, false, true),
            (XHttpMode::PacketUp, 200, 201, true, false),
        ] {
            let client = XHttpClient::new(XHttpConfig::new("example.com", "/x", mode).unwrap());
            let (io, remote) = tokio::io::duplex(16384);
            let peer = tokio::spawn(async move {
                let mut connection = h2::server::handshake(remote).await.unwrap();
                let mut bodies = Vec::new();
                let mut replies = Vec::new();
                while let Some(Ok((request, mut reply))) = connection.accept().await {
                    let status = if request.method() == http::Method::GET {
                        get_status
                    } else {
                        post_status
                    };
                    let response = http::Response::builder().status(status).body(()).unwrap();
                    let mut send = reply.send_response(response, false).unwrap();
                    send.send_data(
                        bytes::Bytes::from_static(b"ready"),
                        mode == XHttpMode::PacketUp && request.method() != http::Method::GET,
                    )
                    .unwrap();
                    bodies.push(request.into_body());
                    replies.push(send);
                }
            });
            let mut stream = client.connect(Box::new(io)).await.unwrap();
            let result = stream.read_exact(&mut [0; 5]).await;
            assert_eq!(
                result.is_ok(),
                read_ok,
                "{mode:?} GET={get_status} POST={post_status}"
            );
            if read_ok {
                let written = async {
                    stream.write_all(b"payload").await?;
                    stream.flush().await
                }
                .await;
                assert_eq!(written.is_ok(), write_ok, "{mode:?} POST={post_status}");
            }
            let _ = stream.shutdown().await;
            client.stop().await;
            peer.await.unwrap();
        }
    })
    .await
    .unwrap();
}

async fn observe_stream_request(options: serde_json::Value) -> http::Request<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let document = serde_json::json!({"mixed-port":1080,"proxies":[{
            "name":"edge","type":"vless","server":"example.com","port":443,
            "uuid":"07070707-0707-0707-0707-070707070707","network":"xhttp","tls":true,
            "xhttp-opts":options
        }],"rules":["MATCH,edge"]});
        let parsed = Config::parse_yaml(&serde_json::to_vec(&document).unwrap()).unwrap();
        let ProxyProtocol::Vless(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        let mut config =
            XHttpConfig::new("example.com", "/x?original=yes", XHttpMode::StreamOne).unwrap();
        config.headers = node.xhttp().unwrap().headers.clone();
        config.request = node.xhttp().unwrap().request.clone();
        let client = XHttpClient::new(config);
        let (io, remote) = tokio::io::duplex(16384);
        let (observed, observation) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(remote).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            observed.send(request.map(|_| ())).unwrap();
            let mut sender = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            sender
                .send_data(bytes::Bytes::from_static(b"ready"), false)
                .unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut stream = client.connect(Box::new(io)).await.unwrap();
        let mut ready = [0; 5];
        stream.read_exact(&mut ready).await.unwrap();
        let observed = observation.await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        peer.await.unwrap();
        observed
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn streaming_content_type_can_be_disabled_without_disabling_padding() {
    let request =
        observe_stream_request(serde_json::json!({"mode":"stream-one","no-grpc-header":true}))
            .await;
    assert!(!request.headers().contains_key("content-type"));
    assert!(
        request.headers()["referer"]
            .to_str()
            .unwrap()
            .contains("x_padding=")
    );
}

#[tokio::test]
async fn custom_semantic_headers_are_allowed_when_no_generated_field_overwrites_them() {
    let request = observe_stream_request(serde_json::json!({
        "mode":"stream-one", "no-grpc-header":true,
        "headers":{"Content-Type":"application/octet-stream","Referer":"https://example.com/custom"},
        "x-padding-obfs-mode":true,"x-padding-placement":"query","x-padding-key":"pad"
    })).await;
    assert_eq!(
        request.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(request.headers()["referer"], "https://example.com/custom");
}

#[tokio::test]
async fn padding_uses_the_configured_http_location_and_encoding() {
    for placement in ["queryInHeader", "header", "query", "cookie"] {
        for method in ["repeat-x", "tokenish"] {
            let mut options = serde_json::json!({"mode":"stream-one", "x-padding-obfs-mode":true,
                "x-padding-placement":placement, "x-padding-method":method, "x-padding-bytes":"100"});
            if placement != "header" {
                options["x-padding-key"] = "pad".into();
            }
            if matches!(placement, "header" | "queryInHeader") {
                options["x-padding-header"] = "X-Pad".into();
            }
            let request = observe_stream_request(options).await;
            assert!(!request.headers().contains_key("referer"));
            let padding = match placement {
                "header" => request.headers()["x-pad"].to_str().unwrap().to_string(),
                "queryInHeader" => url::Url::parse(request.headers()["x-pad"].to_str().unwrap())
                    .unwrap()
                    .query_pairs()
                    .find(|(name, _)| name == "pad")
                    .unwrap()
                    .1
                    .into_owned(),
                "query" => url::Url::parse(&request.uri().to_string())
                    .unwrap()
                    .query_pairs()
                    .find(|(name, _)| name == "pad")
                    .unwrap()
                    .1
                    .into_owned(),
                "cookie" => request.headers()["cookie"]
                    .to_str()
                    .unwrap()
                    .strip_prefix("pad=")
                    .unwrap()
                    .into(),
                _ => unreachable!(),
            };
            assert!(request.uri().query().unwrap().contains("original=yes"));
            if method == "repeat-x" {
                assert_eq!(padding, "X".repeat(100));
            } else {
                assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
                assert!((100..=160).contains(&padding.len()));
                assert_ne!(padding, "X".repeat(100));
            }
        }
    }
}

async fn observe_packet(
    options: serde_json::Value,
    payload: &[u8],
) -> Vec<(http::Request<()>, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let doc = serde_json::json!({"mixed-port":1080,"proxies":[{
            "name":"edge","type":"vless","server":"example.com","port":443,
            "uuid":"07070707-0707-0707-0707-070707070707","network":"xhttp","tls":true,
            "xhttp-opts":options}],"rules":["MATCH,edge"]});
        let config = Config::parse_yaml(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            unreachable!()
        };
        let mut config =
            XHttpConfig::new("example.com", "/x?original=yes", XHttpMode::PacketUp).unwrap();
        config.headers = node.xhttp().unwrap().headers.clone();
        config.request = node.xhttp().unwrap().request.clone();
        let client = XHttpClient::new(config);
        let (io, remote) = tokio::io::duplex(16384);
        let (sent, mut observations) = tokio::sync::mpsc::channel(8);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(remote).await.unwrap();
            let tasks = tokio_util::task::TaskTracker::new();
            let mut downloads = Vec::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                let sent = sent.clone();
                if request.method() == http::Method::GET {
                    sent.send((request.map(|_| ()), Vec::new())).await.unwrap();
                    let mut send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    send.send_data(bytes::Bytes::from_static(b"ready"), false)
                        .unwrap();
                    downloads.push(send);
                } else {
                    tasks.spawn(async move {
                        let (parts, mut body) = request.into_parts();
                        let mut bytes = Vec::new();
                        while let Some(Ok(data)) = body.data().await {
                            bytes.extend_from_slice(&data);
                            body.flow_control().release_capacity(data.len()).unwrap();
                        }
                        sent.send((http::Request::from_parts(parts, ()), bytes))
                            .await
                            .unwrap();
                        respond
                            .send_response(http::Response::new(()), true)
                            .unwrap();
                    });
                }
            }
            tasks.close();
            tasks.wait().await;
        });
        let mut stream = client.connect(Box::new(io)).await.unwrap();
        let mut ready = [0; 5];
        stream.read_exact(&mut ready).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        peer.await.unwrap();
        let mut result = Vec::new();
        while let Some(observed) = observations.recv().await {
            result.push(observed);
        }
        result
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn packet_metadata_and_upload_methods_are_sent_in_each_supported_location() {
    for (placement, method) in [
        ("path", "POST"),
        ("query", "PUT"),
        ("header", "PATCH"),
        ("cookie", "DELETE"),
        ("path", "PROPFIND"),
    ] {
        let mut options = serde_json::json!({"mode":"packet-up","session-placement":placement,
            "seq-placement":placement,"session-table":"number","session-length":"10","uplink-http-method":method});
        if placement != "path" {
            options["session-key"] = "sid".into();
            options["seq-key"] = "seq".into();
        }
        let requests = observe_packet(options, b"data").await;
        let download = requests
            .iter()
            .find(|(r, _)| r.method() == http::Method::GET)
            .unwrap();
        let upload = requests.iter().find(|(r, _)| r.method() == method).unwrap();
        let metadata = |request: &http::Request<()>, key: &str| -> Option<String> {
            match placement {
                "path" => request
                    .uri()
                    .path()
                    .strip_prefix("/x/")
                    .unwrap()
                    .split('/')
                    .nth(if key == "sid" { 0 } else { 1 })
                    .map(str::to_owned),
                "query" => url::Url::parse(&request.uri().to_string())
                    .unwrap()
                    .query_pairs()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.into_owned()),
                "header" => request
                    .headers()
                    .get(key)
                    .map(|v| v.to_str().unwrap().to_owned()),
                "cookie" => request.headers()["cookie"]
                    .to_str()
                    .unwrap()
                    .split("; ")
                    .find_map(|pair| pair.strip_prefix(&format!("{key}=")).map(str::to_owned)),
                _ => unreachable!(),
            }
        };
        let id = metadata(&upload.0, "sid").unwrap();
        assert_eq!(id.len(), 10);
        assert!(id.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(metadata(&download.0, "sid"), Some(id));
        assert_eq!(metadata(&upload.0, "seq"), Some("0".into()));
        assert_eq!(metadata(&download.0, "seq"), None);
        assert_eq!(upload.1, b"data");
    }
}

#[tokio::test]
async fn packet_upload_can_move_payload_into_bounded_header_or_cookie_chunks() {
    use base64::Engine as _;
    for placement in ["body", "auto", "header", "cookie"] {
        let mut options = serde_json::json!({"mode":"packet-up","uplink-data-placement":placement,
            "sc-max-each-post-bytes":"128","sc-min-posts-interval-ms":"1"});
        if matches!(placement, "header" | "cookie") {
            options["uplink-data-key"] = "data".into();
            options["uplink-chunk-size"] = "64".into();
        }
        let payload: Vec<u8> = (0..250).map(|v| v as u8).collect();
        let requests = observe_packet(options, &payload).await;
        let mut actual = Vec::new();
        let mut packets = 0;
        for (request, body) in requests
            .iter()
            .filter(|(r, _)| r.method() != http::Method::GET)
        {
            packets += 1;
            if matches!(placement, "body" | "auto") {
                actual.extend_from_slice(body);
                continue;
            }
            assert!(body.is_empty());
            let mut encoded = String::new();
            for index in 0..10 {
                let chunk = if placement == "header" {
                    request
                        .headers()
                        .get(format!("data-{index}"))
                        .map(|v| v.to_str().unwrap())
                } else {
                    request.headers()["cookie"]
                        .to_str()
                        .unwrap()
                        .split("; ")
                        .find_map(|v| v.strip_prefix(&format!("data_{index}=")))
                };
                let Some(chunk) = chunk else {
                    break;
                };
                assert!(chunk.len() <= 64);
                encoded.push_str(chunk);
            }
            actual.extend(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .unwrap(),
            );
        }
        assert_eq!(packets, 2);
        assert_eq!(actual, payload);
    }
}

#[tokio::test]
async fn http1_stream_one_is_chunked_duplex_and_shutdown_closes_both_directions() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(peer.read_u8().await.unwrap());
                assert!(head.len() < 16384);
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            assert!(head.starts_with("post /x/ http/1.1\r\n"));
            assert!(head.contains("transfer-encoding: chunked\r\n"));
            assert!(head.contains("host: example.com\r\n"));
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                line.push(peer.read_u8().await.unwrap());
            }
            assert_eq!(
                usize::from_str_radix(std::str::from_utf8(&line[..line.len() - 2]).unwrap(), 16)
                    .unwrap(),
                7
            );
            let mut body = [0; 9];
            peer.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"payload\r\n");
            peer.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nreply\r\n")
                .await
                .unwrap();
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
            assert!(peer.write_all(b"5\r\nextra\r\n").await.is_err());
        });
        let mut config = XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap();
        config.http_version = vole::config::XHttpVersion::Http1;
        let client = XHttpClient::new(config);
        let mut io = client.connect(Box::new(io)).await.unwrap();
        io.write_all(b"payload").await.unwrap();
        let mut reply = [0; 5];
        io.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        io.shutdown().await.unwrap();
        assert!(io.read(&mut [0; 1]).await.is_err());
        drop(io);
        client.stop().await;
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http1_packet_up_shares_a_session_across_two_connections() {
    tokio::time::timeout(Duration::from_secs(2), async {
        async fn head(peer: &mut tokio::io::DuplexStream) -> String {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(peer.read_u8().await.unwrap());
                assert!(head.len() < 16384);
            }
            String::from_utf8(head).unwrap()
        }
        let (up, mut upload) = tokio::io::duplex(4096);
        let (down, mut download) = tokio::io::duplex(4096);
        let (path, observed) = tokio::sync::oneshot::channel();
        let download_task = tokio::spawn(async move {
            let head = head(&mut download).await;
            let url = head
                .lines()
                .next()
                .unwrap()
                .split(' ')
                .nth(1)
                .unwrap()
                .to_owned();
            assert!(head.starts_with("GET "));
            path.send(url).unwrap();
            download
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nready\r\n")
                .await
                .unwrap();
            assert_eq!(download.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let upload_task = tokio::spawn(async move {
            let session = observed.await.unwrap();
            for sequence in 0..2 {
                let head = head(&mut upload).await;
                assert!(head.starts_with(&format!("POST {session}/{sequence} HTTP/1.1\r\n")));
                assert!(
                    head.to_ascii_lowercase()
                        .contains("transfer-encoding: chunked")
                );
                let mut bytes = Vec::new();
                loop {
                    let mut line = Vec::new();
                    while !line.ends_with(b"\r\n") {
                        line.push(upload.read_u8().await.unwrap());
                    }
                    let count = usize::from_str_radix(
                        std::str::from_utf8(&line[..line.len() - 2]).unwrap(),
                        16,
                    )
                    .unwrap();
                    let mut chunk = vec![0; count + 2];
                    upload.read_exact(&mut chunk).await.unwrap();
                    assert_eq!(&chunk[count..], b"\r\n");
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                }
                assert_eq!(&bytes, b"packet");
                upload
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
            assert_eq!(upload.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let mut config = XHttpConfig::new("example.com", "/x", XHttpMode::PacketUp).unwrap();
        config.http_version = vole::config::XHttpVersion::Http1;
        let client = XHttpClient::new(config);
        let mut io = client
            .connect_with_download(Box::new(up), &client, Box::new(down))
            .await
            .unwrap();
        let mut ready = [0; 5];
        io.read_exact(&mut ready).await.unwrap();
        io.write_all(b"packet").await.unwrap();
        io.flush().await.unwrap();
        io.write_all(b"packet").await.unwrap();
        io.shutdown().await.unwrap();
        drop(io);
        client.stop().await;
        upload_task.await.unwrap();
        download_task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http1_response_body_can_arrive_after_the_response_headers() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(peer.read_u8().await.unwrap());
            }
            peer.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            peer.write_all(b"5\r\nhello\r\n").await.unwrap();
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
        });
        let mut config = XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap();
        config.http_version = vole::config::XHttpVersion::Http1;
        let client = XHttpClient::new(config);
        let mut io = client.connect(Box::new(io)).await.unwrap();
        io.write_all(b"payload").await.unwrap();
        let mut reply = [0; 5];
        io.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"hello");
        io.shutdown().await.unwrap();
        client.stop().await;
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn custom_request_headers_reach_the_http_peer_without_changing_body() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let document = serde_json::json!({"mixed-port":1080,"proxies":[{
            "name":"edge","type":"vless","server":"example.com","port":443,
            "uuid":"07070707-0707-0707-0707-070707070707","network":"xhttp","tls":true,
            "xhttp-opts":{"mode":"stream-one","headers":{"X-Custom":"private-value"}}
        }],"rules":["MATCH,edge"]});
        let parsed = Config::parse_yaml(&serde_json::to_vec(&document).unwrap()).unwrap();
        let ProxyProtocol::Vless(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        let mut config = XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap();
        config.headers = node.xhttp().unwrap().headers.clone();
        let client = XHttpClient::new(config);
        assert!(!format!("{client:?}").contains("private-value"));
        let (io, remote) = tokio::io::duplex(16384);
        let (observed, observation) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(remote).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.headers()["x-custom"], "private-value");
            assert_eq!(request.headers()["content-type"], "application/grpc");
            assert!(
                request.headers()["referer"]
                    .to_str()
                    .unwrap()
                    .contains("x_padding=")
            );
            let mut received = request.into_body();
            let mut sender = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let task = tokio::spawn(async move {
                let data = received.data().await.unwrap().unwrap();
                assert_eq!(&data[..], b"payload");
                sender
                    .send_data(bytes::Bytes::from_static(b"reply"), true)
                    .unwrap();
                observed.send(()).unwrap();
            });
            while connection.accept().await.is_some() {}
            task.await.unwrap();
        });
        let mut stream = client.connect(Box::new(io)).await.unwrap();
        stream.write_all(b"payload").await.unwrap();
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        observation.await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        peer.await.unwrap();
    })
    .await
    .unwrap();
}
