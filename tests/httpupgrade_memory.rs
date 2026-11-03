#![cfg(feature = "stream-transport")]

use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use vole::transport::{WebSocketEarlyData, WebSocketOptions, connect_websocket};

fn options(fast: bool) -> WebSocketOptions {
    WebSocketOptions::new("ws://cover.invalid/upgrade?q=1", Default::default(), None)
        .unwrap()
        .with_http_upgrade(fast)
        .unwrap()
}

async fn head(peer: &mut tokio::io::DuplexStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(peer.read_u8().await.unwrap());
        assert!(head.len() <= 16384);
    }
    head
}

#[tokio::test]
async fn httpupgrade_early_data_partial_writes_and_response_tail_keep_byte_order() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    tokio::time::timeout(Duration::from_secs(5), async {
        for fast in [false, true] {
            for early in [0, 1, 2048] {
                let options = WebSocketOptions::new("ws://cover.invalid/edge?q=1", Default::default(), (early > 0).then(|| WebSocketEarlyData::Header {name:"Sec-WebSocket-Protocol".parse().unwrap(),max_bytes:early})).unwrap().with_http_upgrade(fast).unwrap();
                let prefix: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
                let expected = prefix.clone();
                let (io, mut peer) = tokio::io::duplex(17);
                let remote = tokio::spawn(async move {
                    let request = String::from_utf8(head(&mut peer).await).unwrap();
                    let ed = request.lines().find_map(|l| l.strip_prefix("sec-websocket-protocol: "));
                    let mut received = ed.map(|s| URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap_or_default();
                    assert_eq!(received.len(), early);
                    assert_eq!(&received, &expected[..early]);
                    let mut remainder = vec![0; expected.len() - early];
                    if fast { peer.read_exact(&mut remainder).await.unwrap(); }
                    peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\ntail").await.unwrap();
                    if !fast { peer.read_exact(&mut remainder).await.unwrap(); }
                    received.extend(remainder);
                    assert_eq!(received, expected);
                    let mut business = Vec::new();
                    peer.read_to_end(&mut business).await.unwrap();
                    assert_eq!(business, b"business");
                });
                let mut io = connect_websocket(Box::new(io), &options, &prefix, Instant::now()+Duration::from_secs(2)).await.unwrap();
                let mut tail = [0;4];
                io.read_exact(&mut tail).await.unwrap();
                assert_eq!(&tail,b"tail");
                io.write_all(b"business").await.unwrap();
                io.shutdown().await.unwrap();
                remote.await.unwrap();
            }
        }
    }).await.unwrap();
    for early in [
        WebSocketEarlyData::Path { max_bytes: 1 },
        WebSocketEarlyData::Header {
            name: "x-ed".parse().unwrap(),
            max_bytes: 1,
        },
    ] {
        assert!(
            WebSocketOptions::new("ws://cover.invalid/", Default::default(), Some(early))
                .unwrap()
                .with_http_upgrade(false)
                .is_err()
        );
    }
}

#[tokio::test]
async fn httpupgrade_rejects_invalid_oversized_and_truncated_responses_without_replay() {
    let responses = [
        "HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_owned(),
        "HTTP/1.0 101 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_owned(),
        "HTTP/1.1 101 OK\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n".to_owned(),
        "HTTP/1.1 101 OK\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n".to_owned(),
        "HTTP/1.1 101 OK\r\nConnection: Upgrade\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_owned(),
        "HTTP/1.1 101 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: websocket\r\n\r\n".to_owned(),
        "HTTP/1.1 101 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 0\r\n\r\n".to_owned(),
        "HTTP/1.1 101 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned(),
        "HTTP/1.1 101 OK\r\n".to_owned()+&"X-A: a\r\n".repeat(65)+"\r\n",
        "HTTP/1.1 101 OK\r\nX-A: ".to_owned()+&"a".repeat(16384)+"\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgr".to_owned(),
    ];
    for fast in [false, true] {
        for response in &responses {
            let response = response.clone();
            let (io, mut peer) = tokio::io::duplex(65536);
            let remote = tokio::spawn(async move {
                head(&mut peer).await;
                if fast {
                    let mut prefix = [0; 6];
                    peer.read_exact(&mut prefix).await.unwrap();
                    assert_eq!(&prefix, b"prefix");
                }
                let _ = peer.write_all(response.as_bytes()).await;
                let _ = peer.shutdown().await;
                let mut rest = Vec::new();
                peer.read_to_end(&mut rest).await.unwrap();
                assert!(
                    rest.is_empty(),
                    "prefix was duplicated or sent after invalid response"
                );
            });
            let result = connect_websocket(
                Box::new(io),
                &options(fast),
                b"prefix",
                Instant::now() + Duration::from_secs(1),
            )
            .await;
            assert!(
                matches!(result, Err(e) if matches!(e.kind(),io::ErrorKind::InvalidData|io::ErrorKind::UnexpectedEof)),
                "invalid response accepted or timed out"
            );
            remote.await.unwrap();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn httpupgrade_waits_for_101_under_the_original_deadline_and_drops_cancelled_io() {
    for fast in [false, true] {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(100);
        tokio::time::advance(Duration::from_millis(60)).await;
        let (io, mut peer) = tokio::io::duplex(4096);
        let result = connect_websocket(Box::new(io), &options(fast), b"prefix", deadline).await;
        assert!(matches!(result, Err(e) if e.kind()==io::ErrorKind::TimedOut));
        assert_eq!(Instant::now(), deadline);
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert!(received.ends_with(if fast { b"prefix" } else { b"\r\n\r\n" }));
        let (io, mut peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            connect_websocket(
                Box::new(io),
                &options(fast),
                b"prefix",
                Instant::now() + Duration::from_secs(10),
            )
            .await
        });
        head(&mut peer).await;
        task.abort();
        assert!(task.await.is_err_and(|e| e.is_cancelled()));
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, if fast { b"prefix".to_vec() } else { vec![] });
    }
}

#[tokio::test]
async fn expired_httpupgrade_deadline_writes_no_prefix_or_head() {
    for fast in [false, true] {
        let (io, mut peer) = tokio::io::duplex(4096);
        let result = connect_websocket(
            Box::new(io),
            &options(fast),
            b"prefix",
            Instant::now() - Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty(), "expired setup transmitted a prefix");
    }
}

#[tokio::test(start_paused = true)]
async fn httpupgrade_rejects_ready_101_after_waiting_past_setup_deadline() {
    for fast in [false, true] {
        let options = options(fast);
        let (io, mut peer) = tokio::io::duplex(4096);
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut handshake = Box::pin(connect_websocket(
            Box::new(io),
            &options,
            b"prefix",
            deadline,
        ));
        assert!(futures_util::poll!(handshake.as_mut()).is_pending());
        head(&mut peer).await;
        if fast {
            let mut prefix = [0; 6];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"prefix");
        }

        // Resume only after both the timeout and the response are ready.
        tokio::time::advance(Duration::from_millis(101)).await;
        peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        let result = handshake.await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        let mut late_bytes = Vec::new();
        peer.read_to_end(&mut late_bytes).await.unwrap();
        assert!(late_bytes.is_empty(), "expired setup transmitted a prefix");
    }
}

#[tokio::test(start_paused = true)]
async fn httpupgrade_does_not_resume_a_blocked_prefix_after_setup_deadline() {
    const RESPONSE: &[u8] =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    tokio::time::timeout(Duration::from_secs(5), async {
        for fast in [false, true] {
            let options = options(fast);
            let (io, mut peer) = tokio::io::duplex(1);
            let deadline = Instant::now() + Duration::from_millis(100);
            let mut handshake = Box::pin(connect_websocket(
                Box::new(io),
                &options,
                b"prefix",
                deadline,
            ));
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                // Each manual handshake poll needs a fresh cooperative IO budget.
                tokio::task::yield_now().await;
                assert!(futures_util::poll!(handshake.as_mut()).is_pending());
                request.push(peer.read_u8().await.unwrap());
            }
            if !fast {
                for byte in RESPONSE {
                    tokio::task::yield_now().await;
                    peer.write_all(&[*byte]).await.unwrap();
                    assert!(futures_util::poll!(handshake.as_mut()).is_pending());
                }
            } else {
                assert!(futures_util::poll!(handshake.as_mut()).is_pending());
            }
            // The prefix has only partially reached the supplied IO. Make the
            // writer ready again, but do not poll setup until its deadline expires.
            assert_eq!(peer.read_u8().await.unwrap(), b'p');
            tokio::time::advance(Duration::from_millis(100)).await;
            let result = handshake.await;
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
            let mut late_bytes = Vec::new();
            peer.read_to_end(&mut late_bytes).await.unwrap();
            assert!(
                late_bytes.is_empty(),
                "expired setup resumed a partial write"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn established_httpupgrade_io_outlives_its_setup_deadline() {
    for fast in [false, true] {
        let (io, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\ntail")
            .await
            .unwrap();
        let mut stream = connect_websocket(
            Box::new(io),
            &options(fast),
            b"prefix",
            Instant::now() + Duration::from_millis(100),
        )
        .await
        .unwrap();
        head(&mut peer).await;
        let mut prefix = [0; 6];
        peer.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"prefix");

        tokio::time::advance(Duration::from_secs(1)).await;
        let mut tail = [0; 4];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");
        stream.write_all(b"upload").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        let mut uploaded = Vec::new();
        peer.read_to_end(&mut uploaded).await.unwrap();
        assert_eq!(uploaded, b"upload");
        peer.write_all(b"download").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut downloaded = Vec::new();
        stream.read_to_end(&mut downloaded).await.unwrap();
        assert_eq!(downloaded, b"download");
    }
}
