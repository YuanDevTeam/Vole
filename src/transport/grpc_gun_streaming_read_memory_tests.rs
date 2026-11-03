//! Real Gun reader over actual h2 and a bounded in-memory byte transport.
use super::*;
use crate::resources::observation::ResourceProbe;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use tokio_util::sync::CancellationToken;

struct Peer {
    stream: BoxStream,
    driver: Option<Driver>,
    tail: Option<oneshot::Sender<()>>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Peer {
    fn release_tail(&mut self) {
        self.tail.take().unwrap().send(()).unwrap();
    }

    async fn finish(self) {
        drop(self.stream);
        self.cancel.cancel();
        if let Some(driver) = self.driver {
            driver.stop().await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

fn message(payload: &[u8]) -> Bytes {
    let mut wire = vec![0; 5];
    wire.push(0x0a);
    let mut length = payload.len();
    while length > 127 {
        wire.push((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    wire.push(length as u8);
    wire.extend_from_slice(payload);
    let length = (wire.len() - 5) as u32;
    wire[1..5].copy_from_slice(&length.to_be_bytes());
    wire.into()
}

async fn peer(prefix: Vec<Bytes>, tail: Bytes, status: &'static str) -> Peer {
    let (raw, supplied) = tokio::io::duplex(CHUNK);
    let (ready, prepared) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let task = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .handshake::<_, Bytes>(supplied)
            .await
            .unwrap();
        let (_request, mut response) = connection.accept().await.unwrap().unwrap();
        let headers = http::Response::builder()
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut output = response.send_response(headers, false).unwrap();
        for part in prefix {
            output.send_data(part, false).unwrap();
        }
        let mut ping = connection.ping_pong().unwrap();
        macro_rules! drive {
            ($future:expr) => {{
                let future = $future;
                tokio::pin!(future);
                loop {
                    tokio::select! { biased;
                        () = stop.cancelled() => return,
                        result = &mut future => break result,
                        next = connection.accept() => {
                            if !matches!(next, Some(Ok(_))) {
                                return;
                            }
                        }
                    }
                }
            }};
        }
        // The real round trip keeps the h2 driver live and observes receipt
        // of the earlier DATA, without releasing the application's tail gate.
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        if ready.send(()).is_err() || drive!(released).is_err() {
            return;
        }
        if !tail.is_empty() {
            output.send_data(tail, false).unwrap();
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static(status));
        output.send_trailers(trailers).unwrap();
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                next = connection.accept() => {
                    if !matches!(next, Some(Ok(_))) {
                        break;
                    }
                }
            }
        }
    });
    let (stream, driver) = grpc_duplex(
        Box::new(raw),
        "http://fixture.invalid/GunService/Tun",
        Instant::now() + Duration::from_secs(3),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), prepared)
        .await
        .unwrap()
        .unwrap();
    Peer {
        stream,
        driver: Some(driver),
        tail: Some(release),
        cancel,
        task,
    }
}

#[tokio::test]
async fn gun_reader_delivers_validated_prefix_before_withheld_message_tail() {
    let probe = ResourceProbe::default();
    let (first, zero, got, expected) = probe
        .scope(async {
            let expected: Vec<_> = (0..LIMIT).map(|n| (n % 251) as u8).collect();
            let wire = message(&expected);
            let header = wire.len() - expected.len();
            let mut prefix: Vec<_> = (0..header).map(|n| wire.slice(n..n + 1)).collect();
            prefix.push(wire.slice(header..header + 257));
            let mut peer = peer(prefix, wire.slice(header + 257..), "0").await;
            let zero = peer.stream.read(&mut []).await.unwrap();
            let mut bytes = [0; 257];
            let first = {
                let reading = peer.stream.read(&mut bytes);
                tokio::pin!(reading);
                // Dropping a Pending borrowed read must retain parsing state.
                futures_util::poll!(reading.as_mut())
            };
            let mut got = Vec::new();
            if let Poll::Ready(Ok(count)) = &first {
                got.extend_from_slice(&bytes[..*count]);
            }
            // Upload FIN must preserve the independently gated read half.
            peer.stream.shutdown().await.unwrap();
            peer.release_tail();
            tokio::time::timeout(Duration::from_secs(3), peer.stream.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            peer.finish().await;
            (first, zero, got, expected)
        })
        .await;
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    assert_eq!(zero, 0);
    assert_eq!(got, expected, "streamed Gun bytes changed or duplicated");
    assert!(
        matches!(first, Poll::Ready(Ok(257))),
        "Gun reader withheld a validated payload prefix until the message tail arrived"
    );
}

#[tokio::test]
async fn gun_reader_split_varints_zero_messages_and_back_to_back_records() {
    for length in [1, 127, 128, CHUNK, LIMIT] {
        let expected: Vec<_> = (0..length).map(|n| (n % 239) as u8).collect();
        let empty = message(&[]);
        let wire = message(&expected);
        let header = wire.len() - length;
        let mut parts = vec![empty];
        parts.extend((0..header).map(|n| wire.slice(n..n + 1)));
        parts.push(wire.slice(header..));
        parts.push(message(b"next"));
        // The original reader accepts these redundant varint encodings.
        parts.push(Bytes::from_static(&[0, 0, 0, 0, 4, 0x0a, 0x81, 0, b'z']));
        parts.push(Bytes::from_static(&[
            0, 0, 0, 0, 5, 0x0a, 0x81, 0x80, 0, b'z',
        ]));
        let mut peer = peer(parts, Bytes::new(), "0").await;
        peer.release_tail();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), peer.stream.read_to_end(&mut got))
            .await
            .unwrap()
            .unwrap();
        peer.finish().await;
        let mut expected = expected;
        expected.extend_from_slice(b"nextzz");
        assert_eq!(got, expected);
    }
}

#[tokio::test]
async fn gun_reader_keeps_header_rejections_and_reports_truncated_body_after_prefix() {
    let mut compressed = message(b"valid").to_vec();
    compressed[0] = 1;
    let mut tag = message(b"valid").to_vec();
    tag[5] = 0x12;
    let mut mismatch = message(b"valid").to_vec();
    mismatch[6] = 4;
    let mut excessive = vec![0; 5];
    excessive[1..].copy_from_slice(&((LIMIT + 5) as u32).to_be_bytes());
    for wire in [
        Bytes::from(compressed),
        Bytes::from(tag),
        Bytes::from(mismatch),
        Bytes::from(excessive),
        Bytes::from_static(&[0, 0, 0, 0, 1, 0x0a]),
        Bytes::from_static(&[0, 0, 0, 0, 2, 0x0a, 0x80, 0]),
        Bytes::from_static(&[0, 0, 0, 0, 4, 0x0a, 0x80, 0x80, 0x80]),
        Bytes::from_static(&[0, 0, 0]),
    ] {
        let mut peer = peer(vec![wire], Bytes::new(), "0").await;
        peer.release_tail();
        let mut got = Vec::new();
        let result =
            tokio::time::timeout(Duration::from_secs(3), peer.stream.read_to_end(&mut got))
                .await
                .unwrap();
        peer.finish().await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(got.is_empty(), "invalid header exposed payload");
    }
    let wire = message(b"complete");
    let mut peer = peer(vec![wire.slice(..wire.len() - 3)], Bytes::new(), "0").await;
    peer.release_tail();
    let mut got = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(3), peer.stream.read_to_end(&mut got))
        .await
        .unwrap();
    peer.finish().await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(got, b"compl", "valid prefix was made artificially atomic");
}

#[tokio::test]
async fn gun_reader_partial_header_cancellation_and_active_stop_keep_owned_progress() {
    let wire = message(b"cancelled-header");
    let mut partial = peer(vec![wire.slice(..3)], wire.slice(3..), "0").await;
    let mut bytes = [0; 32];
    let pending = {
        let reading = partial.stream.read(&mut bytes);
        tokio::pin!(reading);
        futures_util::poll!(reading.as_mut()).is_pending()
    };
    partial.release_tail();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), partial.stream.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    partial.finish().await;
    assert!(pending, "incomplete header produced a false EOF");
    assert_eq!(got, b"cancelled-header");

    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let wire = message(b"prefix-and-withheld-tail");
            let first = wire.len() - b"prefix-and-withheld-tail".len() + 6;
            let mut active = peer(vec![wire.slice(..first)], wire.slice(first..), "0").await;
            let mut prefix = [0; 6];
            tokio::time::timeout(
                Duration::from_secs(3),
                active.stream.read_exact(&mut prefix),
            )
            .await
            .unwrap()
            .unwrap();
            let waiting = {
                let reading = active.stream.read(&mut bytes);
                tokio::pin!(reading);
                futures_util::poll!(reading.as_mut()).is_pending()
            };
            active.driver.take().unwrap().stop().await.unwrap();
            let stopped = active.stream.read(&mut bytes).await.unwrap();
            active.finish().await;
            assert!(waiting);
            assert_eq!(prefix, *b"prefix");
            assert_eq!(stopped, 0);
        })
        .await;
    assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
}
