//! The peer sends only an HTTP/3 frame prefix, never the oversized payload.
use super::*;
use tokio::sync::oneshot;

#[test]
fn receive_prefixes_progress_across_empty_data_and_bypass_qpack() {
    // Empty DATA, one-byte DATA and another empty DATA. Every native chunk
    // split must retain all wire bytes and yield nonempty framing prefixes.
    let wire = [0, 0, 0, 1, 42, 0, 0];
    for size in 1..=wire.len() {
        let mut budget = super::super::budget::Budget::new(16 * 1024, false);
        let mut count = 0;
        for mut chunk in wire.chunks(size) {
            while !chunk.is_empty() {
                let length = budget.prefix(chunk).unwrap();
                assert!(length > 0 && length <= chunk.len());
                count += length;
                chunk = &chunk[length..];
            }
        }
        assert_eq!(count, wire.len());
    }
    let mut qpack = super::super::budget::Budget::new(0, true);
    assert_eq!(qpack.prefix(&[2, 255, 255]).unwrap(), 1);
    assert_eq!(qpack.prefix(&[255, 255]).unwrap(), 2);
}

#[tokio::test]
async fn small_data_frames_do_not_release_unbounded_receive_credit() {
    use std::sync::atomic::AtomicUsize;

    let mut pair = Pair::new(64 * 1024).await;
    let (mut client, server_control) = pair.h3().await;
    let server = pair.server.clone();
    let sent = Arc::new(AtomicUsize::new(0));
    let progress = sent.clone();
    pair.spawn(async move {
        let _server_control = server_control;
        let (mut send, mut receive) = server.accept_bi().await.unwrap();
        assert!(!receive.read_to_end(16 * 1024).await.unwrap().is_empty());
        send.write_all(&[1, 3, 0, 0, 0xd9]).await.unwrap();
        // Coalesced tiny DATA frames reproduce a continuously ready stream:
        // one native QUIC chunk holds many application deliveries.
        let batch = [0, 8, 1, 2, 3, 4, 5, 6, 7, 8].repeat(1000);
        loop {
            if send.write_all(&batch).await.is_err() {
                break;
            }
            progress.fetch_add(batch.len(), Ordering::Relaxed);
        }
    });
    settle(pair, async move {
        let mut stream = client
            .send_request(
                http::Request::get("https://localhost/backpressure")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let mut delivered = 0;
        while delivered < 4096 {
            let mut data = stream.recv_data().await.unwrap().unwrap();
            while data.has_remaining() {
                assert_eq!(data.get_u8(), (delivered % 8 + 1) as u8);
                delivered += 1;
            }
            // Let the native driver refill its bounded window before the next
            // application read. No real sockets or network peer are involved.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(delivered, 4096);
        let accepted = sent.load(Ordering::Relaxed);
        // Includes both QUIC receive credit and the peer's bounded send queue.
        // Consuming 4 KiB must not unlock a stream of prefetched DATA frames.
        assert!(
            accepted <= 256 * 1024,
            "peer accepted {accepted} bytes after {delivered} application bytes"
        );
    })
    .await;
}

#[test]
fn every_prefix_split_rejects_after_complete_declared_length() {
    // Non-minimal 8-byte QUIC varints are valid. These independent wire
    // fixtures complement native IO tests, whose packet coalescing does not
    // guarantee a particular receive-chunk boundary.
    let headers = [0xc0, 0, 0, 0, 0, 0, 0, 1, 0x80, 0, 0x60, 1];
    let settings = [
        0xc0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 4, 0x41, 1,
    ];
    for (wire, uni, expected) in [
        (
            headers.as_slice(),
            false,
            h3::error::Code::H3_EXCESSIVE_LOAD,
        ),
        (settings.as_slice(), true, h3::error::Code::H3_FRAME_ERROR),
    ] {
        for split in 0..wire.len() {
            let mut budget = super::super::budget::Budget::new(16 * 1024, uni);
            assert!(budget.check(&wire[..split]).is_ok());
            assert_eq!(budget.check(&wire[split..]), Err(expected));
        }
    }
}

#[tokio::test]
async fn oversized_headers_prefix_is_rejected_before_payload_and_preserves_sibling() {
    rejected_request_prefix(&[1, 0x80, 0, 0x60, 1]).await;
}

async fn rejected_request_prefix(prefix: &'static [u8]) {
    let mut pair = Pair::new(64 * 1024).await;
    let (mut client, server_control) = pair.h3().await;
    let server = pair.server.clone();
    let native_client = pair.client.clone();
    let (sent, prefix_sent) = oneshot::channel();
    pair.spawn(async move {
        // Retain the official server's critical streams; raw bidi IO below
        // supplies the malformed response without passing its encoder.
        let _server_control = server_control;
        let (mut first, mut request) = server.accept_bi().await.unwrap();
        assert!(!request.read_to_end(16 * 1024).await.unwrap().is_empty());
        first.write_all(prefix).await.unwrap();
        sent.send(()).unwrap();
        let (mut sibling, mut request) = server.accept_bi().await.unwrap();
        assert!(!request.read_to_end(16 * 1024).await.unwrap().is_empty());
        // QPACK field section prefix 0/0 and static :status=200 (index 25),
        // followed by DATA("sibling"); no dynamic QPACK state is involved.
        sibling
            .write_all(&[
                1, 3, 0, 0, 0xd9, 0, 7, b's', b'i', b'b', b'l', b'i', b'n', b'g',
            ])
            .await
            .unwrap();
        sibling.finish().unwrap();
        // Keep the first response open: no payload and no FIN can turn this
        // into a decoded-field or incomplete-frame test instead of a prefix cap.
        let _first = first;
        std::future::pending::<()>().await;
    });
    settle(pair, async move {
        let mut stream = client
            .send_request(
                http::Request::get("https://localhost/oversize")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        prefix_sent.await.unwrap();
        let response = timeout(Duration::from_millis(500), stream.recv_response())
            .await
            .expect("oversized HEADERS prefix must be rejected without waiting for its payload");
        assert!(response.is_err());
        drop(stream);
        assert!(native_client.close_reason().is_none());
        assert!(client.can_open_request());
        let mut sibling = client
            .send_request(
                http::Request::get("https://localhost/sibling")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        sibling.finish().await.unwrap();
        assert_eq!(sibling.recv_response().await.unwrap().status(), 200);
        let mut body = Vec::new();
        while let Some(mut data) = sibling.recv_data().await.unwrap() {
            body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        assert_eq!(body, b"sibling");
        assert!(sibling.recv_trailers().await.unwrap().is_none());
    })
    .await;
}

#[tokio::test]
async fn oversized_unknown_frame_prefix_is_rejected_before_payload_and_preserves_sibling() {
    // Unknown frame 31, declared 32 KiB: above the Core retention budget.
    rejected_request_prefix(&[31, 0x80, 0, 0x80, 0]).await;
}

async fn rejected_control_prefix(prefix: &'static [u8]) {
    let mut pair = Pair::new(64 * 1024).await;
    let (client, mut control) = attach(pair.client.clone(), 16 * 1024).await.unwrap();
    pair.spawn(async move {
        let _client = client;
        let _ = control.wait_idle().await;
    });
    let server = pair.server.clone();
    pair.spawn(async move {
        let mut stream = server.open_uni().await.unwrap();
        stream.write_all(prefix).await.unwrap();
        let _stream = stream;
        // The absence of payload/FIN cannot produce a parser EOF error.
        std::future::pending::<()>().await;
    });
    let client = pair.client.clone();
    settle(pair, async move {
        let _ = timeout(Duration::from_millis(500), client.closed())
            .await
            .expect("invalid control prefix must close before its payload arrives");
        assert!(client.close_reason().is_some());
    })
    .await;
}

#[tokio::test]
async fn oversized_settings_prefix_is_rejected_before_payload_and_stop_joins() {
    // Uni control(0), SETTINGS(4), length 257 (maximum is 256).
    rejected_control_prefix(&[0, 4, 0x41, 1]).await;
}

#[tokio::test]
async fn oversized_varint_control_prefix_is_rejected_before_payload_and_stop_joins() {
    // A valid empty SETTINGS precedes GOAWAY with an impossible 9-byte ID.
    rejected_control_prefix(&[0, 4, 0, 7, 9]).await;
}

#[tokio::test]
async fn fragmented_headers_and_large_data_progress_without_body_scanning() {
    let mut pair = Pair::new(64 * 1024).await;
    let (mut client, server_control) = pair.h3().await;
    let server = pair.server.clone();
    let payload = Bytes::from((0..65_537).map(|n| (n % 251) as u8).collect::<Vec<_>>());
    let expected = payload.clone();
    pair.spawn(async move {
        let _server_control = server_control;
        let (mut send, mut receive) = server.accept_bi().await.unwrap();
        assert!(!receive.read_to_end(16 * 1024).await.unwrap().is_empty());
        // HEADERS type encoded in 8 bytes, length in 2, then static QPACK 200.
        // Separate writes/yields exercise prefix progress across native IO.
        for byte in [0xc0, 0, 0, 0, 0, 0, 0, 1, 0x40, 3, 0, 0, 0xd9] {
            send.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        // DATA length exceeds the non-DATA cap. Payload contains all octets,
        // including byte patterns that resemble oversized frame prefixes.
        send.write_all(&[0, 0x80, 1, 0, 1]).await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        std::future::pending::<()>().await;
    });
    settle(pair, async move {
        let mut stream = client
            .send_request(
                http::Request::get("https://localhost/data")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let mut body = Vec::new();
        while let Some(mut data) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            assert!(body.len() <= expected.len());
        }
        assert_eq!(body, expected);
        assert!(stream.recv_trailers().await.unwrap().is_none());
        assert!(client.can_open_request());
    })
    .await;
}
