//! Public XHTTP stream regressions for the locked, unmodified h2 dependency.
//! The minimal wire peer is an adversarial fixture, not native interoperability.

#![cfg(feature = "outbound-vless")]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::transport::xhttp::{XHttpClient, XHttpConfig, XHttpMode};

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut output = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    output.extend_from_slice(&[kind, flags]);
    output.extend_from_slice(&stream.to_be_bytes());
    output.extend_from_slice(payload);
    output
}

async fn response_followed_by_reset(end_stream: bool) -> std::io::Result<Vec<u8>> {
    let (client_io, mut peer_io) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut preface = [0; 24];
        peer_io.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        peer_io.write_all(&frame(4, 0, 0, &[])).await.unwrap();
        let stream_id = loop {
            let mut header = [0; 9];
            peer_io.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            assert!(length <= 16384);
            let mut payload = vec![0; length];
            peer_io.read_exact(&mut payload).await.unwrap();
            if header[3] == 4 && header[4] & 1 == 0 {
                peer_io.write_all(&frame(4, 1, 0, &[])).await.unwrap();
            }
            if header[3] == 1 {
                break u32::from_be_bytes(header[5..9].try_into().unwrap());
            }
        };
        // HPACK indexed :status 200, then a complete response, then CANCEL.
        // Put them in one write so the client driver receives the entire order
        // before the application drains the DATA. No third-party internals.
        let mut response = frame(1, 4, stream_id, &[0x88]);
        response.extend(frame(
            0,
            u8::from(end_stream),
            stream_id,
            b"complete-before-reset",
        ));
        response.extend(frame(3, 0, stream_id, &8_u32.to_be_bytes()));
        peer_io.write_all(&response).await.unwrap();
        let mut remaining = Vec::new();
        peer_io.read_to_end(&mut remaining).await.unwrap();
    });
    let client = XHttpClient::new(
        XHttpConfig::new("fixture.invalid", "/foundations", XHttpMode::StreamOne).unwrap(),
    );
    let mut stream = client.connect(Box::new(client_io)).await.unwrap();
    let mut response = Vec::new();
    let result =
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await;
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
    result.expect("response read stalled")?;
    Ok(response)
}

#[tokio::test]
async fn xhttp_keeps_complete_response_when_peer_resets_after_end_stream() {
    let response = response_followed_by_reset(true)
        .await
        .expect("END_STREAM must retain complete DATA despite a subsequent reset");
    assert_eq!(response, b"complete-before-reset");
}

#[tokio::test]
async fn xhttp_does_not_hide_reset_before_end_stream() {
    let error = response_followed_by_reset(false)
        .await
        .expect_err("a reset before END_STREAM must not become successful EOF");
    let reset = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<h2::Error>())
        .expect("the HTTP/2 reset must be preserved");
    assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));
}
