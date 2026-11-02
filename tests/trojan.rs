#![cfg(feature = "outbound-trojan")]

use vole::{
    outbound::trojan::{TrojanAuth, TrojanCommand},
    session::Destination,
};

#[test]
fn request_matches_the_official_sha224_and_socks_address_wire_format() {
    // SHA-224 independently checked with OpenSSL, not the production codec.
    let auth = TrojanAuth::new("password").unwrap();
    let destination = Destination::domain("example.com", 443).unwrap();
    let request = auth.request(TrojanCommand::Tcp, &destination).unwrap();
    assert_eq!(
        request.as_ref(),
        b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
    );
}

#[test]
fn authentication_and_requests_are_strict_and_never_debug_credentials() {
    assert!(TrojanAuth::new("").is_err());
    let auth = TrojanAuth::new(" password ").unwrap();
    let plain = TrojanAuth::new("password").unwrap();
    let destination = Destination::Ip("[::1]:53".parse().unwrap());
    let packet = auth.request(TrojanCommand::Udp, &destination).unwrap();
    assert_ne!(
        &packet[..56],
        &plain.request(TrojanCommand::Udp, &destination).unwrap()[..56]
    );
    assert_eq!(
        &packet[56..],
        b"\r\n\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x35\r\n"
    );
    assert!(!format!("{auth:?}").contains("password"));
    assert!(!format!("{auth:?}").contains(std::str::from_utf8(&packet[..56]).unwrap()));
    assert!(
        auth.request(
            TrojanCommand::Tcp,
            &Destination::Ip("127.0.0.1:0".parse().unwrap())
        )
        .is_err()
    );
}

#[tokio::test]
async fn invalid_truncated_and_oversized_frames_fail_closed_without_payload_leaks() {
    use tokio::io::AsyncWriteExt;
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport},
        outbound::trojan::TrojanDatagram,
    };
    for frame in [
        &b"\x09"[..],
        &b"\x01\x01\x02"[..],
        &b"\x01\x01\x02\x03\x04\x00\x00\x00\x01\r\nq"[..],
        &b"\x01\x01\x02\x03\x04\x00\x35\x00\x01XXq"[..],
        &b"\x01\x01\x02\x03\x04\x00\x35\x20\x01\r\n"[..],
        &b"\x03\x00"[..],
        &b"\x03\x01\xff\x00\x35\x00\x01\r\nq"[..],
    ] {
        let (client, mut peer) = tokio::io::duplex(4096);
        let mut transport = TrojanDatagram::new(Box::new(client), DatagramBudget::new(8192, 8192));
        peer.write_all(frame).await.unwrap();
        peer.shutdown().await.unwrap();
        let error = transport.receive().await.unwrap_err().to_string();
        assert!(!error.contains("1.2.3.4"));
        assert!(transport.receive().await.is_err());
        transport.close().await.unwrap();
    }
}

#[tokio::test]
async fn datagram_limits_preserve_messages_and_drain_over_budget_responses() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport},
        outbound::trojan::{MAX_DATAGRAM_PAYLOAD, TrojanDatagram},
        session::Datagram,
    };
    let (client, mut peer) = tokio::io::duplex(16384);
    let mut transport = TrojanDatagram::new(Box::new(client), DatagramBudget::new(u16::MAX, 3));
    let remote = Destination::Ip("1.2.3.4:53".parse().unwrap());
    assert_eq!(
        transport.payload_budget(&remote),
        DatagramBudget::new(8192, 3)
    );
    transport
        .send(Datagram {
            remote: remote.clone(),
            payload: Bytes::from(vec![7; usize::from(MAX_DATAGRAM_PAYLOAD)]),
            sniffed_domain: None,
        })
        .await
        .unwrap();
    let mut request = vec![0; 8192 + 11];
    peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..11], b"\x01\x01\x02\x03\x04\x00\x35\x20\x00\r\n");
    assert!(request[11..].iter().all(|byte| *byte == 7));
    assert!(
        transport
            .send(Datagram {
                remote,
                payload: Bytes::from(vec![7; 8193]),
                sniffed_domain: None
            })
            .await
            .is_err()
    );
    peer.write_all(
        b"\x01\x01\x02\x03\x04\x00\x35\x00\x04\r\nskip\x03\x08dns.test\x00\x35\x00\x03\r\nyes",
    )
    .await
    .unwrap();
    let packet = transport.receive().await.unwrap();
    assert_eq!(packet.remote, Destination::domain("dns.test", 53).unwrap());
    assert_eq!(packet.payload.as_ref(), b"yes");
}

#[tokio::test]
async fn datagram_sends_one_frame_and_receives_fragmented_consecutive_frames() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport},
        outbound::trojan::TrojanDatagram,
        session::Datagram,
    };
    let (client, mut peer) = tokio::io::duplex(1);
    let remote = Destination::Ip("1.2.3.4:53".parse().unwrap());
    let mut transport = TrojanDatagram::new(Box::new(client), DatagramBudget::new(8192, 8192));
    let server = tokio::spawn(async move {
        let mut frame = [0; 14];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x01\x01\x02\x03\x04\x00\x35\x00\x03\r\nabc");
        for payload in [b"one", b"two"] {
            peer.write_all(b"\x01\x01\x02\x03\x04\x00\x35\x00\x03\r\n")
                .await
                .unwrap();
            peer.write_all(payload).await.unwrap();
        }
    });
    transport
        .send(Datagram {
            remote: remote.clone(),
            payload: Bytes::from_static(b"abc"),
            sniffed_domain: None,
        })
        .await
        .unwrap();
    for expected in [b"one", b"two"] {
        let packet = transport.receive().await.unwrap();
        assert_eq!(packet.remote, remote);
        assert_eq!(packet.payload.as_ref(), expected);
    }
    server.await.unwrap();
    transport.close().await.unwrap();
}

#[tokio::test]
async fn cancelled_receive_preserves_partial_frames_and_does_not_block_send() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport},
        outbound::trojan::TrojanDatagram,
        session::Datagram,
    };
    let (client, mut peer) = tokio::io::duplex(4096);
    let mut transport = TrojanDatagram::new(Box::new(client), DatagramBudget::new(8192, 8192));
    peer.write_all(b"\x01\x01\x02").await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), transport.receive())
            .await
            .is_err()
    );
    transport
        .send(Datagram {
            remote: Destination::domain("example.com", 53).unwrap(),
            payload: Bytes::from_static(b"q"),
            sniffed_domain: None,
        })
        .await
        .unwrap();
    let mut sent = [0; 20];
    peer.read_exact(&mut sent).await.unwrap();
    assert_eq!(&sent, b"\x03\x0bexample.com\x00\x35\x00\x01\r\nq");
    peer.write_all(b"\x03\x04\x00\x35\x00\x03\r\nend")
        .await
        .unwrap();
    let packet = transport.receive().await.unwrap();
    assert_eq!(
        packet.remote,
        Destination::Ip("1.2.3.4:53".parse().unwrap())
    );
    assert_eq!(packet.payload.as_ref(), b"end");
}

#[tokio::test]
async fn cancelled_partial_send_poison_closes_without_replaying_or_waiting() {
    use bytes::Bytes;
    use tokio::io::AsyncReadExt;
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport},
        outbound::trojan::TrojanDatagram,
        session::Datagram,
    };
    let (client, mut peer) = tokio::io::duplex(1);
    let mut transport = TrojanDatagram::new(Box::new(client), DatagramBudget::new(8192, 8192));
    let packet = || Datagram {
        remote: Destination::Ip("1.2.3.4:53".parse().unwrap()),
        payload: Bytes::from_static(b"q"),
        sniffed_domain: None,
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            transport.send(packet())
        )
        .await
        .is_err()
    );
    assert!(transport.send(packet()).await.is_err());
    let mut remaining = Vec::new();
    peer.read_to_end(&mut remaining).await.unwrap();
    assert_eq!(remaining, [1]);
    transport.close().await.unwrap();
    transport.close().await.unwrap();
}

#[tokio::test]
async fn receive_future_keeps_packet_scratch_out_of_its_dynamic_frame() {
    use std::{
        future::poll_fn,
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport},
        outbound::trojan::TrojanDatagram,
    };

    struct PendingRead {
        capacity: Arc<AtomicUsize>,
    }
    impl AsyncRead for PendingRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.capacity.store(output.remaining(), Ordering::Relaxed);
            Poll::Pending
        }
    }
    impl AsyncWrite for PendingRead {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(input.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let capacity = Arc::new(AtomicUsize::new(0));
    let mut transport = TrojanDatagram::new(
        Box::new(PendingRead {
            capacity: capacity.clone(),
        }),
        DatagramBudget::new(8192, 8192),
    );
    let mut receive = transport.receive();
    // Query the concrete async_trait future through its dynamic vtable, not
    // the size of the Box/Pin pointer. The resource threshold is not a wire bug.
    let frame_bytes = std::mem::size_of_val(receive.as_ref().get_ref());
    poll_fn(|cx| {
        assert!(receive.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(receive);
    transport.close().await.unwrap();
    assert!(transport.receive().await.is_err());
    assert_eq!(capacity.load(Ordering::Relaxed), 2048);
    assert!(
        frame_bytes < 2048,
        "TROJAN_RECEIVE_FUTURE_SCRATCH_FOOTPRINT: {frame_bytes}"
    );
}
