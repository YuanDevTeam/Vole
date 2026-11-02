#![cfg(feature = "outbound-vmess")]

use vole::{
    outbound::vmess::{
        BodyCipher, BodyOptions, ClientHandshake, Command, VmessIdentity, VmessStream,
    },
    session::Destination,
};

#[tokio::test]
async fn xudp_explicit_close_after_cancel_and_bad_frame_release_io() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vole::{dispatch::DatagramTransport, session::Datagram, xudp::XudpTransport};
    let (io, mut peer) = tokio::io::duplex(1);
    let mut client = XudpTransport::new(Box::new(io), [0; 8], 16);
    let datagram = Datagram {
        remote: "192.0.2.1:53"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        payload: bytes::Bytes::from_static(b"payload"),
        sniffed_domain: None,
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            client.send(datagram.clone())
        )
        .await
        .is_err()
    );
    // Cancellation retains the pending XUDP frame for a later send/receive.
    // Explicit close abandons it without inserting END into the partial frame.
    client.close().await.unwrap();
    let mut wire = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        peer.read_to_end(&mut wire),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(wire.len(), 1);
    assert!(client.send(datagram.clone()).await.is_err());
    assert!(client.receive().await.is_err());
    client.close().await.unwrap();
    let (io, mut peer) = tokio::io::duplex(64);
    let mut client = XudpTransport::new(Box::new(io), [0; 8], 16);
    peer.write_all(&[0, 3]).await.unwrap();
    assert!(client.receive().await.is_err());
    assert!(client.send(datagram).await.is_err());
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    // The two packet-mode VMess codecs must release IO on cancellation too,
    // without waiting for another call or the association owner to drop them.
    use vole::{
        dispatch::DatagramBudget, dns::resolution::ResolutionContext,
        outbound::vmess::VmessDatagram,
    };
    for packetaddr in [false, true] {
        let (io, mut peer) = tokio::io::duplex(1);
        let target: Destination = "192.0.2.1:53"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        let handshake = ClientHandshake::new(
            &VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
            Command::Udp,
            &target,
            BodyOptions::new(BodyCipher::None, false, false).unwrap(),
        )
        .unwrap();
        let stream = VmessStream::new(Box::new(io), handshake);
        let budget = DatagramBudget::new(32, 32);
        let mut client = if packetaddr {
            VmessDatagram::packet_addr(stream, budget, ResolutionContext::default())
        } else {
            VmessDatagram::raw(stream, target.clone(), budget)
        };
        let datagram = Datagram {
            remote: target,
            payload: bytes::Bytes::from_static(b"payload"),
            sniffed_domain: None,
        };
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                client.send(datagram.clone())
            )
            .await
            .is_err()
        );
        let mut wire = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            peer.read_to_end(&mut wire),
        )
        .await
        .expect("cancelled VMess packet send retained IO")
        .unwrap();
        assert_eq!(wire.len(), 1);
        assert!(client.send(datagram).await.is_err());
        assert!(client.receive().await.is_err());
        client.close().await.unwrap();
    }
}

#[tokio::test]
async fn xudp_zero_global_id_omits_the_optional_extension_like_mihomo() {
    use tokio::io::AsyncReadExt;
    use vole::{dispatch::DatagramTransport, session::Datagram, xudp::XudpTransport};
    let (io, mut peer) = tokio::io::duplex(128);
    let mut transport = XudpTransport::new(Box::new(io), [0; 8], 1500);
    transport
        .send(Datagram {
            remote: "1.2.3.4:53".parse::<std::net::SocketAddr>().unwrap().into(),
            payload: bytes::Bytes::from_static(&[7]),
            sniffed_domain: None,
        })
        .await
        .unwrap();
    let mut wire = [0; 17];
    peer.read_exact(&mut wire).await.unwrap();
    assert_eq!(wire, [0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 1, 7]);
}

#[test]
fn packetaddr_has_ip_only_address_first_wire_and_rejects_truncation() {
    use vole::outbound::address::{decode_packet_addr, encode_packet_addr};
    let peer = Destination::Ip("1.2.3.4:53".parse().unwrap());
    let mut wire = bytes::BytesMut::new();
    encode_packet_addr(&peer, &mut wire).unwrap();
    assert_eq!(&wire[..], &[1, 1, 2, 3, 4, 0, 53]);
    assert_eq!(decode_packet_addr(&wire).unwrap(), (peer, 7));
    let peer = Destination::Ip("[::1]:443".parse().unwrap());
    wire.clear();
    encode_packet_addr(&peer, &mut wire).unwrap();
    assert_eq!(
        &wire[..],
        &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187]
    );
    assert_eq!(decode_packet_addr(&wire).unwrap(), (peer, 19));
    for length in 0..19 {
        assert!(decode_packet_addr(&wire[..length]).is_err());
    }
    assert!(decode_packet_addr(&[3, 0, 0]).is_err());
    assert!(decode_packet_addr(&[1, 1, 2, 3, 4, 0, 0]).is_err());
    assert!(
        encode_packet_addr(
            &Destination::domain("fixture.invalid", 53).unwrap(),
            &mut bytes::BytesMut::new()
        )
        .is_err()
    );
}

#[test]
fn vmess_aead_requests_are_fresh_bounded_and_redacted() {
    let identity = VmessIdentity::new(uuid::Uuid::from_bytes([7; 16]));
    let target = Destination::domain("fixture.invalid", 443).unwrap();
    let options = BodyOptions::new(BodyCipher::None, false, false).unwrap();
    let first = ClientHandshake::new(&identity, Command::Tcp, &target, options).unwrap();
    let second = ClientHandshake::new(&identity, Command::Tcp, &target, options).unwrap();
    assert_ne!(first.request(), second.request());
    assert!((99..=384).contains(&first.request().len()));
    assert!(!format!("{identity:?}").contains("07070707"));
    assert!(!format!("{first:?}").contains("fixture.invalid"));
    assert!(first.response_length(&[0; 18]).is_err());
    assert!(BodyOptions::new(BodyCipher::None, true, false).is_err());
    assert!(BodyOptions::new(BodyCipher::None, false, true).is_err());
}

#[tokio::test]
async fn vmess_response_authentication_cannot_be_skipped_by_none_cipher() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let identity = VmessIdentity::new(uuid::Uuid::from_bytes([7; 16]));
    let target = Destination::domain("fixture.invalid", 443).unwrap();
    let handshake = ClientHandshake::new(
        &identity,
        Command::Tcp,
        &target,
        BodyOptions::new(BodyCipher::None, false, false).unwrap(),
    )
    .unwrap();
    let (client, mut peer) = tokio::io::duplex(1024);
    let mut stream = VmessStream::new(Box::new(client), handshake);
    peer.write_all(&[0; 18]).await.unwrap();
    let mut data = [0; 1];
    assert_eq!(
        stream.read(&mut data).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(stream.write_all(b"after-failure").await.is_err());
}

#[tokio::test]
async fn vmess_whole_close_wakes_reader_and_releases_io_before_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let handshake = ClientHandshake::new(
        &VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
        Command::Tcp,
        &Destination::domain("fixture.invalid", 443).unwrap(),
        BodyOptions::new(BodyCipher::Auto, false, false).unwrap(),
    )
    .unwrap();
    let (io, mut peer) = tokio::io::duplex(1024);
    let stream = VmessStream::new(Box::new(io), handshake).with_whole_close();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut byte = [0; 1];
    let read = reader.read(&mut byte);
    tokio::pin!(read);
    assert!(futures_util::poll!(read.as_mut()).is_pending());
    writer.shutdown().await.unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_millis(100), read)
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    assert!(writer.write_all(b"after-close").await.is_err());
    writer.shutdown().await.unwrap();
}
#[tokio::test]
async fn xudp_explicit_budget_rejects_max_plus_one_before_writing() {
    use vole::{
        dispatch::{DatagramBudget, DatagramTransport},
        session::Datagram,
    };
    let (client, mut peer) = tokio::io::duplex(64);
    let mut client =
        vole::xudp::XudpTransport::with_budget(Box::new(client), [0; 8], DatagramBudget::new(4, 4));
    let remote = "192.0.2.1:53"
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into();
    assert!(
        client
            .send(Datagram {
                remote,
                payload: vec![0; 5].into(),
                sniffed_domain: None
            })
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            tokio::io::AsyncReadExt::read_u8(&mut peer)
        )
        .await
        .is_err()
    );
}
