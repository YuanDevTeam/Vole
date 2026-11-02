#![cfg(feature = "outbound-vless")]
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol, VlessOutboundConfig, VlessPacketEncoding},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        VlessOutbound,
    },
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

struct Supplied(Mutex<Option<BoxStream>>);
#[async_trait::async_trait]
impl OutboundConnector for Supplied {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: self.0.lock().unwrap().take().unwrap(),
            effective_peer: session.destination,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn node_config(encoding: &str) -> VlessOutboundConfig {
    let config=Config::parse_yaml(format!("mixed-port: 1080\nproxies: [{{name: edge, type: vless, server: example.com, port: 443, uuid: 07070707-0707-0707-0707-070707070707, udp: true, packet-encoding: {encoding}}}]\nrules: ['MATCH,edge']").as_bytes()).unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    config.clone()
}
fn node_with_config(io: BoxStream, config: &VlessOutboundConfig) -> VlessOutbound {
    VlessOutbound::new_with_path(
        config,
        UpstreamPath::proxy(Arc::new(Supplied(Mutex::new(Some(io))))),
    )
    .unwrap()
}
fn node(io: BoxStream, encoding: &str) -> VlessOutbound {
    node_with_config(io, &node_config(encoding))
}
fn internal_raw_node(io: BoxStream) -> VlessOutbound {
    let mut config = node_config("xudp");
    // Keep the internal fixed-target codec covered through the typed API.
    config.packet_encoding = VlessPacketEncoding::Raw;
    node_with_config(io, &config)
}
fn session() -> DatagramSession {
    DatagramSession::new(InboundKind::InternalMeasure, "127.0.0.1:1".parse().unwrap())
}
fn packet() -> Datagram {
    Datagram {
        remote: Destination::Ip("192.0.2.1:53".parse().unwrap()),
        payload: bytes::Bytes::from_static(b"payload"),
        sniffed_domain: None,
    }
}

#[tokio::test]
async fn stopping_before_first_udp_send_wakes_receive_and_releases_io() {
    for encoding in [
        None,
        Some("none"),
        Some("xudp"),
        Some("packetaddr"),
        Some("packet"),
    ] {
        let (io, mut peer) = tokio::io::duplex(1024);
        let outbound = match encoding {
            Some(encoding) => node(Box::new(io), encoding),
            None => internal_raw_node(Box::new(io)),
        };
        let mut client = outbound
            .open_datagram(
                DatagramRequest::new(session()),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        if matches!(encoding, Some("none" | "xudp")) {
            let header = vole::outbound::encode_request_header(
                uuid::Uuid::from_bytes([7; 16]),
                vole::outbound::VlessCommand::Mux,
                None,
            )
            .unwrap();
            let mut received = vec![0; header.len()];
            tokio::time::timeout(Duration::from_millis(100), peer.read_exact(&mut received))
                .await
                .expect("XUDP must submit its Mux header before the first datagram")
                .unwrap();
            assert_eq!(received, header);
        }
        outbound.shutdown().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.receive())
                .await
                .expect("stopped receive remained pending")
                .is_err()
        );
        assert!(client.send(packet()).await.is_err());
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn raw_and_packetaddr_consume_wire_and_keep_cancelled_receive_progress() {
    // None selects the typed internal codec; the YAML value `none` uses XUDP.
    for encoding in [None, Some("packetaddr"), Some("packet")] {
        let (io, mut peer) = tokio::io::duplex(1024);
        let outbound = match encoding {
            Some(encoding) => node(Box::new(io), encoding),
            None => internal_raw_node(Box::new(io)),
        };
        let mut client = outbound
            .open_datagram(
                DatagramRequest::new(session()),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        let datagram = packet();
        client.send(datagram.clone()).await.unwrap();
        let target = if encoding.is_none() {
            datagram.remote.clone()
        } else {
            Destination::domain("sp.packet-addr.v2fly.arpa", 443).unwrap()
        };
        let header = vole::outbound::encode_request_header(
            uuid::Uuid::from_bytes([7; 16]),
            vole::outbound::VlessCommand::Udp,
            Some(&target),
        )
        .unwrap();
        let mut received = vec![0; header.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, header);
        let length = peer.read_u16().await.unwrap() as usize;
        let mut frame = vec![0; length];
        peer.read_exact(&mut frame).await.unwrap();
        let mut expected = bytes::BytesMut::new();
        if encoding.is_some() {
            vole::outbound::address::encode_packet_addr(&datagram.remote, &mut expected).unwrap();
        }
        expected.extend_from_slice(&datagram.payload);
        assert_eq!(frame, expected);
        peer.write_all(&[0, 0, (length >> 8) as u8]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.receive())
                .await
                .is_err()
        );
        peer.write_all(&[length as u8]).await.unwrap();
        peer.write_all(&frame[..2]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.receive())
                .await
                .is_err()
        );
        peer.write_all(&frame[2..]).await.unwrap();
        let response = client.receive().await.unwrap();
        assert_eq!(response.remote, datagram.remote);
        assert_eq!(response.payload, datagram.payload);
        if encoding.is_none() {
            let mut other = datagram.clone();
            other.remote = Destination::Ip("192.0.2.2:53".parse().unwrap());
            assert!(client.send(other).await.is_err());
        }
        client.close().await.unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn none_and_xudp_keep_mux_wire_targets_and_cancelled_receive_progress() {
    for encoding in ["none", "xudp"] {
        let (io, mut peer) = tokio::io::duplex(1024);
        let outbound = node(Box::new(io), encoding);
        let mut client = outbound
            .open_datagram(
                DatagramRequest::new(session()),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        let header = vole::outbound::encode_request_header(
            uuid::Uuid::from_bytes([7; 16]),
            vole::outbound::VlessCommand::Mux,
            None,
        )
        .unwrap();
        let mut received = vec![0; header.len()];
        tokio::time::timeout(Duration::from_millis(100), peer.read_exact(&mut received))
            .await
            .expect("none and xudp must both submit the VLESS Mux header")
            .unwrap();
        assert_eq!(received, header);

        let datagram = packet();
        client.send(datagram.clone()).await.unwrap();
        // Session zero, NEW/DATA/UDP, port-first IPv4; no GlobalID extension.
        let mut first = vec![0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 192, 0, 2, 1, 0, 7];
        first.extend_from_slice(b"payload");
        let mut received = vec![0; first.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, first);

        // Split both the response prefix and an XUDP DATA body across cancellation.
        first[4] = 2; // Server responses carry KEEP.
        peer.write_all(&[0, 0, first[0]]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.receive())
                .await
                .is_err()
        );
        peer.write_all(&first[1..first.len() - 2]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.receive())
                .await
                .is_err()
        );
        peer.write_all(&first[first.len() - 2..]).await.unwrap();
        let response = client.receive().await.unwrap();
        assert_eq!(response.remote, datagram.remote);
        assert_eq!(response.payload, datagram.payload);

        let other = Datagram {
            remote: Destination::domain("dns.example", 5353).unwrap(),
            payload: bytes::Bytes::from_static(b"other"),
            sniffed_domain: None,
        };
        client.send(other.clone()).await.unwrap();
        // KEEP/DATA/UDP carries the new domain and port on the same association.
        let mut second = vec![0, 20, 0, 0, 2, 1, 2, 0x14, 0xe9, 2, 11];
        second.extend_from_slice(b"dns.example");
        second.extend_from_slice(&[0, 5]);
        second.extend_from_slice(b"other");
        let mut received = vec![0; second.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, second);
        peer.write_all(&second).await.unwrap();
        let response = client.receive().await.unwrap();
        assert_eq!(response.remote, other.remote);
        assert_eq!(response.payload, other.payload);
        client.close().await.unwrap();
        let mut end = [0; 6];
        peer.read_exact(&mut end).await.unwrap();
        assert_eq!(end, [0, 4, 0, 0, 3, 0]);
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn udp_send_cancellation_and_bad_header_ownership() {
    for encoding in [
        None,
        Some("none"),
        Some("xudp"),
        Some("packetaddr"),
        Some("packet"),
    ] {
        let (io, mut peer) = tokio::io::duplex(if matches!(encoding, Some("none" | "xudp")) {
            20
        } else {
            1
        });
        let outbound = match encoding {
            Some(encoding) => node(Box::new(io), encoding),
            None => internal_raw_node(Box::new(io)),
        };
        let mut client = outbound
            .open_datagram(
                DatagramRequest::new(session()),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.send(packet()))
                .await
                .is_err()
        );
        if encoding.is_some() {
            let mut prefix = Vec::new();
            assert!(
                tokio::time::timeout(Duration::from_millis(10), peer.read_to_end(&mut prefix),)
                    .await
                    .is_err(),
                "framed cancellation must retain its recoverable IO owner",
            );
            assert!(!prefix.is_empty());
            client.close().await.unwrap();
        }
        tokio::time::timeout(
            Duration::from_millis(100),
            peer.read_to_end(&mut Vec::new()),
        )
        .await
        .expect("closed or failed send retained IO")
        .unwrap();
        assert!(client.send(packet()).await.is_err());
        assert!(client.receive().await.is_err());

        let (io, mut peer) = tokio::io::duplex(1024);
        let outbound = match encoding {
            Some(encoding) => node(Box::new(io), encoding),
            None => internal_raw_node(Box::new(io)),
        };
        let mut client = outbound
            .open_datagram(
                DatagramRequest::new(session()),
                &EstablishContext::default(),
            )
            .await
            .unwrap();
        client.send(packet()).await.unwrap();
        peer.write_all(&[1, 0]).await.unwrap();
        assert!(client.receive().await.is_err());
        assert!(client.send(packet()).await.is_err());
        tokio::time::timeout(
            Duration::from_millis(100),
            peer.read_to_end(&mut Vec::new()),
        )
        .await
        .unwrap()
        .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn tcp_bad_header_fails_closed_and_committed_request_outlives_setup_deadline() {
    for invalid_header in [true, false] {
        let (io, mut peer) = tokio::io::duplex(1024);
        let outbound = node(Box::new(io), "xudp");
        let context = EstablishContext::with_timeout(Duration::from_millis(30));
        let mut connected = outbound
            .connect_stream(
                StreamSession {
                    metadata: Default::default(),
                    inbound: session().inbound,
                    source: session().source,
                    destination: packet().remote,
                    sniffed_domain: None,
                },
                &context,
            )
            .await
            .unwrap();
        connected.io.write_all(b"request").await.unwrap();
        if invalid_header {
            peer.write_all(&[1, 0]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), connected.io.read(&mut [0; 1]))
                    .await
                    .expect("invalid response header remained pending")
                    .is_err()
            );
            assert!(connected.io.write_all(b"after failure").await.is_err());
        } else {
            tokio::time::advance(Duration::from_millis(100)).await;
            {
                let mut pending_byte = [0; 1];
                let pending_read = connected.io.read(&mut pending_byte);
                tokio::pin!(pending_read);
                assert!(futures_util::poll!(pending_read.as_mut()).is_pending());
            }
            peer.write_all(&[0, 0, b'x']).await.unwrap();
            let mut response = [0; 1];
            tokio::time::timeout(
                Duration::from_millis(100),
                connected.io.read_exact(&mut response),
            )
            .await
            .expect("late response remained pending")
            .unwrap();
            assert_eq!(response, [b'x']);
            connected.io.write_all(b"after response").await.unwrap();
            drop(connected);
            outbound.shutdown().await;
        }
        tokio::time::timeout(
            Duration::from_millis(100),
            peer.read_to_end(&mut Vec::new()),
        )
        .await
        .expect("failed response retained IO")
        .unwrap();
    }
}
