use vole::{dispatch::DatagramBudget, packet::IpVersion};

#[cfg(feature = "outbound-shadowsocks")]
#[tokio::test]
async fn shadowsocks_budget_accounts_for_cipher_headers_and_identity_chain() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use bytes::Bytes;
    use vole::{
        config::{ShadowsocksCipher, ShadowsocksOutboundConfig},
        dialer::{Dialer, ResolvedEndpoint},
        outbound::{
            DatagramRequest, EstablishContext, OutboundConnector, ShadowsocksOutbound, UpstreamPath,
        },
        session::{Datagram, DatagramSession, Destination, InboundKind},
    };
    for (cipher, chain, tx, rx, wire_bytes) in [
        (ShadowsocksCipher::Aes128Gcm, false, 65457, 65449, 67),
        (ShadowsocksCipher::Aes256Gcm, false, 65457, 65449, 67),
        (ShadowsocksCipher::Chacha20Poly1305, false, 65433, 65425, 91),
        (ShadowsocksCipher::Aes128Gcm, true, 65441, 65449, 83),
    ] {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut password = STANDARD.encode(vec![7; cipher.key_len()]);
        if chain {
            password = format!("{}:{password}", STANDARD.encode(vec![8; cipher.key_len()]));
        }
        let outbound = ShadowsocksOutbound::new_with_path(
            &ShadowsocksOutboundConfig {
                address: "127.0.0.1".into(),
                port: address.port(),
                cipher,
                password,
                plugin: None,
                udp_over_tcp: false,
            },
            UpstreamPath::direct(
                ResolvedEndpoint {
                    logical_host: "127.0.0.1".into(),
                    port: address.port(),
                    addresses: vec![address],
                },
                Dialer::default(),
            ),
        )
        .unwrap();
        let request = DatagramRequest::new(DatagramSession::new(
            InboundKind::InternalMeasure,
            "127.0.0.1:0".parse().unwrap(),
        ));
        let mut io = outbound
            .open_datagram(request, &EstablishContext::default())
            .await
            .unwrap();
        let destination = Destination::Ip("1.2.3.4:53".parse().unwrap());
        assert_eq!(io.payload_budget(&destination), DatagramBudget::new(tx, rx));
        io.send(Datagram {
            remote: destination,
            payload: Bytes::from_static(b"12345678901234567"),
            sniffed_domain: None,
        })
        .await
        .unwrap();
        let mut packet = [0; 128];
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                server.recv_from(&mut packet)
            )
            .await
            .unwrap()
            .unwrap()
            .0,
            wire_bytes
        );
        io.close().await.unwrap();
    }
}

#[cfg(feature = "outbound-socks5")]
#[tokio::test]
async fn socks5_budget_retains_distinct_payload_and_envelope_limits() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vole::{
        config::Socks5OutboundConfig,
        dialer::{Dialer, ResolvedEndpoint},
        outbound::{DatagramRequest, EstablishContext, OutboundConnector, Socks5Outbound},
        session::{Datagram, DatagramSession, Destination, InboundKind},
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = server.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = udp.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut control, _) = server.accept().await.unwrap();
            let mut greeting = [0; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            control.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 3, 0, 1]);
            let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
            response.extend_from_slice(&relay.port().to_be_bytes());
            control.write_all(&response).await.unwrap();
            let mut packet = [0; 64];
            let (length, source) = udp.recv_from(&mut packet).await.unwrap();
            assert_eq!(
                &packet[..length],
                &[0, 0, 0, 1, 1, 2, 3, 4, 0, 53, b'a', b'b', b'c']
            );
            udp.send_to(&packet[..length], source).await.unwrap();
            assert_eq!(control.read(&mut [0]).await.unwrap(), 0);
        });
        let outbound = Socks5Outbound::new(
            &Socks5OutboundConfig {
                tls: None,
                address: "127.0.0.1".into(),
                port: endpoint.port(),
                username: None,
                password: None,
            },
            ResolvedEndpoint {
                logical_host: "127.0.0.1".into(),
                port: endpoint.port(),
                addresses: vec![endpoint],
            },
            Dialer::default(),
        )
        .unwrap();
        let request = DatagramRequest::new(DatagramSession::new(
            InboundKind::Socks5,
            "127.0.0.1:0".parse().unwrap(),
        ))
        .with_budget(DatagramBudget::new(3, 3));
        let mut io = outbound
            .open_datagram(request, &EstablishContext::default())
            .await
            .unwrap();
        let destination = Destination::Ip("1.2.3.4:53".parse().unwrap());
        assert_eq!(io.payload_budget(&destination), DatagramBudget::new(3, 3));
        assert!(
            io.send(Datagram {
                remote: destination.clone(),
                payload: Bytes::from_static(b"abcd"),
                sniffed_domain: None
            })
            .await
            .is_err()
        );
        io.send(Datagram {
            remote: destination,
            payload: Bytes::from_static(b"abc"),
            sniffed_domain: None,
        })
        .await
        .unwrap();
        assert_eq!(io.receive().await.unwrap().payload, "abc");
        io.close().await.unwrap();
        drop(io);
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn direct_budget_rejects_large_sends_and_drops_oversize_responses() {
    use bytes::Bytes;
    use vole::{
        dialer::Dialer,
        outbound::{DatagramRequest, DirectOutbound, EstablishContext, OutboundConnector},
        session::{Datagram, DatagramSession, Destination, InboundKind},
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = Destination::Ip(server.local_addr().unwrap());
        let request = DatagramRequest::new(DatagramSession::new(
            InboundKind::Socks5,
            "127.0.0.1:0".parse().unwrap(),
        ))
        .with_budget(DatagramBudget::new(3, 2));
        let mut io = DirectOutbound::new(Dialer::default())
            .open_datagram(request, &EstablishContext::default())
            .await
            .unwrap();
        assert_eq!(io.payload_budget(&peer), DatagramBudget::new(3, 2));
        let packet = |payload: &'static [u8]| Datagram {
            remote: peer.clone(),
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        };
        assert!(io.send(packet(b"1234")).await.is_err());
        io.send(packet(b"123")).await.unwrap();
        let mut bytes = [0; 16];
        let (length, source) = server.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], b"123");
        server.send_to(b"bad", source).await.unwrap();
        server.send_to(b"ok", source).await.unwrap();
        assert_eq!(io.receive().await.unwrap().payload, "ok");
        io.close().await.unwrap();
        io.close().await.unwrap();
        assert!(io.send(packet(b"1")).await.is_err());
    })
    .await
    .unwrap();
}

#[test]
fn layered_directional_budgets_account_for_ip_headers_and_exact_minima() {
    let ipv4 = DatagramBudget::from_path_mtu(1500, IpVersion::V4).unwrap();
    let ipv6 = DatagramBudget::from_path_mtu(1500, IpVersion::V6).unwrap();
    assert_eq!((ipv4.transmit(), ipv4.receive()), (1472, 1472));
    assert_eq!((ipv6.transmit(), ipv6.receive()), (1452, 1452));
    assert!(DatagramBudget::from_path_mtu(47, IpVersion::V6).is_err());
    let layered = ipv6
        .intersect(DatagramBudget::new(1420, 1400))
        .subtract_overhead(20, 200);
    assert_eq!((layered.transmit(), layered.receive()), (1400, 1200));
    assert_eq!(layered.quic_payload_limit().unwrap(), 1200);
    assert!(
        layered
            .subtract_overhead(0, 1)
            .quic_payload_limit()
            .is_err()
    );
    assert!(
        DatagramBudget::new(1199, 1400)
            .quic_payload_limit()
            .is_err()
    );
    assert_eq!(
        DatagramBudget::new(12, 10)
            .subtract_overhead(13, usize::MAX)
            .receive(),
        0
    );
}
