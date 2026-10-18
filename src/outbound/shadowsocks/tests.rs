use super::*;
use crate::{
    config::ShadowsocksCipher,
    dialer::{Dialer, ResolvedEndpoint},
    session::InboundKind,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use shadowsocks::relay::tcprelay::proxy_stream::ProxyServerStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(cipher: ShadowsocksCipher) -> ShadowsocksOutboundConfig {
    ShadowsocksOutboundConfig {
        address: "127.0.0.1".into(),
        port: 12345,
        cipher,
        password: STANDARD.encode(vec![7; cipher.key_len()]),
        plugin: None,
        udp_over_tcp: false,
    }
}

#[tokio::test]
async fn official_tcp_codecs_all_ciphers_first_payload_read_first_and_backpressure() {
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for start in ["payload", "read", "empty-write"] {
            let config = config(cipher);
            let method = cipher.as_str().parse().unwrap();
            let key = vec![7; cipher.key_len()];
            let server_config =
                ServerConfig::new(("127.0.0.1", 12345), config.password, method).unwrap();
            let target = Destination::domain("fixture.invalid", 443).unwrap();
            let (client, server) = tokio::io::duplex(4096);
            let mut client = stream::SsStream::new(
                Context::new_shared(ServerType::Local),
                Box::new(client) as BoxStream,
                &server_config,
                address(&target),
            );
            let mut server = ProxyServerStream::from_stream(
                Context::new_shared(ServerType::Server),
                server,
                method,
                &key,
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    async {
                        if start == "empty-write" {
                            assert_eq!(client.write(&[]).await.unwrap(), 0);
                        }
                        if start != "payload" {
                            let mut hello = [0; 5];
                            client.read_exact(&mut hello).await.unwrap();
                            assert_eq!(&hello, b"hello");
                        }
                        tokio::task::yield_now().await;
                        let payload = vec![0x5a; 128 * 1024];
                        client.write_all(&payload).await.unwrap();
                        client.shutdown().await.unwrap();
                        let mut result = Vec::new();
                        client.read_to_end(&mut result).await.unwrap();
                        assert_eq!(result, b"response");
                    },
                    async {
                        assert_eq!(server.handshake().await.unwrap(), address(&target));
                        if start != "payload" {
                            server.write_all(b"hello").await.unwrap();
                        }
                        let mut payload = Vec::new();
                        server.read_to_end(&mut payload).await.unwrap();
                        assert_eq!(payload, vec![0x5a; 128 * 1024]);
                        server.write_all(b"response").await.unwrap();
                        server.shutdown().await.unwrap();
                    }
                );
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn official_tcp_codecs_all_ciphers_empty_half_close_keeps_response() {
    use std::{future::poll_fn, pin::Pin, task::Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for start in ["fresh", "pending-read", "pending-shutdown"] {
            let config = config(cipher);
            let method = cipher.as_str().parse().unwrap();
            let server_config =
                ServerConfig::new(("127.0.0.1", 12345), config.password, method).unwrap();
            let target = Destination::domain("fixture.invalid", 443).unwrap();
            let (mut socket, mut peer) = tokio::io::duplex(4096);
            // Leave exactly one byte available so the first handshake makes
            // partial progress, then deterministically encounters backpressure.
            let mut prefill = [0x5a; 4095];
            if start != "fresh" {
                socket.write_all(&prefill).await.unwrap();
            }
            let mut client = stream::SsStream::new(
                Context::new_shared(ServerType::Local),
                Box::new(socket) as BoxStream,
                &server_config,
                address(&target),
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                if start != "fresh" {
                    // Cancel after one poll, then let shutdown resume the same
                    // empty first write once transport capacity is available.
                    let pending = poll_fn(|cx| {
                        Poll::Ready(if start == "pending-read" {
                            Pin::new(&mut client).poll_read(cx, &mut ReadBuf::new(&mut [0]))
                        } else {
                            Pin::new(&mut client).poll_shutdown(cx)
                        })
                    })
                    .await;
                    assert!(pending.is_pending(), "{cipher:?}: {start}");
                    // Remove only fixture bytes; the partially written encrypted
                    // handshake remains queued for the official server codec.
                    peer.read_exact(&mut prefill).await.unwrap();
                    assert_eq!(prefill, [0x5a; 4095]);
                }
                client.shutdown().await.unwrap();
                let mut server = ProxyServerStream::from_stream(
                    Context::new_shared(ServerType::Server),
                    peer,
                    method,
                    &vec![7; cipher.key_len()],
                );
                tokio::join!(
                    async {
                        let mut response = Vec::new();
                        client.read_to_end(&mut response).await.unwrap();
                        assert_eq!(response, b"hello");
                    },
                    async {
                        assert_eq!(server.handshake().await.unwrap(), address(&target));
                        let mut payload = Vec::new();
                        server.read_to_end(&mut payload).await.unwrap();
                        assert!(payload.is_empty());
                        server.write_all(b"hello").await.unwrap();
                        server.shutdown().await.unwrap();
                    }
                );
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn ss_physical_tcp_uses_shared_dialer_and_logical_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = listener.local_addr().unwrap();
    let mut config = config(ShadowsocksCipher::Aes128Gcm);
    config.port = remote.port();
    let outbound = ShadowsocksOutbound::new_with_path(
        &config,
        UpstreamPath::direct(
            ResolvedEndpoint {
                logical_host: config.address.clone(),
                port: config.port,
                addresses: vec![remote],
            },
            Dialer::default(),
        ),
    )
    .unwrap();
    let target = Destination::domain("fixture.invalid", 443).unwrap();
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::Http,
        source: "127.0.0.1:10000".parse().unwrap(),
        destination: target.clone(),
        sniffed_domain: None,
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            async {
                let mut connected = OutboundConnector::connect_stream(
                    &outbound,
                    session,
                    &EstablishContext::default(),
                )
                .await
                .unwrap();
                assert_eq!(connected.effective_peer, target);
                connected.io.write_all(b"payload").await.unwrap();
                let mut result = [0; 7];
                connected.io.read_exact(&mut result).await.unwrap();
                assert_eq!(&result, b"payload");
            },
            async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = ProxyServerStream::from_stream(
                    Context::new_shared(ServerType::Server),
                    stream,
                    config.cipher.as_str().parse().unwrap(),
                    &[7; 16],
                );
                assert_eq!(stream.handshake().await.unwrap(), address(&target));
                let mut payload = [0; 7];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            }
        );
    })
    .await
    .unwrap();
    assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
    assert!(!format!("{outbound:?}").contains(&config.password));
}

#[test]
fn official_eih_config_keeps_multiple_identities_in_declared_order() {
    for cipher in [ShadowsocksCipher::Aes128Gcm, ShadowsocksCipher::Aes256Gcm] {
        let mut cfg = config(cipher);
        cfg.password = [1, 2, 3]
            .map(|value| STANDARD.encode(vec![value; cipher.key_len()]))
            .join(":");
        let server = ServerConfig::new(
            ("127.0.0.1", 12345),
            cfg.password.clone(),
            cipher.as_str().parse().unwrap(),
        )
        .unwrap();
        assert_eq!(server.identity_keys().len(), 2);
        assert_eq!(
            server.identity_keys()[0].as_ref(),
            vec![1; cipher.key_len()]
        );
        assert_eq!(
            server.identity_keys()[1].as_ref(),
            vec![2; cipher.key_len()]
        );
        assert_eq!(server.key(), vec![3; cipher.key_len()]);
    }
}

#[tokio::test]
async fn tcp_response_header_time_salt_auth_and_fragmentation_follow_official_codec() {
    use shadowsocks::crypto::v2::tcp::TcpCipher;
    use std::time::{SystemTime, UNIX_EPOCH};
    for method in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for case in [
            "valid-split-body",
            "stale",
            "future",
            "wrong-type",
            "wrong-request-salt",
            "wrong-request-salt-empty-response",
            "wrong-request-salt-header-only",
            "corrupt",
            "short-fixed-header",
        ] {
            let key = vec![7; method.key_len()];
            let cipher = method.as_str().parse().unwrap();
            let server =
                ServerConfig::new(("127.0.0.1", 12345), STANDARD.encode(&key), cipher).unwrap();
            let (client, mut peer) = tokio::io::duplex(4096);
            let mut client = stream::SsStream::new(
                Context::new_shared(ServerType::Local),
                Box::new(client) as BoxStream,
                &server,
                ("private-target.invalid".to_owned(), 80).into(),
            );
            client.write_all(b"private-payload").await.unwrap();
            let mut request_salt = vec![0; method.key_len()];
            peer.read_exact(&mut request_salt).await.unwrap();
            if case.starts_with("wrong-request-salt") {
                request_salt[0] ^= 1;
            }
            let response_salt = vec![9; method.key_len()];
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let timestamp = match case {
                "stale" => now - 120,
                "future" => now + 120,
                _ => now,
            };
            let mut header = vec![if case == "wrong-type" { 0 } else { 1 }];
            header.extend_from_slice(&timestamp.to_be_bytes());
            header.extend_from_slice(&request_salt);
            let body_length = u16::from(case != "wrong-request-salt-empty-response");
            header.extend_from_slice(&body_length.to_be_bytes());
            header.extend_from_slice(&[0; 16]);
            let mut codec = TcpCipher::new(cipher, &key, &response_salt);
            codec.encrypt_packet(&mut header);
            if case == "corrupt" {
                *header.last_mut().unwrap() ^= 1;
            }
            let mut wire = response_salt;
            wire.extend_from_slice(&header);
            if case == "short-fixed-header" {
                wire.truncate(wire.len() - 1);
            }
            peer.write_all(&wire).await.unwrap();
            let mut body = vec![0x5a; usize::from(body_length)];
            body.extend_from_slice(&[0; 16]);
            codec.encrypt_packet(&mut body);
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                if case == "valid-split-body" {
                    tokio::join!(
                        async {
                            let mut value = [0];
                            client.read_exact(&mut value).await.unwrap();
                            assert_eq!(value, [0x5a]);
                        },
                        async {
                            for byte in body {
                                peer.write_all(&[byte]).await.unwrap();
                                tokio::task::yield_now().await;
                            }
                        }
                    );
                } else if case == "wrong-request-salt-header-only" {
                    let error = client.read(&mut [0; 1]).await.unwrap_err();
                    assert_eq!(error.to_string(), "Shadowsocks stream operation failed");
                } else {
                    if case == "wrong-request-salt-empty-response" {
                        peer.write_all(&body).await.unwrap();
                    }
                    peer.shutdown().await.unwrap();
                    let error = client.read(&mut [0; 1]).await.unwrap_err();
                    assert_eq!(error.to_string(), "Shadowsocks stream operation failed");
                }
            })
            .await
            .unwrap();
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn physical_tcp_udp_protection_is_shared_and_fails_closed() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Protector {
        count: AtomicUsize,
        reject: bool,
    }
    impl crate::dialer::SocketProtector for Protector {
        fn protect(&self, _: i32) -> io::Result<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if self.reject {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture protect denied",
                ))
            } else {
                Ok(())
            }
        }
    }
    for reject in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::bind(endpoint).await.unwrap();
        let protector = Arc::new(Protector {
            count: AtomicUsize::new(0),
            reject,
        });
        let mut cfg = config(ShadowsocksCipher::Aes128Gcm);
        cfg.port = endpoint.port();
        let outbound = ShadowsocksOutbound::new_with_path(
            &cfg,
            UpstreamPath::direct(
                ResolvedEndpoint {
                    logical_host: cfg.address.clone(),
                    port: cfg.port,
                    addresses: vec![endpoint],
                },
                Dialer::default().with_protector(protector.clone()),
            ),
        )
        .unwrap();
        let session = StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Socks5,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::domain("private-target.invalid", 443).unwrap(),
            sniffed_domain: None,
        };
        let result =
            OutboundConnector::connect_stream(&outbound, session, &EstablishContext::default())
                .await;
        assert_eq!(result.is_err(), reject);
        assert_eq!(protector.count.load(Ordering::SeqCst), 1);
        if reject {
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(5), listener.accept())
                    .await
                    .is_err()
            );
        } else {
            drop(listener.accept().await.unwrap());
        }
        drop(result);
        let session = DatagramSession::new(InboundKind::Socks5, "127.0.0.1:10000".parse().unwrap());
        let mut udp = OutboundConnector::open_datagram(
            &outbound,
            DatagramRequest::new(session),
            &EstablishContext::default(),
        )
        .await
        .unwrap();
        let result = udp
            .send(crate::session::Datagram {
                remote: Destination::domain("private-target.invalid", 53).unwrap(),
                payload: bytes::Bytes::from_static(b"private-payload"),
                sniffed_domain: None,
            })
            .await;
        assert_eq!(result.is_err(), reject);
        assert_eq!(protector.count.load(Ordering::SeqCst), 2);
        if reject {
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(5),
                    socket.recv_from(&mut [0; 1024])
                )
                .await
                .is_err()
            );
        } else {
            socket.recv_from(&mut [0; 1024]).await.unwrap();
        }
        udp.close().await.unwrap();
        drop(udp);
        drop(outbound);
        assert_eq!(Arc::strong_count(&protector), 1);
        assert_eq!(protector.count.load(Ordering::SeqCst), 2);
    }
}
