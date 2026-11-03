//! Independent rustls memory peers for warm-wire/expiry and version rejection.
use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct FirstFlight {
    io: tokio::io::DuplexStream,
    bytes: Arc<Mutex<Vec<u8>>>,
    reading: bool,
}
impl AsyncRead for FirstFlight {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reading = true;
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for FirstFlight {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, buf);
        if !self.reading
            && let Poll::Ready(Ok(count)) = &result
        {
            let mut bytes = self.bytes.lock().unwrap();
            assert!(bytes.len() + count <= 65536);
            bytes.extend_from_slice(&buf[..*count]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn observed_handshake(
    client: &StandardTlsClient,
    server: Arc<ServerConfig>,
) -> (bool, Vec<u8>) {
    let (io, peer) = tokio::io::duplex(65536);
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let tap = FirstFlight {
        io,
        bytes: bytes.clone(),
        reading: false,
    };
    let (resumed, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            async {
                let mut stream = tokio_rustls::TlsAcceptor::from(server)
                    .accept(peer)
                    .await
                    .unwrap();
                let resumed =
                    stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
                stream.write_all(&[42]).await.unwrap();
                stream.shutdown().await.unwrap();
                resumed
            },
            async {
                let mut stream = client.connect(Box::new(tap)).await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, [42]);
            }
        )
    })
    .await
    .unwrap();
    let bytes = Arc::try_unwrap(bytes).unwrap().into_inner().unwrap();
    (resumed, bytes)
}

#[derive(Debug)]
struct ShortTickets {
    inner: Arc<dyn rustls::server::ProducesTickets>,
}
impl rustls::server::ProducesTickets for ShortTickets {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        2
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.inner.encrypt(plain)
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.inner.decrypt(cipher)
    }
}

#[tokio::test]
async fn selected_profiles_warm_wire_and_expired_tickets_use_real_handshakes() {
    let mut clients = Vec::new();
    for (name, profile) in [
        ("chrome", crate::config::ClientFingerprint::Chrome133),
        ("firefox", crate::config::ClientFingerprint::Firefox120),
        ("safari", crate::config::ClientFingerprint::Safari16),
        ("ios", crate::config::ClientFingerprint::Ios14),
    ] {
        for version in [&TLS12, &TLS13] {
            let chain = chain(false);
            let mut peer = server(&chain, version, false);
            // Only the advertised lifetime is short. The real ticket key stays
            // valid so full renegotiation proves the client's own expiry rule.
            Arc::get_mut(&mut peer).unwrap().ticketer = Arc::new(ShortTickets {
                inner: rustls::crypto::ring::Ticketer::new().unwrap(),
            });
            let client = StandardTlsClient::with_options(
                &trusted(&chain),
                "fixture.invalid",
                TlsClientOptions {
                    client_fingerprint: Some(profile),
                    alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                    ..Default::default()
                },
                4,
                65536,
            )
            .unwrap();
            for (phase, expected) in [("cold", false), ("warm", true)] {
                let (resumed, _) = observed_handshake(&client, peer.clone()).await;
                assert_eq!(resumed, expected, "{name}/{version:?}/{phase}");
            }
            clients.push((name, version, client, peer));
        }
    }
    // Native ticket timestamps use real UNIX time, not Tokio's paused clock.
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (name, version, client, peer) in clients {
        let (resumed, _) = observed_handshake(&client, peer).await;
        // Safari16/iOS14 do not offer the TLS1.2 session-ticket extension.
        // Their stateful session IDs have no ticket-lifetime hint to expire.
        let stateful_id =
            matches!(name, "safari" | "ios") && version.version == rustls::ProtocolVersion::TLSv1_2;
        assert_eq!(
            resumed, stateful_id,
            "{name}/{version:?}: ticket hint expiry"
        );
    }
}

#[cfg(feature = "outbound-vless")]
#[tokio::test]
async fn named_reality_retains_browser_offer_but_rejects_tls12_server_hello() {
    for &profile in crate::security::test_profiles() {
        let chain = chain(false);
        let peer = server(&chain, &TLS12, false);
        let ordinary = client(
            &trusted(&chain),
            "fixture.invalid",
            TlsClientPolicy {
                client_fingerprint: profile,
                ..Default::default()
            },
        );
        assert!(handshake(&ordinary, peer.clone()).await.0);
        let reality = crate::security::SecurityClient::from_security(
            &crate::config::SecurityConfig::Reality(crate::config::RealityConfig {
                support_x25519mlkem768: false,
                client_fingerprint: profile,
                server_name: "fixture.invalid".into(),
                public_key: [7; 32],
                short_id: vec![],
                alpn: vec![],
            }),
        )
        .unwrap();
        let (io, peer_io) = tokio::io::duplex(65536);
        let (result, peer_result) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                reality.connect(Box::new(io)),
                tokio_rustls::TlsAcceptor::from(peer).accept(peer_io)
            )
        })
        .await
        .unwrap();
        assert!(result.is_err());
        let error = peer_result.unwrap_err();
        assert!(
            profile.is_none()
                || matches!(
                    error
                        .get_ref()
                        .and_then(|e| e.downcast_ref::<rustls::Error>()),
                    Some(rustls::Error::AlertReceived(
                        rustls::AlertDescription::ProtocolVersion
                    ))
                ),
            "{error:?}"
        );
    }
}
