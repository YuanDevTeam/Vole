//! Additional shared-adapter policy checks over memory IO, never host servers.
use super::*;
use boring::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use foreign_types::ForeignTypeRef;

fn native_peer(chain: &Chain) -> SslAcceptor {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder
        .set_certificate(&X509::from_der(&chain.certificates[0]).unwrap())
        .unwrap();
    for certificate in &chain.certificates[1..] {
        builder
            .add_extra_chain_cert(X509::from_der(certificate).unwrap())
            .unwrap();
    }
    builder
        .set_private_key(&PKey::private_key_from_der(chain.key.secret_der()).unwrap())
        .unwrap();
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(b"\x02h2", offered).ok_or(AlpnError::ALERT_FATAL)
    });
    builder.build()
}

async fn alps_exchange(
    client: &StandardTlsClient,
    acceptor: &SslAcceptor,
    new_codepoint: bool,
    settings: Option<&[u8]>,
) -> (io::Result<()>, bool, usize, bool) {
    let ssl = Ssl::new(acceptor.context()).unwrap();
    if let Some(settings) = settings {
        // SAFETY: SSL is live and exclusively owned. The native setters copy
        // the bounded application protocol/settings slices before returning.
        unsafe {
            boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), i32::from(new_codepoint));
            assert_eq!(
                boring_sys::SSL_add_application_settings(
                    ssl.as_ptr(),
                    b"h2".as_ptr(),
                    2,
                    settings.as_ptr(),
                    settings.len()
                ),
                1
            );
        }
    }
    let (io, peer) = tokio::io::duplex(16384);
    tokio::time::timeout(Duration::from_secs(3), async {
        let server = async {
            let Ok(mut tls) = tokio_boring::SslStreamBuilder::new(ssl, peer)
                .accept()
                .await
            else {
                return (false, 0, false);
            };
            let negotiated = tls.ssl().peer_application_settings().is_some();
            let resumed = tls.ssl().session_reused();
            let mut request = [0; 4];
            let count = tls.read(&mut request).await.unwrap_or(0);
            if count != 0 {
                assert_eq!(&request[..count], &b"ping"[..count]);
                tls.write_all(b"pong").await.unwrap();
            }
            (negotiated, count, resumed)
        };
        let consumer = async {
            let mut tls = client.connect(Box::new(io)).await?;
            tls.write_all(b"ping").await?;
            let mut response = [0; 4];
            tls.read_exact(&mut response).await?;
            assert_eq!(&response, b"pong");
            Ok(())
        };
        let (result, (negotiated, bytes, resumed)) = tokio::join!(consumer, server);
        (result, negotiated, bytes, resumed)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn selected_profiles_enforce_alps_before_business_and_ticket_publication() {
    use crate::config::ClientFingerprint;
    let chain = chain(false);
    for profile in crate::security::test_profiles().iter().copied().flatten() {
        let chrome = profile == ClientFingerprint::Chrome133;
        let new_codepoint = chrome;
        for settings in [
            None,
            Some(b"".as_slice()),
            Some(b"\0\x03\0\0\0\x64".as_slice()),
        ] {
            let peer = native_peer(&chain);
            let client = StandardTlsClient::with_options(
                &trusted(&chain),
                "fixture.invalid",
                TlsClientOptions {
                    client_fingerprint: Some(profile),
                    alpn: vec![b"h2".to_vec()],
                    required_alpn: Some(b"h2".to_vec()),
                    ..Default::default()
                },
                4,
                65536,
            )
            .unwrap();
            let rejected = chrome && settings.is_some_and(|bytes| !bytes.is_empty());
            let (result, negotiated, bytes, _) =
                alps_exchange(&client, &peer, new_codepoint, settings).await;
            assert_eq!(negotiated, chrome && settings.is_some());
            if rejected {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
                assert_eq!(bytes, 0, "nonempty ALPS cannot admit application data");
                let (result, _, bytes, resumed) =
                    alps_exchange(&client, &peer, new_codepoint, Some(b"")).await;
                result.unwrap();
                assert_eq!(bytes, 4);
                assert!(!resumed, "rejected ALPS cannot publish tickets");
            } else {
                result.unwrap();
                assert_eq!(bytes, 4);
            }
        }
    }
}

#[tokio::test]
async fn selected_profiles_consume_tickets_once_under_concurrent_handshakes() {
    for profile in crate::security::test_profiles().iter().copied().flatten() {
        for capacity in [0, 1, 4] {
            let chain = chain(false);
            let mut peer = server(&chain, &TLS13, false);
            Arc::get_mut(&mut peer).unwrap().send_tls13_tickets = 8;
            let client = StandardTlsClient::with_options(
                &trusted(&chain),
                "fixture.invalid",
                TlsClientOptions {
                    client_fingerprint: Some(profile),
                    ..Default::default()
                },
                capacity,
                65536,
            )
            .unwrap();
            assert!(handshake(&client, peer.clone()).await.0);
            let mut quiet_peer = peer.as_ref().clone();
            quiet_peer.send_tls13_tickets = 0;
            let quiet_peer = Arc::new(quiet_peer);
            let results = futures_util::future::join_all(
                (0..8).map(|_| handshake(&client, quiet_peer.clone())),
            )
            .await;
            assert!(results.iter().all(|(ok, _)| *ok));
            assert_eq!(
                results.iter().filter(|(_, seen)| seen.resumed).count(),
                capacity
            );
            let (ok, seen) = handshake(&client, quiet_peer).await;
            assert!(ok);
            assert!(!seen.resumed, "concurrent consumers cannot replay a ticket");
        }
    }
}

#[tokio::test]
async fn selected_profiles_fall_back_to_authenticated_full_handshake_on_ticket_refusal() {
    for profile in crate::security::test_profiles().iter().copied().flatten() {
        for version in [&TLS12, &TLS13] {
            let chain = chain(false);
            let peer = server(&chain, version, false);
            let client = StandardTlsClient::with_options(
                &trusted(&chain),
                "fixture.invalid",
                TlsClientOptions {
                    client_fingerprint: Some(profile),
                    ..Default::default()
                },
                4,
                65536,
            )
            .unwrap();
            assert!(handshake(&client, peer.clone()).await.0);
            let (ok, seen) = handshake(&client, peer).await;
            assert!(ok && seen.resumed);
            let (ok, seen) = handshake(&client, server(&chain, version, false)).await;
            assert!(ok);
            assert!(
                !seen.resumed,
                "a new server session identity refuses the old ticket"
            );
            let unrelated = super::chain(false);
            assert!(
                !handshake(&client, server(&unrelated, version, false))
                    .await
                    .0,
                "ticket refusal cannot bypass renewed certificate authentication"
            );
        }
    }
}
