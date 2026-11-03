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
            let Ok(tls) = tokio_boring::SslStreamBuilder::new(ssl, peer)
                .accept()
                .await
            else {
                return (false, 0, false);
            };
            let negotiated = tls.ssl().peer_application_settings().is_some();
            let resumed = tls.ssl().session_reused();
            let mut connection = h2::server::Builder::new()
                .max_concurrent_streams(7)
                .initial_window_size(32768)
                .handshake::<_, bytes::Bytes>(tls)
                .await
                .unwrap();
            let Some(Ok((mut request, mut respond))) = connection.accept().await else {
                return (negotiated, 0, resumed);
            };
            let exchange = async {
                let data = request.body_mut().data().await.unwrap().unwrap();
                assert_eq!(data.as_ref(), b"ping");
                request
                    .body_mut()
                    .flow_control()
                    .release_capacity(data.len())
                    .unwrap();
                let mut response = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                response
                    .send_data(bytes::Bytes::from_static(b"pong"), true)
                    .unwrap();
                data.len()
            };
            let count = tokio::select! {
                count = exchange => count,
                _ = std::future::poll_fn(|cx| connection.poll_closed(cx)) => 0,
            };
            connection.graceful_shutdown();
            let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
            (negotiated, count, resumed)
        };
        let consumer = async {
            let tls = client.connect(Box::new(io)).await?;
            let (mut sender, connection) = h2::client::handshake(tls).await.map_err(io_other)?;
            let exchange = async {
                let (response, mut body) = sender
                    .send_request(
                        http::Request::builder()
                            .uri("https://fixture.invalid/")
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .map_err(io_other)?;
                body.send_data(bytes::Bytes::from_static(b"ping"), true)
                    .map_err(io_other)?;
                let mut response = response.await.map_err(io_other)?;
                let data = response
                    .body_mut()
                    .data()
                    .await
                    .ok_or_else(|| io::Error::other("missing H2 response"))?
                    .map_err(io_other)?;
                assert_eq!(data.as_ref(), b"pong");
                response
                    .body_mut()
                    .flow_control()
                    .release_capacity(data.len())
                    .map_err(io_other)?;
                Ok::<(), io::Error>(())
            };
            let (business, driver) = tokio::join!(exchange, connection);
            business?;
            driver.map_err(io_other)
        };
        let (result, (negotiated, bytes, resumed)) = tokio::join!(consumer, server);
        (result, negotiated, bytes, resumed)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn selected_profiles_use_standard_h2_settings_when_the_server_supports_alps() {
    use crate::config::ClientFingerprint;
    let chain = chain(false);
    for profile in [
        ClientFingerprint::Chrome133,
        ClientFingerprint::Firefox120,
        ClientFingerprint::Safari16,
        ClientFingerprint::Ios14,
        ClientFingerprint::Edge85,
        ClientFingerprint::Qq111,
    ] {
        for new_codepoint in [false, true] {
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
                let (result, negotiated, bytes, _) =
                    alps_exchange(&client, &peer, new_codepoint, settings).await;
                result.unwrap();
                assert!(!negotiated, "the H2 consumer did not declare TLS ALPS");
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
