use super::*;

#[path = "identity_rotation_tests.rs"]
mod identity_rotation_memory_tests;
use crate::config::TlsClientPolicy;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::{
    RootCertStore, ServerConfig, SignatureAlgorithm, SignatureScheme,
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
};
use sha2::{Digest, Sha256};
use std::{sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::LazyConfigAcceptor;

#[cfg(feature = "tls-fingerprint")]
#[path = "tls_named_tests.rs"]
mod named;

#[cfg(feature = "tls-fingerprint")]
#[path = "tls_named_wire_tests.rs"]
mod named_wire;

#[cfg(feature = "quiche-h3-transport")]
#[path = "tls_quiche_tests.rs"]
mod quiche;

#[cfg(feature = "outbound-trusttunnel")]
#[path = "trusttunnel_alpn_tests.rs"]
mod trusttunnel_alpn_memory;

struct Chain {
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Chain {
    fn identity_pem(&self) -> crate::config::TlsIdentityPem {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        crate::config::TlsIdentityPem {
            certificate: self
                .certificates
                .iter()
                .map(|cert| {
                    format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                        STANDARD.encode(cert.as_ref())
                    )
                })
                .collect(),
            private_key: format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                STANDARD.encode(self.key.secret_der())
            ),
            origin: None,
        }
    }
}

fn ca(name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params
}

fn chain(expired: bool) -> Chain {
    chain_with_usage(expired, ExtendedKeyUsagePurpose::ServerAuth)
}

fn chain_with_usage(expired: bool, usage: ExtendedKeyUsagePurpose) -> Chain {
    let root =
        CertifiedIssuer::self_signed(ca("fixture root"), KeyPair::generate().unwrap()).unwrap();
    let intermediate = CertifiedIssuer::signed_by(
        ca("fixture intermediate"),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["fixture.invalid".into()]).unwrap();
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(if expired { 2021 } else { 2090 }, 1, 1);
    params.extended_key_usages = vec![usage];
    let leaf = params.signed_by(&key, &intermediate).unwrap();
    Chain {
        certificates: vec![
            leaf.der().clone(),
            intermediate.der().clone(),
            root.der().clone(),
        ],
        key: PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    }
}

fn pin(chain: &Chain, index: usize) -> [u8; 32] {
    Sha256::digest(chain.certificates[index].as_ref()).into()
}

fn trusted(chain: &Chain) -> SecurityContext {
    let mut roots = RootCertStore::empty();
    roots.add(chain.certificates[2].clone()).unwrap();
    SecurityContext {
        provider: Arc::new(rustls::crypto::ring::default_provider()),
        tls_roots: Arc::new(roots),
        identities: Arc::default(),
    }
}

fn client(context: &SecurityContext, name: &str, policy: TlsClientPolicy) -> StandardTlsClient {
    StandardTlsClient::with_options(
        context,
        name,
        TlsClientOptions::from_policy(&policy, None, context).unwrap(),
        4,
        DEFAULT_TLS_BUFFER_LIMIT,
    )
    .unwrap()
}

#[derive(Debug)]
struct BrokenKey(Arc<dyn SigningKey>);
#[derive(Debug)]
struct BrokenSigner(Box<dyn Signer>);
impl SigningKey for BrokenKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|signer| Box::new(BrokenSigner(signer)) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}
impl Signer for BrokenSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.0.sign(message)?;
        *signature.last_mut().unwrap() ^= 1;
        Ok(signature)
    }
    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

fn server(
    chain: &Chain,
    version: &'static rustls::SupportedProtocolVersion,
    broken_signature: bool,
) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut key =
        CertifiedKey::from_der(chain.certificates.clone(), chain.key.clone_key(), &provider)
            .unwrap();
    if broken_signature {
        key.key = Arc::new(BrokenKey(key.key));
    }
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(key))),
    )
}

#[derive(Default, Debug)]
struct Seen {
    alpn: Vec<Vec<u8>>,
    name: Option<String>,
    resumed: bool,
}

async fn handshake(client: &StandardTlsClient, server: Arc<ServerConfig>) -> (bool, Seen) {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let observed = seen.clone();
    let server = async move {
        let start = LazyConfigAcceptor::new(Default::default(), server_io).await?;
        {
            let hello = start.client_hello();
            let mut seen = observed.lock().unwrap();
            seen.alpn = hello
                .alpn()
                .into_iter()
                .flatten()
                .map(<[u8]>::to_vec)
                .collect();
            seen.name = hello.server_name().map(str::to_owned);
        }
        let mut stream = start.into_stream(server).await?;
        observed.lock().unwrap().resumed =
            stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
        stream.write_all(&[42]).await?;
        stream.shutdown().await
    };
    let client = async {
        let mut stream = client.connect(Box::new(client_io)).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        assert_eq!(response, [42]);
        Ok::<_, io::Error>(())
    };
    let (result, _) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
    (
        result.is_ok(),
        Arc::try_unwrap(seen).unwrap().into_inner().unwrap(),
    )
}

#[cfg(feature = "tls-fingerprint")]
#[tokio::test]
async fn named_fingerprint_uses_the_shared_webpki_policy_and_transport_alpn() {
    for profile in crate::security::test_profiles().iter().copied().flatten() {
        let chain = chain(false);
        let mut server = server(&chain, &TLS13, false);
        Arc::get_mut(&mut server).unwrap().alpn_protocols = vec![b"h2".to_vec()];
        for (context, expected) in [(trusted(&chain), true), (SecurityContext::new(), false)] {
            let client = StandardTlsClient::with_options(
                &context,
                "fixture.invalid",
                TlsClientOptions {
                    client_fingerprint: Some(profile),
                    alpn: vec![b"h2".to_vec()],
                    required_alpn: Some(b"h2".to_vec()),
                    ..Default::default()
                },
                0,
                DEFAULT_TLS_BUFFER_LIMIT,
            )
            .unwrap();
            let (accepted, seen) = handshake(&client, server.clone()).await;
            assert_eq!(accepted, expected);
            assert_eq!(seen.alpn, [b"h2".to_vec()]);
            assert_eq!(seen.name.as_deref(), Some("fixture.invalid"));
        }
    }
}

#[tokio::test]
async fn configured_roots_authenticate_standard_and_named_tls_without_relaxing_names() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let chain = chain(false);
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(&chain.certificates[2])
    );
    let config = crate::config::Config::parse_yaml(
        &serde_json::to_vec(&serde_json::json!({
            "tls": {"custom-certifactes": [pem]},
        }))
        .unwrap(),
    )
    .unwrap();
    let context = SecurityContext::with_certificates(&config.tls, Vec::new());
    let server = server(&chain, &TLS13, false);
    for profile in crate::security::test_profiles() {
        for (name, expected) in [("fixture.invalid", true), ("different.invalid", false)] {
            let client = StandardTlsClient::with_options(
                &context,
                name,
                TlsClientOptions {
                    client_fingerprint: *profile,
                    ..Default::default()
                },
                0,
                DEFAULT_TLS_BUFFER_LIMIT,
            )
            .unwrap();
            assert_eq!(handshake(&client, server.clone()).await.0, expected);
        }
    }
}

#[cfg(feature = "tls-fingerprint")]
#[tokio::test]
async fn named_fingerprint_resumption_is_node_owned_and_disabled_at_zero_budget() {
    for profile in crate::security::test_profiles().iter().copied().flatten() {
        let chain = chain(false);
        for version in [&TLS12, &TLS13] {
            let peer = server(&chain, version, false);
            for capacity in [0, 1] {
                let make_client = || {
                    StandardTlsClient::with_options(
                        &trusted(&chain),
                        "fixture.invalid",
                        TlsClientOptions {
                            client_fingerprint: Some(profile),
                            ..Default::default()
                        },
                        capacity,
                        DEFAULT_TLS_BUFFER_LIMIT,
                    )
                    .unwrap()
                };
                let client = make_client();
                let first = handshake(&client, peer.clone()).await;
                assert!(first.0);
                assert!(!first.1.resumed);
                for _ in 0..2 {
                    let next = handshake(&client.clone(), peer.clone()).await;
                    assert!(next.0);
                    assert_eq!(next.1.resumed, capacity != 0);
                }
                let different_node = handshake(&make_client(), peer.clone()).await;
                assert!(different_node.0);
                assert!(!different_node.1.resumed);
            }
        }
    }
}

#[cfg(feature = "tls-fingerprint")]
#[tokio::test]
async fn named_fingerprint_tickets_are_bounded_single_use_and_not_published_on_alpn_rejection() {
    for profile in crate::security::test_profiles().iter().copied().flatten() {
        let chain = chain(false);
        let context = trusted(&chain);
        for capacity in [0, 1, 4] {
            let mut endpoint = server(&chain, &TLS13, false);
            Arc::get_mut(&mut endpoint).unwrap().send_tls13_tickets = 8;
            let client = StandardTlsClient::with_options(
                &context,
                "fixture.invalid",
                TlsClientOptions {
                    client_fingerprint: Some(profile),
                    ..Default::default()
                },
                capacity,
                4096,
            )
            .unwrap();
            assert!(handshake(&client, endpoint.clone()).await.0);
            // Keep the same peer session storage, but issue no replacement tickets.
            let mut no_tickets = endpoint.as_ref().clone();
            no_tickets.send_tls13_tickets = 0;
            let no_tickets = Arc::new(no_tickets);
            let mut resumed = 0;
            for _ in 0..6 {
                let (ok, seen) = handshake(&client, no_tickets.clone()).await;
                assert!(ok);
                resumed += usize::from(seen.resumed);
            }
            assert_eq!(resumed, capacity);
        }
        for version in [&TLS12, &TLS13] {
            let endpoint = server(&chain, version, false);
            let client = StandardTlsClient::with_options(
                &context,
                "fixture.invalid",
                TlsClientOptions {
                    client_fingerprint: Some(profile),
                    alpn: vec![b"h2".to_vec()],
                    required_alpn: Some(b"h2".to_vec()),
                    ..Default::default()
                },
                4,
                4096,
            )
            .unwrap();
            assert!(!handshake(&client, endpoint.clone()).await.0);
            let mut accepted = endpoint.as_ref().clone();
            accepted.alpn_protocols = vec![b"h2".to_vec()];
            let (ok, seen) = handshake(&client, Arc::new(accepted)).await;
            assert!(ok);
            assert!(
                !seen.resumed,
                "failed application policy cannot publish tickets"
            );
        }
    }
}

#[cfg(feature = "tls-fingerprint")]
#[tokio::test(start_paused = true)]
async fn named_fingerprint_close_notify_has_a_five_second_bound() {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    struct Gate(tokio::io::DuplexStream, Arc<AtomicBool>);
    impl AsyncRead for Gate {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, b)
        }
    }
    impl AsyncWrite for Gate {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.1.load(Ordering::Relaxed) {
                Poll::Pending
            } else {
                Pin::new(&mut self.0).poll_write(cx, b)
            }
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("TLS cannot close caller IO")
        }
    }
    for profile in crate::security::test_profiles().iter().copied().flatten() {
        let chain = chain(false);
        let client = client(
            &trusted(&chain),
            "fixture.invalid",
            TlsClientPolicy {
                client_fingerprint: Some(profile),
                ..Default::default()
            },
        );
        let (io, peer) = tokio::io::duplex(65536);
        let gate = Arc::new(AtomicBool::new(false));
        let (connected, accepted) = tokio::join!(
            client.connect(Box::new(Gate(io, gate.clone()))),
            tokio_rustls::TlsAcceptor::from(server(&chain, &TLS13, false)).accept(peer)
        );
        let mut tls = connected.unwrap();
        let _peer = accepted.unwrap();
        gate.store(true, Ordering::Relaxed);
        let started = tokio::time::Instant::now();
        assert_eq!(
            tls.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }
}

#[tokio::test]
async fn webpki_rejects_untrusted_wrong_name_and_expired_unless_explicitly_skipped() {
    for &profile in crate::security::test_profiles() {
        for expired in [false, true] {
            let chain = chain(expired);
            let server = server(&chain, &TLS13, false);
            for (context, name, expected) in [
                (trusted(&chain), "fixture.invalid", !expired),
                (trusted(&chain), "wrong.invalid", false),
                (SecurityContext::new(), "fixture.invalid", false),
            ] {
                assert_eq!(
                    handshake(
                        &client(
                            &context,
                            name,
                            TlsClientPolicy {
                                client_fingerprint: profile,
                                ..Default::default()
                            }
                        ),
                        server.clone()
                    )
                    .await
                    .0,
                    expected
                );
                let insecure = TlsClientPolicy {
                    certificate: TlsCertificatePolicy {
                        skip_cert_verify: true,
                        ..Default::default()
                    },
                    client_fingerprint: profile,
                    ..Default::default()
                };
                assert!(
                    handshake(&client(&context, name, insecure), server.clone())
                        .await
                        .0
                );
            }
        }
    }
}

#[tokio::test]
async fn leaf_pin_is_trust_but_nonleaf_pin_checks_chain_name_and_expiry() {
    for &profile in crate::security::test_profiles() {
        for expired in [false, true] {
            let chain = chain(expired);
            let server = server(&chain, &TLS13, false);
            for index in 0..3 {
                for name in ["fixture.invalid", "wrong.invalid"] {
                    for skip in [false, true] {
                        let policy = TlsClientPolicy {
                            certificate: TlsCertificatePolicy {
                                fingerprint: Some(pin(&chain, index)),
                                skip_cert_verify: skip,
                                ..Default::default()
                            },
                            client_fingerprint: profile,
                            ..Default::default()
                        };
                        let expected = index == 0 || (!expired && name == "fixture.invalid");
                        assert_eq!(
                            handshake(
                                &client(&SecurityContext::new(), name, policy),
                                server.clone()
                            )
                            .await
                            .0,
                            expected,
                            "index={index}, skip={skip}, expired={expired}"
                        );
                    }
                }
            }
            let policy = TlsClientPolicy {
                certificate: TlsCertificatePolicy {
                    fingerprint: Some([0; 32]),
                    skip_cert_verify: true,
                    ..Default::default()
                },
                client_fingerprint: profile,
                ..Default::default()
            };
            assert!(
                !handshake(
                    &client(&SecurityContext::new(), "fixture.invalid", policy),
                    server.clone()
                )
                .await
                .0
            );
            // A pinned unrelated certificate appended to the chain cannot bless
            // a leaf it did not issue, even with skip-cert-verify also enabled.
            let other = chain_for_unrelated();
            let mut unrelated = Chain {
                certificates: chain.certificates.clone(),
                key: chain.key.clone_key(),
            };
            unrelated.certificates.push(other.certificates[2].clone());
            let policy = TlsClientPolicy {
                certificate: TlsCertificatePolicy {
                    fingerprint: Some(pin(&other, 2)),
                    skip_cert_verify: true,
                    ..Default::default()
                },
                client_fingerprint: profile,
                ..Default::default()
            };
            assert!(
                !handshake(
                    &client(&SecurityContext::new(), "fixture.invalid", policy),
                    super_server(&unrelated)
                )
                .await
                .0
            );
        }
    }
}

// Separate names avoid shadowing helpers in the table-driven test above.
fn chain_for_unrelated() -> Chain {
    chain(false)
}
fn super_server(chain: &Chain) -> Arc<ServerConfig> {
    server(chain, &TLS13, false)
}

#[tokio::test]
async fn ticket_storage_obeys_exact_node_budget_and_consumes_each_ticket_once() {
    use crate::security::resumption::NodeSessionStore;
    let chain = chain(false);
    let context = trusted(&chain);
    let name = ServerName::try_from("fixture.invalid").unwrap().to_owned();
    for version in [&TLS12, &TLS13] {
        for capacity in [0, 1, 4] {
            let store = Arc::new(NodeSessionStore::new(name.clone(), capacity));
            let mut client = client(&context, "fixture.invalid", Default::default());
            let Some(StandardConnector::Rustls(connector)) = &client.connector else {
                panic!("unprofiled TLS uses rustls")
            };
            let mut config = connector.config().as_ref().clone();
            let epoch_store = store.for_epoch(Default::default());
            config.resumption = Resumption::store(epoch_store.clone());
            client.connector = Some(StandardConnector::Rustls(TlsConnector::from(Arc::new(
                config,
            ))));
            let mut server = server(&chain, version, false);
            Arc::get_mut(&mut server).unwrap().send_tls13_tickets = 8;
            assert!(handshake(&client, server.clone()).await.0);
            let expected = if version == &TLS12 {
                usize::from(capacity > 0)
            } else {
                capacity
            };
            assert_eq!(store.stored_sessions(), expected);
            let wrong = ServerName::try_from("wrong.invalid").unwrap();
            assert!(epoch_store.take_tls13_ticket(&wrong).is_none());
            assert!(epoch_store.tls12_session(&wrong).is_none());
            if version == &TLS13 {
                for _ in 0..expected {
                    assert!(epoch_store.take_tls13_ticket(&name).is_some());
                }
                assert!(epoch_store.take_tls13_ticket(&name).is_none());
            } else {
                assert_eq!(
                    handshake(&client, server.clone()).await.1.resumed,
                    capacity > 0
                );
                epoch_store.remove_tls12_session(&name);
            }
            assert_eq!(store.stored_sessions(), 0);
        }
    }
}

#[tokio::test]
async fn every_certificate_policy_verifies_tls12_and_tls13_handshake_signatures() {
    for &profile in crate::security::test_profiles() {
        let chain = chain(false);
        for version in [&TLS12, &TLS13] {
            for fingerprint in [None, Some(pin(&chain, 0)), Some(pin(&chain, 1))] {
                let policy = TlsClientPolicy {
                    certificate: TlsCertificatePolicy {
                        skip_cert_verify: true,
                        fingerprint,
                        ..Default::default()
                    },
                    client_fingerprint: profile,
                    ..Default::default()
                };
                let client = client(&SecurityContext::new(), "fixture.invalid", policy);
                assert!(handshake(&client, server(&chain, version, false)).await.0);
                assert!(!handshake(&client, server(&chain, version, true)).await.0);
            }
        }
    }
}

#[tokio::test]
async fn vless_keeps_webpki_tls13_and_required_h2_after_anytls_connections() {
    let chain = chain(false);
    let mut endpoint = server(&chain, &TLS13, false);
    Arc::get_mut(&mut endpoint).unwrap().alpn_protocols = vec![b"h2".to_vec()];
    let insecure = client(
        &SecurityContext::new(),
        "fixture.invalid",
        TlsClientPolicy {
            certificate: TlsCertificatePolicy {
                skip_cert_verify: true,
                ..Default::default()
            },
            alpn: vec![b"h2".to_vec()],
            ..Default::default()
        },
    );
    assert!(handshake(&insecure, endpoint.clone()).await.0);
    for (context, expected) in [(SecurityContext::new(), false), (trusted(&chain), true)] {
        let vless = StandardTlsClient::new(
            &context,
            "fixture.invalid",
            StandardTlsProfile::VlessXhttp,
            4,
            DEFAULT_TLS_BUFFER_LIMIT,
        )
        .unwrap();
        let (ok, seen) = handshake(&vless, endpoint.clone()).await;
        assert_eq!(ok, expected);
        assert_eq!(seen.alpn, [b"h2".to_vec()]);
        assert!(!seen.resumed);
        if expected {
            assert!(handshake(&vless, endpoint.clone()).await.1.resumed);
        }
        assert!(!handshake(&vless, server(&chain, &TLS13, false)).await.0);
        let mut tls12 = server(&chain, &TLS12, false);
        Arc::get_mut(&mut tls12).unwrap().alpn_protocols = vec![b"h2".to_vec()];
        assert!(!handshake(&vless, tls12).await.0);
    }
}

#[tokio::test]
async fn alpn_and_tls_resumption_are_isolated_between_node_policies() {
    let chain = chain(false);
    let server = server(&chain, &TLS13, false);
    let context = trusted(&chain);
    let alpn = vec![b"custom".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];
    let policy = TlsClientPolicy {
        certificate: TlsCertificatePolicy {
            fingerprint: Some(pin(&chain, 2)),
            ..Default::default()
        },
        alpn: alpn.clone(),
        ..Default::default()
    };
    let first = client(&context, "fixture.invalid", policy.clone());
    let (ok, seen) = handshake(&first, server.clone()).await;
    assert!(ok);
    assert!(!seen.resumed);
    assert_eq!(seen.alpn, alpn);
    assert_eq!(seen.name.as_deref(), Some("fixture.invalid"));
    let (ok, seen) = handshake(&first, server.clone()).await;
    assert!(ok);
    assert!(seen.resumed);
    let (ok, seen) = handshake(
        &client(&context, "fixture.invalid", Default::default()),
        server.clone(),
    )
    .await;
    assert!(ok);
    assert!(!seen.resumed);
    assert!(seen.alpn.is_empty());
    assert!(
        !handshake(
            &client(&context, "wrong.invalid", policy.clone()),
            server.clone()
        )
        .await
        .0
    );
    let wrong = TlsClientPolicy {
        certificate: TlsCertificatePolicy {
            fingerprint: Some([0; 32]),
            skip_cert_verify: true,
            ..Default::default()
        },
        ..policy
    };
    assert!(
        !handshake(&client(&context, "fixture.invalid", wrong), server.clone())
            .await
            .0
    );
    assert!(
        !handshake(
            &client(
                &SecurityContext::new(),
                "fixture.invalid",
                Default::default()
            ),
            server
        )
        .await
        .0
    );
}

#[tokio::test]
async fn explicit_verification_name_does_not_change_sni_or_allow_skip_to_override_it() {
    for &profile in crate::security::test_profiles() {
        let chain = chain(false);
        let context = trusted(&chain);
        for (name, skip, fingerprint, expected) in [
            ("fixture.invalid", false, None, true),
            ("fixture.invalid", true, None, true),
            ("wrong.invalid", true, None, false),
            ("wrong.invalid", true, Some(pin(&chain, 0)), true),
            ("wrong.invalid", true, Some(pin(&chain, 1)), false),
            ("fixture.invalid", true, Some([0; 32]), false),
        ] {
            let policy = TlsClientPolicy {
                client_fingerprint: profile,
                certificate: TlsCertificatePolicy {
                    verification_name: Some(name.into()),
                    skip_cert_verify: skip,
                    fingerprint,
                },
                ..Default::default()
            };
            let client = StandardTlsClient::with_options(
                &context,
                "sni.invalid",
                TlsClientOptions::from_policy(&policy, None, &context).unwrap(),
                1,
                DEFAULT_TLS_BUFFER_LIMIT,
            )
            .unwrap();
            let (ok, seen) = handshake(&client, server(&chain, &TLS13, false)).await;
            assert_eq!(ok, expected);
            assert_eq!(seen.name.as_deref(), Some("sni.invalid"));
        }
    }
}

#[tokio::test]
async fn mutual_tls_identity_is_required_verified_and_not_shared_between_clients() {
    for &profile in crate::security::test_profiles() {
        let chain = chain(false);
        let identity = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
        let unknown = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
        for version in [&TLS12, &TLS13] {
            let mut roots = RootCertStore::empty();
            roots.add(identity.certificates[2].clone()).unwrap();
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                trusted(&chain).provider,
            )
            .build()
            .unwrap();
            let server = Arc::new(
                ServerConfig::builder_with_provider(trusted(&chain).provider)
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(chain.certificates.clone(), chain.key.clone_key())
                    .unwrap(),
            );
            for (cert, expected) in [
                (Some(&identity), true),
                (None, false),
                (Some(&unknown), false),
                (Some(&identity), true),
            ] {
                let policy = TlsClientPolicy {
                    client_fingerprint: profile,
                    identity: cert.map(Chain::identity_pem),
                    ..Default::default()
                };
                let client = StandardTlsClient::with_options(
                    &trusted(&chain),
                    "fixture.invalid",
                    TlsClientOptions::from_policy(&policy, None, &trusted(&chain)).unwrap(),
                    1,
                    DEFAULT_TLS_BUFFER_LIMIT,
                )
                .unwrap();
                let (ok, seen) = handshake(&client, server.clone()).await;
                assert_eq!(ok, expected);
                assert!(
                    !seen.resumed,
                    "new identity must not inherit a node's tickets"
                );
                if expected {
                    assert!(handshake(&client, server.clone()).await.1.resumed);
                }
            }
        }
    }
}

#[test]
fn tls_options_reject_invalid_alpn_identity_and_budget_before_using_a_stream() {
    let context = SecurityContext::new();
    for options in [
        TlsClientOptions {
            alpn: vec![vec![]],
            ..Default::default()
        },
        TlsClientOptions {
            alpn: vec![vec![b'a'; 256]],
            ..Default::default()
        },
        TlsClientOptions {
            alpn: vec![vec![b'a'; 255]; 256],
            ..Default::default()
        },
        TlsClientOptions {
            required_alpn: Some(b"h2".to_vec()),
            ..Default::default()
        },
    ] {
        assert!(
            StandardTlsClient::with_options(&context, "example.com", options, 1, 4096).is_err()
        );
    }
    let first = chain(false);
    let second = chain(false);
    let options = TlsClientOptions {
        identity: Some(TlsClientIdentity::from_der(first.certificates, second.key)),
        ..Default::default()
    };
    let error =
        StandardTlsClient::with_options(&context, "example.com", options, 1, 4096).unwrap_err();
    assert_eq!(error.to_string(), "invalid TLS client identity");
    assert!(
        StandardTlsClient::with_options(&context, "example.com", Default::default(), 5, 4096)
            .is_err()
    );
    assert!(
        StandardTlsClient::with_options(
            &context,
            "secret-invalid name",
            Default::default(),
            1,
            4096
        )
        .is_err()
    );
}

#[tokio::test]
async fn certificate_rejection_delivers_no_business_bytes_and_diagnostics_are_redacted() {
    for fingerprint in [None, Some([0; 32])] {
        let chain = chain(false);
        let client = StandardTlsClient::with_options(
            &trusted(&chain),
            "secret-wrong.invalid",
            TlsClientOptions {
                certificate: TlsCertificatePolicy {
                    fingerprint,
                    ..Default::default()
                },
                ..Default::default()
            },
            1,
            4096,
        )
        .unwrap();
        assert!(!format!("{client:?}").contains("secret-wrong"));
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_side = async {
            match client.connect(Box::new(client_io)).await {
                Ok(mut stream) => {
                    stream.write_all(b"business bytes").await.unwrap();
                    panic!("invalid certificate accepted")
                }
                Err(error) => {
                    assert!(!error.to_string().contains("secret-wrong"));
                    assert!(!error.to_string().contains("fixture.invalid"));
                }
            }
        };
        let server_side = async {
            let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(server(&chain, &TLS13, false))
                .accept(server_io)
                .await
            else {
                return 0;
            };
            let mut data = [0; 64];
            stream.read(&mut data).await.unwrap_or(0)
        };
        let (_, bytes) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(client_side, server_side)
        })
        .await
        .unwrap();
        assert_eq!(bytes, 0);
    }
}

#[tokio::test]
async fn tls_close_write_sends_notify_without_closing_the_supplied_transport() {
    for &profile in crate::security::test_profiles() {
        let chain = chain(false);
        let client = StandardTlsClient::with_options(
            &trusted(&chain),
            "fixture.invalid",
            TlsClientOptions {
                client_fingerprint: profile,
                ..Default::default()
            },
            0,
            4096,
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut stream = tokio_rustls::TlsAcceptor::from(server(&chain, &TLS13, false))
                .accept(server_io)
                .await
                .unwrap();
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"request");
            let mut probe = [0; 1];
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(30),
                    stream.get_mut().0.read(&mut probe)
                )
                .await
                .is_err(),
                "TLS CloseWrite must not shut down the underlay"
            );
            stream.write_all(b"tail").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = client.connect(Box::new(client_io)).await.unwrap();
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(
            stream.write(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut body = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut body))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, b"tail");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn tls_close_notify_flush_has_a_five_second_bound() {
    let chain = chain(false);
    let client = client(&trusted(&chain), "fixture.invalid", Default::default());
    let (client_io, server_io) = tokio::io::duplex(128);
    let server = tokio::spawn(async move {
        let _stream = tokio_rustls::TlsAcceptor::from(server(&chain, &TLS13, false))
            .accept(server_io)
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
    let mut stream = client.connect(Box::new(client_io)).await.unwrap();
    assert!(stream.write(&[0; 32768]).await.unwrap() > 0);
    let started = tokio::time::Instant::now();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(6), stream.shutdown())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() >= Duration::from_secs(5));
    drop(stream);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn cancelling_tls_handshake_releases_the_caller_supplied_stream() {
    for &profile in crate::security::test_profiles() {
        let (client_io, mut peer) = tokio::io::duplex(4096);
        let chain = chain(false);
        let client = client(
            &trusted(&chain),
            "fixture.invalid",
            TlsClientPolicy {
                client_fingerprint: profile,
                ..Default::default()
            },
        );
        let reconnect = client.clone();
        let connect = tokio::spawn(async move { client.connect(Box::new(client_io)).await });
        let mut hello = [0; 4096];
        assert!(peer.read(&mut hello).await.unwrap() > 0);
        connect.abort();
        assert!(matches!(connect.await, Err(error) if error.is_cancelled()));
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        let (ok, seen) = handshake(&reconnect, server(&chain, &TLS13, false)).await;
        assert!(
            ok && !seen.resumed,
            "cancelled handshake cannot poison or seed the next connection"
        );
    }
}
