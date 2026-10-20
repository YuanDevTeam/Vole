//! Published file identities over memory TLS; no sockets or external material.
#![cfg(feature = "outbound-http")]

use super::*;
use tokio_util::sync::CancellationToken;

type Accepted = tokio_rustls::server::TlsStream<tokio::io::DuplexStream>;

struct Files {
    directory: tempfile::TempDir,
}

impl Files {
    fn new(identity: &Chain) -> Self {
        let files = Self {
            directory: tempfile::tempdir().unwrap(),
        };
        files.replace(identity);
        files
    }

    fn replace_member(&self, name: &str, contents: &str) {
        use std::io::Write;
        let mut candidate = tempfile::NamedTempFile::new_in(self.directory.path()).unwrap();
        candidate.write_all(contents.as_bytes()).unwrap();
        // Replacing the inode makes every candidate observable even when equal
        // length writes happen within one filesystem timestamp quantum.
        candidate.persist(self.directory.path().join(name)).unwrap();
    }

    fn replace(&self, identity: &Chain) {
        let pem = identity.identity_pem();
        self.replace_member("client.pem", &pem.certificate);
        self.replace_member("client.key", &pem.private_key);
    }

    fn identity(&self, context: &SecurityContext) -> TlsClientIdentity {
        TlsClientIdentity::from_config(&self.configuration(), context).unwrap()
    }

    fn configuration(&self) -> crate::config::TlsIdentityPem {
        let config = crate::config::Config::parse_yaml_with_directory(
            br#"proxies:
  - name: edge
    type: http
    server: fixture.invalid
    port: 443
    tls: true
    certificate: client.pem
    private-key: client.key
rules: ['MATCH,edge']
"#,
            Some(self.directory.path()),
        )
        .unwrap();
        let crate::config::ProxyProtocol::Http(http) = &config.proxies[0].protocol else {
            panic!("file-backed HTTP identity expected");
        };
        http.tls
            .as_ref()
            .unwrap()
            .identity
            .as_ref()
            .unwrap()
            .clone()
    }
}

fn endpoint(peer: &Chain, identities: &[&Chain]) -> Arc<ServerConfig> {
    let mut roots = RootCertStore::empty();
    for identity in identities {
        roots.add(identity.certificates[2].clone()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(peer.certificates.clone(), peer.key.clone_key())
        .unwrap();
    // More than the node's budget makes a late old connection capable of
    // displacing every new ticket if generation checks are accidentally lost.
    config.send_tls13_tickets = 8;
    Arc::new(config)
}

fn rotating_client(
    context: &SecurityContext,
    identity: TlsClientIdentity,
    profile: Option<crate::config::ClientFingerprint>,
) -> StandardTlsClient {
    StandardTlsClient::with_options(
        context,
        "fixture.invalid",
        TlsClientOptions {
            identity: Some(identity),
            client_fingerprint: profile,
            ..Default::default()
        },
        TLS_RESUMPTION_SESSION_BUDGET,
        DEFAULT_TLS_BUFFER_LIMIT,
    )
    .unwrap()
}

async fn open(
    client: &StandardTlsClient,
    endpoint: Arc<ServerConfig>,
    expected: &Chain,
) -> (crate::dispatch::BoxStream, Accepted, bool) {
    let (client_io, peer_io) = tokio::io::duplex(16_384);
    let acceptor = tokio_rustls::TlsAcceptor::from(endpoint);
    let (client, peer) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            client.connect(Box::new(client_io)),
            acceptor.accept(peer_io)
        )
    })
    .await
    .unwrap();
    let peer = peer.unwrap();
    let client = client.unwrap();
    assert_eq!(
        peer.get_ref().1.peer_certificates().unwrap().first(),
        expected.certificates.first(),
        "the new physical TLS connection used another client identity"
    );
    let resumed = peer.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
    (client, peer, resumed)
}

async fn exchange(client: &mut crate::dispatch::BoxStream, peer: &mut Accepted, value: &[u8]) {
    assert!(value.len() <= 1024);
    tokio::time::timeout(Duration::from_secs(3), async {
        let caller = async {
            client.write_all(value).await.unwrap();
            client.flush().await.unwrap();
            let mut reply = vec![0; value.len()];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, value);
        };
        let responder = async {
            let mut request = vec![0; value.len()];
            peer.read_exact(&mut request).await.unwrap();
            assert_eq!(request, value);
            peer.write_all(&request).await.unwrap();
            peer.flush().await.unwrap();
        };
        tokio::join!(caller, responder);
    })
    .await
    .unwrap();
}

fn assert_identity(identity: &TlsClientIdentity, expected: &Chain, generation: u64) {
    let snapshot = identity.snapshot();
    assert_eq!(snapshot.material.certificates, expected.certificates);
    assert_eq!(snapshot.epoch.generation(), generation);
    assert!(snapshot.epoch.is_current());
}

#[tokio::test]
async fn consecutive_rotations_preserve_old_transports_and_reject_late_old_tickets() {
    let peer = chain(false);
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let b = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let c = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    #[cfg(not(feature = "tls-fingerprint"))]
    let profiles = [None];
    #[cfg(feature = "tls-fingerprint")]
    let profiles = [None, Some(crate::config::ClientFingerprint::Chrome133)];
    for profile in profiles {
        let files = Files::new(&a);
        let context = trusted(&peer);
        let identity = files.identity(&context);
        let client = rotating_client(&context, identity.clone(), profile);
        let endpoint = endpoint(&peer, &[&a, &b, &c]);
        let frozen_rustls = match client.current_connector().unwrap() {
            StandardConnector::Rustls(connector) => Some(connector.config().clone()),
            #[cfg(feature = "tls-fingerprint")]
            StandardConnector::Boring(_) => None,
        };
        let (mut old_client, mut old_peer, resumed) = open(&client, endpoint.clone(), &a).await;
        assert!(!resumed);
        // Leave A's post-handshake tickets unread until after B has filled the
        // node cache, so its late TLS callbacks cannot repopulate the new era.
        let old_epoch = identity.snapshot().epoch;
        files.replace(&b);
        context.identities.refresh(&CancellationToken::new());
        assert!(!old_epoch.is_current());
        assert_identity(&identity, &b, 2);
        let (mut b_client, mut b_peer, resumed) = open(&client, endpoint.clone(), &b).await;
        assert!(!resumed, "the old identity's ticket crossed the rotation");
        exchange(&mut b_client, &mut b_peer, b"new-B").await;
        exchange(&mut old_client, &mut old_peer, b"old-A-still-live").await;
        let (mut resumed_b, mut resumed_peer, resumed) = open(&client, endpoint.clone(), &b).await;
        assert!(resumed, "late A tickets displaced B's usable session cache");
        exchange(&mut resumed_b, &mut resumed_peer, b"resumed-B").await;
        drop((resumed_b, resumed_peer));

        files.replace(&c);
        context.identities.refresh(&CancellationToken::new());
        assert_identity(&identity, &c, 3);
        let (mut c_client, mut c_peer, resumed) = open(&client.clone(), endpoint.clone(), &c).await;
        assert!(!resumed, "B's ticket crossed the second rotation");
        exchange(&mut c_client, &mut c_peer, b"new-C").await;
        exchange(&mut b_client, &mut b_peer, b"old-B-still-live").await;
        exchange(&mut old_client, &mut old_peer, b"old-A-after-C").await;

        if let Some(config) = frozen_rustls {
            // A retired QUIC/TLS consumer may still own its immutable config.
            // The old config remains a working A identity, without borrowing
            // the live node's newer resolver or publishing tickets into it.
            let (client_io, peer_io) = tokio::io::duplex(16_384);
            let connector = TlsConnector::from(config);
            let acceptor = tokio_rustls::TlsAcceptor::from(endpoint);
            let (frozen, accepted) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(
                    connector.connect(ServerName::try_from("fixture.invalid").unwrap(), client_io),
                    acceptor.accept(peer_io),
                )
            })
            .await
            .unwrap();
            let mut accepted = accepted.unwrap();
            assert_eq!(
                accepted.get_ref().1.peer_certificates().unwrap().first(),
                a.certificates.first()
            );
            assert_ne!(
                accepted.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            );
            let mut frozen = Box::new(frozen.unwrap()) as crate::dispatch::BoxStream;
            exchange(&mut frozen, &mut accepted, b"frozen-A-config").await;
        }
        // Read C after an older configuration has completed too: neither old
        // transport lifetime nor its ticket callbacks may stall new identity use.
        exchange(&mut c_client, &mut c_peer, b"current-C").await;
    }
}

#[tokio::test]
async fn mismatched_candidates_recover_and_cancel_or_stop_cannot_publish() {
    let peer = chain(false);
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let b = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let c = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let files = Files::new(&a);
    let context = trusted(&peer);
    let identity = files.identity(&context);
    let client = rotating_client(&context, identity.clone(), None);
    let endpoint = endpoint(&peer, &[&a, &b, &c]);
    let b_pem = b.identity_pem();
    files.replace_member("client.pem", &b_pem.certificate);
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&identity, &a, 1);
    let (mut caller, mut accepted, _) = open(&client, endpoint.clone(), &a).await;
    exchange(&mut caller, &mut accepted, b"bad-pair-keeps-A").await;
    drop((caller, accepted));

    files.replace_member("client.key", &b_pem.private_key);
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&identity, &b, 2);
    let (mut caller, mut accepted, _) = open(&client, endpoint.clone(), &b).await;
    exchange(&mut caller, &mut accepted, b"recovered-B").await;
    drop((caller, accepted));

    files.replace(&c);
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    context.identities.refresh(&cancelled);
    assert_identity(&identity, &b, 2);
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&identity, &c, 3);
    let epoch = identity.snapshot().epoch;
    context.identities.begin_shutdown();
    assert!(!epoch.is_current());
    files.replace(&a);
    context.identities.refresh(&CancellationToken::new());
    assert_eq!(identity.snapshot().epoch.generation(), 3);
    assert_eq!(identity.snapshot().material.certificates, c.certificates);
    assert!(!context.identities.has_sources());
}

#[test]
fn different_pairs_rotate_independently_and_identical_sources_share_one_publication() {
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let b = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let first_files = Files::new(&a);
    let second_files = Files::new(&a);
    let context = SecurityContext::new();
    let first = first_files.identity(&context);
    let same_files = first_files.identity(&context);
    let different_files = second_files.identity(&context);
    assert!(Arc::ptr_eq(
        &first.snapshot().material,
        &same_files.snapshot().material
    ));
    assert!(!Arc::ptr_eq(
        &first.snapshot().material,
        &different_files.snapshot().material
    ));
    first_files.replace(&b);
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&first, &b, 2);
    assert_identity(&same_files, &b, 2);
    assert_identity(&different_files, &a, 1);
    second_files.replace(&b);
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&different_files, &b, 2);
}

#[test]
fn larger_same_pair_candidate_cannot_bypass_other_active_material() {
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let first_files = Files::new(&a);
    let other_files = Files::new(&a);
    let context = SecurityContext::new();
    let first = first_files.identity(&context);
    let other = other_files.identity(&context);
    let mut large = a.identity_pem();
    let padding =
        crate::config::MAX_CONFIG_BYTES - large.certificate.len() - large.private_key.len();
    // Whitespace is valid PEM input and still consumes the shared file budget.
    large.certificate.extend(std::iter::repeat_n(' ', padding));
    first_files.replace_member("client.pem", &large.certificate);
    let candidate = first_files.configuration();
    assert!(TlsClientIdentity::from_config(&candidate, &context).is_err());
    assert_identity(&first, &a, 1);
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&first, &a, 1);
    drop(other);
    let accepted = TlsClientIdentity::from_config(&candidate, &context).unwrap();
    assert!(Arc::ptr_eq(
        &first.snapshot().material,
        &accepted.snapshot().material
    ));
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&first, &a, 2);
    assert_identity(&accepted, &a, 2);
}

#[cfg(all(feature = "tls-fingerprint", feature = "outbound-vless"))]
#[test]
fn dynamic_ech_rebuilds_share_the_native_owner_without_resolving_dns() {
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let files = Files::new(&a);
    let context = SecurityContext::new();
    let identity = files.identity(&context);
    let config = crate::config::Config::parse_yaml(
        br#"proxies:
  - name: edge
    type: vless
    server: fixture.invalid
    port: 443
    uuid: 07070707-0707-0707-0707-070707070707
    tls: true
    client-fingerprint: chrome
    ech-opts: {enable: true, query-server-name: query.invalid}
"#,
    )
    .unwrap();
    let crate::config::ProxyProtocol::Vless(vless) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let client = StandardTlsClient::with_options(
        &context,
        "fixture.invalid",
        TlsClientOptions {
            ech: vless.security.as_tls().unwrap().ech.clone(),
            client_fingerprint: Some(crate::config::ClientFingerprint::Chrome133),
            identity: Some(identity),
            ..Default::default()
        },
        0,
        DEFAULT_TLS_BUFFER_LIMIT,
    )
    .unwrap();
    let dynamic = client.dynamic_ech.as_ref().unwrap();
    let owner = dynamic
        .options
        .identity
        .as_ref()
        .unwrap()
        .native
        .as_ref()
        .unwrap()
        .clone();
    let retained = Arc::strong_count(&owner);
    // Exercise the same backend reconstruction after DNS without making a DNS
    // request: only the resolved ECH option is omitted from this ownership test.
    let mut resolved = dynamic.options.clone();
    resolved.ech = None;
    resolved.versions = TlsVersions::Tls13;
    let rebuilt = StandardTlsClient::with_options(
        &context,
        "fixture.invalid",
        resolved,
        0,
        DEFAULT_TLS_BUFFER_LIMIT,
    )
    .unwrap();
    assert_eq!(Arc::strong_count(&owner), retained + 1);
    drop(rebuilt);
    assert_eq!(Arc::strong_count(&owner), retained);
}

#[cfg(feature = "tls-fingerprint")]
#[test]
fn discarded_native_candidate_releases_its_requirement_and_cached_representation() {
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let files = Files::new(&a);
    let context = SecurityContext::new();
    let identity = files.identity(&context);
    let IdentityStorage::Files(source) = &identity.storage else {
        unreachable!()
    };
    let _plain = rotating_client(&context, identity.clone(), None);
    assert!(!source.native_required());
    let rejected = StandardTlsClient::with_options(
        &context,
        "fixture.invalid",
        TlsClientOptions {
            versions: TlsVersions::Tls13,
            client_fingerprint: Some(crate::config::ClientFingerprint::ThreeSixty75),
            identity: Some(identity.clone()),
            ..Default::default()
        },
        0,
        DEFAULT_TLS_BUFFER_LIMIT,
    );
    assert!(rejected.is_err());
    assert!(!source.native_required());
    let candidate = rotating_client(
        &context,
        identity.clone(),
        Some(crate::config::ClientFingerprint::Chrome133),
    );
    assert!(source.native_required());
    let cached = Arc::downgrade(&identity.snapshot().material.native().unwrap());
    assert!(cached.upgrade().is_some());
    drop(candidate);
    assert!(!source.native_required());
    assert!(cached.upgrade().is_none());
}

#[cfg(feature = "tls-fingerprint")]
#[test]
fn native_registration_between_validation_and_publication_rechecks_the_candidate() {
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let b = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let files = Files::new(&a);
    let context = SecurityContext::new();
    let identity = files.identity(&context);
    let mut candidate = b.identity_pem();
    candidate
        .certificate
        .push_str("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n");
    // rustls checks the matching leaf/key at construction; native TLS parses
    // every chain member. The late subscriber must not inherit this candidate.
    let parsed =
        TlsClientIdentity::from_pem(&candidate.certificate, &candidate.private_key).unwrap();
    assert!(parsed.snapshot().material.native().is_err());
    files.replace_member("client.pem", &candidate.certificate);
    files.replace_member("client.key", &candidate.private_key);
    let mut native_owner = None;
    context
        .identities
        .refresh_before_publication(&CancellationToken::new(), &mut || {
            native_owner = Some(identity.for_native().unwrap());
        });
    assert_identity(&identity, &a, 1);
    files.replace(&b);
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&identity, &b, 2);
    assert_eq!(
        native_owner
            .unwrap()
            .native_snapshot()
            .unwrap()
            .material
            .certificates,
        b.certificates
    );
}

#[cfg(unix)]
#[test]
fn transient_read_failure_retries_after_permissions_recover_without_content_change() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid has no arguments, memory access or ownership effects.
    if unsafe { libc::geteuid() } == 0 {
        return; // Root bypasses the file permission failure this case requires.
    }
    let a = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let b = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let files = Files::new(&a);
    let context = SecurityContext::new();
    let identity = files.identity(&context);
    files.replace(&b);
    let path = files.directory.path().join("client.key");
    let metadata = std::fs::metadata(&path).unwrap();
    let permissions = metadata.permissions();
    let modified = metadata.modified().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0)).unwrap();
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&identity, &a, 1);
    std::fs::set_permissions(&path, permissions).unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().modified().unwrap(),
        modified
    );
    context.identities.refresh(&CancellationToken::new());
    assert_identity(&identity, &b, 2);
}
