use super::*;
use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::sign::{Signer, SigningKey, SingleCertAndKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}
fn material() -> (ControllerTls, CertificateDer<'static>) {
    let key = rcgen::generate_simple_self_signed(vec!["controller.example".into()]).unwrap();
    (
        ControllerTls {
            certificate: pem("CERTIFICATE", key.cert.der()).into(),
            private_key: pem("PRIVATE KEY", &key.signing_key.serialize_der()).into(),
            ..Default::default()
        },
        key.cert.der().clone(),
    )
}
fn authority() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}
fn identity(issuer: &CertifiedIssuer<'_, KeyPair>) -> CertifiedKey {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["client.example".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, issuer).unwrap();
    CertifiedKey::from_der(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        &rustls::crypto::ring::default_provider(),
    )
    .unwrap()
}
#[derive(Debug)]
struct WrongProof(Arc<dyn SigningKey>);
#[derive(Debug)]
struct WrongSignature(Box<dyn Signer>);
impl SigningKey for WrongProof {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|signer| Box::new(WrongSignature(signer)) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}
impl Signer for WrongSignature {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.0.sign(message)?;
        signature[0] ^= 1;
        Ok(signature)
    }
    fn scheme(&self) -> rustls::SignatureScheme {
        self.0.scheme()
    }
}

async fn handshake(
    server: Arc<rustls::ServerConfig>,
    trust: &CertificateDer<'static>,
    identity: Option<CertifiedKey>,
    version: &'static rustls::SupportedProtocolVersion,
) -> (bool, bool) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trust.clone()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_root_certificates(roots);
    let mut client = if let Some(key) = identity {
        builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)))
    } else {
        builder.with_no_client_auth()
    };
    client.resumption = rustls::client::Resumption::disabled();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client = async {
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect("controller.example".try_into().unwrap(), client_io)
            .await?;
        let byte = stream.read_u8().await?;
        assert_eq!(byte, 42);
        Ok::<_, io::Error>(())
    };
    let server = async {
        let mut stream = tokio_rustls::TlsAcceptor::from(server)
            .accept(server_io)
            .await?;
        let presented = stream.get_ref().1.peer_certificates().is_some();
        stream.write_all(&[42]).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(presented)
    };
    let (client, server) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
    (client.is_ok() && server.is_ok(), server.unwrap_or(false))
}

#[tokio::test]
async fn controller_secure_tls_auth_modes_preserve_real_proof_and_ca_verification() {
    let (base, certificate) = material();
    let known = authority();
    let unknown = authority();
    for (mode, ca, expected) in [
        ("", false, [true, true, true]),
        ("unknown-mode", false, [true, true, true]),
        ("request", false, [true, true, true]),
        ("require-any", false, [false, true, true]),
        ("verify-if-given", true, [true, true, false]),
        ("require-and-verify", true, [false, true, false]),
        ("", true, [false, true, false]),
        ("request", true, [true, true, true]),
    ] {
        let mut options = base.clone();
        options.client_auth_type = mode.into();
        if ca {
            options.client_auth_cert = pem("CERTIFICATE", known.der()).into();
        }
        let tls = ServerTls::load(&options, Path::new(".")).unwrap();
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            for (identity, accepted) in [
                (None, expected[0]),
                (Some(identity(&known)), expected[1]),
                (Some(identity(&unknown)), expected[2]),
            ] {
                assert_eq!(
                    handshake(tls.config.clone(), &certificate, identity, version)
                        .await
                        .0,
                    accepted,
                    "{mode}, {ca}, {version:?}"
                );
            }
            if matches!(mode, "request" | "require-any") {
                let mut wrong = identity(&unknown);
                wrong.key = Arc::new(WrongProof(wrong.key));
                assert!(
                    !handshake(tls.config.clone(), &certificate, Some(wrong), version)
                        .await
                        .0
                );
            }
        }
    }
}

#[tokio::test]
async fn controller_secure_tls_generates_random_rsa2048_with_matching_signing_key() {
    use rsa::{pkcs8::DecodePublicKey as _, traits::PublicKeyParts as _};
    let tls =
        tokio::task::spawn_blocking(|| ServerTls::load(&ControllerTls::default(), Path::new(".")))
            .await
            .unwrap()
            .unwrap();
    assert!(!tls.watches_files());
    let key = tls.resolver.0.read().unwrap().clone();
    key.keys_match().unwrap();
    assert_eq!(key.key.algorithm(), rustls::SignatureAlgorithm::RSA);
    let certificate = rustls::server::ParsedCertificate::try_from(&key.cert[0]).unwrap();
    let public_key =
        rsa::RsaPublicKey::from_public_key_der(certificate.subject_public_key_info().as_ref())
            .unwrap();
    assert_eq!(public_key.n().bits(), 2048);
    let signer = key
        .key
        .choose_scheme(&[rustls::SignatureScheme::RSA_PSS_SHA256])
        .unwrap();
    assert_eq!(signer.sign(b"controller fixture").unwrap().len(), 256);
}

#[tokio::test]
async fn controller_secure_tls_file_candidates_keep_old_pair_and_stop_watcher() {
    let root = tempfile::tempdir().unwrap();
    let (first, first_certificate) = material();
    let (second, second_certificate) = material();
    let certificate_path = root.path().join("controller.pem");
    let key_path = root.path().join("controller.key");
    let ca = authority();
    let ca_path = root.path().join("clients.pem");
    std::fs::write(&ca_path, pem("CERTIFICATE", ca.der())).unwrap();
    std::fs::write(&certificate_path, first.certificate.as_bytes()).unwrap();
    std::fs::write(&key_path, first.private_key.as_bytes()).unwrap();
    let tls = Arc::new(
        ServerTls::load(
            &ControllerTls {
                certificate: "controller.pem".into(),
                private_key: "controller.key".into(),
                client_auth_type: "require-and-verify".into(),
                client_auth_cert: "clients.pem".into(),
                ..Default::default()
            },
            root.path(),
        )
        .unwrap(),
    );
    assert!(tls.watches_files());
    let cancel = CancellationToken::new();
    let watcher = tokio::spawn(tls.clone().watch(cancel.clone()));
    std::fs::write(&ca_path, b"CA files are not reloaded during this session").unwrap();
    std::fs::write(&certificate_path, b"invalid certificate candidate").unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(tls.resolver.0.read().unwrap().cert[0], first_certificate);
    std::fs::write(&certificate_path, second.certificate.as_bytes()).unwrap();
    std::fs::write(&key_path, second.private_key.as_bytes()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while tls.resolver.0.read().unwrap().cert[0] != second_certificate {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        handshake(
            tls.config.clone(),
            &second_certificate,
            Some(identity(&ca)),
            &rustls::version::TLS13
        )
        .await
        .0
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), watcher)
        .await
        .unwrap()
        .unwrap();
    assert!(!Arc::new(ServerTls::load(&first, root.path()).unwrap()).watches_files());
}
