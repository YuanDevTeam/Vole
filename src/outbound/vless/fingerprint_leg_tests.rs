//! Real TLS over memory IO through both production XHTTP node constructors.
use super::*;
use crate::config::{Config, ProxyProtocol};
use base64::{Engine, engine::general_purpose::STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use rustls::{RootCertStore, ServerConfig, pki_types::PrivateKeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::AsyncReadExt;

struct Identity {
    root: rustls::pki_types::CertificateDer<'static>,
    certificate: String,
    key: String,
}

fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
}

fn identity() -> Identity {
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
    let mut leaf = CertificateParams::new(vec!["client.fixture.invalid".into()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let certificate = leaf.signed_by(&key, &root).unwrap();
    Identity {
        root: root.der().clone(),
        certificate: pem("CERTIFICATE", certificate.der()),
        key: pem("PRIVATE KEY", &key.serialize_der()),
    }
}

fn server(certificate: &rcgen::CertifiedKey<KeyPair>, identity: &Identity) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(identity.root.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            PrivateKeyDer::Pkcs8(certificate.signing_key.serialize_der().into()),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    server.send_tls13_tickets = 2;
    Arc::new(server)
}

fn outbound(
    profile: &str,
    pin: &str,
    upload: &Identity,
    download: Value,
    runtime: bool,
) -> VlessOutbound {
    let config = Config::parse_yaml(json!({
        "mixed-port": 1080,
        "proxies": [{
            "name": "p", "type": "vless", "server": "192.0.2.1", "port": 443,
            "uuid": "07070707-0707-0707-0707-070707070707", "tls": true,
            "servername": "fixture.invalid", "fingerprint": pin,
            "client-fingerprint": profile, "alpn": ["h2"], "network": "xhttp",
            "certificate": upload.certificate, "private-key": upload.key,
            "xhttp-opts": {"mode": "stream-up", "path": "/fixture", "download-settings": download}
        }], "rules": ["MATCH,p"]
    }).to_string().as_bytes()).unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    // These paths are never dialed. Both real adapters receive memory streams.
    let path = || {
        UpstreamPath::direct(
            ResolvedEndpoint {
                logical_host: "192.0.2.1".into(),
                port: 443,
                addresses: vec!["192.0.2.1:443".parse().unwrap()],
            },
            Dialer::default(),
        )
    };
    if runtime {
        VlessOutbound::new_with_shared_security(
            config,
            path(),
            Some(path()),
            &SecurityContext::new(),
            2,
            VlessResourceLimits::new(65536, 65536, 65536),
        )
    } else {
        VlessOutbound::new_with_paths(config, path(), Some(path()))
    }
    .unwrap()
}

async fn exchange(
    client: &SecurityClient,
    peer: Arc<ServerConfig>,
) -> (io::Result<()>, io::Result<bool>, usize) {
    let (io, peer_io) = tokio::io::duplex(65536);
    let received = AtomicUsize::new(0);
    let (client, server) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            async {
                let mut stream = client.connect(Box::new(io)).await?;
                stream.write_all(b"ping").await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                if response != b"pong" {
                    return Err(io::Error::other("memory peer response mismatch"));
                }
                Ok(())
            },
            async {
                let mut stream = tokio_rustls::TlsAcceptor::from(peer)
                    .accept(peer_io)
                    .await?;
                let resumed =
                    stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
                let mut request = [0; 4];
                stream.read_exact(&mut request).await?;
                received.store(request.len(), Ordering::Relaxed);
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").await?;
                stream.shutdown().await?;
                Ok::<_, io::Error>(resumed)
            }
        )
    })
    .await
    .unwrap();
    (client, server, received.load(Ordering::Relaxed))
}

async fn accepted(client: &SecurityClient, peer: Arc<ServerConfig>, resumed: bool) {
    let (client, server, received) = exchange(client, peer).await;
    client.unwrap();
    assert_eq!(server.unwrap(), resumed);
    assert_eq!(received, 4);
}

#[tokio::test]
async fn selected_xhttp_legs_isolate_tickets_and_client_identities() {
    let certificate = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
    let pin = Sha256::digest(certificate.cert.der())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let upload_identity = identity();
    let download_identity = identity();
    for runtime in [false, true] {
        for profile in ["chrome", "firefox", "safari", "ios"] {
            for variant in ["inherit", "different", "clear"] {
                let other = if profile == "chrome" {
                    "firefox"
                } else {
                    "chrome"
                };
                let override_identity = variant != "inherit";
                let download = if override_identity {
                    json!({
                        "client-fingerprint": if variant == "clear" { "none" } else { other },
                        "certificate": download_identity.certificate, "private-key": download_identity.key,
                    })
                } else {
                    json!({})
                };
                let outbound = outbound(profile, &pin, &upload_identity, download, runtime);
                let upload = &outbound.upload.security;
                let download = &outbound.download.as_ref().unwrap().transport.security;
                let peer = server(&certificate, &upload_identity);
                let download_peer = if override_identity {
                    server(&certificate, &download_identity)
                } else {
                    peer.clone()
                };
                accepted(upload, peer.clone(), false).await;
                accepted(upload, peer.clone(), true).await;
                // Even inherited policy, certificate, name and template may
                // not reuse an upload ticket in a freshly constructed leg.
                accepted(download, download_peer.clone(), false).await;
                accepted(download, download_peer.clone(), true).await;
                if override_identity {
                    for (client, wrong_peer) in
                        [(upload, download_peer.clone()), (download, peer.clone())]
                    {
                        let (client, server, bytes) = exchange(client, wrong_peer).await;
                        assert!(client.is_err() && server.is_err());
                        assert_eq!(bytes, 0, "opposite leg identity admitted application bytes");
                    }
                    // A failed cross-identity attempt cannot replace the
                    // immutable client identity; fresh handshakes still work.
                    assert!(exchange(upload, peer).await.0.is_ok());
                    assert!(exchange(download, download_peer).await.0.is_ok());
                }
                outbound.shutdown().await;
            }
        }
    }
}
