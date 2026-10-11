#![cfg(feature = "outbound-vless")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use boring::{
    hpke::HpkeKey,
    pkey::PKey,
    ssl::{SslAcceptor, SslEchKeys, SslMethod, SslVersion},
    x509::X509,
};
use foreign_types::ForeignType;
use hpke::{Kem as _, Serializable};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol},
    security::SecurityClient,
};

fn material(aead: u16) -> (Vec<u8>, HpkeKey) {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).unwrap();
    let (private, public) = hpke::kem::X25519HkdfSha256::gen_keypair_with_rng(&mut rng);
    let mut content = vec![7, 0, 32, 0, 32];
    content.extend_from_slice(&public.to_bytes());
    content.extend_from_slice(&[0, 4, 0, 1]);
    content.extend_from_slice(&aead.to_be_bytes());
    content.extend_from_slice(&[0, 14]);
    content.extend_from_slice(b"public.invalid");
    content.extend_from_slice(&[0, 0]);
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&(content.len() as u16).to_be_bytes());
    config.extend_from_slice(&content);
    // Only the test peer needs an X25519 ECH server key; the stable safe wrapper
    // exposes a P-256 constructor. Use existing official native FFI, not a server
    // implementation or a production dependency on private library structures.
    let key = unsafe {
        let raw = boring_sys::EVP_HPKE_KEY_new();
        assert!(!raw.is_null());
        let key = HpkeKey::from_ptr(raw);
        let bytes = private.to_bytes();
        assert_eq!(
            boring_sys::EVP_HPKE_KEY_init(
                raw,
                boring_sys::EVP_hpke_x25519_hkdf_sha256(),
                bytes.as_ptr(),
                bytes.len()
            ),
            1
        );
        key
    };
    (config, key)
}

fn client(profile: &str, list: &[u8], pin: &str) -> SecurityClient {
    client_with(profile, list, pin, json!({}))
}

fn client_with(profile: &str, list: &[u8], pin: &str, extra: serde_json::Value) -> SecurityClient {
    let mut node = json!({"name":"edge", "type":"vless", "server":"inner.invalid", "port":443,
        "uuid":"07070707-0707-0707-0707-070707070707", "tls":true,
        "client-fingerprint":profile, "fingerprint":pin,
        "ech-opts":{"enable":true, "config":STANDARD.encode(list)}});
    node.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let config = Config::parse_yaml(
        &serde_json::to_vec(&json!({
            "mixed-port":1080,
            "proxies":[node],
            "rules":["MATCH,edge"]
        }))
        .unwrap(),
    )
    .unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        panic!()
    };
    SecurityClient::from_proxy(node).unwrap()
}

#[tokio::test]
async fn rejected_or_wrong_key_ech_never_reaches_application_data_even_with_a_matching_pin() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "rejected_or_wrong_key_ech_never_reaches_application_data_even_with_a_matching_pin",
    );
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["inner.invalid".into(), "public.invalid".into()])
            .unwrap();
    let pin: String = Sha256::digest(cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let (config, _) = material(1);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&config);
    for has_wrong_key in [false, true] {
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        server
            .set_certificate(&X509::from_der(cert.der()).unwrap())
            .unwrap();
        server
            .set_private_key(&PKey::private_key_from_der(&signing_key.serialize_der()).unwrap())
            .unwrap();
        if has_wrong_key {
            let (wrong, key) = material(1);
            let mut keys = SslEchKeys::builder().unwrap();
            keys.add_key(true, &wrong, key).unwrap();
            server.set_ech_keys(&keys.build()).unwrap();
        }
        let server = server.build();
        for profile in ["none", "chrome", "firefox", "safari", "ios"] {
            let client = client(profile, &list, &pin);
            let (io, peer) = tokio::io::duplex(65_536);
            tokio::time::timeout(Duration::from_secs(3), async {
                let native = async {
                    if let Ok(mut tls) = tokio_boring::accept(&server, peer).await {
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(n) if n != 0));
                    }
                };
                let consumer = async {
                    assert!(
                        client.connect(Box::new(io)).await.is_err(),
                        "{profile}: rejected ECH must fail closed"
                    );
                };
                tokio::join!(native, consumer);
            })
            .await
            .unwrap();
        }
    }
}

fn outer_sni(hello: &[u8]) -> &[u8] {
    assert_eq!(hello[0], 1); // handshake ClientHello, record header removed
    let mut offset = 38;
    offset += 1 + usize::from(hello[offset]); // session ID
    offset += 2 + usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
    offset += 1 + usize::from(hello[offset]); // compression
    let len = usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
    offset += 2;
    assert_eq!(offset + len, hello.len());
    let mut sni = None;
    let mut encrypted = false;
    while offset < hello.len() {
        let kind = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]));
        let data = &hello[offset + 4..offset + 4 + len];
        if kind == 0 {
            assert_eq!(data[2], 0);
            assert_eq!(
                usize::from(u16::from_be_bytes([data[3], data[4]])),
                data.len() - 5
            );
            sni = Some(&data[5..]);
        }
        if kind == 0xfe0d {
            encrypted = true;
        }
        if kind == 43 {
            assert_eq!(usize::from(data[0]), data.len() - 1);
            let versions: Vec<_> = data[1..]
                .as_chunks::<2>()
                .0
                .iter()
                .filter(|v| {
                    !(v[0] == v[1] && v[0] & 0x0f == 0x0a) // GREASE is not a TLS version.
                })
                .collect();
            assert_eq!(versions, [b"\x03\x04"], "ECH must offer TLS 1.3 only");
        }
        assert_ne!(kind, 41, "static ECH must not offer a cached PSK");
        offset += 4 + len;
    }
    assert!(encrypted);
    sni.unwrap()
}

#[tokio::test]
async fn client_identity_is_sent_only_after_ech_acceptance() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "client_identity_is_sent_only_after_ech_acceptance",
    );
    use boring::ssl::SslVerifyMode;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["inner.invalid".into(), "public.invalid".into()])
            .unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
    let pin: String = Sha256::digest(cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for accepted in [true, false] {
        for profile in ["none", "chrome", "firefox", "safari", "ios"] {
            let (config, key) = material(1);
            let mut list = (config.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&config);
            let mut keys = SslEchKeys::builder().unwrap();
            keys.add_key(true, &config, key).unwrap();
            let observed = Arc::new(AtomicUsize::new(0));
            let verifier = observed.clone();
            let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            server
                .set_certificate(&X509::from_der(cert.der()).unwrap())
                .unwrap();
            server
                .set_private_key(&PKey::private_key_from_der(&signing_key.serialize_der()).unwrap())
                .unwrap();
            server.set_verify_callback(SslVerifyMode::PEER, move |_, chain| {
                if chain.current_cert().is_some() {
                    verifier.fetch_add(1, Ordering::Relaxed);
                }
                true
            });
            if accepted {
                server.set_ech_keys(&keys.build()).unwrap();
            }
            let server = server.build();
            let client = client_with(
                profile,
                &list,
                &pin,
                json!({
                    "certificate":String::from_utf8(X509::from_der(identity.cert.der()).unwrap().to_pem().unwrap()).unwrap(),
                    "private-key":String::from_utf8(PKey::private_key_from_der(&identity.signing_key.serialize_der()).unwrap().private_key_to_pem_pkcs8().unwrap()).unwrap()
                }),
            );
            let (io, peer) = tokio::io::duplex(65_536);
            tokio::time::timeout(Duration::from_secs(3), async {
                let native = async {
                    let outcome = tokio_boring::accept(&server, peer).await;
                    if accepted {
                        let mut tls = outcome.unwrap();
                        assert!(tls.ssl().ech_accepted());
                        assert!(tls.ssl().peer_certificate().is_some());
                        tls.write_all(b"ok").await.unwrap();
                        tls.flush().await.unwrap();
                    } else if let Ok(tls) = outcome {
                        assert!(tls.ssl().peer_certificate().is_none());
                    }
                };
                let consumer = async {
                    let outcome = client.connect(Box::new(io)).await;
                    if accepted {
                        let mut data = [0; 2];
                        outcome.unwrap().read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"ok");
                    } else {
                        assert!(outcome.is_err());
                    }
                };
                tokio::join!(native, consumer);
            })
            .await
            .unwrap();
            assert_eq!(observed.load(Ordering::Relaxed) > 0, accepted, "{profile}");
        }
    }
}

#[tokio::test]
async fn cancelled_ech_emits_only_public_sni_and_releases_io_for_every_backend() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "cancelled_ech_emits_only_public_sni_and_releases_io_for_every_backend",
    );
    let (config, _) = material(1);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&config);
    for profile in ["none", "chrome", "firefox", "safari", "ios"] {
        let client = client(profile, &list, &"07".repeat(32));
        let mut previous = None;
        for _ in 0..20 {
            let (io, mut peer) = tokio::io::duplex(65_536);
            let cloned = client.clone();
            let task = tokio::spawn(async move { cloned.connect(Box::new(io)).await });
            let mut header = [0; 5];
            tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut header))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(header[0], 22);
            let mut hello = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            peer.read_exact(&mut hello).await.unwrap();
            assert_eq!(outer_sni(&hello), b"public.invalid");
            let random: [u8; 32] = hello[6..38].try_into().unwrap();
            assert_ne!(previous, Some(random));
            previous = Some(random);
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            let mut tail = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut tail))
                .await
                .unwrap()
                .unwrap();
            assert!(
                tail.len() <= 6,
                "only an optional compatibility CCS may follow ClientHello"
            );
        }
    }
}

#[tokio::test]
async fn each_backend_and_hpke_suite_requires_real_ech_acceptance_before_data() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "each_backend_and_hpke_suite_requires_real_ech_acceptance_before_data",
    );
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["inner.invalid".into(), "public.invalid".into()])
            .unwrap();
    let pin: String = Sha256::digest(cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for aead in [1, 2, 3] {
        let (config, key) = material(aead);
        let mut list = (config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&config);
        let mut keys = SslEchKeys::builder().unwrap();
        keys.add_key(true, &config, key).unwrap();
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        server
            .set_certificate(&X509::from_der(cert.der()).unwrap())
            .unwrap();
        server
            .set_private_key(&PKey::private_key_from_der(&signing_key.serialize_der()).unwrap())
            .unwrap();
        server
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        server.set_ech_keys(&keys.build()).unwrap();
        let server = server.build();
        for profile in ["none", "chrome", "firefox", "safari", "ios"] {
            let client = client(profile, &list, &pin);
            for _round in 0..3 {
                let (io, peer) = tokio::io::duplex(65_536);
                tokio::time::timeout(Duration::from_secs(3), async {
                    let native = async {
                        let mut tls = tokio_boring::accept(&server, peer).await.unwrap();
                        assert!(
                            !tls.ssl().session_reused(),
                            "static ECH must never resume TLS"
                        );
                        assert!(
                            tls.ssl().ech_accepted(),
                            "{profile}/{aead}: peer did not accept ECH"
                        );
                        assert_eq!(
                            tls.ssl().servername(boring::ssl::NameType::HOST_NAME),
                            Some("inner.invalid")
                        );
                        let mut data = [0; 7];
                        tls.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"payload");
                        tls.write_all(b"reply").await.unwrap();
                        tls.flush().await.unwrap();
                    };
                    let consumer = async {
                        let mut tls = client
                            .connect(Box::new(io))
                            .await
                            .unwrap_or_else(|e| panic!("{profile}/{aead}: {e}"));
                        tls.write_all(b"payload").await.unwrap();
                        tls.flush().await.unwrap();
                        let mut data = [0; 5];
                        tls.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"reply");
                    };
                    tokio::join!(native, consumer);
                })
                .await
                .unwrap();
            }
        }
    }
}
