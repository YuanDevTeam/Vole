//! Memory-only authentication regressions using the actual QUIC TLS engine.
use super::*;
use crate::security::QuicheTls;
use boring::{
    pkey::PKey,
    ssl::{SslContextBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};

fn peer(chain: &Chain, client_ca: Option<&Chain>) -> SslContextBuilder {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
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
    if let Some(identity) = client_ca {
        builder
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.certificates[2]).unwrap())
            .unwrap();
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    builder
}

fn options(policy: TlsCertificatePolicy) -> TlsClientOptions {
    TlsClientOptions {
        alpn: vec![b"h3".to_vec()],
        required_alpn: Some(b"h3".to_vec()),
        certificate: policy,
        versions: TlsVersions::Tls13,
        ..Default::default()
    }
}

fn handshake(mut tls: QuicheTls, peer: SslContextBuilder) -> io::Result<()> {
    let client_addr = "192.0.2.1:1234".parse().unwrap();
    let server_addr = "192.0.2.2:443".parse().unwrap();
    let mut config = tls.build_config()?;
    config.enable_pacing(false);
    let mut server_config =
        ::quiche::Config::with_boring_ssl_ctx_builder(::quiche::PROTOCOL_VERSION, peer).unwrap();
    server_config.set_application_protos(&[b"h3"]).unwrap();
    server_config.enable_pacing(false);
    let mut client = ::quiche::connect(
        Some(tls.server_name()),
        &::quiche::ConnectionId::from_ref(&[1; 20]),
        client_addr,
        server_addr,
        &mut config,
    )
    .unwrap();
    tls.prepare_connection(&mut client)?;
    let mut server = ::quiche::accept(
        &::quiche::ConnectionId::from_ref(&[2; 20]),
        None,
        server_addr,
        client_addr,
        &mut server_config,
    )
    .unwrap();
    let mut packet = [0; 1500];
    for _ in 0..64 {
        transfer(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut packet,
        )?;
        transfer(
            &mut server,
            &mut client,
            server_addr,
            client_addr,
            &mut packet,
        )?;
        if client.is_established() && server.is_established() {
            return tls.check_handshake(&mut client);
        }
        if client.is_closed() || server.is_closed() {
            break;
        }
    }
    Err(io::Error::other("memory QUIC handshake did not complete"))
}

fn transfer(
    sender: &mut ::quiche::Connection,
    receiver: &mut ::quiche::Connection,
    from: std::net::SocketAddr,
    to: std::net::SocketAddr,
    packet: &mut [u8],
) -> io::Result<()> {
    for _ in 0..64 {
        match sender.send(packet) {
            Ok((length, _)) => {
                let result = receiver.recv(&mut packet[..length], ::quiche::RecvInfo { from, to });
                if !matches!(result, Ok(_) | Err(::quiche::Error::Done)) {
                    return Err(io::Error::other("memory QUIC authentication failed"));
                }
            }
            Err(::quiche::Error::Done) => break,
            Err(_) => return Err(io::Error::other("memory QUIC authentication failed")),
        }
    }
    Ok(())
}

#[test]
fn quiche_preserves_webpki_names_and_pin_precedence() {
    let chain = chain(false);
    for (context, name, policy, expected) in [
        (trusted(&chain), "fixture.invalid", Default::default(), true),
        (
            SecurityContext::new(),
            "fixture.invalid",
            Default::default(),
            false,
        ),
        (trusted(&chain), "other.invalid", Default::default(), false),
        (
            trusted(&chain),
            "other.invalid",
            TlsCertificatePolicy {
                verification_name: Some("fixture.invalid".into()),
                skip_cert_verify: true,
                fingerprint: None,
            },
            true,
        ),
        (
            SecurityContext::new(),
            "other.invalid",
            TlsCertificatePolicy {
                fingerprint: Some(pin(&chain, 0)),
                ..Default::default()
            },
            true,
        ),
        (
            trusted(&chain),
            "fixture.invalid",
            TlsCertificatePolicy {
                fingerprint: Some([0; 32]),
                skip_cert_verify: true,
                ..Default::default()
            },
            false,
        ),
        (
            SecurityContext::new(),
            "fixture.invalid",
            TlsCertificatePolicy {
                fingerprint: Some(pin(&chain, 1)),
                ..Default::default()
            },
            true,
        ),
        (
            SecurityContext::new(),
            "other.invalid",
            TlsCertificatePolicy {
                fingerprint: Some(pin(&chain, 1)),
                ..Default::default()
            },
            false,
        ),
    ] {
        let client =
            StandardTlsClient::with_options(&context, name, options(policy), 0, 65536).unwrap();
        assert_eq!(
            handshake(client.quiche_config().unwrap(), peer(&chain, None)).is_ok(),
            expected
        );
    }
    let expired = super::chain(true);
    let client = StandardTlsClient::with_options(
        &SecurityContext::new(),
        "other.invalid",
        options(TlsCertificatePolicy {
            fingerprint: Some(pin(&expired, 0)),
            ..Default::default()
        }),
        0,
        65536,
    )
    .unwrap();
    handshake(client.quiche_config().unwrap(), peer(&expired, None)).unwrap();
}

#[test]
fn quiche_client_identity_is_verified_by_the_peer() {
    let server = chain(false);
    let trusted_identity = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    let other = chain_with_usage(false, ExtendedKeyUsagePurpose::ClientAuth);
    for (identity, expected) in [
        (Some(&trusted_identity), true),
        (Some(&other), false),
        (None, false),
    ] {
        let mut options = options(Default::default());
        options.identity = identity.map(|chain| {
            TlsClientIdentity::from_der(chain.certificates.clone(), chain.key.clone_key())
        });
        let client = StandardTlsClient::with_options(
            &trusted(&server),
            "fixture.invalid",
            options,
            0,
            65536,
        )
        .unwrap();
        assert_eq!(
            handshake(
                client.quiche_config().unwrap(),
                peer(&server, Some(&trusted_identity))
            )
            .is_ok(),
            expected
        );
    }
}

#[cfg(feature = "ech")]
#[test]
fn quiche_requires_real_ech_acceptance_and_reselects_the_native_backend() {
    use boring::{hpke::HpkeKey, ssl::SslEchKeys};
    use hpke::{Kem, Serializable};
    use rand::SeedableRng;

    let chain = chain(false);
    let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).unwrap();
    let (private, public) = hpke::kem::X25519HkdfSha256::gen_keypair_with_rng(&mut rng);
    let mut contents = vec![7, 0, 32, 0, 32];
    contents.extend_from_slice(&public.to_bytes());
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 14]);
    contents.extend_from_slice(b"public.invalid");
    contents.extend_from_slice(&[0, 0]);
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&config);
    let mut options = options(TlsCertificatePolicy {
        fingerprint: Some(pin(&chain, 0)),
        ..Default::default()
    });
    options.ech =
        Some(crate::config::StaticEchConfig::from_config_list_for_backend(&list, false).unwrap());
    let client =
        StandardTlsClient::with_options(&trusted(&chain), "fixture.invalid", options, 0, 65536)
            .unwrap();
    for accept_ech in [true, false] {
        let server = peer(&chain, None);
        if accept_ech {
            // The existing safe constructor imports X25519, despite its name.
            let key = HpkeKey::dhkem_p256_sha256(&private.to_bytes()).unwrap();
            let mut keys = SslEchKeys::builder().unwrap();
            keys.add_key(true, &config, key).unwrap();
            server.set_ech_keys(&keys.build()).unwrap();
        }
        assert_eq!(
            handshake(client.quiche_config().unwrap(), server).is_ok(),
            accept_ech,
            "a matching pin must not admit rejected ECH"
        );
    }

    // A rustls-compatible P-256-only source cannot silently become ECH GREASE
    // when the same client switches to the native H3 backend.
    let suite = crate::security::ech::SUITES[15];
    let (key, _) = suite.generate_key_pair().unwrap();
    let mut contents = vec![7];
    contents.extend_from_slice(&u16::from(suite.suite().kem).to_be_bytes());
    contents.extend_from_slice(&(key.0.len() as u16).to_be_bytes());
    contents.extend_from_slice(&key.0);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 14]);
    contents.extend_from_slice(b"public.invalid");
    contents.extend_from_slice(&[0, 0]);
    let mut list = ((contents.len() + 4) as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&[0xfe, 0x0d]);
    list.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    list.extend_from_slice(&contents);
    let mut options = self::options(Default::default());
    options.ech =
        Some(crate::config::StaticEchConfig::from_config_list_for_backend(&list, false).unwrap());
    let client =
        StandardTlsClient::with_options(&trusted(&chain), "fixture.invalid", options, 0, 65536)
            .unwrap();
    assert!(client.quiche_config().is_err());
}
