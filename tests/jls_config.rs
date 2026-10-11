#![cfg(feature = "outbound-vless")]

use serde_json::json;
use vole::{
    config::{Config, ProxyProtocol, SecurityConfig, VlessOutboundConfig},
    security::SecurityClient,
};

#[test]
fn public_jls_builds_an_authenticated_security_client_without_exposing_credentials() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "public_jls_builds_an_authenticated_security_client_without_exposing_credentials",
    );
    let config = Config::parse_yaml(
        &serde_json::to_vec(&json!({
            "mixed-port":1080,
            "proxies":[{"name":"edge", "type":"vless", "server":"example.invalid", "port":443,
                "uuid":"07070707-0707-0707-0707-070707070707", "tls":true,
                "jls-opts":{"username":"synthetic-jls-user", "password":"synthetic-jls-password"}}],
            "rules":["MATCH,edge"]
        }))
        .unwrap(),
    )
    .expect("valid JLS must normalize before any IO");
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        panic!()
    };
    let client = SecurityClient::from_proxy(node).expect("JLS must have a real native client");
    for text in [format!("{config:?}"), format!("{client:?}")] {
        assert!(!text.contains("synthetic-jls-user"));
        assert!(!text.contains("synthetic-jls-password"));
    }
}

fn node() -> serde_json::Value {
    json!({"name":"edge", "type":"vless", "server":"example.invalid", "port":443,
        "uuid":"07070707-0707-0707-0707-070707070707", "tls":true,
        "jls-opts":{"username":"synthetic-jls-user", "password":"synthetic-jls-password"}})
}

fn parse(node: serde_json::Value) -> vole::Result<VlessOutboundConfig> {
    let config = Config::parse_yaml(
        &serde_json::to_vec(&json!({
            "mixed-port":1080, "proxies":[node], "rules":["MATCH,edge"]
        }))
        .unwrap(),
    )?;
    let ProxyProtocol::Vless(node) = config.proxies.into_iter().next().unwrap().protocol else {
        panic!()
    };
    Ok(node)
}

#[test]
fn independent_download_inherits_jls_identity_and_applies_its_own_tls_fields() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "independent_download_inherits_jls_identity_and_applies_its_own_tls_fields",
    );
    let mut input = node();
    input["network"] = json!("xhttp");
    input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{
        "servername":"download.invalid", "alpn":["http/1.1"]
    }});
    let config = parse(input).unwrap();
    let SecurityConfig::Jls(download) = &config.download().unwrap().security else {
        panic!("download must not silently lose inherited JLS authentication")
    };
    assert_eq!(download.username, "synthetic-jls-user");
    assert_eq!(download.password, "synthetic-jls-password");
    assert_eq!(download.tls.server_name, "download.invalid");
    assert_eq!(download.tls.alpn, [b"http/1.1"]);
    SecurityClient::from_security(&config.download().unwrap().security).unwrap();
}

#[test]
fn download_jls_credentials_are_replaced_as_a_whole_or_explicitly_cleared() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "download_jls_credentials_are_replaced_as_a_whole_or_explicitly_cleared",
    );
    let mut input = node();
    input["network"] = json!("xhttp");
    input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{
        "jls-opts":{"username":"download-user", "password":"download-password"}
    }});
    let config = parse(input.clone()).unwrap();
    let SecurityConfig::Jls(download) = &config.download().unwrap().security else {
        panic!("explicit download JLS must be retained")
    };
    assert_eq!(download.username, "download-user");
    assert_eq!(download.password, "download-password");
    input["xhttp-opts"]["download-settings"]["jls-opts"] = json!({});
    assert!(matches!(
        parse(input.clone()).unwrap().download().unwrap().security,
        SecurityConfig::Tls(_)
    ));
    input["xhttp-opts"]["download-settings"]["tls"] = json!(false);
    assert!(matches!(
        parse(input).unwrap().download().unwrap().security,
        SecurityConfig::None
    ));
}

#[test]
fn malformed_or_partial_credentials_never_inherit_a_missing_secret() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "malformed_or_partial_credentials_never_inherit_a_missing_secret",
    );
    for replacement in [
        json!(null),
        json!([]),
        json!("secret"),
        json!({}),
        json!({"username":"synthetic-jls-user"}),
        json!({"password":"synthetic-jls-password"}),
        json!({"username":"", "password":"synthetic-jls-password"}),
        json!({"username":"synthetic-jls-user", "password":""}),
        json!({"username":null, "password":"synthetic-jls-password"}),
        json!({"username":"synthetic-jls-user", "password":null}),
        json!({"username":123, "password":"synthetic-jls-password"}),
        json!({"username":"synthetic-jls-user", "password":"synthetic-jls-password", "extra":true}),
        json!({"username":"u".repeat(65_536), "password":"synthetic-jls-password"}),
        json!({"username":"synthetic-jls-user", "password":"密".repeat(21_846)}),
    ] {
        let mut input = node();
        input["jls-opts"] = replacement.clone();
        let error = parse(input)
            .expect_err("invalid primary JLS must fail before IO")
            .to_string();
        assert!(!error.contains("synthetic-jls-user"));
        assert!(!error.contains("synthetic-jls-password"));
        if replacement == json!({}) {
            continue; // Only an independent download leg accepts an empty clear object.
        }
        let mut input = node();
        input["network"] = json!("xhttp");
        input["xhttp-opts"] =
            json!({"mode":"stream-up", "download-settings":{"jls-opts":replacement}});
        assert!(
            parse(input).is_err(),
            "download must not leaf-merge credentials"
        );
    }
    let mut input = node();
    input["jls-opts"] = json!({"username":"u".repeat(65_535), "password":"p".repeat(65_535)});
    SecurityClient::from_proxy(&parse(input).unwrap()).unwrap();
}

#[test]
fn invalid_jls_objects_do_not_echo_credentials_in_public_configuration_errors() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "invalid_jls_objects_do_not_echo_credentials_in_public_configuration_errors",
    );
    for credential in ["username", "password"] {
        let mut input = node();
        input["jls-opts"][credential] = json!(98765432198765_u64);
        let error = parse(input).unwrap_err().to_string();
        assert!(
            !error.contains("98765432198765"),
            "numeric secret was echoed"
        );
    }
    for replacement in [
        json!("synthetic-object-secret"),
        json!({"synthetic-object-secret":true}),
        json!({"username":"synthetic-jls-user", "password":98765432198765_u64}),
    ] {
        for download in [false, true] {
            let mut input = node();
            if download {
                input["network"] = json!("xhttp");
                input["xhttp-opts"] =
                    json!({"mode":"stream-up", "download-settings":{"jls-opts":replacement}});
            } else {
                input["jls-opts"] = replacement.clone();
            }
            let error = parse(input).unwrap_err().to_string();
            assert!(!error.contains("synthetic-object-secret"));
            assert!(!error.contains("synthetic-jls-user"));
            assert!(!error.contains("98765432198765"));
        }
    }
}

#[test]
fn jls_rejects_incompatible_security_at_configuration_time() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "jls_rejects_incompatible_security_at_configuration_time",
    );
    for overrides in [
        json!({"tls":false}),
        json!({"flow":"xtls-rprx-vision"}),
        json!({"reality-opts":{"public-key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}),
        json!({"skip-cert-verify":false}),
        json!({"skip-cert-verify":true}),
        json!({"fingerprint":"07".repeat(32)}),
        json!({"name-cert-verify":"example.invalid"}),
        json!({"certificate":"certificate", "private-key":"key"}),
        json!({"network":"xhttp", "alpn":["h3"], "xhttp-opts":{"mode":"stream-up"}}),
    ] {
        let mut input = node();
        input
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().unwrap().clone());
        assert!(parse(input).is_err());
    }
    for download in [
        json!({"tls":false}),
        json!({"alpn":["h3"]}),
        json!({"skip-cert-verify":true}),
        json!({"name-cert-verify":"other.invalid"}),
        json!({"fingerprint":"07".repeat(32)}),
    ] {
        let mut input = node();
        input["network"] = json!("xhttp");
        input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":download});
        assert!(parse(input).is_err());
    }
}

#[test]
fn download_security_switch_requires_explicit_clearing_of_inherited_identity() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "download_security_switch_requires_explicit_clearing_of_inherited_identity",
    );
    let reality = json!({"public-key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"});
    let mut input = node();
    input["network"] = json!("xhttp");
    input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{"reality-opts":reality}});
    assert!(parse(input.clone()).is_err());
    input["xhttp-opts"]["download-settings"]["jls-opts"] = json!({});
    assert!(matches!(
        parse(input).unwrap().download().unwrap().security,
        SecurityConfig::Reality(_)
    ));

    let mut input = node();
    let credentials = input.as_object_mut().unwrap().remove("jls-opts").unwrap();
    input["reality-opts"] = reality;
    input["network"] = json!("xhttp");
    input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{"jls-opts":credentials}});
    assert!(parse(input.clone()).is_err());
    input["xhttp-opts"]["download-settings"]["reality-opts"] = json!({});
    assert!(matches!(
        parse(input.clone()).unwrap().download().unwrap().security,
        SecurityConfig::Jls(_)
    ));
    input.as_object_mut().unwrap().remove("reality-opts");
    input["skip-cert-verify"] = json!(true);
    assert!(parse(input.clone()).is_err());
    input["xhttp-opts"]["download-settings"]["skip-cert-verify"] = json!(false);
    assert!(matches!(
        parse(input).unwrap().download().unwrap().security,
        SecurityConfig::Jls(_)
    ));
}

#[cfg(feature = "tls-fingerprint")]
#[test]
fn selected_profiles_build_jls_without_changing_its_identity() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "selected_profiles_build_jls_without_changing_its_identity",
    );
    for profile in ["none", "", "chrome", "firefox", "safari", "ios", "random"] {
        let mut input = node();
        input["client-fingerprint"] = json!(profile);
        input["network"] = json!("xhttp");
        input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{}});
        let config = parse(input.clone()).unwrap();
        let SecurityConfig::Jls(main) = &config.security else {
            panic!()
        };
        let SecurityConfig::Jls(download) = &config.download().unwrap().security else {
            panic!()
        };
        assert_eq!(main, download);
        SecurityClient::from_proxy(&config).unwrap();
        input["xhttp-opts"]["download-settings"]["client-fingerprint"] = json!("none");
        let config = parse(input).unwrap();
        let SecurityConfig::Jls(download) = &config.download().unwrap().security else {
            panic!()
        };
        assert!(download.tls.client_fingerprint.is_none());
        SecurityClient::from_security(&config.download().unwrap().security).unwrap();
    }
}

#[tokio::test]
async fn cancelled_jls_handshakes_release_supplied_io_and_never_reuse_randoms() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "cancelled_jls_handshakes_release_supplied_io_and_never_reuse_randoms",
    );
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    let client = SecurityClient::from_proxy(&parse(node()).unwrap()).unwrap();
    let mut previous = None;
    for _ in 0..20 {
        let (io, mut peer) = tokio::io::duplex(32_768);
        let cloned = client.clone();
        let task = tokio::spawn(async move { cloned.connect(Box::new(io)).await });
        let mut header = [0; 5];
        tokio::time::timeout(Duration::from_secs(2), peer.read_exact(&mut header))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header[0], 22);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!((38..=16_384).contains(&length));
        let mut hello = vec![0; length];
        peer.read_exact(&mut hello).await.unwrap();
        let random: [u8; 32] = hello[6..38].try_into().unwrap();
        assert_ne!(previous, Some(random));
        previous = Some(random);
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut header))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn jls_security_client_rejects_ordinary_tls_before_application_data() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "jls_security_client_rejects_ordinary_tls_before_application_data",
    );
    use boring::{
        pkey::PKey,
        ssl::{SslAcceptor, SslMethod, SslVersion},
        x509::X509,
    };
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["example.invalid".to_owned()]).unwrap();
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        server
            .set_certificate(&X509::from_der(cert.der()).unwrap())
            .unwrap();
        server
            .set_private_key(&PKey::private_key_from_der(&signing_key.serialize_der()).unwrap())
            .unwrap();
        server.set_min_proto_version(Some(version)).unwrap();
        server.set_max_proto_version(Some(version)).unwrap();
        let server = server.build();
        for jls in [false, true] {
            let config = parse(node()).unwrap();
            let SecurityConfig::Jls(mut identity) = config.security else {
                panic!()
            };
            let security = if jls {
                SecurityConfig::Jls(identity)
            } else {
                identity.tls.tls13_only = false;
                identity.tls.certificate.fingerprint = Some(Sha256::digest(cert.der()).into());
                SecurityConfig::Tls(identity.tls)
            };
            let client = SecurityClient::from_security(&security).unwrap();
            let (io, peer) = tokio::io::duplex(512);
            tokio::time::timeout(Duration::from_secs(3), async {
                let native = async {
                    let Ok(mut tls) = tokio_boring::accept(&server, peer).await else {
                        return false;
                    };
                    tls.write_all(b"hello").await.unwrap();
                    tls.flush().await.unwrap();
                    true
                };
                let consumer = async {
                    let result = client.connect(Box::new(io)).await;
                    if jls {
                        assert!(result.is_err(), "ordinary TLS must not authenticate JLS");
                    } else {
                        let mut tls = result.unwrap();
                        let mut hello = [0; 5];
                        tls.read_exact(&mut hello).await.unwrap();
                        assert_eq!(&hello, b"hello");
                    }
                };
                let (_, completed) = tokio::join!(consumer, native);
                assert_eq!(completed, !jls);
            })
            .await
            .unwrap();
        }
    }
}
