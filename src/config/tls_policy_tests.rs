use super::*;

fn pem(label: &str, der: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(der)
    )
}

fn node(protocol: &str) -> serde_json::Value {
    let mut node = serde_json::json!({
        "name": "edge", "type": protocol, "server": "cover.invalid", "port": 443,
        "name-cert-verify": "verified.invalid", "fingerprint": "ab".repeat(32),
    });
    match protocol {
        "anytls" | "trojan" | "hysteria2" => node["password"] = "synthetic-secret".into(),
        "vmess" | "vless" => {
            node["uuid"] = "00000000-0000-4000-8000-000000000001".into();
            node["tls"] = true.into();
        }
        "socks5" | "http" => node["tls"] = true.into(),
        _ => unreachable!(),
    }
    node
}

fn parse(node: serde_json::Value) -> Result<Config> {
    Config::parse_yaml(
        serde_yaml_ng::to_string(&serde_json::json!({"mixed-port": 1080, "proxies": [node]}))
            .unwrap()
            .as_bytes(),
    )
}

fn policy(config: &Config) -> &TlsClientPolicy {
    match &config.proxies[0].protocol {
        ProxyProtocol::AnyTls(config) => &config.tls,
        ProxyProtocol::Trojan(config) => &config.tls,
        ProxyProtocol::Vmess(config) => config.tls.as_ref().unwrap(),
        ProxyProtocol::Socks5(config) => config.tls.as_ref().unwrap(),
        _ => unreachable!(),
    }
}

fn client_identity(config: &Config) -> &TlsIdentityPem {
    let identity = match &config.proxies[0].protocol {
        ProxyProtocol::AnyTls(config) => &config.tls.identity,
        ProxyProtocol::Trojan(config) => &config.tls.identity,
        ProxyProtocol::Vmess(config) => &config.tls.as_ref().unwrap().identity,
        ProxyProtocol::Socks5(config) => &config.tls.as_ref().unwrap().identity,
        ProxyProtocol::Http(config) => &config.tls.as_ref().unwrap().identity,
        ProxyProtocol::Hysteria2(config) => &config.tls.identity,
        ProxyProtocol::Vless(config) => match &config.security {
            SecurityConfig::Tls(tls) => &tls.identity,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };
    identity.as_ref().unwrap()
}

#[test]
fn common_tls_identity_files_use_the_configuration_directory_and_inline_validation() {
    let directory = tempfile::tempdir().unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
    let certificate = pem("CERTIFICATE", identity.cert.der());
    let private_key = pem("PRIVATE KEY", &identity.signing_key.serialize_der());
    std::fs::write(directory.path().join("client.crt"), &certificate).unwrap();
    std::fs::write(directory.path().join("client.key"), &private_key).unwrap();

    for protocol in [
        "socks5",
        "anytls",
        "trojan",
        "vmess",
        #[cfg(feature = "outbound-http")]
        "http",
        #[cfg(feature = "outbound-vless")]
        "vless",
        #[cfg(feature = "outbound-hysteria2")]
        "hysteria2",
    ] {
        let mut node = node(protocol);
        node["certificate"] = "./client.crt".into();
        node["private-key"] = "./client.key".into();
        let yaml = serde_yaml_ng::to_string(&serde_json::json!({
            "mixed-port": 1080, "proxies": [node],
        }))
        .unwrap();
        let config =
            Config::parse_yaml_with_directory(yaml.as_bytes(), Some(directory.path())).unwrap();
        let loaded = client_identity(&config);
        assert_eq!(loaded.certificate, certificate);
        assert_eq!(loaded.private_key, private_key);
        assert!(!format!("{config:?}").contains("PRIVATE KEY"));
        crate::security::TlsClientIdentity::from_pem(&loaded.certificate, &loaded.private_key)
            .unwrap();
    }

    let mut absolute = node("anytls");
    absolute["certificate"] = directory.path().join("client.crt").to_str().unwrap().into();
    absolute["private-key"] = directory.path().join("client.key").to_str().unwrap().into();
    assert_eq!(
        client_identity(&parse(absolute).unwrap()).certificate,
        certificate
    );

    let mut missing = node("anytls");
    missing["certificate"] = directory
        .path()
        .join("missing.crt")
        .to_str()
        .unwrap()
        .into();
    missing["private-key"] = directory.path().join("client.key").to_str().unwrap().into();
    let error = parse(missing).unwrap_err().to_string();
    assert!(!error.contains("missing.crt") && !error.contains("PRIVATE KEY"));

    std::fs::write(directory.path().join("client.crt"), "").unwrap();
    std::fs::write(directory.path().join("client.key"), "").unwrap();
    let mut empty_files = node("anytls");
    empty_files["certificate"] = "client.crt".into();
    empty_files["private-key"] = "client.key".into();
    let yaml = serde_json::to_vec(&serde_json::json!({"proxies": [empty_files]})).unwrap();
    let error = Config::parse_yaml_with_directory(&yaml, Some(directory.path()))
        .unwrap_err()
        .to_string();
    assert!(!error.contains("client.crt") && !error.contains("client.key"));
}

#[test]
#[cfg(all(feature = "outbound-http", feature = "outbound-vless"))]
fn provider_and_xhttp_download_identity_files_share_the_data_directory() {
    let directory = tempfile::tempdir().unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
    let certificate = pem("CERTIFICATE", identity.cert.der());
    std::fs::write(directory.path().join("client.crt"), &certificate).unwrap();
    std::fs::write(
        directory.path().join("client.key"),
        pem("PRIVATE KEY", &identity.signing_key.serialize_der()),
    )
    .unwrap();
    let mut proxy = node("http");
    proxy["certificate"] = "client.crt".into();
    proxy["private-key"] = "client.key".into();
    let yaml = serde_yaml_ng::to_string(&serde_json::json!({
        "mixed-port": 1080,
        "proxy-providers": {"local": {"type": "inline", "payload": [proxy]}},
        "proxy-groups": [{"name": "selected", "type": "select", "use": ["local"]}],
    }))
    .unwrap();
    let config =
        Config::parse_yaml_with_directory(yaml.as_bytes(), Some(directory.path())).unwrap();
    assert_eq!(client_identity(&config).certificate, certificate);

    let other = rcgen::generate_simple_self_signed(vec!["download.invalid".into()]).unwrap();
    let other_certificate = pem("CERTIFICATE", other.cert.der());
    let other_key = pem("PRIVATE KEY", &other.signing_key.serialize_der());
    std::fs::write(
        directory.path().join("download-----BEGIN.crt"),
        &other_certificate,
    )
    .unwrap();
    std::fs::write(directory.path().join("download.key"), &other_key).unwrap();
    let mut proxy = node("vless");
    proxy["network"] = "xhttp".into();
    proxy["certificate"] = "client.crt".into();
    proxy["private-key"] = "client.key".into();
    proxy["xhttp-opts"] = serde_json::json!({"download-settings": {
        "certificate": "download-----BEGIN.crt", "private-key": "download.key",
    }});
    let yaml = serde_json::to_vec(&serde_json::json!({"proxies": [proxy]})).unwrap();
    let xhttp = Config::parse_yaml_with_directory(&yaml, Some(directory.path())).unwrap();
    assert_eq!(client_identity(&xhttp).certificate, certificate);
    let ProxyProtocol::Vless(proxy) = &xhttp.proxies[0].protocol else {
        unreachable!()
    };
    let SecurityConfig::Tls(download) = &proxy.download().unwrap().security else {
        unreachable!()
    };
    assert_eq!(
        download.identity.as_ref().unwrap().certificate,
        other_certificate
    );

    std::fs::write(directory.path().join("client.crt"), &other_certificate).unwrap();
    std::fs::write(directory.path().join("client.key"), &other_key).unwrap();
    let next = config
        .providers
        .as_ref()
        .unwrap()
        .materialize(&providers::ProviderContents::new())
        .unwrap();
    assert_eq!(client_identity(&next).certificate, other_certificate);
    assert_eq!(client_identity(&config).certificate, certificate);
}

#[test]
fn common_tls_policy_keeps_verified_identity_separate_from_server_name() {
    let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
    for protocol in ["anytls", "trojan", "vmess", "socks5"] {
        let mut node = node(protocol);
        node["certificate"] = pem("CERTIFICATE", identity.cert.der()).into();
        node["private-key"] = pem("PRIVATE KEY", &identity.signing_key.serialize_der()).into();
        let config = parse(node).unwrap();
        let policy = policy(&config);
        assert_eq!(
            policy.certificate.verification_name.as_deref(),
            Some("verified.invalid")
        );
        assert_eq!(policy.certificate.fingerprint, Some([0xab; 32]));
        assert!(
            crate::security::TlsClientOptions::from_policy(policy, None)
                .unwrap()
                .identity
                .is_some()
        );
        let debug = format!("{policy:?}");
        assert!(!debug.contains("PRIVATE KEY") && !debug.contains("verified.invalid"));
        assert_eq!(
            (config.proxies[0].address(), config.proxies[0].port()),
            ("cover.invalid", 443)
        );
    }
}

#[test]
fn common_tls_identity_rejects_unpaired_or_mismatched_keys() {
    let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["other.invalid".into()]).unwrap();
    for protocol in ["anytls", "trojan", "vmess", "socks5"] {
        let mut node = node(protocol);
        node["certificate"] = pem("CERTIFICATE", identity.cert.der()).into();
        assert!(parse(node.clone()).is_err());
        node["private-key"] = "".into();
        assert!(parse(node.clone()).is_err());
        node["private-key"] = pem("PRIVATE KEY", &other.signing_key.serialize_der()).into();
        let error = parse(node).unwrap_err().to_string();
        assert!(error.contains("invalid TLS client identity"));
        assert!(!error.contains("PRIVATE KEY"));
    }
}

#[test]
fn common_tls_empty_overrides_use_defaults_without_a_client_identity() {
    for protocol in [
        "anytls",
        "trojan",
        "vmess",
        "socks5",
        #[cfg(feature = "outbound-http")]
        "http",
        #[cfg(feature = "outbound-vless")]
        "vless",
        #[cfg(feature = "outbound-hysteria2")]
        "hysteria2",
    ] {
        for identity_fields in [
            serde_json::json!({"certificate": ""}),
            serde_json::json!({"private-key": ""}),
            serde_json::json!({"certificate": "", "private-key": ""}),
        ] {
            let mut node = node(protocol);
            node["fingerprint"] = "".into();
            node["name-cert-verify"] = "".into();
            node.as_object_mut()
                .unwrap()
                .extend(identity_fields.as_object().unwrap().clone());
            if matches!(protocol, "vmess" | "vless") {
                node["servername"] = "".into();
            } else if protocol != "socks5" {
                node["sni"] = "".into();
            }
            if matches!(protocol, "anytls" | "trojan" | "vmess" | "vless") {
                node["client-fingerprint"] = "".into();
            }
            let config = parse(node).unwrap();
            let (name, certificate, has_identity, has_profile) = match &config.proxies[0].protocol {
                ProxyProtocol::AnyTls(node) => (
                    node.server_name.as_str(),
                    &node.tls.certificate,
                    node.tls.identity.is_some(),
                    node.tls.client_fingerprint.is_some(),
                ),
                ProxyProtocol::Trojan(node) => (
                    node.server_name.as_str(),
                    &node.tls.certificate,
                    node.tls.identity.is_some(),
                    node.tls.client_fingerprint.is_some(),
                ),
                ProxyProtocol::Vmess(node) => {
                    let tls = node.tls.as_ref().unwrap();
                    (
                        node.server_name.as_str(),
                        &tls.certificate,
                        tls.identity.is_some(),
                        tls.client_fingerprint.is_some(),
                    )
                }
                ProxyProtocol::Socks5(node) => {
                    let tls = node.tls.as_ref().unwrap();
                    (
                        node.address.as_str(),
                        &tls.certificate,
                        tls.identity.is_some(),
                        tls.client_fingerprint.is_some(),
                    )
                }
                ProxyProtocol::Http(node) => {
                    let tls = node.tls.as_ref().unwrap();
                    (
                        tls.server_name.as_str(),
                        &tls.certificate,
                        tls.identity.is_some(),
                        tls.client_fingerprint.is_some(),
                    )
                }
                ProxyProtocol::Vless(node) => {
                    let SecurityConfig::Tls(tls) = &node.security else {
                        unreachable!()
                    };
                    (
                        tls.server_name.as_str(),
                        &tls.certificate,
                        tls.identity.is_some(),
                        tls.client_fingerprint.is_some(),
                    )
                }
                ProxyProtocol::Hysteria2(node) => (
                    node.tls.server_name.as_str(),
                    &node.tls.certificate,
                    node.tls.identity.is_some(),
                    node.tls.client_fingerprint.is_some(),
                ),
                _ => unreachable!(),
            };
            assert_eq!(name, "cover.invalid", "{protocol}");
            assert_eq!(certificate.verification_name, None, "{protocol}");
            assert_eq!(certificate.fingerprint, None, "{protocol}");
            assert!(!has_identity && !has_profile, "{protocol}");
            assert_eq!(
                (config.proxies[0].address(), config.proxies[0].port()),
                ("cover.invalid", 443)
            );
        }
    }
}
