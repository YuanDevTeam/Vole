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
        "anytls" | "trojan" => node["password"] = "synthetic-secret".into(),
        "vmess" => {
            node["uuid"] = "00000000-0000-4000-8000-000000000001".into();
            node["tls"] = true.into();
        }
        "socks5" => node["tls"] = true.into(),
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
        node["private-key"] = pem("PRIVATE KEY", &other.signing_key.serialize_der()).into();
        let error = parse(node).unwrap_err().to_string();
        assert!(error.contains("invalid TLS client identity"));
        assert!(!error.contains("PRIVATE KEY"));
    }
}
