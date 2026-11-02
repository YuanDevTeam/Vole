//! Public YAML admission for the SS2022 ShadowTLS v3 wrapper; no network IO.
use vole::config::Config;
#[cfg(feature = "shadow-tls-v3")]
use {
    serde_json::{Value, json},
    vole::config::{ClientFingerprint, ProxyProtocol, ShadowTlsConfig},
};

fn yaml(extra: &str) -> String {
    format!(
        "mixed-port: 1080\nproxies:\n  - name: ss\n    type: ss\n    server: fixture.invalid\n    port: 443\n    cipher: 2022-blake3-aes-128-gcm\n    password: BwcHBwcHBwcHBwcHBwcHBw==\n    udp: true\n{extra}\nrules: ['MATCH,ss']\n"
    )
}

#[cfg(feature = "shadow-tls-v3")]
fn node() -> Value {
    json!({"name":"ss", "type":"ss", "server":"fixture.invalid", "port":443,
        "cipher":"2022-blake3-aes-128-gcm", "password":"BwcHBwcHBwcHBwcHBwcHBw==",
        "udp":true, "plugin":"shadow-tls", "plugin-opts":{
            "version":3, "host":"cover.invalid", "password":" synthetic-private-marker "}})
}

#[cfg(feature = "shadow-tls-v3")]
fn parse(node: Value) -> vole::Result<Config> {
    Config::parse_yaml(
        &serde_json::to_vec(&json!({"mixed-port":1080,
        "proxies":[node], "rules":["MATCH,ss"]}))
        .unwrap(),
    )
}

#[cfg(feature = "shadow-tls-v3")]
fn policy(node: Value) -> ShadowTlsConfig {
    let config = parse(node).unwrap();
    let ProxyProtocol::Shadowsocks(ss) = &config.proxies[0].protocol else {
        panic!()
    };
    match ss.plugin.clone().unwrap() {
        vole::config::ShadowsocksPlugin::ShadowTls(config) => config,
        _ => panic!("expected ShadowTLS"),
    }
}

#[cfg(feature = "shadow-tls-v3")]
#[test]
fn shadowtls_preserves_policy_values_and_shared_profiles() {
    let config = policy(node());
    let mut disabled = node();
    disabled.as_object_mut().unwrap().remove("plugin-opts");
    disabled["plugin"] = json!("");
    let disabled = parse(disabled).unwrap();
    let ProxyProtocol::Shadowsocks(plain) = &disabled.proxies[0].protocol else {
        panic!()
    };
    assert!(plain.plugin.is_none());
    assert_eq!(plain.address, "fixture.invalid");
    assert_eq!(plain.port, 443);
    assert_eq!(config.password, " synthetic-private-marker ");
    assert_eq!(config.alpn, [b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(!config.certificate.skip_cert_verify);
    assert!(config.certificate.fingerprint.is_none());
    assert!(config.certificate.verification_name.is_none());
    assert_eq!(config.client_fingerprint, None);
    let mut empty_overrides = node();
    empty_overrides["plugin-opts"]["fingerprint"] = json!("");
    empty_overrides["plugin-opts"]["name-cert-verify"] = json!("");
    let defaults = policy(empty_overrides);
    assert_eq!(defaults.certificate, config.certificate);
    assert_eq!(defaults.server_name, config.server_name);
    assert_eq!(defaults.password, config.password);
    for (name, expected) in [
        ("", None),
        ("none", None),
        ("chrome", Some(ClientFingerprint::Chrome133)),
        ("firefox", Some(ClientFingerprint::Firefox120)),
        ("safari", Some(ClientFingerprint::Safari16)),
        ("ios", Some(ClientFingerprint::Ios14)),
    ] {
        let mut n = node();
        n["client-fingerprint"] = json!(name);
        assert_eq!(policy(n).client_fingerprint, expected);
    }
    let mut random = node();
    random["client-fingerprint"] = json!("random");
    let selected = policy(random.clone()).client_fingerprint;
    assert!(matches!(
        selected,
        Some(
            ClientFingerprint::Chrome133
                | ClientFingerprint::Safari16
                | ClientFingerprint::Ios14
                | ClientFingerprint::Firefox120
        )
    ));
    assert_eq!(policy(random).client_fingerprint, selected);
    for alpn in [
        vec![],
        vec!["custom".to_owned(), "h2".to_owned()],
        vec!["x".repeat(255)],
    ] {
        let mut n = node();
        n["plugin-opts"]["alpn"] = json!(alpn);
        assert_eq!(
            policy(n).alpn,
            alpn.into_iter().map(String::into_bytes).collect::<Vec<_>>()
        );
    }
    for host in ["cover.invalid", "192.0.2.7", "2001:db8::7"] {
        let mut n = node();
        let o = &mut n["plugin-opts"];
        o["host"] = json!(host);
        o["skip-cert-verify"] = json!(true);
        o["fingerprint"] = json!((0..32).map(|_| "ab").collect::<Vec<_>>().join(":"));
        o["name-cert-verify"] = json!("verified.invalid");
        let policy = policy(n);
        assert_eq!(policy.server_name, host);
        assert!(policy.certificate.skip_cert_verify);
        assert_eq!(policy.certificate.fingerprint, Some([0xab; 32]));
        assert_eq!(
            policy.certificate.verification_name.as_deref(),
            Some("verified.invalid")
        );
        let debug = format!("{policy:?}");
        for secret in ["synthetic-private-marker", "verified.invalid", host] {
            assert!(!debug.contains(secret));
        }
    }
    let mut maximum = node();
    maximum["plugin-opts"]["password"] = json!("x".repeat(65_535));
    assert_eq!(policy(maximum).password.len(), 65_535);
}

#[cfg(feature = "shadow-tls-v3")]
#[test]
fn shadowtls_rejects_invalid_types_bounds_unknown_fields_and_nulls_without_secrets() {
    let assert_rejected = |n| {
        let error = parse(n).expect_err("must reject before IO").to_string();
        assert!(!error.contains("synthetic-private-marker"), "{error}");
    };
    for key in ["plugin", "plugin-opts", "client-fingerprint"] {
        let mut n = node();
        n[key] = Value::Null;
        assert_rejected(n);
    }
    for key in [
        "version",
        "host",
        "password",
        "alpn",
        "skip-cert-verify",
        "fingerprint",
        "name-cert-verify",
    ] {
        let mut n = node();
        n["plugin-opts"][key] = Value::Null;
        assert_rejected(n);
    }
    for (key, values) in [
        (
            "version",
            vec![
                json!(1),
                json!(2),
                json!(4),
                json!(3.0),
                json!("3"),
                json!(true),
            ],
        ),
        (
            "host",
            vec![
                json!(""),
                json!("bad name"),
                json!("cover.invalid:443"),
                json!(7),
            ],
        ),
        (
            "password",
            vec![json!(""), json!("x".repeat(65_536)), json!(true), json!(7)],
        ),
        (
            "alpn",
            vec![
                json!("h2"),
                json!([""]),
                json!(["x".repeat(256)]),
                json!([7]),
                json!(vec!["x".repeat(255); 256]),
            ],
        ),
        ("skip-cert-verify", vec![json!(1), json!("true")]),
        (
            "fingerprint",
            vec![json!("ff"), json!("z".repeat(64)), json!(true)],
        ),
        ("name-cert-verify", vec![json!("bad name"), json!(false)]),
        ("strict-mode", vec![json!(true), json!(false)]),
        ("unknown", vec![json!("synthetic-private-marker")]),
    ] {
        for value in values {
            let mut n = node();
            n["plugin-opts"][key] = value;
            assert_rejected(n);
        }
    }
    for value in [
        json!("chrome133"),
        json!("randomized"),
        json!(true),
        json!([]),
    ] {
        let mut n = node();
        n["client-fingerprint"] = value;
        assert_rejected(n);
    }
    for key in ["plugin", "plugin-opts"] {
        let mut n = node();
        n.as_object_mut().unwrap().remove(key);
        assert_rejected(n);
    }
}

#[test]
fn shadowtls_requires_explicit_v3_and_a_complete_plugin_policy() {
    let fields = "    plugin: shadow-tls\n    plugin-opts: {version: 3, host: cover.invalid, password: ' secret '}";
    let result = Config::parse_yaml(yaml(fields).as_bytes());
    // This protocol is independently removable even when boring is present.
    if !cfg!(feature = "shadow-tls-v3") {
        assert!(result.is_err());
        return;
    }
    assert!(result.is_ok(), "{result:?}");
    for fields in [
        "    plugin: shadow-tls",
        "    plugin-opts: {version: 3, host: cover.invalid, password: secret}",
        "    plugin: obfs\n    plugin-opts: {version: 3, host: cover.invalid, password: secret}",
        "    client-fingerprint: none",
    ] {
        assert!(Config::parse_yaml(yaml(fields).as_bytes()).is_err());
    }
    for replacement in [
        "version: 1",
        "version: 2",
        "version: 4",
        "version: null",
        "version: '3'",
        "unused: 3",
    ] {
        let invalid = fields.replace("version: 3", replacement);
        assert!(Config::parse_yaml(yaml(&invalid).as_bytes()).is_err());
    }
}
