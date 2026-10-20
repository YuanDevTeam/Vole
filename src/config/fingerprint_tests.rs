use super::*;

fn yaml(protocol: &str, fields: &str) -> String {
    let auth = match protocol {
        "anytls" | "trojan" => "password: fixture",
        "vmess" => {
            "uuid: 00000000-0000-4000-8000-000000000001\n    alterId: 0\n    cipher: auto\n    tls: true"
        }
        "vless" => "uuid: 00000000-0000-4000-8000-000000000001\n    tls: true",
        _ => unreachable!(),
    };
    format!("mixed-port: 1080\nrules: [MATCH,p]\nproxies:\n  - name: p\n    type: {protocol}\n    server: example.com\n    port: 443\n    {auth}\n    {fields}\n").replace("rules: [MATCH,p]", "rules: ['MATCH,p']")
}

fn profile(config: &Config) -> Option<ClientFingerprint> {
    match &config.proxies[0].protocol {
        ProxyProtocol::AnyTls(p) => p.security.client_fingerprint(),
        ProxyProtocol::Trojan(p) => p.security.client_fingerprint(),
        ProxyProtocol::Vmess(p) => p.security.client_fingerprint(),
        ProxyProtocol::Vless(p) => match &p.security {
            SecurityConfig::Tls(tls) => tls.client_fingerprint,
            SecurityConfig::Reality(reality) => reality.client_fingerprint,
            _ => panic!("expected TLS"),
        },
        _ => unreachable!(),
    }
}

#[test]
fn named_fingerprint_is_strict_and_independent_of_certificate_pins() {
    for protocol in ["anytls", "trojan", "vmess", "vless"] {
        for (value, expected) in [
            ("chrome", Some(ClientFingerprint::Chrome133)),
            ("none", None),
            ("\"\"", None),
        ] {
            let config = Config::parse_yaml(
                yaml(
                    protocol,
                    &format!(
                        "client-fingerprint: {value}\n    fingerprint: {}",
                        "aa".repeat(32)
                    ),
                )
                .as_bytes(),
            )
            .unwrap();
            assert_eq!(profile(&config), expected);
        }
        assert_eq!(
            profile(&Config::parse_yaml(yaml(protocol, "").as_bytes()).unwrap()),
            None
        );
        for value in [
            "chrome120",
            "firefox120",
            "safari16",
            "Chrome120",
            "Chrome",
            "NONE",
            "chrome133",
            "safari16.0",
            "android11",
            "edge85",
            "3607.5",
            "qq11.1",
            "randomized",
            "chrome_psk",
            "chrome_pq",
            "null",
            "1",
            "{}",
            "[]",
            "true",
            "secret-unknown-profile",
        ] {
            let error = Config::parse_yaml(
                yaml(protocol, &format!("client-fingerprint: {value}")).as_bytes(),
            )
            .unwrap_err();
            assert!(!error.to_string().contains("secret-unknown-profile"));
        }
    }
    for protocol in ["vless", "vmess"] {
        for value in ["chrome", "firefox", "safari", "none", "\"\""] {
            assert!(
                Config::parse_yaml(
                    yaml(protocol, &format!("client-fingerprint: {value}"))
                        .replace("tls: true", "tls: false")
                        .as_bytes()
                )
                .is_err()
            );
        }
    }
}

#[test]
fn selected_names_resolve_to_eight_distinct_fixed_templates() {
    for protocol in ["anytls", "trojan", "vmess", "vless"] {
        let mut templates = Vec::new();
        for (name, expected) in [
            ("chrome", ClientFingerprint::Chrome133),
            ("firefox", ClientFingerprint::Firefox120),
            ("safari", ClientFingerprint::Safari16),
            ("ios", ClientFingerprint::Ios14),
            ("android", ClientFingerprint::Android11),
            ("edge", ClientFingerprint::Edge85),
            ("360", ClientFingerprint::ThreeSixty75),
            ("qq", ClientFingerprint::Qq111),
        ] {
            let config = Config::parse_yaml(
                yaml(protocol, &format!("client-fingerprint: {name:?}")).as_bytes(),
            )
            .unwrap();
            let selected = profile(&config).expect("enabled profile");
            assert_eq!(selected, expected);
            assert!(
                !templates.contains(&selected),
                "{name} cannot reuse another template"
            );
            templates.push(selected);
        }
    }
}

#[test]
fn download_fingerprint_inherits_and_can_be_cleared_independently() {
    for (name, template) in [
        ("chrome", ClientFingerprint::Chrome133),
        ("firefox", ClientFingerprint::Firefox120),
        ("safari", ClientFingerprint::Safari16),
    ] {
        let base = yaml(
            "vless",
            &format!(
                "network: xhttp\n    client-fingerprint: {name}\n    xhttp-opts:\n      path: /fixture\n      mode: stream-up\n      download-settings:\n        server: download.example.com"
            ),
        );
        for (extra, expected) in [
            ("", Some(template)),
            ("\n        client-fingerprint: \"\"", None),
            ("\n        client-fingerprint: none", None),
            (
                "\n        client-fingerprint: chrome",
                Some(ClientFingerprint::Chrome133),
            ),
            (
                "\n        client-fingerprint: firefox",
                Some(ClientFingerprint::Firefox120),
            ),
            (
                "\n        client-fingerprint: safari",
                Some(ClientFingerprint::Safari16),
            ),
        ] {
            let text = format!("{}{extra}\n", base.trim_end());
            let config = Config::parse_yaml(text.as_bytes()).unwrap();
            assert_eq!(profile(&config), Some(template));
            let ProxyProtocol::Vless(vless) = &config.proxies[0].protocol else {
                unreachable!()
            };
            let VlessTransport::Xhttp(xhttp) = &vless.transport else {
                unreachable!()
            };
            let SecurityConfig::Tls(tls) = &xhttp.download.as_ref().unwrap().security else {
                unreachable!()
            };
            assert_eq!(tls.client_fingerprint, expected);
        }
        assert!(
            Config::parse_yaml(
                yaml(
                    "vless",
                    &format!("network: xhttp\n    alpn: [h3]\n    client-fingerprint: {name}")
                )
                .as_bytes()
            )
            .is_err()
        );
        assert!(Config::parse_yaml(format!("{}        alpn: [h3]\n", base).as_bytes()).is_err());
        for clear in ["none", "\"\""] {
            for security in ["alpn: [h3]", "tls: false"] {
                assert!(
                    Config::parse_yaml(
                        format!("{base}        {security}\n        client-fingerprint: {clear}\n")
                            .as_bytes()
                    )
                    .is_ok()
                );
            }
        }
        for value in [
            "null",
            "true",
            "1",
            "[]",
            "{}",
            "Chrome",
            "chrome120",
            "firefox120",
            "safari16",
            "chrome133",
            "safari16.0",
        ] {
            assert!(
                Config::parse_yaml(
                    format!("{base}        client-fingerprint: {value}\n").as_bytes()
                )
                .is_err()
            );
        }
        assert!(Config::parse_yaml(format!("{}        tls: false\n", base).as_bytes()).is_err());
    }
}

#[test]
fn reality_accepts_named_profile_without_admitting_certificate_policy() {
    for (name, expected) in [
        ("chrome", Some(ClientFingerprint::Chrome133)),
        ("firefox", Some(ClientFingerprint::Firefox120)),
        ("safari", Some(ClientFingerprint::Safari16)),
        ("none", None),
        ("\"\"", None),
    ] {
        let fields = format!(
            "client-fingerprint: {name}\n    reality-opts:\n      public-key: {}",
            URL_SAFE_NO_PAD.encode([7; 32])
        );
        let config = Config::parse_yaml(yaml("vless", &fields).as_bytes()).unwrap();
        assert_eq!(profile(&config), expected);
        assert!(
            Config::parse_yaml(
                yaml("vless", &format!("skip-cert-verify: true\n    {fields}")).as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn ios_and_process_random_fingerprint_use_the_shared_entries() {
    let selected = process_random_fingerprint();
    for protocol in ["anytls", "trojan", "vmess", "vless"] {
        for (value, expected) in [("ios", ClientFingerprint::Ios14), ("random", selected)] {
            let config = Config::parse_yaml(
                yaml(protocol, &format!("client-fingerprint: {value}")).as_bytes(),
            )
            .unwrap();
            assert_eq!(profile(&config), Some(expected));
        }
    }
    assert_eq!(process_random_fingerprint(), selected);
    let mut counts = [0; 4];
    for value in 0..12 {
        counts[match weighted_fingerprint(value) {
            ClientFingerprint::Chrome133 => 0,
            ClientFingerprint::Safari16 => 1,
            ClientFingerprint::Ios14 => 2,
            ClientFingerprint::Firefox120 => 3,
            _ => unreachable!("random keeps its four-template weights"),
        }] += 1;
    }
    assert_eq!(counts, [6, 3, 2, 1]);
}

#[test]
fn tls12_profiles_reject_only_transports_that_require_tls13() {
    for profile in ["android", "360"] {
        for transport in [
            "network: xhttp",
            "flow: xtls-rprx-vision",
            "jls-opts: {username: fixture, password: fixture}",
            "shadow-tls-opts: {version: 3, password: fixture}",
            "ech-opts: {enable: true}",
        ] {
            let fields = format!("client-fingerprint: {profile:?}\n    {transport}");
            assert!(Config::parse_yaml(yaml("vless", &fields).as_bytes()).is_err());
        }
        let fields = format!(
            "network: xhttp\n    client-fingerprint: chrome\n    xhttp-opts:\n      mode: stream-up\n      download-settings:\n        client-fingerprint: {profile:?}"
        );
        assert!(Config::parse_yaml(yaml("vless", &fields).as_bytes()).is_err());
    }
}
