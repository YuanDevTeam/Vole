use vole::config::Config;

#[test]
fn hysteria2_configuration_follows_its_protocol_feature() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "HYSTERIA2-CFG",
        "hysteria2_configuration_follows_its_protocol_feature",
    );
    let yaml = b"mixed-port: 1080\nproxies: [{name: edge, type: hysteria2, server: localhost, port: 443}]\nrules: ['MATCH,edge']\n";
    let result = Config::parse_yaml(yaml);
    assert_eq!(result.is_ok(), cfg!(feature = "outbound-hysteria2"));
    if let Ok(config) = result {
        assert_eq!(config.proxies[0].address(), "localhost");
        assert_eq!(config.proxies[0].port(), 443);
        assert!(!config.proxies[0].udp);
    }
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
fn hysteria2_accepts_the_approved_tls_bandwidth_obfs_and_hopping_configuration() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "HYSTERIA2-CFG",
        "hysteria2_accepts_the_approved_tls_bandwidth_obfs_and_hopping_configuration",
    );
    let yaml = b"mixed-port: 1080\nproxies:\n  - name: edge\n    type: hysteria2\n    server: localhost\n    ports: 443,8443-8445,8443\n    password: ' credential '\n    udp: true\n    up: 2 Mbps\n    down: 125 KBps\n    udp-mtu: 1200\n    hop-interval: 5-7\n    obfs: salamander\n    obfs-password: ' independent secret '\n    sni: tls.example.com\n    alpn: [custom-h3]\n    skip-cert-verify: true\n    dialer-proxy: upstream\nproxy-groups: [{name: upstream, type: select, proxies: [DIRECT, REJECT]}]\nrules: ['MATCH,edge']\n";
    let config = Config::parse_yaml(yaml).expect("approved Hysteria2 fields");
    assert_eq!(config.proxies[0].port(), 443);
    assert!(config.proxies[0].udp);
    assert!(config.proxies[0].dialer_proxy.is_some());
    assert!(!format!("{config:?}").contains("credential"));
    assert!(!format!("{config:?}").contains("independent secret"));
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
fn hysteria2_fields_are_strict_normalized_and_credentials_are_not_trimmed() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "HYSTERIA2-CFG",
        "hysteria2_fields_are_strict_normalized_and_credentials_are_not_trimmed",
    );
    use serde_json::{Value, json};
    use vole::config::ProxyProtocol;
    let base = json!({"name":"edge", "type":"hysteria2", "server":"localhost", "port":443});
    let parse = |raw: Value| {
        Config::parse_yaml(
            json!({"mixed-port":1080, "proxies":[raw], "rules":["MATCH,edge"]})
                .to_string()
                .as_bytes(),
        )
    };
    let normalized = |raw: Value| {
        let config = parse(raw).unwrap();
        let ProxyProtocol::Hysteria2(node) = config.proxies.into_iter().next().unwrap().protocol
        else {
            panic!()
        };
        node
    };
    let defaults = normalized(base.clone());
    for field in ["obfs", "ports"] {
        let mut raw = base.clone();
        raw[field] = json!("");
        assert_eq!(normalized(raw), defaults, "empty {field} uses defaults");
    }
    for field in [
        "name",
        "server",
        "port",
        "password",
        "udp",
        "sni",
        "alpn",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "up",
        "down",
        "udp-mtu",
        "obfs",
        "obfs-password",
        "ports",
        "hop-interval",
        "dialer-proxy",
    ] {
        for wrong in [Value::Null, json!({"invalid":"type"})] {
            let mut raw = base.clone();
            raw[field] = wrong;
            assert!(
                parse(raw).is_err(),
                "{field} must reject null and object types"
            );
        }
    }
    assert_eq!((defaults.up, defaults.down, defaults.udp_mtu), (0, 0, 1400));
    assert_eq!(defaults.password, "");
    assert_eq!(defaults.tls.server_name, "localhost");
    assert_eq!(defaults.tls.alpn, vec![b"h3".to_vec()]);
    assert!(defaults.tls.tls13_only);
    let mut raw = base.clone();
    raw["sni"] = json!("public.example.com");
    raw["name-cert-verify"] = json!("verified.example.com");
    let node = normalized(raw.clone());
    assert_eq!(node.tls.server_name, "public.example.com");
    assert_eq!(
        node.tls.certificate.verification_name.as_deref(),
        Some("verified.example.com")
    );
    raw["name-cert-verify"] = json!("bad\nname");
    assert!(parse(raw).is_err());
    for (value, expected) in [
        (json!(2), 250000),
        (json!("2"), 250000),
        (json!("2 Mbps"), 250000),
        (json!("125 KBps"), 125000),
        (json!("1Gbps"), 125000000),
        (json!("1 TBps"), 1000000000000),
        (json!("8 bps"), 1),
        (json!("1 bps"), 0),
        (json!(0), 0),
    ] {
        for field in ["up", "down"] {
            let mut raw = base.clone();
            raw[field] = value.clone();
            let node = normalized(raw);
            assert_eq!(if field == "up" { node.up } else { node.down }, expected);
        }
    }
    let mut raw = base.clone();
    raw["ports"] = json!("8443-8445,443,8444");
    raw["hop-interval"] = json!("5-7");
    raw["password"] = json!("  raw credential  ");
    raw["udp-mtu"] = json!(0);
    raw["alpn"] = json!([]);
    let node = normalized(raw.clone());
    assert_eq!(node.password, "  raw credential  ");
    assert_eq!(node.port, 443);
    assert_eq!(node.udp_mtu, 1400);
    let hopping = node.hopping.unwrap();
    assert_eq!(hopping.ports, vec![443, 8443, 8444, 8445]);
    assert_eq!((hopping.min_seconds, hopping.max_seconds), (5, 7));
    raw.as_object_mut().unwrap().remove("port");
    assert!(parse(raw.clone()).is_ok());
    for interval in [json!(5), json!("5"), json!("4294967295")] {
        raw["hop-interval"] = interval;
        assert!(parse(raw.clone()).is_ok());
    }
    for mtu in [64, 65535] {
        let mut raw = base.clone();
        raw["udp-mtu"] = json!(mtu);
        assert!(parse(raw).is_ok());
    }
    for (field, values) in [
        (
            "up",
            vec![
                json!(-1),
                json!(1.5),
                json!("1.5 Mbps"),
                json!("+1 Mbps"),
                json!("1 MiBps"),
                json!("18446744073709551615 TBps"),
                Value::Null,
            ],
        ),
        (
            "udp-mtu",
            vec![json!(1), json!(63), json!(65536), json!(-1), Value::Null],
        ),
        (
            "ports",
            vec![
                json!("1,,2"),
                json!("2-1"),
                json!("0"),
                json!("65536"),
                json!("*"),
                json!([443]),
                Value::Null,
            ],
        ),
        (
            "alpn",
            vec![
                json!([""]),
                json!(["a".repeat(256)]),
                json!("h3"),
                Value::Null,
            ],
        ),
        (
            "password",
            vec![
                json!("bad\r\nheader"),
                json!("a".repeat(8193)),
                json!(12),
                Value::Null,
            ],
        ),
        ("port", vec![json!(0), json!(65536), Value::Null]),
        ("fingerprint", vec![json!("not-a-hash"), Value::Null]),
    ] {
        for value in values {
            let mut raw = base.clone();
            raw[field] = value;
            assert!(parse(raw).is_err(), "{field}");
        }
    }
    for (field, value) in [
        ("tls", json!(false)),
        ("network", json!("tcp")),
        ("client-fingerprint", json!("chrome")),
        ("certificate", json!("bad")),
        ("private-key", json!("bad")),
        ("obfs", json!("salamander")),
        ("obfs-password", json!("secret")),
        ("hop-interval", json!(5)),
    ] {
        let mut raw = base.clone();
        raw[field] = value;
        assert!(parse(raw).is_err(), "{field}");
    }
    for value in [
        json!(0),
        json!(4),
        json!("7-5"),
        json!("5s"),
        json!("4294967296"),
        Value::Null,
    ] {
        let mut raw = base.clone();
        raw["ports"] = json!("443");
        raw["hop-interval"] = value;
        assert!(parse(raw).is_err());
    }
    for value in [json!(""), json!("gecko")] {
        let mut raw = base.clone();
        raw["obfs"] = value;
        raw["obfs-password"] = json!("secret");
        assert!(parse(raw).is_err());
    }
}

#[cfg(feature = "outbound-hysteria2")]
#[test]
fn receive_windows_are_independent_and_preserve_initial_above_maximum() {
    use vole::config::{ProxyProtocol, QuicReceiveWindow};
    let parse = |fields: &str| {
        let yaml = format!(
            "mixed-port: 1080\nproxies:\n  - name: edge\n    type: hysteria2\n    server: localhost\n    port: 443\n{fields}rules: ['MATCH,edge']\n"
        );
        let c = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let ProxyProtocol::Hysteria2(config) = c.proxies.into_iter().next().unwrap().protocol
        else {
            panic!("HY2")
        };
        config
    };
    let defaults = parse("");
    assert_eq!(
        defaults.stream_window,
        QuicReceiveWindow {
            initial: 64 * 1024,
            maximum: 64 * 1024
        }
    );
    assert_eq!(
        defaults.connection_window,
        QuicReceiveWindow {
            initial: 4 * 1024 * 1024,
            maximum: 4 * 1024 * 1024
        }
    );
    let large = parse(
        "    initial-connection-receive-window: 20971520\n    max-connection-receive-window: 16777216\n",
    );
    assert_eq!(
        large.connection_window,
        QuicReceiveWindow {
            initial: 20 * 1024 * 1024,
            maximum: 16 * 1024 * 1024,
        }
    );
    let config = parse(
        "    initial-stream-receive-window: 400\n    max-stream-receive-window: 200\n    initial-connection-receive-window: 600\n    max-connection-receive-window: 1200\n    handshake-timeout: 2\n",
    );
    assert_eq!(
        config.stream_window,
        QuicReceiveWindow {
            initial: 400,
            maximum: 200
        }
    );
    assert_eq!(
        config.connection_window,
        QuicReceiveWindow {
            initial: 600,
            maximum: 1200
        }
    );
    assert_eq!(config.handshake_timeout, std::time::Duration::from_secs(2));
    let config =
        parse("    max-stream-receive-window: 18446744073709551615\n    handshake-timeout: -1\n");
    assert_eq!(config.stream_window.maximum, (1_u64 << 62) - 1);
    assert!(config.handshake_timeout.is_zero());
}
