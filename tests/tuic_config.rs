use serde_json::{Value, json};
use vole::config::Config;

fn node() -> Value {
    json!({"name":"tuic","type":"tuic","server":"peer.invalid","port":443,
        "uuid":"01234567-89ab-cdef-0123-456789abcdef","password":""})
}

fn parse(node: Value) -> vole::Result<Config> {
    Config::parse_yaml(
        json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,tuic"]})
            .to_string()
            .as_bytes(),
    )
}

#[test]
fn v5_identity_defaults_password_without_enabling_business_udp() {
    if !cfg!(feature = "outbound-tuic") {
        assert!(parse(node()).is_err());
        return;
    }
    let c = parse(node()).unwrap();
    assert!(!c.proxies[0].udp);
    assert_eq!(c.proxies[0].server_endpoint(), Some(("peer.invalid", 443)));
    let mut n = node();
    n.as_object_mut().unwrap().remove("password");
    let c = parse(n).unwrap();
    let vole::config::ProxyProtocol::Tuic(t) = &c.proxies[0].protocol else {
        panic!("protocol");
    };
    assert_eq!(t.password, "");
    assert!(!c.proxies[0].udp);
    let mut n = node();
    n.as_object_mut().unwrap().remove("uuid");
    assert!(parse(n).is_err());
}

#[test]
fn malformed_tuic_values_do_not_leak_input_in_errors() {
    for field in ["uuid", "port", "alpn", "congestion-controller"] {
        let mut n = node();
        n[field] = json!("synthetic-private-marker");
        let error = parse(n).unwrap_err().to_string();
        assert!(!error.contains("synthetic-private-marker"), "{error}");
    }
}

#[cfg(feature = "outbound-tuic")]
#[test]
fn v5_business_udp_accepts_exactly_native_or_quic() {
    let mut n = node();
    n["udp"] = json!(true);
    assert!(parse(n.clone()).is_ok());
    for mode in ["native", "quic"] {
        n["udp-relay-mode"] = json!(mode);
        assert!(parse(n.clone()).is_ok());
    }
    for bad in [
        Value::Null,
        json!("tcp"),
        json!("uot"),
        json!(1),
        json!(true),
        json!(""),
    ] {
        n["udp-relay-mode"] = bad;
        assert!(parse(n.clone()).is_err());
    }
}

#[cfg(feature = "outbound-tuic")]
#[test]
fn strict_v5_tls_and_identity_bounds_preserve_values() {
    use vole::config::{ProxyProtocol, TuicCongestion};
    let extract = |n| {
        let c = parse(n).unwrap();
        let ProxyProtocol::Tuic(t) = c.proxies.into_iter().next().unwrap().protocol else {
            panic!("protocol");
        };
        t
    };
    let t = extract(node());
    assert_eq!(t.tls.server_name, "peer.invalid");
    assert_eq!(t.tls.alpn, [b"h3".to_vec()]);
    assert!(t.tls.tls13_only);
    assert_eq!(t.congestion, TuicCongestion::Cubic);
    let mut n = node();
    n["sni"] = json!("");
    n["name-cert-verify"] = json!("");
    n["fingerprint"] = json!("");
    let t = extract(n);
    assert_eq!(t.tls.server_name, "peer.invalid");
    assert_eq!(t.tls.certificate.verification_name, None);
    assert_eq!(t.tls.certificate.fingerprint, None);
    for password in [String::new(), " 原样\t\0 ".to_string(), "x".repeat(65535)] {
        let mut n = node();
        n["password"] = json!(password);
        assert_eq!(extract(n).password, password);
    }
    for (value, expected) in [
        ("new_reno", TuicCongestion::NewReno),
        ("bbr", TuicCongestion::Bbr),
        ("cubic", TuicCongestion::Cubic),
    ] {
        let mut n = node();
        n["congestion-controller"] = json!(value);
        assert_eq!(extract(n).congestion, expected);
    }
    let mut n = node();
    n["sni"] = json!("sni.invalid");
    n["name-cert-verify"] = json!("verified.invalid");
    n["alpn"] = json!(["custom", "h3"]);
    n["skip-cert-verify"] = json!(true);
    n["fingerprint"] = json!("12".repeat(32));
    let t = extract(n);
    assert_eq!(t.tls.alpn, [b"custom".to_vec(), b"h3".to_vec()]);
    assert_eq!(t.tls.certificate.fingerprint, Some([0x12; 32]));
    assert_eq!(
        t.tls.certificate.verification_name.as_deref(),
        Some("verified.invalid")
    );
    assert!(t.tls.certificate.skip_cert_verify);
    for value in [
        "peer.invalid",
        "sni.invalid",
        "verified.invalid",
        "01234567-89ab-cdef-0123-456789abcdef",
    ] {
        assert!(!format!("{t:?}").contains(value));
    }
    for (field, bad) in [
        ("password", json!("x".repeat(65536))),
        ("uuid", json!("0123456789abcdef0123456789abcdef")),
        ("port", json!(0)),
        ("port", json!(65536)),
        ("server", json!("")),
        ("name-cert-verify", json!("bad\nname")),
        ("alpn", json!([])),
        ("alpn", json!([""])),
        ("alpn", json!(["x".repeat(256)])),
        ("alpn", json!(vec!["x".repeat(255); 256])),
        ("congestion-controller", json!("reno")),
        ("fingerprint", json!("bad-pin")),
        ("client-fingerprint", json!("none")),
        ("reduce-rtt", json!(true)),
        ("version", json!(4)),
        ("certificate", json!("unsupported")),
        ("private-key", json!("unsupported")),
    ] {
        let mut n = node();
        n[field] = bad;
        assert!(parse(n).is_err(), "{field}");
    }
    for field in [
        "server",
        "port",
        "uuid",
        "password",
        "sni",
        "alpn",
        "skip-cert-verify",
        "fingerprint",
        "name-cert-verify",
        "congestion-controller",
        "dialer-proxy",
        "udp",
    ] {
        let mut n = node();
        n[field] = Value::Null;
        assert!(parse(n).is_err(), "{field}");
    }
}

#[cfg(feature = "outbound-tuic")]
#[test]
fn quic_fields_consume_defaults_and_reversed_fixed_windows() {
    use vole::config::{ProxyProtocol, QuicReceiveWindow};
    let extract = |n| {
        let c = parse(n).unwrap();
        let ProxyProtocol::Tuic(config) = c.proxies.into_iter().next().unwrap().protocol else {
            panic!("TUIC")
        };
        config
    };
    let defaults = extract(node());
    assert_eq!(
        defaults.stream_window,
        QuicReceiveWindow {
            initial: 15 * 1024 * 1024 / 10,
            maximum: 15 * 1024 * 1024
        }
    );
    assert_eq!(
        defaults.connection_window,
        QuicReceiveWindow {
            initial: 2 * 1024 * 1024,
            maximum: 64 * 1024 * 1024
        }
    );
    let mut zero = node();
    zero["recv-window-conn"] = json!(0);
    zero["recv-window"] = json!(0);
    let zero = extract(zero);
    assert_eq!(zero.stream_window, defaults.stream_window);
    assert_eq!(zero.connection_window, defaults.connection_window);
    let mut larger = node();
    larger["recv-window"] = json!(8 * 1024 * 1024);
    let larger = extract(larger);
    assert_eq!(larger.stream_window, defaults.stream_window);
    assert_eq!(
        larger.connection_window,
        QuicReceiveWindow {
            initial: 8 * 1024 * 1024,
            maximum: 8 * 1024 * 1024
        }
    );
    assert_eq!(defaults.max_open_streams, 89);
    assert!(!defaults.udp_over_stream);
    assert_eq!(
        defaults.heartbeat_interval,
        std::time::Duration::from_secs(10)
    );
    assert_eq!(defaults.max_datagram_frame_size, 1281);
    assert_eq!(defaults.max_udp_relay_packet_size, 1252);
    let mut n = node();
    n["ip"] = json!("192.0.2.1");
    n["heartbeat-interval"] = json!(12);
    n["recv-window-conn"] = json!(17);
    n["recv-window"] = json!(29);
    n["max-open-streams"] = json!(3);
    n["max-datagram-frame-size"] = json!(80);
    n["max-udp-relay-packet-size"] = json!(999);
    n["disable-mtu-discovery"] = json!(true);
    n["udp-over-stream"] = json!(true);
    n["udp-over-stream-version"] = json!(2);
    let t = extract(n.clone());
    assert_eq!(t.address, "peer.invalid");
    assert_eq!(t.tls.server_name, "peer.invalid");
    assert_eq!(t.ip.as_deref(), Some("192.0.2.1"));
    assert_eq!(t.heartbeat_interval, std::time::Duration::from_millis(12));
    assert_eq!(
        t.stream_window,
        QuicReceiveWindow {
            initial: 17,
            maximum: 17
        }
    );
    assert_eq!(
        t.connection_window,
        QuicReceiveWindow {
            initial: 29,
            maximum: 29
        }
    );
    assert_eq!(t.max_open_streams, 2);
    assert_eq!(t.max_datagram_frame_size, 80);
    assert_eq!(t.max_udp_relay_packet_size, 51);
    assert!(t.disable_mtu_discovery);
    assert!(t.udp_over_stream);
    n["max-datagram-frame-size"] = json!(1);
    let tiny = extract(n.clone());
    assert_eq!(tiny.max_datagram_frame_size, 1);
    assert_eq!(tiny.max_udp_relay_packet_size, 0);
    n["max-open-streams"] = json!(1);
    assert_eq!(extract(n.clone()).max_open_streams, 0);
    n["max-open-streams"] = json!(-1);
    assert_eq!(extract(n.clone()).max_open_streams, 0);
    n["max-open-streams"] = json!(i64::MAX);
    assert_eq!(extract(n.clone()).max_open_streams, i64::MAX as usize - 1);
}

#[cfg(feature = "outbound-tuic")]
#[test]
fn uot_is_opt_in_and_accepts_only_explicit_or_default_v2() {
    for enabled in [false, true] {
        let mut n = node();
        n["udp-over-stream"] = json!(enabled);
        for version in [None, Some(json!(2))] {
            if let Some(version) = version {
                n["udp-over-stream-version"] = version;
            }
            let c = parse(n.clone()).unwrap();
            let vole::config::ProxyProtocol::Tuic(t) = &c.proxies[0].protocol else {
                panic!("TUIC");
            };
            assert_eq!(t.udp_over_stream, enabled);
        }
        for bad in [
            json!(0),
            json!(1),
            json!(3),
            json!(-1),
            json!(256),
            json!(2.0),
            json!("2"),
            Value::Null,
            json!(true),
            json!({}),
        ] {
            n["udp-over-stream-version"] = bad;
            assert!(parse(n.clone()).is_err());
        }
    }
}
