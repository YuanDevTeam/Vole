//! Pure configuration and constructor checks; no sockets or resolver calls.
use crate::config::{Config, ProxyProtocol, SecurityConfig};
use serde_json::{Value, json};

fn node(protocol: &str) -> Value {
    let mut node = json!({"name":"edge", "type":protocol, "server":"cover.invalid", "port":443});
    match protocol {
        "vmess" | "vless" => {
            node["uuid"] = json!("00000000-0000-4000-8000-000000000001");
            node["tls"] = json!(true);
        }
        "trojan" | "anytls" => node["password"] = json!("synthetic-proxy-password"),
        _ => unreachable!(),
    }
    node
}

fn parse(node: Value) -> crate::Result<Config> {
    Config::parse_yaml(
        &serde_json::to_vec(&json!({"proxies":[node], "rules":["MATCH,edge"]})).unwrap(),
    )
}

fn security(config: &Config) -> &SecurityConfig {
    match &config.proxies[0].protocol {
        ProxyProtocol::Vmess(node) => &node.security,
        ProxyProtocol::Vless(node) => &node.security,
        ProxyProtocol::Trojan(node) => &node.security,
        ProxyProtocol::AnyTls(node) => &node.security,
        _ => unreachable!(),
    }
}

fn shadow() -> Value {
    json!({"version":3, "password":"synthetic-cover-password"})
}

fn jls() -> Value {
    json!({"username":"synthetic-jls-user", "password":"synthetic-jls-password"})
}

fn reality() -> Value {
    json!({"public-key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", "short-id":"01ab"})
}

#[test]
fn common_identities_construct_for_each_supported_tcp_protocol() {
    let context = crate::security::SecurityContext::new();
    for protocol in ["vmess", "vless", "trojan", "anytls"] {
        for (field, identity) in [("shadow-tls-opts", shadow()), ("jls-opts", jls())] {
            let mut node = node(protocol);
            node[field] = identity;
            let config = parse(node).unwrap();
            let security = security(&config);
            assert!(matches!(
                (field, security),
                ("shadow-tls-opts", SecurityConfig::ShadowTls(_))
                    | ("jls-opts", SecurityConfig::Jls(_))
            ));
            crate::security::SecurityClient::from_security_with_context(
                security, &context, 0, 8192,
            )
            .unwrap();
            let debug = format!("{config:?}");
            for secret in [
                "synthetic-cover-password",
                "synthetic-jls-user",
                "synthetic-jls-password",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }
}

#[test]
fn reality_is_consumed_only_by_supported_stream_tls_transports() {
    for (protocol, networks) in [
        ("vmess", &["tcp", "http", "h2", "grpc"][..]),
        ("trojan", &["tcp", "grpc"][..]),
    ] {
        for network in networks {
            let mut node = node(protocol);
            node["network"] = json!(network);
            node["client-fingerprint"] = json!("chrome");
            node["reality-opts"] = reality();
            let config = parse(node).unwrap();
            assert!(matches!(security(&config), SecurityConfig::Reality(_)));
            crate::security::SecurityClient::from_security(security(&config)).unwrap();
        }
        let mut websocket = node(protocol);
        websocket["network"] = json!("ws");
        websocket["client-fingerprint"] = json!("chrome");
        websocket["reality-opts"] = reality();
        assert!(parse(websocket).is_err());
        let mut unnamed = node(protocol);
        unnamed["reality-opts"] = reality();
        assert!(parse(unnamed).is_err());
    }
}

#[test]
fn vless_websocket_and_both_upgrade_modes_do_not_admit_reality() {
    for options in [
        json!({}),
        json!({"v2ray-http-upgrade":true}),
        json!({"v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":true}),
    ] {
        let mut input = node("vless");
        input["network"] = json!("ws");
        input["ws-opts"] = options;
        input["client-fingerprint"] = json!("chrome");
        input["reality-opts"] = reality();
        assert!(parse(input).is_err());
    }
}

#[test]
fn incompatible_identities_and_unconsumed_fields_fail_before_io() {
    for protocol in ["vmess", "vless", "trojan", "anytls"] {
        for value in [
            json!({}),
            json!({"version":2,"password":"synthetic-cover-password"}),
            json!({"version":3,"password":""}),
            json!({"version":3,"password":"synthetic-cover-password", "host":"unused.invalid"}),
            Value::Null,
        ] {
            let mut input = node(protocol);
            input["shadow-tls-opts"] = value;
            let error = parse(input).unwrap_err().to_string();
            assert!(!error.contains("synthetic-cover-password"));
        }
        let mut conflict = node(protocol);
        conflict["shadow-tls-opts"] = shadow();
        conflict["jls-opts"] = jls();
        assert!(parse(conflict).is_err());
        for identity in ["shadow-tls-opts", "jls-opts"] {
            let mut ech = node(protocol);
            ech[identity] = if identity == "jls-opts" {
                jls()
            } else {
                shadow()
            };
            ech["ech-opts"] = json!({"enable":true});
            assert!(parse(ech).is_err());
        }
        let mut certificate = node(protocol);
        certificate["jls-opts"] = jls();
        certificate["skip-cert-verify"] = json!(false);
        assert!(parse(certificate).is_err());
    }
    for protocol in ["vmess", "vless"] {
        let mut plain = node(protocol);
        plain["tls"] = json!(false);
        plain["shadow-tls-opts"] = shadow();
        assert!(parse(plain).is_err());
    }
    let mut vision = node("vless");
    vision["flow"] = json!("xtls-rprx-vision");
    vision["shadow-tls-opts"] = shadow();
    assert!(parse(vision).is_err());
}

#[test]
fn xhttp_cover_identities_inherit_replace_and_clear_per_leg() {
    let mut input = node("vless");
    input["network"] = json!("xhttp");
    input["shadow-tls-opts"] = shadow();
    input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{"server":"download.invalid", "alpn":["http/1.1"]}});
    let config = parse(input.clone()).unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        panic!()
    };
    let SecurityConfig::ShadowTls(main) = &node.security else {
        panic!()
    };
    let SecurityConfig::ShadowTls(download) = &node.download().unwrap().security else {
        panic!()
    };
    assert_eq!(main.server_name, "cover.invalid");
    assert_eq!(download.server_name, "download.invalid");
    assert_eq!(main.password, download.password);
    assert_eq!(main.required_alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(download.required_alpn.as_deref(), Some(&b"http/1.1"[..]));

    input["xhttp-opts"]["download-settings"]["shadow-tls-opts"] =
        json!({"version":3,"password":"different-cover-password"});
    let replaced = parse(input.clone()).unwrap();
    let ProxyProtocol::Vless(node) = &replaced.proxies[0].protocol else {
        panic!()
    };
    let SecurityConfig::ShadowTls(download) = &node.download().unwrap().security else {
        panic!()
    };
    assert_eq!(download.password, "different-cover-password");

    input["xhttp-opts"]["download-settings"]["jls-opts"] = jls();
    assert!(parse(input.clone()).is_err());
    input["xhttp-opts"]["download-settings"]["shadow-tls-opts"] = json!({});
    let switched = parse(input.clone()).unwrap();
    let ProxyProtocol::Vless(node) = &switched.proxies[0].protocol else {
        panic!()
    };
    assert!(matches!(
        node.download().unwrap().security,
        SecurityConfig::Jls(_)
    ));
    input["xhttp-opts"]["download-settings"]["jls-opts"] = json!({});
    let cleared = parse(input.clone()).unwrap();
    let ProxyProtocol::Vless(node) = &cleared.proxies[0].protocol else {
        panic!()
    };
    assert!(matches!(
        node.download().unwrap().security,
        SecurityConfig::Tls(_)
    ));
    input["alpn"] = json!(["h3"]);
    assert!(parse(input).is_err());
}

#[test]
fn cover_mtls_files_use_the_existing_generation_identity_budget() {
    let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    use base64::Engine as _;
    let pem = |label: &str, bytes: &[u8]| {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    };
    std::fs::write(
        directory.path().join("client.crt"),
        pem("CERTIFICATE", identity.cert.der()),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("client.key"),
        pem("PRIVATE KEY", &identity.signing_key.serialize_der()),
    )
    .unwrap();
    for protocol in ["vmess", "vless", "trojan", "anytls", "ss"] {
        let mut input = if protocol == "ss" {
            json!({"name":"edge", "type":"ss", "server":"cover.invalid", "port":443,
                "cipher":"2022-blake3-aes-128-gcm", "password":"BwcHBwcHBwcHBwcHBwcHBw==",
                "plugin":"shadow-tls", "plugin-opts":{"version":3,"host":"cover.invalid","password":"synthetic-cover-password"}})
        } else {
            let mut input = node(protocol);
            input["shadow-tls-opts"] = shadow();
            input
        };
        let policy = if protocol == "ss" {
            &mut input["plugin-opts"]
        } else {
            &mut input
        };
        policy["certificate"] = json!("client.crt");
        policy["private-key"] = json!("client.key");
        let yaml = serde_json::to_vec(&json!({"proxies":[input]})).unwrap();
        let config = Config::parse_yaml_with_directory(&yaml, Some(directory.path())).unwrap();
        let cover = match &config.proxies[0].protocol {
            ProxyProtocol::Shadowsocks(node) => match node.plugin.as_ref().unwrap() {
                crate::config::ShadowsocksPlugin::ShadowTls(config) => config,
                _ => panic!("expected ShadowTLS"),
            },
            _ => {
                let SecurityConfig::ShadowTls(cover) = security(&config) else {
                    panic!()
                };
                cover
            }
        };
        assert!(cover.identity.is_some());
        crate::security::ShadowTlsClient::new(&crate::security::SecurityContext::new(), cover)
            .unwrap();
        assert!(!format!("{config:?}").contains("PRIVATE KEY"));
    }
}
