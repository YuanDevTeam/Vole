#![cfg(feature = "outbound-trojan")]

use serde_json::{Value, json};
use vole::config::{Config, ProxyProtocol};

fn document(extra: Value) -> Vec<u8> {
    let mut node = json!({"name":"edge", "type":"trojan", "server":"localhost", "port":443, "password":" 密码 "});
    node.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::to_vec(&json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]})).unwrap()
}

#[test]
fn trojan_tcp_configuration_and_node_graph_accept_the_approved_fields() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "TROJAN-CFG",
        "trojan_tcp_configuration_and_node_graph_accept_the_approved_fields",
    );
    let yaml = b"mixed-port: 1080\nproxies:\n  - name: edge\n    type: trojan\n    server: example.com\n    port: 443\n    password: ' password '\n    udp: true\n    sni: tls.example.com\n    alpn: [h2, http/1.1]\n    skip-cert-verify: false\n    fingerprint: '0000000000000000000000000000000000000000000000000000000000000000'\n    dialer-proxy: upstream\nproxy-groups:\n  - name: upstream\n    type: select\n    proxies: [DIRECT, REJECT]\nrules: ['MATCH,edge']\n";
    let config = Config::parse_yaml(yaml).expect("TROJAN Trojan TCP configuration");
    assert_eq!(
        config.proxies[0].server_endpoint(),
        Some(("example.com", 443))
    );
    assert!(config.proxies[0].udp);
    assert!(!format!("{config:?}").contains(" password "));
}

#[test]
fn trojan_tcp_defaults_preserve_credentials_and_address_policy() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "TROJAN-CFG",
        "trojan_tcp_defaults_preserve_credentials_and_address_policy",
    );
    let parsed = Config::parse_yaml(&document(json!({}))).unwrap();
    let ProxyProtocol::Trojan(node) = &parsed.proxies[0].protocol else {
        panic!("wrong protocol")
    };
    assert_eq!(node.password, " 密码 ");
    assert_eq!(node.server_name, "localhost");
    assert!(!parsed.proxies[0].udp);
    assert!(node.tls.alpn.is_empty());
    assert!(!node.tls.certificate.skip_cert_verify);
    assert_eq!(node.tls.certificate.fingerprint, None);
    for server in ["127.0.0.1", "::1", "example.com"] {
        assert!(Config::parse_yaml(&document(json!({"server":server, "network":"tcp"}))).is_ok());
    }
    let config = Config::parse_yaml(&document(json!({"alpn":["second","first"],"skip-cert-verify":true,"fingerprint":"AB:".repeat(31)+"AB"}))).unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(node.tls.alpn, [b"second".to_vec(), b"first".to_vec()]);
    assert!(node.tls.certificate.skip_cert_verify);
    assert_eq!(node.tls.certificate.fingerprint, Some([0xab; 32]));
}

#[test]
fn trojan_invalid_configuration_is_rejected_without_exposing_credentials() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "TROJAN-CFG",
        "trojan_invalid_configuration_is_rejected_without_exposing_credentials",
    );
    for extra in [
        json!({"name":null}),
        json!({"name":3}),
        json!({"name":""}),
        json!({"password":""}),
        json!({"password":null}),
        json!({"password":123}),
        json!({"udp":null}),
        json!({"udp":"true"}),
        json!({"tls":true}),
        json!({"port":0}),
        json!({"port":65536}),
        json!({"port":null}),
        json!({"port":"443"}),
        json!({"server":"https://localhost"}),
        json!({"server":"localhost:443"}),
        json!({"server":null}),
        json!({"network":"invalid"}),
        json!({"network":null}),
        json!({"sni":"https://localhost"}),
        json!({"sni":null}),
        json!({"alpn":null}),
        json!({"alpn":12}),
        json!({"alpn":[3]}),
        json!({"alpn":[""]}),
        json!({"alpn":["x".repeat(256)]}),
        json!({"skip-cert-verify":null}),
        json!({"skip-cert-verify":"true"}),
        json!({"fingerprint":"ab"}),
        json!({"fingerprint":null}),
        json!({"fingerprint":12}),
        json!({"dialer-proxy":null}),
        json!({"dialer-proxy":12}),
        json!({"dialer-proxy":"missing"}),
        json!({"dialer-proxy":"edge"}),
        json!({"ws-opts":{}}),
        json!({"grpc-opts":{}}),
        json!({"extra-option":true}),
    ] {
        let error =
            Config::parse_yaml(&document(extra.clone())).expect_err(&format!("accepted {extra}"));
        assert!(
            !error.to_string().contains("密码"),
            "credential in parser diagnostic"
        );
    }
    for field in ["name", "type", "server", "port", "password"] {
        let mut config: Value = serde_json::from_slice(&document(json!({}))).unwrap();
        config["proxies"][0].as_object_mut().unwrap().remove(field);
        assert!(
            Config::parse_yaml(config.to_string().as_bytes()).is_err(),
            "missing {field}"
        );
    }
    let mut config: Value =
        serde_json::from_slice(&document(json!({"dialer-proxy":"unselected"}))).unwrap();
    config["proxy-groups"] =
        json!([{"name":"unselected","type":"select","proxies":["DIRECT","edge"]}]);
    assert!(
        Config::parse_yaml(config.to_string().as_bytes()).is_err(),
        "unselected graph edge forms a cycle"
    );
}

#[test]
fn trojan_ws_and_grpc_configuration_applies_transport_specific_defaults() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "TROJAN-CFG",
        "trojan_ws_and_grpc_configuration_applies_transport_specific_defaults",
    );
    let config = Config::parse_yaml(&document(json!({"network":"ws"}))).unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(node.tls.alpn, [b"http/1.1".to_vec()]);
    assert_eq!(node.server_name, "localhost");
    let vole::config::TrojanTransport::WebSocket { uri, .. } = &node.transport else {
        unreachable!()
    };
    assert_eq!(uri, "wss://localhost/");
    let config = Config::parse_yaml(&document(json!({"network":"ws","ws-opts":{"path":"/edge?q=1","headers":{"Host":"cover.example:443","X-Fixture":"yes"},"max-early-data":2048}}))).unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(
        node.server_name, "localhost",
        "Trojan SNI must not fall back to WS Host"
    );
    let config = Config::parse_yaml(&document(
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":"edge"}}),
    ))
    .unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(node.tls.alpn, [b"h2".to_vec()]);
    let vole::config::TrojanTransport::Grpc { uri, .. } = &node.transport else {
        unreachable!()
    };
    assert_eq!(uri, "https://localhost/edge/Tun");
    for service in ["Edge", "/custom/Tun"] {
        assert!(
            Config::parse_yaml(&document(
                json!({"network":"grpc","grpc-opts":{"grpc-service-name":service}})
            ))
            .is_ok()
        );
    }
}

#[test]
fn trojan_empty_defaults_and_grpc_authority_match_the_reference() {
    use vole::config::TrojanTransport;
    let config = Config::parse_yaml(&document(json!({"network":"","sni":""}))).unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert!(matches!(node.transport, TrojanTransport::Tcp));
    assert_eq!(node.server_name, "localhost");
    let config =
        Config::parse_yaml(&document(json!({"network":"ws","ws-opts":{"path":""}}))).unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let TrojanTransport::WebSocket { uri, .. } = &node.transport else {
        unreachable!()
    };
    assert_eq!(uri, "wss://localhost/");
    for (server, sni, authority) in [
        ("127.0.0.1", "", "127.0.0.1"),
        ("::1", "", "[::1]"),
        ("127.0.0.1", "cover.invalid", "cover.invalid"),
        ("127.0.0.1", "2001:db8::1", "[2001:db8::1]"),
    ] {
        let config = Config::parse_yaml(&document(json!({
            "server":server, "sni":sni, "network":"grpc",
            "name-cert-verify":"verify.invalid", "grpc-opts":{"grpc-service-name":"edge"}
        })))
        .unwrap();
        let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
            unreachable!()
        };
        let TrojanTransport::Grpc { uri, .. } = &node.transport else {
            unreachable!()
        };
        assert_eq!(uri, &format!("https://{authority}/edge/Tun"));
        assert_eq!(node.server_name, if sni.is_empty() { server } else { sni });
        assert_eq!((node.address.as_str(), node.port), (server, 443));
    }
    let config = Config::parse_yaml(&document(json!({
        "server":"127.0.0.1", "port":8443, "sni":"cover.invalid", "network":"ws",
        "ws-opts":{"headers":{"Host":"request.invalid:7443"}}
    })))
    .unwrap();
    let ProxyProtocol::Trojan(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let TrojanTransport::WebSocket { uri, headers, .. } = &node.transport else {
        unreachable!()
    };
    assert_eq!(uri, "wss://cover.invalid/");
    assert_eq!(
        headers.get("Host").map(String::as_str),
        Some("request.invalid:7443")
    );
    assert_eq!(node.server_name, "cover.invalid");
    assert_eq!((node.address.as_str(), node.port), ("127.0.0.1", 8443));
}

#[test]
fn trojan_transport_boundaries_fail_before_runtime_io() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "TROJAN-CFG",
        "trojan_transport_boundaries_fail_before_runtime_io",
    );
    for fields in [
        json!({"ws-opts":null}),
        json!({"grpc-opts":null}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":"edge?query=1"}}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":null}}),
        json!({"network":"ws","grpc-opts":{"grpc-service-name":"edge"}}),
        json!({"network":"grpc","ws-opts":{},"grpc-opts":{"grpc-service-name":"edge"}}),
        json!({"network":"ws","alpn":[]}),
        json!({"network":"ws","alpn":["h2"]}),
        json!({"network":"grpc","alpn":["http/1.1"],"grpc-opts":{"grpc-service-name":"edge"}}),
    ] {
        assert!(
            Config::parse_yaml(&document(fields.clone())).is_err(),
            "accepted {fields}"
        );
    }
    for opts in [
        json!({"path":"relative"}),
        json!({"path":null}),
        json!({"path":"/bad\r\nheader"}),
        json!({"path":"/bad#fragment"}),
        json!({"path":"/".repeat(16385)}),
        json!({"headers":null}),
        json!({"headers":{"Host":"user:secret@example.com"}}),
        json!({"headers":{"Host":"a.example", "host":"b.example"}}),
        json!({"headers":{"X-Foo":null}}),
        json!({"headers":{"X-Foo":"bad\r\nheader"}}),
        json!({"headers":{"Connection":"keep-alive"}}),
        json!({"headers":{"Upgrade":"websocket"}}),
        json!({"headers":{"Sec-WebSocket-Key":"override"}}),
        json!({"headers":{"Sec-WebSocket-Protocol":"override"}}),
        json!({"headers":{"Content-Length":"1"}}),
        json!({"max-early-data":2049}),
        json!({"max-early-data":-1}),
        json!({"max-early-data":null}),
        json!({"early-data-header-name":"x-ed"}),
        json!({"max-early-data":1,"early-data-header-name":"Host"}),
        json!({"max-early-data":1,"early-data-header-name":"Connection"}),
        json!({"max-early-data":1,"early-data-header-name":null}),
        json!({"max-early-data":1,"early-data-header-name":"x-ed","headers":{"X-ED":"duplicate"}}),
        json!({"max-early-data":1,"early-data-header-name":"","path":"/edge?q=1"}),
        json!({"v2ray-http-upgrade":null}),
    ] {
        assert!(
            Config::parse_yaml(&document(json!({"network":"ws","ws-opts":opts.clone()}))).is_err(),
            "accepted WS options {opts}"
        );
    }
    for max in [0, 1, 2048] {
        for header in [None, Some("x-vole-ed"), Some("")] {
            if max == 0 && header.is_some() {
                continue;
            }
            let mut opts = json!({"max-early-data":max});
            if let Some(name) = header {
                opts["early-data-header-name"] = json!(name);
            }
            assert!(Config::parse_yaml(&document(json!({"network":"ws","ws-opts":opts}))).is_ok());
        }
    }
    for host in ["cover.example:443", "[::1]:443"] {
        assert!(
            Config::parse_yaml(&document(
                json!({"network":"ws","ws-opts":{"headers":{"Host":host}}})
            ))
            .is_ok()
        );
    }
}
