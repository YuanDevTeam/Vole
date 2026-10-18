#![cfg(feature = "outbound-vless")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use vole::{
    config::{Config, ProxyProtocol, SecurityConfig, VlessOutboundConfig},
    security::SecurityClient,
};

fn ech_list() -> Vec<u8> {
    let mut content = vec![7, 0, 32, 0, 32];
    content.extend_from_slice(&[7; 32]);
    content.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 14]);
    content.extend_from_slice(b"public.invalid");
    content.extend_from_slice(&[0, 0]);
    let mut list = ((content.len() + 4) as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&[0xfe, 0x0d]);
    list.extend_from_slice(&(content.len() as u16).to_be_bytes());
    list.extend_from_slice(&content);
    list
}

fn node() -> serde_json::Value {
    json!({"name":"edge", "type":"vless", "server":"example.invalid", "port":443,
        "uuid":"07070707-0707-0707-0707-070707070707", "tls":true,
        "ech-opts":{"enable":true, "config":STANDARD.encode(ech_list())}})
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
fn static_ech_builds_both_tls_backends_without_dns_or_io() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "static_ech_builds_both_tls_backends_without_dns_or_io",
    );
    for profile in ["none", "chrome", "firefox", "safari", "ios", "random"] {
        let mut input = node();
        input["client-fingerprint"] = json!(profile);
        let config = parse(input).expect("static ECH must normalize without a DNS entry point");
        SecurityClient::from_proxy(&config).expect("static ECH must build a real TLS client");
        assert!(!format!("{config:?}").contains(&STANDARD.encode(ech_list())));
    }
}

#[test]
fn ech_options_validate_types_and_static_configuration_takes_priority() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "ech_options_validate_types_and_static_configuration_takes_priority",
    );
    for ech in [
        json!(null),
        json!([]),
        json!("private-config"),
        json!({"enable":null}),
        json!({"enable":"true"}),
        json!({"enable":true,"config":42}),
        json!({"enable":true,"config":"private-config"}),
        json!({"enable":true,"query-server-name":null}),
        json!({"enable":true,"query-server-name":42}),
        json!({"enable":true,"query-server-name":"invalid name"}),
    ] {
        let mut input = node();
        input["ech-opts"] = ech;
        let error = parse(input).unwrap_err().to_string();
        assert!(!error.contains("private-config"));
        assert!(!error.contains("private.invalid"));
    }
    for ech in [
        json!({}),
        json!({"enable":false}),
        json!({"config":""}),
        json!({"enable":false,"config":"unused-invalid-Base64"}),
    ] {
        let mut input = node();
        input["ech-opts"] = ech;
        let SecurityConfig::Tls(tls) = parse(input).unwrap().security else {
            panic!()
        };
        assert!(tls.ech.is_none());
    }
    let baseline = parse(node()).unwrap();
    let mut input = node();
    input["ech-opts"]["query-server-name"] = json!("unused invalid name");
    assert_eq!(parse(input).unwrap().security, baseline.security);
    for ech in [
        json!({"enable":true}),
        json!({"enable":true,"config":""}),
        json!({"enable":true,"query-server-name":"query.invalid"}),
    ] {
        let mut input = node();
        input["ech-opts"] = ech;
        SecurityClient::from_proxy(&parse(input).unwrap()).unwrap();
    }
}

#[test]
fn unsupported_ech_configs_fail_at_parse_before_a_client_can_emit_inner_sni() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "unsupported_ech_configs_fail_at_parse_before_a_client_can_emit_inner_sni",
    );
    let valid = ech_list();
    let mut invalid = vec![vec![0, 0], vec![0, 1, 0], vec![0; 65_538]];
    for length in 1..valid.len() {
        invalid.push(valid[..length].to_vec());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    invalid.push(trailing);
    for (index, value) in [
        (2, 0),
        (8, 0x21),
        (46, 2),
        (48, 4),
        (47, 0xff),
        (50, b'.'),
        (64, b'.'),
    ] {
        let mut bytes = valid.clone();
        bytes[index] = value;
        invalid.push(bytes);
    }
    for (case, bytes) in invalid.into_iter().enumerate() {
        let mut input = node();
        input["client-fingerprint"] = json!("chrome");
        input["ech-opts"]["config"] = json!(STANDARD.encode(bytes));
        assert!(
            parse(input).is_err(),
            "unsupported or malformed fixture {case} must fail before IO"
        );
    }
}

#[test]
fn ech_selection_skips_unknown_or_mandatory_configs_and_keeps_exact_supported_bytes() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "ech_selection_skips_unknown_or_mandatory_configs_and_keeps_exact_supported_bytes",
    );
    use vole::config::StaticEchConfig;
    let valid = ech_list();
    let expected = StaticEchConfig::from_config_list(&valid).unwrap();
    let mut unknown_version = valid[2..].to_vec();
    unknown_version[..2].copy_from_slice(&[0xfe, 0x0c]);
    let mut mandatory = valid[2..].to_vec();
    let length = mandatory.len();
    mandatory[length - 2..].copy_from_slice(&4_u16.to_be_bytes());
    mandatory.extend_from_slice(&[0x80, 0, 0, 0]);
    let content_len = (mandatory.len() - 4) as u16;
    mandatory[2..4].copy_from_slice(&content_len.to_be_bytes());
    let mut duplicate = mandatory.clone();
    duplicate[length..length + 2].copy_from_slice(&[0, 1]);
    duplicate.extend_from_slice(&[0, 1, 0, 0]);
    duplicate[length - 2..length].copy_from_slice(&8_u16.to_be_bytes());
    let content_len = (duplicate.len() - 4) as u16;
    duplicate[2..4].copy_from_slice(&content_len.to_be_bytes());
    for unsupported in [unknown_version, mandatory, duplicate] {
        let mut alone = (unsupported.len() as u16).to_be_bytes().to_vec();
        alone.extend_from_slice(&unsupported);
        assert!(StaticEchConfig::from_config_list(&alone).is_err());
        let mut list = ((unsupported.len() + valid.len() - 2) as u16)
            .to_be_bytes()
            .to_vec();
        list.extend_from_slice(&unsupported);
        list.extend_from_slice(&valid[2..]);
        assert_eq!(StaticEchConfig::from_config_list(&list).unwrap(), expected);
        for profile in ["none", "chrome", "firefox", "safari"] {
            let mut input = node();
            input["client-fingerprint"] = json!(profile);
            input["ech-opts"]["config"] = json!(STANDARD.encode(&list));
            SecurityClient::from_proxy(&parse(input).unwrap()).unwrap();
        }
    }
}

#[test]
fn download_ech_inherits_replaces_or_clears_as_a_whole() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "download_ech_inherits_replaces_or_clears_as_a_whole",
    );
    let mut input = node();
    input["network"] = json!("xhttp");
    input["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{}});
    let node = parse(input.clone()).unwrap();
    assert_eq!(node.security, node.download().unwrap().security);
    let mut different = ech_list();
    different[6] = 9; // config ID
    input["xhttp-opts"]["download-settings"]["ech-opts"] =
        json!({"enable":true, "config":STANDARD.encode(different)});
    let node = parse(input.clone()).unwrap();
    assert_ne!(node.security, node.download().unwrap().security);
    SecurityClient::from_security(&node.download().unwrap().security).unwrap();
    input["xhttp-opts"]["download-settings"]["ech-opts"] = json!({"enable":true});
    let dynamic = parse(input.clone()).unwrap();
    assert_ne!(dynamic.security, dynamic.download().unwrap().security);
    SecurityClient::from_security(&dynamic.download().unwrap().security).unwrap();
    for clear in [json!({}), json!({"enable":false})] {
        input["xhttp-opts"]["download-settings"]["ech-opts"] = clear;
        let node = parse(input.clone()).unwrap();
        let SecurityConfig::Tls(tls) = &node.download().unwrap().security else {
            panic!()
        };
        assert!(tls.ech.is_none());
    }
}

#[test]
fn ech_is_standard_tls_only_with_explicit_download_clear_and_dns_inner_name() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "ech_is_standard_tls_only_with_explicit_download_clear_and_dns_inner_name",
    );
    for extra in [
        json!({"tls":false}),
        json!({"server":"127.0.0.1"}),
        json!({"flow":"xtls-rprx-vision"}),
        json!({"reality-opts":{"public-key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}),
        json!({"jls-opts":{"username":"user","password":"password"}}),
    ] {
        let mut input = node();
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(parse(input).is_err());
    }
    for download in [
        json!({"tls":false}),
        json!({"servername":"127.0.0.1"}),
        json!({"reality-opts":{"public-key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}),
        json!({"jls-opts":{"username":"user","password":"password"}}),
    ] {
        let mut input = node();
        input["network"] = json!("xhttp");
        input["xhttp-opts"] = json!({"mode":"stream-up","download-settings":download});
        assert!(parse(input.clone()).is_err());
        input["xhttp-opts"]["download-settings"]["ech-opts"] = json!({});
        parse(input).unwrap();
    }
    let mut input = node();
    input["network"] = json!("xhttp");
    input["alpn"] = json!(["h3"]);
    input["xhttp-opts"] = json!({"mode":"stream-up","download-settings":{}});
    let node = parse(input).unwrap();
    SecurityClient::from_proxy(&node).unwrap();
    SecurityClient::from_security(&node.download().unwrap().security).unwrap();
}

#[cfg(all(
    feature = "outbound-anytls",
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-hysteria2"
))]
#[test]
fn ech_is_consumed_by_every_reference_protocol_without_changing_the_tls_name() {
    for protocol in ["anytls", "trojan", "vmess", "hysteria2"] {
        for ech in [
            json!({"enable":true,"config":STANDARD.encode(ech_list())}),
            json!({"enable":true,"query-server-name":"query.invalid"}),
        ] {
            let mut input = node();
            input["type"] = json!(protocol);
            input["password"] = json!("fixture");
            input["ech-opts"] = ech;
            input.as_object_mut().unwrap().remove("uuid");
            if protocol == "vmess" {
                input.as_object_mut().unwrap().remove("password");
                input["uuid"] = json!("07070707-0707-0707-0707-070707070707");
                input["alterId"] = json!(0);
                input["cipher"] = json!("auto");
            }
            if protocol != "vmess" {
                input.as_object_mut().unwrap().remove("tls");
            }
            let config = Config::parse_yaml(
                &serde_json::to_vec(&json!({"mixed-port":1080,"proxies":[input]})).unwrap(),
            )
            .unwrap();
            match &config.proxies[0].protocol {
                ProxyProtocol::AnyTls(p) => {
                    assert!(p.security.as_tls().unwrap().ech.is_some());
                    assert_eq!(p.server_name, "example.invalid");
                }
                ProxyProtocol::Trojan(p) => {
                    assert!(p.security.as_tls().unwrap().ech.is_some());
                    assert_eq!(p.server_name, "example.invalid");
                }
                ProxyProtocol::Vmess(p) => {
                    assert!(p.security.as_tls().unwrap().ech.is_some());
                    assert_eq!(p.server_name, "example.invalid");
                }
                ProxyProtocol::Hysteria2(p) => {
                    assert!(p.tls.ech.is_some());
                    assert_eq!(p.tls.server_name, "example.invalid");
                }
                _ => panic!(),
            }
        }
    }
}

#[tokio::test]
async fn dynamic_ech_without_bound_resolution_cannot_emit_a_clear_client_hello() {
    use tokio::io::AsyncReadExt;
    for profile in ["none", "ios"] {
        let mut input = node();
        input["client-fingerprint"] = json!(profile);
        input["ech-opts"] = json!({"enable":true});
        let client = SecurityClient::from_proxy(&parse(input).unwrap()).unwrap();
        let (io, mut peer) = tokio::io::duplex(4096);
        assert!(client.connect(Box::new(io)).await.is_err());
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}
