#![cfg(feature = "outbound-vless")]
use serde_json::{Value, json};
use vole::config::Config;

#[test]
fn inline_client_identity_is_validated_and_redacted_before_io() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "inline_client_identity_is_validated_and_redacted_before_io",
    );
    use base64::Engine as _;
    let pem = |kind: &str, der: &[u8]| {
        format!(
            "-----BEGIN {kind}-----\n{}\n-----END {kind}-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    };
    let identity = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
    let certificate = pem("CERTIFICATE", identity.cert.der());
    let private_key = pem("PRIVATE KEY", &identity.signing_key.serialize_der());
    let config = Config::parse_yaml(&document(
        json!({"tls":true,"certificate":certificate,"private-key":private_key}),
    ))
    .unwrap();
    assert!(!format!("{config:?}").contains("BEGIN"));
    let other = rcgen::generate_simple_self_signed(vec!["other.invalid".into()]).unwrap();
    assert!(Config::parse_yaml(&document(json!({"tls":true,"certificate":certificate,"private-key":pem("PRIVATE KEY",&other.signing_key.serialize_der())}))).is_err());
    assert!(Config::parse_yaml(&document(json!({"tls":true,"certificate":certificate,"private-key":format!("{private_key}{private_key}")}))).is_err());
}

fn document(extra: Value) -> Vec<u8> {
    let mut node = json!({"name":"edge","type":"vless","server":"example.com","port":443,"uuid":"07070707-0707-0707-0707-070707070707"});
    node.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::to_vec(&json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]})).unwrap()
}

#[test]
fn vision_requires_tcp_tls13_and_xudp_before_any_io() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "vision_requires_tcp_tls13_and_xudp_before_any_io",
    );
    use vole::config::{ProxyProtocol, SecurityConfig};
    let config =
        Config::parse_yaml(&document(json!({"flow":"xtls-rprx-vision","tls":true}))).unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    let SecurityConfig::Tls(tls) = &node.security else {
        unreachable!()
    };
    assert!(tls.tls13_only);
    for fields in [
        json!({"flow":"xtls-rprx-vision"}),
        json!({"flow":"xtls-rprx-vision","tls":true,"packet-encoding":"none"}),
        json!({"flow":"xtls-rprx-vision","tls":true,"packet-encoding":"packetaddr"}),
        json!({"flow":"xtls-rprx-vision","tls":true,"network":"ws"}),
        json!({"flow":"xtls-rprx-vision","tls":true,"network":"grpc","grpc-opts":{"grpc-service-name":"test"}}),
        json!({"flow":"xtls-rprx-vision","tls":true,"network":"xhttp"}),
        json!({"flow":"xtls-rprx-vision-udp443","tls":true}),
    ] {
        assert!(Config::parse_yaml(&document(fields)).is_err());
    }
}

#[test]
fn default_tcp_and_three_udp_encodings_are_accepted_without_io() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "default_tcp_and_three_udp_encodings_are_accepted_without_io",
    );
    let config = Config::parse_yaml(&document(json!({}))).expect("default plaintext TCP");
    assert!(!config.proxies[0].udp);
    assert!(!format!("{config:?}").contains("07070707"));
    for encoding in ["xudp", "none", "packetaddr", "packet"] {
        for tls in [false, true] {
            Config::parse_yaml(&document(
                json!({"network":"tcp","tls":tls,"udp":true,"packet-encoding":encoding}),
            ))
            .expect("VLESS TCP UDP encoding");
        }
    }
}

#[test]
fn tcp_and_existing_xhttp_reject_mismatched_and_future_options() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "tcp_and_existing_xhttp_reject_mismatched_and_future_options",
    );
    for fields in [
        json!({"network":"tcp","xhttp-opts":{}}),
        json!({"network":"xhttp","tls":false,"fingerprint":"ab".repeat(32)}),
        json!({"tls":false,"servername":"secret.invalid"}),
        json!({"tls":false,"alpn":[]}),
        json!({"packet-encoding":""}),
        json!({"packet-encoding":"raw"}),
        json!({"flow":"invalid-flow"}),
        json!({"encryption":"auto"}),
        json!({"future":true}),
    ] {
        assert!(Config::parse_yaml(&document(fields)).is_err());
    }
    for key in [
        "name",
        "server",
        "port",
        "uuid",
        "network",
        "tls",
        "udp",
        "flow",
        "encryption",
        "packet-encoding",
        "servername",
        "alpn",
        "dialer-proxy",
        "xhttp-opts",
        "reality-opts",
    ] {
        assert!(
            Config::parse_yaml(&document(json!({key:null}))).is_err(),
            "null {key}"
        );
    }
    Config::parse_yaml(&document(
        json!({"network":"xhttp","tls":true,"alpn":["h2"],"xhttp-opts":{"mode":"auto"}}),
    ))
    .expect("existing XHTTP");
}

#[test]
fn stream_transports_and_explicit_tls_policy_have_strict_public_fields() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "stream_transports_and_explicit_tls_policy_have_strict_public_fields",
    );
    for transport in [
        json!({"network":"ws","ws-opts":{"path":"/vless","headers":{"Host":"localhost:443"},"max-early-data":64}}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":"vless"}}),
        json!({"network":"http","http-opts":{"method":"POST","path":["/one","/two"]}}),
        json!({"network":"h2","h2-opts":{"host":["localhost"],"path":"/vless"}}),
    ] {
        for tls in [false, true] {
            let mut fields = transport.clone();
            fields["tls"] = json!(tls);
            if tls {
                fields["skip-cert-verify"] = json!(true);
                fields["name-cert-verify"] = json!("verified.invalid");
                fields["fingerprint"] = json!("ab".repeat(32));
            }
            Config::parse_yaml(&document(fields)).expect("shared transport and TLS policy");
        }
    }
    for field in [
        "skip-cert-verify",
        "fingerprint",
        "name-cert-verify",
        "certificate",
        "private-key",
        "ws-opts",
        "grpc-opts",
        "http-opts",
        "h2-opts",
    ] {
        assert!(Config::parse_yaml(&document(json!({"tls":true,field:null}))).is_err());
    }
    for fields in [
        json!({"skip-cert-verify":false}),
        json!({"tls":true,"fingerprint":"invalid"}),
        json!({"tls":true,"name-cert-verify":""}),
        json!({"tls":true,"certificate":"bad"}),
        json!({"tls":true,"certificate":"bad","private-key":"bad"}),
        json!({"network":"tcp","ws-opts":{}}),
        json!({"network":"h2","h2-opts":{"host":[]}}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":"vless","future":1}}),
    ] {
        assert!(Config::parse_yaml(&document(fields)).is_err());
    }
}

#[test]
fn extended_ws_and_grpc_fields_are_scoped_and_bounded() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "VLESS-UNIT",
        "extended_ws_and_grpc_fields_are_scoped_and_bounded",
    );
    for fields in [
        json!({"network":"ws","ws-opts":{"v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":true,"max-early-data":1}}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":"test","grpc-user-agent":"probe","ping-interval":1,"max-connections":2,"min-streams":3}}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":"test","max-streams":2}}),
    ] {
        Config::parse_yaml(&document(fields)).expect("VLESS transport extension");
    }
    for fields in [
        json!({"network":"ws","ws-opts":{"v2ray-http-upgrade-fast-open":true}}),
        json!({"network":"ws","ws-opts":{"v2ray-http-upgrade":true,"max-early-data":1,"early-data-header-name":"x-ed"}}),
        json!({"network":"ws","ws-opts":{"v2ray-http-upgrade":null}}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":"test","grpc-user-agent":"bad\r\nvalue"}}),
    ] {
        assert!(Config::parse_yaml(&document(fields)).is_err());
    }
}
