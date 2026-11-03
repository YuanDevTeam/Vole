#![cfg(feature = "outbound-vless")]
use base64::Engine as _;
use serde_json::json;
use vole::config::{Config, ProxyProtocol, VlessEncryption};

#[test]
fn public_encryption_accepts_all_six_modes_without_exposing_key_material() {
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
    for appearance in ["native", "xorpub", "random"] {
        for rtt in ["1rtt", "0rtt"] {
            let config=Config::parse_yaml(&serde_json::to_vec(&json!({
                "mixed-port":1080,
                "proxies":[{"name":"edge", "type":"vless", "server":"example.invalid", "port":443,
                    "uuid":"07070707-0707-0707-0707-070707070707",
                    "encryption":format!("mlkem768x25519plus.{appearance}.{rtt}.{key}.100-35-35")}],
                "rules":["MATCH,edge"]
            })).unwrap()).expect("valid Encryption configuration must normalize before IO");
            let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
                panic!()
            };
            assert!(!matches!(&node.encryption, VlessEncryption::None));
            assert!(!format!("{:?}", node.encryption).contains(&key));
            assert!(!format!("{config:?}").contains(&key));
        }
    }
}

#[test]
fn vision_encryption_is_independent_of_outer_tls_but_keeps_transport_and_udp_limits() {
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
    for tls in [false, true] {
        for appearance in ["native", "xorpub", "random"] {
            let node = json!({"name":"edge", "type":"vless", "server":"example.invalid", "port":443,
                "uuid":"07070707-0707-0707-0707-070707070707", "tls":tls,
                "flow":"xtls-rprx-vision",
                "encryption":format!("mlkem768x25519plus.{appearance}.0rtt.{key}")});
            let parse = |node| {
                Config::parse_yaml(
                    &serde_json::to_vec(&json!({
                        "mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]
                    }))
                    .unwrap(),
                )
            };
            assert!(
                parse(node.clone()).is_ok(),
                "Encryption must supply the Vision splice boundary"
            );
            let mut alias = node.clone();
            alias["packet-encoding"] = json!("none");
            let config = parse(alias).expect("none must keep the Vision XUDP encoding");
            let ProxyProtocol::Vless(vless) = &config.proxies[0].protocol else {
                unreachable!()
            };
            assert_eq!(
                vless.packet_encoding,
                vole::config::VlessPacketEncoding::Xudp
            );
            for (field, value) in [
                ("network", json!("ws")),
                ("packet-encoding", json!("packetaddr")),
                ("smux", json!({"enabled":true})),
            ] {
                let mut invalid = node.clone();
                invalid[field] = value;
                assert!(parse(invalid).is_err());
            }
        }
    }
}
