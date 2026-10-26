#![cfg(all(
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-vless"
))]
use serde_json::json;
use vole::config::{Config, ProxyProtocol, StreamTransport, TrojanTransport, VlessTransport};

#[test]
fn grpc_protocols_share_defaults_signed_thresholds_and_normalization() {
    for protocol in ["trojan", "vmess", "vless"] {
        for (fields, path, ua, max, min, streams) in [
            (json!({}), "/GunService/Tun", "grpc-go/1.36.0", 2, 0, 0),
            (
                json!({"grpc-opts":{"grpc-service-name":"","grpc-user-agent":""}}),
                "/GunService/Tun",
                "grpc-go/1.36.0",
                2,
                0,
                0,
            ),
            (
                json!({"grpc-opts":{"max-connections":1}}),
                "/GunService/Tun",
                "grpc-go/1.36.0",
                1,
                0,
                0,
            ),
            (
                json!({"grpc-opts":{"grpc-service-name":"edge","grpc-user-agent":"probe","ping-interval":1,"max-connections":2,"min-streams":3,"max-streams":4}}),
                "/edge/Tun",
                "probe",
                2,
                3,
                4,
            ),
            (
                json!({"grpc-opts":{"grpc-service-name":"/full/path","max-connections":-1,"min-streams":-1,"max-streams":2}}),
                "/full/path",
                "grpc-go/1.36.0",
                0,
                0,
                2,
            ),
            (
                json!({"grpc-opts":{"max-streams":-1}}),
                "/GunService/Tun",
                "grpc-go/1.36.0",
                0,
                0,
                0,
            ),
        ] {
            let mut node = json!({"name":"edge","type":protocol,"server":"example.com","port":443,"network":"grpc"});
            if protocol == "trojan" {
                node["password"] = json!("test");
            } else {
                node["uuid"] = json!("07070707-0707-0707-0707-070707070707");
            }
            node.as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            let config = Config::parse_yaml(
                json!({"mixed-port":1080,"proxies":[node.clone()],"rules":["MATCH,edge"]})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap();
            let (uri, options) = match &config.proxies[0].protocol {
                ProxyProtocol::Trojan(node) => match &node.transport {
                    TrojanTransport::Grpc { uri, options } => (uri, options),
                    _ => unreachable!(),
                },
                ProxyProtocol::Vmess(node) => match &node.transport {
                    StreamTransport::Grpc { uri, options } => (uri, options),
                    _ => unreachable!(),
                },
                ProxyProtocol::Vless(node) => match &node.transport {
                    VlessTransport::Stream(StreamTransport::Grpc { uri, options }) => {
                        (uri, options)
                    }
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            };
            assert_eq!(uri.parse::<http::Uri>().unwrap().path(), path);
            assert_eq!(options.user_agent, ua);
            assert_eq!(
                (
                    options.max_connections,
                    options.min_streams,
                    options.max_streams
                ),
                (max, min, streams)
            );
            assert_eq!(options.ping_interval, u64::from(ua == "probe"));
            if fields.as_object().unwrap().is_empty() {
                let mut unsupported = node.clone();
                unsupported["grpc-opts"] = json!({"ping-interval":-1});
                assert!(
                    Config::parse_yaml(
                        json!({"mixed-port":1080,"proxies":[unsupported],"rules":["MATCH,edge"]})
                            .to_string()
                            .as_bytes()
                    )
                    .is_err()
                );
            }
        }
    }
}
