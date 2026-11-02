#![cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{Config, ProxyProtocol},
    transport::{WebSocketOptions, connect_websocket},
};

const PROTOCOLS: &[&str] = &[
    #[cfg(feature = "outbound-vmess")]
    "vmess",
    #[cfg(feature = "outbound-trojan")]
    "trojan",
];

fn document(protocol: &str, options: Value) -> Vec<u8> {
    let mut node = json!({"name":"edge","type":protocol,"server":"example.com","port":443,"network":"ws","ws-opts":options});
    if protocol == "trojan" {
        node["password"] = json!("synthetic-upgrade");
    } else {
        node["uuid"] = json!("07070707-0707-0707-0707-070707070707");
    }
    serde_json::to_vec(&json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]})).unwrap()
}

fn options(protocol: &str, value: Value) -> WebSocketOptions {
    let config = Config::parse_yaml(&document(protocol, value)).unwrap();
    match &config.proxies[0].protocol {
        ProxyProtocol::Trojan(node) => node.transport.websocket_options().unwrap().unwrap(),
        ProxyProtocol::Vmess(node) => node.transport.websocket_options().unwrap().unwrap(),
        _ => unreachable!(),
    }
}

#[test]
fn httpupgrade_rejects_ambiguous_modes_and_early_data_before_io() {
    for &protocol in PROTOCOLS {
        for fast in [false, true] {
            for early in [0, 1, 2048, 2049, 4096, u16::MAX] {
                let opts = json!({"v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":fast,"max-early-data":early});
                assert!(Config::parse_yaml(&document(protocol, opts.clone())).is_ok());
                if early > 0 {
                    let mut explicit = opts;
                    explicit["early-data-header-name"] = json!("sEc-WeBsOcKeT-pRoToCoL");
                    assert!(Config::parse_yaml(&document(protocol, explicit)).is_ok());
                }
            }
        }
        for extra in [
            json!({"v2ray-http-upgrade":false,"v2ray-http-upgrade-fast-open":true}),
            json!({"v2ray-http-upgrade":null}),
            json!({"v2ray-http-upgrade":"true"}),
            json!({"v2ray-http-upgrade-fast-open":null}),
            json!({"v2ray-http-upgrade-fast-open":1}),
            json!({"max-early-data":65536}),
            json!({"max-early-data":-1}),
            json!({"max-early-data":null}),
            json!({"max-early-data":1,"early-data-header-name":""}),
            json!({"max-early-data":1,"early-data-header-name":"X-ED"}),
            json!({"max-early-data":0,"early-data-header-name":"Sec-WebSocket-Protocol"}),
            json!({"max-early-data":1,"early-data-header-name":null}),
            json!({"headers":{"Sec-WebSocket-Protocol":"override"}}),
            json!({"headers":{"Upgrade":"override"}}),
            json!({"headers":{"Host":"one.invalid","host":"two.invalid"}}),
            json!({"path":"relative"}),
            json!({"unexpected":true}),
        ] {
            let mut opts = json!({"v2ray-http-upgrade":true});
            opts.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(
                Config::parse_yaml(&document(protocol, opts.clone())).is_err(),
                "accepted {protocol} {opts}"
            );
        }
        let mut config: Value =
            serde_json::from_slice(&document(protocol, json!({"v2ray-http-upgrade":true})))
                .unwrap();
        for network in ["tcp", "grpc", "httpupgrade"] {
            config["proxies"][0]["network"] = json!(network);
            assert!(Config::parse_yaml(config.to_string().as_bytes()).is_err());
        }
    }
}

#[tokio::test]
async fn httpupgrade_configuration_selects_raw_upgrade_and_commits_prefix_once() {
    for &protocol in PROTOCOLS {
        for fast in [false, true] {
            let options = options(
                protocol,
                json!({
                    "path":"/upgrade?q=1#client-only","headers":{"Host":"cover.invalid:443"},
                    "v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":fast
                }),
            );
            let (io, mut peer) = tokio::io::duplex(4096);
            let remote = tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(peer.read_u8().await.unwrap());
                }
                let text = String::from_utf8(head).unwrap().to_ascii_lowercase();
                assert!(text.starts_with("get /upgrade?q=1 http/1.1\r\n"));
                assert!(text.contains("host: cover.invalid:443\r\n"));
                assert!(!text.contains("sec-websocket-key"));
                let mut prefix = [0; 14];
                if fast {
                    peer.read_exact(&mut prefix).await.unwrap();
                } else {
                    assert!(
                        tokio::time::timeout(std::time::Duration::from_millis(10), peer.read_u8())
                            .await
                            .is_err()
                    );
                }
                peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nserver-first").await.unwrap();
                if !fast {
                    peer.read_exact(&mut prefix).await.unwrap();
                }
                assert_eq!(&prefix, b"protocol-first");
                let mut business = [0; 11];
                peer.read_exact(&mut business).await.unwrap();
                assert_eq!(&business, b"application");
                assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
            });
            let mut stream = connect_websocket(
                Box::new(io),
                &options,
                b"protocol-first",
                tokio::time::Instant::now() + std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();
            let mut first = [0; 12];
            stream.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"server-first");
            stream.write_all(b"application").await.unwrap();
            stream.shutdown().await.unwrap();
            remote.await.unwrap();
        }
    }
}
