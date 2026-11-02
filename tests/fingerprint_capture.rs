//! Verify the public configuration's real TLS adapter over bounded memory IO.
//! The observer aborts before authentication; proxy interoperability is separate.
#![cfg(all(feature = "tls-fingerprint", feature = "outbound-vless"))]

use serde_json::json;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use vole::{
    config::{Config, ProxyProtocol},
    security::SecurityClient,
};

fn configuration(profile: &str, context: &str, sni: &str) -> SecurityClient {
    let mut node = json!({
        "name": "p", "type": "vless", "server": "192.0.2.1", "port": 443,
        "uuid": "07070707-0707-0707-0707-070707070707", "tls": true,
        "servername": sni, "client-fingerprint": profile,
        "alpn": ["h2", "http/1.1"]
    });
    match context {
        "tcp" => {}
        "ws" => {
            node["network"] = json!("ws");
            node["alpn"] = json!(["http/1.1"]);
            node["ws-opts"] = json!({"path": "/capture"});
        }
        "grpc" => {
            node["network"] = json!("grpc");
            node["grpc-opts"] = json!({"grpc-service-name": "capture"});
        }
        "vision" => node["flow"] = json!("xtls-rprx-vision"),
        "xhttp-h1" | "xhttp-h2" => {
            node["network"] = json!("xhttp");
            node["alpn"] = json!([if context == "xhttp-h1" {
                "http/1.1"
            } else {
                "h2"
            }]);
            node["xhttp-opts"] = json!({"path": "/capture", "mode": "stream-one"});
        }
        "reality" => {
            node["reality-opts"] = json!({
                // Public RFC 7748 vector, never an account/server secret.
            "public-key": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
                "short-id": "01020304"
            })
        }
        _ => panic!("unknown capture context"),
    }
    let config = Config::parse_yaml(
        json!({"mixed-port": 1080, "proxies": [node], "rules": ["MATCH,p"]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let ProxyProtocol::Vless(proxy) = &config.proxies[0].protocol else {
        unreachable!()
    };
    SecurityClient::from_proxy(proxy).unwrap()
}

async fn capture(client: &SecurityClient) -> Vec<u8> {
    let (io, mut observer) = tokio::io::duplex(65536);
    let observed = async {
        let mut records = Vec::new();
        let mut hello = Vec::new();
        for _ in 0..8 {
            let mut header = [0; 5];
            observer.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22);
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert!((1..=16384).contains(&length));
            let mut body = vec![0; length];
            observer.read_exact(&mut body).await.unwrap();
            records.extend(header);
            records.extend(&body);
            hello.extend(body);
            assert!(hello.len() <= 65536);
            if hello.len() >= 4 {
                assert_eq!(hello[0], 1);
                let expected = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize + 4;
                assert!(hello.len() <= expected);
                if hello.len() == expected {
                    drop(observer);
                    return records;
                }
            }
        }
        panic!("ClientHello record bound exceeded")
    };
    let (result, records) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(client.connect(Box::new(io)), observed)
    })
    .await
    .unwrap();
    assert!(result.is_err(), "capture-only observer cannot authenticate");
    records
}

#[tokio::test]
async fn selected_public_profiles_emit_bounded_client_hellos() {
    let mut cases = 0;
    for profile in ["chrome", "firefox", "safari", "ios"] {
        for context in [
            "tcp", "ws", "grpc", "reality", "vision", "xhttp-h1", "xhttp-h2",
        ] {
            for sni in [
                "fingerprint.test".to_owned(),
                format!("{}.fingerprint.test", "f".repeat(63)),
            ] {
                let client = configuration(profile, context, &sni);
                for _ in 0..2 {
                    drop(capture(&client).await);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 112);
}
