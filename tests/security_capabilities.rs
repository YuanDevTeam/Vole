//! Public configuration preserves real REALITY key shares on both legs.
//! Pure memory IO; no protocol peer or host listener.
#![cfg(all(feature = "tls-fingerprint", feature = "outbound-vless"))]

use tokio::io::AsyncReadExt;

const X25519: u16 = 29;
const X25519_MLKEM768: u16 = 4588;
const HELLO_LIMIT: usize = 65_536;

fn word(bytes: &[u8], at: usize) -> usize {
    u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()).into()
}

fn key_shares(records: &[u8]) -> Vec<(u16, usize)> {
    let mut hello = Vec::new();
    let mut at = 0;
    while at < records.len() {
        assert_eq!(records[at], 22, "expected handshake record");
        let size = word(records, at + 3);
        assert!(size <= 16_384);
        hello.extend_from_slice(&records[at + 5..at + 5 + size]);
        at += 5 + size;
    }
    assert_eq!(hello[0], 1, "expected ClientHello");
    assert_eq!(
        hello.len(),
        4 + u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize
    );
    let mut at = 39 + usize::from(hello[38]);
    at += 2 + word(&hello, at);
    at += 1 + usize::from(hello[at]);
    let end = at + 2 + word(&hello, at);
    assert_eq!(end, hello.len());
    at += 2;
    let mut shares = None;
    while at < end {
        let kind = word(&hello, at);
        let next = at + 4 + word(&hello, at + 2);
        assert!(next <= end);
        if kind == 51 {
            assert!(shares.is_none(), "duplicate key_share extension");
            assert_eq!(at + 6 + word(&hello, at + 4), next);
            let mut item = at + 6;
            let mut found = Vec::new();
            while item < next {
                let group = word(&hello, item) as u16;
                let size = word(&hello, item + 2);
                item += 4 + size;
                assert!(item <= next);
                // GREASE is not a negotiated cryptographic group.
                if group & 0x0f0f != 0x0a0a {
                    found.push((group, size));
                }
            }
            shares = Some(found);
        }
        at = next;
    }
    shares.expect("missing key_share extension")
}

#[tokio::test]
async fn public_hybrid_reality_preserves_real_shares_on_both_transport_legs() {
    use serde_json::json;
    use vole::{
        config::{Config, ProxyProtocol},
        security::SecurityClient,
    };

    for profile in ["none", "chrome", "firefox", "safari", "ios", "edge", "qq"] {
        let yaml = serde_json::to_vec(&json!({
            "mixed-port": 1080,
            "proxies": [{
                "name": "edge", "type": "vless", "server": "example.invalid", "port": 443,
                "uuid": "07070707-0707-0707-0707-070707070707", "tls": true,
                "client-fingerprint": profile,
                "reality-opts": {
                    "public-key": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
                    "support-x25519mlkem768": true
                },
                "network": "xhttp",
                "xhttp-opts": {"mode": "stream-up", "download-settings": {}}
            }],
            "rules": ["MATCH,edge"]
        }))
        .unwrap();
        let config = Config::parse_yaml(&yaml).unwrap();
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            panic!()
        };
        for security in [&node.security, &node.download().unwrap().security] {
            let client = SecurityClient::from_security(security).unwrap();
            let (io, mut peer) = tokio::io::duplex(HELLO_LIMIT);
            let handshake = tokio::spawn(async move { client.connect(Box::new(io)).await });
            let mut header = [0u8; 5];
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                peer.read_exact(&mut header),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(header[0], 22);
            let size = word(&header, 3);
            assert!(size <= 16_384);
            let mut wire = header.to_vec();
            wire.resize(5 + size, 0);
            peer.read_exact(&mut wire[5..]).await.unwrap();
            let shares = key_shares(&wire);
            handshake.abort();
            assert!(matches!(handshake.await, Err(error) if error.is_cancelled()));
            let expected = match profile {
                "none" | "chrome" => vec![(X25519_MLKEM768, 1216), (X25519, 32)],
                "firefox" => vec![(X25519, 32), (23, 65)],
                _ => vec![(X25519, 32)],
            };
            assert_eq!(shares, expected, "public {profile} REALITY");
            assert_eq!(
                peer.read(&mut header).await.unwrap(),
                0,
                "cancel releases supplied IO"
            );
        }
    }
}
