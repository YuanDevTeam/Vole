#![cfg(feature = "outbound-vmess")]
use serde_json::{Value, json};
use vole::config::Config;

fn document(extra: Value) -> Vec<u8> {
    let mut node = json!({"name":"edge","type":"vmess","server":"example.com","port":443,"uuid":"07070707-0707-0707-0707-070707070707"});
    node.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::to_vec(&json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]})).unwrap()
}

#[test]
fn vmess_default_node_and_explicit_cipher_aliases_are_accepted_without_io() {
    let parsed = Config::parse_yaml(&document(json!({}))).expect("VMess default node");
    assert_eq!(
        parsed.proxies[0].server_endpoint(),
        Some(("example.com", 443))
    );
    assert!(!parsed.proxies[0].udp);
    for cipher in ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"] {
        assert!(
            Config::parse_yaml(&document(json!({"cipher":cipher,"alterId":0,"udp":true}))).is_ok()
        );
    }
    assert!(!format!("{parsed:?}").contains("07070707"));
    for (input, expected) in [
        (
            "07070707070707070707070707070707",
            "07070707-0707-0707-0707-070707070707",
        ),
        (
            "{07070707-0707-0707-0707-070707070707}",
            "07070707-0707-0707-0707-070707070707",
        ),
        (
            "urn:uuid:07070707-0707-0707-0707-070707070707",
            "07070707-0707-0707-0707-070707070707",
        ),
        ("invalid-secret", "29a5f9ec-d914-56e3-a82c-19b9150f2a91"),
    ] {
        let parsed = Config::parse_yaml(&document(json!({"uuid":input}))).unwrap();
        let vole::config::ProxyProtocol::Vmess(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        assert_eq!(node.id.hyphenated().to_string(), expected);
    }
}

#[test]
fn vmess_transport_and_security_combinations_are_strict() {
    for tls in [false, true] {
        for (network, options) in [
            ("tcp", json!({})),
            (
                "ws",
                json!({"ws-opts":{"path":"/path?q=1","headers":{"Host":"cover.example:443"},"max-early-data":2048}}),
            ),
            ("grpc", json!({"grpc-opts":{"grpc-service-name":"edge"}})),
            (
                "http",
                json!({"http-opts":{"method":"POST","path":["/a","/b"],"headers":{"Host":["a.example","b.example"],"X-Test":["one","two"]}}}),
            ),
            (
                "h2",
                json!({"h2-opts":{"host":["cover.example","[2001:db8::1]:443"],"path":"/h2"}}),
            ),
        ] {
            let mut fields = json!({"network":network,"tls":tls,"global-padding":true,"authenticated-length":true,"packet-encoding":"packetaddr"});
            fields
                .as_object_mut()
                .unwrap()
                .extend(options.as_object().unwrap().clone());
            assert!(
                Config::parse_yaml(&document(fields)).is_ok(),
                "{network} tls={tls}"
            );
        }
    }
    for fields in [
        json!({"alterId":1}),
        json!({"cipher":"none","global-padding":true}),
        json!({"cipher":"zero","authenticated-length":true}),
        json!({"network":"bogus"}),
        json!({"tls":false,"servername":"secret.invalid"}),
        json!({"tls":false,"skip-cert-verify":false}),
        json!({"tls":false,"alpn":[]}),
        json!({"packet-encoding":"packet"}),
        json!({"ws-opts":{}}),
        json!({"http-opts":{}}),
        json!({"network":"http","http-opts":{"method":"GET\r\n"}}),
        json!({"network":"http","http-opts":{"headers":{"Content-Length":["1"]}}}),
        json!({"network":"http","http-opts":{"headers":{"X-Test":[]}}}),
        json!({"network":"ws","ws-opts":{"max-early-data":65536}}),
        json!({"network":"ws","tls":true,"alpn":["h2"]}),
    ] {
        assert!(
            Config::parse_yaml(&document(fields.clone())).is_err(),
            "accepted {fields}"
        );
    }
    for key in [
        "name",
        "type",
        "server",
        "port",
        "uuid",
        "alterId",
        "cipher",
        "udp",
        "network",
        "tls",
        "servername",
        "alpn",
        "fingerprint",
        "skip-cert-verify",
        "packet-encoding",
        "global-padding",
        "authenticated-length",
        "dialer-proxy",
        "ws-opts",
        "grpc-opts",
        "http-opts",
        "h2-opts",
    ] {
        assert!(
            Config::parse_yaml(&document(json!({key:null}))).is_err(),
            "accepted null {key}"
        );
    }
}

#[tokio::test]
async fn vmess_field_boundaries_and_normalized_transport_values() {
    use vole::config::{ProxyProtocol, VmessTransport};
    for fields in [
        json!({"server":""}),
        json!({"port":0}),
        json!({"port":65536}),
        json!({"network":"ws","ws-opts":{"headers":{"Host":"cover.example:bogus"}}}),
        json!({"network":"h2","h2-opts":{"host":["cover.example:"]}}),
        json!({"network":"http","http-opts":{"headers":{"Host":["cover.example:65536"]}}}),
        json!({"network":"ws","ws-opts":{"path":"/","headers":{"host":"a.example","Host":"b.example"}}}),
        json!({"network":"ws","ws-opts":{"path":"/q?x=1","max-early-data":1,"early-data-header-name":""}}),
        json!({"tls":true,"fingerprint":"secret-not-a-fingerprint"}),
        json!({"tls":true,"alpn":[""]}),
        json!({"network":"http","http-opts":{"path":["relative"]}}),
        json!({"network":"ws","ws-opts":{"unknown":1}}),
        json!({"network":"grpc","grpc-opts":{"grpc-service-name":null}}),
        json!({"network":"h2","h2-opts":{"host":null}}),
        json!({"network":"http","http-opts":{"headers":{"X-Foo":["value\r\nInjected:1"]}}}),
        json!({"future":true}),
    ] {
        let result = Config::parse_yaml(&document(fields.clone()));
        assert!(result.is_err(), "accepted {fields}");
        assert!(
            !result
                .unwrap_err()
                .to_string()
                .contains("secret-not-a-fingerprint")
        );
    }
    for key in [
        "server",
        "uuid",
        "cipher",
        "network",
        "servername",
        "fingerprint",
        "packet-encoding",
    ] {
        assert!(Config::parse_yaml(&document(json!({key:[],"tls":true}))).is_err());
    }
    for key in [
        "port",
        "alterId",
        "udp",
        "tls",
        "skip-cert-verify",
        "global-padding",
        "authenticated-length",
        "alpn",
    ] {
        assert!(Config::parse_yaml(&document(json!({key:{}}))).is_err());
    }
    for missing in ["name", "type", "server", "port", "uuid"] {
        let mut value: Value = serde_json::from_slice(&document(json!({}))).unwrap();
        value["proxies"][0].as_object_mut().unwrap().remove(missing);
        assert!(Config::parse_yaml(value.to_string().as_bytes()).is_err());
    }
    let parsed = Config::parse_yaml(&document(
        json!({"network":"ws","tls":true,"ws-opts":{"headers":{"Host":"localhost:443"}}}),
    ))
    .unwrap();
    let ProxyProtocol::Vmess(node) = &parsed.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(node.server_name, "localhost");
    let parsed=Config::parse_yaml(&document(json!({"network":"http","http-opts":{"method":"POST","path":["/a?x=1","/b"],"headers":{"Host":["one.example:80","[2001:db8::1]:80"],"X-Test":["one","two"]}}}))).unwrap();
    let ProxyProtocol::Vmess(node) = &parsed.proxies[0].protocol else {
        unreachable!()
    };
    let VmessTransport::Http { uris, .. } = &node.transport else {
        unreachable!()
    };
    assert!(uris[0].contains("/a%3Fx=1"));
    use tokio::io::AsyncReadExt;
    let mut selected = std::collections::BTreeSet::new();
    for _ in 0..1024 {
        let (client, mut observer) = tokio::io::duplex(4096);
        let _stream = vole::transport::http_obfs(
            Box::new(client),
            &node.transport.http_options().unwrap().unwrap(),
            b"prefix-once",
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        let mut bytes = [0; 4096];
        let n = observer.read(&mut bytes).await.unwrap();
        let head = std::str::from_utf8(&bytes[..n]).unwrap();
        assert!(head.starts_with("POST /"));
        assert!(head.ends_with("\r\n\r\nprefix-once"));
        assert!(head.contains("x-test: "));
        selected.insert(head.to_owned());
    }
    // Sampling is bounded; all eight independently selected combinations should
    // appear. A selector permanently taking the first entry cannot pass.
    assert_eq!(selected.len(), 8);
}

#[tokio::test]
async fn vmess_normalized_websocket_fields_preserve_headers_and_early_data_order() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    for (maximum, header) in [
        (0, None),
        (1, None),
        (2048, None),
        (2049, None),
        (2048, Some("X-Early")),
        (2048, Some("")),
    ] {
        let mut fields = json!({"network":"ws","ws-opts":{"path":"/edge/","headers":{"Host":"cover.example:443","X-Custom":"exact-value"},"max-early-data":maximum}});
        if let Some(header) = header {
            fields["ws-opts"]["early-data-header-name"] = json!(header);
        }
        let parsed = Config::parse_yaml(&document(fields)).unwrap();
        let vole::config::ProxyProtocol::Vmess(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        let (client, peer) = tokio::io::duplex(65536);
        let prefix = vec![7; 2049];
        let expected = prefix.clone();
        let reader = tokio::spawn(async move {
            let mut early = Vec::new();
            #[allow(
                clippy::result_large_err,
                reason = "Tungstenite's header callback requires an unboxed HTTP error response"
            )]
            let mut ws = tokio_tungstenite::accept_hdr_async(
                peer,
                |request: &http::Request<()>, response: http::Response<()>| {
                    assert_eq!(request.headers()["host"], "cover.example:443");
                    assert_eq!(request.headers()["x-custom"], "exact-value");
                    let path = request.uri().path();
                    if maximum == 0 {
                        assert_eq!(path, "/edge/");
                        assert!(!request.headers().contains_key("sec-websocket-protocol"));
                    } else if header == Some("") {
                        early = URL_SAFE_NO_PAD
                            .decode(path.strip_prefix("/edge/").unwrap())
                            .unwrap();
                    } else {
                        assert_eq!(path, "/edge/");
                        early = URL_SAFE_NO_PAD
                            .decode(
                                request.headers()[header.unwrap_or("sec-websocket-protocol")]
                                    .as_bytes(),
                            )
                            .unwrap();
                    }
                    assert_eq!(early.len(), maximum);
                    Ok(response)
                },
            )
            .await
            .unwrap();
            while early.len() < expected.len() {
                early.extend(ws.next().await.unwrap().unwrap().into_data());
            }
            assert_eq!(early, expected);
            assert_eq!(
                ws.next().await.unwrap().unwrap().into_data().as_ref(),
                b"continuation"
            );
        });
        let mut stream = vole::transport::connect_websocket(
            Box::new(client),
            &node.transport.websocket_options().unwrap().unwrap(),
            &prefix,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        stream.write_all(b"continuation").await.unwrap();
        stream.flush().await.unwrap();
        reader.await.unwrap();
    }
}

#[test]
fn stream_defaults_and_grpc_authority_match_the_reference() {
    use vole::config::{ProxyProtocol, StreamTransport};
    for tls in [false, true] {
        for options in [
            json!({}),
            json!({"h2-opts":{}}),
            json!({"h2-opts":{"host":[],"path":""}}),
        ] {
            let mut fields = options;
            fields["network"] = json!("h2");
            fields["tls"] = json!(tls);
            let config = Config::parse_yaml(&document(fields)).unwrap();
            let ProxyProtocol::Vmess(node) = &config.proxies[0].protocol else {
                unreachable!()
            };
            let StreamTransport::H2 { uris } = &node.transport else {
                unreachable!()
            };
            assert_eq!(
                uris,
                &[format!(
                    "{}://www.example.com/",
                    if tls { "https" } else { "http" }
                )]
            );
        }
    }
    for (name, authority) in [
        (None, "example.com:443"),
        (Some(""), "example.com:443"),
        (Some("cover.example"), "cover.example"),
        (Some("2001:db8::1"), "[2001:db8::1]"),
    ] {
        let mut fields = json!({"network":"grpc","tls":true,"name-cert-verify":"verified.example"});
        if let Some(name) = name {
            fields["servername"] = json!(name);
        }
        let config = Config::parse_yaml(&document(fields)).unwrap();
        let ProxyProtocol::Vmess(node) = &config.proxies[0].protocol else {
            unreachable!()
        };
        let StreamTransport::Grpc { uri, .. } = &node.transport else {
            unreachable!()
        };
        assert_eq!(
            uri.parse::<http::Uri>()
                .unwrap()
                .authority()
                .unwrap()
                .as_str(),
            authority
        );
    }
    for fields in [
        json!({"network":""}),
        json!({"network":"ws","ws-opts":{"path":""}}),
        json!({"network":"http","http-opts":{"method":""}}),
    ] {
        Config::parse_yaml(&document(fields)).unwrap();
    }
}
