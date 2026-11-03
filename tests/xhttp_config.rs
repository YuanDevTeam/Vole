#![cfg(feature = "outbound-vless")]

use serde_json::{Value, json};
use vole::config::{Config, ProxyProtocol, XHttpMode};

fn document(options: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "mixed-port":1080,
        "proxies":[{"name":"edge","type":"vless","server":"example.com","port":443,
            "uuid":"07070707-0707-0707-0707-070707070707","network":"xhttp","tls":true,
            "xhttp-opts":options}],
        "rules":["MATCH,edge"]
    }))
    .unwrap()
}

#[test]
fn xhttp_authorities_reject_userinfo_on_both_legs_without_echoing_it() {
    for host in [
        "synthetic-secret@cover.example",
        "name:synthetic-secret@cover.example:443",
        "@cover.example",
    ] {
        for options in [
            json!({"host":host}),
            json!({"download-settings":{"host":host}}),
        ] {
            let error = Config::parse_yaml(&document(options))
                .unwrap_err()
                .to_string();
            assert!(!error.contains(host));
            assert!(!error.contains("synthetic-secret"));
        }
        assert!(
            vole::transport::xhttp::XHttpConfig::new(
                host,
                "/",
                vole::transport::xhttp::XHttpMode::StreamOne
            )
            .is_err()
        );
    }
    for host in ["cover.example:443", "192.0.2.1:8443", "[2001:db8::1]:443"] {
        for options in [
            json!({"host":host}),
            json!({"download-settings":{"host":host}}),
        ] {
            assert!(Config::parse_yaml(&document(options)).is_ok());
        }
    }
}

#[test]
fn xhttp_fields_reject_wrong_types_null_and_every_range_boundary_before_io() {
    let fields = [
        "host",
        "path",
        "mode",
        "headers",
        "no-grpc-header",
        "x-padding-bytes",
        "x-padding-obfs-mode",
        "x-padding-key",
        "x-padding-header",
        "x-padding-placement",
        "x-padding-method",
        "uplink-http-method",
        "session-placement",
        "session-key",
        "session-table",
        "session-length",
        "seq-placement",
        "seq-key",
        "uplink-data-placement",
        "uplink-data-key",
        "uplink-chunk-size",
        "sc-max-each-post-bytes",
        "sc-min-posts-interval-ms",
        "reuse-settings",
        "download-settings",
    ];
    for field in fields {
        for value in [Value::Null, json!([]), json!(42.5)] {
            assert!(
                Config::parse_yaml(&document(json!({field:value}))).is_err(),
                "accepted invalid type for {field}: {value}"
            );
        }
    }
    for field in [
        "server",
        "port",
        "tls",
        "servername",
        "alpn",
        "skip-cert-verify",
        "name-cert-verify",
        "fingerprint",
        "certificate",
        "private-key",
        "path",
        "host",
        "headers",
        "reality-opts",
        "reuse-settings",
    ] {
        for value in [Value::Null, json!(42.5)] {
            assert!(
                Config::parse_yaml(&document(json!({"download-settings":{field:value}}))).is_err(),
                "download {field}"
            );
        }
    }
    for field in ["reuse-settings", "reality-opts"] {
        assert!(Config::parse_yaml(&document(json!({"download-settings":{field:[]}}))).is_err());
    }
    for (field, low, high, extra) in [
        ("x-padding-bytes", 1u64, 4096, json!({})),
        ("sc-max-each-post-bytes", 1, 16777216, json!({})),
        ("sc-min-posts-interval-ms", 1, 60000, json!({})),
        (
            "uplink-chunk-size",
            64,
            8192,
            json!({"uplink-data-placement":"header","uplink-data-key":"data"}),
        ),
        ("session-length", 10, 128, json!({"session-table":"number"})),
    ] {
        for value in [
            low.to_string(),
            high.to_string(),
            format!("{low}-{high}"),
            format!(" +{low} "),
            format!(" +{low} - +{high} "),
        ] {
            let mut options = extra.clone();
            options[field] = json!(value);
            assert!(
                Config::parse_yaml(&document(options)).is_ok(),
                "valid boundary {field}"
            );
        }
        for value in [
            (high + 1).to_string(),
            "-1".into(),
            "1-0".into(),
            "1.0".into(),
            "1-2-3".into(),
        ] {
            let mut options = extra.clone();
            options[field] = json!(value);
            assert!(
                Config::parse_yaml(&document(options)).is_err(),
                "invalid range {field}"
            );
        }
    }
    for field in [
        "max-concurrency",
        "max-connections",
        "c-max-reuse-times",
        "h-max-request-times",
        "h-max-reusable-secs",
    ] {
        for value in [json!(null), json!(0), json!("-1"), json!("2147483648")] {
            for download in [false, true] {
                let mut options = json!({"reuse-settings":{field:value}});
                if download {
                    options = json!({"download-settings":options});
                }
                assert!(Config::parse_yaml(&document(options)).is_err());
            }
        }
        assert!(
            Config::parse_yaml(&document(json!({"reuse-settings":{field:"0-2147483647"}}))).is_ok()
        );
    }
    for download in [false, true] {
        for value in [
            json!(null),
            json!("0"),
            json!([]),
            json!(2147483648_i64),
            json!(-2147483649_i64),
        ] {
            let mut options = json!({"reuse-settings":{"h-keep-alive-period":value}});
            if download {
                options = json!({"download-settings":options});
            }
            assert!(Config::parse_yaml(&document(options)).is_err());
        }
        for value in [i32::MIN, -1, 0, 1, i32::MAX] {
            let mut options = json!({"reuse-settings":{"h-keep-alive-period":value}});
            if download {
                options = json!({"download-settings":options});
            }
            assert!(Config::parse_yaml(&document(options)).is_ok());
        }
    }
}

#[test]
fn xhttp_numeric_upload_fields_match_strings_and_retain_bounds() {
    let numeric = json!({
        "uplink-data-placement": "header", "uplink-data-key": "data",
        "uplink-chunk-size": 1024,
        "sc-max-each-post-bytes": 4096,
        "sc-min-posts-interval-ms": 1
    });
    let fields = [
        "uplink-chunk-size",
        "sc-max-each-post-bytes",
        "sc-min-posts-interval-ms",
    ];
    let mut quoted = numeric.clone();
    for field in fields {
        quoted[field] = json!(quoted[field].as_u64().unwrap().to_string());
    }
    let numeric_config = Config::parse_yaml(&document(numeric.clone())).unwrap();
    let quoted_config = Config::parse_yaml(&document(quoted)).unwrap();
    assert_eq!(
        numeric_config.proxies[0].protocol,
        quoted_config.proxies[0].protocol
    );

    for (field, low, high) in [
        ("uplink-chunk-size", 0, 8192),
        ("sc-max-each-post-bytes", 1, 16 * 1024 * 1024),
        ("sc-min-posts-interval-ms", 1, 60000),
    ] {
        for value in [low, high] {
            let mut options = numeric.clone();
            options[field] = json!(value);
            assert!(Config::parse_yaml(&document(options)).is_ok());
        }
        for value in [
            json!(low - 1),
            json!(high + 1),
            json!(-1),
            json!(u64::MAX),
            json!(true),
        ] {
            let mut options = numeric.clone();
            options[field] = value;
            assert!(Config::parse_yaml(&document(options)).is_err());
        }
    }
    let mut adaptive = numeric;
    adaptive["uplink-chunk-size"] = json!(0);
    assert!(Config::parse_yaml(&document(adaptive)).is_ok());
}

#[test]
fn xhttp_empty_mode_path_and_download_name_use_each_legs_defaults() {
    let config = Config::parse_yaml(&document(json!({"mode":"", "path":""}))).unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(node.xhttp().unwrap().mode, XHttpMode::PacketUp);
    assert_eq!(node.xhttp().unwrap().path, "/");

    let mut input: Value = serde_json::from_slice(&document(json!({
        "path":"/upload",
        "download-settings":{"server":"download.example.com", "path":"", "servername":""}
    })))
    .unwrap();
    input["proxies"][0]["servername"] = json!("parent.invalid");
    let config = Config::parse_yaml(&serde_json::to_vec(&input).unwrap()).unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(node.xhttp().unwrap().path, "/upload");
    assert_eq!(node.xhttp().unwrap().host, "parent.invalid");
    let download = node.download().unwrap();
    assert_eq!(download.path, "/");
    assert_eq!(download.security.server_name(), "download.example.com");
    assert_eq!(download.host, "download.example.com");
}

#[test]
fn xhttp_empty_request_and_pool_fields_restore_their_defaults() {
    let expected = Config::parse_yaml(&document(json!({}))).unwrap();
    let ProxyProtocol::Vless(expected_node) = &expected.proxies[0].protocol else {
        unreachable!()
    };
    let actual = Config::parse_yaml(&document(json!({
        "uplink-http-method":"",
        "session-placement":"", "session-key":"", "session-length":" \t ",
        "seq-placement":"", "seq-key":"",
        "uplink-data-placement":"", "uplink-data-key":"", "uplink-chunk-size":" \t ",
        "x-padding-bytes":" \t ", "x-padding-key":"", "x-padding-header":"",
        "x-padding-placement":"", "x-padding-method":"",
        "sc-max-each-post-bytes":" \t ", "sc-min-posts-interval-ms":""
    })))
    .unwrap();
    let ProxyProtocol::Vless(actual_node) = &actual.proxies[0].protocol else {
        unreachable!()
    };
    assert_eq!(
        expected_node.xhttp().unwrap().request,
        actual_node.xhttp().unwrap().request
    );
    for download in [false, true] {
        let expected_options = if download {
            json!({"download-settings":{"reuse-settings":{}}})
        } else {
            json!({"reuse-settings":{}})
        };
        let mut options = json!({"reuse-settings":{
            "max-concurrency":"", "max-connections":" \t ", "c-max-reuse-times":"",
            "h-max-request-times":"", "h-max-reusable-secs":" \t "
        }});
        if download {
            options = json!({"download-settings":options});
        }
        let expected = Config::parse_yaml(&document(expected_options)).unwrap();
        let actual = Config::parse_yaml(&document(options)).unwrap();
        let (ProxyProtocol::Vless(expected), ProxyProtocol::Vless(actual)) =
            (&expected.proxies[0].protocol, &actual.proxies[0].protocol)
        else {
            unreachable!()
        };
        let (expected, actual) = if download {
            (
                &expected.download().unwrap().reuse,
                &actual.download().unwrap().reuse,
            )
        } else {
            (
                &expected.xhttp().unwrap().reuse,
                &actual.xhttp().unwrap().reuse,
            )
        };
        assert_eq!(expected, actual);
    }
}

#[test]
fn empty_http_authority_falls_back_to_each_legs_authentication_name() {
    for (host, down_host, up, down) in [
        ("", None, "example.com", "download.example.com"),
        (
            "custom.example.com",
            Some(""),
            "custom.example.com",
            "download.example.com",
        ),
        (
            "custom.example.com",
            None,
            "custom.example.com",
            "custom.example.com",
        ),
    ] {
        let mut options =
            json!({"host":host,"download-settings":{"servername":"download.example.com"}});
        if let Some(value) = down_host {
            options["download-settings"]["host"] = json!(value);
        }
        let config = Config::parse_yaml(&document(options)).unwrap();
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            unreachable!()
        };
        assert_eq!(node.xhttp().unwrap().host, up);
        assert_eq!(node.download().unwrap().host, down);
    }
}

#[test]
fn download_security_changes_do_not_silently_discard_inherited_certificate_policy() {
    for download in [
        json!({"tls":false}),
        json!({"reality-opts":{"public-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}),
    ] {
        for clear in [false, true] {
            let mut down = download.clone();
            if clear {
                down["fingerprint"] = json!("");
                down["name-cert-verify"] = json!("");
                down["skip-cert-verify"] = json!(false);
            }
            let mut value: Value =
                serde_json::from_slice(&document(json!({"download-settings":down}))).unwrap();
            value["proxies"][0]["fingerprint"] = json!("ab".repeat(32));
            value["proxies"][0]["name-cert-verify"] = json!("verify.example.com");
            value["proxies"][0]["skip-cert-verify"] = json!(true);
            assert_eq!(
                Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).is_ok(),
                clear
            );
        }
    }
}

#[test]
fn h3_requires_exclusive_alpn_and_standard_tls_on_each_leg() {
    let mut value: Value =
        serde_json::from_slice(&document(json!({"download-settings":{"alpn":["h3"]}}))).unwrap();
    value["proxies"][0]["alpn"] = json!(["h3"]);
    assert!(Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).is_ok());
    for (alpn, tls, reality) in [
        (json!(["h3", "h2"]), true, false),
        (json!(["h3"]), false, false),
        (json!(["h3"]), true, true),
    ] {
        let mut invalid = value.clone();
        let node = &mut invalid["proxies"][0];
        node["alpn"] = alpn;
        node["tls"] = tls.into();
        if reality {
            node["reality-opts"] =
                json!({"public-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
        }
        assert!(Config::parse_yaml(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    value["proxies"][0]["alpn"] = json!(["h2"]);
    for options in [
        json!({"alpn":["h3"],"tls":false}),
        json!({"alpn":["h3"],"reality-opts":{"public-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}),
    ] {
        value["proxies"][0]["xhttp-opts"]["download-settings"] = options;
        assert!(Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn custom_headers_inherit_replace_clear_and_do_not_leak_values() {
    for (download, expected) in [
        (json!({}), Some("private-upload-value")),
        (
            json!({"headers":{"X-Test":"private-download-value"}}),
            Some("private-download-value"),
        ),
        (json!({"headers":{}}), None),
    ] {
        let config = Config::parse_yaml(&document(json!({
            "headers":{"X-Test":"private-upload-value"},"download-settings":download
        })))
        .expect("XHTTP custom headers");
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            unreachable!()
        };
        let upload = node.xhttp().unwrap();
        let down = node.download().unwrap();
        assert_eq!(upload.headers.as_map()["x-test"], "private-upload-value");
        assert_eq!(
            down.headers
                .as_map()
                .get("x-test")
                .map(|v| v.to_str().unwrap()),
            expected
        );
        for debug in [
            format!("{config:?}"),
            format!("{upload:?}"),
            format!("{down:?}"),
        ] {
            assert!(!debug.contains("private-"));
        }
    }
}

#[test]
fn conflicting_request_fields_are_rejected_on_both_legs_before_io() {
    for options in [
        json!({"session-placement":"header","download-settings":{"headers":{"x-session":"override"}}}),
        json!({"x-padding-obfs-mode":true,"x-padding-placement":"header","x-padding-header":"X-Pad","download-settings":{"headers":{"x-pad":"override"}}}),
        json!({"session-placement":"query","download-settings":{"path":"/x?x_session=override"}}),
        json!({"path":"/x?pad=override","x-padding-obfs-mode":true,"x-padding-placement":"query","x-padding-key":"pad"}),
        json!({"headers":{"Cookie":"pad=override"},"x-padding-obfs-mode":true,"x-padding-placement":"cookie","x-padding-key":"pad"}),
        json!({"session-placement":"header","session-key":"data-0","uplink-data-placement":"header","uplink-data-key":"data"}),
        json!({"seq-placement":"header","seq-key":"X-Session","session-placement":"header"}),
    ] {
        assert!(
            Config::parse_yaml(&document(options.clone())).is_err(),
            "accepted conflicting options: {options}"
        );
    }
}

#[test]
fn http_version_selects_h1_only_for_its_single_alpn_and_supports_plaintext() {
    use vole::config::{SecurityConfig, XHttpVersion};
    for tls in [true, false] {
        for (alpn, version) in [
            (json!(["http/1.1"]), XHttpVersion::Http1),
            (json!(["h2"]), XHttpVersion::Http2),
            (json!(["http/1.1", "h2"]), XHttpVersion::Http2),
            (json!([]), XHttpVersion::Http2),
        ] {
            let mut value: Value =
                serde_json::from_slice(&document(json!({"download-settings":{}}))).unwrap();
            value["proxies"][0]["tls"] = tls.into();
            value["proxies"][0]["alpn"] = alpn;
            let config = Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).unwrap();
            let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
                unreachable!()
            };
            let upload = node.xhttp().unwrap();
            assert_eq!(upload.http_version, version);
            assert_eq!(node.download().unwrap().http_version, version);
            assert_eq!(upload.host, "example.com");
            assert_eq!(matches!(node.security, SecurityConfig::None), !tls);
            if let SecurityConfig::Tls(config) = &node.security {
                let expected = if version == XHttpVersion::Http1 {
                    b"http/1.1".as_slice()
                } else {
                    b"h2".as_slice()
                };
                assert_eq!(config.alpn, vec![expected.to_vec()]);
                assert_eq!(config.required_alpn.as_deref(), Some(expected));
            }
        }
    }
}

#[test]
fn download_certificate_policy_inherits_and_explicit_false_or_empty_clears() {
    use vole::config::SecurityConfig;
    for clear in [false, true] {
        let download = if clear {
            json!({"skip-cert-verify":false,"name-cert-verify":"","fingerprint":""})
        } else {
            json!({})
        };
        let mut value: Value =
            serde_json::from_slice(&document(json!({"download-settings":download}))).unwrap();
        let node = &mut value["proxies"][0];
        node["skip-cert-verify"] = true.into();
        node["name-cert-verify"] = "verify.example.com".into();
        node["fingerprint"] = "ab".repeat(32).into();
        let config = Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).unwrap();
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            unreachable!()
        };
        let SecurityConfig::Tls(download) = &node.download().unwrap().security else {
            unreachable!()
        };
        assert_eq!(download.certificate.skip_cert_verify, !clear);
        assert_eq!(
            download.certificate.verification_name.as_deref(),
            if clear {
                None
            } else {
                Some("verify.example.com")
            }
        );
        assert_eq!(
            download.certificate.fingerprint,
            if clear { None } else { Some([0xab; 32]) }
        );
        let SecurityConfig::Tls(upload) = &node.security else {
            unreachable!()
        };
        assert!(upload.certificate.skip_cert_verify);
        assert_eq!(upload.certificate.fingerprint, Some([0xab; 32]));
    }
}

#[test]
fn download_mtls_identity_is_inherited_or_replaced_and_cleared_as_a_pair() {
    use base64::Engine as _;
    use vole::config::SecurityConfig;
    let identity = |name: &str| {
        let value = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
        let pem = |kind, bytes| {
            format!(
                "-----BEGIN {kind}-----\n{}\n-----END {kind}-----\n",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            )
        };
        (
            pem("CERTIFICATE", value.cert.der().as_ref()),
            pem("PRIVATE KEY", &value.signing_key.serialize_der()),
        )
    };
    let (certificate, private_key) = identity("upload.invalid");
    let (other_certificate, other_key) = identity("download.invalid");
    for (fields, expected) in [
        (json!({}), Some(certificate.as_str())),
        (
            json!({"certificate":other_certificate,"private-key":other_key}),
            Some(other_certificate.as_str()),
        ),
        (json!({"certificate":"","private-key":""}), None),
    ] {
        let mut value: Value =
            serde_json::from_slice(&document(json!({"download-settings":fields}))).unwrap();
        value["proxies"][0]["certificate"] = certificate.clone().into();
        value["proxies"][0]["private-key"] = private_key.clone().into();
        let parsed = Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).unwrap();
        let ProxyProtocol::Vless(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        let SecurityConfig::Tls(download) = &node.download().unwrap().security else {
            unreachable!()
        };
        assert_eq!(
            download.identity.as_ref().map(|v| v.certificate.as_str()),
            expected
        );
        assert!(!format!("{parsed:?}").contains("BEGIN"));
    }
    for fields in [
        json!({"certificate":certificate}),
        json!({"private-key":private_key}),
        json!({"certificate":certificate,"private-key":other_key}),
        json!({"certificate":"","private-key":private_key}),
        json!({"certificate":null,"private-key":null}),
    ] {
        assert!(Config::parse_yaml(&document(json!({"download-settings":fields}))).is_err());
    }
}

#[test]
fn download_reality_object_replaces_inherits_or_clears_without_merging_keys() {
    use base64::Engine as _;
    use vole::config::SecurityConfig;
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7; 32]);
    let other = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8; 32]);
    for (download, expected) in [
        (json!({}), Some(([7; 32], vec![0xaa]))),
        (
            json!({"reality-opts":{"public-key":other}}),
            Some(([8; 32], vec![])),
        ),
        (json!({"reality-opts":{}}), None),
    ] {
        let mut value: Value = serde_json::from_slice(&document(
            json!({"mode":"packet-up","download-settings":download}),
        ))
        .unwrap();
        value["proxies"][0]["reality-opts"] = json!({"public-key":key,"short-id":"aa"});
        let parsed = Config::parse_yaml(&serde_json::to_vec(&value).unwrap()).unwrap();
        let ProxyProtocol::Vless(node) = &parsed.proxies[0].protocol else {
            unreachable!()
        };
        match (&node.download().unwrap().security, expected) {
            (SecurityConfig::Reality(config), Some((key, id))) => {
                assert_eq!(config.public_key, key);
                assert_eq!(config.short_id, id);
            }
            (SecurityConfig::Tls(_), None) => {}
            _ => panic!("wrong download security"),
        }
        assert!(matches!(node.security, SecurityConfig::Reality(_)));
    }
    for reality in [
        json!({"short-id":"aa"}),
        json!({"public-key":""}),
        json!({"public-key":null}),
        json!({"public-key":key,"short-id":null}),
    ] {
        assert!(
            Config::parse_yaml(&document(
                json!({"download-settings":{"reality-opts":reality}})
            ))
            .is_err()
        );
    }
}

#[test]
fn reuse_object_presence_and_download_whole_object_replacement_are_preserved() {
    for (options, upload, down) in [
        (json!({"download-settings":{}}), false, false),
        (
            json!({"reuse-settings":{},"download-settings":{}}),
            true,
            true,
        ),
        (
            json!({"download-settings":{"reuse-settings":{}}}),
            false,
            true,
        ),
    ] {
        let config = Config::parse_yaml(&document(options)).unwrap();
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            unreachable!()
        };
        assert_eq!(node.xhttp().unwrap().reuse.is_some(), upload);
        assert_eq!(node.download().unwrap().reuse.is_some(), down);
    }
    let config = Config::parse_yaml(&document(json!({"reuse-settings":{"max-concurrency":"2-4","h-keep-alive-period":-1},"download-settings":{"reuse-settings":{}}}))).unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        unreachable!()
    };
    assert_ne!(node.xhttp().unwrap().reuse, node.download().unwrap().reuse);
    for value in [
        json!(null),
        json!({"max-connections":1}),
        json!({"max-concurrency":"1-0"}),
        json!({"h-max-request-times":"-1"}),
        json!({"h-keep-alive-period":1.5}),
    ] {
        assert!(Config::parse_yaml(&document(json!({"reuse-settings":value}))).is_err());
    }
}
