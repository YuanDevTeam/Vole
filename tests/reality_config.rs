#![cfg(feature = "outbound-vless")]

use serde_json::{Value, json};
use vole::config::{ClientFingerprint, Config, ProxyProtocol, SecurityConfig};

fn proxy() -> Value {
    json!({
        "name": "edge", "type": "vless", "server": "example.invalid", "port": 443,
        "uuid": "07070707-0707-0707-0707-070707070707", "tls": true,
        "reality-opts": {
            "public-key": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
            "support-x25519mlkem768": true
        }
    })
}

fn parse(proxy: Value) -> vole::Result<Config> {
    Config::parse_yaml(
        &serde_json::to_vec(&json!({
            "mixed-port": 1080, "proxies": [proxy], "rules": ["MATCH,edge"]
        }))
        .unwrap(),
    )
}

#[test]
fn public_reality_accepts_explicit_hybrid_without_replacing_the_fingerprint() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "public_reality_accepts_explicit_hybrid_without_replacing_the_fingerprint",
    );
    for profile in [None, Some("none"), Some(""), Some("chrome")] {
        let mut node = proxy();
        if let Some(profile) = profile {
            node["client-fingerprint"] = json!(profile);
        }
        assert!(
            parse(node).is_ok(),
            "hybrid REALITY rejected for {profile:?}"
        );
    }
}

#[test]
fn public_reality_rejects_profiles_without_the_required_hybrid_share() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "public_reality_rejects_profiles_without_the_required_hybrid_share",
    );
    for profile in ["firefox", "safari", "ios"] {
        let mut node = proxy();
        node["client-fingerprint"] = json!(profile);
        assert!(
            parse(node).is_err(),
            "accepted incompatible profile {profile}"
        );
    }
}

fn securities(node: Value) -> (SecurityConfig, SecurityConfig) {
    let config = parse(node).unwrap();
    let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
        panic!()
    };
    (
        node.security.clone(),
        node.download().unwrap().security.clone(),
    )
}

fn split_proxy() -> Value {
    let mut node = proxy();
    node["network"] = json!("xhttp");
    node["xhttp-opts"] = json!({"mode":"stream-up", "download-settings":{}});
    node
}

#[test]
fn download_inherits_or_replaces_the_entire_reality_object_without_leaf_merging() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "download_inherits_or_replaces_the_entire_reality_object_without_leaf_merging",
    );
    let node = split_proxy();
    let (main, download) = securities(node.clone());
    assert_eq!(main, download);
    let SecurityConfig::Reality(inherited) = download else {
        panic!()
    };
    assert!(inherited.support_x25519mlkem768);
    assert_eq!(inherited.client_fingerprint, None);

    let mut replacement = node.clone();
    replacement["client-fingerprint"] = json!("chrome");
    replacement["reality-opts"]["short-id"] = json!("1234");
    replacement["xhttp-opts"]["download-settings"]["reality-opts"] =
        json!({"public-key":node["reality-opts"]["public-key"]});
    let (_, download) = securities(replacement);
    let SecurityConfig::Reality(download) = download else {
        panic!()
    };
    assert!(!download.support_x25519mlkem768);
    assert!(download.short_id.is_empty());
    assert_eq!(
        download.client_fingerprint,
        Some(ClientFingerprint::Chrome133)
    );

    let mut cleared = node;
    cleared["xhttp-opts"]["download-settings"]["reality-opts"] = json!({});
    assert!(matches!(securities(cleared).1, SecurityConfig::Tls(_)));
}

#[test]
fn hybrid_flag_is_a_strict_nonnullable_boolean_on_both_legs() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "hybrid_flag_is_a_strict_nonnullable_boolean_on_both_legs",
    );
    for value in [Value::Null, json!("true"), json!(1), json!([]), json!({})] {
        let mut main = proxy();
        main["reality-opts"]["support-x25519mlkem768"] = value.clone();
        assert!(parse(main).is_err());
        let mut download = split_proxy();
        download["xhttp-opts"]["download-settings"]["reality-opts"] =
            proxy()["reality-opts"].clone();
        download["xhttp-opts"]["download-settings"]["reality-opts"]["support-x25519mlkem768"] =
            value;
        assert!(parse(download).is_err());
    }
    for value in [false, true] {
        let mut node = split_proxy();
        node["xhttp-opts"]["download-settings"]["reality-opts"] =
            json!({"support-x25519mlkem768":value});
        assert!(
            parse(node).is_err(),
            "nonempty replacement requires public-key"
        );
    }
}

#[test]
fn classic_default_and_explicit_false_preserve_all_existing_profiles() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "classic_default_and_explicit_false_preserve_all_existing_profiles",
    );
    for profile in ["none", "chrome", "firefox", "safari", "ios", "random"] {
        for explicit in [false, true] {
            let mut node = split_proxy();
            node["client-fingerprint"] = json!(profile);
            if explicit {
                node["reality-opts"]["support-x25519mlkem768"] = json!(false);
            } else {
                node["reality-opts"]
                    .as_object_mut()
                    .unwrap()
                    .remove("support-x25519mlkem768");
            }
            let (main, download) = securities(node);
            for security in [main, download] {
                let SecurityConfig::Reality(reality) = security else {
                    panic!()
                };
                assert!(!reality.support_x25519mlkem768);
            }
        }
    }
}

#[test]
fn inherited_profile_is_validated_after_download_reality_replacement() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "inherited_profile_is_validated_after_download_reality_replacement",
    );
    let mut node = split_proxy();
    node["client-fingerprint"] = json!("firefox");
    node["reality-opts"]["support-x25519mlkem768"] = json!(false);
    node["xhttp-opts"]["download-settings"]["reality-opts"] = proxy()["reality-opts"].clone();
    assert!(parse(node.clone()).is_err());
    node["xhttp-opts"]["download-settings"]["client-fingerprint"] = json!("chrome");
    assert!(parse(node).is_ok());

    let mut inherited = split_proxy();
    inherited["xhttp-opts"]["download-settings"]["client-fingerprint"] = json!("safari");
    assert!(parse(inherited).is_err());
}

#[test]
fn hybrid_reality_cannot_be_combined_with_h3_or_plaintext_on_either_leg() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "SECURITY-CONFIG-TLS",
        "hybrid_reality_cannot_be_combined_with_h3_or_plaintext_on_either_leg",
    );
    for download in [false, true] {
        for patch in [json!({"tls":false}), json!({"alpn":["h3"]})] {
            let mut node = split_proxy();
            let target = if download {
                &mut node["xhttp-opts"]["download-settings"]
            } else {
                &mut node
            };
            target
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert!(parse(node).is_err());
        }
    }
}
