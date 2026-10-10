#![cfg(all(feature = "outbound-vless", feature = "sing-mux"))]
use serde_json::json;
use vole::config::Config;

fn parse(options: serde_json::Value, vision: bool) -> bool {
    Config::parse_yaml(
        &serde_json::to_vec(&json!({
            "mixed-port":1080,
            "proxies":[{"name":"edge","type":"vless","server":"example.com","port":443,
                "uuid":"07070707-0707-0707-0707-070707070707","tls":true,
                "flow":if vision {"xtls-rprx-vision"} else {""},"smux":options}],
            "rules":["MATCH,edge"]
        }))
        .unwrap(),
    )
    .is_ok()
}

#[test]
fn sing_mux_accepts_three_protocols_and_rejects_invalid_or_ignored_options() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "sing_mux_accepts_three_protocols_and_rejects_invalid_or_ignored_options",
    );
    for protocol in ["", "h2mux", "smux", "yamux"] {
        for enabled in [false, true] {
            assert!(parse(
                json!({"enabled":enabled,"protocol":protocol,"padding":true,
                "only-tcp":true,"max-connections":2,"min-streams":3}),
                false
            ));
        }
    }
    assert!(parse(json!({"enabled":true,"max-streams":3}), false));
    assert!(parse(json!({}), false));
    assert!(parse(
        json!({"enabled":true,"max-connections":2,"max-streams":3}),
        false
    ));
    assert!(!parse(json!([]), false));
    for field in [
        "enabled",
        "protocol",
        "padding",
        "only-tcp",
        "max-connections",
        "min-streams",
        "max-streams",
    ] {
        for value in [json!(null), json!([]), json!(0.5)] {
            assert!(!parse(json!({field:value}), false), "{field}");
        }
    }
    for field in ["max-connections", "min-streams", "max-streams"] {
        for value in [-1, 0, 1, 2147483647_i64] {
            assert!(parse(json!({field:value}), false));
        }
    }
    for options in [
        json!(null),
        json!({"enabled":null}),
        json!({"protocol":"mux"}),
        json!({"padding":1}),
        json!({"only-tcp":null}),
        json!({"enabled":true,"brutal":true}),
    ] {
        assert!(!parse(options, false));
    }
    assert!(!parse(json!({"enabled":true}), true));
}

#[cfg(all(
    feature = "outbound-http",
    feature = "outbound-socks5",
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-shadowsocks",
    feature = "outbound-anytls",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic"
))]
#[test]
fn shared_smux_wraps_all_protocols_and_computes_effective_udp_capability() {
    for (protocol, fields) in [
        ("http", json!({})),
        ("socks5", json!({"udp":false})),
        ("trojan", json!({"password":"test","udp":false})),
        (
            "vmess",
            json!({"uuid":"07070707-0707-0707-0707-070707070707","udp":false}),
        ),
        (
            "vless",
            json!({"uuid":"07070707-0707-0707-0707-070707070707","udp":false}),
        ),
        ("anytls", json!({"password":"test","udp":false})),
        (
            "ss",
            json!({"cipher":"2022-blake3-aes-128-gcm","password":"BwcHBwcHBwcHBwcHBwcHBw==","udp":false}),
        ),
        ("hysteria2", json!({"password":"test"})),
        (
            "tuic",
            json!({"uuid":"07070707-0707-0707-0707-070707070707","password":"test"}),
        ),
    ] {
        let mut node = json!({"name":"edge","type":protocol,"server":"example.com","port":443});
        node.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let parse_node = |node: serde_json::Value| {
            Config::parse_yaml(
                json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,edge"]})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap()
        };
        let native_udp = parse_node(node.clone()).proxies[0].udp;
        for only_tcp in [false, true] {
            node["smux"] = json!({"enabled":true,"protocol":"","only-tcp":only_tcp,"max-connections":2,"min-streams":3,"max-streams":1});
            let parsed = parse_node(node.clone());
            assert_eq!(parsed.proxies[0].udp, !only_tcp || native_udp, "{protocol}");
            let options = parsed.proxies[0].smux.as_ref().unwrap();
            assert_eq!(
                (
                    options.max_connections,
                    options.min_streams,
                    options.max_streams
                ),
                (2, 3, 1)
            );
        }
    }
}
