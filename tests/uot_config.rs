use serde_json::{Value, json};
use vole::config::{Config, ProxyProtocol};

fn node() -> Value {
    json!({"name":"ss","type":"ss","server":"fixture.invalid","port":443,
        "cipher":"2022-blake3-aes-128-gcm","password":"BwcHBwcHBwcHBwcHBwcHBw==","udp":true})
}

fn parse(node: Value) -> vole::Result<Config> {
    Config::parse_yaml(
        json!({"mixed-port":1080,"proxies":[node],"rules":["MATCH,ss"]})
            .to_string()
            .as_bytes(),
    )
}

#[test]
fn ss_uot_is_opt_in_and_accepts_only_explicit_or_default_v2() {
    if !cfg!(feature = "outbound-shadowsocks") {
        let mut n = node();
        n["udp-over-tcp"] = json!(true);
        assert!(parse(n).is_err());
        return;
    }
    for enabled in [false, true] {
        let mut n = node();
        n["udp-over-tcp"] = json!(enabled);
        let c = parse(n.clone()).unwrap();
        let ProxyProtocol::Shadowsocks(ss) = &c.proxies[0].protocol else {
            panic!("protocol")
        };
        assert_eq!(ss.udp_over_tcp, enabled);
        n["udp-over-tcp-version"] = json!(2);
        assert_eq!(
            parse(n.clone()).is_ok(),
            enabled,
            "only enabled v2 accepts a version"
        );
        for bad in [
            json!(0),
            json!(1),
            json!(3),
            json!(256),
            json!(-1),
            json!(2.0),
            json!("2"),
            json!(null),
            json!(true),
            json!({}),
        ] {
            n["udp-over-tcp-version"] = bad;
            assert!(parse(n.clone()).is_err());
        }
    }
    let c = parse(node()).unwrap();
    let ProxyProtocol::Shadowsocks(ss) = &c.proxies[0].protocol else {
        panic!("protocol")
    };
    assert!(!ss.udp_over_tcp);
    for udp in [Some(json!(false)), None] {
        let mut n = node();
        if let Some(udp) = udp {
            n["udp"] = udp;
        } else {
            n.as_object_mut().unwrap().remove("udp");
        }
        n["udp-over-tcp"] = json!(true);
        assert!(parse(n).is_err());
    }
    for bad in [json!(null), json!("true"), json!(1), json!([])] {
        let mut n = node();
        n["udp-over-tcp"] = bad;
        assert!(parse(n).is_err());
    }
    let mut n = node();
    n["udp-over-tcp-version"] = json!(2);
    assert!(parse(n).is_err());
    let mut n = node();
    n["udp-over-tcp"] = json!(true);
    n["plugin"] = json!("shadow-tls");
    n["plugin-opts"] = json!({"host":"cover.invalid","version":3,"password":"synthetic-secret"});
    assert_eq!(parse(n).is_ok(), cfg!(feature = "shadow-tls-v3"));
    assert!(parse(json!({"name":"ss","type":"anytls","server":"fixture.invalid","port":443,"password":"synthetic-secret","udp":true,"udp-over-tcp":true})).is_err());
}
