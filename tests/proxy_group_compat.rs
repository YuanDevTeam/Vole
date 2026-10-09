use vole::config::{
    Config, DnsRoute, ProxyGroupId, ProxyGroupMemberTarget, RouteTargetId, RuleAction,
};

const COMMON_PREFIX: &str = r#"
mixed-port: 1080
authentication: [user:password]
proxies:
  - name: node-a
    type: socks5
    server: 192.0.2.1
    port: 1080
    udp: true
  - name: node-b
    type: socks5
    server: 192.0.2.2
    port: 1080
    udp: true
"#;

#[test]
fn accepts_the_mihomo_select_common_subset_without_flattening() {
    let yaml = format!(
        r#"{COMMON_PREFIX}
proxy-groups:
  - name: backup
    type: select
    proxies: [node-b, DIRECT]
  - name: primary
    type: select
    proxies: [node-a, backup, REJECT, node-a]
    default-selected: backup
dns:
  enable: true
  nameserver: ["tcp://1.1.1.1:53#primary"]
rules:
  - DOMAIN-SUFFIX,example.com,backup
  - MATCH,primary
"#
    );

    let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
    let backup = ProxyGroupId::new(0).unwrap();
    let primary = ProxyGroupId::new(1).unwrap();

    assert_eq!(config.proxy_groups[1].initial_member, 1);
    assert_eq!(
        config.proxy_groups[1]
            .members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        ["node-a", "backup", "REJECT", "node-a"]
    );
    assert_eq!(
        config.proxy_groups[1].members[1].target,
        ProxyGroupMemberTarget::Route(RouteTargetId::Group(backup))
    );
    assert_eq!(
        config.rules.last().unwrap().action,
        RuleAction::Route(RouteTargetId::Group(primary))
    );
    assert_eq!(
        config.rules[0].action,
        RuleAction::Route(RouteTargetId::Group(backup))
    );
    assert_eq!(
        config.dns.nameservers[0].route,
        DnsRoute::Route(RouteTargetId::Group(primary))
    );
}

#[test]
fn keeps_vole_stricter_than_mihomo_at_the_documented_boundaries() {
    for groups in [
        r#"
proxy-groups:
  - name: primary
    type: select
    proxies: [node-a]
    default-selected: missing
"#,
        r#"
proxy-groups:
  - name: primary
    type: select
    proxies: [node-a]
    url: https://example.com/generate_204
"#,
        r#"
proxy-groups:
  - name: primary
    type: url-test
    proxies: [node-a]
"#,
    ] {
        let yaml = format!("{COMMON_PREFIX}{groups}rules:\n  - MATCH,primary\n");
        assert!(Config::parse_yaml(yaml.as_bytes()).is_err(), "{yaml}");
    }
}

#[test]
fn accepts_group_upstream_but_rejects_cycles_through_unselected_members() {
    let yaml = format!(
        r#"{COMMON_PREFIX}
proxy-groups:
  - name: primary
    type: select
    proxies: [backup, REJECT]
  - name: backup
    type: select
    proxies: [node-b, DIRECT]
rules:
  - MATCH,primary
"#
    )
    .replacen(
        "    server: 192.0.2.1\n",
        "    server: 192.0.2.1\n    dialer-proxy: primary\n",
        1,
    );

    let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
    assert_eq!(
        config.proxies[0].dialer_proxy,
        Some(RouteTargetId::Group(ProxyGroupId::new(0).unwrap()))
    );
    // node-a -> primary -> backup -> node-a is forbidden even while backup
    // initially selects the unrelated node-b.
    let cycle = yaml.replace("proxies: [node-b, DIRECT]", "proxies: [node-b, node-a]");
    let error = Config::parse_yaml(cycle.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("circular"));
}

#[test]
fn validates_config_sized_mixed_graphs_iteratively() {
    let mut yaml =
        String::from("mixed-port: 1080\nauthentication: [u:p]\nrules: ['MATCH,n0']\nproxies:\n");
    for index in 0..1700 {
        yaml.push_str(&format!("  - {{name: n{index}, type: socks5, server: 192.0.2.1, port: 1080, dialer-proxy: g{index}}}\n"));
    }
    yaml.push_str("proxy-groups:\n");
    for index in 0..1700 {
        let member = if index == 1699 {
            "DIRECT".to_owned()
        } else {
            format!("n{}", index + 1)
        };
        yaml.push_str(&format!(
            "  - {{name: g{index}, type: select, proxies: [{member}, REJECT]}}\n"
        ));
    }
    assert!(yaml.len() > 200 * 1024 && yaml.len() < 256 * 1024);
    assert!(Config::parse_yaml(yaml.as_bytes()).is_ok());
    let cycle = yaml.replace("[DIRECT, REJECT]", "[DIRECT, n0]");
    assert!(
        Config::parse_yaml(cycle.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("circular")
    );
}
