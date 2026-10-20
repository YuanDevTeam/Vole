//! Configuration for named functional route targets without server endpoints.
use super::*;
use std::sync::Arc;

pub(super) fn validate_fields(mapping: &serde_yaml_ng::Mapping) -> Result<()> {
    let Some(kind) = mapping.get("type").and_then(serde_yaml_ng::Value::as_str) else {
        return Ok(());
    };
    if !matches!(kind, "direct" | "dns" | "reject" | "rematch") {
        return Ok(());
    }
    for key in mapping.keys().filter_map(serde_yaml_ng::Value::as_str) {
        let accepted = matches!(key, "name" | "type")
            || (kind == "direct"
                && matches!(
                    key,
                    "interface-name" | "routing-mark" | "ip-version" | "tfo"
                ))
            || (kind == "rematch" && matches!(key, "target-rematch-name" | "target-sub-rule"));
        if !accepted {
            return invalid("unsupported functional outbound field");
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawFunctional {
    name: String,
}

impl RawFunctional {
    pub(super) fn normalize(
        self,
        protocol: ProxyProtocol,
    ) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        validate_route_target_definition_name(&self.name, "proxy name")?;
        Ok((self.name, None, true, protocol))
    }
}

/// A routing control; omitted values preserve metadata, empty values clear it.
#[derive(Clone, PartialEq, Eq)]
pub struct RematchConfig {
    pub target_rematch_name: Option<Arc<str>>,
    pub target_sub_rule: Option<Arc<str>>,
}
impl std::fmt::Debug for RematchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RematchConfig")
            .field("sets_name", &self.target_rematch_name.is_some())
            .field("sets_program", &self.target_sub_rule.is_some())
            .finish()
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRematch {
    name: String,
    #[serde(rename = "target-rematch-name", default)]
    target_rematch_name: Option<String>,
    #[serde(rename = "target-sub-rule", default)]
    target_sub_rule: Option<String>,
}
impl RawRematch {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        validate_route_target_definition_name(&self.name, "proxy name")?;
        if self.target_rematch_name.is_none() && self.target_sub_rule.is_none() {
            return invalid("rematch requires target-rematch-name or target-sub-rule");
        }
        Ok((
            self.name,
            None,
            true,
            ProxyProtocol::Rematch(RematchConfig {
                target_rematch_name: self.target_rematch_name.map(Arc::from),
                target_sub_rule: self.target_sub_rule.map(Arc::from),
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rematch_schema_preserves_omitted_empty_and_unknown_program_names() {
        let config = Config::parse_yaml(
            br#"proxies:
  - {name: marked, type: rematch, target-rematch-name: blue}
  - {name: clear, type: rematch, target-rematch-name: '', target-sub-rule: ''}
  - {name: unknown, type: rematch, target-sub-rule: missing}
  - {name: null-program, type: rematch, target-rematch-name: blue, target-sub-rule: null}
  - {name: null-mark, type: rematch, target-rematch-name: null, target-sub-rule: child}
"#,
        )
        .unwrap();
        let node = |index: usize| match &config.proxies[index].protocol {
            ProxyProtocol::Rematch(value) => value,
            _ => panic!("rematch protocol"),
        };
        assert_eq!(node(0).target_rematch_name.as_deref(), Some("blue"));
        assert_eq!(node(0).target_sub_rule.as_deref(), None);
        assert_eq!(node(1).target_rematch_name.as_deref(), Some(""));
        assert_eq!(node(1).target_sub_rule.as_deref(), Some(""));
        assert_eq!(node(2).target_sub_rule.as_deref(), Some("missing"));
        assert_eq!(node(3).target_rematch_name.as_deref(), Some("blue"));
        assert_eq!(node(3).target_sub_rule, None);
        assert_eq!(node(4).target_rematch_name, None);
        assert_eq!(node(4).target_sub_rule.as_deref(), Some("child"));
        assert!(
            config
                .proxies
                .iter()
                .all(|node| node.server_endpoint().is_none() && node.udp)
        );
        for fields in [
            "",
            "target-rematch-name: null",
            "target-rematch-name: null, target-sub-rule: null",
            "target-sub-rule: 1",
            "target-sub-rule: child, udp: true",
            "target-sub-rule: child, dialer-proxy: DIRECT",
            "target-sub-rule: child, smux: {enabled: false}",
        ] {
            assert!(
                Config::parse_yaml(
                    format!("proxies: [{{name: edge, type: rematch, {fields}}}]").as_bytes()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rematch_values_survive_provider_materialization_without_subrule_binding() {
        let config = Config::parse_yaml(
            br#"proxy-providers:
  controls:
    type: inline
    payload:
      - {name: mark, type: rematch, target-rematch-name: '', target-sub-rule: missing}
proxy-groups: [{name: selected, type: select, use: [controls]}]
rules: ['REMATCH-NAME,blue/Green,DIRECT', 'MATCH,selected']
"#,
        )
        .unwrap();
        let fresh = config
            .providers
            .as_ref()
            .unwrap()
            .materialize(&Default::default())
            .unwrap();
        assert_eq!(config.proxies, fresh.proxies);
        assert_eq!(config.rules, fresh.rules);
    }

    #[test]
    fn node_tfo_is_explicit_and_does_not_inherit_across_proxy_chain() {
        let config = Config::parse_yaml(
            br#"proxies:
  - {name: leaf, type: socks5, server: 192.0.2.1, port: 1080, tfo: true, dialer-proxy: hop}
  - {name: hop, type: socks5, server: 192.0.2.2, port: 1080}
  - {name: local, type: direct, tfo: true}
"#,
        )
        .unwrap();
        assert!(config.proxies[0].tfo);
        assert!(!config.proxies[1].tfo);
        assert!(config.proxies[2].tfo);
    }

    #[test]
    fn functional_outbounds_have_names_and_udp_without_server_endpoints() {
        let config = Config::parse_yaml(
            br#"
proxies:
  - {name: local, type: direct, interface-name: eth0, routing-mark: 7, ip-version: ipv4}
  - {name: resolver, type: dns}
  - {name: blocked, type: reject}
rules: ['DST-PORT,53,resolver', 'DOMAIN,blocked.test,blocked', 'MATCH,local']
"#,
        )
        .unwrap();
        assert_eq!(config.proxies.len(), 3);
        assert!(
            config
                .proxies
                .iter()
                .all(|node| node.server_endpoint().is_none() && node.udp)
        );
        assert_eq!(config.proxies[0].egress.interface.as_deref(), Some("eth0"));
        assert_eq!(config.proxies[0].egress.routing_mark, 7);
        assert_eq!(config.proxies[0].ip_version, IpVersion::Ipv4);
    }

    #[test]
    fn functional_schema_rejects_endpoint_and_unconsumed_options() {
        for kind in ["direct", "dns", "reject"] {
            let mut fields = vec![
                "server: example.test",
                "port: 443",
                "udp: true",
                "dialer-proxy: DIRECT",
                "smux: {enabled: false}",
                "action: drop",
            ];
            if kind != "direct" {
                fields.extend(["interface-name: ''", "routing-mark: 0", "ip-version: dual"]);
            }
            for field in fields {
                let input = format!("proxies: [{{name: edge, type: {kind}, {field}}}]");
                assert!(
                    Config::parse_yaml(input.as_bytes()).is_err(),
                    "{kind}: {field}"
                );
            }
        }
    }

    #[test]
    fn drop_and_compatible_are_real_reserved_rule_and_group_targets() {
        let config = Config::parse_yaml(
            br#"
proxy-groups:
  - {name: selected, type: select, proxies: [REJECT-DROP, COMPATIBLE]}
rules: ['DOMAIN,drop.test,REJECT-DROP', 'MATCH,COMPATIBLE']
"#,
        )
        .unwrap();
        assert_eq!(config.rules[0].action, RuleAction::RejectDrop);
        assert_eq!(config.rules[1].action, RuleAction::Direct);
        assert_eq!(
            config.proxy_groups[0].members[0].target,
            ProxyGroupMemberTarget::RejectDrop
        );
        assert_eq!(
            config.proxy_groups[0].members[1].target,
            ProxyGroupMemberTarget::Direct
        );
    }

    #[test]
    fn dns_reserved_tokens_are_not_physical_interface_names() {
        let config = Config::parse_yaml(
            br#"
dns:
  enable: true
  nameserver:
    - udp://192.0.2.53#COMPATIBLE
    - tcp://192.0.2.53#REJECT
    - udp://192.0.2.53#REJECT-DROP
"#,
        )
        .unwrap();
        assert_eq!(
            config
                .dns
                .nameservers
                .iter()
                .map(|server| server.route)
                .collect::<Vec<_>>(),
            [DnsRoute::Direct, DnsRoute::Reject, DnsRoute::RejectDrop]
        );
        assert!(
            config
                .dns
                .nameservers
                .iter()
                .all(|server| server.options.interface.is_none())
        );
    }
}
