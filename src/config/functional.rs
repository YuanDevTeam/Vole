//! Configuration for named functional route targets without server endpoints.
use super::*;

pub(super) fn validate_fields(mapping: &serde_yaml_ng::Mapping) -> Result<()> {
    let Some(kind) = mapping.get("type").and_then(serde_yaml_ng::Value::as_str) else {
        return Ok(());
    };
    if !matches!(kind, "direct" | "dns" | "reject") {
        return Ok(());
    }
    for key in mapping.keys().filter_map(serde_yaml_ng::Value::as_str) {
        let accepted = matches!(key, "name" | "type")
            || (kind == "direct"
                && matches!(key, "interface-name" | "routing-mark" | "ip-version"));
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

#[cfg(test)]
mod tests {
    use super::*;

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
