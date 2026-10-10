use serde::Deserialize;

use crate::{Result, VoleError};

use super::{ProxyConfig, ProxyId, RawOutbound, RouteTargetId, normalize_proxy_graph};

/// Strict node-only configuration accepted by the built-in latency runner.
///
/// A measurement never owns an inbound, routing rules, DNS, sniffer state, or
/// GeoData. Keeping a separate deserializer makes those fields unknown rather
/// than silently ignoring runtime-only behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeasureConfig {
    pub(crate) proxies: Vec<ProxyConfig>,
    pub(crate) default_proxy: ProxyId,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMeasureConfig {
    proxies: Vec<RawOutbound>,
}

impl MeasureConfig {
    pub(crate) fn parse_yaml(input: &[u8]) -> Result<Self> {
        let yaml = super::yaml::parse(input)?;
        let raw: RawMeasureConfig = serde_yaml_ng::from_value(yaml)
            .map_err(|error| VoleError::InvalidConfig(error.to_string()))?;
        raw.normalize()
    }
}

impl RawMeasureConfig {
    fn normalize(self) -> Result<MeasureConfig> {
        let (proxies, _) = normalize_proxy_graph(self.proxies)?;
        let mut referenced_as_parent = vec![false; proxies.len()];
        for proxy in &proxies {
            if let Some(RouteTargetId::Proxy(parent)) = proxy.dialer_proxy {
                referenced_as_parent[parent.index()] = true;
            }
        }
        let mut heads = referenced_as_parent
            .iter()
            .enumerate()
            .filter_map(|(index, referenced)| (!referenced).then_some(ProxyId::from_index(index)));
        let default_proxy = heads.next().ok_or_else(|| {
            VoleError::InvalidConfig(
                "measurement proxies must form one chain with exactly one head".to_owned(),
            )
        })?;
        if heads.next().is_some() {
            return Err(VoleError::InvalidConfig(
                "measurement proxies must form one chain with exactly one head".to_owned(),
            ));
        }

        let mut visited = vec![false; proxies.len()];
        let mut current = Some(default_proxy);
        let mut reachable = 0_usize;
        while let Some(proxy_id) = current {
            if visited[proxy_id.index()] {
                break;
            }
            visited[proxy_id.index()] = true;
            reachable += 1;
            current = match proxies[proxy_id.index()].dialer_proxy {
                Some(RouteTargetId::Proxy(id)) => Some(id),
                None => None,
                Some(RouteTargetId::Group(_)) => {
                    unreachable!("measurement has no group declarations")
                }
            };
        }
        if reachable != proxies.len() {
            return Err(VoleError::InvalidConfig(
                "measurement proxies must form one chain with exactly one head".to_owned(),
            ));
        }

        Ok(MeasureConfig {
            proxies,
            default_proxy,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn measurement_rejects_oversized_documents() {
        let _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-SCHEMA",
            "measurement_rejects_oversized_documents",
        );
        assert!(
            super::MeasureConfig::parse_yaml(&vec![b'x'; super::super::MAX_CONFIG_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn measurement_hysteria2_admission_matches_the_protocol_feature() {
        let yaml =
            b"proxies:\n  - name: node\n    type: hysteria2\n    server: example.com\n    port: 443\n";
        assert_eq!(
            super::MeasureConfig::parse_yaml(yaml).is_ok(),
            cfg!(feature = "outbound-hysteria2")
        );
    }
    use super::*;

    const NODE: &str = r#"
proxies:
  - name: proxy
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: true
"#;

    fn socks_chain(count: usize) -> String {
        assert!(count > 0);
        let mut yaml = "proxies:\n".to_owned();
        for index in 0..count {
            yaml.push_str(&format!("  - name: node-{index}\n    type: socks5\n"));
            if index > 0 {
                yaml.push_str(&format!("    dialer-proxy: node-{}\n", index - 1));
            }
            yaml.push_str(&format!(
                "    server: node-{index}.example.com\n    port: 1080\n    udp: true\n"
            ));
        }
        yaml
    }

    #[test]
    fn accepts_only_the_node_graph_subset() {
        let config = MeasureConfig::parse_yaml(NODE.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.default_proxy.index(), 0);

        for extra in [
            "mixed-port: 18080",
            "port: 18080",
            "socks-port: 18080",
            "listeners: []",
            "udp: true",
            "authentication: [measure:secret]",
            "tun: { enable: false }",
            "sniffer: { enable: false }",
            "dns: { enable: false }",
            "rules: [MATCH,PROXY]",
            "geo-auto-update: false",
            "default-proxy: proxy",
            "proxy-groups: []",
        ] {
            let yaml = NODE.replacen("proxies:", &format!("{extra}\nproxies:"), 1);
            assert!(
                MeasureConfig::parse_yaml(yaml.as_bytes()).is_err(),
                "{extra} must be rejected"
            );
        }
    }

    #[test]
    fn reuses_proxy_graph_validation() {
        let chain = NODE.replace(
            "  - name: proxy\n",
            "  - name: hop\n    type: socks5\n    server: 127.0.0.1\n    port: 1081\n    udp: true\n  - name: exit\n    dialer-proxy: hop\n",
        );
        let config = MeasureConfig::parse_yaml(chain.as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 2);
        assert_eq!(config.default_proxy.index(), 1);

        let unknown = NODE.replace(
            "    server: 127.0.0.1\n",
            "    dialer-proxy: missing\n    server: 127.0.0.1\n",
        );
        assert!(MeasureConfig::parse_yaml(unknown.as_bytes()).is_err());

        let independent = NODE.replace(
            "proxies:\n",
            "proxies:\n  - name: unused\n    type: socks5\n    server: 127.0.0.1\n    port: 1081\n",
        );
        assert!(MeasureConfig::parse_yaml(independent.as_bytes()).is_err());
    }

    #[test]
    fn accepts_a_long_chain_beyond_u8_proxy_indices() {
        let config = MeasureConfig::parse_yaml(socks_chain(300).as_bytes()).unwrap();
        assert_eq!(config.proxies.len(), 300);
        assert_eq!(config.default_proxy.index(), 299);
        assert_eq!(
            config.proxies[299].dialer_proxy,
            Some(RouteTargetId::Proxy(ProxyId::new(298).unwrap()))
        );
    }

    #[test]
    fn accepts_bounded_yaml_templates() {
        assert!(
            MeasureConfig::parse_yaml(NODE.replace("name: proxy", "name: &tag proxy").as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn preserves_mihomo_udp_capability() {
        let enabled = MeasureConfig::parse_yaml(NODE.as_bytes()).unwrap();
        assert!(enabled.proxies[0].udp);

        let disabled =
            MeasureConfig::parse_yaml(NODE.replace("    udp: true\n", "").as_bytes()).unwrap();
        assert!(!disabled.proxies[0].udp);
    }
}
