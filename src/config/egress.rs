use super::*;
use std::sync::Arc;

/// Immutable policy for the physical socket owned by a node. Empty values
/// inherit the session default; they never clear a platform protection policy.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct EgressOptions {
    pub interface: Option<Arc<str>>,
    pub routing_mark: u32,
}

impl EgressOptions {
    pub(super) fn normalize(interface: String, mark: i64) -> Result<Self> {
        // Windows aliases and GUIDs are not Linux IFNAMSIZ names. Only impose
        // a common memory/string boundary here; the OS validates the name.
        if interface.len() > 1_024 || interface.contains('\0') {
            return invalid("interface-name must be at most 1024 bytes without NUL");
        }
        if mark < i64::from(i32::MIN) || mark > i64::from(u32::MAX) {
            return invalid("routing-mark must fit a 32-bit socket mark");
        }
        Ok(Self {
            interface: (!interface.is_empty()).then(|| interface.into()),
            routing_mark: mark as u32,
        })
    }

    #[must_use]
    pub(crate) fn overlay(&self, node: &Self) -> Self {
        Self {
            interface: node.interface.clone().or_else(|| self.interface.clone()),
            routing_mark: if node.routing_mark == 0 {
                self.routing_mark
            } else {
                node.routing_mark
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_options_inherit_empty_values_and_preserve_platform_names() {
        let global = EgressOptions::normalize("Ethernet 网络 2".into(), 42).unwrap();
        assert_eq!(global.overlay(&EgressOptions::default()), global);
        let node = EgressOptions::normalize("en1".into(), 7).unwrap();
        assert_eq!(global.overlay(&node), node);
        let interface_only = EgressOptions::normalize("en2".into(), 0).unwrap();
        assert_eq!(global.overlay(&interface_only).routing_mark, 42);
        let mark_only = EgressOptions::normalize(String::new(), -1).unwrap();
        assert_eq!(global.overlay(&mark_only).interface, global.interface);
        assert_eq!(mark_only.routing_mark, u32::MAX);
        assert!(EgressOptions::normalize(" bad name ".into(), 0).is_ok());
        assert!(EgressOptions::normalize("bad\0name".into(), 0).is_err());
        assert!(EgressOptions::normalize("x".repeat(1_025), 0).is_err());
        assert!(EgressOptions::normalize(String::new(), i64::from(u32::MAX) + 1).is_err());
    }

    #[test]
    fn native_auto_route_preserves_global_node_and_provider_marks_in_candidates() {
        for mark in [7, u32::MAX] {
            let yaml = format!(
                r#"routing-mark: 42
tun: {{enable: true, auto-route: true, file-descriptor: 0}}
proxies:
  - {{name: inherit, type: direct}}
  - {{name: explicit, type: direct, routing-mark: 9}}
proxy-providers:
  nodes:
    type: inline
    override: {{routing-mark: {mark}}}
    payload:
      - {{name: supplied, type: direct, routing-mark: 3}}
"#,
            );
            let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
            let candidate = config
                .providers
                .as_ref()
                .unwrap()
                .materialize(&super::super::providers::ProviderContents::new())
                .unwrap();
            for config in [&config, &candidate] {
                assert!(config.tun.enable && config.tun.auto_route);
                assert_eq!(config.tun.file_descriptor, 0);
                for (name, expected) in [("inherit", 42), ("explicit", 9), ("supplied", mark)] {
                    let node = config.proxies.iter().find(|node| node.tag == name).unwrap();
                    assert_eq!(config.egress.overlay(&node.egress).routing_mark, expected);
                }
            }
        }
    }

    #[test]
    fn egress_provider_overrides_materialize_before_node_and_global_inheritance() {
        let config = Config::parse_yaml(br#"
interface-name: global-if
routing-mark: 42
proxy-providers:
  nodes:
    type: inline
    override: {interface-name: 'Ethernet 2', routing-mark: 7}
    payload:
      - {name: edge, type: socks5, server: 192.0.2.1, port: 1080, interface-name: old, routing-mark: 3}
proxy-groups:
  - {name: select, type: select, use: [nodes]}
rules: ['MATCH,select']
"#).unwrap();
        assert_eq!(config.egress.interface.as_deref(), Some("global-if"));
        let node = &config.proxies[0].egress;
        assert_eq!(node.interface.as_deref(), Some("Ethernet 2"));
        assert_eq!(node.routing_mark, 7);
        assert_eq!(config.egress.overlay(node), *node);
        for invalid in ["null", "true", "'7'", "4294967296"] {
            let input = format!(
                "proxy-providers:\n  nodes:\n    type: inline\n    override: {{routing-mark: {invalid}}}\n    payload: []\n"
            );
            assert!(Config::parse_yaml(input.as_bytes()).is_err());
        }
    }
}
