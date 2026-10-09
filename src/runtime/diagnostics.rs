//! Current effective settings and rule counters; never serialize raw node config.
use crate::{
    config::{Config, RouteTargetId, RuleAction, RuleKind},
    routing::RuleSet,
};
use serde_json::{Value, json};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

pub(crate) struct Diagnostics {
    pub connections: std::sync::Arc<crate::connections::Registry>,
    pub proxy_names: Vec<String>,
    providers: std::collections::BTreeMap<String, Vec<String>>,
    config: Value,
    rules: Vec<Rule>,
}
struct Rule {
    kind: &'static str,
    payload: String,
    target: String,
    hits: AtomicU64,
    hit_at: Mutex<Option<String>>,
}
impl Diagnostics {
    pub fn new(
        config: &Config,
        rules: &RuleSet,
        connections: std::sync::Arc<crate::connections::Registry>,
    ) -> Self {
        Self {
            connections,
            providers: config
                .provider_members
                .iter()
                .map(|(name, members)| (name.clone(), members.clone()))
                .collect(),
            proxy_names: config.proxies.iter().map(|p| p.tag.clone()).collect(),
            config: effective_config(config),
            rules: (0..rules.len())
                .filter_map(|i| rules.rule(i))
                .map(|spec| {
                    let (kind, payload) = rule_description(&spec.kind);
                    let target = match spec.action {
                        RuleAction::Direct => "DIRECT".into(),
                        RuleAction::Reject => "REJECT".into(),
                        RuleAction::Route(RouteTargetId::Proxy(id)) => {
                            config.proxies[id.index()].tag.clone()
                        }
                        RuleAction::Route(RouteTargetId::Group(id)) => {
                            config.proxy_groups[id.index()].name.clone()
                        }
                    };
                    Rule {
                        kind,
                        payload,
                        target,
                        hits: AtomicU64::new(0),
                        hit_at: Mutex::new(None),
                    }
                })
                .collect(),
        }
    }
    pub fn providers(&self, chain: &[String]) -> Vec<String> {
        self.providers
            .iter()
            .filter(|(_, members)| chain.iter().any(|node| members.contains(node)))
            .map(|(name, _)| name.clone())
            .collect()
    }
    pub fn config(&self) -> Value {
        self.config.clone()
    }
    pub fn hit(&self, index: usize) {
        if let Some(rule) = self.rules.get(index) {
            rule.hits.fetch_add(1, Ordering::Relaxed);
            *rule.hit_at.lock().unwrap() = Some(crate::connections::timestamp());
        }
    }
    pub fn matched(&self, index: usize) -> (&'static str, &str) {
        self.rules
            .get(index)
            .map_or(("", ""), |r| (r.kind, r.payload.as_str()))
    }
    pub fn rules(&self) -> Value {
        json!({"rules": self.rules.iter().enumerate().map(|(index, r)| json!({"index":index,"type":r.kind,"payload":r.payload,"proxy":r.target,"size":-1,"extra":{"disabled":false,"hitCount":r.hits.load(Ordering::Relaxed),"hitAt":*r.hit_at.lock().unwrap()}})).collect::<Vec<_>>()})
    }
}
fn effective_config(config: &Config) -> Value {
    use crate::config::{InboundConfig, LogLevel, Mode};
    let mixed = config.inbounds.iter().find_map(|inbound| match inbound {
        InboundConfig::Mixed(mixed) => Some(mixed),
        _ => None,
    });
    json!({
        "mixed-port":config.mixed_port.unwrap_or(0), "allow-lan":mixed.is_some_and(|m| m.access.allow_lan),
        "bind-address":mixed.and_then(|m| m.access.bind_address).map_or_else(|| "*".into(), |ip| ip.to_string()),
        "mode": match config.mode { Mode::Rule => "rule", Mode::Direct => "direct", Mode::Global => "global" },
        "log-level":match config.log_level { LogLevel::Silent => "silent", LogLevel::Error => "error", LogLevel::Warning => "warning", LogLevel::Info => "info", LogLevel::Debug => "debug" },
        "ipv6": config.ipv6, "sniffing": config.sniffer.enable, "tcp-concurrent": config.connections.tcp_concurrent,
        "keep-alive-idle": config.connections.keep_alive_idle, "keep-alive-interval":config.connections.keep_alive_interval, "disable-keep-alive":config.connections.disable_keep_alive,
        "unified-delay":config.unified_delay, "profile":{"store-selected":config.profile.store_selected,"store-fake-ip":config.profile.store_fake_ip},
        "tun":{"enable":config.tun.enable,"device":config.tun.device,"file-descriptor":config.tun.file_descriptor,"mtu":config.tun.mtu,"udp-timeout":config.tun.udp_timeout.as_secs(),"auto-route":config.tun.auto_route,"auto-detect-interface":config.tun.auto_detect_interface,"dns-hijack":config.tun.dns_hijack.iter().map(ToString::to_string).collect::<Vec<_>>()}
    })
}
fn rule_description(rule: &RuleKind) -> (&'static str, String) {
    match rule {
        RuleKind::Domain(s) => ("Domain", s.clone()),
        RuleKind::DomainSuffix(s) => ("DomainSuffix", s.clone()),
        RuleKind::DomainKeyword(s) => ("DomainKeyword", s.clone()),
        RuleKind::DomainWildcard(s) => ("DomainWildcard", s.clone()),
        RuleKind::DomainRegex(r) => ("DomainRegex", r.as_str().into()),
        RuleKind::GeoSite(s) => ("GeoSite", s.clone()),
        RuleKind::GeoIp(s) => ("GeoIP", s.clone()),
        RuleKind::RuleSet { name, .. } => ("RuleSet", name.clone()),
        RuleKind::IpCidr(cidr) => ("IPCIDR", format!("{}/{}", cidr.network, cidr.prefix_len)),
        RuleKind::SrcIpCidr(cidr) => ("SrcIPCIDR", format!("{}/{}", cidr.network, cidr.prefix_len)),
        RuleKind::SrcPorts(ports) | RuleKind::DstPorts(ports) => (
            if matches!(rule, RuleKind::SrcPorts(_)) {
                "SrcPort"
            } else {
                "DstPort"
            },
            ports
                .iter()
                .map(|p| {
                    if p.start == p.end {
                        p.start.to_string()
                    } else {
                        format!("{}-{}", p.start, p.end)
                    }
                })
                .collect::<Vec<_>>()
                .join("/"),
        ),
        RuleKind::Network(network) => (
            "Network",
            match network {
                crate::config::Network::Tcp => "tcp",
                crate::config::Network::Udp => "udp",
            }
            .into(),
        ),
        RuleKind::Match => ("Match", String::new()),
        RuleKind::And(rules) | RuleKind::Or(rules) => (
            if matches!(rule, RuleKind::And(_)) {
                "AND"
            } else {
                "OR"
            },
            logical(rules.iter().map(|r| &r.kind)),
        ),
        RuleKind::Not(rule) => ("NOT", logical(std::iter::once(&rule.kind))),
    }
}
fn logical<'a>(rules: impl Iterator<Item = &'a RuleKind>) -> String {
    format!(
        "({})",
        rules
            .map(|r| {
                let (kind, payload) = rule_description(r);
                format!("({kind},{payload})")
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effective_configuration_excludes_credentials_and_resource_locations() {
        let config = Config::parse_yaml(br#"
mixed-port: 1080
authentication: [user:secret-sentinel]
external-controller: 127.0.0.1:9090
secret: controller-sentinel
proxy-providers:
  nodes:
    type: inline
    payload:
      - {name: edge, type: socks5, server: 192.0.2.1, port: 1080, password: node-sentinel, username: private-user}
proxy-groups: [{name: pool, type: select, use: [nodes]}]
rules: ["MATCH,pool"]
"#).unwrap();
        let rules = RuleSet::compile(config.rules.clone()).unwrap();
        let diagnostics = Diagnostics::new(&config, &rules, Default::default());
        let view = diagnostics.config().to_string();
        for secret in [
            "secret-sentinel",
            "controller-sentinel",
            "node-sentinel",
            "private-user",
            "192.0.2.1",
        ] {
            assert!(!view.contains(secret));
        }
        assert_eq!(diagnostics.config()["mixed-port"], 1080);
        diagnostics.hit(0);
        assert_eq!(diagnostics.rules()["rules"][0]["extra"]["hitCount"], 1);
    }
}
