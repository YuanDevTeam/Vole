//! Current effective settings and rule counters; never serialize raw node config.
use crate::{
    config::{Config, RouteTargetId, RuleAction, RuleKind},
    routing::RuleSet,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

pub(crate) struct Diagnostics {
    pub connections: Arc<crate::connections::Registry>,
    pub proxy_names: Vec<Arc<str>>,
    providers: BTreeMap<Arc<str>, Vec<Arc<str>>>,
    names: BTreeSet<Arc<str>>,
    config: Value,
    rules: Vec<Rule>,
    disabled: Arc<super::rule_disable::RuleDisable>,
}
struct Rule {
    kind: &'static str,
    payload: Arc<str>,
    target: Arc<str>,
    hits: AtomicU64,
    // A numeric UTC value; formatting belongs to the Controller query path.
    hit_at: Mutex<Option<time::OffsetDateTime>>,
}
impl Diagnostics {
    pub fn new(
        config: &Config,
        rules: &RuleSet,
        connections: Arc<crate::connections::Registry>,
    ) -> Self {
        // Intern only display text. Connections can retain these small strings without
        // pinning a Config or an entire retired resource generation.
        let mut texts = BTreeSet::new();
        let mut names = BTreeSet::new();
        for name in ["", "DIRECT", "REJECT", "PASS", "PASS-RULE"]
            .into_iter()
            .chain(config.proxies.iter().map(|p| p.tag.as_str()))
            .chain(config.proxy_groups.iter().map(|g| g.name.as_str()))
            .chain(config.provider_members.keys().map(String::as_str))
        {
            names.insert(intern(&mut texts, name));
        }
        let proxy_names = config
            .proxies
            .iter()
            .map(|p| intern(&mut texts, &p.tag))
            .collect();
        let providers = config
            .provider_members
            .iter()
            .map(|(name, members)| {
                let mut members = members
                    .iter()
                    .map(|member| intern(&mut texts, member))
                    .collect::<Vec<_>>();
                members.sort_unstable();
                members.dedup();
                (intern(&mut texts, name), members)
            })
            .collect();
        let disabled = rules.disable_state().clone();
        let rules = (0..rules.len())
            .filter_map(|i| rules.rule(i))
            .map(|spec| {
                let (kind, payload) = rule_description(&spec.kind);
                let target = match &spec.kind {
                    RuleKind::Flow { control, .. } => control.name(),
                    RuleKind::SubRule { target, .. } => rules.subrule_name(*target),
                    _ => match spec.action {
                        RuleAction::Direct => "DIRECT",
                        RuleAction::Reject => "REJECT",
                        RuleAction::RejectDrop => "REJECT-DROP",
                        RuleAction::Route(RouteTargetId::Proxy(id)) => {
                            &config.proxies[id.index()].tag
                        }
                        RuleAction::Route(RouteTargetId::Group(id)) => {
                            &config.proxy_groups[id.index()].name
                        }
                    },
                };
                Rule {
                    kind,
                    payload: intern(&mut texts, &payload),
                    target: intern(&mut texts, target),
                    hits: AtomicU64::new(0),
                    hit_at: Mutex::new(None),
                }
            })
            .collect();
        Self {
            connections,
            proxy_names,
            providers,
            names,
            config: effective_config(config),
            rules,
            disabled,
        }
    }
    /// Reuse known route/provider names, without retaining dynamic destinations.
    pub fn text(&self, text: &str) -> Arc<str> {
        self.names
            .get(text)
            .cloned()
            .unwrap_or_else(|| Arc::from(text))
    }
    pub fn providers(&self, chain: &[Arc<str>]) -> Vec<Arc<str>> {
        self.providers
            .iter()
            .filter(|(_, members)| chain.iter().any(|node| members.binary_search(node).is_ok()))
            .map(|(name, _)| name.clone())
            .collect()
    }
    pub fn config(&self) -> Value {
        self.config.clone()
    }
    pub fn hit(&self, index: usize) {
        if let Some(rule) = self.rules.get(index) {
            let mut old = rule.hits.load(Ordering::Relaxed);
            while let Err(current) = rule.hits.compare_exchange_weak(
                old,
                old.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                old = current;
            }
            *rule.hit_at.lock().unwrap() = Some(time::OffsetDateTime::now_utc());
        }
    }
    pub fn matched(&self, index: usize) -> (&'static str, Arc<str>) {
        self.rules
            .get(index)
            .map_or_else(|| ("", self.text("")), |r| (r.kind, r.payload.clone()))
    }
    pub fn disable_rules(&self, changes: &[(usize, bool)]) -> Result<(), ()> {
        self.disabled.apply(changes)
    }
    pub fn rules(&self) -> Value {
        let disabled = self.disabled.snapshot();
        json!({"rules": self.rules.iter().enumerate().map(|(index, r)| {
            let hit_at = *r.hit_at.lock().unwrap();
            let hit_at = hit_at.map(|time| {
                time.format(&time::format_description::well_known::Rfc3339)
                    .expect("recorded UTC date")
            });
            json!({"index":index,"type":r.kind,"payload":r.payload.as_ref(),"proxy":r.target.as_ref(),"size":-1,"extra":{"disabled":disabled.contains(index),"hitCount":r.hits.load(Ordering::Relaxed),"hitAt":hit_at}})
        }).collect::<Vec<_>>()})
    }
}
fn intern(texts: &mut BTreeSet<Arc<str>>, text: &str) -> Arc<str> {
    if let Some(shared) = texts.get(text) {
        return shared.clone();
    }
    let shared: Arc<str> = text.into();
    texts.insert(shared.clone());
    shared
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
        "ipv6": config.ipv6, "sniffing": config.sniffer.enable, "tcp-concurrent": config.connections.tcp_concurrent, "find-process-mode":config.find_process_mode.name(),
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
        RuleKind::SrcGeoIp(s) => ("SrcGeoIP", s.clone()),
        RuleKind::IpAsn(s) => ("IPASN", s.clone()),
        RuleKind::SrcIpAsn(s) => ("SrcIPASN", s.clone()),
        RuleKind::InTypes(types) => (
            "InType",
            types
                .iter()
                .map(|kind| kind.name())
                .collect::<Vec<_>>()
                .join("/"),
        ),
        RuleKind::InUsers(users) => ("InUser", users.join("/")),
        RuleKind::RematchNames(names) => ("RematchName", names.join("/")),
        RuleKind::Process(rule) => (rule.description(), rule.pattern.clone()),
        RuleKind::Uid(ranges) => (
            "UID",
            ranges
                .iter()
                .map(|range| {
                    if range.start == range.end {
                        range.start.to_string()
                    } else {
                        format!("{}-{}", range.start, range.end)
                    }
                })
                .collect::<Vec<_>>()
                .join("/"),
        ),
        RuleKind::RuleSet { name, .. } => ("RuleSet", name.clone()),
        RuleKind::IpSuffix(value) => ("IPSuffix", value.as_str().into()),
        RuleKind::SrcIpSuffix(value) => ("SrcIPSuffix", value.as_str().into()),
        RuleKind::IpCidr(cidr) => ("IPCIDR", format!("{}/{}", cidr.network, cidr.prefix_len)),
        RuleKind::SrcIpCidr(cidr) => ("SrcIPCIDR", format!("{}/{}", cidr.network, cidr.prefix_len)),
        RuleKind::SrcPorts(ports) | RuleKind::DstPorts(ports) | RuleKind::InPorts(ports) => (
            if matches!(rule, RuleKind::SrcPorts(_)) {
                "SrcPort"
            } else if matches!(rule, RuleKind::InPorts(_)) {
                "InPort"
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
        RuleKind::Flow { predicate, .. } => rule_description(&predicate.kind),
        RuleKind::SubRule { predicate, .. } => {
            ("SubRule", logical(std::iter::once(&predicate.kind)))
        }
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
    fn shared_diagnostic_text_outlives_only_its_small_value() {
        let mut config = Config::parse_yaml(
            br#"
mixed-port: 1080
proxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080}]
proxy-groups: [{name: pool, type: select, proxies: [edge]}]
rules: ["DOMAIN-SUFFIX,example.com,pool", "DOMAIN-SUFFIX,example.com,pool", "MATCH,edge"]
"#,
        )
        .unwrap();
        config
            .provider_members
            .insert("z-provider".into(), vec!["edge".into()]);
        config
            .provider_members
            .insert("a-provider".into(), vec!["edge".into(), "edge".into()]);
        let rules = RuleSet::compile(config.rules.clone()).unwrap();
        let diagnostics = Arc::new(Diagnostics::new(&config, &rules, Default::default()));
        let (_, payload) = diagnostics.matched(0);
        assert!(Arc::ptr_eq(&payload, &diagnostics.matched(1).1));
        assert!(Arc::ptr_eq(
            &diagnostics.proxy_names[0],
            &diagnostics.text("edge")
        ));
        assert!(Arc::ptr_eq(
            &diagnostics.rules[0].target,
            &diagnostics.text("pool")
        ));
        assert!(Arc::ptr_eq(
            &diagnostics.rules[2].target,
            &diagnostics.proxy_names[0]
        ));
        let providers =
            diagnostics.providers(&[diagnostics.text("edge"), diagnostics.text("pool")]);
        assert_eq!(
            providers.iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
            ["a-provider", "z-provider"]
        );
        assert!(Arc::ptr_eq(&providers[0], &diagnostics.text("a-provider")));
        assert!(diagnostics.rules()["rules"][0]["extra"]["hitAt"].is_null());
        diagnostics.hit(0);
        let view = diagnostics.rules();
        let recorded = diagnostics.rules[0].hit_at.lock().unwrap().unwrap();
        assert_eq!(
            view["rules"][0]["extra"]["hitAt"],
            recorded
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        );
        assert_eq!(view["rules"][0]["extra"]["hitCount"], 1);
        diagnostics.rules[0].hits.store(u64::MAX, Ordering::Relaxed);
        diagnostics.hit(0);
        assert_eq!(
            diagnostics.rules()["rules"][0]["extra"]["hitCount"],
            u64::MAX
        );
        let owner = Arc::downgrade(&diagnostics);
        drop(diagnostics);
        assert!(owner.upgrade().is_none());
        assert_eq!(payload.as_ref(), "example.com");
        assert_eq!(providers[0].as_ref(), "a-provider");
    }

    #[test]
    fn rule_switch_view_shares_only_small_state_with_the_program() {
        let config =
            Config::parse_yaml(b"mixed-port: 1080\nrules: ['MATCH,DIRECT', 'MATCH,REJECT']\n")
                .unwrap();
        let rules = RuleSet::compile(config.rules.clone()).unwrap();
        let program = Arc::downgrade(&rules.graph);
        let diagnostics = Diagnostics::new(&config, &rules, Default::default());
        diagnostics.disable_rules(&[(0, true)]).unwrap();
        let view = diagnostics.rules();
        assert_eq!(view["rules"][0]["extra"]["disabled"], true);
        assert_eq!(view["rules"][1]["extra"]["disabled"], false);
        assert!(matches!(
            rules.evaluate(
                &crate::routing::RoutingContext::new(
                    crate::config::Network::Tcp,
                    &crate::session::Destination::Ip("192.0.2.1:443".parse().unwrap())
                )
                .unwrap()
            ),
            crate::routing::RuleEvaluation::Matched(crate::routing::RuleMatch {
                action: RuleAction::Reject,
                rule_index: 1
            })
        ));
        drop(rules);
        assert!(
            program.upgrade().is_none(),
            "diagnostics must not pin the whole program"
        );
        assert_eq!(diagnostics.rules()["rules"][0]["extra"]["disabled"], true);
    }

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
