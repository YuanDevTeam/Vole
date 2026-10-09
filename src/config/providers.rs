//! Provider declarations and deterministic materialization of one resource generation.
use super::*;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Http,
    File,
    Inline,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleBehavior {
    Domain,
    Ipcidr,
    Classical,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleFormat {
    #[default]
    Yaml,
    Text,
    Mrs,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProviderSpec {
    #[serde(rename = "type")]
    pub kind: ProviderType,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub interval: u64,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub header: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub size_limit: u64,
    #[serde(default)]
    pub payload: Vec<Value>,
    #[serde(default)]
    pub health_check: HealthCheckConfig,
    pub behavior: Option<RuleBehavior>,
    #[serde(default)]
    pub format: RuleFormat,
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub exclude_filter: String,
    #[serde(default)]
    pub exclude_type: String,
    #[serde(default, rename = "override")]
    pub overrides: BTreeMap<String, Value>,
}
impl std::fmt::Debug for ProviderSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderSpec")
            .field("kind", &self.kind)
            .field("behavior", &self.behavior)
            .finish_non_exhaustive()
    }
}
impl ProviderSpec {
    fn validate(&self, is_rule: bool) -> Result<()> {
        if is_rule != self.behavior.is_some() {
            return invalid(
                "rule providers require behavior; proxy providers do not accept behavior",
            );
        }
        if self.behavior == Some(RuleBehavior::Classical) && self.format == RuleFormat::Mrs {
            return invalid("classical providers do not support mrs");
        }
        if !is_rule && self.format != RuleFormat::Yaml {
            return invalid("proxy providers use YAML");
        }
        if is_rule
            && (!self.filter.is_empty()
                || !self.exclude_filter.is_empty()
                || !self.exclude_type.is_empty()
                || !self.overrides.is_empty())
        {
            return invalid("rule providers do not accept proxy filters or overrides");
        }
        match self.kind {
            ProviderType::Http => {
                let options = crate::resource::http::HttpOptions {
                    allow_http: true,
                    allow_ip: true,
                    ..Default::default()
                };
                crate::resource::http::parse_url(&self.url, &options).map_err(|_| {
                    VoleError::InvalidConfig(
                        "provider requires an absolute HTTP(S) URL without credentials".into(),
                    )
                })?;
            }
            ProviderType::File if self.path.is_empty() => {
                return invalid("file provider requires path");
            }
            _ => {}
        }
        self.health_check.validate()?;
        if is_rule && self.health_check != HealthCheckConfig::default() {
            return invalid("rule providers do not support health-check");
        }
        Filter::new(&self.filter, &self.exclude_filter, &self.exclude_type)?;
        for key in self.overrides.keys() {
            if ![
                "ip-version",
                "udp",
                "udp-over-tcp",
                "up",
                "down",
                "dialer-proxy",
                "skip-cert-verify",
                "additional-prefix",
                "additional-suffix",
                "proxy-name",
            ]
            .contains(&key.as_str())
            {
                return invalid(format!("unsupported provider override `{key}`"));
            }
        }
        validate_overrides(&self.overrides)?;
        // Validate request metadata even when the initial content comes from cache.
        crate::resource::http::validate_options(&crate::resource::http::HttpOptions {
            headers: self.headers(),
            ..Default::default()
        })
        .map_err(|_| VoleError::InvalidConfig("invalid provider header".into()))?;
        Ok(())
    }
    pub(crate) fn headers(&self) -> Vec<(String, String)> {
        self.header
            .iter()
            .flat_map(|(name, values)| {
                values
                    .iter()
                    .map(move |value| (name.clone(), value.clone()))
            })
            .collect()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderTemplate {
    base: Value,
    pub proxies: Vec<(String, ProviderSpec)>,
    pub rules: Vec<(String, ProviderSpec)>,
}
impl std::fmt::Debug for ProviderTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderTemplate")
            .field("proxies", &self.proxies.len())
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderContent {
    Proxies(Vec<Value>),
    Rules(Arc<RuleCollection>),
}
pub type ProviderContents = BTreeMap<String, ProviderContent>;

impl ProviderTemplate {
    pub(super) fn extract(mut base: Value) -> Result<Self> {
        let map = base
            .as_mapping_mut()
            .ok_or_else(|| VoleError::InvalidConfig("configuration must be a mapping".into()))?;
        let mut take = |key: &str, is_rule| -> Result<Vec<(String, ProviderSpec)>> {
            let Some(value) = map.remove(key) else {
                return Ok(Vec::new());
            };
            let entries = value
                .as_mapping()
                .ok_or_else(|| VoleError::InvalidConfig("providers must be a mapping".into()))?;
            entries
                .iter()
                .map(|(name, spec)| {
                    let name = name
                        .as_str()
                        .filter(|name| !name.is_empty())
                        .ok_or_else(|| {
                            VoleError::InvalidConfig(
                                "provider name must be a nonempty string".into(),
                            )
                        })?
                        .to_owned();
                    let spec: ProviderSpec = serde_yaml_ng::from_value(spec.clone())
                        .map_err(|error| VoleError::InvalidConfig(error.to_string()))?;
                    spec.validate(is_rule)?;
                    Ok((name, spec))
                })
                .collect()
        };
        let proxies = take("proxy-providers", false)?;
        let rules = take("rule-providers", true)?;
        Ok(Self {
            base,
            proxies,
            rules,
        })
    }
    pub(crate) fn key(is_rule: bool, name: &str) -> String {
        format!("{}/{name}", if is_rule { "rules" } else { "proxies" })
    }
    pub(crate) fn parse_content(
        &self,
        spec: &ProviderSpec,
        bytes: &[u8],
    ) -> Result<ProviderContent> {
        if let Some(behavior) = spec.behavior {
            return RuleCollection::parse(bytes, behavior, spec.format)
                .map(|data| ProviderContent::Rules(Arc::new(data)));
        }
        #[derive(Deserialize)]
        struct Payload {
            proxies: Vec<Value>,
        }
        let raw = yaml::parse(bytes)?;
        let parsed: Payload = serde_yaml_ng::from_value(raw)
            .map_err(|error| VoleError::InvalidConfig(error.to_string()))?;
        Ok(ProviderContent::Proxies(parsed.proxies))
    }
    fn bundled(&self, spec: &ProviderSpec) -> Result<ProviderContent> {
        if let Some(behavior) = spec.behavior {
            let items = spec
                .payload
                .iter()
                .map(|v| {
                    v.as_str().map(str::to_owned).ok_or_else(|| {
                        VoleError::InvalidConfig(
                            "rule provider payload must contain strings".into(),
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(ProviderContent::Rules(Arc::new(
                RuleCollection::from_payload(items, behavior)?,
            )))
        } else {
            Ok(ProviderContent::Proxies(spec.payload.clone()))
        }
    }
    pub fn materialize(self: &Arc<Self>, contents: &ProviderContents) -> Result<Config> {
        let mut value = self.base.clone();
        let base = value.as_mapping_mut().expect("validated mapping");
        let mut proxies: Vec<Value> = base
            .get("proxies")
            .map(|v| serde_yaml_ng::from_value(v.clone()))
            .transpose()
            .map_err(|error| VoleError::InvalidConfig(error.to_string()))?
            .unwrap_or_default();
        let static_names = proxies.iter().map(node_name).collect::<Result<Vec<_>>>()?;
        let mut providers = HashMap::new();
        for (name, spec) in &self.proxies {
            let fallback = self.bundled(spec)?;
            let ProviderContent::Proxies(nodes) =
                contents.get(&Self::key(false, name)).unwrap_or(&fallback)
            else {
                return invalid("provider content kind mismatch");
            };
            let filter = Filter::new(&spec.filter, &spec.exclude_filter, &spec.exclude_type)?;
            let nodes = filter.select(nodes.clone(), false)?;
            let mut names = Vec::new();
            for mut node in nodes {
                apply_overrides(&mut node, &spec.overrides)?;
                names.push(node_name(&node)?);
                proxies.push(node);
            }
            providers.insert(name.clone(), names);
        }
        let types = proxies
            .iter()
            .map(|node| {
                Ok((
                    node_name(node)?,
                    node.get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        let group_values = base
            .get_mut("proxy-groups")
            .and_then(Value::as_sequence_mut);
        if let Some(groups) = group_values {
            for group in groups {
                let map = group.as_mapping_mut().ok_or_else(|| {
                    VoleError::InvalidConfig("proxy group must be a mapping".into())
                })?;
                let declared: Vec<String> = take_or(map, "proxies", Vec::new())?;
                let mut used: Vec<String> = take_or(map, "use", Vec::new())?;
                let all = take_or(map, "include-all", false)?;
                let all_proxies = take_or(map, "include-all-proxies", false)? || all;
                let all_providers = take_or(map, "include-all-providers", false)? || all;
                let fallback: String = take_or(map, "empty-fallback", "COMPATIBLE".to_owned())?;
                let filter = Filter::new(
                    &take_or(map, "filter", String::new())?,
                    &take_or(map, "exclude-filter", String::new())?,
                    &take_or(map, "exclude-type", String::new())?,
                )?;
                if all_providers {
                    used = self.proxies.iter().map(|(name, _)| name.clone()).collect();
                }
                if map
                    .get("url")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                    && let Some(url) = used
                        .iter()
                        .filter_map(|name| self.proxies.iter().find(|(n, _)| n == name))
                        .map(|(_, spec)| &spec.health_check.url)
                        .find(|url| !url.is_empty())
                {
                    map.insert("url".into(), url.clone().into());
                }
                let dynamic = !used.is_empty() || all_proxies || all_providers;
                let mut names = declared;
                if all_proxies {
                    names.extend(
                        static_names
                            .iter()
                            .filter(|name| filter.includes(name))
                            .cloned(),
                    );
                }
                let mut dynamic_names = Vec::new();
                for provider in &used {
                    let members = providers.get(provider).ok_or_else(|| {
                        VoleError::InvalidConfig(format!("unknown proxy provider `{provider}`"))
                    })?;
                    dynamic_names
                        .extend(members.iter().filter(|name| filter.includes(name)).cloned());
                }
                filter.sort_matches(&mut dynamic_names);
                names.extend(dynamic_names);
                names.retain(|name| {
                    !filter.excludes(
                        name,
                        types.get(name).map(String::as_str).unwrap_or("Selector"),
                    )
                });
                if names.is_empty() {
                    if !dynamic {
                        return invalid("proxy group requires proxies or use");
                    }
                    names.push(fallback.clone());
                }
                if let Some(default) = map.get("default-selected").and_then(Value::as_str)
                    && dynamic
                    && !names.iter().any(|name| name == default)
                {
                    map.remove("default-selected");
                }
                map.insert(
                    "proxies".into(),
                    serde_yaml_ng::to_value(names).expect("string sequence"),
                );
                // An empty fallback cannot itself be a group, avoiding hidden dependency cycles.
                if fallback != "COMPATIBLE"
                    && fallback != "DIRECT"
                    && fallback != "REJECT"
                    && !types.contains_key(&fallback)
                {
                    return invalid("empty-fallback must be a proxy node or built-in target");
                }
            }
        }
        base.insert("proxies".into(), Value::Sequence(proxies));
        let raw: RawVoleConfig = serde_yaml_ng::from_value(value)
            .map_err(|error| VoleError::InvalidConfig(error.to_string()))?;
        let mut config = raw.normalize()?;
        let mut sets = HashMap::new();
        for (name, spec) in &self.rules {
            let fallback = self.bundled(spec)?;
            let ProviderContent::Rules(rules) =
                contents.get(&Self::key(true, name)).unwrap_or(&fallback)
            else {
                return invalid("provider content kind mismatch");
            };
            sets.insert(name.clone(), rules.clone());
        }
        bind_rules(&mut config.rules, &sets)?;
        bind_rules(&mut config.sniffer.skip_src_address, &sets)?;
        bind_rules(&mut config.sniffer.skip_dst_address, &sets)?;
        for rule in config
            .sniffer
            .skip_src_address
            .iter()
            .chain(&config.sniffer.skip_dst_address)
        {
            if let RuleKind::RuleSet {
                content: Some(set), ..
            } = &rule.kind
                && set.behavior() == RuleBehavior::Domain
            {
                return invalid(
                    "sniffer address filter requires an ipcidr or classical rule provider",
                );
            }
        }
        for selector in config
            .sniffer
            .force_domain
            .iter_mut()
            .chain(&mut config.sniffer.skip_domain)
        {
            bind_domain_selector(selector, &sets)?;
        }
        bind_rules(&mut config.dns.fake_ip.rules, &sets)?;
        for rule in &config.dns.fake_ip.rules {
            if let RuleKind::RuleSet {
                content: Some(set), ..
            } = &rule.kind
                && set.behavior() == RuleBehavior::Ipcidr
            {
                return invalid("fake-IP filter requires a domain or classical rule provider");
            }
        }
        for selector in &mut config.dns.fake_ip.filter {
            bind_domain_selector(selector, &sets)?;
        }
        for policy in config
            .dns
            .nameserver_policies
            .iter_mut()
            .chain(&mut config.dns.proxy_policies)
        {
            bind_domain_selector(&mut policy.selector, &sets)?;
        }
        config.provider_members = providers;
        config.providers = Some(self.clone());
        Ok(config)
    }
}
fn bind_domain_selector(
    selector: &mut DnsPolicySelector,
    sets: &HashMap<String, Arc<RuleCollection>>,
) -> Result<()> {
    if let DnsPolicySelector::RuleSets { names, sets: bound } = selector {
        for name in names.iter() {
            let set = sets.get(name).ok_or_else(|| {
                VoleError::InvalidConfig(format!("unknown rule provider `{name}`"))
            })?;
            if set.behavior() == RuleBehavior::Ipcidr {
                return invalid("domain selector requires a domain or classical rule provider");
            }
            bound.push(set.clone());
        }
    }
    Ok(())
}
fn bind_rules(rules: &mut [RuleSpec], sets: &HashMap<String, Arc<RuleCollection>>) -> Result<()> {
    for rule in rules {
        match &mut rule.kind {
            RuleKind::RuleSet { name, content } => {
                *content = Some(
                    sets.get(name)
                        .ok_or_else(|| {
                            VoleError::InvalidConfig(format!("unknown rule provider `{name}`"))
                        })?
                        .clone(),
                )
            }
            RuleKind::And(children) | RuleKind::Or(children) => bind_rules(children, sets)?,
            RuleKind::Not(child) => bind_rules(std::slice::from_mut(child), sets)?,
            _ => {}
        }
    }
    Ok(())
}
fn take_or<T: serde::de::DeserializeOwned>(map: &mut Mapping, key: &str, default: T) -> Result<T> {
    map.remove(key)
        .map(|v| {
            serde_yaml_ng::from_value(v)
                .map_err(|error| VoleError::InvalidConfig(error.to_string()))
        })
        .unwrap_or(Ok(default))
}
fn node_name(value: &Value) -> Result<String> {
    value
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| VoleError::InvalidConfig("provider node requires name".into()))
}

struct Filter {
    include: Vec<regex::Regex>,
    exclude: Vec<regex::Regex>,
    types: Vec<String>,
}
impl Filter {
    fn new(include: &str, exclude: &str, types: &str) -> Result<Self> {
        let compile = |s: &str| -> Result<Vec<regex::Regex>> {
            if s.is_empty() {
                return Ok(Vec::new());
            }
            s.split('`').map(|pattern| regex::Regex::new(pattern).map_err(|_| VoleError::InvalidConfig("unsupported provider/group regular expression (lookaround and backreferences are not supported)".into()))).collect()
        };
        Ok(Self {
            include: compile(include)?,
            exclude: compile(exclude)?,
            types: types
                .split('|')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        })
    }
    fn includes(&self, name: &str) -> bool {
        self.include.is_empty() || self.include.iter().any(|r| r.is_match(name))
    }
    fn excludes(&self, name: &str, kind: &str) -> bool {
        self.exclude.iter().any(|r| r.is_match(name))
            || self
                .types
                .iter()
                .any(|ty| ty.eq_ignore_ascii_case(protocol_type(kind)))
    }
    fn sort_matches(&self, names: &mut Vec<String>) {
        if self.include.len() > 1 {
            names.sort_by_key(|name| {
                self.include
                    .iter()
                    .position(|r| r.is_match(name))
                    .unwrap_or(usize::MAX)
            });
            let mut seen = HashSet::new();
            names.retain(|name| seen.insert(name.clone()));
        }
    }
    fn select(&self, nodes: Vec<Value>, _group: bool) -> Result<Vec<Value>> {
        let mut result = Vec::new();
        for node in nodes {
            let name = node_name(&node)?;
            let kind = node.get("type").and_then(Value::as_str).unwrap_or_default();
            if self.includes(&name) && !self.excludes(&name, kind) {
                result.push(node);
            }
        }
        if self.include.len() > 1 {
            result.sort_by_key(|node| {
                self.include
                    .iter()
                    .position(|r| {
                        r.is_match(node.get("name").and_then(Value::as_str).unwrap_or_default())
                    })
                    .unwrap_or(usize::MAX)
            });
        }
        Ok(result)
    }
}
fn protocol_type(kind: &str) -> &str {
    match kind {
        "ss" => "Shadowsocks",
        "socks5" => "Socks5",
        "http" => "Http",
        other => other,
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    pattern: String,
    target: String,
}
fn validate_overrides(overrides: &BTreeMap<String, Value>) -> Result<()> {
    for (key, value) in overrides {
        let valid = match key.as_str() {
            "udp" | "udp-over-tcp" | "skip-cert-verify" => value.is_bool(),
            "proxy-name" => {
                let replacements: Vec<Replacement> = serde_yaml_ng::from_value(value.clone())
                    .map_err(|_| {
                        VoleError::InvalidConfig("invalid provider name replacements".into())
                    })?;
                for replacement in replacements {
                    regex::Regex::new(&replacement.pattern).map_err(|_| {
                        VoleError::InvalidConfig(
                            "unsupported provider name replacement expression".into(),
                        )
                    })?;
                }
                true
            }
            _ => value.is_string(),
        };
        if !valid {
            return invalid(format!("invalid provider override `{key}`"));
        }
    }
    Ok(())
}
fn apply_overrides(node: &mut Value, overrides: &BTreeMap<String, Value>) -> Result<()> {
    let original_name = node_name(node)?;
    let map = node
        .as_mapping_mut()
        .ok_or_else(|| VoleError::InvalidConfig("provider node must be a mapping".into()))?;
    let mut name = original_name;
    for (key, value) in overrides {
        if ["additional-prefix", "additional-suffix", "proxy-name"].contains(&key.as_str()) {
            continue;
        }
        let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
        let applicable = match key.as_str() {
            "udp" => kind != "http",
            "up" | "down" => kind == "hysteria2",
            "udp-over-tcp" => kind == "ss",
            "skip-cert-verify" => matches!(
                kind,
                "vless" | "vmess" | "trojan" | "anytls" | "hysteria2" | "tuic" | "http"
            ),
            _ => true,
        };
        if applicable {
            map.insert(Value::String(key.clone()), value.clone());
        }
    }
    if let Some(replacements) = overrides.get("proxy-name") {
        let replacements: Vec<Replacement> = serde_yaml_ng::from_value(replacements.clone())
            .map_err(|error| VoleError::InvalidConfig(error.to_string()))?;
        for replacement in replacements {
            let regex = regex::Regex::new(&replacement.pattern).map_err(|_| {
                VoleError::InvalidConfig("unsupported provider name replacement expression".into())
            })?;
            name = regex
                .replace_all(&name, replacement.target.as_str())
                .into_owned();
        }
    }
    let text = |key| -> Result<&str> {
        overrides
            .get(key)
            .map(|v| {
                v.as_str().ok_or_else(|| {
                    VoleError::InvalidConfig("provider name affix must be a string".into())
                })
            })
            .unwrap_or(Ok(""))
    };
    map.insert(
        "name".into(),
        format!(
            "{}{}{}",
            text("additional-prefix")?,
            name,
            text("additional-suffix")?
        )
        .into(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inline_provider_groups_and_rule_policies_share_materialized_content() {
        let config = Config::parse_yaml(
            br#"
mixed-port: 1080
proxy-providers:
  nodes:
    type: inline
    filter: '^keep'
    override: {udp: true, skip-cert-verify: true, additional-prefix: 'P-'}
    payload:
      - {name: keep-one, type: socks5, server: 192.0.2.1, port: 1080}
      - {name: discard, type: socks5, server: 192.0.2.2, port: 1080}
proxy-groups:
  - {name: choose, type: select, use: [nodes], hidden: true, icon: icon, disable-udp: true}
  - {name: empty, type: select, use: [nodes], filter: absent}
rule-providers:
  domains: {type: inline, behavior: domain, payload: ['+.example.com']}
  custom: {type: inline, behavior: classical, payload: ['DOMAIN,internal.example']}
dns:
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy: {'rule-set:domains,custom': [8.8.8.8]}
rules: ['RULE-SET,domains,choose', 'RULE-SET,custom,DIRECT,no-resolve']
"#,
        )
        .unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].tag, "P-keep-one");
        assert!(config.proxies[0].udp);
        assert!(config.proxy_groups[0].disable_udp);
        assert!(config.proxy_groups[0].hidden);
        assert_eq!(config.proxy_groups[1].members[0].name, "COMPATIBLE");
        let RuleKind::RuleSet {
            content: Some(set), ..
        } = &config.rules[0].kind
        else {
            panic!("unbound set")
        };
        assert!(set.matches_domain("sub.example.com", &crate::routing::EmptyGeoMatcher));
        let DnsPolicySelector::RuleSets { sets, .. } = &config.dns.nameserver_policies[0].selector
        else {
            panic!("unbound policy")
        };
        assert!(Arc::ptr_eq(set, &sets[0]));
    }
}
