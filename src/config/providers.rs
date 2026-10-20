//! Provider declarations and deterministic materialization of one resource generation.
use super::name_regex::{Budget, NameRegex};
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
    #[serde(skip)]
    pub(crate) age_identities: Option<crate::resource::age_provider::Identities>,
    #[serde(skip)]
    pub(super) compiled_override_exprs: Arc<[super::override_expr::Expr]>,
    #[serde(rename = "type")]
    pub kind: ProviderType,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub path_in_bundle: String,
    #[serde(default)]
    pub interval: u64,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub dialer_proxy: String,
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
        if !is_rule && !self.path_in_bundle.is_empty() {
            return invalid("path-in-bundle is only supported by rule providers");
        }
        if is_rule
            && self.kind != ProviderType::Inline
            && !self.path_in_bundle.is_empty()
            && !crate::resource::bundle::valid_member(&self.path_in_bundle)
        {
            return invalid("invalid rule provider bundle member");
        }
        if !is_rule && self.format != RuleFormat::Yaml {
            return invalid("proxy providers use YAML");
        }
        if is_rule
            && (!self.filter.is_empty()
                || !self.exclude_filter.is_empty()
                || !self.exclude_type.is_empty()
                || !self.dialer_proxy.is_empty()
                || !self.overrides.is_empty())
        {
            return invalid("rule providers do not accept proxy filters or overrides");
        }
        if !self.dialer_proxy.is_empty() {
            validate_route_target_name(&self.dialer_proxy, "provider dialer-proxy")?;
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
                        "provider requires a valid absolute HTTP(S) URL".into(),
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
                "interface-name",
                "routing-mark",
                "udp",
                "udp-over-tcp",
                "up",
                "down",
                "dialer-proxy",
                "skip-cert-verify",
                "name-cert-verify",
                "additional-prefix",
                "additional-suffix",
                "proxy-name",
                "override-expr",
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
    pub(crate) resource_paths: Arc<crate::resource::paths::ProviderPaths>,
    pub(crate) http_policy: Option<Arc<crate::http_processing::Policy>>,
    pub(super) base: Value,
    pub(super) identity_directory: Option<std::path::PathBuf>,
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
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderContent {
    Proxies(Vec<Value>),
    Rules(Arc<RuleCollection>),
}
impl std::fmt::Debug for ProviderContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proxies(nodes) => f
                .debug_struct("Proxies")
                .field("count", &nodes.len())
                .finish(),
            Self::Rules(rules) => f
                .debug_struct("Rules")
                .field("count", &rules.len())
                .finish(),
        }
    }
}
pub type ProviderContents = BTreeMap<String, ProviderContent>;

impl ProviderTemplate {
    /// Concrete foreground defaults must survive provider re-materialization.
    /// This does not expose arbitrary overrides or write back the source document.
    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn override_controller(
        &mut self,
        http: Option<std::net::SocketAddr>,
        tls: Option<std::net::SocketAddr>,
        unix: Option<&str>,
        secret: Option<&str>,
    ) {
        use zeroize::Zeroize as _;
        let base = self.base.as_mapping_mut().expect("validated mapping");
        for (key, value) in [
            ("external-controller", http.map(|value| value.to_string())),
            (
                "external-controller-tls",
                tls.map(|value| value.to_string()),
            ),
            ("external-controller-unix", unix.map(str::to_owned)),
            ("secret", secret.map(str::to_owned)),
        ] {
            if let Some(value) = value {
                if let Some(Value::String(mut old)) = base.insert(key.into(), Value::String(value))
                {
                    old.zeroize();
                }
            }
        }
    }
    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn controller_secret(&self) -> Option<&str> {
        self.base
            .get("secret")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    }
    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn controller_cors(&self) -> super::ControllerCors {
        self.base
            .get("external-controller-cors")
            .map_or_else(Default::default, |value| {
                serde_yaml_ng::from_value(value.clone()).expect("validated Controller CORS")
            })
    }
    pub(crate) fn request_user_agent(&self) -> String {
        self.base
            .get("global-ua")
            .and_then(Value::as_str)
            .map_or_else(super::default_global_ua, str::to_owned)
    }
    pub(super) fn extract(mut base: Value) -> Result<Self> {
        let map = base
            .as_mapping_mut()
            .ok_or_else(|| VoleError::InvalidConfig("configuration must be a mapping".into()))?;
        let mut expression_compilation = super::override_expr::CompileBudget::default();
        let mut take = |key: &str, is_rule| -> Result<Vec<(String, ProviderSpec)>> {
            let Some(value) = map.remove(key) else {
                return Ok(Vec::new());
            };
            let Value::Mapping(entries) = value else {
                return invalid("providers must be a mapping");
            };
            entries
                .into_iter()
                .map(|(name, mut spec)| {
                    let name = name
                        .as_str()
                        .filter(|name| !name.is_empty())
                        .ok_or_else(|| {
                            VoleError::InvalidConfig(
                                "provider name must be a nonempty string".into(),
                            )
                        })?
                        .to_owned();
                    let age = spec
                        .as_mapping_mut()
                        .and_then(|map| map.remove("age-secret-key"));
                    if is_rule && age.is_some() {
                        if let Some(Value::String(secret)) = age {
                            let _ = zeroize::Zeroizing::new(secret);
                        }
                        return invalid("rule providers do not accept age-secret-key");
                    }
                    let identities = age
                        .map(crate::resource::age_provider::Identities::from_value)
                        .transpose()?
                        .flatten();
                    let mut spec: ProviderSpec = serde_yaml_ng::from_value(spec)
                        .map_err(|error| VoleError::InvalidConfig(error.to_string()))?;
                    spec.age_identities = identities;
                    spec.validate(is_rule)?;
                    if let Some(expressions) = spec
                        .overrides
                        .get("override-expr")
                        .and_then(Value::as_sequence)
                    {
                        spec.compiled_override_exprs = expressions
                            .iter()
                            .map(|source| {
                                super::override_expr::Expr::parse_with_budget(
                                    source.as_str().expect("validated expression string"),
                                    &mut expression_compilation,
                                )
                            })
                            .collect::<Result<Vec<_>>>()?
                            .into();
                    }
                    Ok((name, spec))
                })
                .collect()
        };
        let proxies = take("proxy-providers", false)?;
        let rules = take("rule-providers", true)?;
        Ok(Self {
            resource_paths: Arc::new(crate::resource::paths::ProviderPaths::default()),
            http_policy: None,
            base,
            identity_directory: None,
            proxies,
            rules,
        })
    }
    pub(crate) fn key(is_rule: bool, name: &str) -> String {
        format!("{}/{name}", if is_rule { "rules" } else { "proxies" })
    }
    #[cfg(test)]
    pub(crate) fn parse_content(
        &self,
        spec: &ProviderSpec,
        bytes: &[u8],
    ) -> Result<ProviderContent> {
        self.parse_content_with_control(
            spec,
            bytes,
            &crate::resource::age_provider::DecodeControl::new(
                None,
                std::time::Instant::now() + crate::resource::http::DEFAULT_DOWNLOAD_TIMEOUT,
            ),
        )
    }
    pub(crate) fn parse_content_with_control(
        &self,
        spec: &ProviderSpec,
        bytes: &[u8],
        control: &crate::resource::age_provider::DecodeControl<'_>,
    ) -> Result<ProviderContent> {
        control.check()?;
        if let Some(behavior) = spec.behavior {
            return RuleCollection::parse(bytes, behavior, spec.format)
                .map(|data| ProviderContent::Rules(Arc::new(data)));
        }
        #[derive(Deserialize)]
        struct Payload {
            proxies: Vec<Value>,
        }
        let decoded = crate::resource::age_provider::decode(
            bytes,
            spec.age_identities.as_ref(),
            control,
            MAX_CONFIG_BYTES,
        )?;
        let proxies = yaml::parse(decoded.as_ref())
            .and_then(|raw| {
                serde_yaml_ng::from_value::<Payload>(raw)
                    .map(|payload| payload.proxies)
                    .map_err(|_| VoleError::InvalidConfig("invalid proxy provider YAML".into()))
            })
            .or_else(|_| crate::resource::provider_input::parse(decoded.as_ref(), control))?;
        control.check()?;
        Ok(ProviderContent::Proxies(proxies))
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
        self.materialize_with_cancel(contents, None)
    }
    pub(crate) fn materialize_with_cancel(
        self: &Arc<Self>,
        contents: &ProviderContents,
        cancellation: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<Config> {
        let mut budget = Budget::new(cancellation);
        let mut expression_budget = super::override_expr::Budget::new(cancellation);
        let has_expressions = self
            .proxies
            .iter()
            .any(|(_, spec)| !spec.compiled_override_exprs.is_empty());
        budget.check()?;
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
            let nodes = filter.select(nodes.clone(), &mut budget)?;
            let mut names = Vec::new();
            for mut node in nodes {
                if !spec.dialer_proxy.is_empty() {
                    node.as_mapping_mut()
                        .ok_or_else(|| {
                            VoleError::InvalidConfig("provider node must be a mapping".into())
                        })?
                        .insert("dialer-proxy".into(), spec.dialer_proxy.clone().into());
                }
                apply_overrides(&mut node, &spec.overrides, &mut budget)?;
                for expression in spec.compiled_override_exprs.iter() {
                    expression.apply(&mut node, &mut expression_budget)?;
                }
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
                if declared.is_empty() && !dynamic {
                    return invalid("proxy group requires proxies or use");
                }
                let mut names = declared;
                if all_proxies {
                    for name in &static_names {
                        if filter.includes(name, &mut budget)? {
                            names.push(name.clone());
                        }
                    }
                }
                let mut dynamic_names = Vec::new();
                for provider in &used {
                    let members = providers.get(provider).ok_or_else(|| {
                        VoleError::InvalidConfig(format!("unknown proxy provider `{provider}`"))
                    })?;
                    for name in members {
                        if filter.includes(name, &mut budget)? {
                            dynamic_names.push(name.clone());
                        }
                    }
                }
                filter.sort_matches(&mut dynamic_names, &mut budget)?;
                names.extend(dynamic_names);
                let mut selected = Vec::with_capacity(names.len());
                for name in names {
                    if !filter.excludes(
                        &name,
                        types.get(&name).map(String::as_str).unwrap_or("Selector"),
                        &mut budget,
                    )? {
                        selected.push(name);
                    }
                }
                let mut names = selected;
                if names.is_empty() {
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
                    && fallback != "REJECT-DROP"
                    && !types.contains_key(&fallback)
                {
                    return invalid("empty-fallback must be a proxy node or built-in target");
                }
            }
        }
        let mut identities =
            super::identity_files::IdentityFiles::new(self.identity_directory.as_deref());
        for node in &mut proxies {
            budget.check()?;
            identities.inline_node(node)?;
        }
        base.insert("proxies".into(), Value::Sequence(proxies));
        let raw: RawVoleConfig = serde_yaml_ng::from_value(value).map_err(|error| {
            if has_expressions {
                VoleError::InvalidConfig("invalid provider override candidate schema".into())
            } else {
                VoleError::InvalidConfig(error.to_string())
            }
        })?;
        let mut config = raw.normalize().map_err(|error| {
            if has_expressions {
                VoleError::InvalidConfig("invalid provider override candidate graph".into())
            } else {
                error
            }
        })?;
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
        for sub in &mut config.sub_rules {
            bind_rules(&mut sub.rules, &sets)?;
        }
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
            RuleKind::RuleSet { name, content, .. } => {
                *content = Some(
                    sets.get(name)
                        .ok_or_else(|| {
                            VoleError::InvalidConfig(format!("unknown rule provider `{name}`"))
                        })?
                        .clone(),
                )
            }
            RuleKind::And(children) | RuleKind::Or(children) => bind_rules(children, sets)?,
            RuleKind::Not(child)
            | RuleKind::Flow {
                predicate: child, ..
            }
            | RuleKind::SubRule {
                predicate: child, ..
            } => bind_rules(std::slice::from_mut(child), sets)?,
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
    include: Vec<NameRegex>,
    exclude: Vec<NameRegex>,
    types: Vec<String>,
}
impl Filter {
    fn new(include: &str, exclude: &str, types: &str) -> Result<Self> {
        let compile = |s: &str| -> Result<Vec<NameRegex>> {
            if s.is_empty() {
                return Ok(Vec::new());
            }
            s.split('`').map(NameRegex::new).collect()
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
    fn match_index(&self, name: &str, budget: &mut Budget<'_>) -> Result<Option<usize>> {
        if self.include.is_empty() {
            return Ok(Some(0));
        }
        for (index, regex) in self.include.iter().enumerate() {
            if regex.is_match(name, budget)? {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
    fn includes(&self, name: &str, budget: &mut Budget<'_>) -> Result<bool> {
        Ok(self.match_index(name, budget)?.is_some())
    }
    fn excludes(&self, name: &str, kind: &str, budget: &mut Budget<'_>) -> Result<bool> {
        for regex in &self.exclude {
            if regex.is_match(name, budget)? {
                return Ok(true);
            }
        }
        Ok(self
            .types
            .iter()
            .any(|ty| ty.eq_ignore_ascii_case(protocol_type(kind))))
    }
    fn sort_matches(&self, names: &mut Vec<String>, budget: &mut Budget<'_>) -> Result<()> {
        if self.include.len() > 1 {
            let mut keyed = names
                .drain(..)
                .map(|name| Ok((self.match_index(&name, budget)?.unwrap_or(usize::MAX), name)))
                .collect::<Result<Vec<_>>>()?;
            keyed.sort_by_key(|(index, _)| *index);
            let mut seen = HashSet::new();
            names.extend(
                keyed
                    .into_iter()
                    .map(|(_, name)| name)
                    .filter(|name| seen.insert(name.clone())),
            );
        }
        Ok(())
    }
    fn select(&self, nodes: Vec<Value>, budget: &mut Budget<'_>) -> Result<Vec<Value>> {
        let mut result = Vec::new();
        for node in nodes {
            budget.check()?;
            let name = node_name(&node)?;
            let kind = node.get("type").and_then(Value::as_str).unwrap_or_default();
            if !self.excludes(&name, kind, budget)?
                && let Some(index) = self.match_index(&name, budget)?
            {
                result.push((index, node));
            }
        }
        if self.include.len() > 1 {
            result.sort_by_key(|(index, _)| *index);
        }
        Ok(result.into_iter().map(|(_, node)| node).collect())
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
            "routing-mark" => value
                .as_i64()
                .is_some_and(|mark| EgressOptions::normalize(String::new(), mark).is_ok()),
            "udp" | "udp-over-tcp" | "skip-cert-verify" => value.is_bool(),
            "override-expr" => value
                .as_sequence()
                .is_some_and(|values| values.iter().all(Value::is_string)),
            "proxy-name" => {
                let replacements: Vec<Replacement> = serde_yaml_ng::from_value(value.clone())
                    .map_err(|_| {
                        VoleError::InvalidConfig("invalid provider name replacements".into())
                    })?;
                for replacement in replacements {
                    NameRegex::new(&replacement.pattern)?;
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
fn apply_overrides(
    node: &mut Value,
    overrides: &BTreeMap<String, Value>,
    budget: &mut Budget<'_>,
) -> Result<()> {
    let original_name = node_name(node)?;
    let map = node
        .as_mapping_mut()
        .ok_or_else(|| VoleError::InvalidConfig("provider node must be a mapping".into()))?;
    let mut name = original_name;
    for (key, value) in overrides {
        if [
            "additional-prefix",
            "additional-suffix",
            "proxy-name",
            "override-expr",
        ]
        .contains(&key.as_str())
        {
            continue;
        }
        let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
        let applicable = match key.as_str() {
            "udp" => kind != "http",
            "up" | "down" => kind == "hysteria2",
            "udp-over-tcp" => kind == "ss",
            "skip-cert-verify" | "name-cert-verify" => match kind {
                "hysteria2" | "tuic" | "trusttunnel" | "masque" => true,
                "trojan" | "anytls" => {
                    !map.contains_key("reality-opts") && !map.contains_key("jls-opts")
                }
                "http" | "socks5" => map.get("tls").and_then(Value::as_bool) == Some(true),
                "vmess" | "vless" => {
                    map.get("tls").and_then(Value::as_bool) == Some(true)
                        && !map.contains_key("reality-opts")
                        && !map.contains_key("jls-opts")
                }
                _ => false,
            },
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
            let regex = NameRegex::new(&replacement.pattern)?;
            name = regex.replace(&name, &replacement.target, budget)?;
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
    fn age_provider_identities_are_validated_before_content_read() {
        let key = include_str!("../../tests/fixtures/provider-age/x25519.key").trim_end();
        let yaml =
            format!("proxy-providers:\n  nodes: {{type: inline, age-secret-key: '{key}'}}\n");
        let template = ProviderTemplate::extract(serde_yaml_ng::from_str(&yaml).unwrap()).unwrap();
        let spec = &template.proxies[0].1;
        assert!(spec.age_identities.is_some());
        for bytes in [
            include_bytes!("../../tests/fixtures/provider-age/x25519.age").as_slice(),
            include_bytes!("../../tests/fixtures/provider-age/provider.yaml").as_slice(),
        ] {
            let ProviderContent::Proxies(nodes) = template.parse_content(spec, bytes).unwrap()
            else {
                panic!("proxy provider content");
            };
            assert_eq!(nodes[0]["name"].as_str(), Some("age-node"));
        }
        for value in ["null", "''"] {
            let yaml =
                format!("proxy-providers:\n  nodes: {{type: inline, age-secret-key: {value}}}\n");
            ProviderTemplate::extract(serde_yaml_ng::from_str(&yaml).unwrap()).unwrap();
        }
        for yaml in [
            "proxy-providers:\n  nodes: {type: inline, age-secret-key: invalid-private-fixture}\n",
            "rule-providers:\n  nodes: {type: inline, behavior: domain, age-secret-key: null}\n",
        ] {
            let error =
                ProviderTemplate::extract(serde_yaml_ng::from_str(yaml).unwrap()).unwrap_err();
            assert!(!error.to_string().contains("invalid-private-fixture"));
        }
    }
    #[test]
    fn override_expr_materializes_after_filters_and_structured_names() {
        let yaml = br#"
mixed-port: 1080
proxy-providers:
  nodes:
    type: inline
    filter: '^keep'
    override:
      udp: true
      proxy-name: [{pattern: '^keep-', target: ''}]
      additional-prefix: 'PRE-'
      additional-suffix: '-END'
      override-expr:
        - '.name = ([.name, (.udp | tostring)] | join("/"))'
        - '.name |= (split("-") | map(downcase) | join("_"))'
        - '.port += ([1, [2, 3]] | flatten | length)'
    payload:
      - {name: keep-east, type: socks5, server: 192.0.2.1, port: 1080}
      - {name: omit-west, type: socks5, server: 192.0.2.1, port: 1080}
proxy-groups: [{name: choice, type: select, use: [nodes]}]
"#;
        let config = Config::parse_yaml(yaml).unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].tag, "pre_east_end/true");
        assert_eq!(config.proxy_groups[0].members[0].name, "pre_east_end/true");
        let template = config.providers.as_ref().unwrap();
        let expressions = &template.proxies[0].1.compiled_override_exprs;
        assert_eq!(expressions.len(), 3);
        let cloned = template.proxies[0].1.clone();
        assert!(Arc::ptr_eq(expressions, &cloned.compiled_override_exprs));
        let cancelled = tokio_util::sync::CancellationToken::new();
        cancelled.cancel();
        assert!(
            template
                .materialize_with_cancel(&ProviderContents::new(), Some(&cancelled))
                .is_err()
        );

        for expression in [
            ".port = .password",
            ".dialer-proxy = .name",
            ".type = .password",
        ] {
            let source = format!(
                "proxy-providers:\n  nodes:\n    type: inline\n    override:\n      override-expr: ['{expression}']\n    payload: [{{name: original, type: socks5, server: 192.0.2.1, port: 1080, username: account, password: private-node-value}}]\n"
            );
            let error = Config::parse_yaml(source.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private-node-value"));
            assert!(!error.contains(expression));
        }
        assert!(Config::parse_yaml(b"proxy-providers: {nodes: {type: inline, payload: [], override: {override-expr: ['.port = (']}}}").is_err());
    }

    #[test]
    fn static_members_filtered_to_empty_use_the_declared_fallback() {
        for (fallback, expected) in [
            ("", "COMPATIBLE"),
            (", empty-fallback: DIRECT", "DIRECT"),
            (", empty-fallback: edge", "edge"),
        ] {
            let yaml = format!(
                "mixed-port: 1080\nproxies: [{{name: edge, type: socks5, server: 192.0.2.1, port: 1080}}]\nproxy-groups: [{{name: filtered, type: select, proxies: [edge], exclude-filter: '^edge'{fallback}}}]\nrules: ['MATCH,filtered']\n"
            );
            let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
            assert_eq!(config.proxy_groups[0].members.len(), 1);
            assert_eq!(config.proxy_groups[0].members[0].name, expected);
            assert!(
                Config::parse_yaml(yaml.replace("proxies: [edge]", "proxies: []").as_bytes())
                    .is_err()
            );
        }
    }

    #[test]
    fn provider_and_group_name_expressions_materialize_real_templates() {
        let config = Config::parse_yaml(
            r#"
mixed-port: 1080
proxy-providers:
  nodes:
    type: inline
    filter: '^(?!.*(流量|到期)).*(HK|SG)'
    exclude-filter: '(?<=HK-)99$'
    override:
      proxy-name:
        - {pattern: '(?<=HK-)(\d+)', target: '${1}x'}
    payload:
      - {name: HK-01, type: socks5, server: 192.0.2.1, port: 1080}
      - {name: HK-99, type: socks5, server: 192.0.2.1, port: 1080}
      - {name: SG-SG, type: socks5, server: 192.0.2.1, port: 1080}
      - {name: SG-SG到期, type: socks5, server: 192.0.2.1, port: 1080}
proxy-groups:
  - {name: choose, type: select, use: [nodes], filter: '^(SG)-\1$`HK', exclude-filter: '(?<=HK-)02'}
"#
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            config
                .proxies
                .iter()
                .map(|p| p.tag.as_str())
                .collect::<Vec<_>>(),
            ["HK-01x", "SG-SG"]
        );
        assert_eq!(
            config.proxy_groups[0]
                .members
                .iter()
                .map(|m| m.name.as_str())
                .collect::<Vec<_>>(),
            ["SG-SG", "HK-01x"]
        );
        let template = config.providers.unwrap();
        let cancelled = tokio_util::sync::CancellationToken::new();
        cancelled.cancel();
        assert!(
            template
                .materialize_with_cancel(&ProviderContents::new(), Some(&cancelled))
                .is_err()
        );
    }

    #[test]
    fn provider_dialer_and_certificate_overrides_materialize_in_reference_order() {
        for (kind, source) in [
            ("inline", ""),
            ("file", "path: nodes.yaml"),
            ("http", "url: https://subscription.invalid/nodes.yaml"),
        ] {
            for (provider, override_dialer, expected) in [
                ("", "", "node-path"),
                ("provider-path", "", "provider-path"),
                ("provider-path", "override-path", "override-path"),
            ] {
                let yaml = format!(
                    r#"
mixed-port: 1080
proxy-providers:
  remote:
    type: {kind}
    {source}
    proxy: node-path
    dialer-proxy: '{provider}'
    override:
      name-cert-verify: verified.invalid
      skip-cert-verify: true
      {override_entry}
    payload:
      - {{name: edge, type: socks5, tls: true, server: cover.invalid, port: 443, dialer-proxy: node-path}}
      - {{name: plain-socks, type: socks5, server: 192.0.2.1, port: 1080}}
      - {{name: plain-http, type: http, server: 192.0.2.2, port: 8080}}
      - {{name: plain-vmess, type: vmess, server: 192.0.2.3, port: 1080, uuid: 00000000-0000-4000-8000-000000000001}}
      - {{name: plain-vless, type: vless, server: 192.0.2.4, port: 1080, uuid: 00000000-0000-4000-8000-000000000001}}
proxy-groups:
  - {{name: node-path, type: select, proxies: [DIRECT]}}
  - {{name: provider-path, type: select, proxies: [DIRECT]}}
  - {{name: override-path, type: select, proxies: [DIRECT]}}
"#,
                    override_entry = if override_dialer.is_empty() {
                        String::new()
                    } else {
                        format!("dialer-proxy: {override_dialer}")
                    },
                );
                let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
                let group = config
                    .proxy_groups
                    .iter()
                    .position(|group| group.name == expected)
                    .unwrap();
                assert_eq!(
                    config.proxies[0].dialer_proxy,
                    Some(RouteTargetId::Group(ProxyGroupId::from_index(group)))
                );
                let ProxyProtocol::Socks5(node) = &config.proxies[0].protocol else {
                    panic!("SOCKS provider node")
                };
                let certificate = &node.tls.as_ref().unwrap().certificate;
                assert_eq!(
                    certificate.verification_name.as_deref(),
                    Some("verified.invalid")
                );
                assert!(certificate.skip_cert_verify);
                assert_eq!(node.address, "cover.invalid");
                assert_eq!(
                    config.providers.as_ref().unwrap().proxies[0].1.proxy,
                    "node-path"
                );
            }
        }
    }

    #[test]
    fn quic_provider_certificate_name_override_uses_existing_certificate_policy() {
        for (kind, credentials) in [
            ("hysteria2", "password: fixture"),
            (
                "tuic",
                "uuid: 00000000-0000-4000-8000-000000000001, password: fixture",
            ),
        ] {
            let config = Config::parse_yaml(format!(
                "mixed-port: 1080\nproxy-providers:\n  nodes:\n    type: inline\n    override: {{name-cert-verify: verified.invalid}}\n    payload:\n      - {{name: edge, type: {kind}, server: cover.invalid, port: 443, {credentials}}}\n"
            ).as_bytes()).unwrap();
            let tls = match &config.proxies[0].protocol {
                ProxyProtocol::Hysteria2(node) => &node.tls,
                ProxyProtocol::Tuic(node) => &node.tls,
                _ => unreachable!(),
            };
            assert_eq!(
                tls.certificate.verification_name.as_deref(),
                Some("verified.invalid")
            );
            assert_eq!(tls.server_name, "cover.invalid");
        }
    }

    #[test]
    fn subrule_provider_candidate_rebinds_without_replacing_old_snapshot() {
        use crate::{
            routing::{EmptyGeoMatcher, RoutingContext, RuleEvaluation, RuleMatch, RuleSet},
            session::Destination,
        };
        let mut config = Config::parse_yaml(
            br#"
mixed-port: 1080
rule-providers:
  domains: {type: inline, behavior: classical, payload: ['DOMAIN,old.example','GEOSITE,cn']}
rules: ['SUB-RULE,(NETWORK,TCP),child', 'MATCH,DIRECT']
sub-rules:
  child: ['RULE-SET,domains,REJECT']
  unused: ['GEOSITE,us,DIRECT']
"#,
        )
        .unwrap();
        let template = config.providers.clone().unwrap();
        let requirements = crate::geodata::GeoRequirements::for_config(&config).unwrap();
        assert_eq!(requirements.total_codes(), 2);
        let RuleKind::RuleSet {
            content: Some(set), ..
        } = &config
            .sub_rules
            .iter()
            .find(|program| program.name == "child")
            .unwrap()
            .rules[0]
            .kind
        else {
            panic!("unbound child provider");
        };
        let old_set = Arc::downgrade(set);
        let old = RuleSet::compile_config(&mut config).unwrap();
        drop(config);
        let mut contents = ProviderContents::new();
        contents.insert(
            ProviderTemplate::key(true, "domains"),
            template
                .parse_content(
                    &template.rules[0].1,
                    b"payload: ['DOMAIN,new.example','GEOSITE,cn']\n",
                )
                .unwrap(),
        );
        let mut candidate = template.materialize(&contents).unwrap();
        let new = RuleSet::compile_config(&mut candidate).unwrap();
        let action = |rules: &RuleSet, host| {
            let context =
                RoutingContext::new(Network::Tcp, &Destination::domain(host, 443).unwrap())
                    .unwrap();
            rules.evaluate_with_geo(&context, &EmptyGeoMatcher)
        };
        let rejected = RuleEvaluation::Matched(RuleMatch {
            action: RuleAction::Reject,
            rule_index: 0,
        });
        assert_eq!(action(&old, "old.example"), rejected);
        assert_eq!(action(&new, "new.example"), rejected);
        assert_eq!(
            action(&new, "old.example"),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                rule_index: 1
            })
        );
        assert!(old_set.upgrade().is_some());
        drop(old);
        assert!(old_set.upgrade().is_none());
    }

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
        assert!(
            set.matches_domain(
                "sub.example.com",
                &crate::routing::EmptyGeoMatcher,
                &Default::default()
            )
            .unwrap()
        );
        let DnsPolicySelector::RuleSets { sets, .. } = &config.dns.nameserver_policies[0].selector
        else {
            panic!("unbound policy")
        };
        assert!(Arc::ptr_eq(set, &sets[0]));
    }
}
