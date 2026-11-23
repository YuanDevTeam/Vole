//! Pure parsing and compilation of the same ordered YAML used for sharing.
#[cfg(any(
    test,
    all(
        feature = "inbound-http",
        feature = "http-diagnostics",
        target_vendor = "apple"
    )
))]
use super::Policy;
use super::{
    MAX_ADDENDUM, MAX_DOCUMENTS, MAX_PARAMETER_OVERRIDES, PluginInput, PluginPermissions,
    PolicyCandidate, SourceLocation, invalid,
};
#[path = "parameters.rs"]
mod parameters;
pub(crate) use parameters::ParameterValue;
use parameters::{ParameterDeclarations, ParameterValues, TextValue};
#[path = "rule_conditions.rs"]
mod rule_conditions;
use crate::http_processing::{
    body::ProtobufRemoveSpec,
    headers,
    origin::Origin,
    rules::{
        ActionKind, BodyOperation as CompiledBodyOperation, HeaderView, JsonFilterSpec,
        MAX_BODY_VALUE, MAX_PATTERN, MAX_RULE_TEXT, MAX_RULES, Matcher, Occurrences,
        PatchOperation, Phase, RawRule, ReplacementMode, RequestSelector, Rule, RuleAction,
        SearchMode, SelectorCompiler, StaticResponse, checked_url, validate_header_name,
    },
    script_config::{BodyMode, CompiledScript},
    scripts::{self, CompiledSource},
};
use base64::Engine as _;
use rule_conditions::{Conditions, HeaderCondition};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    io,
    sync::Arc,
};

const MAX_TARGETS: usize = 64;
const MAX_ORIGINS: usize = 64;

pub(crate) fn nonnull<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("null is not an omitted HTTP setting"))
}

fn optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    nonnull(deserializer).map(Some)
}

pub(crate) struct Document {
    #[cfg(test)]
    raw: Box<[String]>,
    identity: [u8; 32],
    rules: Arc<[Rule]>,
    scripts: Arc<[CompiledScript]>,
    locations: Box<[SourceLocation]>,
    sources: Box<[SourceMetadata]>,
    request_conditions: Box<[Conditions]>,
    response_conditions: Box<[Conditions]>,
    pub(super) groups: Box<[Group]>,
}

pub(super) struct Group {
    source: usize,
    target: usize,
    pub(super) origins: Arc<[Origin]>,
    pub(super) rewrite: bool,
    pub(super) scripts: bool,
    pub(super) intercept_only: bool,
    declared_origins: Arc<[Origin]>,
    declared_intercept_only: bool,
    declared_rules: Box<[RuleSummary]>,
}

impl Group {
    fn declares_script(&self) -> bool {
        self.declared_rules
            .iter()
            .any(|rule| rule.request.js.is_some() || rule.response.js.is_some())
    }
}

struct SourceMetadata {
    name: Option<String>,
    description: Option<String>,
    parameters: ParameterDeclarations,
    upstream_origins: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PluginSummary<'a> {
    source: usize,
    name: Option<&'a str>,
    description: Option<&'a str>,
    parameters: &'a ParameterDeclarations,
    upstream_origins: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TargetSummary<'a> {
    source: usize,
    target: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    origins: Vec<OriginSummary<'a>>,
    rewrite: bool,
    js: bool,
    intercept_only: bool,
    rules: &'a [RuleSummary],
}

#[derive(Serialize)]
struct OriginSummary<'a> {
    scheme: &'static str,
    host: &'a str,
    port: u16,
    wildcard: bool,
    origin: String,
}

#[derive(Serialize)]
struct RuleSummary {
    index: usize,
    path: String,
    id: Option<String>,
    name: Option<String>,
    digest: String,
    #[serde(rename = "redirectTo", skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
    request: PhaseSummary,
    response: PhaseSummary,
}

#[derive(Default, Serialize)]
struct PhaseSummary {
    native: bool,
    body: bool,
    respond: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    js: Option<BodyMode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDocument {
    #[serde(default, deserialize_with = "optional")]
    name: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    description: Option<String>,
    #[serde(default)]
    parameters: ParameterDeclarations,
    targets: Vec<RawGroup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawGroup {
    origins: Vec<String>,
    #[serde(default)]
    intercept_only: bool,
    #[serde(default)]
    rules: Vec<RuleDefinition>,
}

#[derive(Deserialize)]
#[serde(try_from = "serde_yaml_ng::Value")]
struct RuleDefinition {
    entry: RawEntry,
    digest: String,
}

impl TryFrom<serde_yaml_ng::Value> for RuleDefinition {
    type Error = serde_yaml_ng::Error;

    fn try_from(value: serde_yaml_ng::Value) -> Result<Self, Self::Error> {
        let digest = sha256_hex(&serde_yaml_ng::to_string(&value)?);
        let entry = serde_yaml_ng::from_value(value)?;
        Ok(Self { entry, digest })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    #[serde(default, deserialize_with = "optional")]
    id: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    name: Option<String>,
    #[serde(default, rename = "match")]
    selection: Selection,
    #[serde(default, deserialize_with = "optional")]
    request: Option<Request>,
    #[serde(default, deserialize_with = "optional")]
    response: Option<Response>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Selection {
    #[serde(default, deserialize_with = "optional")]
    method: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    path_exact: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    path_prefix: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    url_regex: Option<String>,
    #[serde(default)]
    request_headers: Vec<HeaderCondition>,
    #[serde(default)]
    parameters: ParameterValues,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default, deserialize_with = "optional")]
    respond: Option<Respond>,
    #[serde(default, deserialize_with = "optional")]
    url: Option<UrlTransform>,
    #[serde(default)]
    headers: Vec<HeaderTransform>,
    #[serde(default)]
    body: Vec<BodyTransform>,
    #[serde(default, deserialize_with = "optional")]
    js: Option<Script>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    #[serde(default, deserialize_with = "optional")]
    when: Option<ResponseWhen>,
    #[serde(default)]
    headers: Vec<HeaderTransform>,
    #[serde(default)]
    body: Vec<BodyTransform>,
    #[serde(default, deserialize_with = "optional")]
    js: Option<Script>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWhen {
    #[serde(default, deserialize_with = "optional")]
    status: Option<u16>,
    #[serde(default)]
    headers: Vec<HeaderCondition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Respond {
    status: u16,
    #[serde(default)]
    headers: Vec<RespondHeader>,
    #[serde(default, deserialize_with = "optional")]
    body: Option<RespondBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RespondHeader {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct RespondBody(#[serde(with = "serde_yaml_ng::with::singleton_map")] RespondContent);

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RespondContent {
    Text(TextValue),
    Base64(String),
}

#[derive(Deserialize)]
struct UrlTransform(#[serde(with = "serde_yaml_ng::with::singleton_map")] UrlOperation);

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum UrlOperation {
    Replace(ReplaceUrl),
    Redirect(RedirectUrl),
    Reject(bool),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReplaceUrl {
    Literal(String),
    Detailed(DetailedReplaceUrl),
}

fn whole_url() -> ReplacementMode {
    ReplacementMode::Url
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailedReplaceUrl {
    value: String,
    #[serde(default = "whole_url")]
    mode: ReplacementMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectUrl {
    status: u16,
    to: String,
    #[serde(default = "whole_url")]
    mode: ReplacementMode,
}

#[derive(Deserialize)]
struct HeaderTransform(#[serde(with = "serde_yaml_ng::with::singleton_map")] HeaderOperation);

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum HeaderOperation {
    Set(BTreeMap<String, TextValue>),
    Add(BTreeMap<String, TextValue>),
    Remove(String),
    Replace(ReplaceHeader),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ReplaceHeader {
    name: String,
    search: String,
    replacement: String,
    #[serde(default)]
    search_mode: SearchMode,
    #[serde(default)]
    occurrences: Occurrences,
}

#[derive(Deserialize)]
struct BodyTransform(#[serde(with = "serde_yaml_ng::with::singleton_map")] BodyOperation);

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum BodyOperation {
    Set(TextValue),
    Replace(ReplaceBody),
    JsonPatch(Vec<PatchOperation>),
    JsonFilter(JsonFilterSpec),
    ProtobufRemove(ProtobufRemoveSpec),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ReplaceBody {
    search: String,
    replacement: String,
    #[serde(default)]
    search_mode: SearchMode,
    #[serde(default)]
    occurrences: Occurrences,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Script {
    source: String,
    #[serde(default)]
    body: BodyMode,
}

struct Input<'a> {
    yaml: &'a str,
    overrides: Option<&'a ParameterValues>,
    managed: Option<&'a PluginInput>,
}

struct Grants {
    https: BTreeSet<Origin>,
    js: bool,
    intercept_only: bool,
    upstream: BTreeSet<Origin>,
}

impl Grants {
    fn compile(input: &PluginPermissions) -> io::Result<Self> {
        fn origins(
            raw: &[String],
            allow: impl Fn(&Origin) -> bool,
        ) -> io::Result<BTreeSet<Origin>> {
            if raw.len() > MAX_ORIGINS {
                return Err(invalid());
            }
            let mut origins = BTreeSet::new();
            for value in raw {
                let origin = Origin::parse(value)?;
                if !allow(&origin) || !origins.insert(origin) {
                    return Err(invalid());
                }
            }
            Ok(origins)
        }
        Ok(Self {
            https: origins(&input.https_origins, Origin::is_https)?,
            js: input.js,
            intercept_only: input.intercept_only,
            upstream: origins(&input.upstream_origins, |origin| !origin.is_wildcard())?,
        })
    }
}

struct Source<'a> {
    index: usize,
    declarations: &'a ParameterDeclarations,
    parameters: Arc<ParameterValues>,
    parameter_bytes: usize,
    grants: Option<Grants>,
    ids: BTreeSet<String>,
    https_origins: BTreeSet<Origin>,
    upstream_origins: BTreeSet<Origin>,
}

fn origin_label(origin: &Origin) -> String {
    format!(
        "{}://{}{}:{}",
        origin.scheme(),
        if origin.is_wildcard() { "*." } else { "" },
        origin.host(),
        origin.port()
    )
}

fn invalid_at(source: usize, path: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid HTTP plugin configuration at plugins[{source}]{path}"),
    )
}

pub(super) fn sha256_hex(input: &str) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(input.as_bytes()) {
        write!(hex, "{byte:02x}").expect("write to string");
    }
    hex
}

impl Document {
    #[cfg(any(
        test,
        all(
            feature = "inbound-http",
            feature = "http-diagnostics",
            target_vendor = "apple"
        )
    ))]
    pub(crate) fn parse(input: &str) -> io::Result<Arc<Self>> {
        Self::parse_inputs(&[Input {
            yaml: input,
            overrides: None,
            managed: None,
        }])
    }

    pub(crate) fn parse_documents(inputs: &[String]) -> io::Result<Arc<Self>> {
        Self::parse_overrides(inputs, &BTreeMap::new())
    }

    pub(crate) fn parse_overrides(
        inputs: &[String],
        overrides: &BTreeMap<usize, ParameterValues>,
    ) -> io::Result<Arc<Self>> {
        if inputs.len() > MAX_DOCUMENTS || overrides.keys().any(|index| *index >= inputs.len()) {
            return Err(invalid());
        }
        let inputs: Vec<_> = inputs
            .iter()
            .enumerate()
            .map(|(index, yaml)| Input {
                yaml,
                overrides: overrides.get(&index),
                managed: None,
            })
            .collect();
        Self::parse_inputs(&inputs)
    }

    pub(crate) fn parse_managed(inputs: &[PluginInput]) -> io::Result<Arc<Self>> {
        if inputs.len() > MAX_DOCUMENTS {
            return Err(invalid());
        }
        let mut instances = BTreeSet::new();
        let inputs = inputs
            .iter()
            .map(|input| {
                if input.id.len() > 64
                    || !valid_name(&input.id)
                    || !instances.insert(input.id.as_str())
                    || input.digest.len() != 64
                {
                    return Err(invalid());
                }
                Ok(Input {
                    yaml: &input.yaml,
                    overrides: Some(&input.parameters),
                    managed: Some(input),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Self::parse_inputs(&inputs)
    }

    fn parse_inputs(inputs: &[Input<'_>]) -> io::Result<Arc<Self>> {
        super::require_http_adapter()?;
        let bytes = inputs
            .iter()
            .try_fold(0usize, |total, input| total.checked_add(input.yaml.len()));
        if inputs.is_empty()
            || inputs.len() > MAX_DOCUMENTS
            || bytes.is_none_or(|n| n > MAX_ADDENDUM)
        {
            return Err(invalid());
        }

        let mut hash = Sha256::new();
        hash.update((inputs.len() as u64).to_be_bytes());
        let mut compiler = Compiler::default();
        let mut budget = MAX_ADDENDUM * 4;
        let mut override_budget = MAX_PARAMETER_OVERRIDES;
        let mut sources = Vec::with_capacity(inputs.len());
        for (index, entry) in inputs.iter().enumerate() {
            let input = entry.yaml;
            hash.update((input.len() as u64).to_be_bytes());
            hash.update(input.as_bytes());
            if let Some(managed) = entry.managed
                && sha256_hex(input) != managed.digest
            {
                return Err(invalid_at(index, ".digest"));
            }
            let yaml = input.strip_prefix('\u{feff}').unwrap_or(input);
            super::super::numeric_input::validate(yaml.as_bytes())
                .map_err(|_| invalid_at(index, ".yaml"))?;
            let value = crate::config::yaml::parse_with_budget(yaml.as_bytes(), &mut budget)
                .map_err(|_| invalid_at(index, ".yaml"))?;
            let raw: RawDocument =
                serde_yaml_ng::from_value(value).map_err(|_| invalid_at(index, ".yaml"))?;
            if raw.targets.is_empty()
                || raw.name.as_deref().is_some_and(|name| !valid_name(name))
                || raw
                    .description
                    .as_ref()
                    .is_some_and(|description| description.len() > MAX_PATTERN)
                || compiler.groups.len() + raw.targets.len() > MAX_TARGETS
            {
                return Err(invalid_at(index, ".targets"));
            }

            let parameters = parameters::resolve(&raw.parameters, entry.overrides)
                .map_err(|_| invalid_at(index, ".parameters"))?;
            if let Some(overrides) = entry.overrides {
                let size = serde_json::to_vec(overrides).map_err(|_| invalid())?.len();
                override_budget = override_budget.checked_sub(size).ok_or_else(invalid)?;
            }
            let grants = entry
                .managed
                .map(|value| Grants::compile(&value.permissions))
                .transpose()
                .map_err(|_| invalid_at(index, ".permissions"))?;
            let normalized_grants = grants.as_ref().map(|grants| {
                (
                    grants.https.iter().map(origin_label).collect::<Vec<_>>(),
                    grants.js,
                    grants.intercept_only,
                    grants.upstream.iter().map(origin_label).collect::<Vec<_>>(),
                )
            });
            let identity = serde_json::to_vec(&(
                entry.managed.map(|value| value.id.as_str()),
                &parameters,
                normalized_grants,
            ))
            .map_err(|_| invalid())?;
            hash.update((identity.len() as u64).to_be_bytes());
            hash.update(identity);
            let mut source = Source {
                index,
                declarations: &raw.parameters,
                parameter_bytes: parameters::bridge_bytes(&parameters),
                parameters: Arc::new(parameters),
                grants,
                ids: BTreeSet::new(),
                https_origins: BTreeSet::new(),
                upstream_origins: BTreeSet::new(),
            };
            let first_group = compiler.groups.len();
            for (target, group) in raw.targets.into_iter().enumerate() {
                compiler.group(&mut source, target, group)?;
            }
            if let Some(grants) = &source.grants {
                let groups = &compiler.groups[first_group..];
                if !grants.https.is_subset(&source.https_origins)
                    || !grants.upstream.is_subset(&source.upstream_origins)
                    || (grants.js && !groups.iter().any(Group::declares_script))
                    || (grants.intercept_only
                        && !groups.iter().any(|group| group.declared_intercept_only))
                {
                    return Err(invalid_at(index, ".permissions"));
                }
            }
            let upstream_origins = source.upstream_origins.iter().map(origin_label).collect();
            sources.push(SourceMetadata {
                name: raw.name,
                description: raw.description,
                parameters: raw.parameters,
                upstream_origins,
            });
        }
        Ok(Arc::new(Self {
            #[cfg(test)]
            raw: inputs.iter().map(|input| input.yaml.to_owned()).collect(),
            identity: hash.finalize().into(),
            rules: compiler.rules.into(),
            scripts: compiler.scripts.into(),
            locations: compiler.locations.into(),
            sources: sources.into(),
            request_conditions: compiler.request_conditions.into(),
            response_conditions: compiler.response_conditions.into(),
            groups: compiler.groups.into(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn raw_documents(&self) -> &[String] {
        &self.raw
    }

    pub(crate) fn target_summary(&self) -> Vec<TargetSummary<'_>> {
        self.groups
            .iter()
            .map(|group| TargetSummary {
                source: group.source,
                target: group.target,
                name: self.sources[group.source].name.as_deref(),
                origins: group
                    .declared_origins
                    .iter()
                    .map(|origin| OriginSummary {
                        scheme: origin.scheme(),
                        host: origin.host(),
                        port: origin.port(),
                        wildcard: origin.is_wildcard(),
                        origin: origin_label(origin),
                    })
                    .collect(),
                rewrite: group
                    .declared_rules
                    .iter()
                    .any(|rule| rule.request.native || rule.response.native),
                js: group.declares_script(),
                intercept_only: group.declared_intercept_only,
                rules: &group.declared_rules,
            })
            .collect()
    }

    #[cfg(feature = "invoke")]
    pub(crate) fn rule_id(&self, location: SourceLocation) -> Option<&str> {
        self.groups
            .iter()
            .find(|group| group.source == location.source && group.target == location.target)?
            .declared_rules
            .get(location.index)?
            .id
            .as_deref()
    }

    pub(crate) fn plugin_summary(&self) -> Vec<PluginSummary<'_>> {
        self.sources
            .iter()
            .enumerate()
            .map(|(source, metadata)| PluginSummary {
                source,
                name: metadata.name.as_deref(),
                description: metadata.description.as_deref(),
                parameters: &metadata.parameters,
                upstream_origins: &metadata.upstream_origins,
            })
            .collect()
    }

    pub(crate) fn request_conditions(&self, headers: HeaderView<'_>) -> u64 {
        self.request_conditions
            .iter()
            .fold(0, |mask, c| mask | c.selected(None, headers))
    }

    pub(crate) fn response_conditions(&self, status: u16, headers: HeaderView<'_>) -> u64 {
        if !(200..=599).contains(&status) {
            return 0;
        }
        self.response_conditions
            .iter()
            .fold(0, |mask, c| mask | c.selected(Some(status), headers))
    }

    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }

    pub(super) fn location(&self, index: usize) -> Option<&SourceLocation> {
        self.locations.get(index)
    }

    #[cfg(any(
        test,
        all(
            feature = "inbound-http",
            feature = "http-diagnostics",
            target_vendor = "apple"
        )
    ))]
    pub(crate) fn static_policy(self: &Arc<Self>) -> io::Result<Arc<Policy>> {
        Policy::for_evaluation(self.compile()?, &super::HttpSettings::default())
    }

    pub(crate) fn compile(self: &Arc<Self>) -> io::Result<Arc<PolicyCandidate>> {
        Ok(Arc::new(PolicyCandidate {
            document: self.clone(),
            rules: self.rules.clone(),
            scripts: self.scripts.clone(),
        }))
    }
}

#[derive(Default)]
struct Compiler {
    selectors: SelectorCompiler,
    sources: BTreeMap<String, CompiledSource>,
    rules: Vec<Rule>,
    scripts: Vec<CompiledScript>,
    locations: Vec<SourceLocation>,
    groups: Vec<Group>,
    request_conditions: Vec<Conditions>,
    response_conditions: Vec<Conditions>,
    origin_count: usize,
    native_text: usize,
    script_text: usize,
    entry_count: usize,
    native_count: usize,
    script_count: usize,
    reply_bytes: usize,
}

struct PhaseScope<'a> {
    name: &'a Option<String>,
    selector: Arc<RequestSelector>,
    location: SourceLocation,
    source: &'a Source<'a>,
    active: bool,
}

impl Compiler {
    fn group(&mut self, source: &mut Source<'_>, target: usize, group: RawGroup) -> io::Result<()> {
        self.origin_count += group.origins.len();
        if self.origin_count > MAX_ORIGINS
            || self.entry_count + group.rules.len() > MAX_RULES
            || group.origins.is_empty()
            || group.intercept_only != group.rules.is_empty()
        {
            return Err(invalid_at(source.index, format_args!(".targets[{target}]")));
        }
        let mut seen = BTreeSet::new();
        let declared_origins: Arc<[Origin]> = group
            .origins
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                let error = || {
                    invalid_at(
                        source.index,
                        format_args!(".targets[{target}].origins[{index}]"),
                    )
                };
                let origin = Origin::parse(raw).map_err(|_| error())?;
                if (group.intercept_only && !origin.is_https()) || !seen.insert(origin.clone()) {
                    return Err(error());
                }
                if origin.is_https() {
                    source.https_origins.insert(origin.clone());
                }
                Ok(origin)
            })
            .collect::<io::Result<Vec<_>>>()?
            .into();
        let origins = if let Some(grants) = &source.grants {
            declared_origins
                .iter()
                .filter(|origin| !origin.is_https() || grants.https.contains(*origin))
                .cloned()
                .collect()
        } else {
            declared_origins.clone()
        };

        let (native_before, scripts_before) = (self.rules.len(), self.scripts.len());
        let mut declared_rules = Vec::with_capacity(group.rules.len());
        for (index, definition) in group.rules.into_iter().enumerate() {
            let location = SourceLocation {
                source: source.index,
                target,
                index,
            };
            declared_rules.push(definition.entry.summary(location, definition.digest));
            self.entry(
                source,
                location,
                origins.clone(),
                &declared_origins,
                definition.entry,
            )
            .map_err(|_| {
                invalid_at(
                    location.source,
                    format_args!(".targets[{target}].rules[{index}]"),
                )
            })?;
        }
        self.groups.push(Group {
            source: source.index,
            target,
            origins,
            rewrite: self.rules[native_before..].iter().any(|rule| {
                !matches!(
                    &rule.action,
                    RuleAction::Body { operation: CompiledBodyOperation::JsonPatch(patch), .. }
                        if patch.is_empty()
                )
            }),
            scripts: self.scripts.len() > scripts_before,
            intercept_only: group.intercept_only
                && source
                    .grants
                    .as_ref()
                    .is_none_or(|grants| grants.intercept_only),
            declared_origins,
            declared_intercept_only: group.intercept_only,
            declared_rules: declared_rules.into(),
        });
        Ok(())
    }

    fn entry(
        &mut self,
        source: &mut Source<'_>,
        location: SourceLocation,
        origins: Arc<[Origin]>,
        declared_origins: &[Origin],
        entry: RawEntry,
    ) -> io::Result<()> {
        let bit = 1_u64 << self.entry_count;
        self.entry_count += 1;
        let name = entry.name;
        if name.as_deref().is_some_and(|value| !valid_name(value))
            || entry
                .id
                .is_some_and(|id| !parameters::valid_key(&id) || !source.ids.insert(id))
        {
            return Err(invalid());
        }

        let active = parameters::matches(
            source.declarations,
            &source.parameters,
            &entry.selection.parameters,
        )? && !origins.is_empty();
        let (selector, selector_size, request_condition) =
            entry
                .selection
                .compile(origins.clone(), bit, &mut self.selectors)?;
        let request_mask = if let Some(condition) = request_condition {
            if active {
                self.request_conditions.push(condition);
            }
            bit
        } else {
            0
        };
        let selector = Arc::new(selector.requiring(request_mask, 0));
        let native_start = self.native_count;
        let script_start = self.script_count;
        let mut response_size = 0;

        if let Some(request) = entry.request {
            if let Some(respond) = request.respond {
                if request.url.is_some()
                    || !request.headers.is_empty()
                    || !request.body.is_empty()
                    || request.js.is_some()
                    || entry.response.is_some()
                {
                    return Err(invalid());
                }
                let reply = respond.compile(&source.parameters)?;
                self.reply_bytes = self
                    .reply_bytes
                    .checked_add(reply.body.len())
                    .filter(|bytes| *bytes <= MAX_ADDENDUM)
                    .ok_or_else(invalid)?;
                for (header, value) in &reply.headers {
                    charge_text(&mut self.native_text, header.len() + value.len())?;
                }
                self.push(
                    Rule::respond(name.clone(), selector.clone(), reply),
                    location,
                    active,
                )?;
            } else {
                if let Some(url) = request.url {
                    let raw = url.rule(name.clone())?;
                    let fixed = fixed_upstream(&raw, &selector.matcher);
                    if let Some(fixed) = &fixed
                        && declared_origins.iter().any(|origin| origin != fixed)
                    {
                        source.upstream_origins.insert(fixed.clone());
                    }
                    let mut rule =
                        Rule::compile_scoped(raw, selector.clone(), &mut self.native_text)?;
                    let mut active = active;
                    if let Some(grants) = &source.grants {
                        let approved = fixed
                            .as_ref()
                            .filter(|origin| grants.upstream.contains(origin));
                        if let Some(fixed) = &fixed
                            && approved.is_none()
                            && !origins.iter().any(|origin| {
                                origin.scheme() == fixed.scheme()
                                    && origin.port() == fixed.port()
                                    && origin.matches_host(fixed.host())
                            })
                        {
                            active = false;
                        }
                        rule.restrict_upstream(approved.cloned());
                    }
                    self.push(rule, location, active)?;
                }
                self.phase(
                    (request.headers, request.body, request.js),
                    Phase::Request,
                    PhaseScope {
                        name: &name,
                        selector: selector.clone(),
                        location,
                        source,
                        active,
                    },
                )?;
            }
        }
        if let Some(response) = entry.response {
            let mut selector = selector;
            if let Some(when) = response.when {
                let (condition, size) =
                    Conditions::compile(bit, when.status, when.headers, &mut self.selectors)?
                        .ok_or_else(invalid)?;
                response_size = size;
                if active {
                    self.response_conditions.push(condition);
                }
                selector = Arc::new((*selector).clone().requiring(request_mask, bit));
            }
            self.phase(
                (response.headers, response.body, response.js),
                Phase::Response,
                PhaseScope {
                    name: &name,
                    selector,
                    location,
                    source,
                    active,
                },
            )?;
        }
        if self.native_count == native_start && self.script_count == script_start {
            return Err(invalid());
        }
        if self.native_count > native_start {
            charge_text(&mut self.native_text, selector_size + response_size)?;
        }
        if self.script_count > script_start {
            charge_text(
                &mut self.script_text,
                selector_size + response_size + name.as_ref().map_or(0, String::len),
            )?;
        }
        Ok(())
    }

    fn push(&mut self, rule: Rule, location: SourceLocation, active: bool) -> io::Result<()> {
        if self.native_count == MAX_RULES {
            return Err(invalid());
        }
        self.native_count += 1;
        if active {
            self.rules.push(rule);
            self.locations.push(location);
        }
        Ok(())
    }

    fn phase(
        &mut self,
        (headers, body, script): (Vec<HeaderTransform>, Vec<BodyTransform>, Option<Script>),
        phase: Phase,
        scope: PhaseScope<'_>,
    ) -> io::Result<()> {
        let PhaseScope {
            name,
            selector,
            location,
            source,
            active,
        } = scope;
        for header in headers {
            let rule = Rule::compile_scoped(
                header.rule(phase, name.clone(), &source.parameters)?,
                selector.clone(),
                &mut self.native_text,
            )?;
            self.push(rule, location, active)?;
        }
        for transform in body {
            let rule = transform.compile(
                phase,
                name.clone(),
                selector.clone(),
                &source.parameters,
                &mut self.native_text,
            )?;
            self.push(rule, location, active)?;
        }
        if let Some(script) = script {
            if self.script_count == MAX_RULES {
                return Err(invalid());
            }
            self.script_count += 1;
            let compiled = match self.sources.get(&script.source) {
                Some(compiled) => compiled.clone(),
                None => {
                    let compiled = scripts::validate_source(&script.source)?;
                    self.sources.insert(script.source, compiled.clone());
                    compiled
                }
            };
            if active && source.grants.as_ref().is_none_or(|grants| grants.js) {
                let script_name = name.clone().unwrap_or_else(|| {
                    format!("{}/{}/{}", location.source, location.target, location.index)
                });
                self.scripts.push(CompiledScript {
                    #[cfg(feature = "invoke")]
                    location,
                    name: script_name,
                    phase,
                    body: script.body,
                    compiled,
                    selector,
                    parameters: source.parameters.clone(),
                    parameter_bytes: source.parameter_bytes,
                    managed: source.grants.is_some(),
                });
            }
        }
        Ok(())
    }
}

impl RawEntry {
    fn summary(&self, location: SourceLocation, digest: String) -> RuleSummary {
        RuleSummary {
            index: location.index,
            path: format!("targets[{}].rules[{}]", location.target, location.index),
            id: self.id.clone(),
            name: self.name.clone(),
            digest,
            redirect_to: self
                .request
                .as_ref()
                .and_then(|request| request.url.as_ref())
                .and_then(|url| url.redirect_preview(self.selection.url_regex.is_some())),
            request: self
                .request
                .as_ref()
                .map_or_else(PhaseSummary::default, |request| PhaseSummary {
                    native: request.respond.is_some()
                        || request.url.is_some()
                        || !request.headers.is_empty()
                        || !request.body.is_empty(),
                    body: !request.body.is_empty()
                        || request
                            .respond
                            .as_ref()
                            .is_some_and(|reply| reply.body.is_some()),
                    respond: request.respond.is_some(),
                    js: request.js.as_ref().map(|script| script.body),
                }),
            response: self
                .response
                .as_ref()
                .map_or_else(PhaseSummary::default, |response| PhaseSummary {
                    native: !response.headers.is_empty() || !response.body.is_empty(),
                    body: !response.body.is_empty(),
                    respond: false,
                    js: response.js.as_ref().map(|script| script.body),
                }),
        }
    }
}

impl Respond {
    fn compile(self, parameters: &ParameterValues) -> io::Result<StaticResponse> {
        if !(200..=599).contains(&self.status) || self.status == 206 {
            return Err(invalid());
        }
        let body = match self.body.map(|value| value.0) {
            None => Vec::new(),
            Some(RespondContent::Text(value)) => value.into_text(parameters)?.into_bytes(),
            Some(RespondContent::Base64(value)) => {
                if value.len() > MAX_BODY_VALUE.div_ceil(3) * 4 {
                    return Err(invalid());
                }
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| invalid())?
            }
        };
        if body.len() > MAX_BODY_VALUE
            || (!body.is_empty() && matches!(self.status, 204 | 205 | 304))
        {
            return Err(invalid());
        }
        let mut headers: Vec<(String, String)> = self
            .headers
            .into_iter()
            .map(|entry| {
                validate_header_name(&entry.name)?;
                let name = entry.name.to_ascii_lowercase();
                if matches!(
                    name.as_str(),
                    "content-range" | "proxy-authenticate" | "proxy-authorization"
                ) {
                    return Err(invalid());
                }
                Ok((name, entry.value))
            })
            .collect::<io::Result<_>>()?;
        let has_length = !matches!(self.status, 204 | 304);
        if has_length {
            headers.push(("content-length".into(), body.len().to_string()));
        }
        headers::check(&headers)?;
        if has_length {
            headers.pop();
        }
        Ok(StaticResponse {
            status: self.status,
            headers,
            body: body.into(),
        })
    }
}

/// A match replacement on a regex can keep a prefix of the caller's URL.
/// Only advertise an authority we can determine before runtime expansion.
fn fixed_upstream(rule: &RawRule, selection: &Matcher) -> Option<Origin> {
    if rule.action != ActionKind::Replace
        || (matches!(selection, Matcher::Regex(_))
            && rule.replacement_mode == Some(ReplacementMode::Match))
    {
        return None;
    }
    let (scheme, suffix) = rule.replacement.as_deref()?.split_once("://")?;
    let authority = suffix.split(['/', '?', '#']).next()?;
    if authority.contains('$') {
        return None;
    }
    Origin::parse(&format!("{scheme}://{authority}")).ok()
}

impl Selection {
    fn compile(
        self,
        origins: Arc<[Origin]>,
        bit: u64,
        compiler: &mut SelectorCompiler,
    ) -> io::Result<(RequestSelector, usize, Option<Conditions>)> {
        let method_size = self.method.as_ref().map_or(0, String::len);
        if self.method.as_deref().is_some_and(|method| {
            method.len() > 64 || http::Method::from_bytes(method.as_bytes()).is_err()
        }) {
            return Err(invalid());
        }
        let (matcher, selector_size) = match (self.path_exact, self.path_prefix, self.url_regex) {
            (None, None, None) => (Matcher::Any, 0),
            (Some(path), None, None) => (Matcher::PathExact(path_pattern(&path)?), path.len()),
            (None, Some(path), None) => (Matcher::PathPrefix(path_pattern(&path)?), path.len()),
            (None, None, Some(regex)) if regex.len() <= MAX_PATTERN => {
                (Matcher::Regex(compiler.regex(&regex)?), regex.len())
            }
            _ => return Err(invalid()),
        };
        let condition = Conditions::compile(bit, None, self.request_headers, compiler)?;
        let (condition, condition_size) = match condition {
            Some((condition, size)) => (Some(condition), size),
            None => (None, 0),
        };
        Ok((
            RequestSelector::new(origins, self.method, matcher),
            method_size + selector_size + condition_size,
            condition,
        ))
    }
}

impl UrlTransform {
    fn redirect_preview(&self, regex: bool) -> Option<String> {
        let UrlOperation::Redirect(redirect) = &self.0 else {
            return None;
        };
        if !regex || !redirect.to.contains('$') && redirect.mode == ReplacementMode::Url {
            return checked_url(&redirect.to).ok().map(Into::into);
        }
        if redirect.mode == ReplacementMode::Match {
            return None;
        }
        let (scheme, suffix) = redirect.to.split_once("://")?;
        let authority = suffix.split(['/', '?', '#']).next()?;
        if authority.contains('$') {
            return None;
        }
        checked_url(&format!("{scheme}://{authority}"))
            .ok()
            .map(|url| url.origin().ascii_serialization())
    }

    fn rule(self, name: Option<String>) -> io::Result<RawRule> {
        let (kind, replacement, mode) = match self.0 {
            UrlOperation::Replace(ReplaceUrl::Literal(value)) => {
                (ActionKind::Replace, Some(value), Some(ReplacementMode::Url))
            }
            UrlOperation::Replace(ReplaceUrl::Detailed(replace)) => {
                (ActionKind::Replace, Some(replace.value), Some(replace.mode))
            }
            UrlOperation::Redirect(redirect) => {
                let kind = match redirect.status {
                    302 => ActionKind::Redirect302,
                    307 => ActionKind::Redirect307,
                    _ => return Err(invalid()),
                };
                (kind, Some(redirect.to), Some(redirect.mode))
            }
            UrlOperation::Reject(true) => (ActionKind::Reject, None, None),
            UrlOperation::Reject(false) => return Err(invalid()),
        };
        let mut rule = RawRule::action(kind, name);
        rule.replacement = replacement;
        rule.replacement_mode = mode;
        Ok(rule)
    }
}

impl HeaderTransform {
    fn rule(
        self,
        phase: Phase,
        name: Option<String>,
        parameters: &ParameterValues,
    ) -> io::Result<RawRule> {
        use ActionKind::{
            RequestHeaderAdd, RequestHeaderRemove, RequestHeaderReplace, RequestHeaderSet,
            ResponseHeaderAdd, ResponseHeaderRemove, ResponseHeaderReplace, ResponseHeaderSet,
        };
        use HeaderOperation::*;
        let kind = match (&self.0, phase) {
            (Set(_), Phase::Request) => RequestHeaderSet,
            (Set(_), Phase::Response) => ResponseHeaderSet,
            (Add(_), Phase::Request) => RequestHeaderAdd,
            (Add(_), Phase::Response) => ResponseHeaderAdd,
            (Remove(_), Phase::Request) => RequestHeaderRemove,
            (Remove(_), Phase::Response) => ResponseHeaderRemove,
            (Replace(_), Phase::Request) => RequestHeaderReplace,
            (Replace(_), Phase::Response) => ResponseHeaderReplace,
        };
        let mut rule = RawRule::action(kind, name);
        match self.0 {
            Set(values) | Add(values) => {
                if values.len() != 1 {
                    return Err(invalid());
                }
                let (header, value) = values.into_iter().next().ok_or_else(invalid)?;
                if header.eq_ignore_ascii_case("location")
                    && matches!(value, TextValue::Parameter(_))
                {
                    return Err(invalid());
                }
                rule.header = Some(header);
                rule.value = Some(value.into_text(parameters)?);
            }
            Remove(header) => rule.header = Some(header),
            Replace(value) => {
                rule.header = Some(value.name);
                rule.search = Some(value.search);
                rule.replacement = Some(value.replacement);
                rule.search_mode = Some(value.search_mode);
                rule.occurrences = Some(value.occurrences);
            }
        }
        Ok(rule)
    }
}

impl BodyTransform {
    fn compile(
        self,
        phase: Phase,
        name: Option<String>,
        selector: Arc<RequestSelector>,
        parameters: &ParameterValues,
        total: &mut usize,
    ) -> io::Result<Rule> {
        use ActionKind::{
            RequestBodyJsonPatch, RequestBodyReplace, RequestBodySet, ResponseBodyJsonPatch,
            ResponseBodyReplace, ResponseBodySet,
        };
        use BodyOperation::*;
        let action = |request, response| match phase {
            Phase::Request => request,
            Phase::Response => response,
        };
        let raw = match self.0 {
            Set(value) => {
                let mut rule = RawRule::action(action(RequestBodySet, ResponseBodySet), name);
                rule.value = Some(value.into_text(parameters)?);
                rule
            }
            Replace(value) => {
                let mut rule =
                    RawRule::action(action(RequestBodyReplace, ResponseBodyReplace), name);
                rule.search = Some(value.search);
                rule.replacement = Some(value.replacement);
                rule.search_mode = Some(value.search_mode);
                rule.occurrences = Some(value.occurrences);
                rule
            }
            JsonPatch(value) => {
                let mut rule =
                    RawRule::action(action(RequestBodyJsonPatch, ResponseBodyJsonPatch), name);
                rule.patch = Some(value);
                rule
            }
            JsonFilter(spec) => {
                let (filter, cost) = crate::http_processing::body::JsonFilter::compile(spec)?;
                charge_text(total, cost + name.as_ref().map_or(0, String::len))?;
                return Ok(Rule::body(
                    name,
                    selector,
                    phase,
                    CompiledBodyOperation::JsonFilter(filter),
                ));
            }
            ProtobufRemove(spec) => {
                let (filter, cost) = crate::http_processing::body::ProtobufRemove::compile(spec)?;
                charge_text(total, cost + name.as_ref().map_or(0, String::len))?;
                return Ok(Rule::body(
                    name,
                    selector,
                    phase,
                    CompiledBodyOperation::ProtobufRemove(filter),
                ));
            }
        };
        Rule::compile_scoped(raw, selector, total)
    }
}

fn path_pattern(path: &str) -> io::Result<Box<str>> {
    if path.len() > MAX_PATTERN
        || !path.starts_with('/')
        || path.contains(['?', '#', '\\'])
        || path
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(invalid());
    }
    let url = checked_url(&format!("https://example.invalid{path}"))?;
    Ok(url.path().into())
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && !name.chars().any(char::is_control)
}

fn charge_text(total: &mut usize, bytes: usize) -> io::Result<()> {
    *total = total
        .checked_add(bytes)
        .filter(|n| *n <= MAX_RULE_TEXT)
        .ok_or_else(invalid)?;
    Ok(())
}

#[cfg(all(test, feature = "inbound-http"))]
#[path = "selector_sharing_tests.rs"]
mod selector_sharing_tests;
