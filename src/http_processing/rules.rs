//! Bounded native actions and request selectors shared with scripts.
use super::{
    body::{JsonFilter, ProtobufRemove},
    origin::Origin,
};
use regex::{Regex, RegexBuilder};
use std::{collections::BTreeMap, io, sync::Arc};
use url::Url;

#[path = "rule_schema.rs"]
mod schema;
#[cfg(test)]
pub(crate) use schema::MatchKind;
pub(crate) use schema::{
    ActionKind, JsonFilterSpec, Occurrences, PatchOperation, Phase, RawRule, ReplacementMode,
    SearchMode,
};

#[path = "rule_search.rs"]
mod search;
#[path = "rule_template.rs"]
mod template;
pub(crate) use search::Search;

pub(crate) const MAX_RULES: usize = 64;
pub(crate) const MAX_PATTERN: usize = 2048;
pub(crate) const MAX_RULE_TEXT: usize = 64 * 1024;
pub(crate) const MAX_URL: usize = 8192;
pub(crate) const MAX_BODY_VALUE: usize = 256 * 1024;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTP rewrite rule")
}

pub(crate) struct Rule {
    pub(crate) name: Option<Box<str>>,
    pub(crate) enabled: bool,
    pub(crate) selector: Arc<RequestSelector>,
    pub(crate) action: RuleAction,
    upstream: UpstreamAccess,
}

#[derive(Clone)]
pub(crate) enum Matcher {
    Any,
    PathExact(Box<str>),
    PathPrefix(Box<str>),
    Regex(Arc<Regex>),
    #[cfg(test)]
    Exact(Box<str>),
    #[cfg(test)]
    Prefix(Box<str>),
}

#[derive(Clone, Copy)]
pub(crate) struct RequestMatch<'a> {
    pub(crate) url: &'a Url,
    pub(crate) method: &'a str,
    request: u64,
    response: u64,
}

impl RequestMatch<'_> {
    pub(crate) fn with_conditions(mut self, request: u64, response: u64) -> Self {
        self.request = request;
        self.response = response;
        self
    }
}

impl<'a> From<(&'a Url, &'a str)> for RequestMatch<'a> {
    fn from((url, method): (&'a Url, &'a str)) -> Self {
        Self {
            url,
            method,
            request: 0,
            response: 0,
        }
    }
}

#[cfg(test)]
impl<'a> From<&'a Url> for RequestMatch<'a> {
    fn from(url: &'a Url) -> Self {
        (url, "GET").into()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum HeaderView<'a> {
    Fields(&'a [(String, String)]),
    Map(&'a http::HeaderMap),
}

#[derive(Clone)]
pub(crate) struct RequestSelector {
    pub(crate) matcher: Matcher,
    scope: Arc<[Origin]>,
    method: Option<Box<str>>,
    request: u64,
    response: u64,
}

impl RequestSelector {
    pub(super) fn new(scope: Arc<[Origin]>, method: Option<String>, matcher: Matcher) -> Self {
        Self {
            matcher,
            scope,
            method: method.map(String::into_boxed_str),
            request: 0,
            response: 0,
        }
    }

    pub(super) fn scope(&self) -> &[Origin] {
        &self.scope
    }

    pub(super) fn requiring(mut self, request: u64, response: u64) -> Self {
        self.request = request;
        self.response = response;
        self
    }

    pub(super) fn matches(&self, original: RequestMatch<'_>) -> bool {
        original.request & self.request == self.request
            && original.response & self.response == self.response
            && (self.scope.is_empty()
                || self
                    .scope
                    .iter()
                    .any(|origin| origin.matches_url(original.url)))
            && self
                .method
                .as_deref()
                .is_none_or(|method| method == original.method)
            && match &self.matcher {
                Matcher::Any => true,
                Matcher::PathExact(value) => original.url.path() == value.as_ref(),
                Matcher::PathPrefix(value) => original.url.path().starts_with(value.as_ref()),
                Matcher::Regex(regex) => regex.is_match(original.url.as_str()),
                #[cfg(test)]
                Matcher::Exact(value) => original.url.as_str() == value.as_ref(),
                #[cfg(test)]
                Matcher::Prefix(value) => original.url.as_str().starts_with(value.as_ref()),
            }
    }
}

/// One native-selector builder profile, scoped to one candidate compilation.
#[derive(Default)]
pub(crate) struct SelectorCompiler {
    regexes: BTreeMap<Box<str>, Arc<Regex>>,
}

impl SelectorCompiler {
    pub(super) fn regex(&mut self, pattern: &str) -> io::Result<Arc<Regex>> {
        if let Some(regex) = self.regexes.get(pattern) {
            return Ok(Arc::clone(regex));
        }
        if self.regexes.len() == MAX_RULES {
            return Err(invalid());
        }
        // Exact pattern bytes plus this fixed builder profile form the key.
        let regex = Arc::new(bounded_regex(pattern)?);
        self.regexes.insert(pattern.into(), Arc::clone(&regex));
        Ok(regex)
    }
}

pub(crate) enum RuleAction {
    Respond(Arc<StaticResponse>),
    Url {
        kind: ActionKind,
        replacement: Option<UrlReplacement>,
    },
    Header {
        phase: Phase,
        header: Box<str>,
        operation: HeaderOperation,
    },
    Body {
        phase: Phase,
        operation: BodyOperation,
    },
}

pub(crate) struct StaticResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: bytes::Bytes,
}

enum UpstreamAccess {
    Local,
    Managed(Option<Origin>),
}

pub(crate) enum HeaderOperation {
    Set(Box<str>),
    Add(Box<str>),
    Remove,
    Replace(Search),
}

pub(crate) enum BodyOperation {
    Set(Box<str>),
    Replace(Search),
    JsonPatch(Box<[PatchOperation]>),
    JsonFilter(JsonFilter),
    ProtobufRemove(ProtobufRemove),
}

pub(crate) struct UrlReplacement {
    mode: ReplacementMode,
    value: ReplacementValue,
}

enum ReplacementValue {
    Literal(Box<str>),
    Template(template::Template),
}

pub(crate) enum UrlAction {
    Forward(Url),
    Redirect { status: u16, url: Url },
    Reject,
    Respond(Arc<StaticResponse>),
}

// Action parameters are mutually exclusive even when explicitly set to an
// empty value. Missing and null cannot masquerade as one another.
const REPLACEMENT: u16 = 1;
const REPLACEMENT_MODE: u16 = 2;
const HEADER: u16 = 4;
const VALUE: u16 = 8;
const SEARCH: u16 = 16;
const SEARCH_MODE: u16 = 32;
const OCCURRENCES: u16 = 64;
const PATCH: u16 = 128;

impl RawRule {
    fn parameters(&self) -> u16 {
        let mut mask = 0;
        for (present, bit) in [
            (self.replacement.is_some(), REPLACEMENT),
            (self.replacement_mode.is_some(), REPLACEMENT_MODE),
            (self.header.is_some(), HEADER),
            (self.value.is_some(), VALUE),
            (self.search.is_some(), SEARCH),
            (self.search_mode.is_some(), SEARCH_MODE),
            (self.occurrences.is_some(), OCCURRENCES),
            (self.patch.is_some(), PATCH),
        ] {
            if present {
                mask |= bit;
            }
        }
        mask
    }

    fn text_size(&self) -> io::Result<usize> {
        let mut size = self.url.len();
        for text in [&self.name, &self.header, &self.search] {
            size = size
                .checked_add(text.as_ref().map_or(0, String::len))
                .ok_or_else(invalid)?;
        }
        // Body literals belong to the separately bounded body/configuration
        // workspace, not the 8 KiB URL-result limit.
        if !matches!(
            self.action,
            ActionKind::RequestBodySet
                | ActionKind::RequestBodyReplace
                | ActionKind::ResponseBodySet
                | ActionKind::ResponseBodyReplace
        ) {
            for text in [&self.replacement, &self.value] {
                size = size
                    .checked_add(text.as_ref().map_or(0, String::len))
                    .ok_or_else(invalid)?;
            }
        }
        Ok(size)
    }

    fn compile_search(&mut self) -> io::Result<Search> {
        Search::compile(
            self.search.take().ok_or_else(invalid)?,
            self.replacement.take().ok_or_else(invalid)?,
            self.search_mode.unwrap_or_default(),
            self.occurrences.unwrap_or_default(),
        )
    }
}

impl Rule {
    #[cfg(test)]
    pub(crate) fn compile(raw: RawRule, total_text: &mut usize) -> io::Result<Self> {
        Self::compile_with_selectors(raw, total_text, &mut SelectorCompiler::default())
    }

    #[cfg(test)]
    pub(crate) fn compile_with_selectors(
        raw: RawRule,
        total_text: &mut usize,
        selectors: &mut SelectorCompiler,
    ) -> io::Result<Self> {
        let matcher = match raw.match_kind {
            MatchKind::Regex => Matcher::Regex(selectors.regex(&raw.url)?),
            MatchKind::Exact => Matcher::Exact(checked_url(&raw.url)?.as_str().into()),
            MatchKind::Prefix => Matcher::Prefix(checked_url(&raw.url)?.as_str().into()),
        };
        let selector = Arc::new(RequestSelector::new(Arc::from([]), None, matcher));
        Self::compile_scoped(raw, selector, total_text)
    }

    pub(super) fn compile_scoped(
        mut raw: RawRule,
        selector: Arc<RequestSelector>,
        total_text: &mut usize,
    ) -> io::Result<Self> {
        let next_text = total_text
            .checked_add(raw.text_size()?)
            .ok_or_else(invalid)?;
        if raw.url.len() > MAX_PATTERN
            || next_text > MAX_RULE_TEXT
            || raw
                .search
                .as_ref()
                .is_some_and(|value| value.len() > MAX_PATTERN)
            || raw
                .value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_BODY_VALUE)
            || raw
                .replacement
                .as_ref()
                .is_some_and(|value| value.len() > MAX_BODY_VALUE)
        {
            return Err(invalid());
        }
        let parameters = raw.parameters();
        let search_parameters = REPLACEMENT | SEARCH | SEARCH_MODE | OCCURRENCES;
        let allowed = match raw.action {
            ActionKind::Replace | ActionKind::Redirect302 | ActionKind::Redirect307 => {
                REPLACEMENT | REPLACEMENT_MODE
            }
            ActionKind::Reject => 0,
            ActionKind::RequestHeaderSet
            | ActionKind::RequestHeaderAdd
            | ActionKind::ResponseHeaderSet
            | ActionKind::ResponseHeaderAdd => HEADER | VALUE,
            ActionKind::RequestHeaderRemove | ActionKind::ResponseHeaderRemove => HEADER,
            ActionKind::RequestHeaderReplace | ActionKind::ResponseHeaderReplace => {
                HEADER | search_parameters
            }
            ActionKind::RequestBodySet | ActionKind::ResponseBodySet => VALUE,
            ActionKind::RequestBodyReplace | ActionKind::ResponseBodyReplace => search_parameters,
            ActionKind::RequestBodyJsonPatch | ActionKind::ResponseBodyJsonPatch => PATCH,
        };
        if parameters & !allowed != 0 {
            return Err(invalid());
        }
        let phase = match raw.action {
            ActionKind::ResponseHeaderSet
            | ActionKind::ResponseHeaderAdd
            | ActionKind::ResponseHeaderRemove
            | ActionKind::ResponseHeaderReplace
            | ActionKind::ResponseBodySet
            | ActionKind::ResponseBodyReplace
            | ActionKind::ResponseBodyJsonPatch => Phase::Response,
            _ => Phase::Request,
        };
        let action = if raw.action.is_url() {
            let replacement = if raw.action == ActionKind::Reject {
                None
            } else {
                let value = raw.replacement.take().ok_or_else(invalid)?;
                if value.len() > MAX_URL {
                    return Err(invalid());
                }
                let mode = raw.replacement_mode.unwrap_or_default();
                let value = match &selector.matcher {
                    Matcher::Regex(regex) => {
                        if value.chars().any(|character| {
                            character.is_control()
                                || character.is_whitespace()
                                || matches!(character, '\\' | '#')
                        }) {
                            return Err(invalid());
                        }
                        let template = template::Template::compile(&value, regex)?;
                        if mode == ReplacementMode::Url
                            && let Some(value) = template.constant(MAX_URL)?
                        {
                            checked_url(&value)?;
                        }
                        ReplacementValue::Template(template)
                    }
                    _ => ReplacementValue::Literal(checked_url(&value)?.as_str().into()),
                };
                Some(UrlReplacement { mode, value })
            };
            RuleAction::Url {
                kind: raw.action,
                replacement,
            }
        } else if allowed & HEADER != 0 {
            let header = raw.header.take().ok_or_else(invalid)?;
            validate_header_name(&header)?;
            let operation = match raw.action {
                ActionKind::RequestHeaderSet | ActionKind::ResponseHeaderSet => {
                    let value = raw.value.take().ok_or_else(invalid)?;
                    validate_header_value(&value)?;
                    HeaderOperation::Set(value.into())
                }
                ActionKind::RequestHeaderAdd | ActionKind::ResponseHeaderAdd => {
                    let value = raw.value.take().ok_or_else(invalid)?;
                    validate_header_value(&value)?;
                    HeaderOperation::Add(value.into())
                }
                ActionKind::RequestHeaderRemove | ActionKind::ResponseHeaderRemove => {
                    HeaderOperation::Remove
                }
                _ => {
                    if let Some(value) = &raw.replacement {
                        validate_header_value(value)?;
                    }
                    HeaderOperation::Replace(raw.compile_search()?)
                }
            };
            RuleAction::Header {
                phase,
                header: header.to_ascii_lowercase().into(),
                operation,
            }
        } else {
            let operation = match raw.action {
                ActionKind::RequestBodySet | ActionKind::ResponseBodySet => {
                    BodyOperation::Set(raw.value.take().ok_or_else(invalid)?.into())
                }
                ActionKind::RequestBodyReplace | ActionKind::ResponseBodyReplace => {
                    BodyOperation::Replace(raw.compile_search()?)
                }
                _ => {
                    let patch = raw.patch.take().ok_or_else(invalid)?;
                    validate_patch(&patch)?;
                    BodyOperation::JsonPatch(patch.into())
                }
            };
            RuleAction::Body { phase, operation }
        };
        *total_text = next_text;
        Ok(Self {
            name: raw.name.map(String::into_boxed_str),
            enabled: raw.enabled,
            selector,
            action,
            upstream: UpstreamAccess::Local,
        })
    }

    pub(super) fn body(
        name: Option<String>,
        selector: Arc<RequestSelector>,
        phase: Phase,
        operation: BodyOperation,
    ) -> Self {
        Self {
            name: name.map(String::into_boxed_str),
            enabled: true,
            selector,
            action: RuleAction::Body { phase, operation },
            upstream: UpstreamAccess::Local,
        }
    }

    pub(super) fn respond(
        name: Option<String>,
        selector: Arc<RequestSelector>,
        response: StaticResponse,
    ) -> Self {
        Self {
            name: name.map(String::into_boxed_str),
            enabled: true,
            selector,
            action: RuleAction::Respond(Arc::new(response)),
            upstream: UpstreamAccess::Local,
        }
    }

    pub(super) fn restrict_upstream(&mut self, approved: Option<Origin>) {
        self.upstream = UpstreamAccess::Managed(approved);
    }

    pub(crate) fn matches<'a>(&self, original: impl Into<RequestMatch<'a>>) -> bool {
        self.enabled && self.selector.matches(original.into())
    }

    pub(crate) fn evaluate_url<'a>(
        &self,
        original: impl Into<RequestMatch<'a>>,
    ) -> io::Result<Option<UrlAction>> {
        let original = original.into();
        let url = original.url;
        if url.as_str().len() > MAX_URL {
            return Err(invalid());
        }
        let (kind, replacement) = match &self.action {
            RuleAction::Respond(response) => {
                return Ok(self
                    .matches(original)
                    .then(|| UrlAction::Respond(response.clone())));
            }
            RuleAction::Url { kind, replacement } => (kind, replacement),
            _ => return Ok(None),
        };
        if !self.matches(original) {
            return Ok(None);
        }
        if *kind == ActionKind::Reject {
            return Ok(Some(UrlAction::Reject));
        }
        let replacement = replacement.as_ref().expect("compiled URL replacement");
        let mut out = String::new();
        match (&self.selector.matcher, &replacement.value) {
            (Matcher::Any | Matcher::PathExact(_), ReplacementValue::Literal(value)) => {
                template::append(&mut out, value, MAX_URL)?;
            }
            (Matcher::PathPrefix(prefix), ReplacementValue::Literal(value)) => {
                let suffix = &url.path()[prefix.len()..];
                if replacement.mode == ReplacementMode::Match {
                    let target = checked_url(value)?;
                    let mut path = target.path().to_owned();
                    if path.ends_with('/') && suffix.starts_with('/') {
                        path.pop();
                    }
                    template::append(&mut path, suffix, MAX_URL)?;
                    let mut target = target;
                    target.set_path(&path);
                    if target.query().is_none() {
                        target.set_query(url.query());
                    }
                    template::append(&mut out, target.as_str(), MAX_URL)?;
                } else {
                    template::append(&mut out, value, MAX_URL)?;
                }
            }
            #[cfg(test)]
            (Matcher::Exact(_), ReplacementValue::Literal(value)) => {
                template::append(&mut out, value, MAX_URL)?;
            }
            #[cfg(test)]
            (Matcher::Prefix(prefix), ReplacementValue::Literal(value)) => {
                let suffix = &url.as_str()[prefix.len()..];
                let value = if replacement.mode == ReplacementMode::Match
                    && !value.contains('?')
                    && value.ends_with('/')
                    && suffix.starts_with('/')
                {
                    &value[..value.len() - 1]
                } else {
                    value.as_ref()
                };
                template::append(&mut out, value, MAX_URL)?;
                if replacement.mode == ReplacementMode::Match {
                    template::append(&mut out, suffix, MAX_URL)?;
                }
            }
            (Matcher::Regex(regex), ReplacementValue::Template(value)) => {
                let captures = regex.captures(url.as_str()).expect("matched regex");
                let found = captures.get(0).expect("regex capture zero");
                if replacement.mode == ReplacementMode::Match {
                    template::append(&mut out, &url.as_str()[..found.start()], MAX_URL)?;
                }
                value.append(&captures, &mut out, MAX_URL)?;
                if replacement.mode == ReplacementMode::Match {
                    template::append(&mut out, &url.as_str()[found.end()..], MAX_URL)?;
                }
            }
            _ => unreachable!("replacement compiled for its selector"),
        }
        let target = checked_url(&out)?;
        Ok(Some(match kind {
            ActionKind::Replace => {
                if let UpstreamAccess::Managed(allowed) = &self.upstream
                    && !same_origin(url, &target)
                    && !allowed
                        .as_ref()
                        .is_some_and(|origin| origin.matches_url(&target))
                {
                    return Ok(None);
                }
                UrlAction::Forward(target)
            }
            ActionKind::Redirect302 => UrlAction::Redirect {
                status: 302,
                url: target,
            },
            ActionKind::Redirect307 => UrlAction::Redirect {
                status: 307,
                url: target,
            },
            _ => unreachable!("URL action"),
        }))
    }
}

pub(super) fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.port_or_known_default() == right.port_or_known_default()
        && left
            .host_str()
            .zip(right.host_str())
            .is_some_and(|(left, right)| {
                left.strip_suffix('.')
                    .unwrap_or(left)
                    .eq_ignore_ascii_case(right.strip_suffix('.').unwrap_or(right))
            })
}

pub(crate) fn checked_url(raw: &str) -> io::Result<Url> {
    if raw.len() > MAX_URL
        || raw.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '\\'
        })
    {
        return Err(invalid());
    }
    // Normalization can erase an empty userinfo delimiter; inspect the input
    // authority before parsing rather than accepting `https://@host/`.
    if raw.split_once(':').is_some_and(|(_, tail)| {
        tail.trim_start_matches('/')
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    }) {
        return Err(invalid());
    }
    let url = Url::parse(raw).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        || url.as_str().len() > MAX_URL
    {
        return Err(invalid());
    }
    Ok(url)
}

pub(crate) fn offline_url(raw: &str) -> io::Result<Url> {
    if raw.len() > MAX_URL {
        return Err(invalid());
    }
    let raw = raw.trim();
    checked_url(raw.split_once('#').map_or(raw, |(url, _)| url))
}

fn bounded_regex(pattern: &str) -> io::Result<Regex> {
    if pattern.len() > MAX_PATTERN {
        return Err(invalid());
    }
    RegexBuilder::new(pattern)
        .size_limit(128 * 1024)
        .dfa_size_limit(64 * 1024)
        .build()
        .map_err(|_| invalid())
}

pub(crate) fn validate_header_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err(invalid());
    }
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "content-encoding"
            | "connection"
            | "upgrade"
            | "expect"
            | "trailer"
            | "te"
            | "http2-settings"
            | "keep-alive"
            | "proxy-connection"
    ) {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn validate_header_value(value: &str) -> io::Result<()> {
    if value
        .bytes()
        .any(|byte| (byte < 32 && byte != b'\t') || byte == 127)
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_patch(patch: &[PatchOperation]) -> io::Result<()> {
    let mut bytes = 0;
    for operation in patch {
        let (path, from, value) = match operation {
            PatchOperation::Add { path, value }
            | PatchOperation::Replace { path, value }
            | PatchOperation::Test { path, value } => (path, None, Some(value)),
            PatchOperation::Remove { path } => (path, None, None),
            PatchOperation::Move { from, path } | PatchOperation::Copy { from, path } => {
                (path, Some(from), None)
            }
        };
        pointer(path)?;
        if let Some(from) = from {
            pointer(from)?;
        }
        bytes += path.len() + from.map_or(0, String::len);
        if let Some(value) = value {
            bytes += serde_json::to_vec(value).map_err(|_| invalid())?.len();
        }
        if bytes > MAX_BODY_VALUE {
            return Err(invalid());
        }
    }
    Ok(())
}

fn pointer(value: &str) -> io::Result<()> {
    if !value.is_empty() && !value.starts_with('/') {
        return Err(invalid());
    }
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
