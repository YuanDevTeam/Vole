//! The common flat HTTP rule schema and pure, bounded rule compiler.
use regex::{Regex, RegexBuilder};
use std::io;
use url::Url;

#[path = "rule_schema.rs"]
mod schema;
pub(crate) use schema::{
    ActionKind, MatchKind, Occurrences, PatchOperation, Phase, RawRule, ReplacementMode, SearchMode,
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
    pub(crate) selector: Matcher,
    pub(crate) action: RuleAction,
}

pub(crate) enum Matcher {
    Exact(Box<str>),
    Prefix(Box<str>),
    Regex(Regex),
}

pub(crate) enum RuleAction {
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
    pub(crate) fn compile(mut raw: RawRule, total_text: &mut usize) -> io::Result<Self> {
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
        let selector = match raw.match_kind {
            MatchKind::Regex => Matcher::Regex(bounded_regex(&raw.url)?),
            MatchKind::Exact => Matcher::Exact(checked_url(&raw.url)?.as_str().into()),
            MatchKind::Prefix => Matcher::Prefix(checked_url(&raw.url)?.as_str().into()),
        };
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
                let value = match &selector {
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
        })
    }

    pub(crate) fn matches(&self, url: &Url) -> bool {
        self.enabled
            && match &self.selector {
                Matcher::Exact(value) => url.as_str() == value.as_ref(),
                Matcher::Prefix(value) => url.as_str().starts_with(value.as_ref()),
                Matcher::Regex(regex) => regex.is_match(url.as_str()),
            }
    }

    pub(crate) fn evaluate_url(&self, url: &Url) -> io::Result<Option<UrlAction>> {
        if url.as_str().len() > MAX_URL {
            return Err(invalid());
        }
        let RuleAction::Url { kind, replacement } = &self.action else {
            return Ok(None);
        };
        if !self.matches(url) {
            return Ok(None);
        }
        if *kind == ActionKind::Reject {
            return Ok(Some(UrlAction::Reject));
        }
        let replacement = replacement.as_ref().expect("compiled URL replacement");
        let mut out = String::new();
        match (&self.selector, &replacement.value) {
            (Matcher::Exact(_), ReplacementValue::Literal(value)) => {
                template::append(&mut out, value, MAX_URL)?
            }
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
            ActionKind::Replace => UrlAction::Forward(target),
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
