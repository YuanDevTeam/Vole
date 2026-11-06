//! Inline script declarations and pure compilation of their URL selectors.
use super::{
    config::{invalid, nonnull},
    rules::{MAX_PATTERN, MAX_RULE_TEXT, MAX_RULES, MatchKind, Phase, checked_url},
    scripts::{self, CompiledSource},
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io;
use url::Url;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BodyMode {
    #[default]
    None,
    Text,
    Bytes,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawScripts {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default, deserialize_with = "nonnull")]
    scripts: Vec<RawScript>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawScript {
    name: String,
    #[serde(deserialize_with = "phase", serialize_with = "serialize_phase")]
    phase: Phase,
    url: String,
    #[serde(default, rename = "match")]
    match_kind: MatchKind,
    #[serde(default)]
    body: BodyMode,
    source: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum RawPhase {
    Request,
    Response,
}

fn phase<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Phase, D::Error> {
    RawPhase::deserialize(deserializer).map(|phase| match phase {
        RawPhase::Request => Phase::Request,
        RawPhase::Response => Phase::Response,
    })
}

fn serialize_phase<S: Serializer>(phase: &Phase, serializer: S) -> Result<S::Ok, S::Error> {
    match phase {
        Phase::Request => RawPhase::Request,
        Phase::Response => RawPhase::Response,
    }
    .serialize(serializer)
}

#[derive(Clone)]
enum Matcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

#[derive(Clone)]
pub(crate) struct CompiledScript {
    pub(crate) name: String,
    pub(crate) phase: Phase,
    pub(crate) body: BodyMode,
    pub(crate) compiled: CompiledSource,
    matcher: Matcher,
}

impl CompiledScript {
    pub(crate) fn matches(&self, url: &Url) -> bool {
        match &self.matcher {
            Matcher::Exact(value) => url.as_str() == value,
            Matcher::Prefix(value) => url.as_str().starts_with(value),
            Matcher::Regex(regex) => regex.is_match(url.as_str()),
        }
    }
}

impl RawScripts {
    pub(crate) fn is_active(&self) -> bool {
        self.enabled && !self.scripts.is_empty()
    }

    /// Platform admission belongs to actual preparation, never YAML validation.
    pub(crate) fn ensure_available(&self) -> io::Result<()> {
        if self.is_active() {
            scripts::ensure_available()?;
        }
        Ok(())
    }

    /// Disabled declarations are validated too; enabling cannot expose a
    /// previously unchecked source or selector.
    pub(crate) fn compile(&self) -> io::Result<Vec<CompiledScript>> {
        if self.scripts.len() > MAX_RULES {
            return Err(invalid());
        }
        let mut text = 0usize;
        self.scripts
            .iter()
            .map(|script| {
                text = text
                    .checked_add(script.name.len())
                    .and_then(|size| size.checked_add(script.url.len()))
                    .filter(|size| *size <= MAX_RULE_TEXT)
                    .ok_or_else(invalid)?;
                if script.name.trim().is_empty()
                    || script.name.chars().any(char::is_control)
                    || script.url.len() > MAX_PATTERN
                {
                    return Err(invalid());
                }
                let matcher = match script.match_kind {
                    MatchKind::Exact => Matcher::Exact(checked_url(&script.url)?.to_string()),
                    MatchKind::Prefix => Matcher::Prefix(checked_url(&script.url)?.to_string()),
                    MatchKind::Regex => Matcher::Regex(
                        RegexBuilder::new(&script.url)
                            .size_limit(128 * 1024)
                            .dfa_size_limit(64 * 1024)
                            .build()
                            .map_err(|_| invalid())?,
                    ),
                };
                Ok(CompiledScript {
                    name: script.name.clone(),
                    phase: script.phase,
                    body: script.body,
                    compiled: scripts::validate_source(&script.source)?,
                    matcher,
                })
            })
            .collect()
    }
}
