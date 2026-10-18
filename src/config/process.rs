//! Process predicates share the routing decision's bounded matcher.
use super::{DomainRegex, MatchFailure, Result, RuleDecision, invalid};
use serde::Deserialize;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum FindProcessMode {
    #[default]
    Strict,
    Always,
    Off,
}
impl TryFrom<String> for FindProcessMode {
    type Error = &'static str;
    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "always" => Ok(Self::Always),
            "off" => Ok(Self::Off),
            _ => Err("find-process-mode requires strict, always or off"),
        }
    }
}
impl FindProcessMode {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Always => "always",
            Self::Off => "off",
        }
    }
}

pub(crate) const MAX_PROCESS_TEXT: usize = 32 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessField {
    Name,
    Path,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessRule {
    pub field: ProcessField,
    pub(crate) pattern: String,
    kind: ProcessMatch,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessMatch {
    Exact,
    Wildcard,
    Regex(DomainRegex),
}
impl std::fmt::Debug for ProcessRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessRule")
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}
impl ProcessRule {
    pub(crate) fn parse(kind: &str, payload: &str) -> Result<Self> {
        if payload.is_empty() || payload.len() > MAX_PROCESS_TEXT || payload.contains('\0') {
            return invalid("invalid process predicate payload");
        }
        let field = if kind.starts_with("PROCESS-NAME") {
            ProcessField::Name
        } else {
            ProcessField::Path
        };
        let matcher = if kind.ends_with("-REGEX") {
            ProcessMatch::Regex(DomainRegex::new(payload).map_err(|_| {
                super::VoleError::InvalidConfig(
                    "invalid process regex or compilation budget".into(),
                )
            })?)
        } else if kind.ends_with("-WILDCARD") {
            ProcessMatch::Wildcard
        } else {
            ProcessMatch::Exact
        };
        Ok(Self {
            field,
            pattern: payload.into(),
            kind: matcher,
        })
    }
    pub(crate) fn description(&self) -> &'static str {
        match (self.field, &self.kind) {
            (ProcessField::Name, ProcessMatch::Exact) => "ProcessName",
            (ProcessField::Path, ProcessMatch::Exact) => "ProcessPath",
            (ProcessField::Name, ProcessMatch::Wildcard) => "ProcessNameWildcard",
            (ProcessField::Path, ProcessMatch::Wildcard) => "ProcessPathWildcard",
            (ProcessField::Name, ProcessMatch::Regex(_)) => "ProcessNameRegex",
            (ProcessField::Path, ProcessMatch::Regex(_)) => "ProcessPathRegex",
        }
    }
    pub(crate) fn matches(
        &self,
        value: &str,
        decision: &RuleDecision,
    ) -> std::result::Result<bool, MatchFailure> {
        if value.is_empty() {
            return Ok(false);
        }
        if value.len() > MAX_PROCESS_TEXT || value.contains('\0') {
            return Err(MatchFailure::InvalidInput);
        }
        match &self.kind {
            ProcessMatch::Regex(regex) => regex.is_match_process(value, decision),
            ProcessMatch::Exact => decision.linear(self.pattern.len(), value.len(), || {
                self.pattern.to_lowercase() == value.to_lowercase()
            }),
            ProcessMatch::Wildcard => decision.linear(self.pattern.len(), value.len(), || {
                wildcard(&self.pattern.to_lowercase(), &value.to_lowercase())
            }),
        }
    }
}
// UTF-8 character boundaries matter for '?' in desktop process paths.
fn wildcard(pattern: &str, value: &str) -> bool {
    let (mut p, mut v, mut retry) = (0, 0, None);
    while v < value.len() {
        let next = pattern[p..].chars().next();
        match next {
            Some('*') => {
                p += 1;
                retry = Some((p, v));
            }
            Some(c) if c == '?' || Some(c) == value[v..].chars().next() => {
                p += c.len_utf8();
                v += value[v..].chars().next().unwrap().len_utf8();
            }
            _ => {
                if let Some((after_star, consumed)) = retry {
                    v = consumed + value[consumed..].chars().next().unwrap().len_utf8();
                    p = after_star;
                    retry = Some((p, v));
                } else {
                    return false;
                }
            }
        }
    }
    pattern[p..].chars().all(|c| c == '*')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidRange {
    pub start: u32,
    pub end: u32,
}
pub(crate) fn uid_ranges(payload: &str) -> Result<Vec<UidRange>> {
    if !cfg!(any(target_os = "linux", target_os = "android")) {
        return invalid("UID rules require Linux or Android");
    }
    let mut ranges = Vec::new();
    for item in payload.split('/') {
        let item = item.trim();
        let (start, end) = item.split_once('-').unwrap_or((item, item));
        let (Ok(start), Ok(end)) = (start.trim().parse::<u32>(), end.trim().parse::<u32>()) else {
            return invalid("invalid UID range");
        };
        if ranges.len() >= 28 || start > end {
            return invalid("invalid UID range");
        }
        ranges.push(UidRange { start, end });
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_predicates_preserve_unicode_and_shared_budget() {
        for (kind, pattern, value) in [
            ("PROCESS-NAME", "应用", "应用"),
            ("PROCESS-PATH", "/Applications/WEB", "/applications/web"),
            ("PROCESS-NAME-WILDCARD", "应?*", "应用程序"),
            (
                "PROCESS-PATH-WILDCARD",
                "C:\\*\\应用.exe",
                "c:\\程序\\应用.EXE",
            ),
            ("PROCESS-NAME-REGEX", "(?=应用)应用$", "应用"),
            ("PROCESS-PATH-REGEX", "^/路径/.*$", "/路径/程序"),
        ] {
            assert!(
                ProcessRule::parse(kind, pattern)
                    .unwrap()
                    .matches(value, &Default::default())
                    .unwrap()
            );
        }
        assert!(
            !ProcessRule::parse("PROCESS-NAME-REGEX", ".*")
                .unwrap()
                .matches("", &Default::default())
                .unwrap()
        );
        let decision = RuleDecision::default();
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        decision.set_cancellation(token);
        assert_eq!(
            ProcessRule::parse("PROCESS-NAME", "x")
                .unwrap()
                .matches("x", &decision),
            Err(MatchFailure::Cancelled)
        );
    }
    #[test]
    fn mode_and_platform_uid_boundaries_are_explicit() {
        assert_eq!(
            super::super::Config::parse_yaml(b"find-process-mode: ALWAYS")
                .unwrap()
                .find_process_mode,
            FindProcessMode::Always
        );
        assert!(super::super::Config::parse_yaml(b"find-process-mode: true").is_err());
        assert!(super::super::Config::parse_yaml(b"find-process-mode: enabled").is_err());
        assert_eq!(
            uid_ranges("1001-1003/4294967295").is_ok(),
            cfg!(any(target_os = "linux", target_os = "android"))
        );
        assert!(uid_ranges("4294967296").is_err());
        assert!(uid_ranges("1003-1001").is_err());
    }
}
