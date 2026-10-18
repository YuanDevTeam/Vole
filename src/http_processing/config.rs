//! The HTTP addendum is separate from the Mihomo configuration schema.
use regex::{Captures, Regex, RegexBuilder};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fmt, io, sync::Arc};
use url::Url;

pub(crate) const MAX_ADDENDUM: usize = 1024 * 1024;
pub(super) const MAX_URL: usize = 8192;
const MAX_RULES: usize = 64;
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawConfig {
    #[serde(default = "default_ports")]
    http_ports: Vec<u16>,
    #[serde(default)]
    rewrite: Vec<RawRule>,
}
fn default_ports() -> Vec<u16> {
    vec![80, 8080]
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawRule {
    pattern: String,
    action: ActionKind,
    replacement: Option<String>,
}
#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ActionKind {
    Replace,
    Redirect302,
    Redirect307,
    Reject,
}
struct Rule {
    pattern: Regex,
    action: ActionKind,
    replacement: Option<Box<str>>,
}
pub(crate) struct Policy {
    identity: [u8; 32],
    http_ports: Box<[u16]>,
    rules: Box<[Rule]>,
}
impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPolicy")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}
impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}
impl Eq for Policy {}
pub(super) enum Action {
    Forward(Url),
    Redirect { status: u16, url: Url },
    Reject,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid HTTP processing configuration",
    )
}
impl Policy {
    pub(crate) fn compile_optional(input: Option<&str>) -> crate::Result<Option<Arc<Self>>> {
        let input = input.filter(|value| !value.is_empty());
        #[cfg(not(feature = "inbound-http"))]
        if input.is_some() {
            return Err(crate::VoleError::InvalidConfig(
                "HTTP processing is not compiled in".into(),
            ));
        }
        input
            .map(Self::compile)
            .transpose()
            .map(|policy| policy.filter(|policy| policy.enabled()))
            .map_err(|_| {
                crate::VoleError::InvalidConfig("invalid HTTP processing configuration".into())
            })
    }

    pub(crate) fn compile(input: &str) -> io::Result<Arc<Self>> {
        if input.len() > MAX_ADDENDUM {
            return Err(invalid());
        }
        let value =
            crate::config::yaml::parse_with_budget(input.as_bytes(), &mut (MAX_ADDENDUM * 4))
                .map_err(|_| invalid())?;
        for (key, limit) in [("rewrite", MAX_RULES), ("http-ports", 64)] {
            if value
                .get(key)
                .and_then(serde_yaml_ng::Value::as_sequence)
                .is_some_and(|items| items.len() > limit)
            {
                return Err(invalid());
            }
        }
        let raw: RawConfig = serde_yaml_ng::from_value(value).map_err(|_| invalid())?;
        if raw.rewrite.len() > MAX_RULES || raw.http_ports.len() > 64 || raw.http_ports.contains(&0)
        {
            return Err(invalid());
        }
        let mut total = 0;
        let mut rules = Vec::with_capacity(raw.rewrite.len());
        for rule in raw.rewrite {
            total += rule.pattern.len() + rule.replacement.as_ref().map_or(0, String::len);
            if rule.pattern.len() > 2048
                || total > 64 * 1024
                || rule.replacement.as_ref().is_some_and(|s| s.len() > MAX_URL)
            {
                return Err(invalid());
            }
            if (rule.action == ActionKind::Reject) != rule.replacement.is_none() {
                return Err(invalid());
            }
            let pattern = RegexBuilder::new(&rule.pattern)
                .size_limit(128 * 1024)
                .dfa_size_limit(64 * 1024)
                .build()
                .map_err(|_| invalid())?;
            rules.push(Rule {
                pattern,
                action: rule.action,
                replacement: rule.replacement.map(String::into_boxed_str),
            });
        }
        Ok(Arc::new(Self {
            identity: Sha256::digest(input.as_bytes()).into(),
            http_ports: raw.http_ports.into(),
            rules: rules.into(),
        }))
    }
    pub(crate) fn enabled(&self) -> bool {
        !self.rules.is_empty()
    }
    pub(crate) fn plain_port(&self, port: u16) -> bool {
        !self.rules.is_empty() && self.http_ports.contains(&port)
    }
    pub(super) fn evaluate(&self, url: Url) -> io::Result<Action> {
        if url.as_str().len() > MAX_URL {
            return Err(invalid());
        }
        for rule in &self.rules {
            let Some(captures) = rule.pattern.captures(url.as_str()) else {
                continue;
            };
            if rule.action == ActionKind::Reject {
                return Ok(Action::Reject);
            }
            let replacement = expand(
                &captures,
                rule.replacement.as_deref().expect("validated replacement"),
            )?;
            let target = checked_url(&replacement)?;
            return Ok(match rule.action {
                ActionKind::Replace => Action::Forward(target),
                ActionKind::Redirect302 => Action::Redirect {
                    status: 302,
                    url: target,
                },
                ActionKind::Redirect307 => Action::Redirect {
                    status: 307,
                    url: target,
                },
                ActionKind::Reject => unreachable!(),
            });
        }
        Ok(Action::Forward(url))
    }
}
pub(super) fn checked_url(raw: &str) -> io::Result<Url> {
    if raw.len() > MAX_URL || raw.bytes().any(|b| b <= b' ' || b == 127 || b == b'\\') {
        return Err(invalid());
    }
    let url = Url::parse(raw).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(invalid());
    }
    Ok(url)
}
// Expand only into a bounded result. regex::Captures::expand may allocate a
// multiple of the input when a long capture appears many times in a template.
fn expand(captures: &Captures<'_>, template: &str) -> io::Result<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(index) = rest.find('$') {
        append(&mut out, &rest[..index])?;
        rest = &rest[index + 1..];
        if rest.starts_with('$') {
            append(&mut out, "$")?;
            rest = &rest[1..];
            continue;
        }
        let (name, tail) = if let Some(braced) = rest.strip_prefix('{') {
            let end = braced.find('}').ok_or_else(invalid)?;
            (&braced[..end], &braced[end + 1..])
        } else {
            let end = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            if end == 0 {
                append(&mut out, "$")?;
                continue;
            }
            (&rest[..end], &rest[end..])
        };
        if name.is_empty() {
            return Err(invalid());
        }
        let value = if name.bytes().all(|b| b.is_ascii_digit()) {
            name.parse::<usize>().ok().and_then(|i| captures.get(i))
        } else {
            captures.name(name)
        };
        if let Some(value) = value {
            append(&mut out, value.as_str())?;
        }
        rest = tail;
    }
    append(&mut out, rest)?;
    Ok(out)
}
fn append(out: &mut String, value: &str) -> io::Result<()> {
    if value.len() > MAX_URL.saturating_sub(out.len()) {
        return Err(invalid());
    }
    out.push_str(value);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_http_rules_bound_capture_expansion_and_apply_only_first_match() {
        let policy=Policy::compile("rewrite:\n- {pattern: '^http://old\\.example/(.*)$', action: replace, replacement: 'https://new.example/$1'}\n- {pattern: '.', action: reject}\n").unwrap();
        let Action::Forward(url) = policy
            .evaluate(checked_url("http://old.example/path?q=1").unwrap())
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(url.as_str(), "https://new.example/path?q=1");
        assert!(matches!(
            policy
                .evaluate(checked_url("http://other.example/").unwrap())
                .unwrap(),
            Action::Reject
        ));
        let regex = Regex::new("(.*)").unwrap();
        let input = "x".repeat(MAX_URL);
        let captures = regex.captures(&input).unwrap();
        assert!(expand(&captures, "$1$1").is_err());
        assert_eq!(expand(&captures, "$$/literal").unwrap(), "$/literal");
        for raw in [
            "http://u:p@host/",
            "file:///tmp/file",
            "http://host/#fragment",
            "http://host/\r\n",
        ] {
            assert!(checked_url(raw).is_err());
        }
        assert!(
            Policy::compile(
                "rewrite: [{pattern: '.', action: reject, replacement: 'http://host/'}]"
            )
            .is_err()
        );
        assert!(Policy::compile("rewrite: [{pattern: '.', action: replace}]").is_err());
    }
}

#[cfg(all(test, feature = "inbound-http"))]
mod snapshot_tests {
    use super::*;
    #[test]
    fn addendum_is_strict_and_kept_outside_mihomo_yaml() {
        let mut config = crate::config::Config::parse_yaml(b"rules: ['MATCH,DIRECT']\n").unwrap();
        config
            .set_http_config(Some("rewrite: [{pattern: '.', action: reject}]"))
            .unwrap();
        let policy = config.http_policy().unwrap();
        assert!(policy.enabled());
        let template = config.providers.as_ref().unwrap();
        let rebuilt = template
            .materialize(&crate::config::providers::ProviderContents::new())
            .unwrap();
        assert!(Arc::ptr_eq(&policy, &rebuilt.http_policy().unwrap()));
        assert!(
            crate::config::Config::parse_yaml(b"rewrite: []\nrules: ['MATCH,DIRECT']\n").is_err()
        );
        for bad in [
            "mitm: {}",
            "rewrite: [{pattern: '.', action: mock}]",
            "http-ports: [0]",
            "rewrite: [{pattern: '.', action: replace}]",
        ] {
            assert!(Policy::compile(bad).is_err());
        }
        assert!(Policy::compile(&format!("http-ports: [{}]", vec!["80"; 65].join(","))).is_err());
        assert!(Policy::compile_optional(Some("")).unwrap().is_none());
        assert!(
            Policy::compile_optional(Some("rewrite: []"))
                .unwrap()
                .is_none()
        );
    }
}
