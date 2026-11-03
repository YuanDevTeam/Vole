//! Ordered header transactions shared by the HTTP/1 and HTTP/2 adapters.
use super::rules::{HeaderOperation, Phase, Rule, RuleAction, validate_header_value};
use std::io;
use url::Url;

pub(crate) type Fields = Vec<(String, String)>;
pub(crate) const MAX_FIELDS: usize = 100;
pub(crate) const MAX_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Unchanged,
    Changed,
    RolledBack,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "HTTP header rewrite failed")
}

pub(crate) fn check(fields: &[(String, String)]) -> io::Result<()> {
    if fields.len() > MAX_FIELDS {
        return Err(invalid());
    }
    let mut size = 0usize;
    for (name, value) in fields {
        http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
        validate_header_value(value).map_err(|_| invalid())?;
        size = size
            .checked_add(name.len() + value.len() + 32)
            .filter(|size| *size <= MAX_BYTES)
            .ok_or_else(invalid)?;
    }
    Ok(())
}

/// Cross-origin cleaning precedes the transaction: rollback must not restore
/// credentials belonging to the original authority.
pub(crate) fn strip_origin_credentials(fields: &mut Fields) {
    fields.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("authorization") && !name.eq_ignore_ascii_case("cookie")
    });
}

pub(crate) fn apply(rules: &[Rule], original: &Url, phase: Phase, fields: &mut Fields) -> Outcome {
    if !rules.iter().any(|rule| {
        matches!(&rule.action, RuleAction::Header { phase: p, .. } if *p == phase)
            && rule.matches(original)
    }) {
        return Outcome::Unchanged;
    }
    if check(fields).is_err() {
        return Outcome::RolledBack;
    }
    let mut candidate = fields.clone();
    let result = (|| {
        for rule in rules {
            let RuleAction::Header {
                phase: rule_phase,
                header,
                operation,
            } = &rule.action
            else {
                continue;
            };
            if *rule_phase != phase || !rule.matches(original) {
                continue;
            }
            // Connection nominations remain protocol owned even when the
            // adapter will subsequently remove the Connection field itself.
            if fields.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case(header))
            }) {
                return Err(invalid());
            }
            match operation {
                HeaderOperation::Set(value) => {
                    candidate.retain(|(name, _)| !name.eq_ignore_ascii_case(header));
                    append(&mut candidate, header, value)?;
                }
                HeaderOperation::Add(value) => append(&mut candidate, header, value)?,
                HeaderOperation::Remove => {
                    candidate.retain(|(name, _)| !name.eq_ignore_ascii_case(header));
                }
                HeaderOperation::Replace(search) => {
                    for (name, value) in &mut candidate {
                        if name.eq_ignore_ascii_case(header) {
                            let replacement = search.apply(value, MAX_BYTES)?;
                            validate_header_value(&replacement)?;
                            *value = replacement;
                        }
                    }
                }
            }
            check(&candidate)?;
        }
        Ok::<_, io::Error>(())
    })();
    if result.is_err() {
        Outcome::RolledBack
    } else if candidate == *fields {
        Outcome::Unchanged
    } else {
        *fields = candidate;
        Outcome::Changed
    }
}

pub(crate) fn apply_map(
    rules: &[Rule],
    original: &Url,
    phase: Phase,
    fields: &mut http::HeaderMap,
) -> Outcome {
    if !rules.iter().any(|rule| {
        matches!(&rule.action, RuleAction::Header { phase: p, .. } if *p == phase)
            && rule.matches(original)
    }) {
        return Outcome::Unchanged;
    }
    let Some(mut candidate) = from_map(fields) else {
        return Outcome::RolledBack;
    };
    let outcome = apply(rules, original, phase, &mut candidate);
    if outcome != Outcome::Changed {
        return outcome;
    }
    let Some(converted) = to_map(candidate) else {
        return Outcome::RolledBack;
    };
    *fields = converted;
    Outcome::Changed
}

pub(crate) fn to_map(fields: Fields) -> Option<http::HeaderMap> {
    let mut converted = http::HeaderMap::with_capacity(fields.len());
    for (name, value) in fields {
        converted.append(
            http::header::HeaderName::from_bytes(name.as_bytes()).ok()?,
            http::header::HeaderValue::from_bytes(value.as_bytes()).ok()?,
        );
    }
    Some(converted)
}

pub(crate) fn from_map(fields: &http::HeaderMap) -> Option<Fields> {
    if fields.len() > MAX_FIELDS {
        return None;
    }
    let mut size = 0usize;
    let mut result = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        size = size.checked_add(name.as_str().len() + value.len() + 32)?;
        if size > MAX_BYTES {
            return None;
        }
        let value = std::str::from_utf8(value.as_bytes()).ok()?;
        result.push((name.as_str().to_owned(), value.to_owned()));
    }
    Some(result)
}

fn append(fields: &mut Fields, header: &str, value: &str) -> io::Result<()> {
    let current: usize = fields
        .iter()
        .map(|(name, value)| name.len() + value.len() + 32)
        .sum();
    if fields.len() >= MAX_FIELDS || current + header.len() + value.len() + 32 > MAX_BYTES {
        return Err(invalid());
    }
    fields.push((header.to_owned(), value.to_owned()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_processing::rules::RawRule;

    fn rules(yaml: &str) -> Vec<Rule> {
        let raw: Vec<RawRule> = serde_yaml_ng::from_str(yaml).unwrap();
        let mut total = 0;
        raw.into_iter()
            .map(|raw| Rule::compile(raw, &mut total).unwrap())
            .collect()
    }

    #[test]
    fn header_transaction_preserves_values_order_and_original_selector() {
        let rules = rules(
            r#"
- {url: '^https://old\.example/', action: response-header-add, header: Set-Cookie, value: c=3}
- {url: '^https://old\.example/', action: response-header-replace, header: Set-Cookie, search: '=', replacement: ':', occurrences: first}
- {url: '^https://new\.example/', action: response-header-remove, header: Set-Cookie}
"#,
        );
        let mut fields = vec![
            ("Set-Cookie".into(), "a=1".into()),
            ("set-cookie".into(), "b=2".into()),
        ];
        assert_eq!(
            apply(
                &rules,
                &Url::parse("https://old.example/a").unwrap(),
                Phase::Response,
                &mut fields
            ),
            Outcome::Changed
        );
        assert_eq!(
            fields
                .iter()
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            ["a:1", "b:2", "c:3"]
        );
    }

    #[test]
    fn header_failure_rolls_back_without_restoring_cross_origin_credentials() {
        let rules = rules(
            r#"
- {url: '.', action: request-header-add, header: X-New, value: ok}
- {url: '.', action: request-header-replace, header: X-Test, search: '(.+)', search-mode: regex, replacement: '$1$1'}
"#,
        );
        let mut fields = vec![
            ("Authorization".into(), "secret".into()),
            ("X-Test".into(), "a".repeat(20 * 1024)),
        ];
        strip_origin_credentials(&mut fields);
        let before = fields.clone();
        assert_eq!(
            apply(
                &rules,
                &Url::parse("https://a.example/").unwrap(),
                Phase::Request,
                &mut fields
            ),
            Outcome::RolledBack
        );
        assert_eq!(fields, before);
    }

    #[test]
    fn connection_nominations_cannot_be_edited() {
        let rules =
            rules("- {url: '.', action: request-header-set, header: X-Hop, value: changed}");
        let mut fields = vec![
            ("Connection".into(), "X-Hop".into()),
            ("X-Hop".into(), "original".into()),
        ];
        assert_eq!(
            apply(
                &rules,
                &Url::parse("http://a.example/").unwrap(),
                Phase::Request,
                &mut fields
            ),
            Outcome::RolledBack
        );
        assert_eq!(fields[1].1, "original");
    }
}
