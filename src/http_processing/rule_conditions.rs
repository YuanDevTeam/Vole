//! Matching inputs snapshot selected conditions before a stage mutates headers.
use super::{MAX_PATTERN, SelectorCompiler, invalid, optional};
use crate::http_processing::rules::{HeaderView, validate_header_value};
use http::HeaderName;
use regex::Regex;
use serde::Deserialize;
use std::{io, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeaderCondition {
    name: String,
    #[serde(default, deserialize_with = "optional")]
    exists: Option<bool>,
    #[serde(default, deserialize_with = "optional")]
    equals: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    regex: Option<String>,
}

struct HeaderPredicate {
    name: HeaderName,
    operator: Operator,
}

enum Operator {
    Exists(bool),
    Equals(String),
    Regex(Arc<Regex>),
}

impl HeaderPredicate {
    fn matches(&self, headers: HeaderView<'_>) -> bool {
        if let Operator::Exists(expected) = self.operator {
            let exists = match headers {
                HeaderView::Fields(fields) => fields
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(self.name.as_str())),
                HeaderView::Map(map) => map.contains_key(&self.name),
            };
            return exists == expected;
        }

        let matches_value = |value: &str| match &self.operator {
            Operator::Equals(expected) => value == expected,
            Operator::Regex(regex) => regex.is_match(value),
            Operator::Exists(_) => unreachable!("existence checked above"),
        };
        match headers {
            HeaderView::Fields(fields) => fields.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case(self.name.as_str()) && matches_value(value)
            }),
            HeaderView::Map(map) => map
                .get_all(&self.name)
                .iter()
                .filter_map(|value| std::str::from_utf8(value.as_bytes()).ok())
                .any(matches_value),
        }
    }
}

pub(super) struct Conditions {
    mask: u64,
    status: Option<u16>,
    headers: Box<[HeaderPredicate]>,
}

impl Conditions {
    pub(super) fn compile(
        mask: u64,
        status: Option<u16>,
        headers: Vec<HeaderCondition>,
        selectors: &mut SelectorCompiler,
    ) -> io::Result<Option<(Self, usize)>> {
        if status.is_none() && headers.is_empty() {
            return Ok(None);
        }
        if status.is_some_and(|status| !(200..=599).contains(&status)) || headers.len() > 64 {
            return Err(invalid());
        }
        let mut bytes = 0;
        let mut predicates = Vec::with_capacity(headers.len());
        for header in headers {
            if header.name.len() > MAX_PATTERN {
                return Err(invalid());
            }
            let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| invalid())?;
            bytes += header.name.len();
            let operator = match (header.exists, header.equals, header.regex) {
                (Some(value), None, None) => Operator::Exists(value),
                (None, Some(value), None) if value.len() <= MAX_PATTERN => {
                    validate_header_value(&value)?;
                    bytes += value.len();
                    Operator::Equals(value)
                }
                (None, None, Some(pattern)) => {
                    bytes += pattern.len();
                    Operator::Regex(selectors.regex(&pattern)?)
                }
                _ => return Err(invalid()),
            };
            predicates.push(HeaderPredicate { name, operator });
        }
        Ok(Some((
            Self {
                mask,
                status,
                headers: predicates.into(),
            },
            bytes,
        )))
    }

    pub(super) fn selected(&self, status: Option<u16>, headers: HeaderView<'_>) -> u64 {
        if self.status.is_none_or(|expected| status == Some(expected))
            && self
                .headers
                .iter()
                .all(|predicate| predicate.matches(headers))
        {
            self.mask
        } else {
            0
        }
    }
}
