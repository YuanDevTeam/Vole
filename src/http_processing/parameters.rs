//! Literal parameter declarations and the effective values of one installation.
use super::{invalid, optional, valid_name};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

const MAX_PARAMETERS: usize = 32;
const MAX_STRING: usize = 2048;
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

pub(crate) type ParameterValues = BTreeMap<String, ParameterValue>;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub(crate) enum ParameterValue {
    Boolean(bool),
    Integer(i64),
    String(String),
}

impl ParameterValue {
    fn valid(&self, kind: ParameterType) -> bool {
        match (self, kind) {
            (Self::Boolean(_), ParameterType::Boolean) => true,
            (Self::Integer(value), ParameterType::Integer) => {
                (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value)
            }
            (Self::String(value), ParameterType::String) => value.len() <= MAX_STRING,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ParameterType {
    Boolean,
    Integer,
    String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParameterDeclaration {
    #[serde(rename = "type")]
    kind: ParameterType,
    default: ParameterValue,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    label: Option<String>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    description: Option<String>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    choices: Option<Vec<ParameterValue>>,
}

pub(super) type ParameterDeclarations = BTreeMap<String, ParameterDeclaration>;

impl ParameterDeclaration {
    fn accepts(&self, value: &ParameterValue) -> bool {
        value.valid(self.kind)
            && self
                .choices
                .as_ref()
                .is_none_or(|choices| choices.contains(value))
    }

    fn validate(&self) -> io::Result<()> {
        if !self.accepts(&self.default)
            || self
                .label
                .as_deref()
                .is_some_and(|value| !valid_name(value) || value.len() > MAX_STRING)
            || self
                .description
                .as_deref()
                .is_some_and(|value| value.len() > MAX_STRING)
        {
            return Err(invalid());
        }
        if let Some(choices) = &self.choices {
            let mut seen = BTreeSet::new();
            if self.kind == ParameterType::Boolean
                || choices.is_empty()
                || choices
                    .iter()
                    .any(|value| !value.valid(self.kind) || !seen.insert(value))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub(super) fn resolve(
    declarations: &ParameterDeclarations,
    overrides: Option<&ParameterValues>,
) -> io::Result<ParameterValues> {
    if declarations.len() > MAX_PARAMETERS
        || overrides.is_some_and(|values| values.keys().any(|key| !declarations.contains_key(key)))
    {
        return Err(invalid());
    }
    declarations
        .iter()
        .map(|(key, declaration)| {
            if !valid_key(key) {
                return Err(invalid());
            }
            declaration.validate()?;
            let value = overrides
                .and_then(|values| values.get(key))
                .unwrap_or(&declaration.default);
            if !declaration.accepts(value) {
                return Err(invalid());
            }
            Ok((key.clone(), value.clone()))
        })
        .collect()
}

pub(super) fn matches(
    declarations: &ParameterDeclarations,
    effective: &ParameterValues,
    conditions: &ParameterValues,
) -> io::Result<bool> {
    let mut matched = true;
    for (key, expected) in conditions {
        if !declarations
            .get(key)
            .is_some_and(|entry| entry.accepts(expected))
        {
            return Err(invalid());
        }
        matched &= effective.get(key) == Some(expected);
    }
    Ok(matched)
}

pub(super) fn valid_key(key: &str) -> bool {
    key.len() <= 64
        && key.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Worst-case work for the bounded native-to-JS metadata projection.
pub(super) fn bridge_bytes(values: &ParameterValues) -> usize {
    values
        .iter()
        .map(|(key, value)| {
            let value_len = match value {
                ParameterValue::String(value) => value.len(),
                ParameterValue::Integer(_) => 17,
                ParameterValue::Boolean(_) => 5,
            };
            128 + 16 * (key.len() + value_len)
        })
        .sum()
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum TextValue {
    Literal(String),
    Parameter(ParameterReference),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ParameterReference {
    param: String,
}

impl TextValue {
    pub(super) fn into_text(self, effective: &ParameterValues) -> io::Result<String> {
        match self {
            Self::Literal(value) => Ok(value),
            Self::Parameter(reference) => match effective.get(&reference.param) {
                Some(ParameterValue::String(value)) => Ok(value.clone()),
                _ => Err(invalid()),
            },
        }
    }
}
