//! The independent HTTP document. Parsing is pure and never reads resources.
use super::{MAX_ADDENDUM, Policy, PolicyCandidate, SourceLocation, invalid};
use crate::http_processing::{
    mitm::RawMitm,
    providers::{Payload, ProviderSpec},
    rules::{MAX_RULES, RawRule, Rule},
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::Arc,
};

pub(crate) fn nonnull<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("null is not an omitted HTTP setting"))
}

fn plain_ports() -> Vec<u16> {
    vec![80, 8080]
}
fn enabled() -> bool {
    true
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Document {
    #[serde(default = "plain_ports", deserialize_with = "nonnull")]
    pub(crate) http_ports: Vec<u16>,
    #[serde(default, rename = "rewrite-providers", deserialize_with = "nonnull")]
    pub(crate) providers: BTreeMap<String, ProviderSpec>,
    #[serde(default, deserialize_with = "nonnull")]
    pub(crate) rewrite: Rewrite,
    #[serde(default, deserialize_with = "nonnull")]
    pub(crate) mitm: RawMitm,
    #[serde(skip)]
    identity: [u8; 32],
    #[serde(skip)]
    pub(crate) input_bytes: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rewrite {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default, deserialize_with = "nonnull")]
    pub(crate) rules: Vec<RuleEntry>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum RuleEntry {
    Rule(RawRule),
    Reference(Reference),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Reference {
    pub(crate) rule_set: String,
    #[serde(default = "enabled")]
    pub(crate) enabled: bool,
}

impl Document {
    pub(crate) fn parse(input: &str) -> io::Result<Arc<Self>> {
        if input.len() > MAX_ADDENDUM {
            return Err(invalid());
        }
        crate::http_processing::numeric_input::validate(input.as_bytes())?;
        let value =
            crate::config::yaml::parse_with_budget(input.as_bytes(), &mut (MAX_ADDENDUM * 4))
                .map_err(|_| invalid())?;
        if !value.is_mapping() {
            return Err(invalid());
        }
        let mut document: Self = serde_yaml_ng::from_value(value).map_err(|_| invalid())?;
        document.input_bytes = input.len();
        document.finish()?;
        Ok(Arc::new(document))
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        validate_ports(&self.http_ports)?;
        self.mitm.validate_static()?;
        if self.providers.len() > MAX_RULES || self.rewrite.rules.len() > MAX_RULES {
            return Err(invalid());
        }
        for (name, provider) in &self.providers {
            if name.trim().is_empty() || name.chars().any(char::is_control) {
                return Err(invalid());
            }
            provider.validate()?;
        }
        let mut references = BTreeSet::new();
        let mut text = 0;
        for entry in &self.rewrite.rules {
            match entry {
                RuleEntry::Rule(rule) => {
                    compile_rule(rule.clone(), &mut text)?;
                }
                RuleEntry::Reference(reference) => {
                    if !self.providers.contains_key(&reference.rule_set)
                        || !references.insert(&reference.rule_set)
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        let mut paths = BTreeSet::new();
        for provider in self.providers.values() {
            if let ProviderSpec::Http {
                path: Some(path), ..
            } = provider
                && !paths.insert(path)
            {
                return Err(invalid());
            }
        }
        self.identity = Sha256::digest(serde_json::to_vec(self).map_err(|_| invalid())?).into();
        Ok(())
    }

    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }

    pub(crate) fn active_provider_names(&self) -> impl Iterator<Item = &str> {
        self.rewrite.rules.iter().filter_map(|entry| match entry {
            RuleEntry::Reference(reference) if reference.enabled => {
                Some(reference.rule_set.as_str())
            }
            _ => None,
        })
    }

    pub(crate) fn unresolved_count(&self) -> usize {
        self.active_provider_names()
            .filter(|name| !matches!(self.providers[*name], ProviderSpec::Inline { .. }))
            .count()
    }

    pub(crate) fn static_policy(self: &Arc<Self>) -> io::Result<Arc<Policy>> {
        let candidate = if self.unresolved_count() == 0 {
            Some(self.compile(&BTreeMap::new())?)
        } else {
            None
        };
        Ok(Arc::new(Policy::from_static(self.clone(), candidate)))
    }

    pub(crate) fn compile(
        self: &Arc<Self>,
        contents: &BTreeMap<String, Arc<Payload>>,
    ) -> io::Result<Arc<PolicyCandidate>> {
        let mut rules = Vec::new();
        let mut text = 0;
        let mut payloads = BTreeMap::new();
        let mut origins = Vec::new();
        let mut bytes = self.input_bytes;
        for (index, entry) in self.rewrite.rules.iter().enumerate() {
            match entry {
                RuleEntry::Rule(rule) => {
                    if rules.len() == MAX_RULES {
                        return Err(invalid());
                    }
                    rules.push(compile_rule(rule.clone(), &mut text)?);
                    origins.push(SourceLocation::Local { index });
                }
                RuleEntry::Reference(reference) if reference.enabled => {
                    let raw_rules = match &self.providers[&reference.rule_set] {
                        ProviderSpec::Inline { payload } => payload.as_slice(),
                        _ => {
                            let payload = contents.get(&reference.rule_set).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "HTTP rewrite resource is not prepared",
                                )
                            })?;
                            bytes = bytes
                                .checked_add(payload.input_bytes())
                                .ok_or_else(invalid)?;
                            if bytes > MAX_ADDENDUM {
                                return Err(invalid());
                            }
                            payloads.insert(reference.rule_set.clone(), payload.clone());
                            payload.rules()
                        }
                    };
                    for (index, rule) in raw_rules.iter().enumerate() {
                        if rules.len() == MAX_RULES {
                            return Err(invalid());
                        }
                        rules.push(compile_rule(rule.clone(), &mut text)?);
                        origins.push(SourceLocation::Provider {
                            provider: reference.rule_set.clone(),
                            index,
                        });
                    }
                }
                RuleEntry::Reference(_) => (),
            }
            if rules.len() > MAX_RULES {
                return Err(invalid());
            }
        }
        let mut hash = Sha256::new();
        hash.update(self.identity);
        for (name, payload) in &payloads {
            hash.update((name.len() as u64).to_be_bytes());
            hash.update(name.as_bytes());
            hash.update(payload.identity());
        }
        Ok(Arc::new(PolicyCandidate {
            document: self.clone(),
            rules: rules.into(),
            payloads,
            identity: hash.finalize().into(),
            origins: origins.into(),
            source_identity: None,
        }))
    }
}

pub(crate) fn compile_rule(raw: RawRule, text: &mut usize) -> io::Result<Rule> {
    if matches!(raw.action, crate::http_processing::rules::ActionKind::RequestBodySet | crate::http_processing::rules::ActionKind::RequestBodyReplace | crate::http_processing::rules::ActionKind::RequestBodyJsonPatch | crate::http_processing::rules::ActionKind::ResponseBodySet | crate::http_processing::rules::ActionKind::ResponseBodyReplace | crate::http_processing::rules::ActionKind::ResponseBodyJsonPatch) {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "HTTP rewrite action is not available"));
    }
    Rule::compile(raw, text)
}

fn validate_ports(ports: &[u16]) -> io::Result<()> {
    if ports.len() > 64
        || ports.contains(&0)
        || ports.iter().collect::<BTreeSet<_>>().len() != ports.len()
    {
        return Err(invalid());
    }
    Ok(())
}
