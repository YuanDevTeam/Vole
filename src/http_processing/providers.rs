//! Named HTTP-rule resources. Remote content never carries local TLS authority.
#[path = "providers_store.rs"]
mod store;
pub(crate) use store::{DownloadContext, SourceContext, Store};

use super::{
    config::{MAX_ADDENDUM, compile_rule, invalid, nonnull},
    rules::{MAX_RULES, RawRule},
};
use crate::resource::http::{self, HttpOptions};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

fn interval() -> u64 {
    86400
}
fn optional<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    nonnull(deserializer).map(Some)
}
fn headers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error> {
    #[derive(Deserialize)]
    struct Values(#[serde(deserialize_with = "nonnull")] Vec<String>);
    let map: BTreeMap<String, Values> = nonnull(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(name, values)| (name, values.0))
        .collect())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ProviderSpec {
    File {
        path: String,
    },
    Http {
        url: String,
        #[serde(
            default,
            deserialize_with = "optional",
            skip_serializing_if = "Option::is_none"
        )]
        path: Option<String>,
        #[serde(default = "interval")]
        interval: u64,
        #[serde(default, deserialize_with = "headers")]
        header: BTreeMap<String, Vec<String>>,
    },
    Inline {
        #[serde(deserialize_with = "nonnull")]
        payload: Vec<RawRule>,
    },
}

impl ProviderSpec {
    pub(crate) fn validate(&self) -> io::Result<()> {
        match self {
            Self::File { path } => validate_path(path),
            Self::Inline { payload } => validate_rules(payload),
            Self::Http {
                url, path, header, ..
            } => {
                super::rules::checked_url(url)?;
                if let Some(path) = path {
                    validate_path(path)?;
                }
                let mut names = BTreeSet::new();
                if header.len() > 64 {
                    return Err(invalid());
                }
                for (name, values) in header {
                    if !names.insert(name.to_ascii_lowercase()) || values.len() > 64 {
                        return Err(invalid());
                    }
                    if values.iter().any(|value| {
                        value
                            .chars()
                            .any(|character| character.is_control() && character != '\t')
                    }) {
                        return Err(invalid());
                    }
                }
                let options = self.options()?;
                let mut names_only = options.clone();
                names_only.headers = header
                    .keys()
                    .map(|name| (name.clone(), String::new()))
                    .collect();
                http::validate_options(&names_only).map_err(|_| invalid())?;
                http::parse_url(url, &options).map_err(|_| invalid())?;
                http::validate_options(&options).map_err(|_| invalid())
            }
        }
    }

    pub(super) fn options(&self) -> io::Result<HttpOptions> {
        let Self::Http { header, .. } = self else {
            return Err(invalid());
        };
        Ok(HttpOptions {
            headers: header
                .iter()
                .flat_map(|(name, values)| {
                    values
                        .iter()
                        .map(move |value| (name.to_ascii_lowercase(), value.clone()))
                })
                .collect(),
            size_limit: Some(MAX_ADDENDUM as u64),
            allow_http: true,
            allow_ip: true,
            ..Default::default()
        })
    }

    pub(super) fn source_identity(&self) -> io::Result<String> {
        let Self::Http { url, .. } = self else {
            return Err(invalid());
        };
        http::request_identity(url, &self.options()?).map_err(|_| invalid())
    }
}

fn validate_path(path: &str) -> io::Result<()> {
    if path.is_empty() || path.contains('\0') {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    #[serde(rename = "payload", deserialize_with = "nonnull")]
    rules: Vec<RawRule>,
    #[serde(skip)]
    identity: [u8; 32],
    #[serde(skip)]
    input_bytes: usize,
}

impl Payload {
    pub(crate) fn parse(input: &[u8]) -> io::Result<Self> {
        if input.len() > MAX_ADDENDUM {
            return Err(invalid());
        }
        let value = crate::config::yaml::parse_with_budget(input, &mut (MAX_ADDENDUM * 4))
            .map_err(|_| invalid())?;
        let mut payload: Self = serde_yaml_ng::from_value(value).map_err(|_| invalid())?;
        payload.input_bytes = input.len();
        payload.finish()?;
        Ok(payload)
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        validate_rules(&self.rules)?;
        let encoded = serde_json::to_vec(&self.rules).map_err(|_| invalid())?;
        self.identity = Sha256::digest(encoded).into();
        if self.input_bytes == 0 {
            self.input_bytes = serde_yaml_ng::to_string(self).map_err(|_| invalid())?.len();
        }
        if self.input_bytes > MAX_ADDENDUM {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn rules(&self) -> &[RawRule] {
        &self.rules
    }
    pub(crate) fn input_bytes(&self) -> usize {
        self.input_bytes
    }
}

fn validate_rules(rules: &[RawRule]) -> io::Result<()> {
    if rules.len() > MAX_RULES {
        return Err(invalid());
    }
    let mut text = 0;
    for rule in rules {
        compile_rule(rule.clone(), &mut text)?;
    }
    Ok(())
}
