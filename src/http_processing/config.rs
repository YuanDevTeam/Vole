//! Immutable business HTTP policy, separate from Mihomo configuration.
#[path = "document.rs"]
mod document;
pub(crate) use document::{Document, compile_rule, nonnull};

use super::{
    private_context::CaMaterial,
    providers::Payload,
    rules::{self, Rule, UrlAction},
};
#[cfg(any(test, all(windows, feature = "windows-uwp")))]
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, io, sync::Arc};
use url::Url;

pub(crate) const MAX_ADDENDUM: usize = 1024 * 1024;
#[cfg(any(test, all(windows, feature = "windows-uwp")))]
pub(crate) const MAX_SNAPSHOT: usize = MAX_ADDENDUM * 8;
pub(super) use rules::MAX_URL;
pub(super) use rules::checked_url;

pub(super) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid HTTP processing configuration",
    )
}

#[derive(Clone)]
pub(crate) struct PolicyCandidate {
    pub(crate) document: Arc<Document>,
    pub(super) rules: Arc<[Rule]>,
    pub(super) payloads: BTreeMap<String, Arc<Payload>>,
    pub(super) identity: [u8; 32],
    pub(super) origins: Box<[SourceLocation]>,
    pub(super) source_identity: Option<[u8; 32]>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub(crate) enum SourceLocation {
    Local { index: usize },
    Provider { provider: String, index: usize },
}

impl PolicyCandidate {
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }

    pub(crate) fn source_identity(&self) -> Option<[u8; 32]> {
        self.source_identity
    }

    pub(crate) fn origin(&self, index: usize) -> Option<&SourceLocation> {
        self.origins.get(index)
    }

    pub(crate) fn bind_source(mut self: Arc<Self>, identity: [u8; 32]) -> Arc<Self> {
        let candidate = Arc::make_mut(&mut self);
        let mut hash = Sha256::new();
        hash.update(candidate.identity);
        hash.update(identity);
        candidate.identity = hash.finalize().into();
        candidate.source_identity = Some(identity);
        self
    }

    pub(crate) fn bind_ca(
        self: &Arc<Self>,
        material: Option<&CaMaterial>,
    ) -> io::Result<Arc<Policy>> {
        #[cfg(feature = "inbound-http")]
        let mitm = super::mitm::Mitm::compile(self.document.mitm.clone(), material)?;
        #[cfg(not(feature = "inbound-http"))]
        if self.document.mitm.enabled || material.is_some() {
            return Err(invalid());
        }
        let mut hash = Sha256::new();
        hash.update(self.identity);
        #[cfg(feature = "inbound-http")]
        if let Some(mitm) = &mitm {
            hash.update(mitm.identity());
        }
        Ok(Arc::new(Policy {
            identity: hash.finalize().into(),
            document: self.document.clone(),
            candidate: Some(self.clone()),
            #[cfg(feature = "inbound-http")]
            mitm,
        }))
    }

    /// Complete actual content for an internal, protected cross-process
    /// snapshot. CA material is deliberately not representable here.
    #[cfg(any(test, all(windows, feature = "windows-uwp")))]
    pub(crate) fn export_snapshot(&self) -> io::Result<String> {
        #[derive(Serialize)]
        struct Snapshot<'a> {
            document: &'a Document,
            payloads: BTreeMap<&'a str, &'a Payload>,
            source_identity: Option<[u8; 32]>,
        }
        let snapshot = Snapshot {
            document: &self.document,
            payloads: self
                .payloads
                .iter()
                .map(|(name, payload)| (name.as_str(), payload.as_ref()))
                .collect(),
            source_identity: self.source_identity,
        };
        let encoded = serde_yaml_ng::to_string(&snapshot).map_err(|_| invalid())?;
        if encoded.len() > MAX_SNAPSHOT {
            return Err(invalid());
        }
        Ok(encoded)
    }

    #[cfg(any(test, all(windows, feature = "windows-uwp")))]
    pub(crate) fn import_snapshot(input: &str) -> io::Result<Arc<Self>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Snapshot {
            #[serde(deserialize_with = "nonnull")]
            document: Document,
            #[serde(deserialize_with = "nonnull")]
            payloads: BTreeMap<String, Payload>,
            source_identity: Option<[u8; 32]>,
        }
        if input.len() > MAX_SNAPSHOT {
            return Err(invalid());
        }
        super::numeric_input::validate(input.as_bytes())?;
        let value =
            crate::config::yaml::parse_with_budget(input.as_bytes(), &mut (MAX_SNAPSHOT * 4))
                .map_err(|_| invalid())?;
        let mut snapshot: Snapshot = serde_yaml_ng::from_value(value).map_err(|_| invalid())?;
        snapshot.document.input_bytes = serde_yaml_ng::to_string(&snapshot.document)
            .map_err(|_| invalid())?
            .len();
        snapshot.document.finish()?;
        let names: std::collections::BTreeSet<_> = snapshot
            .document
            .active_provider_names()
            .filter(|name| {
                !matches!(
                    snapshot.document.providers[*name],
                    super::providers::ProviderSpec::Inline { .. }
                )
            })
            .map(str::to_owned)
            .collect();
        if snapshot.payloads.keys().any(|name| !names.contains(name)) {
            return Err(invalid());
        }
        for payload in snapshot.payloads.values_mut() {
            payload.finish()?;
        }
        let candidate = Arc::new(snapshot.document).compile(
            &snapshot
                .payloads
                .into_iter()
                .map(|(name, payload)| (name, Arc::new(payload)))
                .collect(),
        )?;
        Ok(if let Some(identity) = snapshot.source_identity {
            candidate.bind_source(identity)
        } else {
            candidate
        })
    }
}

pub(crate) struct Policy {
    identity: [u8; 32],
    document: Arc<Document>,
    candidate: Option<Arc<PolicyCandidate>>,
    #[cfg(feature = "inbound-http")]
    mitm: Option<Arc<super::mitm::Mitm>>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPolicy")
            .field("rules", &self.all_rules().len())
            .field("prepared", &self.is_prepared())
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

impl Policy {
    pub(crate) fn for_evaluation(candidate: Arc<PolicyCandidate>) -> Arc<Self> {
        Arc::new(Self::from_static(
            candidate.document.clone(),
            Some(candidate),
        ))
    }

    pub(crate) fn compile_optional(input: Option<&str>) -> crate::Result<Option<Arc<Self>>> {
        let input = input.filter(|value| !value.is_empty());
        #[cfg(not(feature = "inbound-http"))]
        if input.is_some() {
            return Err(crate::VoleError::InvalidConfig(
                "HTTP processing is not compiled in".into(),
            ));
        }
        input.map(Self::compile).transpose().map_err(|_| {
            crate::VoleError::InvalidConfig("invalid HTTP processing configuration".into())
        })
    }

    pub(crate) fn compile(input: &str) -> io::Result<Arc<Self>> {
        Document::parse(input)?.static_policy()
    }

    pub(super) fn from_static(
        document: Arc<Document>,
        candidate: Option<Arc<PolicyCandidate>>,
    ) -> Self {
        let identity = candidate
            .as_ref()
            .map_or_else(|| document.identity(), |candidate| candidate.identity());
        Self {
            identity,
            document,
            candidate,
            #[cfg(feature = "inbound-http")]
            mitm: None,
        }
    }

    pub(crate) fn document(&self) -> &Arc<Document> {
        &self.document
    }
    pub(crate) fn candidate(&self) -> Option<&Arc<PolicyCandidate>> {
        self.candidate.as_ref()
    }
    pub(crate) fn is_prepared(&self) -> bool {
        self.candidate.is_some()
            && (!self.document.mitm.enabled || {
                #[cfg(feature = "inbound-http")]
                {
                    self.mitm.is_some()
                }
                #[cfg(not(feature = "inbound-http"))]
                {
                    false
                }
            })
    }
    pub(crate) fn plain_port(&self, port: u16) -> bool {
        !self.rules().is_empty() && self.document.http_ports.contains(&port)
    }
    pub(crate) fn rules(&self) -> &[Rule] {
        if self.document.rewrite.enabled {
            self.all_rules()
        } else {
            &[]
        }
    }
    pub(crate) fn all_rules(&self) -> &[Rule] {
        self.candidate
            .as_ref()
            .map_or(&[], |candidate| &candidate.rules)
    }
    #[cfg(feature = "inbound-http")]
    pub(crate) fn body_budget(&self) -> &super::body_budget::Budget {
        static BUDGET: std::sync::LazyLock<super::body_budget::Budget> =
            std::sync::LazyLock::new(super::body_budget::Budget::default);
        &BUDGET
    }
    #[cfg(feature = "inbound-http")]
    pub(super) fn mitm(&self) -> Option<&Arc<super::mitm::Mitm>> {
        self.mitm.as_ref()
    }
    pub(super) fn evaluate(&self, url: Url) -> io::Result<Action> {
        if url.as_str().len() > MAX_URL {
            return Err(invalid());
        }
        for rule in self.rules() {
            if let Some(action) = rule.evaluate_url(&url)? {
                return Ok(match action {
                    UrlAction::Forward(url) => Action::Forward(url),
                    UrlAction::Redirect { status, url } => Action::Redirect { status, url },
                    UrlAction::Reject => Action::Reject,
                });
            }
        }
        Ok(Action::Forward(url))
    }
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
