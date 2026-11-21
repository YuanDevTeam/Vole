//! Business HTTP policy compiled from shared documents and host-local settings.
#[path = "document.rs"]
mod document;
#[cfg(all(windows, feature = "windows-uwp"))]
pub(crate) use document::nonnull;
pub(crate) use document::{Document, ParameterValue};

#[cfg(feature = "inbound-http")]
use super::mitm;
use super::{
    mitm::Patterns,
    origin::Origin,
    private_context::CaMaterial,
    rules::{self, Rule, StaticResponse, UrlAction},
    script_config::CompiledScript,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
use url::Url;

pub(crate) const MAX_ADDENDUM: usize = 1024 * 1024;
pub(crate) const MAX_DOCUMENTS: usize = 64;
pub(crate) const MAX_PARAMETER_OVERRIDES: usize = 64 * 1024;
pub(super) use rules::MAX_URL;
#[cfg(feature = "inbound-http")]
pub(super) use rules::checked_url;

pub(super) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid HTTP processing configuration",
    )
}

pub(super) fn require_http_adapter() -> io::Result<()> {
    if !cfg!(feature = "inbound-http") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP processing is not compiled in",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct HttpSettings {
    pub(crate) mitm_enabled: bool,
    pub(crate) exclude_domains: Vec<String>,
    pub(crate) rewrite_enabled: bool,
    pub(crate) js_enabled: bool,
    pub(crate) allow_intercept_only: bool,
}

impl Default for HttpSettings {
    fn default() -> Self {
        Self {
            mitm_enabled: false,
            exclude_domains: Vec::new(),
            rewrite_enabled: true,
            js_enabled: true,
            allow_intercept_only: false,
        }
    }
}

/// Host-local installation input. Only the YAML bytes are shared.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct PluginInput {
    pub(crate) id: String,
    pub(crate) yaml: String,
    pub(crate) digest: String,
    #[serde(default)]
    pub(crate) parameters: BTreeMap<String, ParameterValue>,
    #[serde(default)]
    pub(crate) permissions: PluginPermissions,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct PluginPermissions {
    pub(crate) https_origins: Vec<String>,
    pub(crate) js: bool,
    pub(crate) intercept_only: bool,
    pub(crate) upstream_origins: Vec<String>,
}

pub(crate) struct PolicyCandidate {
    pub(crate) document: Arc<Document>,
    pub(super) rules: Arc<[Rule]>,
    pub(crate) scripts: Arc<[CompiledScript]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SourceLocation {
    pub(crate) source: usize,
    pub(crate) target: usize,
    pub(crate) index: usize,
}

struct Effective {
    origins: BTreeSet<Origin>,
    exclusions: Arc<Patterns>,
    #[cfg(feature = "inbound-http")]
    h3_fallback: BTreeSet<Origin>,
}

impl Effective {
    fn requires_ca(&self) -> bool {
        self.origins.iter().any(Origin::is_https)
    }
}

impl PolicyCandidate {
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.document.identity()
    }

    pub(crate) fn origin(&self, index: usize) -> Option<&SourceLocation> {
        self.document.location(index)
    }

    fn effective(&self, settings: &HttpSettings) -> io::Result<Effective> {
        let exclusions = Arc::new(Patterns::compile(&settings.exclude_domains)?);
        let mut origins = BTreeSet::new();
        #[cfg(feature = "inbound-http")]
        let mut h3_fallback = BTreeSet::new();
        for group in self.document.groups.iter() {
            let rewrites = (settings.rewrite_enabled && group.rewrite)
                || (settings.js_enabled && group.scripts);
            if !(rewrites || (settings.allow_intercept_only && group.intercept_only)) {
                continue;
            }
            for origin in group.origins.iter() {
                let https = origin.is_https();
                if https && (!settings.mitm_enabled || exclusions.covers(origin)) {
                    continue;
                }
                #[cfg(feature = "inbound-http")]
                if https && settings.rewrite_enabled && rewrites {
                    h3_fallback.insert(origin.clone());
                }
                origins.insert(origin.clone());
            }
        }
        Ok(Effective {
            origins,
            exclusions,
            #[cfg(feature = "inbound-http")]
            h3_fallback,
        })
    }

    fn active_scripts<'a>(
        &'a self,
        settings: &HttpSettings,
        effective: &'a Effective,
    ) -> impl Iterator<Item = &'a CompiledScript> {
        let enabled = settings.js_enabled;
        self.scripts.iter().filter(move |script| {
            enabled
                && script
                    .selector
                    .scope()
                    .iter()
                    .any(|origin| effective.origins.contains(origin))
        })
    }

    pub(crate) fn requires_ca(&self, settings: &HttpSettings) -> io::Result<bool> {
        Ok(self.effective(settings)?.requires_ca())
    }

    pub(crate) fn prepare_platform(
        &self,
        settings: &HttpSettings,
        cancellation: &CancellationToken,
    ) -> io::Result<()> {
        let effective = self.effective(settings)?;
        let mut scripts = self.active_scripts(settings, &effective).peekable();
        if scripts.peek().is_some() {
            super::scripts::ensure_available()?;
            if cancellation.is_cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if scripts.any(CompiledScript::needs_jsc_for_business) {
                super::scripts::prepare_platform(cancellation)?;
            }
        }
        Ok(())
    }

    pub(crate) fn bind_settings(
        self: &Arc<Self>,
        settings: &HttpSettings,
        material: Option<&CaMaterial>,
    ) -> io::Result<Arc<Policy>> {
        require_http_adapter()?;
        let effective = self.effective(settings)?;
        if self.active_scripts(settings, &effective).next().is_some() {
            super::scripts::ensure_available()?;
        }
        #[cfg(feature = "inbound-http")]
        let mitm = mitm::Mitm::compile(
            effective
                .origins
                .iter()
                .filter(|origin| origin.is_https())
                .cloned(),
            Arc::clone(&effective.exclusions),
            material,
        )?;
        #[cfg(not(feature = "inbound-http"))]
        let _ = material;
        let hash = policy_hash(self.identity(), settings)?;
        #[cfg(feature = "inbound-http")]
        let hash = {
            let mut hash = hash;
            if let Some(mitm) = &mitm {
                hash.update(mitm.identity());
            }
            hash
        };
        Ok(Arc::new(Policy {
            identity: hash.finalize().into(),
            candidate: self.clone(),
            plain_ports: plain_ports(&effective),
            effective: effective.origins.into_iter().collect(),
            exclusions: effective.exclusions,
            #[cfg(feature = "inbound-http")]
            h3_fallback: effective.h3_fallback.into_iter().collect(),
            settings: settings.clone(),
            prepared: true,
            #[cfg(feature = "inbound-http")]
            mitm,
        }))
    }
}

fn policy_hash(identity: [u8; 32], settings: &HttpSettings) -> io::Result<Sha256> {
    let mut hash = Sha256::new();
    hash.update(identity);
    hash.update(serde_json::to_vec(settings).map_err(|_| invalid())?);
    Ok(hash)
}

fn plain_ports(effective: &Effective) -> Box<[u16]> {
    effective
        .origins
        .iter()
        .filter(|origin| !origin.is_https())
        .map(Origin::port)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) struct Policy {
    identity: [u8; 32],
    candidate: Arc<PolicyCandidate>,
    plain_ports: Box<[u16]>,
    effective: Box<[Origin]>,
    exclusions: Arc<Patterns>,
    #[cfg(feature = "inbound-http")]
    h3_fallback: Box<[Origin]>,
    settings: HttpSettings,
    prepared: bool,
    #[cfg(feature = "inbound-http")]
    mitm: Option<Arc<mitm::Mitm>>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPolicy")
            .field("rules", &self.all_rules().len())
            .field("scripts", &self.all_scripts().len())
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
    Respond(Arc<StaticResponse>),
}

impl Policy {
    pub(crate) fn for_evaluation(
        candidate: Arc<PolicyCandidate>,
        settings: &HttpSettings,
    ) -> io::Result<Arc<Self>> {
        let effective = candidate.effective(settings)?;
        let prepared = !effective.requires_ca()
            && candidate
                .active_scripts(settings, &effective)
                .next()
                .is_none();
        Ok(Arc::new(Self {
            identity: policy_hash(candidate.identity(), settings)?
                .finalize()
                .into(),
            candidate,
            plain_ports: plain_ports(&effective),
            effective: effective.origins.into_iter().collect(),
            exclusions: effective.exclusions,
            #[cfg(feature = "inbound-http")]
            h3_fallback: effective.h3_fallback.into_iter().collect(),
            settings: settings.clone(),
            prepared,
            #[cfg(feature = "inbound-http")]
            mitm: None,
        }))
    }

    #[cfg(any(
        test,
        all(
            feature = "inbound-http",
            feature = "http-diagnostics",
            target_os = "tvos"
        )
    ))]
    pub(crate) fn compile(input: &str) -> io::Result<Arc<Self>> {
        Document::parse(input)?.static_policy()
    }

    pub(crate) fn document(&self) -> &Arc<Document> {
        &self.candidate.document
    }
    pub(crate) fn candidate(&self) -> Option<&Arc<PolicyCandidate>> {
        Some(&self.candidate)
    }
    pub(crate) fn settings(&self) -> &HttpSettings {
        &self.settings
    }
    pub(crate) fn is_prepared(&self) -> bool {
        self.prepared
    }
    pub(crate) fn allows_target(&self, url: &Url) -> bool {
        !self.exclusions.excludes_url(url)
            && self.effective.iter().any(|origin| origin.matches_url(url))
    }
    #[cfg(feature = "inbound-http")]
    pub(crate) fn h3_fallback_for_url(&self, url: &Url) -> bool {
        self.h3_fallback
            .iter()
            .any(|origin| origin.matches_url(url))
            && !self.exclusions.excludes_url(url)
    }

    #[cfg(feature = "inbound-http")]
    pub(crate) fn h3_fallback_for_udp(&self, port: u16, server_name: Option<&str>) -> bool {
        // The ClientHello parser supplies a normalized SNI. A candidate port
        // check comes before the bounded QUIC Initial inspection.
        self.mitm.is_some()
            && server_name.is_none_or(|name| !self.exclusions.matches(name))
            && self.h3_fallback.iter().any(|origin| {
                origin.port() == port && server_name.is_none_or(|name| origin.matches_host(name))
            })
    }
    pub(crate) fn plain_port(&self, port: u16) -> bool {
        self.plain_ports.binary_search(&port).is_ok()
    }
    pub(crate) fn rules(&self) -> &[Rule] {
        if self.settings.rewrite_enabled {
            self.all_rules()
        } else {
            &[]
        }
    }
    pub(crate) fn all_rules(&self) -> &[Rule] {
        &self.candidate.rules
    }
    pub(crate) fn scripts(&self) -> &[CompiledScript] {
        if self.settings.js_enabled {
            self.all_scripts()
        } else {
            &[]
        }
    }
    pub(crate) fn all_scripts(&self) -> &[CompiledScript] {
        &self.candidate.scripts
    }
    #[cfg(feature = "inbound-http")]
    pub(crate) fn body_budget(&self) -> &super::body_budget::Budget {
        static BUDGET: std::sync::LazyLock<super::body_budget::Budget> =
            std::sync::LazyLock::new(super::body_budget::Budget::default);
        &BUDGET
    }
    #[cfg(feature = "inbound-http")]
    pub(super) fn mitm(&self) -> Option<&Arc<mitm::Mitm>> {
        self.mitm.as_ref()
    }
    pub(crate) fn request_conditions(&self, headers: rules::HeaderView<'_>) -> u64 {
        self.document().request_conditions(headers)
    }
    pub(crate) fn response_conditions(&self, status: u16, headers: rules::HeaderView<'_>) -> u64 {
        self.document().response_conditions(status, headers)
    }
    #[cfg(test)]
    pub(super) fn evaluate(&self, url: Url, method: &str) -> io::Result<Action> {
        self.evaluate_selected(url, method, 0, true)
    }
    pub(super) fn evaluate_selected(
        &self,
        url: Url,
        method: &str,
        request: u64,
        allow_respond: bool,
    ) -> io::Result<Action> {
        if url.as_str().len() > MAX_URL {
            return Err(invalid());
        }
        for rule in self.rules() {
            if let Some(action) = rule.evaluate_url(
                rules::RequestMatch::from((&url, method)).with_conditions(request, 0),
            )? {
                return Ok(match action {
                    UrlAction::Forward(url) => Action::Forward(url),
                    UrlAction::Redirect { status, url } => Action::Redirect { status, url },
                    UrlAction::Reject => Action::Reject,
                    UrlAction::Respond(response) if allow_respond => Action::Respond(response),
                    UrlAction::Respond(_) => continue,
                });
            }
        }
        Ok(Action::Forward(url))
    }
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
