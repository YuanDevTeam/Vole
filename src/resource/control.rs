use crate::{
    dns::runtime::RuntimeDns,
    routing::{ProxyGroupError, ProxyGroups},
};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(crate) struct DelayRequest {
    pub url: String,
    pub timeout: Duration,
    pub expected: Vec<(u16, u16)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeError {
    NotFound,
    Timeout,
    Failed,
    Stopped,
}

/// A query holds its resource generation through completion and output admission.
pub(crate) struct DnsSnapshot {
    pub dns: Arc<RuntimeDns>,
    pub _generation: Option<Arc<dyn Send + Sync>>,
}
#[async_trait]
pub(crate) trait RuntimeResources: Send + Sync {
    fn connections(&self) -> Arc<crate::connections::Registry>;
    fn configs(&self) -> serde_json::Value;
    fn rules(&self) -> serde_json::Value;
    fn groups(&self) -> Arc<ProxyGroups>;
    fn select(&self, group: &str, member: &str) -> Result<(), ProxyGroupError>;
    fn clear_fixed(&self, _group: &str) -> Result<(), ProxyGroupError> {
        Err(ProxyGroupError::NotSelectable)
    }
    fn health(&self) -> serde_json::Value;
    fn providers(&self, rules: bool) -> serde_json::Value;
    fn dns(&self) -> Option<DnsSnapshot>;
    async fn refresh(&self, rules: bool, name: &str) -> Result<(), &'static str>;
    async fn node_delay(
        &self,
        _name: &str,
        _request: &DelayRequest,
        _cancel: &CancellationToken,
    ) -> Result<u64, ProbeError> {
        Err(ProbeError::NotFound)
    }
    async fn group_delay(
        &self,
        _name: &str,
        _request: &DelayRequest,
        _cancel: &CancellationToken,
    ) -> Result<std::collections::BTreeMap<String, u64>, ProbeError> {
        Err(ProbeError::NotFound)
    }
    async fn provider_healthcheck(
        &self,
        _name: &str,
        _cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        Err(ProbeError::NotFound)
    }
}
