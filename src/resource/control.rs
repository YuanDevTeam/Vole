use crate::{
    dns::runtime::RuntimeDns,
    routing::{ProxyGroupError, ProxyGroups},
};
use async_trait::async_trait;
use std::sync::Arc;

/// A query holds its resource generation through completion and output admission.
pub(crate) struct DnsSnapshot {
    pub dns: Arc<RuntimeDns>,
    pub _generation: Option<Arc<dyn Send + Sync>>,
}
#[async_trait]
pub(crate) trait RuntimeResources: Send + Sync {
    fn groups(&self) -> Arc<ProxyGroups>;
    fn select(&self, group: &str, member: &str) -> Result<(), ProxyGroupError>;
    fn providers(&self, rules: bool) -> serde_json::Value;
    fn dns(&self) -> Option<DnsSnapshot>;
    async fn refresh(&self, rules: bool, name: &str) -> Result<(), &'static str>;
}
