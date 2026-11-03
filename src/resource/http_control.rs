//! HTTP-rule refresh work owned by the shared runtime application worker.
use crate::http_processing::{
    config::{Document, PolicyCandidate},
    providers::{DownloadContext, SourceContext, Store},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::config_apply::ApplyError;

/// The runtime supplies its protected physical dispatcher and the admitted
/// request's child cancellation token. No separate runtime, task or token can
/// outlive the application worker's Stop barrier.
pub(crate) async fn refresh(
    document: Arc<Document>,
    context: &SourceContext,
    store: &Mutex<Store>,
    network: &DownloadContext,
    cancellation: &CancellationToken,
    force: bool,
) -> Result<Arc<PolicyCandidate>, ApplyError> {
    if cancellation.is_cancelled() {
        return Err(ApplyError::Stopped);
    }
    let mut store = store.try_lock().map_err(|_| ApplyError::Busy)?;
    let candidate = store
        .prepare(document, context, Some(network), cancellation, force)
        .await
        .map_err(|_| {
            if cancellation.is_cancelled() {
                ApplyError::Stopped
            } else {
                ApplyError::PreparationFailed
            }
        })?;
    if cancellation.is_cancelled() {
        Err(ApplyError::Stopped)
    } else {
        Ok(candidate)
    }
}

#[cfg(test)]
#[path = "http_control_tests.rs"]
mod tests;
