//! One bounded configuration-application admission, shared by adapters.
use serde::Deserialize;
use std::sync::{Arc, mpsc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc as async_mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(crate) struct ConfigApplyHandle {
    slots: Arc<Semaphore>,
    requests: async_mpsc::Sender<ApplyRequest>,
    cancel: CancellationToken,
}
pub(crate) enum ConfigUpdate {
    RecoverySnapshot(mpsc::SyncSender<Box<crate::runtime::RecoverySnapshot>>),
    Replace(String),
    ReplaceWithHttp {
        yaml: String,
        http: String,
        base_dir: Option<Option<std::path::PathBuf>>,
    },
    Patch(ConfigPatch),
    RefreshGeoData,
    RefreshHttp {
        document: Arc<crate::http_processing::config::Document>,
        context: crate::http_processing::providers::SourceContext,
        store: Arc<tokio::sync::Mutex<crate::http_processing::providers::Store>>,
        force: bool,
        security: Option<crate::security::SecurityContext>,
        reply: Option<mpsc::SyncSender<Arc<crate::http_processing::config::PolicyCandidate>>>,
    },
    FlushFakeIp,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct ConfigPatch {
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub sniffing: Option<bool>,
    pub tcp_concurrent: Option<bool>,
    pub find_process_mode: Option<String>,
    pub interface_name: Option<String>,
}
impl ConfigPatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.log_level.is_none()
            && self.sniffing.is_none()
            && self.tcp_concurrent.is_none()
            && self.find_process_mode.is_none()
            && self.interface_name.is_none()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyError {
    Busy,
    Stopped,
    InvalidConfig,
    RestartRequired,
    PreparationFailed,
    TimedOut,
}
impl ApplyError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Busy => "configuration application is busy",
            Self::Stopped => "runtime stopped",
            Self::InvalidConfig => "invalid configuration candidate",
            Self::RestartRequired => "configuration changes startup resources; reconnect required",
            Self::PreparationFailed => "configuration candidate preparation failed",
            Self::TimedOut => "configuration application timed out",
        }
    }
}
pub(crate) struct ConfigAdmission {
    requests: async_mpsc::Sender<ApplyRequest>,
    _slot: OwnedSemaphorePermit,
    cancel: CancellationToken,
}
pub(crate) struct ApplyRequest {
    update: ConfigUpdate,
    completion: Completion,
    cancellation: CancellationToken,
    _slot: OwnedSemaphorePermit,
}
pub(crate) struct PendingApply {
    asynchronous: Option<oneshot::Receiver<Result<(), ApplyError>>>,
    synchronous: Option<mpsc::Receiver<Result<(), ApplyError>>>,
    cancellation: CancellationToken,
}
struct Completion {
    asynchronous: Option<oneshot::Sender<Result<(), ApplyError>>>,
    synchronous: Option<mpsc::SyncSender<Result<(), ApplyError>>>,
}
impl ConfigApplyHandle {
    pub(crate) fn recovery_snapshot(
        &self,
    ) -> Result<Box<crate::runtime::RecoverySnapshot>, ApplyError> {
        let (send, receive) = mpsc::sync_channel(1);
        self.try_admit()?
            .submit(ConfigUpdate::RecoverySnapshot(send))?
            .wait_blocking()?;
        receive.recv().map_err(|_| ApplyError::Stopped)
    }
    pub(crate) fn channel(cancel: CancellationToken) -> (Self, async_mpsc::Receiver<ApplyRequest>) {
        let (requests, receiver) = async_mpsc::channel(1);
        (
            Self {
                slots: Arc::new(Semaphore::new(1)),
                requests,
                cancel,
            },
            receiver,
        )
    }
    pub(crate) fn try_admit(&self) -> Result<ConfigAdmission, ApplyError> {
        if self.cancel.is_cancelled() {
            return Err(ApplyError::Stopped);
        }
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApplyError::Busy)?;
        Ok(ConfigAdmission {
            requests: self.requests.clone(),
            _slot: slot,
            cancel: self.cancel.clone(),
        })
    }
}
impl ConfigAdmission {
    pub(crate) fn submit(self, update: ConfigUpdate) -> Result<PendingApply, ApplyError> {
        if self.cancel.is_cancelled() {
            return Err(ApplyError::Stopped);
        }
        let (async_send, asynchronous) = oneshot::channel();
        let (sync_send, synchronous) = mpsc::sync_channel(1);
        let cancellation = self.cancel.child_token();
        let request = ApplyRequest {
            update,
            completion: Completion {
                asynchronous: Some(async_send),
                synchronous: Some(sync_send),
            },
            cancellation: cancellation.clone(),
            _slot: self._slot,
        };
        self.requests
            .try_send(request)
            .map_err(|error| match error {
                async_mpsc::error::TrySendError::Full(_) => ApplyError::Busy,
                async_mpsc::error::TrySendError::Closed(_) => ApplyError::Stopped,
            })?;
        Ok(PendingApply {
            asynchronous: Some(asynchronous),
            synchronous: Some(synchronous),
            cancellation,
        })
    }
}
impl ApplyRequest {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub(crate) fn take_update(&mut self) -> ConfigUpdate {
        std::mem::replace(
            &mut self.update,
            ConfigUpdate::Patch(ConfigPatch::default()),
        )
    }
    pub(crate) fn complete(self, result: Result<(), ApplyError>) {
        self.completion.complete(result);
    }
}
impl PendingApply {
    pub(crate) async fn wait(mut self) -> Result<(), ApplyError> {
        match tokio::time::timeout(
            std::time::Duration::from_secs(90),
            self.asynchronous.take().unwrap(),
        )
        .await
        {
            Ok(result) => result.unwrap_or(Err(ApplyError::Stopped)),
            Err(_) => Err(ApplyError::TimedOut),
        }
    }
    pub(crate) fn wait_blocking(mut self) -> Result<(), ApplyError> {
        match self
            .synchronous
            .take()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(90))
        {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ApplyError::Stopped),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ApplyError::TimedOut),
        }
    }
}
impl Drop for PendingApply {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Completion {
    pub(crate) fn complete(mut self, result: Result<(), ApplyError>) {
        if let Some(sender) = self.asynchronous.take() {
            let _ = sender.send(result);
        }
        if let Some(sender) = self.synchronous.take() {
            let _ = sender.try_send(result);
        }
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        if let Some(sender) = self.asynchronous.take() {
            let _ = sender.send(Err(ApplyError::Stopped));
        }
        if let Some(sender) = self.synchronous.take() {
            let _ = sender.try_send(Err(ApplyError::Stopped));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn application_admission_is_single_before_reading_and_survives_caller_cancellation() {
        let cancel = CancellationToken::new();
        let (handle, mut receiver) = ConfigApplyHandle::channel(cancel.clone());
        let admission = handle.try_admit().unwrap();
        assert!(matches!(handle.try_admit(), Err(ApplyError::Busy)));
        let pending = admission
            .submit(ConfigUpdate::Replace("rules: [MATCH,DIRECT]".into()))
            .unwrap();
        drop(pending);
        assert!(matches!(handle.try_admit(), Err(ApplyError::Busy)));
        let request = receiver.recv().await.unwrap();
        assert!(request.cancellation.is_cancelled());
        request.completion.complete(Ok(()));
        drop(request._slot);
        assert!(handle.try_admit().is_ok());
        cancel.cancel();
        assert!(matches!(handle.try_admit(), Err(ApplyError::Stopped)));
    }
    #[tokio::test]
    async fn asynchronous_and_foreign_thread_results_use_the_same_bounded_completion() {
        let (handle, mut receiver) = ConfigApplyHandle::channel(CancellationToken::new());
        let pending = handle
            .try_admit()
            .unwrap()
            .submit(ConfigUpdate::Patch(ConfigPatch::default()))
            .unwrap();
        let request = receiver.recv().await.unwrap();
        request
            .completion
            .complete(Err(ApplyError::RestartRequired));
        assert_eq!(pending.wait().await, Err(ApplyError::RestartRequired));
        drop(request._slot);
        let pending = handle
            .try_admit()
            .unwrap()
            .submit(ConfigUpdate::Patch(ConfigPatch::default()))
            .unwrap();
        let thread = std::thread::spawn(move || pending.wait_blocking());
        drop(receiver.recv().await.unwrap());
        assert_eq!(thread.join().unwrap(), Err(ApplyError::Stopped));
    }
}
