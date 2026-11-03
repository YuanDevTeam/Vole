//! SIGHUP uses the existing bounded candidate worker and never reconnects a session.
use super::{
    ControllerOverrides, CoreController, InvokeFailure, failure, input::ReloadInput, lock,
};
use crate::{
    config::providers::ProviderTemplate,
    resource::config_apply::{ConfigApplyHandle, ConfigUpdate},
};
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

pub(super) struct ReloadContext {
    pub(super) input: ReloadInput,
    pub(super) directory: PathBuf,
    pub(super) overrides: Arc<ControllerOverrides>,
}
impl ReloadContext {
    fn handle(controller: &CoreController) -> Result<ConfigApplyHandle, InvokeFailure> {
        let _command = controller.try_command()?;
        let inner = lock(&controller.inner);
        if controller
            .tombstoned
            .load(std::sync::atomic::Ordering::Acquire)
            || inner.lifecycle.state() != crate::LifecycleState::Running
        {
            return Err(failure("foreground runtime is stopped"));
        }
        inner
            .engine
            .as_ref()
            .and_then(|engine| engine.config_apply.clone())
            .ok_or_else(|| failure("runtime does not support configuration application"))
    }
    pub(super) async fn apply(
        &self,
        controller: &CoreController,
        cancellation: &CancellationToken,
    ) -> Result<(), InvokeFailure> {
        let handle = Self::handle(controller)?;
        let admission = handle
            .try_admit()
            .map_err(|error| failure(error.message()))?;
        let source = self.input.clone();
        let directory = self.directory.clone();
        let overrides = self.overrides.clone();
        let preparation_cancel = cancellation.clone();
        let template = tokio::task::spawn_blocking(move || {
            let yaml = source.read(&preparation_cancel)?;
            let mut template = ProviderTemplate::update_yaml(yaml.as_bytes(), &directory)
                .map_err(|_| failure("invalid configuration candidate"))?;
            if preparation_cancel.is_cancelled() {
                return Err(failure("configuration reload cancelled"));
            }
            overrides.apply_template(Arc::make_mut(&mut template));
            Ok(template)
        })
        .await
        .map_err(|_| failure("configuration reload worker failed"))??;
        if cancellation.is_cancelled() {
            return Err(failure("configuration reload cancelled"));
        }
        let pending = admission
            .submit(ConfigUpdate::ReplaceTemplate(template))
            .map_err(|error| failure(error.message()))?;
        let operation = pending.cancellation();
        let waiting = pending.wait();
        tokio::pin!(waiting);
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => { operation.cancel(); waiting.await },
            result = &mut waiting => result,
        };
        result.map_err(|error| failure(error.message()))
    }
}
