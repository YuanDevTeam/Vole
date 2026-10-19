//! HTTP resource ownership shared by foreground and native Invoke adapters.
use super::{InvokeFailure, InvokePath, lock, registry};
use crate::{
    config::Config,
    dialer::Dialer,
    http_processing::{
        Policy,
        config::{Document, PolicyCandidate},
        private_context::CaMaterial,
        providers::{DownloadContext, SourceContext, Store},
    },
};
use serde::Deserialize;
use std::{io, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;
#[path = "http_test.rs"]
mod evaluation;
pub(super) use evaluation::{TestPayload, evaluate};

pub(super) fn check_envelope(input: &str) -> Result<(), InvokeFailure> {
    use serde_json::value::RawValue;
    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow)]
        method: &'a RawValue,
        #[serde(borrow)]
        payload: &'a RawValue,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Input<'a> {
        #[serde(borrow)]
        config_yaml: Option<&'a RawValue>,
        #[serde(borrow)]
        http_config_yaml: Option<&'a RawValue>,
        #[serde(borrow)]
        http_context: Option<&'a RawValue>,
        #[serde(borrow)]
        request: Option<&'a RawValue>,
        #[serde(borrow)]
        response: Option<&'a RawValue>,
        #[serde(borrow)]
        url: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    struct Context<'a> {
        #[serde(borrow)]
        ca: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Ca<'a> {
        #[serde(borrow)]
        certificate: &'a RawValue,
        #[serde(borrow)]
        private_key: &'a RawValue,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Sample<'a> {
        #[serde(borrow)]
        body_base64: Option<&'a RawValue>,
        #[serde(borrow)]
        headers: Option<&'a RawValue>,
        #[serde(borrow)]
        method: Option<&'a RawValue>,
        #[serde(borrow)]
        status: Option<&'a RawValue>,
    }
    let invalid = |_| InvokeFailure::invalid_request("invalid HTTP input envelope");
    let envelope: Envelope<'_> = serde_json::from_str(input).map_err(invalid)?;
    if envelope.method.get().len() > 256 {
        return Err(InvokeFailure::invalid_request("invalid method"));
    }
    let method: String = serde_json::from_str(envelope.method.get()).map_err(invalid)?;
    if !matches!(
        method.as_str(),
        "start" | "reconnect" | "validateConfig" | "refreshHttpProviders" | "testHttp"
    ) {
        return Ok(());
    }
    if input.len().saturating_sub(envelope.payload.get().len()) > 64 * 1024 {
        return Err(InvokeFailure::invalid_request(
            "HTTP envelope overhead exceeds limit",
        ));
    }
    let input: Input<'_> = serde_json::from_str(envelope.payload.get()).map_err(invalid)?;
    let known: usize = [
        input.config_yaml,
        input.http_config_yaml,
        input.http_context,
        input.request,
        input.response,
        input.url,
    ]
    .into_iter()
    .flatten()
    .map(|raw| raw.get().len())
    .sum();
    if envelope.payload.get().len().saturating_sub(known) > 64 * 1024 {
        return Err(InvokeFailure::invalid_request(
            "HTTP payload overhead exceeds limit",
        ));
    }
    if let Some(raw) = input.url {
        super::check_json_string_limit(raw.get(), crate::http_processing::rules::MAX_URL)?;
    }
    if let Some(raw) = input.config_yaml {
        super::check_json_string_limit(raw.get(), crate::config::MAX_CONFIG_BYTES)?;
    }
    if let Some(raw) = input.http_config_yaml {
        super::check_json_string_limit(raw.get(), crate::http_processing::MAX_ADDENDUM)?;
    }
    if let Some(raw) = input.http_context {
        if raw.get().len()
            > super::MAX_ERROR_BYTES
                + super::MAX_ERROR_BYTES
                + crate::http_processing::private_context::MAX_CA_INPUT
        {
            return Err(InvokeFailure::invalid_request(
                "HTTP context exceeds input limit",
            ));
        }
        let context: Context<'_> = serde_json::from_str(raw.get()).map_err(invalid)?;
        if let Some(raw) = context.ca {
            if !matches!(method.as_str(), "start" | "reconnect") {
                return Err(InvokeFailure::invalid_request(
                    "this operation does not accept CA material",
                ));
            }
            let ca: Ca<'_> = serde_json::from_str(raw.get()).map_err(invalid)?;
            for raw in [ca.certificate, ca.private_key] {
                super::check_json_string_limit(
                    raw.get(),
                    crate::http_processing::private_context::MAX_CA_PEM_BYTES,
                )?;
            }
        }
    }
    for raw in [input.request, input.response].into_iter().flatten() {
        let sample: Sample<'_> = serde_json::from_str(raw.get()).map_err(invalid)?;
        let known: usize = [
            sample.body_base64,
            sample.headers,
            sample.method,
            sample.status,
        ]
        .into_iter()
        .flatten()
        .map(|raw| raw.get().len())
        .sum();
        if raw.get().len().saturating_sub(known) > 4096
            || sample.status.is_some_and(|raw| raw.get().len() > 8)
        {
            return Err(InvokeFailure::invalid_request(
                "HTTP sample overhead exceeds limit",
            ));
        }
        if let Some(raw) = sample.method {
            super::check_json_string_limit(raw.get(), 64)?;
        }
        if let Some(raw) = sample.body_base64 {
            super::check_json_string_limit(
                raw.get(),
                crate::http_processing::body::MAX_BODY.div_ceil(3) * 4,
            )?;
        }
        if sample.headers.is_some_and(|headers| {
            headers.get().len() > 6 * crate::http_processing::headers::MAX_BYTES + 4096
        }) {
            return Err(InvokeFailure::invalid_request(
                "HTTP sample headers exceed input limit",
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct HttpContextInput {
    pub(crate) base_dir: Option<InvokePath>,
    pub(crate) ca: Option<CaMaterial>,
}
impl std::fmt::Debug for HttpContextInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpContextInput").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct StartPayload {
    pub(super) config_yaml: String,
    pub(super) http_config_yaml: Option<String>,
    pub(super) http_context: Option<HttpContextInput>,
    #[serde(skip)]
    pub(super) source_file: Option<PathBuf>,
    #[serde(skip)]
    pub(super) cancellation: Option<CancellationToken>,
}

pub(crate) fn source_context(
    context: Option<HttpContextInput>,
    data_dir: PathBuf,
    config_path: Option<PathBuf>,
) -> io::Result<(SourceContext, Option<CaMaterial>)> {
    let (base_dir, ca) = context.map_or((None, None), |context| {
        (context.base_dir.map(InvokePath::into_path), context.ca)
    });
    if base_dir.as_ref().is_some_and(|path| !path.is_absolute()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP baseDir must be absolute",
        ));
    }
    Ok((
        SourceContext {
            base_dir,
            data_dir: Some(data_dir),
            config_path,
        },
        ca,
    ))
}

pub(crate) fn download_context(config: &Config, dialer: Dialer) -> DownloadContext {
    DownloadContext {
        dispatcher: Arc::new(crate::outbound::ConnectorDispatcher::new(Arc::new(
            crate::outbound::NamedDirectOutbound::new(dialer),
        ))),
        security: crate::security::SecurityContext::load(&config.tls),
    }
}

pub(crate) async fn prepare_candidate(
    input: &str,
    context: SourceContext,
    download: Option<&DownloadContext>,
    store: &tokio::sync::Mutex<Store>,
    force: bool,
) -> io::Result<Arc<PolicyCandidate>> {
    prepare_cancelled(
        input,
        context,
        download,
        store,
        force,
        &CancellationToken::new(),
    )
    .await
}

async fn prepare_cancelled(
    input: &str,
    context: SourceContext,
    download: Option<&DownloadContext>,
    store: &tokio::sync::Mutex<Store>,
    force: bool,
    cancellation: &CancellationToken,
) -> io::Result<Arc<PolicyCandidate>> {
    let document = Document::parse(input)?;
    let mut store = store.try_lock().map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "HTTP resource preparation is busy",
        )
    })?;
    let operation_cancel = cancellation.child_token();
    let preparation = store.prepare(document, &context, download, &operation_cancel, force);
    tokio::pin!(preparation);
    tokio::select! { biased;
        () = cancellation.cancelled() => {
            operation_cancel.cancel(); let _ = preparation.await;
            Err(io::ErrorKind::Interrupted.into())
        },
        () = tokio::time::sleep(std::time::Duration::from_secs(90)) => {
            operation_cancel.cancel(); let _ = preparation.await;
            Err(io::ErrorKind::TimedOut.into())
        },
        result = &mut preparation => result,
    }
}

pub(super) fn runtime_store() -> Result<Arc<tokio::sync::Mutex<Store>>, InvokeFailure> {
    lock(&registry().runtime_data)
        .as_ref()
        .map(|data| data.http.clone())
        .ok_or_else(|| {
            InvokeFailure::invalid_state("call initialize before preparing HTTP resources")
        })
}

pub(super) async fn attach(
    config: &mut Config,
    input: Option<&str>,
    context: Option<HttpContextInput>,
    config_path: Option<PathBuf>,
    cancellation: Option<&CancellationToken>,
) -> Result<(), InvokeFailure> {
    let Some(input) = input else {
        if context.is_some() {
            return Err(InvokeFailure::invalid_request(
                "httpContext requires httpConfigYaml",
            ));
        }
        config.set_http_policy(None).map_err(InvokeFailure::from)?;
        return Ok(());
    };
    if input.is_empty() {
        config.set_http_policy(None).map_err(InvokeFailure::from)?;
        return Ok(());
    }
    let directory = registry().data_directory()?;
    let (source, ca) = source_context(context, directory.root().to_owned(), config_path)
        .map_err(InvokeFailure::from)?;
    let dialer = {
        let platform = lock(&registry().platform);
        #[cfg(target_os = "android")]
        let dialer = platform
            .android_protector
            .clone()
            .map_or_else(Dialer::default, |protector| {
                Dialer::default().with_protector(protector)
            });
        #[cfg(not(target_os = "android"))]
        let dialer = {
            let _ = &platform;
            Dialer::default()
        };
        dialer.with_dns_sources(registry().dns_sources()?)
    };
    let network = download_context(config, dialer);
    let store = runtime_store()?;
    let token = cancellation.cloned().unwrap_or_default();
    let candidate = prepare_cancelled(input, source, Some(&network), store.as_ref(), false, &token)
        .await
        .map_err(|_| InvokeFailure::new("HTTP resource preparation failed"))?;
    let policy = candidate
        .bind_ca(ca.as_ref())
        .map_err(|_| InvokeFailure::new("HTTP private context is invalid or missing"))?;
    config
        .set_http_policy(Some(policy))
        .map_err(InvokeFailure::from)
}

pub(super) fn parse_reconnect(
    payload: StartPayload,
    apply: &crate::resource::config_apply::ConfigApplyHandle,
) -> Result<Config, InvokeFailure> {
    let mut config = super::parse_config_yaml(&payload.config_yaml)?;
    let Some(input) = payload.http_config_yaml.as_deref() else {
        if payload.http_context.is_some() {
            return Err(InvokeFailure::invalid_request(
                "httpContext requires httpConfigYaml",
            ));
        }
        return Ok(config);
    };
    let directory = registry().data_directory()?;
    let (context, ca) = source_context(
        payload.http_context,
        directory.root().to_owned(),
        payload.source_file,
    )
    .map_err(InvokeFailure::from)?;
    if input.is_empty() {
        return Ok(config);
    }
    // The old engine still owns the physical-network protection and Stop
    // barrier. Preparation must finish there before we stop that engine.
    let admission = apply
        .try_admit()
        .map_err(|error| InvokeFailure::new(error.message()))?;
    let document = Document::parse(input)
        .map_err(|_| InvokeFailure::new("invalid HTTP processing configuration"))?;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    admission
        .submit(crate::resource::config_apply::ConfigUpdate::RefreshHttp {
            document,
            context,
            store: runtime_store()?,
            force: false,
            security: Some(crate::security::SecurityContext::load(&config.tls)),
            reply: Some(send),
        })
        .map_err(|error| InvokeFailure::new(error.message()))?
        .wait_blocking()
        .map_err(|error| InvokeFailure::new(error.message()))?;
    let candidate = receive
        .try_recv()
        .map_err(|_| InvokeFailure::new("HTTP resource preparation did not return a candidate"))?;
    let policy = candidate
        .bind_ca(ca.as_ref())
        .map_err(|_| InvokeFailure::new("HTTP private context is invalid or missing"))?;
    config
        .set_http_policy(Some(policy))
        .map_err(InvokeFailure::from)?;
    Ok(config)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ResourcePayload {
    http_config_yaml: String,
    http_context: Option<HttpContextInput>,
}

enum RefreshAdmission<'a> {
    Instance(Arc<super::CoreController>),
    Idle(IdleRefreshLease<'a>),
}
struct IdleRefreshLease<'a>(&'a super::RuntimeRegistry);
impl Drop for IdleRefreshLease<'_> {
    fn drop(&mut self) {
        lock(&self.0.inner).idle_http_refresh = false;
    }
}
fn admit_refresh(registry: &super::RuntimeRegistry) -> Result<RefreshAdmission<'_>, InvokeFailure> {
    let mut inner = lock(&registry.inner);
    if inner.idle_http_refresh {
        return Err(InvokeFailure::invalid_state(
            "HTTP resource preparation is busy",
        ));
    }
    if let Some(controller) = &inner.instance {
        return Ok(RefreshAdmission::Instance(controller.clone()));
    }
    // Creation and idle preparation share this registry admission. Do not
    // hold the registry lock across filesystem or network work.
    inner.idle_http_refresh = true;
    Ok(RefreshAdmission::Idle(IdleRefreshLease(registry)))
}

pub(super) fn refresh(payload: ResourcePayload) -> Result<serde_json::Value, InvokeFailure> {
    match admit_refresh(registry())? {
        RefreshAdmission::Instance(controller) => {
            super::invoke_instance_guarded(&controller, || {
                let _command = controller.try_command()?;
                refresh_owned(payload, Some(&controller))
            })
        }
        RefreshAdmission::Idle(_lease) => refresh_owned(payload, None),
    }
}

fn refresh_owned(
    payload: ResourcePayload,
    controller: Option<&super::CoreController>,
) -> Result<serde_json::Value, InvokeFailure> {
    let directory = registry().data_directory()?;
    let (context, ca) = source_context(payload.http_context, directory.root().to_owned(), None)
        .map_err(InvokeFailure::from)?;
    if ca.is_some() {
        return Err(InvokeFailure::invalid_request(
            "this operation does not accept CA material",
        ));
    }
    if let Some(controller) = controller {
        let apply = {
            let mut inner = lock(&controller.inner);
            super::refresh_runtime_status(&mut inner);
            if inner.lifecycle.state() == crate::LifecycleState::Running {
                Some(
                    inner
                        .engine
                        .as_ref()
                        .and_then(|engine| engine.config_apply.clone())
                        .ok_or_else(|| {
                            InvokeFailure::invalid_state("runtime cannot refresh HTTP resources")
                        })?,
                )
            } else if inner.lifecycle.state() == crate::LifecycleState::Stopped {
                None
            } else {
                return Err(InvokeFailure::invalid_state(
                    "HTTP resources cannot refresh during a lifecycle transition",
                ));
            }
        };
        if let Some(apply) = apply {
            let admission = apply
                .try_admit()
                .map_err(|error| InvokeFailure::new(error.message()))?;
            let document = Document::parse(&payload.http_config_yaml)
                .map_err(|_| InvokeFailure::new("invalid HTTP processing configuration"))?;
            admission
                .submit(crate::resource::config_apply::ConfigUpdate::RefreshHttp {
                    document,
                    context,
                    store: runtime_store()?,
                    force: true,
                    security: None,
                    reply: None,
                })
                .map_err(|error| InvokeFailure::new(error.message()))?
                .wait_blocking()
                .map_err(|error| InvokeFailure::new(error.message()))?;
            return Ok(serde_json::json!({"resourcesReady": true, "applied": false}));
        }
    }
    #[cfg(all(windows, feature = "windows-uwp"))]
    return Err(InvokeFailure::invalid_state(
        "HTTP resource refresh requires a bound Session Host",
    ));
    #[cfg(not(all(windows, feature = "windows-uwp")))]
    refresh_idle(payload.http_config_yaml, context)
}

#[cfg(not(all(windows, feature = "windows-uwp")))]
fn refresh_idle(input: String, context: SourceContext) -> Result<serde_json::Value, InvokeFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(InvokeFailure::from)?;
    let config = super::parse_config_yaml("rules: ['MATCH,DIRECT']")?;
    #[cfg(target_os = "android")]
    let dialer = lock(&registry().platform)
        .android_protector
        .clone()
        .map_or_else(Dialer::default, |protector| {
            Dialer::default().with_protector(protector)
        });
    #[cfg(not(target_os = "android"))]
    let dialer = Dialer::default();
    let network = download_context(&config, dialer.with_dns_sources(registry().dns_sources()?));
    let store = runtime_store()?;
    let result = runtime.block_on(prepare_candidate(
        &input,
        context,
        Some(&network),
        store.as_ref(),
        true,
    ));
    runtime.shutdown_timeout(std::time::Duration::from_millis(100));
    let _candidate = result.map_err(|_| InvokeFailure::new("HTTP resource preparation failed"))?;
    Ok(serde_json::json!({"resourcesReady": true, "applied": false}))
}

pub(crate) async fn maintenance(
    store: Arc<tokio::sync::Mutex<Store>>,
    network: DownloadContext,
    cancellation: CancellationToken,
) -> io::Result<()> {
    loop {
        let (due, notification) = match store.try_lock() {
            Ok(store) => (store.next_due(), store.notification()),
            Err(_) => {
                tokio::select! { biased;
                    () = cancellation.cancelled() => return Ok(()),
                    () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                }
                continue;
            }
        };
        // No polling timer when there is no scheduled HTTP source. A bounded
        // notification also notices explicit preparation of a new document.
        tokio::select! { biased;
            () = cancellation.cancelled() => return Ok(()),
            () = notification.notified() => continue,
            () = async { match due { Some(delay) => tokio::time::sleep(delay).await, None => std::future::pending().await } } => {}
        }
        let Ok(mut store) = store.try_lock() else {
            continue;
        };
        if store.next_due().is_some_and(|due| due.is_zero()) {
            // Failed updates keep the last complete candidate; the store owns
            // retry backoff. Awaiting this work preserves the Stop barrier.
            let _ = store.refresh_due(&network, &cancellation).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_refresh_admission_blocks_instance_creation_until_release() {
        let registry = super::super::RuntimeRegistry::default();
        let admission = admit_refresh(&registry).unwrap();
        assert!(matches!(&admission, RefreshAdmission::Idle(_)));
        assert!(registry.create_instance().is_err());
        assert!(admit_refresh(&registry).is_err());
        drop(admission);
        let controller = registry.create_instance().unwrap();
        let RefreshAdmission::Instance(admitted) = admit_refresh(&registry).unwrap() else {
            panic!("existing instance owns resource preparation");
        };
        assert!(Arc::ptr_eq(&controller, &admitted));
    }

    #[test]
    fn private_material_is_bounded_before_value_deserialization() {
        let oversized = serde_json::json!({
            "method":"start", "instanceId":"1", "payload":{
                "configYaml":"rules: ['MATCH,DIRECT']", "httpContext":{"ca":{
                    "certificate":"public", "privateKey":"x".repeat(crate::http_processing::private_context::MAX_CA_PEM_BYTES + 1)
                }}
            }
        }).to_string();
        assert!(check_envelope(&oversized).is_err());
        let validation = r#"{"method":"validateConfig","payload":{"configYaml":"","httpContext":{"ca":{"certificate":"public","privateKey":"secret"}}}}"#;
        assert!(check_envelope(validation).is_err());
    }
}
