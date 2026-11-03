//! Shared JSON Invoke dispatcher for CLI, C ABI, JNI and platform hosts.
//! One runtime-local registry owns lifecycle and configuration operations.

#![cfg_attr(target_os = "android", allow(clippy::missing_const_for_thread_local))]

use std::{
    cell::Cell,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    str,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, TryLockError,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::SyncSender,
    },
    thread,
    time::Duration,
};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::{
    BUILD_IDENTITY, ENGINE, Lifecycle, LifecycleState, ResourceLimits, VoleError,
    config::Config,
    data_dir::DataDirectory,
    dialer::{Dialer, SocketProtector, SystemResolver},
    geodata::{GeoDataManager, GeoDataStatus, GeoResourceState},
    resource::config_apply::{ConfigApplyHandle, ConfigUpdate},
    runtime::PreparedCore,
};

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "macos",
    target_os = "linux"
))]
use crate::{
    TunFraming,
    platform::{TunFd, TunIo},
};

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "macos",
    target_os = "linux"
))]
type InvokeTun = (TunFd, TunFraming, u16);
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "macos",
    target_os = "linux"
)))]
type InvokeTun = ();

mod foreground;
pub(crate) mod http;
mod measure_delay;
pub use foreground::InvokePath;

// Five YAML documents, worst-case JSON escaping, and a bounded envelope.
pub(crate) const MAX_INVOKE_BYTES: usize = 30 * crate::config::MAX_CONFIG_BYTES + 64 * 1024;
const MAX_ERROR_BYTES: usize = 4096;
static REGISTRY: OnceLock<RuntimeRegistry> = OnceLock::new();

thread_local! {
    static IS_RUNTIME_THREAD: Cell<bool> = const { Cell::new(false) };
}

#[derive(Default)]
struct RegistryInner {
    instance: Option<Arc<CoreController>>,
    idle_http_refresh: bool,
}

#[derive(Default)]
struct PlatformState {
    tun_owner: Option<u64>,
    #[cfg(target_os = "android")]
    android_protector: Option<Arc<dyn SocketProtector>>,
}

struct RuntimeRegistry {
    inner: Mutex<RegistryInner>,
    platform: Mutex<PlatformState>,
    runtime_data: Mutex<Option<RuntimeData>>,
    next_id: AtomicU64,
}

struct RuntimeData {
    directory: Arc<DataDirectory>,
    geodata: Arc<GeoDataManager>,
    dns_sources: Arc<crate::dns::source::NetworkSources>,
    http: Arc<tokio::sync::Mutex<crate::http_processing::providers::Store>>,
    provider_paths: Arc<crate::resource::paths::ProviderPaths>,
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RegistryInner::default()),
            platform: Mutex::new(PlatformState::default()),
            runtime_data: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }
}

struct CoreController {
    id: u64,
    tombstoned: AtomicBool,
    /// Held for the complete duration of every instance method. Contending
    /// calls fail fast rather than waiting behind a lifecycle operation.
    command: Mutex<()>,
    inner: Mutex<CoreInner>,
}

impl CoreController {
    fn new(id: u64) -> Self {
        Self {
            id,
            tombstoned: AtomicBool::new(false),
            command: Mutex::new(()),
            inner: Mutex::new(CoreInner::default()),
        }
    }
}

enum StartupConfig {
    #[cfg(test)]
    Yaml(String),
    Input(Box<http::StartPayload>),
    Resolved(Box<crate::runtime::RecoverySnapshot>),
}

#[derive(Default)]
struct CoreInner {
    lifecycle: Lifecycle,
    prepared: Option<PreparedState>,
    engine: Option<Engine>,
    last_error: String,
    tun_lease: Option<TunLease>,
    tun_allocator_relief: Option<TunAllocatorRelief>,
}

struct PreparedState {
    core: PreparedCore,
    protector: Option<Arc<dyn SocketProtector>>,
}

struct Engine {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
    completion: tokio::sync::watch::Receiver<bool>,
    config_apply: Option<ConfigApplyHandle>,
}

struct EngineCompletion(tokio::sync::watch::Sender<bool>);
impl Drop for EngineCompletion {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

struct PlatformAcquisition {
    tun_lease: Option<TunLease>,
    protector: Option<Arc<dyn SocketProtector>>,
}

struct TunLease {
    owner: u64,
}

impl Drop for TunLease {
    fn drop(&mut self) {
        registry().release_tun(self.owner);
    }
}

#[derive(Clone)]
struct TunAllocatorRelief {
    state: Arc<TunAllocatorReliefState>,
}

struct TunAllocatorReliefState {
    relieved: AtomicBool,
}

impl TunAllocatorRelief {
    fn new(has_tun: bool) -> Option<Self> {
        if has_tun {
            Some(Self {
                state: Arc::new(TunAllocatorReliefState {
                    relieved: AtomicBool::new(false),
                }),
            })
        } else {
            None
        }
    }

    fn relieve(&self) {
        self.state.relieve_with(relieve_tun_allocator);
    }
}

impl TunAllocatorReliefState {
    fn relieve_with(&self, relief: impl FnOnce()) {
        if !self.relieved.swap(true, Ordering::AcqRel) {
            relief();
        }
    }
}

impl Drop for TunAllocatorReliefState {
    fn drop(&mut self) {
        self.relieve_with(relieve_tun_allocator);
    }
}

/// Makes an admitted destroy request a terminal registry barrier even when
/// synchronous stop reports an error or unwinds. Per-instance busy rejection
/// happens before this guard is created and therefore keeps the instance live.
struct InstanceRemovalGuard<'a> {
    controller: &'a Arc<CoreController>,
}

impl Drop for InstanceRemovalGuard<'_> {
    fn drop(&mut self) {
        self.controller.tombstoned.store(true, Ordering::Release);
        registry().remove_instance(self.controller);
    }
}

pub(crate) struct RuntimeThreadGuard;

impl RuntimeThreadGuard {
    pub(crate) fn enter() -> Self {
        IS_RUNTIME_THREAD.with(|marker| {
            // Admission state must also be set when debug assertions are disabled.
            let was_runtime_thread = marker.replace(true);
            debug_assert!(!was_runtime_thread);
        });
        Self
    }
}

impl Drop for RuntimeThreadGuard {
    fn drop(&mut self) {
        IS_RUNTIME_THREAD.with(|marker| marker.set(false));
    }
}

// Logging is restored before Invoke admission is released on worker exit.
struct RuntimeWorkerScope {
    _logging: tracing::dispatcher::DefaultGuard,
    _admission: RuntimeThreadGuard,
}

impl RuntimeWorkerScope {
    fn enter(dispatch: &tracing::Dispatch) -> Self {
        let admission = RuntimeThreadGuard::enter();
        Self {
            _logging: tracing::dispatcher::set_default(dispatch),
            _admission: admission,
        }
    }
}

thread_local! {
    static RUNTIME_WORKER_SCOPE: std::cell::RefCell<Option<RuntimeWorkerScope>> =
        const { std::cell::RefCell::new(None) };
}

pub(crate) fn engine_runtime_builder() -> tokio::runtime::Builder {
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .on_thread_start(move || {
            RUNTIME_WORKER_SCOPE.with(|scope| {
                *scope.borrow_mut() = Some(RuntimeWorkerScope::enter(&dispatch));
            });
        })
        .on_thread_stop(|| {
            let scope = RUNTIME_WORKER_SCOPE.with(|scope| scope.borrow_mut().take());
            drop(scope);
        });
    builder
}

impl Engine {
    fn stop(&mut self) -> Result<(), InvokeFailure> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(result) => result.map_err(InvokeFailure::from),
            Err(_) => Err(InvokeFailure::internal("Vole runtime thread panicked")),
        }
    }

    fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // This is also the unwind safety net for a panic after the runtime was
        // spawned but before it was committed into its instance.
        let _ = self.stop();
    }
}

#[derive(Debug)]
pub(crate) struct InvokeFailure {
    pub(crate) message: String,
}

impl InvokeFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: bounded_error(message.into()),
        }
    }

    pub(crate) fn invalid_request(message: impl std::fmt::Display) -> Self {
        Self::new(format!("invalid request: {message}"))
    }

    fn invalid_state(message: impl std::fmt::Display) -> Self {
        Self::new(format!("invalid state: {message}"))
    }

    fn internal(message: impl std::fmt::Display) -> Self {
        Self::new(format!("internal error: {message}"))
    }
}

impl From<VoleError> for InvokeFailure {
    fn from(value: VoleError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<io::Error> for InvokeFailure {
    fn from(value: io::Error) -> Self {
        Self::new(value.to_string())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    method: String,
    payload: Value,
    #[serde(
        rename = "instanceId",
        default,
        deserialize_with = "deserialize_present_instance_id"
    )]
    instance_id: Option<String>,
}

fn deserialize_present_instance_id<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConfigYamlPayload {
    config_yaml: String,
    #[serde(default)]
    http_config_yaml: Option<String>,
    #[serde(default)]
    http_context: Option<http::HttpContextInput>,
}
impl std::fmt::Debug for ConfigYamlPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigYamlPayload")
            .field("config_bytes", &self.config_yaml.len())
            .field(
                "http_config_bytes",
                &self.http_config_yaml.as_ref().map(String::len),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InitializePayload {
    data_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

#[derive(Debug, serde::Serialize)]
pub(crate) struct InvokeResponse {
    success: bool,
    data: Value,
    error: String,
}

impl InvokeResponse {
    fn success(data: Value) -> Self {
        Self {
            success: true,
            data,
            error: String::new(),
        }
    }

    pub(crate) fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Value::Null,
            error: bounded_error(error.into()),
        }
    }
}

fn registry() -> &'static RuntimeRegistry {
    REGISTRY.get_or_init(RuntimeRegistry::default)
}

impl RuntimeRegistry {
    fn initialize_data_directory(
        &self,
        raw_path: &str,
    ) -> Result<Arc<DataDirectory>, InvokeFailure> {
        if raw_path.is_empty() {
            return Err(InvokeFailure::invalid_request("dataDir is empty"));
        }
        self.initialize_path(Path::new(raw_path))
    }

    fn initialize_path(&self, path: &Path) -> Result<Arc<DataDirectory>, InvokeFailure> {
        self.initialize_path_with_provider_paths(path, None)
    }
    fn initialize_path_with_provider_paths(
        &self,
        path: &Path,
        provider_paths: Option<Arc<crate::resource::paths::ProviderPaths>>,
    ) -> Result<Arc<DataDirectory>, InvokeFailure> {
        let initialized = Arc::new(DataDirectory::initialize(path).map_err(|error| {
            InvokeFailure::new(format!("failed to initialize dataDir: {error}"))
        })?);
        let geodata =
            GeoDataManager::open(initialized.geodata(), Duration::from_secs(24 * 60 * 60))
                .map_err(|error| {
                    InvokeFailure::new(format!("failed to initialize GeoData storage: {error}"))
                })?;
        let mut current = lock(&self.runtime_data);
        if let Some(current) = current.as_ref() {
            if current.directory.root() == initialized.root() {
                if provider_paths
                    .as_ref()
                    .is_some_and(|next| next.as_ref() != current.provider_paths.as_ref())
                {
                    return Err(InvokeFailure::invalid_state(
                        "provider path authorization is already initialized differently",
                    ));
                }
                return Ok(current.directory.clone());
            }
            return Err(InvokeFailure::invalid_state(
                "Vole dataDir is already initialized to a different path",
            ));
        }
        *current = Some(RuntimeData {
            directory: initialized.clone(),
            provider_paths: provider_paths.unwrap_or_default(),
            geodata,
            dns_sources: Arc::new(crate::dns::source::NetworkSources::default()),
            http: Arc::new(tokio::sync::Mutex::new(
                crate::http_processing::providers::Store::new(),
            )),
        });
        Ok(initialized)
    }

    fn provider_paths(&self) -> Option<Arc<crate::resource::paths::ProviderPaths>> {
        lock(&self.runtime_data)
            .as_ref()
            .map(|data| data.provider_paths.clone())
    }
    fn data_directory(&self) -> Result<Arc<DataDirectory>, InvokeFailure> {
        lock(&self.runtime_data)
            .as_ref()
            .map(|data| data.directory.clone())
            .ok_or_else(|| {
                InvokeFailure::invalid_state(
                    "Vole dataDir is not initialized; call initialize before configuration methods",
                )
            })
    }

    fn geodata_manager(&self) -> Result<Arc<GeoDataManager>, InvokeFailure> {
        lock(&self.runtime_data)
            .as_ref()
            .map(|data| data.geodata.clone())
            .ok_or_else(|| {
                InvokeFailure::invalid_state(
                    "Vole dataDir is not initialized; call initialize before configuration methods",
                )
            })
    }

    fn dns_sources(&self) -> Result<Arc<crate::dns::source::NetworkSources>, InvokeFailure> {
        lock(&self.runtime_data)
            .as_ref()
            .map(|data| data.dns_sources.clone())
            .ok_or_else(|| InvokeFailure::invalid_state("Vole dataDir is not initialized"))
    }
    fn create_instance(&self) -> Result<Arc<CoreController>, InvokeFailure> {
        let mut inner = lock(&self.inner);
        if inner.idle_http_refresh {
            return Err(InvokeFailure::invalid_state(
                "HTTP resource preparation is busy",
            ));
        }
        if inner.instance.is_some() {
            return Err(InvokeFailure::invalid_state(
                "a public lifecycle instance already exists; destroy it before creating another",
            ));
        }
        let id = self
            .next_id
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| InvokeFailure::internal("instance ID space is exhausted"))?;
        debug_assert_ne!(id, 0);
        let controller = Arc::new(CoreController::new(id));
        inner.instance = Some(controller.clone());
        Ok(controller)
    }

    fn instance(&self, raw_id: &str) -> Result<Arc<CoreController>, InvokeFailure> {
        let id = parse_instance_id(raw_id)?;
        let inner = lock(&self.inner);
        let controller = inner
            .instance
            .as_ref()
            .filter(|controller| controller.id == id)
            .ok_or_else(|| InvokeFailure::invalid_request("unknown instanceId"))?;
        if controller.tombstoned.load(Ordering::Acquire) {
            return Err(InvokeFailure::invalid_request("unknown instanceId"));
        }
        Ok(controller.clone())
    }

    fn remove_instance(&self, controller: &Arc<CoreController>) {
        let mut inner = lock(&self.inner);
        if inner
            .instance
            .as_ref()
            .is_some_and(|registered| Arc::ptr_eq(registered, controller))
        {
            inner.instance = None;
        }
    }

    fn acquire_platform_resources(
        &self,
        owner: u64,
        has_tun: bool,
    ) -> Result<PlatformAcquisition, InvokeFailure> {
        let mut platform = lock(&self.platform);
        if has_tun && platform.tun_owner.is_some() {
            return Err(InvokeFailure::invalid_state(
                "the public TUN lifecycle is already prepared or running",
            ));
        }
        #[cfg(target_os = "android")]
        let protector = select_android_protector(has_tun, platform.android_protector.as_ref())?;
        #[cfg(not(target_os = "android"))]
        let protector = None;
        let tun_lease = has_tun.then(|| {
            platform.tun_owner = Some(owner);
            TunLease { owner }
        });
        Ok(PlatformAcquisition {
            tun_lease,
            protector,
        })
    }

    fn release_tun(&self, owner: u64) {
        let mut platform = lock(&self.platform);
        if platform.tun_owner == Some(owner) {
            platform.tun_owner = None;
        }
    }

    #[cfg(target_os = "android")]
    fn replace_android_socket_protector(
        &self,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<(), String> {
        let mut platform = lock(&self.platform);
        ensure_android_protector_replaceable(platform.tun_owner)?;
        platform.android_protector = protector;
        Ok(())
    }
}

#[cfg(any(target_os = "android", test))]
fn ensure_android_protector_replaceable(tun_owner: Option<u64>) -> Result<(), String> {
    if tun_owner.is_some() {
        return Err(
            "Android protector can only be replaced while the public TUN lifecycle is inactive"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(any(target_os = "android", test))]
fn select_android_protector(
    has_tun: bool,
    registered: Option<&Arc<dyn SocketProtector>>,
) -> Result<Option<Arc<dyn SocketProtector>>, InvokeFailure> {
    if !has_tun {
        return Ok(None);
    }
    registered.cloned().map(Some).ok_or_else(|| {
        InvokeFailure::new(
            "platform operation failed: Android protector is required for a TUN configuration",
        )
    })
}

fn parse_instance_id(raw_id: &str) -> Result<u64, InvokeFailure> {
    let id = raw_id
        .parse::<u64>()
        .map_err(|_| InvokeFailure::invalid_request("instanceId must be a decimal u64 string"))?;
    if id == 0 || id.to_string() != raw_id {
        return Err(InvokeFailure::invalid_request(
            "instanceId must be a canonical non-zero decimal u64 string",
        ));
    }
    Ok(id)
}

/// Executes a bounded JSON request through the shared runtime controller.
pub fn invoke_bytes(request: &[u8]) -> Vec<u8> {
    if is_runtime_thread() {
        return runtime_thread_response();
    }
    invoke_bytes_admitted(request)
}

/// Executes an owned JSON request through the same dispatcher. The CLI uses
/// this to clear and release serialized configuration/key text before a long
/// foreground session; borrowed FFI callers retain ownership of their input.
pub fn invoke_owned_bytes(request: Vec<u8>) -> Vec<u8> {
    let request = zeroize::Zeroizing::new(request);
    if is_runtime_thread() {
        return runtime_thread_response();
    }
    #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "macos"))]
    let _logging = crate::platform::apple_logging::enter();
    invoke_guarded(move || {
        let decoded = decode_request(&request)?;
        drop(request);
        dispatch_request(decoded)
    })
}

/// Shared byte-oriented dispatcher used by C and Android JNI.
/// It intentionally returns bytes so JNI never routes arbitrary JSON through
/// Modified UTF-8 strings.
pub(crate) fn invoke_bytes_admitted(request: &[u8]) -> Vec<u8> {
    #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "macos"))]
    let _logging = crate::platform::apple_logging::enter();
    invoke_guarded(|| dispatch_bytes(request))
}

pub(crate) fn is_runtime_thread() -> bool {
    IS_RUNTIME_THREAD.with(Cell::get)
}

pub(crate) fn runtime_thread_response() -> Vec<u8> {
    br#"{"success":false,"data":null,"error":"Invoke cannot be called from the Vole runtime thread"}"#
        .to_vec()
}

fn invoke_guarded(operation: impl FnOnce() -> Result<InvokeResponse, InvokeFailure>) -> Vec<u8> {
    let response = match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => InvokeResponse::failure(error.message),
        Err(_) => {
            InvokeResponse::failure("internal error: panic caught at the Vole Invoke boundary")
        }
    };
    serialize_response(response)
}

fn invoke_instance_guarded<T>(
    controller: &Arc<CoreController>,
    operation: impl FnOnce() -> Result<T, InvokeFailure>,
) -> Result<T, InvokeFailure> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => {
            controller.recover_after_panic()?;
            if controller.tombstoned.load(Ordering::Acquire) {
                registry().remove_instance(controller);
            }
            Err(InvokeFailure::internal(
                "panic caught at the Vole Invoke boundary",
            ))
        }
    }
}

// Borrow the envelope to enforce the small network-metadata admission bound
// before materializing its JSON Value. Other methods retain their own schema.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequestEnvelope<'a> {
    #[serde(borrow)]
    method: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    payload: &'a serde_json::value::RawValue,
    #[serde(rename = "instanceId", default, borrow)]
    _instance_id: Option<&'a serde_json::value::RawValue>,
}

fn check_dns_network_envelope(request: &str) -> Result<(), InvokeFailure> {
    let raw: RawRequestEnvelope<'_> =
        serde_json::from_str(request).map_err(InvokeFailure::invalid_request)?;
    // An ASCII method's JSON spelling can use at most six bytes per letter.
    // Decode only that bounded scalar; never search request/config contents.
    if raw.method.get().len() > 6 * "updateDnsNetwork".len() + 2 {
        return Ok(());
    }
    let is_update = serde_json::from_str::<String>(raw.method.get())
        .is_ok_and(|method| method == "updateDnsNetwork");
    if !is_update {
        return Ok(());
    }
    let bytes = raw.payload.get().len();
    if bytes > crate::dns::source::MAX_METADATA_BYTES {
        return Err(InvokeFailure::invalid_request(
            "DNS network metadata exceeds 64 KiB",
        ));
    }
    const MAX_DNS_ENVELOPE_OVERHEAD: usize = 64 * 1024;
    if request.len() - bytes > MAX_DNS_ENVELOPE_OVERHEAD {
        return Err(InvokeFailure::invalid_request(
            "DNS network envelope overhead exceeds 64 KiB",
        ));
    }
    Ok(())
}

// Admit configuration work before allocating a JSON Value or decoded YAML.
// Both Controller and Invoke use the one runtime candidate worker.
fn dispatch_config_update(request: &str) -> Result<Option<InvokeResponse>, InvokeFailure> {
    let raw: RawRequestEnvelope<'_> = serde_json::from_str(request)
        .map_err(|_| InvokeFailure::invalid_request("invalid request envelope"))?;
    if raw.method.get().len() > 6 * "updateConfig".len() + 2
        || !serde_json::from_str::<String>(raw.method.get())
            .is_ok_and(|method| method == "updateConfig")
    {
        return Ok(None);
    }
    if request.len() - raw.payload.get().len() > 64 * 1024 {
        return Err(InvokeFailure::invalid_request(
            "configuration envelope overhead exceeds 64 KiB",
        ));
    }
    let id = raw._instance_id.ok_or_else(|| {
        InvokeFailure::invalid_request("instanceId is required for method `updateConfig`")
    })?;
    if id.get().len() > 128 {
        return Err(InvokeFailure::invalid_request("invalid instanceId"));
    }
    let id: String = serde_json::from_str(id.get())
        .map_err(|_| InvokeFailure::invalid_request("invalid instanceId"))?;
    let controller = registry().instance(&id)?;
    invoke_instance_guarded(&controller, || {
        let _command = controller.try_command()?;
        let apply = {
            let mut inner = lock(&controller.inner);
            refresh_runtime_status(&mut inner);
            if inner.lifecycle.state() != LifecycleState::Running {
                return Err(InvokeFailure::invalid_state(
                    "instance must be running before updateConfig",
                ));
            }
            inner
                .engine
                .as_ref()
                .and_then(|engine| engine.config_apply.clone())
                .ok_or_else(|| {
                    InvokeFailure::invalid_state(
                        "runtime does not support configuration application",
                    )
                })?
        };
        let admission = apply
            .try_admit()
            .map_err(|e| InvokeFailure::new(e.message()))?;
        let input = decode_update_input(raw.payload.get())?;
        let base_dir = input
            .http_context
            .map(|context| {
                if context.ca.is_some() {
                    return Err(InvokeFailure::invalid_request(
                        "updateConfig does not accept CA material",
                    ));
                }
                let base = context.base_dir.map(InvokePath::into_path);
                if base.as_ref().is_some_and(|path| !path.is_absolute()) {
                    return Err(InvokeFailure::invalid_request(
                        "HTTP baseDir must be absolute",
                    ));
                }
                Ok(base)
            })
            .transpose()?;
        if input.http_config_yaml.is_none() && base_dir.is_some() {
            return Err(InvokeFailure::invalid_request(
                "httpContext requires httpConfigYaml",
            ));
        }
        let update = match input.http_config_yaml {
            Some(http) => ConfigUpdate::ReplaceWithHttp {
                yaml: input.config_yaml,
                http,
                base_dir,
            },
            None => ConfigUpdate::Replace(input.config_yaml),
        };
        admission
            .submit(update)
            .map_err(|e| InvokeFailure::new(e.message()))?
            .wait_blocking()
            .map_err(|e| InvokeFailure::new(e.message()))?;
        Ok(Some(InvokeResponse::success(json!({}))))
    })
}

fn decode_update_input(payload: &str) -> Result<ConfigYamlPayload, InvokeFailure> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawConfig<'a> {
        #[serde(rename = "configYaml", borrow)]
        yaml: &'a serde_json::value::RawValue,
        #[serde(rename = "httpConfigYaml", default, borrow)]
        http: Option<&'a serde_json::value::RawValue>,
        #[serde(rename = "httpContext", default, borrow)]
        context: Option<&'a serde_json::value::RawValue>,
    }
    let raw: RawConfig<'_> = serde_json::from_str(payload)
        .map_err(|_| InvokeFailure::invalid_request("invalid configuration update payload"))?;
    check_json_string_limit(raw.yaml.get(), crate::config::MAX_CONFIG_BYTES)?;
    if let Some(http) = raw.http {
        check_json_string_limit(http.get(), crate::http_processing::MAX_ADDENDUM)?;
    }
    if raw.context.is_some_and(|raw| raw.get().len() > 8192) {
        return Err(InvokeFailure::invalid_request(
            "HTTP context exceeds input limit",
        ));
    }
    Ok(ConfigYamlPayload {
        config_yaml: serde_json::from_str(raw.yaml.get())
            .map_err(|_| InvokeFailure::invalid_request("invalid configYaml string"))?,
        http_config_yaml: raw
            .http
            .map(|http| serde_json::from_str(http.get()))
            .transpose()
            .map_err(|_| InvokeFailure::invalid_request("invalid httpConfigYaml string"))?,
        http_context: raw
            .context
            .map(|raw| serde_json::from_str(raw.get()))
            .transpose()
            .map_err(|_| InvokeFailure::invalid_request("invalid HTTP context"))?,
    })
}
#[cfg(test)]
fn decode_update_yaml(payload: &str) -> Result<String, InvokeFailure> {
    decode_update_input(payload).map(|input| input.config_yaml)
}

// RawValue validates JSON syntax without decoding strings. Count decoded UTF-8
// first, including surrogate pairs, so escaped input cannot allocate >8 MiB.
fn check_json_string_limit(raw: &str, limit: usize) -> Result<(), InvokeFailure> {
    let bad = || InvokeFailure::invalid_request("configYaml must be a valid string");
    let bytes = raw.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || *bytes.last().unwrap() != b'"' {
        return Err(bad());
    }
    let hex = |slice: &[u8]| -> Option<u16> {
        slice.iter().try_fold(0_u16, |n, c| {
            let digit = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            Some((n << 4) | u16::from(digit))
        })
    };
    let mut i = 1;
    let mut decoded = 0;
    while i < bytes.len() - 1 {
        let width = if bytes[i] != b'\\' {
            i += 1;
            1
        } else {
            i += 1;
            match bytes.get(i).copied().ok_or_else(bad)? {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                    i += 1;
                    1
                }
                b'u' => {
                    let code = hex(bytes.get(i + 1..i + 5).ok_or_else(bad)?).ok_or_else(bad)?;
                    i += 5;
                    match code {
                        0..=0x7f => 1,
                        0x80..=0x7ff => 2,
                        0xd800..=0xdbff => {
                            if bytes.get(i..i + 2) != Some(b"\\u") {
                                return Err(bad());
                            }
                            let low =
                                hex(bytes.get(i + 2..i + 6).ok_or_else(bad)?).ok_or_else(bad)?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(bad());
                            }
                            i += 6;
                            4
                        }
                        0xdc00..=0xdfff => return Err(bad()),
                        _ => 3,
                    }
                }
                _ => return Err(bad()),
            }
        };
        decoded += width;
        if decoded > limit {
            return Err(InvokeFailure::invalid_request(
                "configuration string exceeds its input limit",
            ));
        }
    }
    if i != bytes.len() - 1 {
        return Err(bad());
    }
    Ok(())
}

enum DecodedRequest {
    Complete(InvokeResponse),
    Envelope(RequestEnvelope),
}

fn dispatch_bytes(request: &[u8]) -> Result<InvokeResponse, InvokeFailure> {
    dispatch_request(decode_request(request)?)
}

fn decode_request(request: &[u8]) -> Result<DecodedRequest, InvokeFailure> {
    if request.len() > MAX_INVOKE_BYTES {
        return Err(InvokeFailure::invalid_request(format!(
            "Invoke envelope exceeds the {MAX_INVOKE_BYTES}-byte limit"
        )));
    }
    let request = str::from_utf8(request)
        .map_err(|_| InvokeFailure::invalid_request("request is not valid UTF-8"))?;
    check_dns_network_envelope(request)?;
    http::check_envelope(request)?;
    foreground::check_envelope(request)?;
    if let Some(response) = dispatch_config_update(request)? {
        return Ok(DecodedRequest::Complete(response));
    }
    let envelope: RequestEnvelope =
        serde_json::from_str(request).map_err(InvokeFailure::invalid_request)?;
    if !envelope.payload.is_object() {
        return Err(InvokeFailure::invalid_request("payload must be an object"));
    }

    Ok(DecodedRequest::Envelope(envelope))
}

fn dispatch_request(request: DecodedRequest) -> Result<InvokeResponse, InvokeFailure> {
    let envelope = match request {
        DecodedRequest::Complete(response) => return Ok(response),
        DecodedRequest::Envelope(envelope) => envelope,
    };
    let data = match envelope.method.as_str() {
        "initialize" => {
            require_instance_omitted(&envelope)?;
            let payload: InitializePayload = decode_payload(envelope.payload)?;
            let directory = registry().initialize_data_directory(&payload.data_dir)?;
            json!({"dataDir": directory.root().to_string_lossy()})
        }
        "updateDnsNetwork" => {
            require_instance_omitted(&envelope)?;
            crate::dns::source::check_metadata_size(&envelope.payload)
                .map_err(InvokeFailure::from)?;
            let update: crate::dns::source::DnsNetworkUpdate = decode_payload(envelope.payload)?;
            let sources = registry().dns_sources()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(InvokeFailure::from)?;
            runtime
                .block_on(sources.replace(update))
                .map_err(InvokeFailure::from)?;
            json!({})
        }
        "createInstance" => {
            require_instance_omitted(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            let controller = registry().create_instance()?;
            json!({"instanceId": controller.id.to_string()})
        }
        "getGeoDataState" => {
            require_instance_omitted(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            geodata_status_data(registry().geodata_manager()?.status().map_err(|error| {
                InvokeFailure::new(format!("failed to read GeoData state: {error}"))
            })?)
        }
        "validateConfig" => {
            require_instance_omitted(&envelope)?;
            let payload: ConfigYamlPayload = decode_payload(envelope.payload)?;
            if let Some(context) = payload.http_context {
                if context.ca.is_some() {
                    return Err(InvokeFailure::invalid_request(
                        "validateConfig does not accept CA material",
                    ));
                }
                if context
                    .base_dir
                    .map(InvokePath::into_path)
                    .is_some_and(|path| !path.is_absolute())
                {
                    return Err(InvokeFailure::invalid_request(
                        "HTTP baseDir must be absolute",
                    ));
                }
            }
            let resources_ready = payload
                .http_config_yaml
                .as_deref()
                .filter(|input| !input.is_empty())
                .map(crate::http_processing::config::Document::parse)
                .transpose()
                .map_err(|_| InvokeFailure::new("invalid HTTP processing configuration"))?
                .is_none_or(|document| document.unresolved_count() == 0);
            validate_config_with_http(payload.config_yaml, payload.http_config_yaml)?;
            json!({"httpResourcesValidated":resources_ready,"httpsReady":false})
        }
        "measureDelay" => {
            require_instance_omitted(&envelope)?;
            let payload: measure_delay::MeasureDelayPayload = decode_payload(envelope.payload)?;
            let results = measure_delay::measure_delay(payload)?;
            json!({"results": results})
        }
        "start" | "reconnect" => {
            let controller = require_instance(&envelope)?;
            let reconnect = envelope.method == "reconnect";
            let payload: http::StartPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                if reconnect {
                    controller.reconnect(payload)?;
                } else {
                    controller.start_config(StartupConfig::Input(Box::new(payload)))?;
                }
                Ok(json!({}))
            })?
        }
        "refreshHttpProviders" => {
            require_instance_omitted(&envelope)?;
            http::refresh(decode_payload(envelope.payload)?)?
        }
        "testHttp" => {
            require_instance_omitted(&envelope)?;
            http::evaluate(decode_payload::<http::TestPayload>(envelope.payload)?)?
        }
        "foreground" => {
            require_instance_omitted(&envelope)?;
            let payload: foreground::ForegroundPayload = decode_payload(envelope.payload)?;
            foreground::execute(payload)?
        }
        "stop" => {
            let controller = require_instance(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                controller.stop()?;
                Ok(json!({}))
            })?
        }
        "getState" => {
            let controller = require_instance(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || controller.state_data())?
        }
        "destroyInstance" => {
            let controller = require_instance(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                controller.destroy()?;
                Ok(json!({}))
            })?
        }
        "version" => {
            require_instance_omitted(&envelope)?;
            let _: EmptyPayload = decode_payload(envelope.payload)?;
            json!({
                "buildIdentity": BUILD_IDENTITY,
                "engine": ENGINE,
                "version": env!("CARGO_PKG_VERSION"),
            })
        }
        method => {
            return Err(InvokeFailure::invalid_request(format!(
                "unknown method `{method}`"
            )));
        }
    };
    Ok(InvokeResponse::success(data))
}

fn require_instance(envelope: &RequestEnvelope) -> Result<Arc<CoreController>, InvokeFailure> {
    let raw_id = envelope.instance_id.as_deref().ok_or_else(|| {
        InvokeFailure::invalid_request(format!(
            "instanceId is required for method `{}`",
            envelope.method
        ))
    })?;
    registry().instance(raw_id)
}

fn require_instance_omitted(envelope: &RequestEnvelope) -> Result<(), InvokeFailure> {
    if envelope.instance_id.is_some() {
        return Err(InvokeFailure::invalid_request(format!(
            "instanceId must be omitted for method `{}`",
            envelope.method
        )));
    }
    Ok(())
}

fn decode_payload<T: for<'de> Deserialize<'de>>(payload: Value) -> Result<T, InvokeFailure> {
    serde_json::from_value(payload).map_err(InvokeFailure::invalid_request)
}

impl CoreController {
    fn try_command(&self) -> Result<MutexGuard<'_, ()>, InvokeFailure> {
        let guard = match self.command.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(InvokeFailure::invalid_state(format!(
                    "instance {} is busy",
                    self.id
                )));
            }
        };
        self.ensure_live()?;
        Ok(guard)
    }

    fn ensure_live(&self) -> Result<(), InvokeFailure> {
        if self.tombstoned.load(Ordering::Acquire) {
            return Err(InvokeFailure::invalid_request("unknown instanceId"));
        }
        Ok(())
    }

    fn prepare_locked(&self, input: StartupConfig) -> Result<(), InvokeFailure> {
        {
            let mut inner = lock(&self.inner);
            refresh_runtime_status(&mut inner);
            if inner.lifecycle.state() != LifecycleState::Stopped {
                return Err(InvokeFailure::invalid_state(
                    "instance must be stopped before start",
                ));
            }
        }

        // Parse before claiming runtime-local resources. Android only needs a
        // protect controller for a configuration that actually contains TUN;
        // non-TUN configurations do not depend on controller registration.
        let _data_directory = registry().data_directory()?;
        let (mut config, http_input, resolved_cache) = match input {
            #[cfg(test)]
            StartupConfig::Yaml(yaml) => (parse_config_yaml(&yaml)?, None, None),
            StartupConfig::Input(mut payload) => {
                let mut config = parse_config_yaml(&payload.config_yaml)?;
                if let (Some(template), Some(paths)) =
                    (&mut config.providers, payload.provider_paths.clone())
                {
                    Arc::make_mut(template).resource_paths = paths;
                }
                std::mem::take(&mut payload.foreground_overrides).apply(&mut config);
                (config, Some(payload), None)
            }
            StartupConfig::Resolved(snapshot) => {
                (snapshot.config, None, Some(snapshot.provider_cache))
            }
        };
        let dispatch = crate::logging::dispatch(config.log_level);
        let _logging = tracing::dispatcher::set_default(&dispatch);
        let has_tun = config
            .inbounds
            .iter()
            .any(|inbound| matches!(inbound, crate::config::InboundConfig::Tun(_)));
        // The unique TUN lease and, on Android, the registered protector are
        // captured in one critical section so the protector cannot be replaced
        // during the prepared/running TUN lifecycle.
        let acquisition = registry().acquire_platform_resources(self.id, has_tun)?;
        let PlatformAcquisition {
            tun_lease,
            protector,
        } = acquisition;
        if has_tun {
            crate::platform::process_memory::configure_allocator();
        }
        let allocator_relief = TunAllocatorRelief::new(has_tun);
        {
            let mut inner = lock(&self.inner);
            inner.last_error.clear();
            inner
                .lifecycle
                .transition(LifecycleState::Preparing)
                .map_err(InvokeFailure::from)?;
            inner.tun_lease = tun_lease;
            inner.tun_allocator_relief = allocator_relief;
        }

        let prepared = (|| {
            let limits = ResourceLimits::default();
            let geodata_manager = registry().geodata_manager()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(InvokeFailure::from)?;
            let prepared = runtime.block_on(async {
                let cancellation = http_input
                    .as_ref()
                    .and_then(|input| input.cancellation.clone());
                if let Some(input) = http_input {
                    http::attach(
                        &mut config,
                        input.http_config_yaml.as_deref(),
                        input.http_context,
                        input.source_file,
                        input.provider_paths,
                        input.cancellation.as_ref(),
                    )
                    .await?;
                }
                let prepared = match resolved_cache {
                    Some(cache) => {
                        PreparedCore::prepare_resolved(
                            config,
                            cache,
                            geodata_manager,
                            &SystemResolver,
                            limits,
                        )
                        .await
                    }
                    None => {
                        PreparedCore::prepare_config(
                            config,
                            geodata_manager,
                            &SystemResolver,
                            limits,
                        )
                        .await
                    }
                }
                .map_err(InvokeFailure::from)?;
                if cancellation.is_some_and(|token| token.is_cancelled()) {
                    return Err(InvokeFailure::new("core preparation was cancelled"));
                }
                Ok(prepared)
            });
            // Bootstrap DNS runs on the runtime-shared bounded worker. Keep a
            // finite shutdown boundary so future prepare-only tasks cannot
            // turn Runtime::drop into an unbounded synchronous wait.
            runtime.shutdown_timeout(Duration::from_millis(100));
            prepared
        })();

        let mut inner = lock(&self.inner);
        match prepared {
            Ok(prepared) => {
                inner.prepared = Some(PreparedState {
                    core: prepared,
                    protector,
                });
                match inner
                    .lifecycle
                    .transition(LifecycleState::Prepared)
                    .map_err(InvokeFailure::from)
                {
                    Ok(()) => {
                        observe_tun_memory(has_tun, "prepare-complete");
                        Ok(())
                    }
                    Err(error) => reset_failed_operation(&mut inner, "prepare-transition-failed")
                        .and(Err(error)),
                }
            }
            Err(error) => reset_failed_operation(&mut inner, "prepare-failed").and(Err(error)),
        }
    }

    fn start_config(&self, config: StartupConfig) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        self.prepare_locked(config)?;
        let result = self.start_prepared_locked();
        if result.is_err() {
            reset_failed_operation(&mut lock(&self.inner), "start-failed")?;
        }
        result
    }

    fn reconnect(&self, input: http::StartPayload) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        let apply = {
            let mut inner = lock(&self.inner);
            refresh_runtime_status(&mut inner);
            if inner.lifecycle.state() != LifecycleState::Running {
                return Err(InvokeFailure::invalid_state(
                    "instance must be running before reconnect",
                ));
            }
            inner
                .engine
                .as_ref()
                .and_then(|engine| engine.config_apply.clone())
                .ok_or_else(|| {
                    InvokeFailure::invalid_state("runtime cannot capture a recovery snapshot")
                })?
        };
        // Resolve external sources while the old engine and its platform lease
        // are still usable. GeoData registration and TUN binding happen only
        // after the synchronous old-engine stop barrier.
        let config = http::parse_reconnect(input, &apply)?;
        let manager = registry().geodata_manager()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(InvokeFailure::from)?;
        let next = runtime.block_on(PreparedCore::resolve_config(config, &manager));
        runtime.shutdown_timeout(Duration::from_millis(100));
        let (config, provider_cache) = next.map_err(InvokeFailure::from)?;
        let next = Box::new(crate::runtime::RecoverySnapshot {
            config,
            provider_cache,
        });
        let previous = apply
            .recovery_snapshot()
            .map_err(|error| InvokeFailure::new(error.message()))?;
        self.stop_locked()?;
        let result = self
            .prepare_locked(StartupConfig::Resolved(next))
            .and_then(|()| self.start_prepared_locked());
        if let Err(error) = result {
            reset_failed_operation(&mut lock(&self.inner), "reconnect-failed")?;
            if self
                .prepare_locked(StartupConfig::Resolved(previous))
                .and_then(|()| self.start_prepared_locked())
                .is_err()
            {
                reset_failed_operation(&mut lock(&self.inner), "reconnect-recovery-failed")?;
                return Err(InvokeFailure::new(
                    "reconnect failed and previous session could not be restored",
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    fn start_prepared_locked(&self) -> Result<(), InvokeFailure> {
        let (prepared, tun, has_tun, allocator_relief) = {
            let mut inner = lock(&self.inner);
            refresh_runtime_status(&mut inner);
            if inner.lifecycle.state() != LifecycleState::Prepared {
                return Err(InvokeFailure::invalid_state(
                    "instance must be prepared before start",
                ));
            }
            let has_tun = inner
                .prepared
                .as_ref()
                .ok_or_else(|| InvokeFailure::internal("prepared core is missing"))?
                .core
                .has_tun();
            let tun = acquire_start_tun(inner.prepared.as_ref().unwrap().core.tun_config())?;
            let prepared = inner
                .prepared
                .take()
                .ok_or_else(|| InvokeFailure::internal("prepared core is missing"))?;
            inner.last_error.clear();
            inner
                .lifecycle
                .transition(LifecycleState::Starting)
                .map_err(InvokeFailure::from)?;
            let allocator_relief = inner.tun_allocator_relief.clone();
            (prepared, tun, has_tun, allocator_relief)
        };

        let dialer = prepared
            .protector
            .clone()
            .map_or_else(Dialer::default, |protector| {
                Dialer::default().with_protector(protector)
            })
            .with_dns_sources(registry().dns_sources()?);
        let (stop_tx, stop_rx) = oneshot::channel();
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let (completed_tx, completed_rx) = tokio::sync::watch::channel(false);
        let instance_id = self.id;
        let context = EngineContext {
            instance_id,
            has_tun,
            allocator_relief,
        };
        let dispatch = crate::logging::dispatch(prepared.core.log_level());
        let spawned = thread::Builder::new()
            .name(format!("vole-runtime-{instance_id}"))
            .spawn(crate::resources::observation::inherit_thread(move || {
                let _logging = tracing::dispatcher::set_default(&dispatch);
                let _completion = EngineCompletion(completed_tx);
                let _runtime_thread = RuntimeThreadGuard::enter();
                run_engine(context, prepared.core, tun, dialer, stop_rx, startup_tx)
            }));
        let runtime_thread = match spawned {
            Ok(thread) => thread,
            Err(error) => {
                let mut inner = lock(&self.inner);
                return reset_failed_operation(&mut inner, "start-spawn-failed")
                    .and(Err(InvokeFailure::from(error)));
            }
        };
        let mut engine = Engine {
            stop: Some(stop_tx),
            thread: Some(runtime_thread),
            completion: completed_rx,
            config_apply: None,
        };

        match startup_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(config_apply)) => {
                engine.config_apply = config_apply;
                let mut inner = lock(&self.inner);
                if let Err(error) = inner
                    .lifecycle
                    .transition(LifecycleState::Running)
                    .map_err(InvokeFailure::from)
                {
                    drop(inner);
                    let _ = engine.stop();
                    let mut inner = lock(&self.inner);
                    return reset_failed_operation(&mut inner, "start-transition-failed")
                        .and(Err(error));
                }
                inner.engine = Some(engine);
                observe_tun_memory(has_tun, "start-complete");
                Ok(())
            }
            Ok(Err(error)) => {
                let _ = engine.stop();
                let mut inner = lock(&self.inner);
                reset_failed_operation(&mut inner, "start-runtime-failed").and(Err(error))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let stopped = engine.stop();
                let mut inner = lock(&self.inner);
                let outcome = stopped.and_then(|()| {
                    Err(InvokeFailure::internal(
                        "Vole runtime exited before reporting startup",
                    ))
                });
                reset_failed_operation(&mut inner, "start-disconnected").and(outcome)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = engine.stop();
                let mut inner = lock(&self.inner);
                reset_failed_operation(&mut inner, "start-timeout")
                    .and(Err(InvokeFailure::new("Vole runtime startup timed out")))
            }
        }
    }

    fn stop(&self) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        self.stop_locked()
    }

    fn stop_locked(&self) -> Result<(), InvokeFailure> {
        let (mut engine, had_tun) = {
            let mut inner = lock(&self.inner);
            refresh_runtime_status(&mut inner);
            match inner.lifecycle.state() {
                LifecycleState::Stopped => {
                    let had_tun = inner.tun_lease.is_some();
                    inner.last_error.clear();
                    observe_tun_memory(had_tun, "stop-complete");
                    clear_instance_leases(&mut inner);
                    return Ok(());
                }
                LifecycleState::Prepared => {
                    let had_tun = inner.tun_lease.is_some();
                    inner.prepared = None;
                    inner.last_error.clear();
                    let transitioned = inner
                        .lifecycle
                        .transition(LifecycleState::Stopped)
                        .map_err(InvokeFailure::from);
                    observe_tun_memory(had_tun, "stop-complete");
                    clear_instance_leases(&mut inner);
                    return transitioned;
                }
                LifecycleState::Running | LifecycleState::Failed => {
                    let had_tun = inner.tun_lease.is_some();
                    inner
                        .lifecycle
                        .transition(LifecycleState::Stopping)
                        .map_err(InvokeFailure::from)?;
                    (inner.engine.take(), had_tun)
                }
                LifecycleState::Preparing | LifecycleState::Starting | LifecycleState::Stopping => {
                    return Err(InvokeFailure::invalid_state(
                        "core cannot stop during a lifecycle transition",
                    ));
                }
            }
        };

        let stopped = engine.as_mut().map_or(Ok(()), Engine::stop);
        drop(engine);
        let mut inner = lock(&self.inner);
        inner.prepared = None;
        inner.engine = None;
        let transitioned = inner
            .lifecycle
            .transition(LifecycleState::Stopped)
            .map_err(InvokeFailure::from);
        match &stopped {
            Ok(()) => inner.last_error.clear(),
            Err(error) => inner.last_error = error.message.clone(),
        }
        clear_instance_leases(&mut inner);
        let _ = had_tun;
        transitioned.and(stopped)
    }

    fn state_data(&self) -> Result<Value, InvokeFailure> {
        // Reads participate in the same per-instance admission as lifecycle
        // mutations. Besides making the public fail-fast contract uniform,
        // this prevents a state read that already resolved the controller from
        // completing after destroyInstance's synchronous removal barrier.
        let _command = self.try_command()?;
        let mut inner = lock(&self.inner);
        refresh_runtime_status(&mut inner);
        Ok(json!({
            "state": inner.lifecycle.state().as_str(),
            "lastError": inner.last_error,
        }))
    }

    // Foreground owns this lifecycle and must wait for an already admitted
    // command rather than leave a live engine behind on public busy rejection.
    fn destroy_foreground(self: &Arc<Self>) -> Result<(), InvokeFailure> {
        let _command = lock(&self.command);
        if self.tombstoned.load(Ordering::Acquire) {
            return Ok(());
        }
        let _removal = InstanceRemovalGuard { controller: self };
        self.stop_locked()
    }

    fn destroy(self: &Arc<Self>) -> Result<(), InvokeFailure> {
        self.destroy_with(|| self.stop_locked())
    }

    fn destroy_with(
        self: &Arc<Self>,
        operation: impl FnOnce() -> Result<(), InvokeFailure>,
    ) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        let _removal = InstanceRemovalGuard { controller: self };
        operation()
    }

    fn recover_after_panic(&self) -> Result<(), InvokeFailure> {
        let _command = lock(&self.command);
        let (mut engine, had_tun) = {
            let mut inner = lock(&self.inner);
            let had_tun = inner.tun_lease.is_some();
            inner.prepared = None;
            inner.last_error =
                "internal error: panic caught at the Vole Invoke boundary".to_owned();
            match inner.lifecycle.state() {
                LifecycleState::Running | LifecycleState::Failed => {
                    let _ = inner.lifecycle.transition(LifecycleState::Stopping);
                }
                LifecycleState::Preparing | LifecycleState::Starting => {
                    let _ = inner.lifecycle.transition(LifecycleState::Failed);
                }
                LifecycleState::Prepared => {
                    let _ = inner.lifecycle.transition(LifecycleState::Stopped);
                }
                LifecycleState::Stopped | LifecycleState::Stopping => {}
            }
            (inner.engine.take(), had_tun)
        };
        if let Some(engine) = engine.as_mut() {
            let _ = engine.stop();
        }
        drop(engine);
        let mut inner = lock(&self.inner);
        inner.lifecycle = Lifecycle::default();
        inner.engine = None;
        observe_tun_memory(had_tun, "panic-recovery");
        clear_instance_leases(&mut inner);
        Ok(())
    }
}

fn clear_instance_leases(inner: &mut CoreInner) {
    // Prepared-only paths own the final allocator-relief handle here. Running
    // paths share it with the engine, whose completion performs relief first.
    inner.tun_allocator_relief = None;
    inner.tun_lease = None;
}

fn observe_tun_memory(has_tun: bool, stage: &'static str) {
    if has_tun {
        crate::platform::process_memory::observe(stage);
    }
}

fn relieve_tun_allocator() {
    crate::platform::process_memory::relieve_allocator_pressure();
}

#[cfg(target_os = "android")]
pub(crate) fn replace_android_socket_protector(
    protector: Option<Arc<dyn SocketProtector>>,
) -> Result<(), String> {
    registry().replace_android_socket_protector(protector)
}

fn validate_config_with_http(
    config_yaml: String,
    http_config_yaml: Option<String>,
) -> Result<(), InvokeFailure> {
    let config = parse_config_yaml_with_http(&config_yaml, http_config_yaml.as_deref())?;
    drop(config_yaml);
    PreparedCore::validate_config(config).map_err(InvokeFailure::from)
}

fn parse_config_yaml(config_yaml: &str) -> Result<Config, InvokeFailure> {
    parse_config_yaml_with_http(config_yaml, None)
}
fn parse_config_yaml_with_http(
    config_yaml: &str,
    http: Option<&str>,
) -> Result<Config, InvokeFailure> {
    let directory = registry().data_directory().ok();
    let mut config =
        parse_config_yaml_with_directory(config_yaml, directory.as_ref().map(|dir| dir.root()))?;
    if let (Some(template), Some(paths)) = (&mut config.providers, registry().provider_paths()) {
        Arc::make_mut(template).resource_paths = paths;
    }
    config.set_http_config(http).map_err(InvokeFailure::from)?;
    Ok(config)
}

fn parse_config_yaml_with_directory(
    config_yaml: &str,
    directory: Option<&Path>,
) -> Result<Config, InvokeFailure> {
    if config_yaml.is_empty() {
        return Err(InvokeFailure::invalid_request("configYaml is empty"));
    }
    Config::parse_yaml_with_directory(config_yaml.as_bytes(), directory)
        .map_err(InvokeFailure::from)
}

fn geodata_status_data(status: GeoDataStatus) -> Value {
    json!({
        "geosite": geodata_resource_data(status.geosite),
        "geoip": geodata_resource_data(status.geoip),
        "asn": geodata_resource_data(status.asn),
    })
}

fn geodata_resource_data(state: GeoResourceState) -> Value {
    json!({
        "required": state.required,
        "available": state.available,
        "updating": state.updating,
        "lastSuccess": state.last_success,
        "nextCheck": state.next_check,
        "lastError": state.last_error,
        "etag": state.etag,
        "hash": state.hash,
    })
}

#[cfg(unix)]
fn acquire_start_tun(
    config: Option<&crate::config::TunConfig>,
) -> Result<Option<InvokeTun>, InvokeFailure> {
    let Some(config) = config else {
        return Ok(None);
    };
    let framing = if cfg!(any(
        target_os = "ios",
        target_os = "tvos",
        target_os = "macos"
    )) {
        TunFraming::Utun
    } else {
        TunFraming::RawIp
    };
    if config.file_descriptor > 0 {
        let fd = TunFd::duplicate_with_mtu(config.file_descriptor, config.mtu)?;
        Ok(Some((fd, framing, config.mtu)))
    } else {
        Ok(None)
    }
}

#[cfg(not(unix))]
fn acquire_start_tun(
    config: Option<&crate::config::TunConfig>,
) -> Result<Option<InvokeTun>, InvokeFailure> {
    if let Some(config) = config {
        if config.file_descriptor != 0 {
            return Err(InvokeFailure::invalid_request(
                "tun.file-descriptor is unsupported on this target",
            ));
        }
        #[cfg(not(all(windows, feature = "windows-wintun")))]
        return Err(InvokeFailure::new(
            "native TUN resource is unavailable on this target",
        ));
    }
    Ok(None)
}

struct EngineContext {
    instance_id: u64,
    has_tun: bool,
    allocator_relief: Option<TunAllocatorRelief>,
}

fn run_engine(
    context: EngineContext,
    prepared: PreparedCore,
    tun: Option<InvokeTun>,
    dialer: Dialer,
    stop: oneshot::Receiver<()>,
    startup: SyncSender<Result<Option<ConfigApplyHandle>, InvokeFailure>>,
) -> io::Result<()> {
    let EngineContext {
        instance_id,
        has_tun,
        allocator_relief,
    } = context;
    tracing::info!(instance_id, has_tun, "Vole runtime engine starting");
    let result = run_engine_inner(instance_id, has_tun, prepared, tun, dialer, stop, startup);
    observe_tun_memory(has_tun, "stop-complete");
    if let Some(relief) = allocator_relief {
        relief.relieve();
    }
    match &result {
        Ok(()) => tracing::info!(instance_id, "Vole runtime engine stopped"),
        Err(error) => {
            tracing::error!(
                instance_id,
                error_kind = ?error.kind(),
                "Vole runtime engine failed"
            );
        }
    }
    result
}

fn run_engine_inner(
    instance_id: u64,
    has_tun: bool,
    prepared: PreparedCore,
    tun: Option<InvokeTun>,
    dialer: Dialer,
    stop: oneshot::Receiver<()>,
    startup: SyncSender<Result<Option<ConfigApplyHandle>, InvokeFailure>>,
) -> io::Result<()> {
    let runtime = match engine_runtime_builder().enable_io().enable_time().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            let message = error.to_string();
            let _ = startup.send(Err(InvokeFailure::internal(&message)));
            return Err(io::Error::new(error.kind(), message));
        }
    };
    runtime.block_on(async move {
        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "tvos",
            target_os = "macos",
            target_os = "linux"
        ))]
        let started = match tun {
            Some((fd, framing, mtu)) => match TunIo::new_with_mtu(fd, framing, mtu) {
                Ok(tun) => prepared.start_tun(tun, dialer).await,
                Err(error) => Err(io::Error::other(error)),
            },
            None if has_tun => {
                #[cfg(target_os = "linux")]
                {
                    prepared.start_native_tun(dialer).await
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let config = prepared.tun_config().expect("validated TUN configuration");
                    if config.auto_route || config.auto_detect_interface {
                        Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "automatic TUN networking is only available on Linux",
                        ))
                    } else {
                        match TunIo::open(&config.device, config.mtu) {
                            Ok(tun) => prepared.start_tun(tun, dialer).await,
                            Err(error) => Err(io::Error::other(error)),
                        }
                    }
                }
            }
            None => prepared.start_local(dialer).await,
        };
        #[cfg(all(windows, feature = "windows-wintun"))]
        let started = {
            debug_assert!(tun.is_none());
            if has_tun {
                prepared.start_wintun(dialer).await
            } else {
                prepared.start_local(dialer).await
            }
        };
        #[cfg(not(any(
            all(windows, feature = "windows-wintun"),
            target_os = "android",
            target_os = "ios",
            target_os = "tvos",
            target_os = "macos",
            target_os = "linux"
        )))]
        let started = {
            debug_assert!(tun.is_none());
            prepared.start_local(dialer).await
        };
        let mut running = match started {
            Ok(running) => running,
            Err(error) => {
                let kind = error.kind();
                let message = error.to_string();
                let _ = startup.send(Err(InvokeFailure::from(error)));
                return Err(io::Error::new(kind, message));
            }
        };
        running.maintain_http(
            http::runtime_store().map_err(|_| io::Error::other("HTTP runtime store is missing"))?,
        );
        tracing::info!(instance_id, has_tun, "Vole runtime engine started");
        if startup.send(Ok(running.config_apply_handle())).is_err() {
            return running.stop().await;
        }
        running
            .run_until_shutdown(wait_for_engine_shutdown(stop, has_tun))
            .await
    })
}

async fn wait_for_engine_shutdown(
    mut stop: oneshot::Receiver<()>,
    has_tun: bool,
) -> io::Result<()> {
    if has_tun {
        let interval = crate::platform::process_memory::TELEMETRY_INTERVAL;
        let first_tick = tokio::time::Instant::now() + interval;
        let mut telemetry = tokio::time::interval_at(first_tick, interval);
        telemetry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stop => return Ok(()),
                _ = telemetry.tick() => observe_tun_memory(true, "running"),
            }
        }
    }
    let _ = stop.await;
    Ok(())
}

fn refresh_runtime_status(inner: &mut CoreInner) {
    if inner.lifecycle.state() != LifecycleState::Running
        || !inner.engine.as_ref().is_some_and(Engine::is_finished)
    {
        return;
    }
    let result = inner.engine.as_mut().map_or_else(
        || {
            Err(InvokeFailure::internal(
                "Vole runtime disappeared unexpectedly",
            ))
        },
        Engine::stop,
    );
    inner.engine = None;
    inner.last_error = match result {
        Ok(()) => "Vole runtime stopped unexpectedly".to_owned(),
        Err(error) => error.message,
    };
    let _ = inner.lifecycle.transition(LifecycleState::Failed);
}

fn reset_failed_operation(
    inner: &mut CoreInner,
    telemetry_stage: &'static str,
) -> Result<(), InvokeFailure> {
    let had_tun = inner.tun_lease.is_some();
    inner.prepared = None;
    inner.engine = None;
    match inner.lifecycle.state() {
        LifecycleState::Preparing | LifecycleState::Starting => {
            let _ = inner.lifecycle.transition(LifecycleState::Failed);
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Prepared => {
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Failed | LifecycleState::Stopping => {
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Running => {
            let _ = inner.lifecycle.transition(LifecycleState::Stopping);
            let _ = inner.lifecycle.transition(LifecycleState::Stopped);
        }
        LifecycleState::Stopped => {}
    }
    observe_tun_memory(had_tun, telemetry_stage);
    clear_instance_leases(inner);
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn serialize_response(response: InvokeResponse) -> Vec<u8> {
    serde_json::to_vec(&response).unwrap_or_else(|_| {
        b"{\"success\":false,\"data\":null,\"error\":\"internal error: response serialization failed\"}"
            .to_vec()
    })
}

fn bounded_error(mut message: String) -> String {
    if message.len() <= MAX_ERROR_BYTES {
        return message;
    }
    let mut end = MAX_ERROR_BYTES.saturating_sub(3);
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    message.truncate(end);
    message.push_str("...");
    message
}

#[cfg(test)]
mod tests {
    #[test]
    fn owned_invoke_uses_the_shared_strict_and_runtime_thread_boundaries() {
        let version = br#"{"method":"version","payload":{}}"#;
        assert_eq!(
            super::invoke_bytes(version),
            super::invoke_owned_bytes(version.to_vec())
        );
        for invalid in [
            br#"{"method":"version","payload":{},"extra":true}"#.as_slice(),
            br#"{"method":"version","payload":{"secret":"private-fixture"}}"#,
            br#"{"method":"foreground","payload":{"action":"help","extra":true}}"#,
        ] {
            assert_eq!(
                super::invoke_bytes(invalid),
                super::invoke_owned_bytes(invalid.to_vec())
            );
        }
        let oversized_key = serde_json::json!({"method":"foreground","payload":{"action":"help","ageSecretKey":"x".repeat(16 * 1024 + 1)}}).to_string();
        assert_eq!(
            super::invoke_bytes(oversized_key.as_bytes()),
            super::invoke_owned_bytes(oversized_key.into_bytes())
        );
        super::IS_RUNTIME_THREAD.with(|flag| {
            let old = flag.replace(true);
            let response = super::invoke_owned_bytes(version.to_vec());
            flag.set(old);
            assert_eq!(response, super::runtime_thread_response());
        });
    }

    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Barrier, Mutex},
    };

    #[cfg(target_os = "linux")]
    use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

    use super::*;
    #[cfg(feature = "ffi")]
    use crate::ffi::{VoleFree, VoleInvoke};
    #[cfg(feature = "ffi")]
    use std::{ffi::CStr, ptr};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn allocator_relief_requires_tun() {
        assert!(TunAllocatorRelief::new(false).is_none());
        let relief = TunAllocatorRelief::new(true).expect("TUN owns allocator relief");
        // Claim with a pure hook so this regression never trims the test
        // process's allocator as a side effect of dropping the handle.
        relief.state.relieve_with(|| {});
    }

    #[test]
    fn shared_allocator_relief_is_claimed_exactly_once() {
        let state = Arc::new(TunAllocatorReliefState {
            relieved: AtomicBool::new(false),
        });
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let state = state.clone();
                let calls = calls.clone();
                thread::spawn(move || {
                    state.relieve_with(|| {
                        calls.fetch_add(1, Ordering::Relaxed);
                    });
                })
            })
            .collect();
        for attempt in attempts {
            attempt.join().unwrap();
        }
        state.relieve_with(|| {
            calls.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(state.relieved.load(Ordering::Relaxed));
    }

    struct TestDataDirectory {
        _temporary: tempfile::TempDir,
    }

    struct AcceptingProtector;

    impl SocketProtector for AcceptingProtector {
        fn protect(&self, _socket: i32) -> io::Result<()> {
            Ok(())
        }
    }

    fn invoke(request: &str) -> Value {
        serde_json::from_slice(&super::invoke_bytes(request.as_bytes())).unwrap()
    }

    fn assert_failure(response: &Value) {
        assert_eq!(response["success"], false);
        assert!(response["data"].is_null());
        assert!(
            response["error"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        assert_eq!(response.as_object().unwrap().len(), 3);
    }

    fn request(method: &str, instance_id: Option<&str>, payload: Value) -> Value {
        let mut envelope = json!({
            "method": method,
            "payload": payload,
        });
        if let Some(instance_id) = instance_id {
            envelope["instanceId"] = Value::String(instance_id.to_owned());
        }
        invoke(&envelope.to_string())
    }

    fn create_instance() -> String {
        let response = request("createInstance", None, json!({}));
        assert_eq!(response["success"], true, "{response}");
        response["data"]["instanceId"].as_str().unwrap().to_owned()
    }

    fn prepare_private(instance_id: &str, payload: Value) -> Value {
        let controller = registry().instance(instance_id).unwrap();
        let payload: ConfigYamlPayload = decode_payload(payload).unwrap();
        let _command = controller.try_command().unwrap();
        let result = controller.prepare_locked(StartupConfig::Yaml(payload.config_yaml));
        json!({"success": result.is_ok()})
    }

    fn destroy_instance(instance_id: &str) {
        let response = request("destroyInstance", Some(instance_id), json!({}));
        assert_eq!(response["success"], true, "{response}");
    }

    fn state(instance_id: &str) -> Value {
        request("getState", Some(instance_id), json!({}))
    }

    fn reset_registry() {
        let controller = lock(&registry().inner).instance.clone();
        if let Some(controller) = controller {
            let _ = controller.destroy();
        }
        let inner = lock(&registry().inner);
        assert!(inner.instance.is_none());
        drop(inner);
        let platform = lock(&registry().platform);
        assert_eq!(platform.tun_owner, None);
        drop(platform);
        *lock(&registry().runtime_data) = None;
    }

    fn initialize_test_data_directory() -> TestDataDirectory {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("vole");
        let response = request(
            "initialize",
            None,
            json!({"dataDir": root.to_str().unwrap()}),
        );
        assert_eq!(response["success"], true, "{response}");
        TestDataDirectory {
            _temporary: temporary,
        }
    }

    fn config_with_outbound(mixed_port: Option<u16>, tun: bool, outbound_port: u16) -> String {
        let listener = match (mixed_port, tun) {
            (Some(port), false) => format!(
                "mixed-port: {port}
authentication:
  - measure:secret\n"
            ),
            (None, true) => "tun:\n  enable: true\n  mtu: 1500\n".to_owned(),
            _ => panic!("test configuration must select exactly one listener"),
        };
        format!(
            r#"{listener}proxies:
  - name: proxy
    type: vless
    server: 127.0.0.1
    port: {outbound_port}
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      host: example.com
      path: /vole
      mode: packet-up
rules:
  - MATCH,proxy
"#
        )
    }

    fn tun_config() -> String {
        config_with_outbound(None, true, 443)
    }

    fn mixed_config(port: u16) -> String {
        config_with_outbound(Some(port), false, 443)
    }

    fn current_config(mixed_port: u16, rules: &str) -> String {
        format!(
            r#"mixed-port: {mixed_port}
authentication:
  - measure:secret
proxies:
  - name: proxy
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      host: example.com
      path: /vole
      mode: packet-up
rules:
{rules}
"#
        )
    }

    fn free_ports(count: usize) -> Vec<u16> {
        let listeners: Vec<_> = (0..count)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect()
    }

    fn probe_http_listener(port: u16) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(
                b"GET / HTTP/1.1\r\n\
                  Host: example.com\r\n\
                  Proxy-Authorization: Basic bWVhc3VyZTpzZWNyZXQ=\r\n\r\n",
            )
            .unwrap();
        let mut response = [0_u8; 128];
        let length = stream.read(&mut response).unwrap();
        assert!(
            response[..length].starts_with(b"HTTP/1.1 400")
                || response[..length].starts_with(b"HTTP/1.1 501"),
            "unexpected response: {}",
            String::from_utf8_lossy(&response[..length])
        );
    }

    #[test]
    fn version_and_state_use_the_fixed_response_envelope() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let version = invoke(r#"{"method":"version","payload":{}}"#);
        assert_eq!(
            version,
            json!({
                "success": true,
                "data": {
                    "buildIdentity": BUILD_IDENTITY,
                    "engine": ENGINE,
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "error": "",
            })
        );

        let instance_id = create_instance();
        let instance_state = state(&instance_id);
        assert_eq!(instance_state["data"]["state"], "stopped");
        assert_eq!(instance_state["data"]["lastError"], "");
        destroy_instance(&instance_id);
    }

    #[test]
    fn initialize_is_idempotent_only_for_the_same_data_directory() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        assert_failure(&request("initialize", None, json!({"dataDir": "relative"})));
        assert_failure(&request("getGeoDataState", None, json!({})));

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("vole");
        let first = request(
            "initialize",
            None,
            json!({"dataDir": root.to_str().unwrap()}),
        );
        assert_eq!(first["success"], true, "{first}");
        assert!(root.join(crate::data_dir::CONFIGS_DIR_NAME).is_dir());
        assert!(root.join(crate::data_dir::GEODATA_DIR_NAME).is_dir());

        let same = request(
            "initialize",
            None,
            json!({"dataDir": root.to_str().unwrap()}),
        );
        assert_eq!(same["success"], true, "{same}");

        let geodata = request("getGeoDataState", None, json!({}));
        assert_eq!(geodata["success"], true, "{geodata}");
        for kind in ["geosite", "geoip"] {
            assert_eq!(geodata["data"][kind]["required"], false);
            assert_eq!(geodata["data"][kind]["available"], false);
            assert_eq!(geodata["data"][kind]["updating"], false);
            assert!(geodata["data"][kind]["lastSuccess"].is_null());
            assert!(geodata["data"][kind]["nextCheck"].is_null());
            assert!(geodata["data"][kind]["lastError"].is_null());
            assert!(geodata["data"][kind]["etag"].is_null());
            assert!(geodata["data"][kind]["hash"].is_null());
        }

        let different = temporary.path().join("other");
        let rejected = request(
            "initialize",
            None,
            json!({"dataDir": different.to_str().unwrap()}),
        );
        assert_failure(&rejected);
        assert!(
            rejected["error"]
                .as_str()
                .unwrap()
                .contains("already initialized")
        );
        reset_registry();
    }

    #[test]
    fn envelope_and_payload_are_strict() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        for request in [
            r#"{"method":"version","payload":{},"extra":true}"#,
            r#"{"method":"version","payload":{"extra":true}}"#,
        ] {
            let response = invoke(request);
            assert_failure(&response);
            assert!(
                response["error"]
                    .as_str()
                    .unwrap()
                    .contains("unknown field `extra`")
            );
        }
        for request in [
            r#"{"method":"version"}"#,
            r#"{"payload":{}}"#,
            r#"{"method":"version","payload":null}"#,
            r#"{"method":"version","payload":{},"instanceId":"1"}"#,
            r#"{"method":"createInstance","payload":{},"instanceId":"1"}"#,
            r#"{"method":"getGeoDataState","payload":{},"instanceId":"1"}"#,
            r#"{"method":"validateConfig","payload":{"configYaml":"x"},"instanceId":"1"}"#,
            r#"{"method":"validateConfig","payload":{"configPath":"x"}}"#,
            r#"{"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"https://example.com/"},"instanceId":"1"}"#,
            r#"{"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"https://example.com/","extra":true}}"#,
            r#"{"method":"measureDelay","payload":{"configYamls":[],"timeout":5,"url":"https://example.com/"}}"#,
            r#"{"method":"measureDelay","payload":{"configYamls":[""],"timeout":5,"url":"https://example.com/"}}"#,
            r#"{"method":"measureDelay","payload":{"configYamls":["x"],"timeout":0,"url":"https://example.com/"}}"#,
            r#"{"method":"measureDelay","payload":{"configYamls":["x"],"timeout":31,"url":"https://example.com/"}}"#,
            r#"{"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"ftp://example.com/"}}"#,
            r#"{"method":"measureDelay","payload":{"configYaml":"x","timeout":5,"url":"https://example.com/","proxy":"http://127.0.0.1:18080"}}"#,
            r#"{"method":"getState","payload":{}}"#,
            r#"{"method":"getState","payload":{},"instanceId":null}"#,
            r#"{"method":"getState","payload":{},"instanceId":1}"#,
            r#"{"method":"getState","payload":{},"instanceId":"0"}"#,
            r#"{"method":"getState","payload":{},"instanceId":"01"}"#,
            r#"{"method":"getState","payload":{},"instanceId":"999999"}"#,
            r#"{"method":"missing","payload":{}}"#,
        ] {
            assert_failure(&invoke(request));
        }
        let legacy_concurrency = invoke(
            r#"{"method":"measureDelay","payload":{"configYamls":["x"],"timeout":5,"url":"https://example.com/","concurrency":1}}"#,
        );
        assert_failure(&legacy_concurrency);
        assert!(
            legacy_concurrency["error"]
                .as_str()
                .unwrap()
                .contains("concurrency")
        );
        let oversized_measure = request(
            "measureDelay",
            None,
            json!({
                "configYamls": vec!["x"; 6],
                "timeout": 5,
                "url": "https://example.com/",
            }),
        );
        assert_failure(&oversized_measure);
        assert!(
            oversized_measure["error"]
                .as_str()
                .unwrap()
                .contains("configYamls")
        );
        for method in ["start", "stop", "getState", "destroyInstance"] {
            let response = request(method, None, json!({}));
            assert_failure(&response);
            assert!(
                response["error"]
                    .as_str()
                    .unwrap()
                    .contains("instanceId is required")
            );
        }
    }

    #[test]
    fn byte_dispatch_preserves_utf8_for_chinese_and_emoji_requests() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let response =
            invoke_bytes(r#"{"method":"version","payload":{"备注":"你好😀"}}"#.as_bytes());
        let text = str::from_utf8(&response).unwrap();
        let json: Value = serde_json::from_str(text).unwrap();
        assert_failure(&json);
    }

    #[test]
    fn runtime_thread_cannot_reenter_invoke() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let response = thread::Builder::new()
            .name("arbitrary-runtime-name".to_owned())
            .spawn(|| {
                let _runtime_thread = RuntimeThreadGuard::enter();
                invoke_bytes(r#"{"method":"version","payload":{}}"#.as_bytes())
            })
            .unwrap()
            .join()
            .unwrap();
        let json: Value = serde_json::from_slice(&response).unwrap();
        assert_failure(&json);
        assert!(json["error"].as_str().unwrap().contains("runtime thread"));
    }

    #[test]
    fn engine_workers_preserve_invoke_admission_and_shutdown() {
        use crate::resources::observation::{self, ResourceKind, ResourceProbe};

        let (sent, received) = std::sync::mpsc::channel();
        let thread = thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let defaults = tokio::runtime::Builder::new_multi_thread().build().unwrap();
                let default_workers = defaults.metrics().num_workers();
                drop(defaults);

                let _engine_admission = RuntimeThreadGuard::enter();
                let runtime = engine_runtime_builder()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                assert_eq!(
                    runtime.handle().runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread,
                );
                assert_eq!(runtime.metrics().num_workers(), default_workers);
                let rejected = || {
                    assert!(is_runtime_thread());
                    let response: Value = serde_json::from_slice(&invoke_bytes(
                        br#"{"method":"version","payload":{}}"#,
                    ))
                    .unwrap();
                    assert_failure(&response);
                    assert!(
                        response["error"]
                            .as_str()
                            .unwrap()
                            .contains("runtime thread")
                    );
                };
                let probe = ResourceProbe::default();
                // Keep the handle outside block_on so Runtime::drop, rather
                // than awaiting the deliberately pending task, proves shutdown.
                #[allow(clippy::async_yields_async)]
                let pending = probe.scope_sync(|| {
                    runtime.block_on(async {
                        rejected();
                        let asynchronous = tokio::spawn(async move { rejected() });
                        let blocking = tokio::task::spawn_blocking(rejected);
                        tokio::time::timeout(Duration::from_secs(1), async {
                            asynchronous.await.unwrap();
                            blocking.await.unwrap();
                        })
                        .await
                        .unwrap();
                        let (started, ready) = oneshot::channel();
                        let pending = observation::spawn(async move {
                            let _session = observation::track(ResourceKind::Session);
                            let _ = started.send(());
                            std::future::pending::<()>().await;
                        });
                        tokio::time::timeout(Duration::from_secs(1), ready)
                            .await
                            .unwrap()
                            .unwrap();
                        pending
                    })
                });
                assert_eq!(probe.snapshot().current(ResourceKind::Task), 1);
                assert_eq!(probe.snapshot().current(ResourceKind::Session), 1);
                drop(runtime);
                assert!(pending.is_finished());
                drop(pending);
                assert!(probe.snapshot().is_idle());
                assert!(is_runtime_thread(), "worker exit cleared the engine marker");
            }));
            let _ = sent.send(result);
        });
        let result = received
            .recv_timeout(Duration::from_secs(3))
            .expect("runtime admission/shutdown regression exceeded three seconds");
        thread.join().unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[cfg(feature = "ffi")]
    #[test]
    fn null_invalid_utf8_and_oversized_input_return_json_failures() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        // SAFETY: null is explicitly accepted as an error case.
        let null_response = unsafe { VoleInvoke(ptr::null()) };
        assert!(!null_response.is_null());
        // SAFETY: response is a live Vole allocation.
        let null_json: Value =
            serde_json::from_str(unsafe { CStr::from_ptr(null_response) }.to_str().unwrap())
                .unwrap();
        unsafe { VoleFree(null_response) };
        assert_failure(&null_json);

        let invalid = [0xff_u8, 0];
        // SAFETY: invalid has a NUL terminator and readable bounded storage.
        let invalid_response = unsafe { VoleInvoke(invalid.as_ptr().cast()) };
        let invalid_json: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(invalid_response) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        unsafe { VoleFree(invalid_response) };
        assert_failure(&invalid_json);

        let mut oversized = vec![b' '; MAX_INVOKE_BYTES + 2];
        *oversized.last_mut().unwrap() = 0;
        // SAFETY: oversized is NUL-terminated and readable for the bounded scan.
        let oversized_response = unsafe { VoleInvoke(oversized.as_ptr().cast()) };
        let oversized_json: Value = serde_json::from_str(
            unsafe { CStr::from_ptr(oversized_response) }
                .to_str()
                .unwrap(),
        )
        .unwrap();
        unsafe { VoleFree(oversized_response) };
        assert_failure(&oversized_json);
    }

    #[test]
    fn update_config_invoke_shares_admission_and_keeps_lifecycle_command_serial() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let id = create_instance();
        let controller = registry().instance(&id).unwrap();
        assert_failure(&request(
            "updateConfig",
            Some(&id),
            json!({"configYaml":"rules: [MATCH,DIRECT]"}),
        ));
        let (handle, mut receiver) =
            ConfigApplyHandle::channel(tokio_util::sync::CancellationToken::new());
        let (_sent, completion) = tokio::sync::watch::channel(false);
        {
            let mut inner = lock(&controller.inner);
            for state in [
                LifecycleState::Preparing,
                LifecycleState::Prepared,
                LifecycleState::Starting,
                LifecycleState::Running,
            ] {
                inner.lifecycle.transition(state).unwrap();
            }
            inner.engine = Some(Engine {
                stop: None,
                thread: None,
                completion,
                config_apply: Some(handle.clone()),
            });
        }
        let occupied = handle.try_admit().unwrap();
        let busy = request(
            "updateConfig",
            Some(&id),
            json!({"extra":"invalid schema must not be decoded"}),
        );
        assert_eq!(busy["error"], "configuration application is busy");
        drop(occupied);
        let id2 = id.clone();
        let caller = thread::spawn(move || {
            request(
                "updateConfig",
                Some(&id2),
                json!({"configYaml":"rules: [MATCH,DIRECT]"}),
            )
        });
        let mut candidate = receiver.blocking_recv().unwrap();
        assert!(
            matches!(candidate.take_update(), ConfigUpdate::Replace(yaml) if yaml == "rules: [MATCH,DIRECT]")
        );
        let stopped = request("stop", Some(&id), json!({}));
        assert_failure(&stopped);
        assert!(stopped["error"].as_str().unwrap().contains("busy"));
        candidate.complete(Ok(()));
        assert_eq!(caller.join().unwrap()["success"], true);
        destroy_instance(&id);
        assert_registry_is_idle();
    }

    #[test]
    fn update_config_raw_string_budget_and_strict_shape_precede_decoding() {
        for value in ["", "plain", "界", "\\", "\n", "😀"] {
            let encoded = serde_json::to_string(value).unwrap();
            assert!(check_json_string_limit(&encoded, value.len()).is_ok());
            if !value.is_empty() {
                assert!(check_json_string_limit(&encoded, value.len() - 1).is_err());
            }
            assert_eq!(
                decode_update_yaml(&format!(r#"{{"configYaml":{encoded}}}"#)).unwrap(),
                value
            );
        }
        assert!(check_json_string_limit(r#""\u754c""#, 3).is_ok());
        assert!(check_json_string_limit(r#""\uD83D\uDE00""#, 4).is_ok());
        assert!(check_json_string_limit(r#""\uD83D\uDE00""#, 3).is_err());
        for invalid in [r#""\uD800""#, r#""\uDC00""#, "null", "1"] {
            assert!(check_json_string_limit(invalid, 32).is_err());
        }
        for payload in [
            r#"{"configYaml":"a","extra":1}"#,
            r#"{"configYaml":"a","configYaml":"b"}"#,
            r#"{"configYaml":null}"#,
            "{}",
        ] {
            assert!(decode_update_yaml(payload).is_err());
        }
        let max = crate::config::MAX_CONFIG_BYTES;
        let escaped = format!(r#"{{"configYaml":"{}"}}"#, r"\u0061".repeat(max + 1));
        assert!(decode_update_yaml(&escaped).is_err());
        // A raw input of arbitrary JSON shape cannot bypass method matching.
        assert!(
            dispatch_config_update(r#"{"method":"version","payload":{}}"#)
                .unwrap()
                .is_none()
        );
        assert!(dispatch_config_update(r#"{"method":"updateConfig","payload":{}}"#).is_err());
    }

    #[test]
    fn update_dns_network_raw_admission_is_bounded_before_value_or_registry_work() {
        let padded = format!(
            "{{{}\"generation\":1,\"system\":[],\"dhcp\":[]}}",
            " ".repeat(crate::dns::source::MAX_METADATA_BYTES)
        );
        for method in ["updateDnsNetwork", r"\u0075pdateDnsNetwork"] {
            let envelope = format!(r#"{{"payload":{padded},"method":"{method}"}}"#);
            let response = invoke(&envelope);
            assert_failure(&response);
            assert_eq!(
                response["error"],
                "invalid request: DNS network metadata exceeds 64 KiB"
            );
        }
        let overhead = format!(
            r#"{{"method":"updateDnsNetwork","payload":{{}},"instanceId":"{}"}}"#,
            "x".repeat(64 * 1024)
        );
        assert!(check_dns_network_envelope(&overhead).is_err());
        let unrelated = json!({"method":"validateConfig","payload":{"configYaml":"updateDnsNetwork".repeat(8192)}}).to_string();
        assert!(check_dns_network_envelope(&unrelated).is_ok());
    }

    #[test]
    fn update_dns_network_is_runtime_local_strict_and_monotonic() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let payload = json!({"generation":1,"system":[{"address":"203.0.113.53","interface":"physical0"}],"dhcp":[]});
        assert_failure(&request("updateDnsNetwork", None, payload.clone()));
        let _data = initialize_test_data_directory();
        assert_eq!(
            request("updateDnsNetwork", None, payload.clone())["success"],
            true
        );
        assert_eq!(
            request("updateDnsNetwork", None, payload.clone())["success"],
            true
        );
        assert_failure(&request("updateDnsNetwork", Some("1"), payload));
        assert_failure(&request(
            "updateDnsNetwork",
            None,
            json!({"generation":1,"system":[],"dhcp":[]}),
        ));
        assert_eq!(
            request(
                "updateDnsNetwork",
                None,
                json!({"generation":2,"system":[],"dhcp":[]})
            )["success"],
            true
        );
        assert_failure(&request(
            "updateDnsNetwork",
            None,
            json!({"generation":1,"system":[],"dhcp":[]}),
        ));
        assert_failure(&request(
            "updateDnsNetwork",
            None,
            json!({"generation":3,"system":[],"dhcp":[],"extra":true}),
        ));
        reset_registry();
    }

    #[test]
    fn start_accepts_only_config_yaml_and_removed_prepare_is_unknown() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let id = create_instance();
        for payload in [
            json!({}),
            json!({"configYaml":"proxies: []", "tunFd":7}),
            json!({"configYaml":"proxies: []", "tunFraming":"utun"}),
        ] {
            assert_failure(&request("start", Some(&id), payload));
        }
        assert_failure(&request(
            "prepare",
            Some(&id),
            json!({"configYaml":"proxies: []"}),
        ));
        assert_eq!(state(&id)["data"]["state"], "stopped");
        destroy_instance(&id);
    }

    #[test]
    fn config_yaml_input_is_strict_bounded_and_never_loaded_as_a_path() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();

        let uninitialized = request(
            "validateConfig",
            None,
            json!({"configYaml": "mixed-port: 10080\nproxies: [{name: unused, type: socks5, server: 127.0.0.1, port: 1081}]\nrules: ['MATCH,unused']"}),
        );
        assert_eq!(uninitialized["success"], true, "{uninitialized}");
        let uninitialized_measure = request(
            "measureDelay",
            None,
            json!({
                "configYamls": ["proxies: []"],
                "timeout": 5,
                "url": "https://example.com/",
            }),
        );
        assert_failure(&uninitialized_measure);
        assert!(
            uninitialized_measure["error"]
                .as_str()
                .unwrap()
                .contains("not initialized")
        );

        let _directory = initialize_test_data_directory();
        let legacy_path = request(
            "validateConfig",
            None,
            json!({"configPath": "/tmp/config-that-must-not-be-read.yaml"}),
        );
        assert_failure(&legacy_path);
        assert!(
            legacy_path["error"]
                .as_str()
                .unwrap()
                .contains("configPath")
        );

        let empty = request("validateConfig", None, json!({"configYaml": ""}));
        assert_failure(&empty);
        assert!(
            empty["error"]
                .as_str()
                .unwrap()
                .contains("configYaml is empty")
        );

        let path_like_yaml = request(
            "validateConfig",
            None,
            json!({"configYaml": "/tmp/config-that-must-not-be-read.yaml"}),
        );
        assert_failure(&path_like_yaml);
        assert!(!path_like_yaml["error"].as_str().unwrap().contains("open"));

        let oversized = request(
            "validateConfig",
            None,
            json!({"configYaml": "x".repeat(crate::config::MAX_CONFIG_BYTES + 1)}),
        );
        assert_failure(&oversized);
        assert!(oversized["error"].as_str().unwrap().contains("byte limit"));
        reset_registry();
    }

    #[test]
    fn invoke_accepts_five_max_sized_inline_yaml_documents() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = "\\".repeat(crate::config::MAX_CONFIG_BYTES);
        let request = serde_json::to_vec(&json!({
            "method": "measureDelay",
            "payload": {
                "configYamls": vec![config_yaml; measure_delay::MAX_MEASURE_CONFIGS],
                "timeout": 5,
                "url": "https://example.com/",
            },
        }))
        .unwrap();
        assert!(request.len() > 1024 * 1024);
        assert!(request.len() <= MAX_INVOKE_BYTES);

        let response: Value = serde_json::from_slice(&invoke_bytes(&request)).unwrap();
        assert_eq!(response["success"], true, "{response}");
        let results = response["data"]["results"].as_array().unwrap();
        assert_eq!(results.len(), measure_delay::MAX_MEASURE_CONFIGS);
        assert!(results.iter().all(|result| result["success"] == false));
        reset_registry();
    }

    #[test]
    fn validate_config_does_not_change_instance_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let instance_id = create_instance();
        let _directory = initialize_test_data_directory();
        let request = json!({
            "method": "validateConfig",
            "payload": {"configYaml": "not: [valid"},
        });
        assert_failure(&invoke(&request.to_string()));
        assert_eq!(state(&instance_id)["data"]["state"], "stopped");
        destroy_instance(&instance_id);
    }

    #[test]
    fn validate_config_allows_referenced_geodata_assets_to_be_missing() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = current_config(10080, "  - GEOSITE,cn,DIRECT\n  - MATCH,proxy");

        let response = request("validateConfig", None, json!({"configYaml": config_yaml}));
        assert_eq!(response["success"], true, "{response}");
        assert_registry_is_idle();
    }

    #[test]
    fn concurrent_validate_config_calls_return_the_same_result() {
        const CONCURRENT: usize = 12;

        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = mixed_config(10080);
        let request = Arc::new(
            json!({
                "method": "validateConfig",
                "payload": {"configYaml": config_yaml},
            })
            .to_string(),
        );
        let barrier = Arc::new(Barrier::new(CONCURRENT + 1));
        let threads: Vec<_> = (0..CONCURRENT)
            .map(|_| {
                let request = request.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    invoke(&request)
                })
            })
            .collect();
        barrier.wait();
        for thread in threads {
            let response = thread.join().unwrap();
            assert_eq!(response["success"], true, "{response}");
        }
        assert_registry_is_idle();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn start_keeps_missing_geodata_rules_dormant_and_reports_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = current_config(
            free_ports(1)[0],
            "  - GEOSITE,cn,DIRECT\n  - GEOIP,private,DIRECT,no-resolve\n  - MATCH,proxy",
        );
        let instance_id = create_instance();

        let prepared = request(
            "start",
            Some(&instance_id),
            json!({"configYaml": config_yaml}),
        );
        assert_eq!(prepared["success"], true, "{prepared}");
        let geodata = request("getGeoDataState", None, json!({}));
        assert_eq!(geodata["success"], true, "{geodata}");
        for kind in ["geosite", "geoip"] {
            assert_eq!(geodata["data"][kind]["required"], true);
            assert_eq!(geodata["data"][kind]["available"], false);
            assert!(
                geodata["data"][kind]["lastError"]
                    .as_str()
                    .is_some_and(|error| error.contains(".dat")),
                "{geodata}"
            );
        }

        assert_eq!(state(&instance_id)["data"]["state"], "running");
        assert_eq!(
            request("stop", Some(&instance_id), json!({}))["success"],
            true
        );
        let stopped = request("getGeoDataState", None, json!({}));
        assert_eq!(stopped["data"]["geosite"]["required"], false);
        assert_eq!(stopped["data"]["geoip"]["required"], false);
        destroy_instance(&instance_id);
        assert_registry_is_idle();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn config_driven_tun_failure_returns_stopped_and_keeps_host_fd() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let id = create_instance();
        let (original, peer) = UnixDatagram::pair().unwrap();
        original.set_nonblocking(true).unwrap();
        let before = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
        let yaml = format!(
            "tun:\n  enable: true\n  file-descriptor: {}\n  mtu: 1500\nproxies: [{{name: unused, type: socks5, server: 127.0.0.1, port: 1081}}]\nrules: ['MATCH,unused']",
            original.as_raw_fd()
        );
        for _ in 0..3 {
            assert_failure(&request("start", Some(&id), json!({"configYaml":yaml})));
            assert_eq!(state(&id)["data"]["state"], "stopped");
            assert!(lock(&registry().platform).tun_owner.is_none());
        }
        destroy_instance(&id);
        assert_eq!(
            unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) },
            before
        );
        original.send(b"ok").unwrap();
        let mut bytes = [0; 2];
        assert_eq!(peer.recv(&mut bytes).unwrap(), 2);
        assert_eq!(&bytes, b"ok");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn repeated_create_run_stop_destroy_leaves_registry_idle() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = mixed_config(free_ports(1)[0]);

        for cycle in 0..20 {
            let instance_id = create_instance();
            let prepared = request(
                "start",
                Some(&instance_id),
                json!({"configYaml": &config_yaml}),
            );
            assert_eq!(prepared["success"], true, "cycle {cycle}: {prepared}");
            let stopped = request("stop", Some(&instance_id), json!({}));
            assert_eq!(stopped["success"], true, "cycle {cycle}: {stopped}");
            destroy_instance(&instance_id);
            assert_failure(&state(&instance_id));
            assert!(lock(&registry().inner).instance.is_none());
            let platform = lock(&registry().platform);
            assert_eq!(platform.tun_owner, None);
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn public_lifecycle_is_singleton_until_destroyed() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let port = free_ports(1)[0];
        let config_yaml = mixed_config(port);
        let first = create_instance();

        let rejected = request("createInstance", None, json!({}));
        assert_failure(&rejected);
        assert!(
            rejected["error"]
                .as_str()
                .unwrap()
                .contains("public lifecycle instance already exists")
        );

        let prepared = request("start", Some(&first), json!({"configYaml": config_yaml}));
        assert_eq!(prepared["success"], true, "{prepared}");
        probe_http_listener(port);
        assert_eq!(request("stop", Some(&first), json!({}))["success"], true);

        assert_failure(&request("createInstance", None, json!({})));
        destroy_instance(&first);
        let replacement = create_instance();
        assert!(parse_instance_id(&replacement).unwrap() > parse_instance_id(&first).unwrap());
        destroy_instance(&replacement);
    }

    #[test]
    fn same_instance_command_is_fail_fast() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let instance_id = create_instance();
        let controller = registry().instance(&instance_id).unwrap();
        let command = lock(&controller.command);
        let response = request("stop", Some(&instance_id), json!({}));
        assert_failure(&response);
        assert!(response["error"].as_str().unwrap().contains("is busy"));
        drop(command);
        destroy_instance(&instance_id);
    }

    #[test]
    fn android_protector_is_required_only_for_tun() {
        assert!(select_android_protector(false, None).unwrap().is_none());

        let missing = match select_android_protector(true, None) {
            Ok(_) => panic!("TUN must reject a missing Android protector"),
            Err(error) => error,
        };
        assert!(missing.message.contains("required for a TUN configuration"));

        let registered: Arc<dyn SocketProtector> = Arc::new(AcceptingProtector);
        let selected = select_android_protector(true, Some(&registered)).unwrap();
        assert!(selected.is_some());
        assert!(Arc::ptr_eq(&selected.unwrap(), &registered));

        assert!(ensure_android_protector_replaceable(None).is_ok());
        assert!(ensure_android_protector_replaceable(Some(7)).is_err());
    }

    #[test]
    fn tun_lease_is_held_during_internal_preparation_until_stop_or_destroy() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let instance_id = create_instance();
        let payload = json!({"configYaml": tun_config()});

        assert_eq!(
            prepare_private(&instance_id, payload.clone())["success"],
            true
        );
        assert_eq!(
            lock(&registry().platform).tun_owner,
            Some(parse_instance_id(&instance_id).unwrap())
        );

        assert_eq!(
            request("stop", Some(&instance_id), json!({}))["success"],
            true
        );
        assert_eq!(lock(&registry().platform).tun_owner, None);
        assert_eq!(prepare_private(&instance_id, payload)["success"], true);
        destroy_instance(&instance_id);
        assert_eq!(lock(&registry().platform).tun_owner, None);
    }

    #[test]
    fn panic_recovery_releases_the_public_tun_lease() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let instance_id = create_instance();
        let payload = json!({"configYaml": tun_config()});

        assert_eq!(
            prepare_private(&instance_id, payload.clone())["success"],
            true
        );
        let controller = registry().instance(&instance_id).unwrap();
        let result = invoke_instance_guarded(&controller, || -> Result<(), InvokeFailure> {
            panic!("test panic while holding a TUN lease")
        });
        assert!(result.unwrap_err().message.contains("panic caught"));
        assert_eq!(state(&instance_id)["data"]["state"], "stopped");
        assert_eq!(lock(&registry().platform).tun_owner, None);
        assert_eq!(prepare_private(&instance_id, payload)["success"], true);
        assert_eq!(
            request("stop", Some(&instance_id), json!({}))["success"],
            true
        );
        destroy_instance(&instance_id);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn panic_recovery_preserves_the_public_generation_until_destroy() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let _directory = initialize_test_data_directory();
        let config_yaml = mixed_config(free_ports(1)[0]);
        let first = create_instance();
        assert_eq!(
            request("start", Some(&first), json!({"configYaml": config_yaml}),)["success"],
            true
        );
        assert_eq!(state(&first)["data"]["state"], "running");

        let first_controller = registry().instance(&first).unwrap();
        let result = invoke_instance_guarded(&first_controller, || -> Result<(), InvokeFailure> {
            panic!("test panic")
        });
        assert!(result.unwrap_err().message.contains("panic caught"));
        let first_state = state(&first);
        assert_eq!(first_state["data"]["state"], "stopped");
        assert!(
            first_state["data"]["lastError"]
                .as_str()
                .unwrap()
                .contains("panic caught")
        );
        let first_inner = lock(&first_controller.inner);
        assert!(first_inner.engine.is_none());
        drop(first_inner);
        assert_failure(&request("createInstance", None, json!({})));

        destroy_instance(&first);
        assert!(first_controller.tombstoned.load(Ordering::Acquire));
        assert!(first_controller.stop().is_err());
        assert!(registry().instance(&first).is_err());
        let replacement = create_instance();
        assert!(parse_instance_id(&replacement).unwrap() > parse_instance_id(&first).unwrap());
        destroy_instance(&replacement);
    }

    #[test]
    fn admitted_destroy_panic_is_still_a_terminal_registry_barrier() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let instance_id = create_instance();
        let controller = registry().instance(&instance_id).unwrap();

        let result = invoke_instance_guarded(&controller, || {
            controller.destroy_with(|| -> Result<(), InvokeFailure> {
                panic!("test panic during destroy cleanup")
            })
        });

        assert!(result.unwrap_err().message.contains("panic caught"));
        assert!(controller.tombstoned.load(Ordering::Acquire));
        assert!(registry().instance(&instance_id).is_err());
        reset_registry();
    }

    #[test]
    fn concurrent_create_allows_exactly_one_public_instance() {
        const CONCURRENT: usize = 12;

        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let barrier = Arc::new(Barrier::new(CONCURRENT + 1));
        let threads: Vec<_> = (0..CONCURRENT)
            .map(|_| {
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    request("createInstance", None, json!({}))
                })
            })
            .collect();
        barrier.wait();
        let responses: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        let successes: Vec<_> = responses
            .iter()
            .filter(|response| response["success"] == true)
            .collect();
        assert_eq!(successes.len(), 1, "{responses:?}");
        for response in responses
            .iter()
            .filter(|response| response["success"] == false)
        {
            assert!(
                response["error"]
                    .as_str()
                    .unwrap()
                    .contains("public lifecycle instance already exists"),
                "{response}"
            );
        }
        let first = successes[0]["data"]["instanceId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(parse_instance_id(&first).unwrap(), 0);
        destroy_instance(&first);

        let replacement = create_instance();
        assert!(parse_instance_id(&replacement).unwrap() > parse_instance_id(&first).unwrap());
        destroy_instance(&replacement);
    }

    #[test]
    fn admitted_destroy_panic_joins_engine_before_returning_failure() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let id = create_instance();
        let controller = registry().instance(&id).unwrap();
        let (stop, receive) = oneshot::channel();
        let (sent, completion) = tokio::sync::watch::channel(false);
        let exited = Arc::new(AtomicBool::new(false));
        let observed = exited.clone();
        let worker = thread::spawn(move || {
            let _completion = EngineCompletion(sent);
            let _ = receive.blocking_recv();
            observed.store(true, Ordering::Release);
            Ok(())
        });
        {
            let mut inner = lock(&controller.inner);
            for state in [
                LifecycleState::Preparing,
                LifecycleState::Prepared,
                LifecycleState::Starting,
                LifecycleState::Running,
            ] {
                inner.lifecycle.transition(state).unwrap();
            }
            inner.engine = Some(Engine {
                stop: Some(stop),
                thread: Some(worker),
                completion,
                config_apply: None,
            });
        }
        let result = invoke_instance_guarded(&controller, || {
            controller.destroy_with(|| panic!("memory destroy fixture"))
        });
        assert!(result.is_err());
        assert!(exited.load(Ordering::Acquire));
        assert!(lock(&controller.inner).engine.is_none());
        assert_failure(&state(&id));
        assert_registry_is_idle();
    }

    #[test]
    fn foreground_destroy_waits_for_admitted_command_and_removes_instance() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_registry();
        let id = create_instance();
        let controller = registry().instance(&id).unwrap();
        let command = lock(&controller.command);
        let owner = controller.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = sent.send(owner.destroy_foreground());
        });
        assert!(received.recv_timeout(Duration::from_millis(10)).is_err());
        drop(command);
        received
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(controller.tombstoned.load(Ordering::Acquire));
        assert_failure(&state(&id));
        assert_registry_is_idle();
    }

    #[test]
    fn engine_completion_notifies_after_panic_and_join_reports_failure() {
        let (sent, mut received) = tokio::sync::watch::channel(false);
        let worker = thread::spawn(move || -> io::Result<()> {
            let _completion = EngineCompletion(sent);
            panic!("memory failure fixture");
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            if !*received.borrow() {
                received.changed().await.unwrap();
            }
        });
        assert!(*received.borrow());
        let mut engine = Engine {
            stop: None,
            thread: Some(worker),
            completion: received,
            config_apply: None,
        };
        assert!(engine.stop().is_err());
    }

    #[test]
    fn error_text_is_bounded_without_breaking_utf8() {
        let error = bounded_error("界".repeat(MAX_ERROR_BYTES));
        assert!(error.len() <= MAX_ERROR_BYTES);
        assert!(error.ends_with("..."));
    }

    fn assert_registry_is_idle() {
        assert!(lock(&registry().inner).instance.is_none());
        let platform = lock(&registry().platform);
        assert_eq!(platform.tun_owner, None);
    }

    #[test]
    fn update_http_addendum_preserves_optional_clear_and_its_separate_byte_limit() {
        let input = decode_update_input(
            r#"{"configYaml":"rules: ['MATCH,DIRECT']","httpConfigYaml":"rewrite: []"}"#,
        )
        .unwrap();
        assert_eq!(input.http_config_yaml.as_deref(), Some("rewrite: []"));
        assert_eq!(
            decode_update_input(r#"{"configYaml":"x","httpConfigYaml":""}"#)
                .unwrap()
                .http_config_yaml
                .as_deref(),
            Some("")
        );
        assert!(decode_update_input(r#"{"configYaml":"x","httpConfigYaml":1}"#).is_err());
        let input = format!(
            r#"{{"configYaml":"x","httpConfigYaml":"{}"}}"#,
            "x".repeat(crate::http_processing::MAX_ADDENDUM + 1)
        );
        assert!(decode_update_input(&input).is_err());
    }
}
