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

#[derive(Default)]
struct CoreInner {
    lifecycle: Lifecycle,
    prepared: Option<PreparedState>,
    engine: Option<Engine>,
    last_error: String,
    tun_lease: Option<TunLease>,
    apple_tun_allocator_relief: Option<AppleTunAllocatorRelief>,
}

struct PreparedState {
    core: PreparedCore,
    protector: Option<Arc<dyn SocketProtector>>,
}

struct Engine {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
    completion: tokio::sync::watch::Receiver<bool>,
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
struct AppleTunAllocatorRelief {
    state: Arc<AppleTunAllocatorReliefState>,
}

struct AppleTunAllocatorReliefState {
    relieved: AtomicBool,
}

impl AppleTunAllocatorRelief {
    fn new(has_tun: bool) -> Option<Self> {
        #[cfg(any(target_os = "ios", target_os = "tvos"))]
        if has_tun {
            return Some(Self {
                state: Arc::new(AppleTunAllocatorReliefState {
                    relieved: AtomicBool::new(false),
                }),
            });
        }
        let _ = has_tun;
        None
    }

    fn relieve(&self) {
        if !self.state.relieved.swap(true, Ordering::AcqRel) {
            relieve_apple_tun_allocator();
        }
    }
}

impl Drop for AppleTunAllocatorReliefState {
    fn drop(&mut self) {
        if !self.relieved.swap(true, Ordering::AcqRel) {
            relieve_apple_tun_allocator();
        }
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConfigYamlPayload {
    config_yaml: String,
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
                return Ok(current.directory.clone());
            }
            return Err(InvokeFailure::invalid_state(
                "Vole dataDir is already initialized to a different path",
            ));
        }
        *current = Some(RuntimeData {
            directory: initialized.clone(),
            geodata,
        });
        Ok(initialized)
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

    fn create_instance(&self) -> Result<Arc<CoreController>, InvokeFailure> {
        let mut inner = lock(&self.inner);
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

fn dispatch_bytes(request: &[u8]) -> Result<InvokeResponse, InvokeFailure> {
    if request.len() > MAX_INVOKE_BYTES {
        return Err(InvokeFailure::invalid_request(format!(
            "Invoke envelope exceeds the {MAX_INVOKE_BYTES}-byte limit"
        )));
    }
    let request = str::from_utf8(request)
        .map_err(|_| InvokeFailure::invalid_request("request is not valid UTF-8"))?;
    let envelope: RequestEnvelope =
        serde_json::from_str(request).map_err(InvokeFailure::invalid_request)?;
    if !envelope.payload.is_object() {
        return Err(InvokeFailure::invalid_request("payload must be an object"));
    }

    let data = match envelope.method.as_str() {
        "initialize" => {
            require_instance_omitted(&envelope)?;
            let payload: InitializePayload = decode_payload(envelope.payload)?;
            let directory = registry().initialize_data_directory(&payload.data_dir)?;
            json!({"dataDir": directory.root().to_string_lossy()})
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
            validate_config(payload.config_yaml)?;
            json!({})
        }
        "measureDelay" => {
            require_instance_omitted(&envelope)?;
            let payload: measure_delay::MeasureDelayPayload = decode_payload(envelope.payload)?;
            let results = measure_delay::measure_delay(payload)?;
            json!({"results": results})
        }
        "start" => {
            let controller = require_instance(&envelope)?;
            let payload: ConfigYamlPayload = decode_payload(envelope.payload)?;
            invoke_instance_guarded(&controller, || {
                controller.start(payload.config_yaml)?;
                Ok(json!({}))
            })?
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

    fn prepare_locked(&self, config_yaml: String) -> Result<(), InvokeFailure> {
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
        let config = parse_config_yaml(&config_yaml)?;
        let dispatch = crate::logging::dispatch(config.log_level);
        let _logging = tracing::dispatcher::set_default(&dispatch);
        drop(config_yaml);
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
        let allocator_relief = AppleTunAllocatorRelief::new(has_tun);
        {
            let mut inner = lock(&self.inner);
            inner.last_error.clear();
            inner
                .lifecycle
                .transition(LifecycleState::Preparing)
                .map_err(InvokeFailure::from)?;
            inner.tun_lease = tun_lease;
            inner.apple_tun_allocator_relief = allocator_relief;
        }

        let prepared = (|| {
            let limits = ResourceLimits::default();
            let geodata_manager = registry().geodata_manager()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(InvokeFailure::from)?;
            let prepared = runtime
                .block_on(PreparedCore::prepare_config(
                    config,
                    geodata_manager,
                    &SystemResolver,
                    limits,
                ))
                .map_err(InvokeFailure::from);
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
                        observe_apple_tun_memory(has_tun, "prepare-complete");
                        Ok(())
                    }
                    Err(error) => reset_failed_operation(&mut inner, "prepare-transition-failed")
                        .and(Err(error)),
                }
            }
            Err(error) => reset_failed_operation(&mut inner, "prepare-failed").and(Err(error)),
        }
    }

    fn start(&self, config_yaml: String) -> Result<(), InvokeFailure> {
        let _command = self.try_command()?;
        self.prepare_locked(config_yaml)?;
        let result = self.start_prepared_locked();
        if result.is_err() {
            reset_failed_operation(&mut lock(&self.inner), "start-failed")?;
        }
        result
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
            let allocator_relief = inner.apple_tun_allocator_relief.clone();
            (prepared, tun, has_tun, allocator_relief)
        };

        let dialer = prepared
            .protector
            .clone()
            .map_or_else(Dialer::default, |protector| {
                Dialer::default().with_protector(protector)
            });
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
        };

        match startup_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {
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
                observe_apple_tun_memory(has_tun, "start-complete");
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
                    observe_apple_tun_memory(had_tun, "stop-complete");
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
                    observe_apple_tun_memory(had_tun, "stop-complete");
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
        observe_apple_tun_memory(had_tun, "panic-recovery");
        clear_instance_leases(&mut inner);
        Ok(())
    }
}

fn clear_instance_leases(inner: &mut CoreInner) {
    // Prepared-only paths own the final allocator-relief handle here. Running
    // paths share it with the engine, whose completion performs relief first.
    inner.apple_tun_allocator_relief = None;
    inner.tun_lease = None;
}

fn observe_apple_tun_memory(has_tun: bool, stage: &'static str) {
    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    if has_tun {
        crate::platform::process_memory::observe(stage);
    }
    let _ = (has_tun, stage);
}

fn relieve_apple_tun_allocator() {
    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    crate::platform::process_memory::relieve_allocator_pressure();
}

#[cfg(target_os = "android")]
pub(crate) fn replace_android_socket_protector(
    protector: Option<Arc<dyn SocketProtector>>,
) -> Result<(), String> {
    registry().replace_android_socket_protector(protector)
}

fn validate_config(config_yaml: String) -> Result<(), InvokeFailure> {
    let config = parse_config_yaml(&config_yaml)?;
    drop(config_yaml);
    PreparedCore::validate_config(config).map_err(InvokeFailure::from)
}

fn parse_config_yaml(config_yaml: &str) -> Result<Config, InvokeFailure> {
    if config_yaml.is_empty() {
        return Err(InvokeFailure::invalid_request("configYaml is empty"));
    }
    Config::parse_yaml(config_yaml.as_bytes()).map_err(InvokeFailure::from)
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
    allocator_relief: Option<AppleTunAllocatorRelief>,
}

fn run_engine(
    context: EngineContext,
    prepared: PreparedCore,
    tun: Option<InvokeTun>,
    dialer: Dialer,
    stop: oneshot::Receiver<()>,
    startup: SyncSender<Result<(), InvokeFailure>>,
) -> io::Result<()> {
    let EngineContext {
        instance_id,
        has_tun,
        allocator_relief,
    } = context;
    tracing::info!(instance_id, has_tun, "Vole runtime engine starting");
    let result = run_engine_inner(instance_id, has_tun, prepared, tun, dialer, stop, startup);
    observe_apple_tun_memory(has_tun, "stop-complete");
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
    startup: SyncSender<Result<(), InvokeFailure>>,
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
        let running = match started {
            Ok(running) => running,
            Err(error) => {
                let kind = error.kind();
                let message = error.to_string();
                let _ = startup.send(Err(InvokeFailure::from(error)));
                return Err(io::Error::new(kind, message));
            }
        };
        tracing::info!(instance_id, has_tun, "Vole runtime engine started");
        if startup.send(Ok(())).is_err() {
            return running.stop().await;
        }
        running
            .run_until_shutdown(wait_for_engine_shutdown(stop, has_tun))
            .await
    })
}

async fn wait_for_engine_shutdown(stop: oneshot::Receiver<()>, has_tun: bool) -> io::Result<()> {
    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    let mut stop = stop;
    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    if has_tun {
        let interval = crate::platform::process_memory::TELEMETRY_INTERVAL;
        let first_tick = tokio::time::Instant::now() + interval;
        let mut telemetry = tokio::time::interval_at(first_tick, interval);
        telemetry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stop => return Ok(()),
                _ = telemetry.tick() => observe_apple_tun_memory(true, "running"),
            }
        }
    }
    let _ = has_tun;
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
    observe_apple_tun_memory(had_tun, telemetry_stage);
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
        let result = controller.prepare_locked(payload.config_yaml);
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
}
