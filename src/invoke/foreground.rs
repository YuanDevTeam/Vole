//! Foreground lifecycle is an Invoke operation; CLI transports only options.
use super::{
    CoreController, InvokeFailure, StartupConfig, invoke_instance_guarded, lock, registry,
};
mod input;
mod overrides;
pub(super) use overrides::ControllerOverrides;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::{
    Event, Level, Metadata, Subscriber,
    field::{Field, Visit},
    level_filters::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};
use zeroize::Zeroizing;

const HELP: &str = "Vole standalone proxy core\n\
Usage: vole [-d <data-dir>] [-f <config-file>] [-config <base64>] [-age-secret-key <key>] [-ext-ctl <address>] [-ext-ctl-tls <address>] [-secret <token>] [-http-config <file>] [-http-ca <file>] [-t] [-v] [-h]\n\
  -d <data-dir>     Data directory (default: home/.config/vole)\n\
  -f <config-file>  Configuration file; - reads stdin (default: <data-dir>/config.yaml)\n\
  -config <base64>  Base64-encoded configuration; nonempty text takes priority\n\
  -age-secret-key <key>  AGE identity for an encrypted configuration\n\
  -ext-ctl <address>  Override the HTTP Controller address when nonempty\n\
  -ext-ctl-tls <address>  Override the TLS Controller address when nonempty\n\
  -secret <token>   Override Controller authentication when nonempty\n\
  -http-config <file>  Explicit HTTP processing addendum (optional)\n\
  -http-ca <file>   Private CA JSON file for selected HTTPS processing\n\
  -t               Validate configuration and exit\n\
  -v               Print software version and build identity\n\
  -h               Print this help\n";

/// Lossless native paths in Invoke metadata. Ordinary hosts may use a string.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InvokePath {
    Text(String),
    #[cfg(unix)]
    Unix(UnixPath),
    #[cfg(windows)]
    Windows(WindowsPath),
}
#[cfg(unix)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnixPath {
    unix_bytes: Vec<u8>,
}
#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WindowsPath {
    windows_wide: Vec<u16>,
}
impl From<PathBuf> for InvokePath {
    fn from(path: PathBuf) -> Self {
        if let Some(text) = path.to_str() {
            return Self::Text(text.to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::Unix(UnixPath {
                unix_bytes: path.as_os_str().as_bytes().to_vec(),
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            Self::Windows(WindowsPath {
                windows_wide: path.as_os_str().encode_wide().collect(),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            unreachable!("native path encoding is unsupported")
        }
    }
}
impl InvokePath {
    pub(crate) fn into_path(self) -> PathBuf {
        match self {
            Self::Text(value) => PathBuf::from(value),
            #[cfg(unix)]
            Self::Unix(value) => {
                use std::os::unix::ffi::OsStringExt;
                OsString::from_vec(value.unix_bytes).into()
            }
            #[cfg(windows)]
            Self::Windows(value) => {
                use std::os::windows::ffi::OsStringExt;
                OsString::from_wide(&value.windows_wide).into()
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ForegroundPayload {
    action: ForegroundAction,
    #[serde(default)]
    data_dir: Option<InvokePath>,
    #[serde(default)]
    config_path: Option<InvokePath>,
    #[serde(default, deserialize_with = "input::private_text")]
    config_string: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "input::private_text")]
    age_secret_key: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "input::private_text")]
    external_controller: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "input::private_text")]
    external_controller_tls: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "input::private_text")]
    secret: Option<Zeroizing<String>>,
    #[serde(default)]
    http_config_path: Option<InvokePath>,
    #[serde(default)]
    http_ca_path: Option<InvokePath>,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ForegroundAction {
    Run,
    Validate,
    Help,
}
struct PathOptions {
    data_dir: Option<PathBuf>,
    config_file: Option<PathBuf>,
}
fn nonempty_path(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}
fn option_path(value: Option<InvokePath>, environment: &str) -> Option<PathBuf> {
    match value {
        Some(value) => {
            let path = value.into_path();
            (!path.as_os_str().is_empty()).then_some(path)
        }
        None => nonempty_path(std::env::var_os(environment)),
    }
}
fn failure(stage: &str) -> InvokeFailure {
    InvokeFailure::new(stage)
}
fn io_failure(stage: &str, error: io::Error) -> InvokeFailure {
    InvokeFailure::new(format!("{stage} failed ({:?})", error.kind()))
}
static FOREGROUND: Mutex<()> = Mutex::new(());

pub(super) fn check_envelope(request: &str) -> Result<(), InvokeFailure> {
    input::check_envelope(request)
}

pub(super) fn execute(payload: ForegroundPayload) -> Result<Value, InvokeFailure> {
    if matches!(payload.action, ForegroundAction::Help) {
        return Ok(json!({"output":"","diagnostics":HELP}));
    }
    if payload.http_ca_path.is_some() && payload.http_config_path.is_none() {
        return Err(failure("httpCaPath requires httpConfigPath"));
    }
    let _lease = if matches!(payload.action, ForegroundAction::Run) {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(failure(
                "foreground run requires a synchronous caller outside Tokio",
            ));
        }
        let lease = match FOREGROUND.try_lock() {
            Ok(lease) => lease,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(failure("foreground is already running"));
            }
        };
        Some(lease)
    } else {
        None
    };
    let source = input::options(payload.config_string, payload.age_secret_key)?;
    let options = PathOptions {
        data_dir: option_path(payload.data_dir, "VOLE_HOME_DIR"),
        config_file: option_path(payload.config_path, "VOLE_CONFIG_FILE"),
    };
    let cwd = std::env::current_dir().map_err(|e| io_failure("resolve working directory", e))?;
    let paths = Paths::resolve(&options, &cwd, &PathDefaults::environment())
        .map_err(|e| io_failure("resolve paths", e))?;
    let http_input = payload
        .http_config_path
        .map(|path| {
            let path = path.into_path();
            if path.as_os_str().is_empty() || path == Path::new("-") {
                return Err(failure("HTTP configuration requires an explicit file path"));
            }
            let path = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            let bytes = read_config_limit(&path, crate::http_processing::MAX_ADDENDUM)
                .map_err(|error| io_failure("read HTTP configuration", error))?;
            String::from_utf8(bytes)
                .map(|yaml| (yaml, path))
                .map_err(|_| failure("HTTP configuration is not UTF-8"))
        })
        .transpose()?;
    let http_yaml = http_input.as_ref().map(|(yaml, _)| yaml.as_str());
    // Stdin belongs to the foreground request. Default OS Ctrl+C handling is
    // preserved while it is still supplying its bounded configuration input.
    let input = input::MainInput::read(source.config, source.key, &paths, || {
        read_bounded(io::stdin().lock())
    })?;
    if matches!(payload.action, ForegroundAction::Validate) {
        let config = Zeroizing::new(input.into_yaml(None)?);
        validate_yaml(&config, &paths.data_dir, http_yaml)?;
        let external = http_yaml
            .filter(|input| !input.is_empty())
            .map(crate::http_processing::config::Document::parse)
            .transpose()
            .map_err(|_| failure("invalid HTTP processing configuration"))?
            .is_some_and(|document| document.unresolved_count() != 0);
        return Ok(
            json!({"output":"configuration valid\n","diagnostics":if external {"HTTP external resources are not validated\n"} else {""}}),
        );
    }
    // Like Mihomo, -t validates the source and returns before run-only overrides.
    let overrides = ControllerOverrides::read(
        payload.external_controller,
        payload.external_controller_tls,
        payload.secret,
    )?;
    let dispatch = tracing::Dispatch::new(StderrSubscriber::new());
    let _logging = tracing::dispatcher::set_default(&dispatch);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| io_failure("create foreground runtime", e))?;
    let ca = read_http_ca(payload.http_ca_path, http_yaml, &cwd)?;
    runtime.block_on(async {
        let signals =
            ShutdownSignals::register().map_err(|e| io_failure("register shutdown signals", e))?;
        let shutdown = signals.wait();
        tokio::pin!(shutdown);
        let cancellation = tokio_util::sync::CancellationToken::new();
        let decoding_cancellation = cancellation.clone();
        let mut decoding = tokio::task::spawn_blocking(move || {
            input
                .into_yaml(Some(&decoding_cancellation))
                .map(Zeroizing::new)
        });
        let mut yaml = tokio::select! {
            biased;
            signal = &mut shutdown => {
                cancellation.cancel();
                let _ = decoding.await.map_err(|_| failure("configuration decoder failed"))?;
                signal.map_err(|e| io_failure("shutdown signal", e))?;
                return Ok(());
            }
            result = &mut decoding => {
                result.map_err(|_| failure("configuration decoder failed"))??
            }
        };
        registry()
            .initialize_path(&paths.data_dir)
            .map_err(|_| failure("data directory initialization failed"))?;
        let controller = registry().create_instance()?;
        let mut cleanup = ForegroundInstance(Some(controller.clone()));
        let context = http_input
            .as_ref()
            .map(|(_, path)| super::http::HttpContextInput {
                base_dir: path.parent().map(|path| path.to_owned().into()),
                ca,
            });
        let (http_config_yaml, source_file) = http_input.unzip();
        let startup = StartupConfig::Input(super::http::StartPayload {
            config_yaml: std::mem::take(&mut *yaml),
            http_config_yaml,
            http_context: context,
            source_file,
            cancellation: Some(cancellation.clone()),
            foreground_overrides: overrides,
        });
        let result = run_controller(controller, startup, shutdown, cancellation).await;
        let stopped = cleanup.destroy();
        result.and(stopped)
    })?;
    Ok(json!({"output":"","diagnostics":""}))
}

fn read_http_ca(
    path: Option<InvokePath>,
    http_yaml: Option<&str>,
    cwd: &Path,
) -> Result<Option<crate::http_processing::private_context::CaMaterial>, InvokeFailure> {
    let Some(path) = path else { return Ok(None) };
    let input = http_yaml.ok_or_else(|| failure("httpCaPath requires httpConfigPath"))?;
    let enabled = !input.is_empty()
        && crate::http_processing::config::Document::parse(input)
            .map_err(|_| failure("invalid HTTP processing configuration"))?
            .mitm
            .enabled;
    if !enabled {
        return Ok(None);
    }
    let path = path.into_path();
    let path = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    crate::http_processing::private_context::CaMaterial::read_file(&path)
        .map(Some)
        .map_err(|_| failure("private HTTP CA input failed"))
}

fn validate_yaml(yaml: &str, directory: &Path, http: Option<&str>) -> Result<(), InvokeFailure> {
    let mut config = super::parse_config_yaml_with_directory(yaml, Some(directory))
        .map_err(|_| failure("invalid configuration"))?;
    config
        .set_http_config(http)
        .map_err(|_| failure("invalid HTTP processing configuration"))?;
    crate::runtime::PreparedCore::validate_config(config)
        .map_err(|_| failure("invalid configuration"))
}
struct ForegroundInstance(Option<Arc<CoreController>>);
impl ForegroundInstance {
    fn destroy(&mut self) -> Result<(), InvokeFailure> {
        self.0
            .take()
            .map_or(Ok(()), |controller| {
                invoke_instance_guarded(&controller, || controller.destroy_foreground())
            })
            .map_err(|_| failure("foreground cleanup failed"))
    }
}
impl Drop for ForegroundInstance {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

async fn run_controller(
    controller: Arc<CoreController>,
    config: StartupConfig,
    shutdown: impl std::future::Future<Output = io::Result<()>>,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<(), InvokeFailure> {
    tokio::pin!(shutdown);
    let starting = controller.clone();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let mut startup = tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            invoke_instance_guarded(&starting, || starting.start_config(config))
        })
    });
    if !await_startup(&mut startup, shutdown.as_mut(), Some(&cancellation)).await? {
        return Ok(());
    }
    // Copy a completion subscription without holding command admission while
    // waiting. The owner may still getState/stop/destroy through ordinary Invoke.
    let mut completion = {
        let _command = lock(&controller.command);
        if controller.tombstoned.load(Ordering::Acquire) {
            return Ok(());
        }
        let inner = lock(&controller.inner);
        if inner.lifecycle.state() == crate::LifecycleState::Stopped {
            return Ok(());
        }
        inner
            .engine
            .as_ref()
            .ok_or_else(|| failure("core runtime is missing"))?
            .completion
            .clone()
    };
    if !*completion.borrow() {
        tokio::select! {
            biased;
            changed=completion.changed()=> { let _=changed; },
            signal=&mut shutdown=>return signal.map_err(|e|io_failure("shutdown signal",e)),
        }
    }
    // Joining is authoritative, including panics. Preserve its failure before
    // destroy clears lifecycle state or removes the registry slot.
    let _command = lock(&controller.command);
    if controller.tombstoned.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut inner = lock(&controller.inner);
    super::refresh_runtime_status(&mut inner);
    if inner.lifecycle.state() == crate::LifecycleState::Stopped {
        Ok(())
    } else {
        Err(failure("core runtime exited unexpectedly"))
    }
}

async fn await_startup(
    startup: &mut tokio::task::JoinHandle<Result<(), InvokeFailure>>,
    shutdown: std::pin::Pin<&mut impl std::future::Future<Output = io::Result<()>>>,
    cancellation: Option<&tokio_util::sync::CancellationToken>,
) -> Result<bool, InvokeFailure> {
    tokio::select! {
        biased;
        signal=shutdown=> {
            // Startup is joined even when shutdown arrives first.
            let cancelled_startup = cancellation.is_some() && !startup.is_finished();
            if let Some(cancellation) = cancellation { cancellation.cancel(); }
            let result = startup.await.map_err(|_|failure("core startup worker failed"))?;
            if !cancelled_startup {
                result.map_err(|_|failure("core startup failed"))?;
            }
            signal.map_err(|e|io_failure("shutdown signal",e))?;
            Ok(false)
        }
        result=&mut *startup=> {
            result.map_err(|_|failure("core startup worker failed"))?
                .map_err(|_|failure("core startup failed"))?;
            Ok(true)
        }
    }
}

#[derive(Default)]
struct PathDefaults {
    home: Option<PathBuf>,
    xdg: Option<PathBuf>,
}

impl PathDefaults {
    fn environment() -> Self {
        #[cfg(windows)]
        let home = std::env::var_os("USERPROFILE");
        #[cfg(not(windows))]
        let home = std::env::var_os("HOME");
        Self {
            home: nonempty_path(home),
            xdg: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Paths {
    data_dir: PathBuf,
    config_file: PathBuf,
    stdin: bool,
}

impl Paths {
    fn resolve(
        options: &PathOptions,
        launch_dir: &Path,
        defaults: &PathDefaults,
    ) -> io::Result<Self> {
        if !launch_dir.is_absolute() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let absolute = |path: &Path| {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                clean_path(&launch_dir.join(path))
            }
        };
        let data_dir = match options.data_dir.as_deref() {
            Some(path) => absolute(path),
            None => {
                let home = absolute(defaults.home.as_deref().unwrap_or(launch_dir));
                let default = home.join(".config/vole");
                if fs::metadata(&default).is_err() {
                    defaults
                        .xdg
                        .as_deref()
                        .map_or(default, |xdg| absolute(xdg).join("vole"))
                } else {
                    default
                }
            }
        };
        let stdin = options.config_file.as_deref() == Some(Path::new("-"));
        let config_file = if stdin {
            data_dir.join("config.yaml")
        } else {
            options
                .config_file
                .as_deref()
                .map_or_else(|| data_dir.join("config.yaml"), absolute)
        };
        if !data_dir.is_absolute() || !config_file.is_absolute() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            data_dir,
            config_file,
            stdin,
        })
    }
}

fn clean_path(path: &Path) -> PathBuf {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            component => clean.push(component.as_os_str()),
        }
    }
    clean
}
fn read_config(path: &Path) -> io::Result<Vec<u8>> {
    read_config_limit(path, crate::config::MAX_CONFIG_BYTES)
}
fn read_config_limit(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    require_regular(&metadata)?;
    if metadata.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration exceeds byte limit",
        ));
    }
    let file = open_regular(path)?;
    read_bounded_limit(file, limit)
}

fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // A replacement FIFO between metadata and open must not block while
        // waiting for a writer. Regular files ignore this nonblocking flag.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    require_regular(&file.metadata()?)?;
    Ok(file)
}

fn require_regular(metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration must be a regular file",
        ))
    }
}

fn read_bounded(reader: impl Read) -> io::Result<Vec<u8>> {
    read_bounded_limit(reader, crate::config::MAX_CONFIG_BYTES)
}
fn read_bounded_limit(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut config = Vec::new();
    reader.take((limit + 1) as u64).read_to_end(&mut config)?;
    if config.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration exceeds byte limit",
        ));
    }
    Ok(config)
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn register() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn wait(mut self) -> io::Result<()> {
        let received = tokio::select! {
            received = self.interrupt.recv() => received,
            received = self.terminate.recv() => received,
        };
        received.ok_or_else(|| io::Error::other("shutdown signal stream closed"))
    }
}

#[cfg(windows)]
struct ShutdownSignals {
    interrupt: tokio::signal::windows::CtrlC,
    break_signal: tokio::signal::windows::CtrlBreak,
}

#[cfg(windows)]
impl ShutdownSignals {
    fn register() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::windows::ctrl_c()?,
            break_signal: tokio::signal::windows::ctrl_break()?,
        })
    }

    async fn wait(mut self) -> io::Result<()> {
        let received = tokio::select! {
            received = self.interrupt.recv() => received,
            received = self.break_signal.recv() => received,
        };
        received.ok_or_else(|| io::Error::other("shutdown signal stream closed"))
    }
}

#[cfg(not(any(unix, windows)))]
struct ShutdownSignals;

#[cfg(not(any(unix, windows)))]
impl ShutdownSignals {
    fn register() -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn wait(self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

const LOG_BYTES: usize = 512;
const LOG_EVENTS_PER_SECOND: u32 = 64;

struct StderrSubscriber {
    next_span: AtomicU64,
    rate: Mutex<(Instant, u32)>,
}

impl StderrSubscriber {
    fn new() -> Self {
        Self {
            next_span: AtomicU64::new(1),
            rate: Mutex::new((Instant::now(), 0)),
        }
    }

    fn accepts(metadata: &Metadata<'_>) -> bool {
        let target = metadata.target();
        metadata.is_event()
            && *metadata.level() <= Level::DEBUG
            && (target == "vole"
                || target.starts_with("vole::")
                || target == "vole_netstack"
                || target.starts_with("vole_netstack::"))
    }

    fn admit(&self) -> bool {
        let Ok(mut rate) = self.rate.lock() else {
            return false;
        };
        if rate.0.elapsed() >= Duration::from_secs(1) {
            *rate = (Instant::now(), 0);
        }
        if rate.1 >= LOG_EVENTS_PER_SECOND {
            return false;
        }
        rate.1 += 1;
        true
    }
}

impl Subscriber for StderrSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        Self::accepts(metadata)
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if Self::accepts(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::DEBUG)
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        loop {
            let id = self.next_span.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return Id::from_u64(id);
            }
        }
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if !Self::accepts(event.metadata()) || !self.admit() {
            return;
        }
        use fmt::Write as _;

        let mut line = LogLine::new();
        _ = write!(
            line,
            "vole: [{}] {}",
            event.metadata().level(),
            event.metadata().target()
        );
        event.record(&mut NumericFields(&mut line));
        _ = writeln!(io::stderr().lock(), "{}", line.as_str());
    }
}

struct NumericFields<'a>(&'a mut LogLine);

impl Visit for NumericFields<'_> {
    fn record_u64(&mut self, field: &Field, value: u64) {
        use fmt::Write as _;
        if public_numeric_field(field.name()) {
            _ = write!(self.0, " {}={value}", field.name());
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        use fmt::Write as _;
        if public_numeric_field(field.name()) {
            _ = write!(self.0, " {}={value}", field.name());
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        use fmt::Write as _;
        if public_numeric_field(field.name()) {
            _ = write!(self.0, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn fmt::Debug) {}
    fn record_str(&mut self, _field: &Field, _value: &str) {}
}

fn public_numeric_field(name: &str) -> bool {
    matches!(
        name,
        "mtu" | "packet_queue" | "event_queue" | "cancelled" | "panicked" | "dns_hijack" | "ipv6"
    ) || name.starts_with("current_")
        || name.starts_with("peak_")
        || [
            "_current",
            "_peak",
            "_count",
            "_dropped",
            "_drops",
            "_bytes",
            "_capacity",
            "_limit",
            "_ms",
            "_seconds",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

struct LogLine {
    bytes: [u8; LOG_BYTES],
    len: usize,
}

impl LogLine {
    fn new() -> Self {
        Self {
            bytes: [0; LOG_BYTES],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        // Writes append complete UTF-8 characters only.
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for LogLine {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for character in text.chars().filter(|character| !character.is_control()) {
            let mut buffer = [0; 4];
            let character = character.encode_utf8(&mut buffer);
            if self.len + character.len() > self.bytes.len() {
                break;
            }
            self.bytes[self.len..self.len + character.len()].copy_from_slice(character.as_bytes());
            self.len += character.len();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn options(data: Option<PathBuf>, config: Option<PathBuf>) -> PathOptions {
        PathOptions {
            data_dir: data,
            config_file: config,
        }
    }
    #[test]
    fn paths_resolve_independently_from_launch_directory() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(
            &options(
                Some("data/../state".into()),
                Some("configs/file.yaml".into()),
            ),
            dir.path(),
            &PathDefaults::default(),
        )
        .unwrap();
        assert_eq!(paths.data_dir, dir.path().join("state"));
        assert_eq!(paths.config_file, dir.path().join("configs/file.yaml"));
        let defaults = Paths::resolve(
            &options(Some("state".into()), None),
            dir.path(),
            &PathDefaults::default(),
        )
        .unwrap();
        assert_eq!(defaults.config_file, dir.path().join("state/config.yaml"));
    }
    #[cfg(unix)]
    #[test]
    fn absolute_paths_preserve_symlink_parent_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let launch = dir.path().join("launch");
        let target = dir.path().join("target");
        fs::create_dir(&launch).unwrap();
        fs::create_dir_all(target.join("child")).unwrap();
        std::os::unix::fs::symlink(target.join("child"), launch.join("link")).unwrap();
        fs::write(launch.join("config.yaml"), b"launch").unwrap();
        fs::write(target.join("config.yaml"), b"target").unwrap();

        let data = launch.join("link/..");
        let config = data.join("config.yaml");
        let absolute = Paths::resolve(
            &options(Some(data.clone()), Some(config.clone())),
            &launch,
            &PathDefaults::default(),
        )
        .unwrap();
        assert_eq!(absolute.data_dir, data);
        assert_eq!(absolute.config_file, config);
        assert_eq!(read_config(&absolute.config_file).unwrap(), b"target");
        assert_eq!(
            read_config(&absolute.data_dir.join("config.yaml")).unwrap(),
            b"target"
        );

        let relative = Paths::resolve(
            &options(Some("link/..".into()), Some("link/../config.yaml".into())),
            &launch,
            &PathDefaults::default(),
        )
        .unwrap();
        assert_eq!(relative.data_dir, launch);
        assert_eq!(read_config(&relative.config_file).unwrap(), b"launch");
    }
    #[test]
    fn home_and_xdg_defaults_do_not_create_directories() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let xdg = dir.path().join("xdg");
        let defaults = PathDefaults {
            home: Some(home.clone()),
            xdg: Some(xdg.clone()),
        };
        let paths = Paths::resolve(&options(None, None), dir.path(), &defaults).unwrap();
        assert_eq!(paths.data_dir, xdg.join("vole"));
        fs::create_dir_all(home.join(".config/vole")).unwrap();
        assert_eq!(
            Paths::resolve(&options(None, None), dir.path(), &defaults)
                .unwrap()
                .data_dir,
            home.join(".config/vole")
        );
        assert!(!xdg.exists());
    }
    #[test]
    fn stdin_is_a_request_option_and_reads_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(
            &options(None, Some("-".into())),
            dir.path(),
            &PathDefaults::default(),
        )
        .unwrap();
        assert!(paths.stdin);
        let limit = crate::config::MAX_CONFIG_BYTES;
        assert_eq!(
            read_bounded(Cursor::new(vec![b'x'; limit])).unwrap().len(),
            limit
        );
        assert_eq!(
            read_bounded(Cursor::new(vec![b'x'; limit + 1]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn validation_is_pure_even_for_unavailable_tun_and_geodata() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("absent");
        let config = dir.path().join("input.yaml");
        fs::write(&config,"tun: {enable: true, file-descriptor: 2147483647, mtu: 1500}\nproxies: [{name: unused, type: socks5, server: 127.0.0.1, port: 1081}]\nrules: ['GEOSITE,cn,DIRECT','MATCH,unused']").unwrap();
        let payload = ForegroundPayload {
            action: ForegroundAction::Validate,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: Some(data.clone().into()),
            config_path: Some(config.into()),
            http_config_path: None,
            http_ca_path: None,
        };
        assert_eq!(execute(payload).unwrap()["output"], "configuration valid\n");
        assert!(!data.exists());
    }
    #[test]
    #[cfg(feature = "outbound-http")]
    fn validation_resolves_identity_files_from_data_dir_without_initializing_it() {
        use base64::Engine as _;
        let pem = |kind: &str, der: &[u8]| {
            format!(
                "-----BEGIN {kind}-----\n{}\n-----END {kind}-----\n",
                base64::engine::general_purpose::STANDARD.encode(der)
            )
        };
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("state");
        fs::create_dir(&data).unwrap();
        let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
        fs::write(
            data.join("client.crt"),
            pem("CERTIFICATE", identity.cert.der()),
        )
        .unwrap();
        fs::write(
            data.join("client.key"),
            pem("PRIVATE KEY", &identity.signing_key.serialize_der()),
        )
        .unwrap();
        let config = directory.path().join("config.yaml");
        fs::write(&config, "proxies:\n  - name: edge\n    type: http\n    server: proxy.invalid\n    port: 443\n    tls: true\n    certificate: client.crt\n    private-key: client.key\n").unwrap();
        let result = execute(ForegroundPayload {
            action: ForegroundAction::Validate,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: Some(data.clone().into()),
            config_path: Some(config.into()),
            http_config_path: None,
            http_ca_path: None,
        })
        .unwrap();
        assert_eq!(result["output"], "configuration valid\n");
        assert!(!data.join("geodata").exists() && !data.join("configs").exists());
    }

    #[test]
    fn validation_failures_do_not_echo_config_or_initialize_data() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("absent");
        let config = dir.path().join("input.yaml");
        fs::write(&config, "private-token: super-secret").unwrap();
        let error = execute(ForegroundPayload {
            action: ForegroundAction::Validate,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: Some(data.clone().into()),
            config_path: Some(config.into()),
            http_config_path: None,
            http_ca_path: None,
        })
        .unwrap_err();
        assert!(!error.message.contains("secret"));
        assert!(!data.exists());
    }
    #[test]
    fn unused_ca_is_not_read_and_ca_without_http_is_rejected_before_input() {
        let invalid_path = || Some(InvokePath::Text("\0".to_owned()));
        assert!(
            read_http_ca(
                invalid_path(),
                Some("mitm: {enabled: false}"),
                Path::new("/")
            )
            .unwrap()
            .is_none()
        );
        assert!(
            read_http_ca(invalid_path(), Some(""), Path::new("/"))
                .unwrap()
                .is_none()
        );
        let error = execute(ForegroundPayload {
            action: ForegroundAction::Validate,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: invalid_path(),
            config_path: invalid_path(),
            http_config_path: None,
            http_ca_path: invalid_path(),
        })
        .unwrap_err();
        assert_eq!(error.message, "httpCaPath requires httpConfigPath");
    }
    #[test]
    fn run_admission_rejects_busy_before_reading_input() {
        let _lease = lock(&FOREGROUND);
        let error = execute(ForegroundPayload {
            action: ForegroundAction::Run,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: Some(InvokePath::Text("\0".to_owned())),
            config_path: Some(InvokePath::Text("-".to_owned())),
            http_config_path: None,
            http_ca_path: None,
        })
        .unwrap_err();
        assert_eq!(error.message, "foreground is already running");
    }
    #[tokio::test]
    async fn run_rejects_external_tokio_context_before_input() {
        let error = execute(ForegroundPayload {
            action: ForegroundAction::Run,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: None,
            config_path: Some(InvokePath::Text("-".to_owned())),
            http_config_path: None,
            http_ca_path: None,
        })
        .unwrap_err();
        assert!(error.message.contains("synchronous caller"));
    }

    #[test]
    fn help_does_not_read_or_initialize_paths() {
        let result = execute(ForegroundPayload {
            action: ForegroundAction::Help,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: Some(InvokePath::Text("\0".to_owned())),
            config_path: Some(InvokePath::Text("\0".to_owned())),
            http_config_path: None,
            http_ca_path: None,
        })
        .unwrap();
        assert_eq!(result["diagnostics"], HELP);
    }
    #[test]
    fn config_requires_regular_file_and_checks_opened_handle() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_config(dir.path()).is_err());
        let path = dir.path().join("config");
        fs::write(&path, b"hello").unwrap();
        assert_eq!(read_config(&path).unwrap(), b"hello");
        fs::write(&path, vec![0; crate::config::MAX_CONFIG_BYTES + 1]).unwrap();
        assert!(read_config(&path).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_without_waiting_for_writer() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        assert!(read_config(&path).is_err());
        assert!(open_regular(&path).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn native_path_json_roundtrip_opens_exact_filename() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OsString::from_vec(vec![255]));
        #[cfg(target_os = "linux")]
        fs::write(&path, b"bytes").unwrap();
        let value = serde_json::to_vec(&InvokePath::from(path.clone())).unwrap();
        let decoded: InvokePath = serde_json::from_slice(&value).unwrap();
        assert_eq!(decoded.into_path(), path);
        #[cfg(target_os = "linux")]
        assert_eq!(read_config(&path).unwrap(), b"bytes");
    }
    #[tokio::test]
    async fn signal_during_startup_awaits_worker_before_cleanup() {
        let (sent, received) = tokio::sync::oneshot::channel();
        let mut startup = tokio::spawn(async move {
            received.await.unwrap();
            Ok(())
        });
        let signal = async { Ok(()) };
        tokio::pin!(signal);
        let wait = await_startup(&mut startup, signal.as_mut(), None);
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait.as_mut())
                .await
                .is_err()
        );
        sent.send(()).unwrap();
        assert!(!wait.await.unwrap());
    }
    #[tokio::test]
    async fn signal_cancels_startup_and_joins_its_cleanup_before_success() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let (sent, received) = tokio::sync::oneshot::channel();
        let mut startup = tokio::spawn(async move {
            worker_cancellation.cancelled().await;
            received.await.unwrap();
            Err(failure("startup cancelled"))
        });
        let signal = async { Ok(()) };
        tokio::pin!(signal);
        let wait = await_startup(&mut startup, signal.as_mut(), Some(&cancellation));
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait.as_mut())
                .await
                .is_err()
        );
        assert!(cancellation.is_cancelled());
        sent.send(()).unwrap();
        assert!(!wait.await.unwrap());
    }
    #[tokio::test]
    async fn startup_failure_is_preserved_when_signal_is_ready() {
        let mut startup = tokio::spawn(async { Err(failure("private secret")) });
        let signal = async { Ok(()) };
        tokio::pin!(signal);
        assert_eq!(
            await_startup(&mut startup, signal.as_mut(), None)
                .await
                .unwrap_err()
                .message,
            "core startup failed"
        );
    }
    #[test]
    fn scoped_logging_is_inherited_by_runtime_workers() {
        let dispatch = tracing::Dispatch::new(StderrSubscriber::new());
        tracing::dispatcher::with_default(&dispatch, || {
            let runtime = super::super::engine_runtime_builder().build().unwrap();
            runtime.block_on(async {
                tokio::spawn(async {
                    assert!(tracing::dispatcher::get_default(|dispatch| dispatch
                        .downcast_ref::<StderrSubscriber>()
                        .is_some()));
                })
                .await
                .unwrap();
            });
        });
        assert!(!tracing::dispatcher::get_default(|dispatch| dispatch
            .downcast_ref::<StderrSubscriber>()
            .is_some()));
    }

    #[test]
    fn stderr_fields_exclude_targets_and_log_buffer_is_bounded() {
        assert!(!public_numeric_field("destination"));
        assert!(!public_numeric_field("uuid"));
        let mut line = LogLine::new();
        fmt::Write::write_str(&mut line, &"😀".repeat(200)).unwrap();
        assert!(line.len <= LOG_BYTES);
        assert!(!line.as_str().is_empty());
    }

    #[test]
    fn stderr_events_preserve_drop_counts_and_filter_private_values() {
        struct Capture(Arc<Mutex<String>>);
        impl Subscriber for Capture {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }
            fn record(&self, _: &Id, _: &Record<'_>) {}
            fn record_follows_from(&self, _: &Id, _: &Id) {}
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut line = LogLine::new();
                event.record(&mut NumericFields(&mut line));
                self.0.lock().unwrap().push_str(line.as_str());
            }
        }
        let rendered = Arc::new(Mutex::new(String::new()));
        tracing::subscriber::with_default(Capture(rendered.clone()), || {
            tracing::info!(
                packet_queue_drops = 1_u64,
                udp_queue_drops = 2_u64,
                udp_association_queue_drops = 3_u64,
                udp_response_queue_drops = 4_u64,
                dns_queue_drops = 5_u64,
                udp_drops = 6_u64,
                mtu = 1500_u64,
                destination = "private destination",
                uuid = 123_u64,
                password_bytes = "private credential",
                "private message"
            );
        });
        let rendered = rendered.lock().unwrap();
        for (field, count) in [
            ("packet_queue_drops", 1),
            ("udp_queue_drops", 2),
            ("udp_association_queue_drops", 3),
            ("udp_response_queue_drops", 4),
            ("dns_queue_drops", 5),
            ("udp_drops", 6),
        ] {
            assert!(rendered.contains(&format!(" {field}={count}")));
        }
        assert!(rendered.contains(" mtu=1500"));
        for private in ["private", "destination", "uuid", "password", "message"] {
            assert!(!rendered.contains(private));
        }
    }

    #[test]
    #[cfg(feature = "inbound-http")]
    fn explicit_http_file_is_validated_without_initializing_data_or_autoloading() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("absent");
        let main = root.path().join("main.yaml");
        let http = root.path().join("extra.yaml");
        fs::write(&main, "rules: ['MATCH,DIRECT']").unwrap();
        fs::write(
            &http,
            "rewrite: {enabled: true, rules: [{url: '.', action: reject}]}",
        )
        .unwrap();
        let result = execute(ForegroundPayload {
            action: ForegroundAction::Validate,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: Some(data.clone().into()),
            config_path: Some(main.clone().into()),
            http_config_path: Some(http.clone().into()),
            http_ca_path: Some(root.path().join("missing-private-ca.json").into()),
        })
        .unwrap();
        assert_eq!(result["output"], "configuration valid\n");
        assert!(!data.exists());
        fs::write(http, "private-secret: private-data").unwrap();
        let result = execute(ForegroundPayload {
            action: ForegroundAction::Validate,
            config_string: None,
            age_secret_key: None,
            external_controller: None,
            external_controller_tls: None,
            secret: None,
            data_dir: Some(data.clone().into()),
            config_path: Some(main.clone().into()),
            http_config_path: None,
            http_ca_path: None,
        })
        .unwrap();
        assert_eq!(result["output"], "configuration valid\n");
        assert!(!data.exists());
    }
}
