use std::{
    ffi::{CString, c_char},
    marker::PhantomData,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    ptr,
    sync::{Mutex, OnceLock, TryLockError},
};

use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use windows::{
    ApplicationModel::{Package, StartupTask, StartupTaskState},
    Foundation::Uri,
    Networking::Vpn::{
        IVpnProfile, VpnManagementAgent, VpnManagementConnectionStatus, VpnManagementErrorStatus,
        VpnPlugInProfile,
    },
    Storage::ApplicationData,
    Win32::{
        Foundation::E_NOINTERFACE,
        System::{
            Com::CoIncrementMTAUsage,
            WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
        },
    },
    core::{Interface as _, Result as WindowsResult},
};

use super::{
    managed_processes::SessionBackend,
    policy::WindowsVpnPolicy,
    profile::{WindowsNetworkSettings, WindowsProfileConfiguration},
    snapshot::{HttpSessionInput, SessionReference},
};
use crate::{
    config::Config,
    dialer::Dialer,
    http_processing::providers::Store,
    invoke::http::{HttpContextInput, download_context, prepare_candidate, source_context},
    platform::validate_packet_channel_config,
};

const BRIDGE_VERSION: u32 = 3;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ERROR_BYTES: usize = 4096;
const DEFAULT_PROFILE_NAME: &str = "Vole";
const MAX_PROFILE_NAME_BYTES: usize = 256;
const STARTUP_TASK_ID: &str = "VoleStartup";
static COMMAND: Mutex<()> = Mutex::new(());
static HTTP_STORE: OnceLock<tokio::sync::Mutex<Store>> = OnceLock::new();
// windows-rs caches agile WinRT factories for process lifetime. Keep one opaque
// MTA usage cookie for the same lifetime, including gaps between caller threads.
// Never decrement it per request or during DLL/process teardown: cached factories
// could still be used, and COM shutdown under the loader lock is unsupported.
static MTA_USAGE: Mutex<Option<usize>> = Mutex::new(None);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BridgeRequest {
    bridge_version: u32,
    method: String,
    payload: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

/// A host-selected Windows profile name, never a filesystem path or session ID.
struct ProfileName(String);

impl Default for ProfileName {
    fn default() -> Self {
        Self(DEFAULT_PROFILE_NAME.to_owned())
    }
}

impl<'de> Deserialize<'de> for ProfileName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        if name.is_empty()
            || name.len() > MAX_PROFILE_NAME_BYTES
            || name.trim() != name
            || name.chars().any(char::is_control)
        {
            return Err(serde::de::Error::custom("invalid Windows VPN profile name"));
        }
        Ok(Self(name))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfilePayload {
    #[serde(default)]
    profile_name: ProfileName,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartPayload {
    #[serde(default)]
    profile_name: ProfileName,
    config_yaml: String,
    #[serde(default)]
    http_config_yaml: Option<String>,
    #[serde(default)]
    http_context: Option<HttpContextInput>,
    network_settings: WindowsNetworkSettings,
    policy: WindowsVpnPolicy,
    #[serde(default, deserialize_with = "deserialize_session_backend")]
    session_backend: Option<SessionBackend>,
}

fn deserialize_session_backend<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SessionBackend>, D::Error>
where
    D: Deserializer<'de>,
{
    SessionBackend::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetStartupTaskPayload {
    enabled: bool,
}

struct PackageEnvironment {
    family_name: String,
    local_folder: PathBuf,
    installed_folder: PathBuf,
}

struct ProfileMatch {
    profile: VpnPlugInProfile,
    status: VpnManagementConnectionStatus,
}

// The per-call initialization must be released on its original thread.
struct WinRtGuard(PhantomData<*mut ()>);

impl WinRtGuard {
    fn enter() -> Result<Self, String> {
        // Reject STA/ASTA before acquiring the process-wide MTA reference.
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(display_error)?;
        let guard = Self(PhantomData);
        let mut cookie = MTA_USAGE
            .lock()
            .map_err(|_| "Windows host MTA lifetime lock is poisoned".to_owned())?;
        if cookie.is_none() {
            // This reference outlives all per-call guards. On failure the guard
            // still balances RoInitialize, and a later call can retry retention.
            *cookie = Some(unsafe { CoIncrementMTAUsage() }.map_err(display_error)?.0 as usize);
        }
        Ok(guard)
    }
}

impl Drop for WinRtGuard {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

/// Executes a packaged Windows host request. The returned string must be
/// released with `VoleFree` from the same DLL.
///
/// # Safety
/// `request_json` must be null or point to readable storage containing a NUL
/// terminator within `MAX_REQUEST_BYTES + 1` bytes.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn VoleWindowsVpnInvoke(request_json: *const c_char) -> *mut c_char {
    let response = match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller contract is documented above and the scan is bounded.
        unsafe { read_request(request_json) }.and_then(invoke_bytes)
    })) {
        Ok(Ok(data)) => success(data),
        Ok(Err(error)) => failure(&error),
        Err(_) => failure("panic contained at Windows host boundary"),
    };
    CString::new(response).map_or(ptr::null_mut(), CString::into_raw)
}

fn invoke_bytes(request: &[u8]) -> Result<Value, String> {
    let request: BridgeRequest =
        serde_json::from_slice(request).map_err(|_| "invalid Windows host request".to_owned())?;
    if request.bridge_version != BRIDGE_VERSION {
        return Err("unsupported Windows bridge version".to_owned());
    }
    let _command = match COMMAND.try_lock() {
        Ok(command) => command,
        Err(TryLockError::WouldBlock) => return Err("Windows host operation is busy".to_owned()),
        Err(TryLockError::Poisoned(_)) => {
            return Err("Windows host operation lock is poisoned".to_owned());
        }
    };
    let _winrt = WinRtGuard::enter()?;
    match request.method.as_str() {
        "getEnvironment" => {
            decode_payload::<EmptyPayload>(request.payload)?;
            get_environment()
        }
        "getVpnStatus" => get_vpn_status(decode_payload(request.payload)?),
        "startVpn" => start_vpn(decode_payload(request.payload)?),
        "stopVpn" => stop_vpn(decode_payload(request.payload)?),
        "getStartupTaskStatus" => {
            decode_payload::<EmptyPayload>(request.payload)?;
            get_startup_task_status()
        }
        "setStartupTaskEnabled" => set_startup_task_enabled(decode_payload(request.payload)?),
        _ => Err("unknown Windows bridge method".to_owned()),
    }
}

fn get_environment() -> Result<Value, String> {
    let environment = package_environment()?;
    Ok(json!({
        "packageFamilyName": environment.family_name,
        "packageLocalDataDir": environment.local_folder.to_string_lossy(),
    }))
}

fn get_vpn_status(payload: ProfilePayload) -> Result<Value, String> {
    let environment = package_environment()?;
    let agent = VpnManagementAgent::new().map_err(display_error)?;
    let profile = find_profile(&agent, &environment.family_name, &payload.profile_name.0)?;
    profile_status_data(profile.as_ref())
}

fn start_vpn(payload: StartPayload) -> Result<Value, String> {
    let StartPayload {
        profile_name,
        config_yaml,
        http_config_yaml,
        http_context,
        network_settings,
        policy,
        session_backend,
    } = payload;
    let mut config = Config::parse_yaml(config_yaml.as_bytes())
        .map_err(|_| "invalid Vole configuration".to_owned())?;
    if !config.tun.enable {
        return Err("Windows VPN configuration must enable TUN".to_owned());
    }
    validate_packet_channel_config(&config.tun).map_err(display_error)?;
    policy
        .validate_for(
            config.ipv6,
            network_settings.dns_ipv4_address(),
            network_settings.dns_ipv6_address(),
        )
        .map_err(str::to_owned)?;

    let environment = package_environment()?;
    let agent = VpnManagementAgent::new().map_err(display_error)?;
    let existing = find_profile(&agent, &environment.family_name, &profile_name.0)?;
    let connected = if let Some(existing) = &existing {
        match existing.status {
            VpnManagementConnectionStatus::Connected => true,
            VpnManagementConnectionStatus::Disconnected => false,
            VpnManagementConnectionStatus::Connecting
            | VpnManagementConnectionStatus::Disconnecting => {
                return Err("Windows VPN profile is busy".to_owned());
            }
            _ => return Err("unknown Windows VPN profile status".to_owned()),
        }
    } else {
        false
    };
    let mut http_candidate = None;
    let mut http_base_dir = None;
    let mut private_ca = None;
    if let Some(input) = http_config_yaml
        .as_deref()
        .filter(|input| !input.is_empty())
    {
        let (source, ca) =
            source_context(http_context, environment.local_folder.join("vole"), None)
                .map_err(|_| "invalid HTTP source context".to_owned())?;
        http_base_dir = source.base_dir.clone();
        // The frontend does not own the active Provider's PhysicalBinding.
        // When connected it may reuse validated content, never create an
        // unbound fallback socket through the VPN being configured.
        let network = (!connected).then(|| download_context(&config, Dialer::default()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "HTTP resource runtime creation failed".to_owned())?;
        let result = runtime.block_on(prepare_candidate(
            input,
            source,
            network.as_ref(),
            HTTP_STORE.get_or_init(|| tokio::sync::Mutex::new(Store::default())),
            false,
        ));
        runtime.shutdown_timeout(std::time::Duration::from_millis(100));
        let candidate = result.map_err(|_| "HTTP resource preparation failed".to_owned())?;
        private_ca = candidate.document.mitm.enabled.then_some(ca).flatten();
        let policy = candidate
            .bind_ca(private_ca.as_ref())
            .map_err(|_| "invalid or missing private HTTP CA".to_owned())?;
        config
            .set_http_policy(Some(policy))
            .map_err(|_| "invalid HTTP processing configuration".to_owned())?;
        http_candidate = Some(candidate);
    } else if http_context.is_some() {
        return Err("httpContext requires httpConfigYaml".to_owned());
    }
    let http = http_candidate
        .as_ref()
        .map(|candidate| -> Result<HttpSessionInput<'_>, String> {
            Ok(HttpSessionInput {
                rules: candidate
                    .export_snapshot()
                    .map_err(|_| "HTTP snapshot preparation failed".to_owned())?,
                base_dir: http_base_dir,
                ca: private_ca.as_ref(),
                package_family: &environment.family_name,
            })
        })
        .transpose()?;
    let snapshot = SessionReference::publish(
        &environment.local_folder,
        &environment.installed_folder,
        config_yaml,
        session_backend,
        http,
    )
    .map_err(display_error)?;
    let profile_configuration =
        WindowsProfileConfiguration::new(&snapshot, config.ipv6, network_settings, policy);
    let profile_configuration_json = profile_configuration.to_json().map_err(display_error)?;
    let always_on = profile_configuration.policy().always_on();
    let token = snapshot.token();

    if let Some(existing) = &existing {
        match existing.status {
            VpnManagementConnectionStatus::Connected => {
                let current = existing
                    .profile
                    .CustomConfiguration()
                    .map_err(display_error)?
                    .to_string();
                if current == profile_configuration_json
                    && existing.profile.AlwaysOn().map_err(display_error)? == always_on
                {
                    return profile_status_data(Some(existing));
                }
                return Err("Windows VPN is connected with different session settings".to_owned());
            }
            VpnManagementConnectionStatus::Connecting
            | VpnManagementConnectionStatus::Disconnecting => {
                return Err("Windows VPN profile is busy".to_owned());
            }
            VpnManagementConnectionStatus::Disconnected => {}
            _ => return Err("unknown Windows VPN profile status".to_owned()),
        }
    }

    let previous = existing
        .as_ref()
        .and_then(|existing| existing.profile.CustomConfiguration().ok())
        .and_then(|value| WindowsProfileConfiguration::parse(&value.to_string()).ok())
        .and_then(|configuration| configuration.session_reference().ok());
    let profile = existing
        .as_ref()
        .map_or_else(VpnPlugInProfile::new, |existing| {
            Ok(existing.profile.clone())
        })
        .map_err(display_error)?;
    configure_profile(
        &profile,
        &environment.family_name,
        &profile_name.0,
        &profile_configuration_json,
        always_on,
    )?;
    let status = if existing.is_some() {
        agent
            .UpdateProfileFromObjectAsync(&profile)
            .and_then(|operation| operation.join())
            .map_err(display_error)?
    } else {
        agent
            .AddProfileFromObjectAsync(&profile)
            .and_then(|operation| operation.join())
            .map_err(display_error)?
    };
    require_management_ok(status, "save Windows VPN profile")?;
    _ = snapshot.prune(&environment.local_folder, previous.as_ref());

    let status = agent
        .ConnectProfileAsync(&profile)
        .and_then(|operation| operation.join())
        .map_err(display_error)?;
    if status != VpnManagementErrorStatus::Ok
        && status != VpnManagementErrorStatus::AlreadyConnected
    {
        return Err(format!("connect Windows VPN returned status {}", status.0));
    }
    Ok(json!({"status": "connected", "snapshotToken": token}))
}

fn stop_vpn(payload: ProfilePayload) -> Result<Value, String> {
    let environment = package_environment()?;
    let agent = VpnManagementAgent::new().map_err(display_error)?;
    let Some(profile) = find_profile(&agent, &environment.family_name, &payload.profile_name.0)?
    else {
        return Ok(json!({"status": "disconnected", "snapshotToken": null}));
    };
    if profile.status == VpnManagementConnectionStatus::Disconnected {
        return profile_status_data(Some(&profile));
    }
    let status = agent
        .DisconnectProfileAsync(&profile.profile)
        .and_then(|operation| operation.join())
        .map_err(display_error)?;
    if !matches!(
        status,
        VpnManagementErrorStatus::Ok
            | VpnManagementErrorStatus::AlreadyDisconnecting
            | VpnManagementErrorStatus::CannotFindProfile
            | VpnManagementErrorStatus::NoConnection
    ) {
        return Err(format!(
            "disconnect Windows VPN returned status {}",
            status.0
        ));
    }
    Ok(json!({
        "status": if status == VpnManagementErrorStatus::AlreadyDisconnecting {
            "disconnecting"
        } else {
            "disconnected"
        },
        "snapshotToken": profile
            .profile
            .CustomConfiguration()
            .ok()
            .and_then(|value| WindowsProfileConfiguration::parse(&value.to_string()).ok())
            .map(|configuration| configuration.snapshot_token().to_owned()),
    }))
}

fn get_startup_task_status() -> Result<Value, String> {
    let task = startup_task()?;
    Ok(startup_task_data(task.State().map_err(display_error)?))
}

fn set_startup_task_enabled(payload: SetStartupTaskPayload) -> Result<Value, String> {
    let task = startup_task()?;
    let state = if payload.enabled {
        match task.State().map_err(display_error)? {
            StartupTaskState::Disabled => task
                .RequestEnableAsync()
                .and_then(|operation| operation.join())
                .map_err(display_error)?,
            state => state,
        }
    } else {
        let state = task.State().map_err(display_error)?;
        if state != StartupTaskState::DisabledByPolicy {
            task.Disable().map_err(display_error)?;
            task.State().map_err(display_error)?
        } else {
            state
        }
    };
    Ok(startup_task_data(state))
}

fn package_environment() -> Result<PackageEnvironment, String> {
    let package =
        Package::Current().map_err(|_| "Windows package identity is required".to_owned())?;
    let installed_folder = package
        .InstalledLocation()
        .and_then(|folder| folder.Path())
        .map_err(display_error)?;
    let family_name = package
        .Id()
        .and_then(|id| id.FamilyName())
        .map_err(display_error)?
        .to_string();
    let local_folder = ApplicationData::Current()
        .and_then(|data| data.LocalFolder())
        .and_then(|folder| folder.Path())
        .map_err(display_error)?;
    Ok(PackageEnvironment {
        family_name,
        local_folder: PathBuf::from(local_folder.to_string()),
        installed_folder: PathBuf::from(installed_folder.to_string()),
    })
}

fn find_profile(
    agent: &VpnManagementAgent,
    family_name: &str,
    profile_name: &str,
) -> Result<Option<ProfileMatch>, String> {
    let profiles = agent
        .GetProfilesAsync()
        .and_then(|operation| operation.join())
        .map_err(display_error)?;
    let mut found = None;
    for index in 0..profiles.Size().map_err(display_error)? {
        let profile: IVpnProfile = profiles.GetAt(index).map_err(display_error)?;
        let Some(plugin) = plugin_profile(profile.cast())? else {
            continue;
        };
        if plugin.VpnPluginPackageFamilyName().map_err(display_error)? != family_name {
            continue;
        }
        let status = plugin.ConnectionStatus().map_err(display_error)?;
        if !matches_profile_name(
            profile_name,
            &plugin.ProfileName().map_err(display_error)?.to_string(),
            status,
        )? {
            continue;
        }
        if found.is_some() {
            return Err(
                "multiple package-owned Windows VPN profiles match the requested name".to_owned(),
            );
        }
        found = Some(ProfileMatch {
            profile: plugin,
            status,
        });
    }
    Ok(found)
}

/// Only called for profiles whose package family has already been verified.
fn matches_profile_name(
    requested: &str,
    actual: &str,
    status: VpnManagementConnectionStatus,
) -> Result<bool, String> {
    if actual == requested {
        return Ok(true);
    }
    if status != VpnManagementConnectionStatus::Disconnected {
        return Err("another package-owned Windows VPN profile is active".to_owned());
    }
    Ok(false)
}

fn plugin_profile(
    cast: WindowsResult<VpnPlugInProfile>,
) -> Result<Option<VpnPlugInProfile>, String> {
    match cast {
        Ok(plugin) => Ok(Some(plugin)),
        Err(error) if error.code() == E_NOINTERFACE => Ok(None),
        Err(error) => Err(display_error(error)),
    }
}

fn configure_profile(
    profile: &VpnPlugInProfile,
    family_name: &str,
    profile_name: &str,
    profile_configuration: &str,
    always_on: bool,
) -> Result<(), String> {
    profile
        .SetProfileName(&profile_name.into())
        .and_then(|()| profile.SetVpnPluginPackageFamilyName(&family_name.into()))
        .and_then(|()| profile.SetCustomConfiguration(&profile_configuration.into()))
        .and_then(|()| profile.SetAlwaysOn(always_on))
        .map_err(display_error)?;
    let servers = profile.ServerUris().map_err(display_error)?;
    servers.Clear().map_err(display_error)?;
    servers
        .Append(&Uri::CreateUri(&"https://192.0.2.1".into()).map_err(display_error)?)
        .map_err(display_error)
}

fn profile_status_data(profile: Option<&ProfileMatch>) -> Result<Value, String> {
    let Some(profile) = profile else {
        return Ok(json!({"status": "disconnected", "snapshotToken": null}));
    };
    let status = match profile.status {
        VpnManagementConnectionStatus::Disconnected => "disconnected",
        VpnManagementConnectionStatus::Disconnecting => "disconnecting",
        VpnManagementConnectionStatus::Connected => "connected",
        VpnManagementConnectionStatus::Connecting => "connecting",
        _ => return Err("unknown Windows VPN profile status".to_owned()),
    };
    let profile_configuration = profile
        .profile
        .CustomConfiguration()
        .map_err(display_error)?
        .to_string();
    let token = WindowsProfileConfiguration::parse(&profile_configuration)
        .ok()
        .map(|configuration| configuration.snapshot_token().to_owned());
    if status != "disconnected" && token.is_none() {
        return Err("active Windows VPN profile has invalid configuration".to_owned());
    }
    Ok(json!({"status": status, "snapshotToken": token}))
}

fn startup_task() -> Result<StartupTask, String> {
    StartupTask::GetAsync(&STARTUP_TASK_ID.into())
        .and_then(|operation| operation.join())
        .map_err(display_error)
}

fn startup_task_data(state: StartupTaskState) -> Value {
    let state = match state {
        StartupTaskState::Enabled | StartupTaskState::EnabledByPolicy => "enabled",
        StartupTaskState::Disabled => "disabled",
        StartupTaskState::DisabledByUser => "requiresApproval",
        StartupTaskState::DisabledByPolicy => "unavailable",
        _ => "unavailable",
    };
    json!({"state": state})
}

fn require_management_ok(status: VpnManagementErrorStatus, operation: &str) -> Result<(), String> {
    if status == VpnManagementErrorStatus::Ok {
        Ok(())
    } else {
        Err(format!("{operation} returned status {}", status.0))
    }
}

fn decode_payload<T: for<'de> Deserialize<'de>>(payload: Value) -> Result<T, String> {
    serde_json::from_value(payload).map_err(|_| "invalid Windows host payload".to_owned())
}

unsafe fn read_request<'a>(request: *const c_char) -> Result<&'a [u8], String> {
    if request.is_null() {
        return Err("Windows host request is null".to_owned());
    }
    // SAFETY: the caller guarantees readable storage; strnlen bounds the scan.
    let length = unsafe { libc::strnlen(request, MAX_REQUEST_BYTES + 1) };
    if length > MAX_REQUEST_BYTES {
        return Err("Windows host request exceeds 1 MiB or is not NUL-terminated".to_owned());
    }
    // SAFETY: strnlen found a terminator within the caller-provided storage.
    Ok(unsafe { std::slice::from_raw_parts(request.cast::<u8>(), length) })
}

fn success(data: Value) -> String {
    json!({"success": true, "data": data, "error": ""}).to_string()
}

fn failure(message: &str) -> String {
    let mut message = message.to_owned();
    if message.len() > MAX_ERROR_BYTES {
        let mut end = MAX_ERROR_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    json!({"success": false, "data": null, "error": message}).to_string()
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoke(request: &str) -> Value {
        match invoke_bytes(request.as_bytes()) {
            Ok(data) => serde_json::from_str(&success(data)).unwrap(),
            Err(error) => serde_json::from_str(&failure(&error)).unwrap(),
        }
    }

    fn default_policy() -> Value {
        json!({
            "alwaysOn": false,
            "allowLocalNetwork": true,
            "excludedCidrs": []
        })
    }

    #[test]
    fn rejects_obsolete_bridge_versions_before_touching_winrt() {
        assert_eq!(
            invoke(r#"{"bridgeVersion":2,"method":"getEnvironment","payload":{}}"#),
            json!({
                "success": false,
                "data": null,
                "error": "unsupported Windows bridge version"
            })
        );
    }

    fn start_payload() -> Value {
        json!({
            "configYaml": "tun:\n  enable: true\n",
            "networkSettings": {
                "ipv4Address": "192.168.8.1",
                "ipv6Address": "fd00:8::2",
                "dnsIpv4Address": "223.5.5.5",
                "dnsIpv6Address": "2400:3200::1"
            },
            "policy": default_policy()
        })
    }

    #[test]
    fn profile_payload_defaults_and_custom_names_are_shared_by_lifecycle_commands() {
        let status_or_stop: ProfilePayload = decode_payload(json!({})).unwrap();
        let start: StartPayload = decode_payload(start_payload()).unwrap();
        assert_eq!(status_or_stop.profile_name.0, "Vole");
        assert_eq!(start.profile_name.0, "Vole");

        for name in [
            "Example VPN".to_owned(),
            "示例 VPN".to_owned(),
            "v".repeat(256),
            "名".repeat(85),
        ] {
            let status_or_stop: ProfilePayload =
                decode_payload(json!({"profileName": name})).unwrap();
            let mut input = start_payload();
            input["profileName"] = json!(name);
            let start: StartPayload = decode_payload(input).unwrap();
            assert_eq!(status_or_stop.profile_name.0, name);
            assert_eq!(start.profile_name.0, name);
        }
    }

    #[test]
    fn profile_payload_rejects_invalid_names_without_echoing_input() {
        for name in [
            Value::Null,
            json!(false),
            json!(123),
            json!([]),
            json!({}),
            json!(""),
            json!(" "),
            json!(" Example VPN"),
            json!("Example VPN\u{3000}"),
            json!("Example\nVPN"),
            json!("Example\0VPN"),
            json!("Example\u{007f}VPN"),
            json!("v".repeat(257)),
            json!("名".repeat(86)),
        ] {
            let status_or_stop = decode_payload::<ProfilePayload>(json!({"profileName": name}));
            let mut input = start_payload();
            input["profileName"] = name;
            let start = decode_payload::<StartPayload>(input);
            assert_eq!(
                status_or_stop.err().as_deref(),
                Some("invalid Windows host payload")
            );
            assert_eq!(start.err().as_deref(), Some("invalid Windows host payload"));
        }
    }

    #[test]
    fn profile_payload_keeps_unknown_fields_and_unrelated_methods_strict() {
        assert!(
            decode_payload::<ProfilePayload>(json!({
                "profileName": "Example VPN", "unknown": true
            }))
            .is_err()
        );
        let mut input = start_payload();
        input["profileName"] = json!("Example VPN");
        input["unknown"] = json!(true);
        assert!(decode_payload::<StartPayload>(input).is_err());
        assert!(decode_payload::<EmptyPayload>(json!({"profileName": "Example VPN"})).is_err());
        assert!(
            decode_payload::<SetStartupTaskPayload>(json!({
                "enabled": true, "profileName": "Example VPN"
            }))
            .is_err()
        );
    }

    #[test]
    fn profile_lookup_matches_names_exactly_and_preserves_the_single_session_guard() {
        for status in [
            VpnManagementConnectionStatus::Disconnected,
            VpnManagementConnectionStatus::Connecting,
            VpnManagementConnectionStatus::Connected,
            VpnManagementConnectionStatus::Disconnecting,
        ] {
            assert!(matches_profile_name("Example VPN", "Example VPN", status).unwrap());
            for other in ["Vole", "example vpn", "Other VPN"] {
                let result = matches_profile_name("Example VPN", other, status);
                if status == VpnManagementConnectionStatus::Disconnected {
                    assert!(!result.unwrap());
                } else {
                    assert_eq!(
                        result.unwrap_err(),
                        "another package-owned Windows VPN profile is active"
                    );
                }
            }
        }
        assert!(
            !matches_profile_name(
                "Café",
                "Cafe\u{0301}",
                VpnManagementConnectionStatus::Disconnected
            )
            .unwrap()
        );
    }

    #[test]
    fn start_payload_accepts_only_strict_external_network_settings() {
        let payload: StartPayload = decode_payload(json!({
            "configYaml": "tun:\n  enable: true\n",
            "networkSettings": {
                "ipv4Address": "192.168.8.1",
                "ipv6Address": "fd00:8::2",
                "dnsIpv4Address": "223.5.5.5",
                "dnsIpv6Address": "2400:3200::1"
            },
            "policy": default_policy()
        }))
        .unwrap();
        assert_eq!(
            payload.network_settings.ipv4_address().to_string(),
            "192.168.8.1"
        );
        assert_eq!(
            payload.network_settings.dns_ipv4_address().to_string(),
            "223.5.5.5"
        );

        assert!(
            decode_payload::<StartPayload>(json!({
                "configYaml": "tun:\n  enable: true\n",
                "policy": default_policy()
            }))
            .is_err()
        );
        assert!(
            decode_payload::<StartPayload>(json!({
                "configYaml": "tun:\n  enable: true\n",
                "networkSettings": {
                    "ipv4Address": "192.168.8.1",
                    "ipv6Address": "fd00:8::2",
                    "dnsIpv4Address": "192.168.8.1",
                    "dnsIpv6Address": "2400:3200::1"
                },
                "policy": default_policy()
            }))
            .is_err()
        );
    }

    #[test]
    fn start_payload_requires_global_vpn_policy() {
        let network_settings = json!({
            "ipv4Address": "192.168.8.1",
            "ipv6Address": "fd00:8::2",
            "dnsIpv4Address": "223.5.5.5",
            "dnsIpv6Address": "2400:3200::1"
        });
        assert!(
            decode_payload::<StartPayload>(json!({
                "configYaml": "tun:\n  enable: true\n",
                "networkSettings": network_settings.clone(),
                "policy": {
                    "alwaysOn": false,
                    "allowLocalNetwork": true,
                    "excludedCidrs": []
                }
            }))
            .is_ok()
        );
        assert!(
            decode_payload::<StartPayload>(json!({
                "configYaml": "tun:\n  enable: true\n",
                "networkSettings": network_settings
            }))
            .is_err()
        );
    }

    #[test]
    fn start_payload_accepts_only_process_fields_in_session_backend() {
        let network_settings = json!({
            "ipv4Address": "192.168.8.1",
            "ipv6Address": "fd00:8::2",
            "dnsIpv4Address": "223.5.5.5",
            "dnsIpv6Address": "2400:3200::1"
        });
        let payload: StartPayload = decode_payload(json!({
            "configYaml": "tun:\n  enable: true\n",
            "networkSettings": network_settings.clone(),
            "policy": default_policy(),
            "sessionBackend": {
                "processes": [{
                    "executableRelativePath": "bin\\proxy.exe",
                    "arguments": ["run", "--mode", "vpn"]
                }]
            }
        }))
        .unwrap();
        assert!(payload.session_backend.is_some());
        assert!(
            decode_payload::<StartPayload>(json!({
                "configYaml": "tun:\n  enable: true\n",
                "networkSettings": network_settings.clone(),
                "policy": default_policy(),
                "sessionBackend": null
            }))
            .is_err()
        );

        for field in ["port", "udp", "readiness", "restart"] {
            assert!(
                decode_payload::<StartPayload>(json!({
                    "configYaml": "tun:\n  enable: true\n",
                    "networkSettings": network_settings.clone(),
                    "policy": default_policy(),
                    "sessionBackend": {
                        "processes": [{
                            "executableRelativePath": "bin\\proxy.exe",
                            "arguments": []
                        }],
                        (field): true
                    }
                }))
                .is_err(),
                "accepted {field}"
            );
        }
    }

    #[test]
    fn rejects_unknown_methods_without_exposing_profile_crud() {
        assert_eq!(
            invoke(r#"{"bridgeVersion":3,"method":"deleteProfile","payload":{}}"#),
            json!({
                "success": false,
                "data": null,
                "error": "unknown Windows bridge method"
            })
        );
    }

    #[test]
    fn profile_configuration_applies_always_on_capability() {
        let _winrt = WinRtGuard::enter().unwrap();
        let profile = VpnPlugInProfile::new().unwrap();

        configure_profile(&profile, "example.family", "示例 VPN", "{}", true).unwrap();

        assert_eq!(profile.ProfileName().unwrap(), "示例 VPN");
        assert_eq!(
            profile.VpnPluginPackageFamilyName().unwrap(),
            "example.family"
        );
        assert_eq!(profile.CustomConfiguration().unwrap(), "{}");
        assert!(profile.AlwaysOn().unwrap());
    }

    #[test]
    fn plugin_profile_skips_only_no_interface() {
        use windows::core::Error as WindowsError;

        assert!(
            plugin_profile(Err(WindowsError::from_hresult(E_NOINTERFACE)))
                .unwrap()
                .is_none()
        );
        assert!(
            plugin_profile(Err(WindowsError::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            )))
            .is_err()
        );
    }
}
