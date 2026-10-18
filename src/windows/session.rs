use std::{
    io,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    sync::Notify,
    task::JoinSet,
    time::{Instant, sleep},
};
use windows::{
    ApplicationModel::Package,
    Storage::ApplicationData,
    Win32::System::{
        RemoteDesktop::ProcessIdToSessionId,
        WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
    },
};

use super::{
    log,
    managed_processes::ManagedProcessSet,
    packet_channel::{
        ControlMessage, DATA_PIPE_READ_BUFFER_BYTES, MAX_PACKET_BATCH_PACKETS, PROTOCOL_VERSION,
        PhysicalBinding, Rendezvous, read_control_async, read_packet_frame_async, read_rendezvous,
        write_control_async, write_packet_batch_async,
    },
    snapshot::SessionReference,
};
use crate::{
    ResourceLimits,
    config::Config,
    dialer::{Dialer, SystemResolver},
    geodata::GeoDataManager,
    platform::{TunIo, validate_packet_channel_config},
    runtime::{PreparedCore, RunningCore},
};

const PACKET_QUEUE_CAPACITY: usize = 256;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(2);

struct WinRtGuard;

impl WinRtGuard {
    fn enter() -> io::Result<Self> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
            .map(|()| Self)
            .map_err(io::Error::other)
    }
}

impl Drop for WinRtGuard {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

#[doc(hidden)]
pub fn run() -> io::Result<()> {
    let _winrt = WinRtGuard::enter()?;
    let result = run_initialized();
    if result.is_err() {
        // Cached WinRT factories must not be queried after RoUninitialize.
        log_startup_failure();
    }
    result
}

fn run_initialized() -> io::Result<()> {
    let (local_folder, installed_folder) = package_folders()?;
    log::append(&local_folder, "session", "Session Host starting");
    let _runtime_thread = crate::invoke::RuntimeThreadGuard::enter();
    let runtime = crate::invoke::engine_runtime_builder()
        .enable_io()
        .enable_time()
        .build()?;
    let result = runtime.block_on(run_async(&local_folder, &installed_folder));
    log::append(
        &local_folder,
        "session",
        if result.is_ok() {
            "Session Host stopped"
        } else {
            "Session Host failed"
        },
    );
    result
}

fn log_startup_failure() {
    if let Ok((local_folder, _)) = package_folders() {
        log::append(&local_folder, "session", "Session Host startup failed");
    }
}

async fn run_async(local_folder: &Path, installed_folder: &Path) -> io::Result<()> {
    let rendezvous = wait_for_rendezvous(local_folder).await?;
    let token = rendezvous.snapshot_token.clone();
    let session_id = current_session_id()?;
    let (control_name, data_name) = rendezvous.qualified_names(session_id)?;
    let control = open_pipe(&control_name, STARTUP_TIMEOUT).await?;
    let data = open_pipe(&data_name, STARTUP_TIMEOUT).await?;
    // The Provider publishes and removes rendezvous; competing deletes can return ACCESS_DENIED.

    let (mut control_read, mut control_write) = tokio::io::split(control);
    // Authenticate the candidate token before reading Snapshot or starting processes.
    let binding = complete_session_handshake(&mut control_read, &mut control_write, &token).await?;

    let started = start_session(local_folder, installed_folder, &token, binding, data).await;
    let (running, mut data_tasks, mut managed_processes) = match started {
        Ok(started) => started,
        Err(error) => {
            _ = write_control_async(
                &mut control_write,
                &ControlMessage::RuntimeFailed {
                    version: PROTOCOL_VERSION,
                    code: "runtime-start-failed".to_owned(),
                    redacted_message: "Vole runtime failed to start".to_owned(),
                },
            )
            .await;
            return Err(error);
        }
    };
    write_control_async(
        &mut control_write,
        &ControlMessage::RuntimeReady {
            version: PROTOCOL_VERSION,
        },
    )
    .await?;

    let mut stopped_counters = None;
    let result = running
        .run_until_shutdown(async {
            tokio::select! {
                message = read_control_async(&mut control_read) => match message {
                    Ok(ControlMessage::Stop { packet_counters, .. }) => {
                        stopped_counters = Some(packet_counters);
                        Ok(())
                    }
                    Err(error) if is_pipe_closed(&error) => Ok(()),
                    Ok(_) => Err(invalid_data("invalid control message during runtime")),
                    Err(error) => Err(error),
                },
                joined = data_tasks.join_next() => match joined {
                    Some(Ok(Ok(()))) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "packet task exited")),
                    Some(Ok(Err(error))) => Err(error),
                    Some(Err(error)) => Err(io::Error::other(error)),
                    None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "packet tasks exited")),
                },
                process = wait_for_managed_process_exit(managed_processes.as_ref()) => {
                    process.and_then(|()| Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "managed Windows session process exited",
                    )))
                }
            }
        })
        .await;
    data_tasks.abort_all();
    while data_tasks.join_next().await.is_some() {}
    let process_stop = match managed_processes.as_mut() {
        Some(processes) => processes.terminate_and_wait(PROCESS_STOP_TIMEOUT).await,
        None => Ok(()),
    };
    let result = match (result, process_stop) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    };

    match (result, stopped_counters) {
        (Ok(()), Some(packet_counters)) => {
            write_control_async(
                &mut control_write,
                &ControlMessage::Stopped {
                    version: PROTOCOL_VERSION,
                    packet_counters,
                },
            )
            .await
        }
        (Ok(()), None) => Ok(()),
        (Err(error), _) => {
            _ = write_control_async(
                &mut control_write,
                &ControlMessage::RuntimeFailed {
                    version: PROTOCOL_VERSION,
                    code: "runtime-failed".to_owned(),
                    redacted_message: "Vole runtime stopped unexpectedly".to_owned(),
                },
            )
            .await;
            Err(error)
        }
    }
}

async fn complete_session_handshake(
    control_read: &mut (impl AsyncRead + Unpin),
    control_write: &mut (impl AsyncWrite + Unpin),
    token: &str,
) -> io::Result<PhysicalBinding> {
    write_control_async(
        control_write,
        &ControlMessage::SessionHello {
            version: PROTOCOL_VERSION,
            snapshot_token: token.to_owned(),
        },
    )
    .await?;
    match read_control_async(control_read).await? {
        ControlMessage::ProviderHello {
            snapshot_token,
            physical_binding,
            ..
        } if snapshot_token == token => Ok(physical_binding),
        _ => Err(invalid_data("invalid Provider handshake")),
    }
}

async fn start_session(
    local_folder: &Path,
    installed_folder: &Path,
    token: &str,
    binding: PhysicalBinding,
    data: NamedPipeClient,
) -> io::Result<(
    RunningCore,
    JoinSet<io::Result<()>>,
    Option<ManagedProcessSet>,
)> {
    let snapshot = SessionReference::parse(token)
        .map_err(io::Error::other)?
        .read(local_folder, installed_folder)
        .map_err(io::Error::other)?;
    let mut managed_processes = snapshot
        .session_backend()
        .map(|backend| ManagedProcessSet::start(installed_folder, backend))
        .transpose()?;
    let started = start_vole(
        local_folder,
        snapshot.config_yaml(),
        snapshot.http_config_yaml(),
        binding,
        data,
    )
    .await;
    let (running, mut data_tasks) = match started {
        Ok(started) => started,
        Err(error) => {
            if let Some(processes) = managed_processes.as_mut() {
                _ = processes.terminate_and_wait(PROCESS_STOP_TIMEOUT).await;
            }
            return Err(error);
        }
    };
    if let Some(processes) = managed_processes.as_ref()
        && let Err(error) = processes.ensure_running()
    {
        _ = running.stop().await;
        data_tasks.abort_all();
        while data_tasks.join_next().await.is_some() {}
        if let Some(processes) = managed_processes.as_mut() {
            _ = processes.terminate_and_wait(PROCESS_STOP_TIMEOUT).await;
        }
        return Err(error);
    }
    Ok((running, data_tasks, managed_processes))
}

async fn start_vole(
    local_folder: &Path,
    config_yaml: &str,
    http_config_yaml: Option<&str>,
    binding: PhysicalBinding,
    data: NamedPipeClient,
) -> io::Result<(RunningCore, JoinSet<io::Result<()>>)> {
    let mut config = Config::parse_yaml(config_yaml.as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid session configuration")
    })?;
    config.set_http_config(http_config_yaml).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid HTTP processing configuration",
        )
    })?;
    let mtu = validate_packet_channel_config(&config.tun)?;
    let geodata = GeoDataManager::open(
        local_folder.join("vole/geodata"),
        Duration::from_secs(24 * 60 * 60),
    )
    .map_err(io::Error::other)?;
    let limits = ResourceLimits {
        tun_max_datagram_size: usize::from(mtu),
        ..ResourceLimits::default()
    };
    let prepared = PreparedCore::prepare_config(config, geodata, &SystemResolver, limits).await?;

    let wake = Arc::new(Notify::new());
    let observed = Arc::clone(&wake);
    let (tun, packets) = TunIo::new(PACKET_QUEUE_CAPACITY, mtu, move || {
        observed.notify_one();
        Ok(())
    })?;
    let (data_read, mut data_write) = tokio::io::split(data);
    let mut data_read = BufReader::with_capacity(DATA_PIPE_READ_BUFFER_BYTES, data_read);
    let mut tasks = JoinSet::new();
    let ingress = packets.clone();
    tasks.spawn(async move {
        loop {
            let packet = read_packet_frame_async(&mut data_read).await?;
            _ = ingress.try_send(packet);
        }
    });
    tasks.spawn(async move {
        let mut packet_batch = Vec::with_capacity(MAX_PACKET_BATCH_PACKETS);
        let mut frame_buffer = Vec::new();
        loop {
            wake.notified().await;
            while let Some(packet) = packets.pop_egress() {
                packet_batch.clear();
                packet_batch.push(packet);
                while packet_batch.len() < MAX_PACKET_BATCH_PACKETS {
                    let Some(packet) = packets.pop_egress() else {
                        break;
                    };
                    packet_batch.push(packet);
                }
                write_packet_batch_async(&mut data_write, &packet_batch, &mut frame_buffer).await?;
            }
        }
    });

    let dialer =
        dialer_from_binding(&binding)?.with_physical_adapter(binding.adapter_id.as_str().into());
    let running = prepared.start_tun(tun, dialer).await?;
    Ok((running, tasks))
}

fn dialer_from_binding(binding: &PhysicalBinding) -> io::Result<Dialer> {
    let ipv4 = binding
        .ipv4
        .as_ref()
        .map(|binding| {
            NonZeroU32::new(binding.interface_index)
                .map(|index| (binding.source, index))
                .ok_or_else(|| invalid_data("invalid IPv4 interface index"))
        })
        .transpose()?;
    let ipv6 = binding
        .ipv6
        .as_ref()
        .map(|binding| {
            NonZeroU32::new(binding.interface_index)
                .map(|index| (binding.source, index))
                .ok_or_else(|| invalid_data("invalid IPv6 interface index"))
        })
        .transpose()?;
    Ok(Dialer::default().with_windows_interface(ipv4, ipv6))
}

async fn wait_for_rendezvous(local_folder: &Path) -> io::Result<Rendezvous> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        match read_rendezvous(local_folder) {
            Ok(rendezvous) => return Ok(rendezvous),
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn open_pipe(name: &str, timeout: Duration) -> io::Result<NamedPipeClient> {
    let deadline = Instant::now() + timeout;
    loop {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return Ok(pipe),
            Err(error) if Instant::now() < deadline => {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    return Err(error);
                }
                sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn current_session_id() -> io::Result<u32> {
    let mut session_id = 0;
    unsafe { ProcessIdToSessionId(std::process::id(), &mut session_id) }
        .map_err(io::Error::other)?;
    Ok(session_id)
}

fn package_folders() -> io::Result<(PathBuf, PathBuf)> {
    let local = ApplicationData::Current()
        .and_then(|data| data.LocalFolder())
        .and_then(|folder| folder.Path())
        .map_err(io::Error::other)?;
    let installed = Package::Current()
        .and_then(|package| package.InstalledLocation())
        .and_then(|folder| folder.Path())
        .map_err(io::Error::other)?;
    Ok((
        PathBuf::from(local.to_string()),
        PathBuf::from(installed.to_string()),
    ))
}

async fn wait_for_managed_process_exit(processes: Option<&ManagedProcessSet>) -> io::Result<()> {
    match processes {
        Some(processes) => processes.wait_for_any_exit().await,
        None => std::future::pending().await,
    }
}

fn is_pipe_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    )
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::packet_channel::AddressBindingV4;

    #[tokio::test]
    async fn provider_cannot_bind_a_candidate_to_another_snapshot() {
        let candidate =
            "vole-session-v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut provider = Vec::new();
        write_control_async(
            &mut provider,
            &ControlMessage::ProviderHello {
                version: PROTOCOL_VERSION,
                snapshot_token: candidate.replace('0', "1"),
                physical_binding: PhysicalBinding {
                    adapter_id: "adapter".to_owned(),
                    profile_name: "Ethernet".to_owned(),
                    network_names: vec![],
                    ipv4: Some(AddressBindingV4 {
                        source: "192.0.2.10".parse().unwrap(),
                        interface_index: 10,
                    }),
                    ipv6: None,
                },
            },
        )
        .await
        .unwrap();

        let error =
            complete_session_handshake(&mut provider.as_slice(), &mut Vec::new(), candidate)
                .await
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn physical_binding_builds_the_existing_paired_windows_dialer() {
        let binding = PhysicalBinding {
            adapter_id: "adapter".to_owned(),
            profile_name: "Ethernet".to_owned(),
            network_names: vec![],
            ipv4: Some(AddressBindingV4 {
                source: "192.0.2.10".parse().unwrap(),
                interface_index: 10,
            }),
            ipv6: None,
        };
        let debug = format!("{:?}", dialer_from_binding(&binding).unwrap());
        assert!(debug.contains("192.0.2.10"));
        assert!(debug.contains("10"));
    }
}
