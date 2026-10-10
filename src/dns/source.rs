//! Explicit physical DNS metadata. This module never configures a network.
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex as StdMutex, Weak},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::{config::DnsSource, dialer::Dialer};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, feature = "windows-uwp"))]
pub(crate) mod windows;

pub(crate) const MAX_METADATA_BYTES: usize = 64 * 1024;
const DISCOVERY_TTL: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DnsServerAddress {
    pub address: IpAddr,
    #[serde(default)]
    pub scope_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SystemDnsServer {
    pub address: IpAddr,
    pub interface: String,
    #[serde(default)]
    pub scope_id: u32,
    #[serde(default)]
    pub requires_encryption: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DhcpDnsInterface {
    pub interface: String,
    pub servers: Vec<DnsServerAddress>,
    #[serde(default)]
    pub requires_encryption: bool,
}

/// Host-supplied network data, separate from the Mihomo YAML schema.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DnsNetworkUpdate {
    pub generation: u64,
    pub system: Vec<SystemDnsServer>,
    pub dhcp: Vec<DhcpDnsInterface>,
}

impl DnsNetworkUpdate {
    pub(crate) fn validate(&self) -> io::Result<()> {
        check_metadata_size(self)?;
        if self.generation == 0 {
            return Err(invalid("DNS network generation must be positive"));
        }
        let mut interfaces = std::collections::HashSet::new();
        for server in &self.system {
            validate_interface(&server.interface)?;
            endpoint(server.address, server.scope_id)?;
        }
        for lease in &self.dhcp {
            validate_interface(&lease.interface)?;
            if !interfaces.insert(&lease.interface) {
                return Err(invalid("duplicate DHCP DNS interface"));
            }
            for server in &lease.servers {
                endpoint(server.address, server.scope_id)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn check_metadata_size(value: &impl Serialize) -> io::Result<()> {
    struct Size(usize);
    impl io::Write for Size {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_METADATA_BYTES)
                .ok_or_else(|| invalid("DNS network metadata exceeds 64 KiB"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Size(0), value)
        .map_err(|_| invalid("DNS network metadata exceeds 64 KiB"))
}

pub(crate) fn validate_interface(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 256
        || name.chars().any(char::is_control)
        || name.trim() != name
        || name.contains(['/', '\\'])
    {
        return Err(invalid("invalid DNS source interface"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(super) fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "physical DNS source is unavailable",
    )
}

fn endpoint(ip: IpAddr, scope: u32) -> io::Result<SocketAddr> {
    let ip = ip.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return Err(invalid("DNS source must be a physical unicast address"));
    }
    match ip {
        IpAddr::V4(_) if scope != 0 => Err(invalid("IPv4 DNS source cannot have a scope")),
        IpAddr::V6(ip) if ip.is_unicast_link_local() && scope == 0 => {
            Err(invalid("link-local DNS source requires a scope"))
        }
        IpAddr::V6(ip) if scope != 0 => Ok(SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, scope))),
        _ => Ok(SocketAddr::new(ip, 53)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DnsBinding {
    pub interface: Arc<str>,
    pub interface_index: Option<std::num::NonZeroU32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SourceEndpoint {
    pub endpoint: SocketAddr,
    pub binding: DnsBinding,
    pub requires_encryption: bool,
}

pub(super) struct SourceSelection {
    pub generation: u64,
    pub endpoints: Arc<[SourceEndpoint]>,
}

#[derive(Clone, Default)]
pub(crate) struct SourceExclusions {
    pub interface: Option<Arc<str>>,
    pub addresses: Vec<IpAddr>,
}
impl SourceExclusions {
    pub(super) fn permits(&self, server: &SourceEndpoint) -> bool {
        self.interface.as_deref() != Some(server.binding.interface.as_ref())
            && !self.addresses.contains(&server.endpoint.ip())
    }
}

struct Discovery {
    refreshed: Instant,
    endpoints: Arc<[SourceEndpoint]>,
}
#[derive(Default)]
struct SourceState {
    generation: u64,
    host: Option<DnsNetworkUpdate>,
    discovery: HashMap<DnsSource, Discovery>,
}

/// Shared by resource generations. Weak roots make invalidation cover every
/// still-live DNS tree without retaining retired resource generations.
pub(crate) struct NetworkSources {
    epoch: Arc<RwLock<u64>>,
    state: StdMutex<SourceState>,
    roots: StdMutex<Vec<Weak<super::runtime::RuntimeDns>>>,
    discovery: Mutex<()>,
}
impl Default for NetworkSources {
    fn default() -> Self {
        Self {
            epoch: Arc::new(RwLock::new(0)),
            state: StdMutex::new(SourceState::default()),
            roots: StdMutex::new(Vec::new()),
            discovery: Mutex::new(()),
        }
    }
}
impl std::fmt::Debug for NetworkSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkSources").finish_non_exhaustive()
    }
}

impl NetworkSources {
    pub(crate) fn epoch(&self) -> Arc<RwLock<u64>> {
        self.epoch.clone()
    }
    pub(crate) fn register(&self, root: &Arc<super::runtime::RuntimeDns>) {
        let mut roots = self
            .roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        roots.retain(|root| root.strong_count() != 0);
        roots.push(Arc::downgrade(root));
    }
    async fn clear_roots(&self) {
        let roots = {
            let mut roots = self
                .roots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            roots.retain(|root| root.strong_count() != 0);
            roots.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        };
        for root in roots {
            root.clear_cache_tree().await;
        }
    }

    pub(crate) async fn replace(&self, update: DnsNetworkUpdate) -> io::Result<()> {
        update.validate()?;
        let mut epoch = self.epoch.write().await;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(previous) = &state.host {
                if update.generation < previous.generation {
                    return Err(invalid("obsolete DNS network generation"));
                }
                if update.generation == previous.generation {
                    return if *previous == update {
                        Ok(())
                    } else {
                        Err(invalid("conflicting DNS network generation"))
                    };
                }
            }
            state.host = Some(update);
            state.discovery = HashMap::new();
            state.generation = state.generation.wrapping_add(1);
        }
        *epoch = epoch.wrapping_add(1);
        self.clear_roots().await;
        Ok(())
    }

    pub(super) async fn select(
        &self,
        source: &DnsSource,
        dialer: Option<&Dialer>,
        exclusions: &SourceExclusions,
    ) -> io::Result<SourceSelection> {
        // Serialize only lazy metadata refreshes, never DNS I/O. The guard is
        // cancelled with its query; a host replacement does not wait on it.
        let _discovery = self.discovery.lock().await;
        let observed = {
            let _epoch = self.epoch.read().await;
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(host) = &state.host {
                return select_host(host, source, state.generation, exclusions);
            }
            if let Some(cached) = state.discovery.get(source)
                && cached.refreshed.elapsed() < DISCOVERY_TTL
            {
                return selection(state.generation, cached.endpoints.clone(), exclusions);
            }
            state.generation
        };
        let endpoints = match self.discover(source, dialer, exclusions).await {
            Ok(endpoints) => endpoints,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(_) => Vec::new(),
        };
        let mut epoch = self.epoch.write().await;
        let generation = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A replaced host snapshot is authoritative even if an old OS
            // discovery finished later. Never publish that stale completion.
            if let Some(host) = &state.host {
                return select_host(host, source, state.generation, exclusions);
            }
            if state.generation != observed {
                return Err(unavailable());
            }
            let changed = state
                .discovery
                .get(source)
                .is_none_or(|old| old.endpoints.as_ref() != endpoints);
            state
                .discovery
                .retain(|_, entry| entry.refreshed.elapsed() < DISCOVERY_TTL);
            let bytes = state
                .discovery
                .iter()
                .filter(|(key, _)| *key != source)
                .map(|(key, entry)| discovery_bytes(key, &entry.endpoints))
                .sum::<usize>();
            let added = discovery_bytes(source, &endpoints);
            if bytes
                .checked_add(added)
                .is_none_or(|size| size > MAX_METADATA_BYTES)
            {
                return Err(unavailable());
            }
            if changed {
                state.generation = state.generation.wrapping_add(1);
                *epoch = epoch.wrapping_add(1);
            }
            state.discovery.insert(
                source.clone(),
                Discovery {
                    refreshed: Instant::now(),
                    endpoints: endpoints.into(),
                },
            );
            (state.generation, changed)
        };
        if generation.1 {
            self.clear_roots().await;
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        selection(
            generation.0,
            state.discovery.get(source).unwrap().endpoints.clone(),
            exclusions,
        )
    }

    async fn discover(
        &self,
        source: &DnsSource,
        dialer: Option<&Dialer>,
        exclusions: &SourceExclusions,
    ) -> io::Result<Vec<SourceEndpoint>> {
        #[cfg(target_os = "linux")]
        {
            let source = source.clone();
            let exclusions = exclusions.clone();
            dialer
                .ok_or_else(unavailable)?
                .run_dns_discovery(move |check| linux::discover(&source, &exclusions, check))
                .await
        }
        #[cfg(all(windows, feature = "windows-uwp"))]
        {
            if !matches!(source, DnsSource::System) {
                return Err(unavailable());
            }
            let dialer = dialer.ok_or_else(unavailable)?;
            let adapter = dialer.physical_dns_adapter().ok_or_else(unavailable)?;
            let snapshot = dialer
                .run_dns_discovery(move |check| windows::snapshot(&adapter, check))
                .await?;
            Ok(select_host(&snapshot, source, 0, exclusions)?
                .endpoints
                .to_vec())
        }
        #[cfg(not(any(target_os = "linux", all(windows, feature = "windows-uwp"))))]
        {
            let _ = (source, dialer, exclusions);
            Err(unavailable())
        }
    }
}

fn select_host(
    host: &DnsNetworkUpdate,
    source: &DnsSource,
    generation: u64,
    exclusions: &SourceExclusions,
) -> io::Result<SourceSelection> {
    let mut servers = Vec::new();
    match source {
        DnsSource::System => {
            for server in &host.system {
                servers.push(SourceEndpoint {
                    endpoint: endpoint(server.address, server.scope_id)?,
                    binding: DnsBinding {
                        interface: server.interface.as_str().into(),
                        interface_index: None,
                    },
                    requires_encryption: server.requires_encryption,
                });
            }
        }
        DnsSource::Dhcp(interface) => {
            if let Some(lease) = host
                .dhcp
                .iter()
                .find(|lease| lease.interface == interface.as_ref())
            {
                for server in &lease.servers {
                    servers.push(SourceEndpoint {
                        endpoint: endpoint(server.address, server.scope_id)?,
                        binding: DnsBinding {
                            interface: lease.interface.as_str().into(),
                            interface_index: None,
                        },
                        requires_encryption: lease.requires_encryption,
                    });
                }
            }
        }
    }
    selection(generation, servers.into(), exclusions)
}
fn selection(
    generation: u64,
    servers: Arc<[SourceEndpoint]>,
    exclusions: &SourceExclusions,
) -> io::Result<SourceSelection> {
    let servers = servers
        .iter()
        .filter(|server| exclusions.permits(server))
        .cloned()
        .collect::<Vec<_>>();
    if servers.is_empty() || servers.iter().any(|server| server.requires_encryption) {
        return Err(unavailable());
    }
    Ok(SourceSelection {
        generation,
        endpoints: servers.into(),
    })
}

fn discovery_bytes(source: &DnsSource, endpoints: &[SourceEndpoint]) -> usize {
    let key = match source {
        DnsSource::System => 0,
        DnsSource::Dhcp(name) => name.len(),
    };
    64 + key
        + endpoints
            .iter()
            .map(|entry| entry.binding.interface.len() + 64)
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(generation: u64, address: &str) -> DnsNetworkUpdate {
        DnsNetworkUpdate {
            generation,
            system: vec![SystemDnsServer {
                address: address.parse().unwrap(),
                interface: "physical0".into(),
                scope_id: 0,
                requires_encryption: false,
            }],
            dhcp: vec![DhcpDnsInterface {
                interface: "physical1".into(),
                servers: vec![DnsServerAddress {
                    address: "192.0.2.53".parse().unwrap(),
                    scope_id: 0,
                }],
                requires_encryption: false,
            }],
        }
    }

    #[tokio::test]
    async fn replacement_is_monotonic_idempotent_and_selects_exact_interface() {
        let sources = NetworkSources::default();
        let current = update(1, "203.0.113.53");
        sources.replace(current.clone()).await.unwrap();
        let epoch = *sources.epoch.read().await;
        sources.replace(current.clone()).await.unwrap();
        assert_eq!(*sources.epoch.read().await, epoch);
        assert!(sources.replace(update(1, "203.0.113.54")).await.is_err());
        sources.replace(update(2, "203.0.113.54")).await.unwrap();
        assert!(sources.replace(current).await.is_err());
        let system = sources
            .select(&DnsSource::System, None, &SourceExclusions::default())
            .await
            .unwrap();
        assert_eq!(
            system.endpoints[0].endpoint.ip(),
            "203.0.113.54".parse::<IpAddr>().unwrap()
        );
        let dhcp = sources
            .select(
                &DnsSource::Dhcp("physical1".into()),
                None,
                &SourceExclusions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            dhcp.endpoints[0].endpoint.ip(),
            "192.0.2.53".parse::<IpAddr>().unwrap()
        );
        assert!(
            sources
                .select(
                    &DnsSource::Dhcp("physical0".into()),
                    None,
                    &SourceExclusions::default()
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn replacement_excludes_tun_and_never_downgrades_encryption() {
        let sources = NetworkSources::default();
        let mut snapshot = update(1, "203.0.113.53");
        snapshot.system[0].requires_encryption = true;
        sources.replace(snapshot.clone()).await.unwrap();
        assert!(
            sources
                .select(&DnsSource::System, None, &SourceExclusions::default())
                .await
                .is_err()
        );
        snapshot.generation = 2;
        snapshot.system[0].requires_encryption = false;
        sources.replace(snapshot).await.unwrap();
        for exclusions in [
            SourceExclusions {
                interface: Some("physical0".into()),
                addresses: vec![],
            },
            SourceExclusions {
                interface: None,
                addresses: vec!["203.0.113.53".parse().unwrap()],
            },
        ] {
            assert!(
                sources
                    .select(&DnsSource::System, None, &exclusions)
                    .await
                    .is_err()
            );
        }
        sources
            .replace(DnsNetworkUpdate {
                generation: 3,
                system: vec![],
                dhcp: vec![],
            })
            .await
            .unwrap();
        assert!(
            sources
                .select(&DnsSource::System, None, &SourceExclusions::default())
                .await
                .is_err()
        );
    }

    #[test]
    fn metadata_is_strict_bounded_and_rejects_stub_addresses() {
        assert!(update(0, "203.0.113.53").validate().is_err());
        let mut large = update(1, "203.0.113.53");
        large.system = vec![large.system[0].clone(); 1024];
        assert!(large.validate().is_err());
        assert!(
            serde_json::from_str::<DnsNetworkUpdate>(
                r#"{"generation":1,"system":[],"dhcp":[],"extra":true}"#
            )
            .is_err()
        );
        for address in [
            "127.0.0.53",
            "::1",
            "::ffff:127.0.0.53",
            "0.0.0.0",
            "224.0.0.1",
            "ff02::1",
        ] {
            assert!(endpoint(address.parse().unwrap(), 0).is_err(), "{address}");
        }
        assert!(endpoint("fe80::53".parse().unwrap(), 0).is_err());
        let SocketAddr::V6(scoped) = endpoint("fe80::53".parse().unwrap(), 3).unwrap() else {
            panic!("IPv6")
        };
        assert_eq!(scoped.scope_id(), 3);
        assert!(endpoint("192.0.2.53".parse().unwrap(), 3).is_err());
        for name in [
            "",
            "../physical0",
            "physical0\n",
            " physical0",
            "physical0/",
        ] {
            assert!(validate_interface(name).is_err());
        }
        assert!(discovery_bytes(&DnsSource::Dhcp("physical1".into()), &[]) > 64);
    }
}
