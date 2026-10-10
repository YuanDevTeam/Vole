#![cfg_attr(not(any(feature = "invoke", feature = "cli")), allow(dead_code))]

use crate::routing::diagnostics;

use tracing::instrument::WithSubscriber;

#[cfg(all(
    test,
    unix,
    feature = "inbound-http",
    feature = "inbound-socks5",
    feature = "outbound-socks5"
))]
#[path = "runtime_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::{future::Future, io, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::future::{join_all, select_all};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[cfg(all(
    feature = "tun",
    any(
        unix,
        all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
    )
))]
use crate::{platform::TunIo, tun_runtime::TunRuntime};
#[cfg(not(all(
    feature = "tun",
    any(
        unix,
        all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
    )
)))]
type TunRuntime = ();

#[cfg(any(feature = "inbound-http", feature = "inbound-socks5"))]
use crate::controller::RuntimeController;
#[cfg(not(any(feature = "inbound-http", feature = "inbound-socks5")))]
type RuntimeController = ();

#[cfg(feature = "invoke")]
use crate::config::MeasureConfig;
#[cfg(test)]
use crate::config::ProxyId;
#[cfg(all(feature = "inbound-http", feature = "inbound-socks5"))]
use crate::inbound::mixed::MixedServer;
use crate::{
    ResourceLimits,
    config::{
        Config, InboundConfig, ProxyConfig, ProxyGroupMemberTarget, ProxyProtocol, RouteTargetId,
        SelectProxyGroupConfig, proxy_graph_order,
    },
    dialer::{Dialer, ResolvedEndpoint, Resolver},
    dispatch::{Dispatcher, observe_handshakes_with_stats, observe_sessions_with_stats},
    dns::{resolution::ResolutionContext, runtime::RuntimeDns},
    geodata::{
        GeoDataManager, GeoDataRegistration, GeoRequirements, service::GeoDataUpdateService,
    },
    outbound::{
        ConnectorDispatcher, DirectOutbound, OutboundConnector, SelectUpstream,
        SelectUpstreamMember, UpstreamPath,
    },
    resources::RuntimeResourceStats,
    routing::{GeoMatcher, ProxyGroups, RouteTargetDispatchers, RoutingDispatcher, RuleSet},
    traffic::TunTrafficStats,
};

#[cfg(feature = "outbound-shadowsocks")]
use crate::outbound::ShadowsocksOutbound;
#[cfg(feature = "outbound-socks5")]
use crate::outbound::Socks5Outbound;
#[cfg(feature = "outbound-trojan")]
use crate::outbound::trojan::TrojanOutbound;
#[cfg(feature = "outbound-anytls")]
use crate::outbound::{AnyTlsOutbound, server_destination};
#[cfg(feature = "outbound-vless")]
use crate::outbound::{VlessOutbound, VlessResourceLimits};
use crate::security::SecurityContext;
#[cfg(feature = "outbound-anytls")]
use crate::security::StandardTlsClient;
#[cfg(any(
    feature = "outbound-http",
    feature = "outbound-socks5",
    feature = "outbound-anytls",
    feature = "outbound-vless",
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic",
    feature = "shadow-tls-v3"
))]
use crate::security::TLS_RESUMPTION_SESSION_BUDGET;

mod health;
mod providers;
use providers::ProviderRuntime;

/// Validated configuration; physical server names resolve on first use.
#[derive(Debug)]
pub(crate) struct PreparedCore {
    config: Config,
    security: SecurityContext,
    provider_cache: std::sync::Mutex<Option<crate::resource::cache::ProviderCache>>,
    endpoints: Vec<PreparedProxyEndpoints>,
    limits: ResourceLimits,
    rules: RuleSet,
    geodata_manager: Arc<GeoDataManager>,
    geodata_registration: GeoDataRegistration,
    // Shared TUN startup uses this in FFI, Windows CLI, and memory tests.
    // The Unix CLI has no host descriptor to attach.
    #[cfg_attr(
        all(feature = "cli", not(feature = "invoke"), unix, not(test)),
        allow(dead_code)
    )]
    traffic_stats: Option<Arc<TunTrafficStats>>,
}

/// A node-only outbound graph prepared for one built-in latency probe.
///
/// Unlike `PreparedCore`, this type never registers GeoData, compiles rules,
/// builds DNS, or starts an inbound. Each value owns independent connector and
/// security state and is dropped when its measurement item completes.
#[cfg(feature = "invoke")]
pub(crate) struct PreparedMeasurement {
    config: MeasureConfig,
    security: SecurityContext,
    endpoints: Vec<PreparedProxyEndpoints>,
    limits: ResourceLimits,
}

/// Pre-resolved physical destinations used by standalone measurements.
/// Running sessions leave these empty and resolve node endpoints on demand.
/// XHTTP measurements can retain a separate endpoint for the download leg.
#[derive(Debug, Clone, Default)]
struct PreparedProxyEndpoints {
    upload: Option<ResolvedEndpoint>,
    download: Option<ResolvedEndpoint>,
}

#[cfg(feature = "invoke")]
pub(crate) struct MeasurementRuntime {
    security: SecurityContext,
    dispatcher: Arc<dyn Dispatcher>,
    proxy_graph: Arc<BuiltProxyGraph>,
}

#[cfg(feature = "invoke")]
impl MeasurementRuntime {
    pub(crate) fn security(&self) -> &SecurityContext {
        &self.security
    }
    #[must_use]
    pub(crate) fn dispatcher(&self) -> Arc<dyn Dispatcher> {
        self.dispatcher.clone()
    }

    pub(crate) async fn shutdown(self) {
        self.proxy_graph.begin_shutdown();
        self.proxy_graph.shutdown().await;
    }
}

#[cfg(feature = "invoke")]
impl Drop for MeasurementRuntime {
    fn drop(&mut self) {
        self.proxy_graph.begin_shutdown();
    }
}

struct BuiltRuntimeParts {
    connections: Arc<crate::connections::Registry>,
    diagnostics: Option<Arc<diagnostics::Diagnostics>>,
    dispatcher: Arc<dyn Dispatcher>,
    // Local dispatch owns its DNS reference; this copy feeds shared TUN startup.
    #[cfg_attr(
        all(feature = "cli", not(feature = "invoke"), unix, not(test)),
        allow(dead_code)
    )]
    dns: Option<Arc<RuntimeDns>>,
    geodata_updater: Option<GeoDataUpdateService>,
    proxy_groups: Arc<ProxyGroups>,
    proxy_graph: Arc<BuiltProxyGraph>,
    resources: Option<Arc<ProviderRuntime>>,
    health: Arc<health::HealthRuntime>,
    resource_targets: RouteTargetDispatchers,
    direct: Arc<dyn Dispatcher>,
}

struct BuiltProxyGraph {
    dialer: Dialer,
    resolution: ResolutionContext,
    nodes: Vec<Arc<dyn OutboundConnector>>,
    lifecycle_order: Vec<BuiltRouteTarget>,
    selections: Vec<Arc<crate::routing::GroupSelection>>,
}

enum BuiltRouteTarget {
    Proxy(Arc<dyn OutboundConnector>),
    Group(Arc<SelectUpstream>),
}

impl BuiltProxyGraph {
    #[cfg(feature = "invoke")]
    fn get(&self, index: usize) -> Option<&Arc<dyn OutboundConnector>> {
        self.nodes.get(index)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn connectors(&self) -> &[Arc<dyn OutboundConnector>] {
        &self.nodes
    }

    fn begin_shutdown(&self) {
        self.dialer.begin_shutdown();
        self.resolution.close();
        for target in self.lifecycle_order.iter().rev() {
            if let BuiltRouteTarget::Proxy(connector) = target {
                connector.begin_shutdown();
            }
        }
    }

    async fn shutdown(&self) {
        for target in self.lifecycle_order.iter().rev() {
            if let BuiltRouteTarget::Proxy(connector) = target {
                connector.shutdown().await;
            }
        }
        self.dialer.shutdown().await;
    }
}

impl Drop for BuiltProxyGraph {
    fn drop(&mut self) {
        self.begin_shutdown();
        self.nodes.clear();
        while let Some(target) = self.lifecycle_order.pop() {
            match target {
                BuiltRouteTarget::Proxy(connector) => drop(connector),
                BuiltRouteTarget::Group(group) => drop(group),
            }
        }
    }
}

impl PreparedCore {
    pub(crate) fn log_level(&self) -> crate::config::LogLevel {
        self.config.log_level
    }

    #[cfg(test)]
    async fn prepare(
        yaml: &[u8],
        resolver: &dyn Resolver,
        limits: ResourceLimits,
    ) -> io::Result<Self> {
        let config = Config::parse_yaml(yaml)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let directory = tempfile::tempdir()?;
        let manager = GeoDataManager::open(
            &directory.path().join("geodata"),
            Duration::from_secs(24 * 60 * 60),
        )
        .map_err(io::Error::other)?;
        Self::prepare_config(config, manager, resolver, limits).await
    }

    /// Completes bootstrap preparation for a configuration that has already
    /// passed strict schema validation. The Invoke layer uses this split to
    /// claim runtime-local resources, notably the unique TUN lease, before a
    /// potentially blocking DNS lookup.
    pub(crate) async fn prepare_config(
        mut config: Config,
        geodata_manager: Arc<GeoDataManager>,
        resolver: &dyn Resolver,
        limits: ResourceLimits,
    ) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let provider_cache = if let Some(template) = config.providers.clone() {
            let root = geodata_manager
                .store_dir()
                .parent()
                .ok_or_else(|| io::Error::other("dataDir is missing"))?
                .to_path_buf();
            let cache = tokio::task::spawn_blocking(move || {
                crate::resource::cache::ProviderCache::open(&root, template)
            })
            .await
            .map_err(io::Error::other)??;
            config = cache
                .template
                .materialize(&cache.contents)
                .map_err(io::Error::other)?;
            Some(cache)
        } else {
            None
        };
        crate::dns::hosts::materialize_lan(&mut config.dns.hosts)?;
        let (rules, geodata_registration) = prepare_routing(&mut config, &geodata_manager)?;
        let _ = resolver;
        let endpoints = vec![PreparedProxyEndpoints::default(); config.proxies.len()];
        let traffic_stats = config
            .tun
            .enable
            .then(|| Arc::new(TunTrafficStats::default()));
        let trust = config.tls.clone();
        let security = tokio::task::spawn_blocking(move || SecurityContext::load(&trust))
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            config,
            security,
            provider_cache: std::sync::Mutex::new(provider_cache),
            endpoints,
            limits,
            rules,
            geodata_manager,
            geodata_registration,
            traffic_stats,
        })
    }

    /// Performs every configuration-owned validation step without resolving
    /// the proxy, opening GeoData files, or retaining a matcher.
    pub(crate) fn validate_config(mut config: Config) -> io::Result<()> {
        GeoRequirements::for_config(&config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        RuleSet::compile_config(&mut config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(())
    }

    #[must_use]
    #[cfg(test)]
    fn proxy(&self, id: ProxyId) -> &ProxyConfig {
        &self.config.proxies[id.index()]
    }

    #[must_use]
    #[cfg(test)]
    fn endpoint(&self, id: ProxyId) -> Option<&ResolvedEndpoint> {
        self.endpoints
            .get(id.index())
            .and_then(|endpoints| endpoints.upload.as_ref())
    }

    #[must_use]
    #[cfg(test)]
    fn download_endpoint(&self, id: ProxyId) -> Option<&ResolvedEndpoint> {
        self.endpoints
            .get(id.index())
            .and_then(|endpoints| endpoints.download.as_ref())
    }

    #[must_use]
    pub(crate) fn has_tun(&self) -> bool {
        self.config
            .inbounds
            .iter()
            .any(|inbound| matches!(inbound, InboundConfig::Tun(_)))
    }

    #[must_use]
    // Retained for FFI, Windows CLI, and memory tests that attach TUN I/O.
    #[cfg_attr(
        all(feature = "cli", not(feature = "invoke"), unix, not(test)),
        allow(dead_code)
    )]
    pub(crate) fn traffic_stats(&self) -> Option<Arc<TunTrafficStats>> {
        self.traffic_stats.clone()
    }

    // Sniffing remains a shared TUN capability, including Windows CLI.
    #[cfg_attr(
        all(feature = "cli", not(feature = "invoke"), unix, not(test)),
        allow(dead_code)
    )]
    fn domain_sniffer_config(&self) -> Option<Arc<crate::config::SnifferConfig>> {
        (self.has_tun() && self.config.sniffer.enable)
            .then(|| Arc::new(self.config.sniffer.clone()))
    }

    #[cfg(test)]
    fn build_proxy_graph(&self, dialer: Dialer) -> io::Result<BuiltProxyGraph> {
        build_proxy_graph(
            &self.config.proxies,
            &self.config.proxy_groups,
            &self.endpoints,
            self.limits,
            dialer,
            ResolutionContext::runtime(self.config.ipv6),
            &self.security,
        )
    }

    fn build_dispatcher(&self, dialer: Dialer) -> io::Result<BuiltRuntimeParts> {
        let mut parts = GraphBuilder {
            security: self.security.clone(),
            connections: Arc::default(),
            config: self.config.clone(),
            endpoints: self.endpoints.clone(),
            limits: self.limits,
            rules: self.rules.clone(),
            geo_matcher: self.geodata_registration.matcher(),
            previous_dns: None,
            data_dir: self
                .geodata_manager
                .store_dir()
                .parent()
                .map(std::path::Path::to_path_buf),
        }
        .build(dialer.clone())?;
        if let Some(cache) = self.provider_cache.lock().unwrap().take() {
            let resources = ProviderRuntime::new(cache, self, &parts, dialer);
            parts.dispatcher = resources.clone();
            parts.resources = Some(resources);
        }
        let report = self.geodata_registration.initial_report();
        if let Some(update) = self.config.geodata_update.as_ref().filter(|_| {
            report.geosite.required
                || report.geoip.required
                || report.asn.required
                || self
                    .config
                    .providers
                    .as_ref()
                    .is_some_and(|providers| !providers.rules.is_empty())
        }) {
            parts.geodata_updater = Some(GeoDataUpdateService::new(
                self.geodata_manager.clone(),
                parts.dispatcher.clone(),
                self.geodata_registration.updater_lease(),
                update.urls.clone(),
                self.config.global_ua.clone(),
                self.config.etag_support,
                update.auto_update && update.interval_hours > 0,
                self.security.clone(),
            ));
        }
        Ok(parts)
    }

    async fn bind_controller(
        &self,
        traffic: Option<Arc<TunTrafficStats>>,
        proxy_groups: Arc<ProxyGroups>,
    ) -> io::Result<Option<RuntimeController>> {
        let Some(config) = &self.config.external_controller else {
            return Ok(None);
        };
        #[cfg(any(feature = "inbound-http", feature = "inbound-socks5"))]
        {
            RuntimeController::bind(config, traffic, proxy_groups)
                .await
                .map(Some)
        }
        #[cfg(not(any(feature = "inbound-http", feature = "inbound-socks5")))]
        {
            let _ = (config, traffic, proxy_groups);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "external controller support is disabled at build time",
            ))
        }
    }

    /// Starts configured local proxy listeners. TUN is started separately once
    /// a platform descriptor and netstack are available.
    pub(crate) async fn start_local(self, dialer: Dialer) -> io::Result<RunningCore> {
        let dispatch = crate::logging::dispatch(self.config.log_level);
        self.start_local_inner(dialer)
            .with_subscriber(dispatch)
            .await
    }

    async fn start_local_inner(self, dialer: Dialer) -> io::Result<RunningCore> {
        let BuiltRuntimeParts {
            dispatcher,
            geodata_updater,
            proxy_groups,
            proxy_graph,
            resources,
            ..
        } = self.build_dispatcher(dialer)?;
        let controller = self.bind_controller(None, proxy_groups).await?;
        #[cfg(any(feature = "inbound-http", feature = "inbound-socks5"))]
        let controller = {
            let control = resources.as_ref().map(|resources| {
                resources.clone() as Arc<dyn crate::resource::control::RuntimeResources>
            });
            controller.map(|controller| controller.with_resources(control))
        };
        RunningCore::start_components(
            &self.config.inbounds,
            dispatcher,
            None,
            None,
            controller,
            geodata_updater,
            self.geodata_registration,
            proxy_graph,
            resources,
        )
        .await
    }

    #[must_use]
    pub(crate) fn tun_config(&self) -> Option<&crate::config::TunConfig> {
        self.config.tun.enable.then_some(&self.config.tun)
    }

    /// Ordinary Windows sessions own a Wintun adapter. Packaged VPN
    /// sessions supply their packet adapter explicitly through `start_tun`.
    #[cfg(all(windows, feature = "windows-wintun"))]
    pub(crate) async fn start_wintun(self, dialer: Dialer) -> io::Result<RunningCore> {
        // Creation stays in the startup future; callers must await it through
        // shutdown rather than detach native work onto a blocking task.
        let config = self.tun_config().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "TUN configuration is missing")
        })?;
        let device = crate::platform::WindowsWintunIo::open(&config.device, config.mtu)?;
        self.start_tun(TunIo::from_wintun(device), dialer).await
    }

    /// Starts the configured TUN listener and any loopback HTTP listener in the
    /// same cancellation domain.
    #[cfg(all(
        feature = "tun",
        any(
            unix,
            all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
        )
    ))]
    // Unix CLI supplies no descriptor; FFI, Windows CLI, and tests use this seam.
    #[cfg_attr(
        all(feature = "cli", not(feature = "invoke"), unix, not(test)),
        allow(dead_code)
    )]
    pub(crate) async fn start_tun(self, tun: TunIo, dialer: Dialer) -> io::Result<RunningCore> {
        let dispatch = crate::logging::dispatch(self.config.log_level);
        self.start_tun_inner(tun, dialer)
            .with_subscriber(dispatch)
            .await
    }

    #[cfg(all(feature = "tun", target_os = "linux"))]
    pub(crate) async fn start_native_tun(self, dialer: Dialer) -> io::Result<RunningCore> {
        let (tun, dialer, mut network) = crate::platform::linux_network::open(
            &self.config.tun,
            &self.config.dns,
            self.config.ipv6,
            dialer,
        )?;
        match self.start_tun(tun, dialer).await {
            Ok(mut running) => {
                running.system_network = network;
                Ok(running)
            }
            Err(error) => {
                if let Some(network) = &mut network {
                    network.restore()?;
                }
                Err(error)
            }
        }
    }

    #[cfg(all(
        feature = "tun",
        any(
            unix,
            all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
        )
    ))]
    async fn start_tun_inner(mut self, tun: TunIo, dialer: Dialer) -> io::Result<RunningCore> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let dialer = dialer.with_dns_tun_interface(tun.interface_name().ok().map(Into::into));
        self.limits.tun_max_datagram_size = usize::from(self.config.tun.mtu);
        let tun_count = self
            .config
            .inbounds
            .iter()
            .filter(|inbound| matches!(inbound, InboundConfig::Tun(_)))
            .count();
        if tun_count != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("start_tun requires exactly one TUN listener, found {tun_count}"),
            ));
        }
        let BuiltRuntimeParts {
            dispatcher,
            dns,
            geodata_updater,
            proxy_groups,
            proxy_graph,
            resources,
            ..
        } = self.build_dispatcher(dialer)?;
        let sniffer = self.domain_sniffer_config();
        let traffic_stats = self
            .traffic_stats()
            .unwrap_or_else(|| Arc::new(TunTrafficStats::default()));
        let control = resources.as_ref().map(|resources| {
            resources.clone() as Arc<dyn crate::resource::control::RuntimeResources>
        });
        let controller = self
            .bind_controller(Some(traffic_stats.clone()), proxy_groups)
            .await?
            .map(|controller| controller.with_resources(control.clone()));
        let tun_runtime = TunRuntime::new_with_stats(
            tun,
            self.limits,
            self.tun_config().expect("validated TUN configuration"),
            dispatcher.clone(),
            dns,
            self.config.ipv6,
            true,
            sniffer,
            traffic_stats.clone(),
        )?
        .with_resources(control);
        RunningCore::start_components(
            &self.config.inbounds,
            dispatcher,
            Some(tun_runtime),
            Some(traffic_stats),
            controller,
            geodata_updater,
            self.geodata_registration,
            proxy_graph,
            resources,
        )
        .await
    }
}

struct GraphBuilder {
    security: SecurityContext,
    connections: Arc<crate::connections::Registry>,
    config: Config,
    endpoints: Vec<PreparedProxyEndpoints>,
    limits: ResourceLimits,
    rules: RuleSet,
    geo_matcher: Arc<dyn GeoMatcher>,
    previous_dns: Option<Arc<RuntimeDns>>,
    data_dir: Option<std::path::PathBuf>,
}
impl GraphBuilder {
    fn build(&self, dialer: Dialer) -> io::Result<BuiltRuntimeParts> {
        let dialer = dialer
            .with_ipv6(self.config.ipv6)
            .with_connections(self.config.connections)
            .with_fresh_initialization();
        let handshake_stats = RuntimeResourceStats::new("runtime_handshake_observation");
        let proxy_graph = self.build_proxy_graph(dialer.clone())?;
        let proxy_dispatchers = self.wrap_proxy_dispatchers(
            proxy_graph.connectors(),
            &handshake_stats,
            &proxy_graph.resolution,
        )?;
        let activities = proxy_dispatchers
            .iter()
            .map(|_| health::Activity::new())
            .collect::<Vec<_>>();
        let proxy_dispatchers = proxy_dispatchers
            .into_iter()
            .zip(&activities)
            .map(|(dispatcher, activity)| {
                Arc::new(health::ActiveDispatcher {
                    dispatcher,
                    activity: activity.clone(),
                }) as Arc<dyn Dispatcher>
            })
            .collect::<Vec<_>>();
        let direct_raw: Arc<dyn Dispatcher> = Arc::new(DirectOutbound::new(dialer.clone()));
        let direct = observe_handshakes_with_stats(direct_raw, handshake_stats.clone());
        let proxy_groups = ProxyGroups::with_selections(
            &self.config.proxy_groups,
            proxy_dispatchers.clone(),
            direct.clone(),
            &proxy_graph.selections,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let route_targets =
            RouteTargetDispatchers::with_proxy_groups(proxy_dispatchers, &proxy_groups)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let rules = self.rules.clone();
        let redir_host_entries = if self.config.dns.enable
            && (self.rules.uses_domain_routing() || self.config.sniffer.enable)
        {
            self.limits.dns_redir_host_entries
        } else {
            0
        };
        let geo_matcher = self.geo_matcher.clone();
        let mut dns_config = self.config.dns.clone();
        if !dns_config.enable {
            dns_config.ipv6 = self.config.ipv6;
        }
        let dns = Some(Arc::new(
            RuntimeDns::new_routed_proxies_with_cache_limits_and_security(
                &dns_config,
                route_targets.clone(),
                direct.clone(),
                rules.clone(),
                geo_matcher.clone(),
                dns_config.cache_max_size,
                redir_host_entries,
                self.security.clone(),
            )
            .with_network_sources(
                dialer.clone(),
                crate::dns::source::SourceExclusions {
                    interface: dialer.dns_tun_interface().or_else(|| {
                        (self.config.tun.enable && !self.config.tun.device.is_empty())
                            .then(|| self.config.tun.device.as_str().into())
                    }),
                    addresses: if self.config.tun.enable {
                        vec![
                            self.config
                                .dns
                                .fake_ip
                                .range
                                .map(|range| range.interface_address)
                                .unwrap_or_else(|| "198.18.0.1".parse().unwrap()),
                            self.config
                                .dns
                                .fake_ip
                                .range
                                .map(|range| match range.interface_address {
                                    std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(
                                        std::net::Ipv4Addr::from(u32::from(ip).saturating_add(1)),
                                    ),
                                    ip => ip,
                                })
                                .unwrap_or_else(|| "198.18.0.2".parse().unwrap()),
                            "fdfe:dcba:9876::1".parse().unwrap(),
                            "fdfe:dcba:9876::2".parse().unwrap(),
                        ]
                    } else {
                        Vec::new()
                    },
                },
            )
            .with_mapping_from(self.previous_dns.as_deref())
            .with_fake_ip_store(
                if self.config.profile.store_fake_ip && self.previous_dns.is_none() {
                    self.data_dir.as_deref()
                } else {
                    None
                },
            )?,
        ));
        if let Some(dns) = &dns {
            dns.network_sources().register(dns);
        }
        proxy_graph.resolution.bind_runtime(dns.as_ref())?;
        let health = health::HealthRuntime::new(
            &self.config,
            proxy_groups.clone(),
            route_targets.clone(),
            direct.clone(),
            activities,
            dns.clone(),
            self.security.clone(),
        );
        let diagnostics = self.config.external_controller.as_ref().map(|_| {
            Arc::new(diagnostics::Diagnostics::new(
                &self.config,
                &rules,
                self.connections.clone(),
            ))
        });
        let mut router = RoutingDispatcher::new_with_ipv6(
            route_targets.clone(),
            direct.clone(),
            dns.clone(),
            self.config.ipv6,
            rules,
            geo_matcher,
        )
        .with_tun_config(&self.config.tun)
        .with_sniffer(&self.config.sniffer)
        .with_tcp_concurrent(self.config.connections.tcp_concurrent);
        if let Some(diagnostics) = &diagnostics {
            router = router.with_diagnostics(diagnostics.clone());
        }
        let router: Arc<dyn Dispatcher> = Arc::new(router);
        let session_stats = RuntimeResourceStats::new("runtime_session_observation");
        Ok(BuiltRuntimeParts {
            connections: self.connections.clone(),
            diagnostics,
            dispatcher: observe_sessions_with_stats(router, session_stats),
            dns,
            geodata_updater: None,
            proxy_groups,
            proxy_graph: Arc::new(proxy_graph),
            resources: None,
            health,
            resource_targets: route_targets,
            direct,
        })
    }

    fn build_proxy_graph(&self, dialer: Dialer) -> io::Result<BuiltProxyGraph> {
        build_proxy_graph(
            &self.config.proxies,
            &self.config.proxy_groups,
            &self.endpoints,
            self.limits,
            dialer,
            ResolutionContext::runtime(self.config.ipv6),
            &self.security,
        )
    }

    fn wrap_proxy_dispatchers(
        &self,
        connectors: &[Arc<dyn OutboundConnector>],
        handshake_stats: &RuntimeResourceStats,
        resolution: &ResolutionContext,
    ) -> io::Result<Vec<Arc<dyn Dispatcher>>> {
        let mut dispatchers = Vec::with_capacity(connectors.len());
        for (proxy, connector) in self.config.proxies.iter().zip(connectors) {
            let mut dispatcher: Arc<dyn Dispatcher> = Arc::new(
                ConnectorDispatcher::with_udp_capability(connector.clone(), proxy.udp)
                    .with_resolution(resolution.clone()),
            );
            dispatcher = observe_handshakes_with_stats(dispatcher, handshake_stats.clone());
            dispatchers.push(dispatcher);
        }
        Ok(dispatchers)
    }
}

#[cfg(feature = "invoke")]
impl PreparedMeasurement {
    pub(crate) async fn prepare_config(
        config: MeasureConfig,
        resolver: &dyn Resolver,
        limits: ResourceLimits,
    ) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let endpoints = prepare_proxy_endpoints(&config.proxies, &[], resolver, true).await?;
        let trust = config.tls.clone();
        let security = tokio::task::spawn_blocking(move || SecurityContext::load(&trust))
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            config,
            security,
            endpoints,
            limits,
        })
    }

    pub(crate) fn into_runtime(self, dialer: Dialer) -> io::Result<MeasurementRuntime> {
        self.into_runtime_with_resolver(dialer, Arc::new(crate::dialer::SystemResolver))
    }

    pub(crate) fn into_runtime_with_resolver(
        self,
        dialer: Dialer,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<MeasurementRuntime> {
        let dialer = dialer.with_fresh_initialization();
        let proxy_graph = build_proxy_graph(
            &self.config.proxies,
            &[],
            &self.endpoints,
            self.limits,
            dialer,
            ResolutionContext::measurement(resolver, true),
            &self.security,
        )?;
        let connector = proxy_graph
            .get(self.config.default_proxy.index())
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "default proxy is missing from the measurement graph",
                )
            })?;
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(
            ConnectorDispatcher::new(connector).with_resolution(proxy_graph.resolution.clone()),
        );
        let handshake_stats = RuntimeResourceStats::new("measurement_handshake_observation");
        let dispatcher = observe_handshakes_with_stats(dispatcher, handshake_stats);
        let session_stats = RuntimeResourceStats::new("measurement_session_observation");
        Ok(MeasurementRuntime {
            security: self.security,
            dispatcher: observe_sessions_with_stats(dispatcher, session_stats),
            proxy_graph: Arc::new(proxy_graph),
        })
    }
}

fn build_proxy_graph(
    proxies: &[ProxyConfig],
    groups: &[SelectProxyGroupConfig],
    endpoints: &[PreparedProxyEndpoints],
    limits: ResourceLimits,
    dialer: Dialer,
    resolution: ResolutionContext,
    security: &SecurityContext,
) -> io::Result<BuiltProxyGraph> {
    if endpoints.len() != proxies.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy endpoint registry length does not match the proxy graph",
        ));
    }
    let order = proxy_graph_order(proxies, groups)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    #[cfg(any(
        feature = "outbound-http",
        feature = "outbound-socks5",
        feature = "outbound-anytls",
        feature = "outbound-vless",
        feature = "outbound-trojan",
        feature = "outbound-vmess",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "shadow-tls-v3"
    ))]
    let (_, standard_tls_count) = security_counts(proxies);
    #[cfg(any(
        feature = "outbound-http",
        feature = "outbound-socks5",
        feature = "outbound-anytls",
        feature = "outbound-vless",
        feature = "outbound-trojan",
        feature = "outbound-vmess",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "shadow-tls-v3"
    ))]
    let security_context = Some(security.clone());
    #[cfg(any(
        feature = "outbound-http",
        feature = "outbound-socks5",
        feature = "outbound-anytls",
        feature = "outbound-vless",
        feature = "outbound-trojan",
        feature = "outbound-vmess",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "shadow-tls-v3"
    ))]
    let resumption_sessions = standard_tls_resumption_sessions(standard_tls_count);

    // Declared before the temporary registries: even on partial construction
    // failure they drop first, then this guard releases the DAG in reverse
    // dependency order without recursive destruction of configuration-sized chains.
    let mut graph = BuiltProxyGraph {
        dialer: dialer.clone(),
        resolution,
        nodes: Vec::new(),
        lifecycle_order: Vec::with_capacity(order.len()),
        selections: groups
            .iter()
            .map(|group| {
                let selection = Arc::new(crate::routing::GroupSelection::new(group.initial_member));
                selection.configure_balance(group);
                selection
            })
            .collect(),
    };
    let mut nodes: Vec<Option<Arc<dyn OutboundConnector>>> = vec![None; proxies.len()];
    let mut group_nodes: Vec<Option<Arc<SelectUpstream>>> = vec![None; groups.len()];
    for target in order {
        let index = match target {
            RouteTargetId::Group(id) => {
                let config = &groups[id.index()];
                let members = config
                    .members
                    .iter()
                    .map(|member| match member.target {
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(id)) => {
                            SelectUpstreamMember::Proxy(
                                nodes[id.index()]
                                    .as_ref()
                                    .expect("dependency built")
                                    .clone(),
                            )
                        }
                        ProxyGroupMemberTarget::Route(RouteTargetId::Group(id)) => {
                            SelectUpstreamMember::Group(
                                group_nodes[id.index()]
                                    .as_ref()
                                    .expect("dependency built")
                                    .clone(),
                            )
                        }
                        ProxyGroupMemberTarget::Direct => SelectUpstreamMember::Direct,
                        ProxyGroupMemberTarget::Reject => SelectUpstreamMember::Reject,
                        ProxyGroupMemberTarget::Control(_) => SelectUpstreamMember::Control,
                    })
                    .collect();
                let group = Arc::new(
                    SelectUpstream::new(graph.selections[id.index()].clone(), members)
                        .with_udp_disabled(config.disable_udp),
                );
                group_nodes[id.index()] = Some(group.clone());
                graph.lifecycle_order.push(BuiltRouteTarget::Group(group));
                continue;
            }
            RouteTargetId::Proxy(id) => id.index(),
        };
        let proxy = &proxies[index];
        let node_dialer = dialer.clone().with_ip_version(proxy.ip_version);
        let upstream = build_upstream_path(
            crate::outbound::server_destination(proxy.address(), proxy.port())?,
            proxy.dialer_proxy,
            endpoints[index].upload.clone(),
            &nodes,
            &group_nodes,
            &node_dialer,
        )?;
        let connector: Arc<dyn OutboundConnector> = match &proxy.protocol {
            ProxyProtocol::WireGuard(config) => {
                #[cfg(feature = "outbound-wireguard")]
                {
                    Arc::new(
                        crate::outbound::wireguard::WireGuardOutbound::with_shared_security(
                            config, upstream, security,
                        )?,
                    )
                }
                #[cfg(not(feature = "outbound-wireguard"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "WireGuard support is disabled",
                    ));
                }
            }
            ProxyProtocol::Http(config) => {
                #[cfg(feature = "outbound-http")]
                {
                    Arc::new(crate::outbound::http::HttpOutbound::with_shared_security(
                        config,
                        upstream,
                        security_context.as_ref().expect("HTTP security context"),
                        resumption_sessions,
                        limits.tls_buffer_limit,
                    )?)
                }
                #[cfg(not(feature = "outbound-http"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "HTTP outbound support is disabled",
                    ));
                }
            }
            ProxyProtocol::Tuic(config) => {
                #[cfg(feature = "outbound-tuic")]
                {
                    Arc::new(crate::outbound::tuic::TuicOutbound::with_shared_security(
                        config,
                        upstream,
                        security_context.as_ref().expect("TLS context"),
                        limits.tls_buffer_limit,
                    )?)
                }
                #[cfg(not(feature = "outbound-tuic"))]
                {
                    let _ = config;
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "TUIC support is disabled in this build",
                    ));
                }
            }
            ProxyProtocol::Hysteria2(config) => {
                #[cfg(feature = "outbound-hysteria2")]
                {
                    Arc::new(
                        crate::outbound::hysteria2::Hysteria2Outbound::with_shared_security(
                            config,
                            upstream,
                            security_context.as_ref().expect("TLS context"),
                            resumption_sessions,
                            limits.tls_buffer_limit,
                        )?,
                    )
                }
                #[cfg(not(feature = "outbound-hysteria2"))]
                {
                    let _ = config;
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Hysteria2 support is disabled in this build",
                    ));
                }
            }
            ProxyProtocol::Vmess(config) => {
                #[cfg(feature = "outbound-vmess")]
                {
                    Arc::new(crate::outbound::vmess::VmessOutbound::with_shared_security(
                        config,
                        upstream,
                        security_context.as_ref().expect("VMess security context"),
                        resumption_sessions,
                        limits.tls_buffer_limit,
                    )?)
                }
                #[cfg(not(feature = "outbound-vmess"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "VMess outbound support is disabled at build time",
                    ));
                }
            }
            ProxyProtocol::Trojan(config) => {
                #[cfg(feature = "outbound-trojan")]
                {
                    Arc::new(TrojanOutbound::with_shared_security(
                        config,
                        upstream,
                        security_context
                            .as_ref()
                            .expect("Trojan graph has security material"),
                        resumption_sessions,
                        limits.tls_buffer_limit,
                    )?)
                }
                #[cfg(not(feature = "outbound-trojan"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Trojan outbound support is disabled at build time",
                    ));
                }
            }
            ProxyProtocol::Shadowsocks(config) => {
                #[cfg(feature = "outbound-shadowsocks")]
                {
                    #[cfg(feature = "shadow-tls-v3")]
                    let security = security_context.as_ref();
                    Arc::new(ShadowsocksOutbound::with_security(
                        config,
                        upstream,
                        #[cfg(feature = "shadow-tls-v3")]
                        security,
                    )?)
                }
                #[cfg(not(feature = "outbound-shadowsocks"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Shadowsocks outbound support is disabled at build time",
                    ));
                }
            }
            ProxyProtocol::Vless(config) => {
                #[cfg(feature = "outbound-vless")]
                {
                    let download_upstream = config
                        .download()
                        .map(|download| {
                            build_upstream_path(
                                crate::outbound::server_destination(
                                    &download.address,
                                    download.port,
                                )?,
                                proxy.dialer_proxy,
                                endpoints[index].download.clone(),
                                &nodes,
                                &group_nodes,
                                &node_dialer,
                            )
                        })
                        .transpose()?;
                    Arc::new(VlessOutbound::new_with_shared_security(
                        config,
                        upstream,
                        download_upstream,
                        security_context
                            .as_ref()
                            .expect("VLESS graph has shared security material"),
                        resumption_sessions,
                        VlessResourceLimits::new(
                            limits.tls_buffer_limit,
                            limits.xhttp_send_buffer_size,
                            limits.xhttp_upload_chunk_size,
                        ),
                    )?)
                }
                #[cfg(not(feature = "outbound-vless"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "VLESS outbound support is disabled at build time",
                    ));
                }
            }
            ProxyProtocol::Socks5(config) => {
                #[cfg(feature = "outbound-socks5")]
                {
                    Arc::new(Socks5Outbound::with_shared_security(
                        config,
                        upstream,
                        security_context.as_ref(),
                        resumption_sessions,
                        limits.tls_buffer_limit,
                    )?)
                }
                #[cfg(not(feature = "outbound-socks5"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "SOCKS5 outbound support is disabled at build time",
                    ));
                }
            }
            ProxyProtocol::AnyTls(config) => {
                #[cfg(feature = "outbound-anytls")]
                {
                    let tls = StandardTlsClient::with_options(
                        security_context
                            .as_ref()
                            .expect("AnyTLS graph has shared security material"),
                        &config.server_name,
                        crate::security::TlsClientOptions::from_policy(&config.tls, None)?,
                        resumption_sessions,
                        limits.tls_buffer_limit,
                    )?;
                    Arc::new(AnyTlsOutbound::new(
                        server_destination(&config.address, config.port)?,
                        upstream,
                        &config.password,
                        Arc::new(tls),
                        limits.tcp_buffer_per_direction,
                    )?)
                }
                #[cfg(not(feature = "outbound-anytls"))]
                {
                    let _ = (config, upstream);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "AnyTLS outbound support is disabled at build time",
                    ));
                }
            }
        };

        #[cfg(feature = "sing-mux")]
        let connector: Arc<dyn OutboundConnector> = if let Some(options) = &proxy.smux {
            Arc::new(crate::outbound::SingMuxConnector::new(
                connector,
                options.clone(),
            ))
        } else {
            connector
        };
        let connector: Arc<dyn OutboundConnector> = Arc::new(crate::outbound::IpVersionConnector {
            inner: connector,
            version: proxy.ip_version,
        });
        graph
            .lifecycle_order
            .push(BuiltRouteTarget::Proxy(connector.clone()));
        nodes[index] = Some(connector);
    }
    graph.nodes = nodes
        .into_iter()
        .map(|node| node.expect("every validated proxy graph node was built"))
        .collect();
    Ok(graph)
}

fn build_upstream_path(
    server: crate::session::Destination,
    parent: Option<RouteTargetId>,
    endpoint: Option<ResolvedEndpoint>,
    nodes: &[Option<Arc<dyn OutboundConnector>>],
    groups: &[Option<Arc<SelectUpstream>>],
    dialer: &Dialer,
) -> io::Result<UpstreamPath> {
    match parent {
        Some(RouteTargetId::Proxy(id)) => Ok(UpstreamPath::proxy(
            nodes[id.index()]
                .as_ref()
                .expect("dependency built")
                .clone(),
        )),
        Some(RouteTargetId::Group(id)) => Ok(UpstreamPath::Group {
            server,
            group: groups[id.index()]
                .as_ref()
                .expect("dependency built")
                .clone(),
            endpoint,
            dialer: dialer.clone(),
        }),
        None => Ok(endpoint.map_or_else(
            || UpstreamPath::LazyDirect {
                dialer: dialer.clone(),
            },
            |endpoint| UpstreamPath::direct(endpoint, dialer.clone()),
        )),
    }
}

async fn prepare_proxy_endpoints(
    proxies: &[ProxyConfig],
    groups: &[SelectProxyGroupConfig],
    resolver: &dyn Resolver,
    ipv6: bool,
) -> io::Result<Vec<PreparedProxyEndpoints>> {
    let order = proxy_graph_order(proxies, groups)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut direct_groups = vec![false; groups.len()];
    for target in order {
        if let RouteTargetId::Group(id) = target {
            direct_groups[id.index()] =
                groups[id.index()]
                    .members
                    .iter()
                    .any(|member| match member.target {
                        ProxyGroupMemberTarget::Direct => true,
                        ProxyGroupMemberTarget::Route(RouteTargetId::Group(child)) => {
                            direct_groups[child.index()]
                        }
                        _ => false,
                    });
        }
    }
    let lookups = proxies
        .iter()
        .enumerate()
        .filter(|(_, proxy)| match proxy.dialer_proxy {
            None => true,
            Some(RouteTargetId::Group(id)) => direct_groups[id.index()],
            Some(RouteTargetId::Proxy(_)) => false,
        })
        .map(|(index, proxy)| async move {
            let upload_address = proxy.address();
            let upload_port = proxy.port();
            let download = match &proxy.protocol {
                ProxyProtocol::Vless(config) => config.download(),
                ProxyProtocol::WireGuard(_)
                | ProxyProtocol::Http(_)
                | ProxyProtocol::Socks5(_)
                | ProxyProtocol::Trojan(_)
                | ProxyProtocol::Vmess(_)
                | ProxyProtocol::AnyTls(_)
                | ProxyProtocol::Shadowsocks(_)
                | ProxyProtocol::Tuic(_)
                | ProxyProtocol::Hysteria2(_) => None,
            };

            let (upload, download) = match download {
                Some(download)
                    if download.address != upload_address || download.port != upload_port =>
                {
                    let (upload, download) = tokio::join!(
                        resolver.resolve(upload_address, upload_port),
                        resolver.resolve(&download.address, download.port),
                    );
                    (upload?, Some(download?))
                }
                Some(_) => {
                    let upload = resolver.resolve(upload_address, upload_port).await?;
                    (upload.clone(), Some(upload))
                }
                None => (resolver.resolve(upload_address, upload_port).await?, None),
            };
            let upload = restrict_endpoint_addresses(upload, ipv6)?;
            let download = download
                .map(|endpoint| restrict_endpoint_addresses(endpoint, ipv6))
                .transpose()?;
            Ok::<_, io::Error>((
                index,
                PreparedProxyEndpoints {
                    upload: Some(upload),
                    download,
                },
            ))
        });
    let resolved = tokio::time::timeout(Duration::from_secs(10), join_all(lookups))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bootstrap DNS timed out"))?;
    let mut endpoints = vec![PreparedProxyEndpoints::default(); proxies.len()];
    for endpoint in resolved {
        let (index, endpoint) = endpoint?;
        endpoints[index] = endpoint;
    }
    Ok(endpoints)
}

fn restrict_endpoint_addresses(
    mut endpoint: ResolvedEndpoint,
    ipv6: bool,
) -> io::Result<ResolvedEndpoint> {
    if ipv6 {
        return Ok(endpoint);
    }
    endpoint.addresses.retain(SocketAddr::is_ipv4);
    if endpoint.addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "proxy server did not resolve to a permitted address",
        ));
    }
    Ok(endpoint)
}

#[cfg(any(
    feature = "outbound-http",
    feature = "outbound-socks5",
    feature = "outbound-anytls",
    feature = "outbound-vless",
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic",
    feature = "shadow-tls-v3"
))]
fn security_counts(proxies: &[ProxyConfig]) -> (usize, usize) {
    proxies.iter().fold(
        (0, 0),
        |(client_count, standard_count), proxy| match &proxy.protocol {
            ProxyProtocol::Vless(config) => {
                let download = config.download();
                (
                    client_count + 1 + usize::from(download.is_some()),
                    standard_count
                        + usize::from(matches!(
                            &config.security,
                            crate::config::SecurityConfig::Tls(_)
                        ))
                        + download.map_or(0, |download| {
                            usize::from(matches!(
                                &download.security,
                                crate::config::SecurityConfig::Tls(_)
                            ))
                        }),
                )
            }
            ProxyProtocol::AnyTls(_) | ProxyProtocol::Trojan(_) | ProxyProtocol::Hysteria2(_) => {
                (client_count + 1, standard_count + 1)
            }
            ProxyProtocol::Vmess(config) => (
                client_count + 1,
                standard_count + usize::from(config.tls.is_some()),
            ),
            ProxyProtocol::Shadowsocks(config) => (
                client_count + usize::from(config.shadow_tls.is_some()),
                standard_count,
            ),
            ProxyProtocol::Http(config) => (
                client_count + 1,
                standard_count + usize::from(config.tls.is_some()),
            ),
            ProxyProtocol::Socks5(config) => (
                client_count + usize::from(config.tls.is_some()),
                standard_count + usize::from(config.tls.is_some()),
            ),
            ProxyProtocol::Tuic(_) => (client_count + 1, standard_count),
            ProxyProtocol::WireGuard(_) => (client_count, standard_count),
        },
    )
}

#[cfg(any(
    feature = "outbound-http",
    feature = "outbound-socks5",
    feature = "outbound-anytls",
    feature = "outbound-vless",
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic",
    feature = "shadow-tls-v3"
))]
fn standard_tls_resumption_sessions(standard_tls_count: usize) -> usize {
    if standard_tls_count == 0 || standard_tls_count > TLS_RESUMPTION_SESSION_BUDGET {
        0
    } else {
        TLS_RESUMPTION_SESSION_BUDGET / standard_tls_count
    }
}

fn prepare_routing(
    config: &mut Config,
    geodata_manager: &Arc<GeoDataManager>,
) -> io::Result<(RuleSet, GeoDataRegistration)> {
    let requirements = GeoRequirements::for_config(config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let geodata_registration = geodata_manager
        .register_with_interval(
            requirements,
            Duration::from_secs(
                config
                    .geodata_update
                    .as_ref()
                    .map_or(crate::config::GEO_UPDATE_INTERVAL_HOURS, |update| {
                        update.interval_hours
                    })
                    * 3600,
            ),
        )
        .map_err(io::Error::other)?;
    // GeoData must inspect the normalized rule specifications first. Once that
    // borrowing load is complete, move the rules directly into the compiled
    // set so PreparedCore does not retain a second owned rule graph.
    let rules = RuleSet::compile_config(config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok((rules, geodata_registration))
}

pub(crate) struct RunningCore {
    #[cfg(all(feature = "tun", target_os = "linux"))]
    system_network: Option<crate::platform::linux_network::NetworkLease>,
    cancellation: CancellationToken,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    traffic_stats: Option<Arc<TunTrafficStats>>,
    proxy_graph: Arc<BuiltProxyGraph>,
    resources: Option<Arc<ProviderRuntime>>,
    _geodata_registration: GeoDataRegistration,
}

impl std::fmt::Debug for RunningCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningCore")
            .field("task_count", &self.tasks.len())
            .field("has_traffic_stats", &self.traffic_stats.is_some())
            .finish_non_exhaustive()
    }
}

impl RunningCore {
    // Runtime construction keeps ownership transfers explicit; grouping these
    // independent components into another one-use container would only hide
    // the shutdown responsibilities enforced below.
    #[allow(clippy::too_many_arguments)]
    async fn start_components(
        inbounds: &[InboundConfig],
        dispatcher: Arc<dyn Dispatcher>,
        tun_runtime: Option<TunRuntime>,
        traffic_stats: Option<Arc<TunTrafficStats>>,
        controller: Option<RuntimeController>,
        geodata_updater: Option<GeoDataUpdateService>,
        geodata_registration: GeoDataRegistration,
        proxy_graph: Arc<BuiltProxyGraph>,
        resources: Option<Arc<ProviderRuntime>>,
    ) -> io::Result<Self> {
        let cancellation = CancellationToken::new();
        let mut tasks = Vec::with_capacity(
            inbounds.len()
                + usize::from(tun_runtime.is_some())
                + usize::from(controller.is_some())
                + usize::from(geodata_updater.is_some()),
        );
        #[cfg(not(all(feature = "inbound-http", feature = "inbound-socks5")))]
        let _ = &dispatcher;

        // Bind every listener before spawning anything. All acquired sockets,
        // the already-bound Controller and the untouched graph roll back by RAII.
        #[cfg(all(feature = "inbound-http", feature = "inbound-socks5"))]
        let mut mixed_servers = Vec::new();

        for inbound in inbounds {
            match inbound {
                InboundConfig::Mixed(config) => {
                    #[cfg(not(all(feature = "inbound-http", feature = "inbound-socks5")))]
                    {
                        let _ = config;
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "mixed listener requires HTTP and SOCKS5 support at build time",
                        ));
                    }
                    #[cfg(all(feature = "inbound-http", feature = "inbound-socks5"))]
                    mixed_servers.push(
                        MixedServer::bind(config.clone(), dispatcher.clone())?
                            .with_connections(proxy_graph.dialer.connections()),
                    );
                }
                InboundConfig::Tun(_) => {
                    if tun_runtime.is_none() {
                        cancellation.cancel();
                        abort_and_join(&mut tasks).await;
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "TUN listener requires start_tun with a platform descriptor",
                        ));
                    }
                }
            }
        }

        #[cfg(all(feature = "inbound-http", feature = "inbound-socks5"))]
        for server in mixed_servers {
            let child = cancellation.clone();
            tasks.push(crate::resources::observation::spawn(server.serve(child)));
        }

        #[cfg(all(
            feature = "tun",
            any(
                unix,
                all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
            )
        ))]
        if let Some(tun_runtime) = tun_runtime {
            let child = cancellation.clone();
            tasks.push(crate::resources::observation::spawn(tun_runtime.run(child)));
        }

        #[cfg(any(feature = "inbound-http", feature = "inbound-socks5"))]
        if let Some(controller) = controller {
            let child = cancellation.clone();
            tasks.push(crate::resources::observation::spawn(
                controller.serve(child),
            ));
        }

        #[cfg(not(any(feature = "inbound-http", feature = "inbound-socks5")))]
        debug_assert!(controller.is_none());

        if let Some(geodata_updater) = geodata_updater {
            let child = cancellation.clone();
            tasks.push(crate::resources::observation::spawn(
                geodata_updater.run(child),
            ));
        }

        if let Some(resources) = &resources {
            tasks.push(crate::resources::observation::spawn(
                resources.clone().run(cancellation.clone()),
            ));
        }
        Ok(Self {
            #[cfg(all(feature = "tun", target_os = "linux"))]
            system_network: None,
            resources,
            cancellation,
            tasks,
            traffic_stats,
            proxy_graph,
            _geodata_registration: geodata_registration,
        })
    }

    pub(crate) async fn stop(self) -> io::Result<()> {
        self.run_until_shutdown(std::future::ready(Ok(()))).await
    }

    /// Runs until the host requests shutdown or any long-lived component
    /// exits. A component that ends before shutdown is always treated as a
    /// core failure, even when it returned `Ok(())`.
    pub(crate) async fn run_until_shutdown<F>(mut self, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = io::Result<()>>,
    {
        tokio::pin!(shutdown);
        let (completed, shutdown_error) = tokio::select! {
            biased;
            result = &mut shutdown => (None, result.err()),
            completed = wait_first_task(&mut self.tasks), if !self.tasks.is_empty() => (completed, None),
        };
        self.proxy_graph.begin_shutdown();
        if let Some(resources) = &self.resources {
            resources.begin_shutdown();
        }
        let result = stop_components(
            &self.cancellation,
            &mut self.tasks,
            shutdown_error.or_else(|| completed.map(component_completion_error)),
        )
        .await;
        self.proxy_graph.shutdown().await;
        if let Some(resources) = &self.resources {
            resources.shutdown().await;
        }
        #[cfg(all(feature = "tun", target_os = "linux"))]
        let result = if let Some(mut network) = self.system_network.take() {
            result.and(network.restore())
        } else {
            result
        };
        result
    }
}

async fn stop_components(
    cancellation: &CancellationToken,
    tasks: &mut Vec<JoinHandle<io::Result<()>>>,
    mut first_error: Option<io::Error>,
) -> io::Result<()> {
    cancellation.cancel();
    for task in tasks.drain(..) {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
            Err(error) if first_error.is_none() => first_error = Some(io::Error::other(error)),
            _ => {}
        }
    }
    first_error.map_or(Ok(()), Err)
}

async fn wait_first_task(
    tasks: &mut Vec<JoinHandle<io::Result<()>>>,
) -> Option<Result<io::Result<()>, tokio::task::JoinError>> {
    if tasks.is_empty() {
        return None;
    }
    let (result, index, remaining) = select_all(tasks.iter_mut()).await;
    drop(remaining);
    drop(tasks.swap_remove(index));
    Some(result)
}

fn component_completion_error(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Error {
    match result {
        Ok(Ok(())) => io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Vole runtime component stopped unexpectedly",
        ),
        Ok(Err(error)) => error,
        Err(error) => io::Error::other(error),
    }
}

impl Drop for RunningCore {
    fn drop(&mut self) {
        self.proxy_graph.begin_shutdown();
        if let Some(resources) = &self.resources {
            resources.begin_shutdown();
        }
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn abort_and_join(tasks: &mut Vec<JoinHandle<io::Result<()>>>) {
    for task in tasks.iter() {
        task.abort();
    }
    for task in tasks.drain(..) {
        let _ = task.await;
    }
}

#[cfg(test)]
mod shutdown_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn stopping_waits_for_component_cleanup() {
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let released = Arc::new(AtomicBool::new(false));
        let observed = released.clone();
        let (cancelled, cancelled_rx) = oneshot::channel();
        let (finish, finish_rx) = oneshot::channel();
        let component = tokio::spawn(async move {
            child.cancelled().await;
            cancelled.send(()).unwrap();
            finish_rx.await.unwrap();
            released.store(true, Ordering::SeqCst);
            Ok(())
        });
        let barrier = tokio::spawn(async move {
            let mut tasks = vec![component];
            stop_components(&cancellation, &mut tasks, None)
                .await
                .unwrap();
            assert!(tasks.is_empty());
        });

        cancelled_rx.await.unwrap();
        assert!(!barrier.is_finished());
        assert!(!observed.load(Ordering::SeqCst));
        finish.send(()).unwrap();
        barrier.await.unwrap();
        assert!(observed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn unexpected_component_exit_joins_siblings_before_reporting_failure() {
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let (started, started_rx) = oneshot::channel();
        let (cancelled, cancelled_rx) = oneshot::channel();
        let (finish, finish_rx) = oneshot::channel();
        let sibling = tokio::spawn(async move {
            started.send(()).unwrap();
            child.cancelled().await;
            cancelled.send(()).unwrap();
            finish_rx.await.unwrap();
            Err(io::Error::other("sibling cleanup failed"))
        });
        started_rx.await.unwrap();
        let completed = tokio::spawn(async { Ok(()) });
        let barrier = tokio::spawn(async move {
            let mut tasks = vec![completed, sibling];
            let failure = component_completion_error(wait_first_task(&mut tasks).await.unwrap());
            assert_eq!(failure.kind(), io::ErrorKind::UnexpectedEof);
            let result = stop_components(&cancellation, &mut tasks, Some(failure)).await;
            assert!(tasks.is_empty());
            result
        });

        cancelled_rx.await.unwrap();
        assert!(!barrier.is_finished());
        finish.send(()).unwrap();
        assert_eq!(
            barrier.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[cfg(test)]
#[path = "runtime_group_tests.rs"]
mod group_tests;

#[cfg(all(
    test,
    feature = "inbound-http",
    feature = "inbound-socks5",
    feature = "outbound-socks5"
))]
#[path = "runtime_socks_tests.rs"]
mod socks_tests;

#[cfg(test)]
mod tests {
    use crate::config::ProxyGroupId;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[cfg(all(
        feature = "tun",
        any(
            unix,
            all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
        )
    ))]
    use std::net::Ipv4Addr;

    #[cfg(all(unix, feature = "tun"))]
    use std::{os::fd::AsRawFd, os::unix::net::UnixDatagram};

    use async_trait::async_trait;
    use tempfile::tempdir;
    #[cfg(all(unix, feature = "tun"))]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    #[cfg(all(unix, feature = "tun"))]
    use crate::config::TunInboundConfig;
    use crate::dialer::ResolvedEndpoint;
    #[cfg(all(windows, feature = "tun"))]
    use crate::platform::TunIo;

    struct FixedResolver;

    #[tokio::test]
    async fn integration_feature_admission_is_explicit_without_opening_sockets() {
        let variants = [
            ("socks5", "", cfg!(feature = "outbound-socks5")),
            (
                "anytls",
                ", password: fixture",
                cfg!(feature = "outbound-anytls"),
            ),
            (
                "ss",
                ", cipher: 2022-blake3-aes-128-gcm, password: BwcHBwcHBwcHBwcHBwcHBw==",
                cfg!(feature = "outbound-shadowsocks"),
            ),
            (
                "trojan",
                ", password: fixture",
                cfg!(feature = "outbound-trojan"),
            ),
            (
                "vmess",
                ", uuid: 08080808-0808-0808-0808-080808080808",
                cfg!(feature = "outbound-vmess"),
            ),
            (
                "vless",
                ", uuid: 08080808-0808-0808-0808-080808080808",
                cfg!(feature = "outbound-vless"),
            ),
            (
                "hysteria2",
                ", password: fixture",
                cfg!(feature = "outbound-hysteria2"),
            ),
            (
                "tuic",
                ", uuid: 08080808-0808-0808-0808-080808080808, password: fixture",
                cfg!(feature = "outbound-tuic"),
            ),
            (
                "wireguard",
                ", ip: 10.84.0.2, private-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=, public-key: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                cfg!(feature = "outbound-wireguard"),
            ),
        ];
        for (protocol, fields, enabled) in variants {
            let _case = crate::resources::case_events::Case::new("INTEGRATION-FEATURE", protocol);
            let yaml = format!(
                "mixed-port: 1080\nproxies:\n  - {{name: peer, type: {protocol}, server: 127.0.0.1, port: 443{fields}}}\nrules: ['MATCH,peer']\n"
            );
            let result = match PreparedCore::prepare(
                yaml.as_bytes(),
                &FixedResolver,
                ResourceLimits::default(),
            )
            .await
            {
                Ok(core) => core
                    .build_proxy_graph(Dialer::default())
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                Err(error) => Err(error.to_string()),
            };
            if enabled {
                assert!(result.is_ok(), "{protocol}: {result:?}");
            } else {
                let error = result.unwrap_err();
                assert!(
                    error.contains("disabled") || error.contains("not enabled"),
                    "{protocol}: {error}"
                );
            }
        }
    }

    #[async_trait]
    impl Resolver for FixedResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
            Ok(ResolvedEndpoint {
                logical_host: host.to_owned(),
                port,
                addresses: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)],
            })
        }
    }

    #[derive(Default)]
    struct RecordingResolver {
        hosts: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Resolver for RecordingResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
            self.hosts.lock().unwrap().push(host.to_owned());
            Ok(ResolvedEndpoint {
                logical_host: host.to_owned(),
                port,
                addresses: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)],
            })
        }
    }

    #[derive(Default)]
    struct ConcurrentResolver {
        active: AtomicUsize,
        peak: AtomicUsize,
    }

    #[async_trait]
    impl Resolver for ConcurrentResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.peak.fetch_max(active, Ordering::AcqRel);
            tokio::time::sleep(Duration::from_millis(25)).await;
            self.active.fetch_sub(1, Ordering::AcqRel);
            Ok(ResolvedEndpoint {
                logical_host: host.to_owned(),
                port,
                addresses: vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)],
            })
        }
    }

    const CONFIG: &str = r#"mixed-port: 18080
authentication:
  - measure:secret
proxies:
  - name: proxy
    type: vless
    server: server.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      path: /x
      mode: packet-up
rules:
  - MATCH,proxy
"#;

    #[test]
    fn disabled_ipv6_filters_proxy_bootstrap_addresses() {
        let endpoint = ResolvedEndpoint {
            logical_host: "proxy.example".to_owned(),
            port: 443,
            addresses: vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
            ],
        };
        let filtered = restrict_endpoint_addresses(endpoint, false).unwrap();
        assert_eq!(filtered.addresses, vec!["192.0.2.1:443".parse().unwrap()]);

        let ipv6_only = ResolvedEndpoint {
            logical_host: "proxy.example".to_owned(),
            port: 443,
            addresses: vec!["[2001:db8::1]:443".parse().unwrap()],
        };
        assert_eq!(
            restrict_endpoint_addresses(ipv6_only, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    fn config_with_rules(rules: &str) -> String {
        CONFIG.replacen("rules:\n  - MATCH,proxy\n", rules, 1)
    }

    fn config_with_download(fields: &str) -> String {
        CONFIG.replace(
            "      mode: packet-up\n",
            &format!("      mode: packet-up\n      download-settings:\n{fields}\n"),
        )
    }

    #[tokio::test]
    async fn controller_diagnostics_are_opt_in_for_business_routes() {
        for controller in [false, true] {
            let mut yaml = String::from(
                "mixed-port: 1080\nproxy-groups: [{name: local, type: select, proxies: [REJECT]}]\nrules: ['MATCH,REJECT']\n",
            );
            if controller {
                yaml.push_str("external-controller: 127.0.0.1:9090\nsecret: test-token\n");
            }
            let prepared =
                PreparedCore::prepare(yaml.as_bytes(), &FixedResolver, ResourceLimits::default())
                    .await
                    .unwrap();
            let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
            let result = parts
                .dispatcher
                .connect_tcp(crate::session::StreamSession {
                    metadata: Default::default(),
                    inbound: crate::session::InboundKind::Socks5,
                    source: "127.0.0.1:12345".parse().unwrap(),
                    destination: crate::session::Destination::Ip("192.0.2.1:443".parse().unwrap()),
                    sniffed_domain: None,
                })
                .await;
            assert!(matches!(
                result,
                Err(crate::dispatch::DispatchError::NotAllowed)
            ));
            // REJECT exercises the assembled business path without opening a socket.
            assert_eq!(parts.diagnostics.is_some(), controller);
            let snapshot = serde_json::to_value(parts.connections.snapshot()).unwrap();
            assert_eq!(
                snapshot["errors"].as_array().unwrap().len(),
                usize::from(controller)
            );
            if let Some(diagnostics) = &parts.diagnostics {
                assert_eq!(diagnostics.rules()["rules"][0]["extra"]["hitCount"], 1);
            }
            parts.proxy_graph.shutdown().await;
        }
    }

    #[tokio::test]
    async fn prepares_udp_capabilities_through_runtime_wrappers() {
        let prepared = PreparedCore::prepare(
            br#"
mixed-port: 1080
proxies: [{name: tcp-only, type: socks5, server: 192.0.2.1, port: 1080}]
proxy-groups:
  - {name: selected, type: select, proxies: [tcp-only, DIRECT]}
  - {name: disabled, type: select, proxies: [DIRECT], disable-udp: true}
  - {name: balanced, type: load-balance, proxies: [tcp-only]}
"#,
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
        assert!(
            !parts
                .resource_targets
                .get(ProxyId::new(0).unwrap())
                .unwrap()
                .supports_udp()
        );
        for (index, expected) in [false, false, true].into_iter().enumerate() {
            let route = RouteTargetId::Group(ProxyGroupId::new(index).unwrap());
            assert_eq!(
                parts
                    .resource_targets
                    .get_route(route)
                    .unwrap()
                    .supports_udp(),
                expected
            );
        }
        parts.proxy_groups.select("selected", "DIRECT").unwrap();
        assert!(
            parts
                .resource_targets
                .get_route(RouteTargetId::Group(ProxyGroupId::new(0).unwrap()))
                .unwrap()
                .supports_udp()
        );
        parts.proxy_graph.shutdown().await;
    }

    #[cfg(all(
        feature = "sing-mux",
        feature = "outbound-http",
        feature = "outbound-socks5"
    ))]
    #[tokio::test]
    async fn prepares_shared_mux_capabilities_and_registers_only_final_graph_nodes() {
        let prepared = PreparedCore::prepare(
            br#"
mixed-port: 1080
proxies:
  - {name: mux-http, type: http, server: 192.0.2.1, port: 1080, smux: {enabled: true}}
  - {name: native-udp, type: socks5, server: 192.0.2.2, port: 1080, udp: false, smux: {enabled: true, only-tcp: true}}
proxy-groups:
  - {name: selected, type: select, proxies: [mux-http, native-udp]}
  - {name: disabled, type: select, proxies: [mux-http], disable-udp: true}
"#,
            &FixedResolver,
            ResourceLimits::default(),
        ).await.unwrap();
        let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
        for (index, expected) in [true, false].into_iter().enumerate() {
            assert_eq!(
                parts
                    .resource_targets
                    .get(ProxyId::new(index).unwrap())
                    .unwrap()
                    .supports_udp(),
                expected
            );
            let node = &parts.proxy_graph.nodes[index];
            assert_eq!(parts.proxy_graph.lifecycle_order.iter().filter(|target| {
                matches!(target, BuiltRouteTarget::Proxy(registered) if Arc::ptr_eq(node, registered))
            }).count(), 1);
        }
        assert_eq!(
            parts
                .proxy_graph
                .lifecycle_order
                .iter()
                .filter(|target| matches!(target, BuiltRouteTarget::Proxy(_)))
                .count(),
            2
        );
        for (index, expected) in [true, false].into_iter().enumerate() {
            assert_eq!(
                parts
                    .resource_targets
                    .get_route(RouteTargetId::Group(ProxyGroupId::new(index).unwrap()))
                    .unwrap()
                    .supports_udp(),
                expected
            );
        }
        parts.proxy_groups.select("selected", "native-udp").unwrap();
        assert!(
            !parts
                .resource_targets
                .get_route(RouteTargetId::Group(ProxyGroupId::new(0).unwrap()))
                .unwrap()
                .supports_udp()
        );
        parts.proxy_graph.begin_shutdown();
        parts.proxy_graph.shutdown().await;
    }

    #[tokio::test]
    async fn prepares_builtin_routes_without_static_nodes_or_bootstrap() {
        let resolver = RecordingResolver::default();
        for (groups, target) in [
            ("", "DIRECT"),
            ("", "REJECT"),
            (
                "proxy-groups:\n  - name: local\n    type: select\n    proxies: [DIRECT, REJECT]\n",
                "local",
            ),
        ] {
            let yaml = format!(
                "mixed-port: 1080\n{groups}dns:\n  enable: true\n  nameserver: [1.1.1.1]\n  nameserver-policy:\n    '+.example.com': 223.5.5.5\nrules: ['MATCH,{target}']\n"
            );
            let prepared =
                PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
                    .await
                    .unwrap();
            assert!(prepared.endpoints.is_empty());
            let parts = prepared.build_dispatcher(Dialer::default()).unwrap();
            assert_eq!(parts.proxy_graph.len(), 0);
            assert!(parts.dns.is_some());
            parts.proxy_graph.shutdown().await;
        }
        assert!(resolver.hosts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn prepare_defers_proxy_endpoint_resolution() {
        let prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        let id = ProxyId::new(0).unwrap();
        assert_eq!(prepared.proxy(id).tag, "proxy");
        assert!(matches!(
            prepared.proxy(id).protocol,
            ProxyProtocol::Vless(_)
        ));
        assert!(prepared.endpoint(id).is_none());
        assert!(!prepared.has_tun());
        assert!(
            prepared.config.rules.is_empty(),
            "normalized rules must be moved out of the retained config"
        );
        assert_eq!(prepared.rules.len(), 1);
        assert_eq!(
            prepared.rules.rule(0).map(|rule| rule.action),
            Some(crate::config::RuleAction::Route(
                crate::config::RouteTargetId::Proxy(id)
            )),
            "moving the normalized rules must preserve the compiled default route"
        );
    }

    #[tokio::test]
    async fn prepare_defers_identical_download_endpoints() {
        let resolver = RecordingResolver::default();
        let yaml = CONFIG.replace(
            "      mode: packet-up\n",
            "      mode: packet-up\n      download-settings: {}\n",
        );
        let prepared = PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
            .await
            .unwrap();
        assert!(resolver.hosts.lock().unwrap().is_empty());

        let id = ProxyId::new(0).unwrap();
        assert!(prepared.endpoint(id).is_none());
        assert!(prepared.download_endpoint(id).is_none());
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn prepare_defers_distinct_download_endpoints() {
        let resolver = ConcurrentResolver::default();
        let yaml = config_with_download("        server: download.test\n        port: 8443");
        let prepared = PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
            .await
            .unwrap();
        assert_eq!(resolver.peak.load(Ordering::Acquire), 0);

        let id = ProxyId::new(0).unwrap();
        assert!(prepared.endpoint(id).is_none());
        assert!(prepared.download_endpoint(id).is_none());
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            1
        );
    }

    #[test]
    #[cfg(any(
        feature = "outbound-http",
        feature = "outbound-socks5",
        feature = "outbound-anytls",
        feature = "outbound-vless"
    ))]
    fn security_budget_counts_every_vless_transport_leg() {
        let yaml = config_with_download("        server: download.test\n        port: 8443");
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(security_counts(&config.proxies), (2, 2));
        assert_eq!(standard_tls_resumption_sessions(2), 2);
    }

    #[tokio::test]
    async fn production_tun_sniffer_is_independent_of_domain_rules() {
        let domain_rules = r#"
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - MATCH,proxy
"#;
        let tun = r#"
tun:
  enable: true
  mtu: 1500
"#;
        let sniffer = r#"
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [8080]
    TLS:
      ports: ["8443-8444"]
"#;

        let no_tun = PreparedCore::prepare(
            format!("{}{sniffer}", config_with_rules(domain_rules)).as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(no_tun.domain_sniffer_config().is_none());

        let no_domain_rules = PreparedCore::prepare(
            format!("{CONFIG}{tun}{sniffer}").as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(no_domain_rules.domain_sniffer_config().is_some());

        let disabled = PreparedCore::prepare(
            format!(
                "{}{tun}sniffer:\n  enable: false\n  sniff:\n    HTTP: {{}}\n",
                config_with_rules(domain_rules)
            )
            .as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(disabled.domain_sniffer_config().is_none());

        let enabled = PreparedCore::prepare(
            format!("{}{tun}{sniffer}", config_with_rules(domain_rules)).as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let normalized = enabled
            .domain_sniffer_config()
            .expect("the TUN sniffer is enabled");
        assert!(normalized.matches_http_port(8080));
        assert!(!normalized.matches_http_port(80));
        assert!(normalized.matches_tls_port(8444));
        assert!(!normalized.matches_tls_port(443));
    }

    #[test]
    fn nameserver_policy_validation_does_not_require_geosite_asset() {
        let yaml = format!(
            r#"{CONFIG}
dns:
  enable: true
  nameserver: ["tcp://1.1.1.1:53#proxy"]
  nameserver-policy:
    "geosite:private,cn,apple":
      - "tcp://223.5.5.5:53#DIRECT"
"#
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        PreparedCore::validate_config(config).unwrap();
    }

    #[cfg(feature = "outbound-vless")]
    #[tokio::test]
    async fn geodata_updater_fetches_missing_assets_and_requires_actual_demand() {
        fn configured(auto_update: bool, geodata_rule: bool) -> String {
            let fields = format!(
                r#"geox-url:
  geoip: https://downloads.example.test/custom-geoip.dat
  geosite: https://downloads.example.test/custom-geosite.dat
geo-auto-update: {auto_update}
geo-update-interval: 24
"#
            );
            if geodata_rule {
                config_with_rules("rules:\n  - GEOSITE,cn,proxy\n  - MATCH,proxy\n").replacen(
                    "mixed-port: 18080\n",
                    &format!("{fields}mixed-port: 18080\n"),
                    1,
                )
            } else {
                CONFIG.replacen(
                    "mixed-port: 18080\n",
                    &format!("{fields}mixed-port: 18080\n"),
                    1,
                )
            }
        }

        async fn updater_for(yaml: &str) -> Option<GeoDataUpdateService> {
            PreparedCore::prepare(yaml.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap()
                .build_dispatcher(Dialer::default())
                .unwrap()
                .geodata_updater
        }

        let missing_config_with_demand =
            config_with_rules("rules:\n  - GEOIP,cn,proxy\n  - MATCH,proxy\n");
        assert!(updater_for(&missing_config_with_demand).await.is_some());
        let asn_only = config_with_rules("rules:\n  - IP-ASN,0,proxy\n  - MATCH,proxy\n");
        assert!(updater_for(&asn_only).await.is_some());
        assert!(updater_for(&configured(false, true)).await.is_some());
        assert!(updater_for(&configured(true, false)).await.is_none());

        let updater = updater_for(&configured(true, true))
            .await
            .expect("enabled explicit GeoData config plus demand starts the updater");
        assert_eq!(
            updater.urls().geoip,
            "https://downloads.example.test/custom-geoip.dat"
        );
        assert_eq!(
            updater.urls().geosite,
            "https://downloads.example.test/custom-geosite.dat"
        );
    }

    #[cfg(feature = "outbound-vless")]
    #[tokio::test]
    async fn a_manager_rejects_a_second_prepared_configuration() {
        fn configured(auto_update: bool, rule: &str, source: &str) -> String {
            let fields = format!(
                r#"geox-url:
  geoip: https://{source}/geoip.dat
  geosite: https://{source}/geosite.dat
geo-auto-update: {auto_update}
geo-update-interval: 24
"#
            );
            config_with_rules(&format!("rules:\n  - {rule},proxy\n  - MATCH,proxy\n")).replacen(
                "mixed-port: 18080\n",
                &format!("{fields}mixed-port: 18080\n"),
                1,
            )
        }

        let directory = tempdir().unwrap();
        let manager =
            GeoDataManager::open(directory.path(), Duration::from_secs(24 * 60 * 60)).unwrap();
        let _active = PreparedCore::prepare_config(
            Config::parse_yaml(
                configured(true, "GEOSITE,enabled", "enabled.example.test").as_bytes(),
            )
            .unwrap(),
            manager.clone(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let second = PreparedCore::prepare_config(
            Config::parse_yaml(
                configured(false, "GEOIP,disabled", "disabled.example.test").as_bytes(),
            )
            .unwrap(),
            manager.clone(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap_err();

        assert!(second.to_string().contains("active registration"));
    }

    fn two_socks_config(chained: bool) -> String {
        let dialer = if chained {
            "    dialer-proxy: node-b\n"
        } else {
            ""
        };
        format!(
            r#"mixed-port: 18080
authentication:
  - measure:secret
proxies:
  - name: node-a
    type: socks5
{dialer}    server: a.test
    port: 1080
  - name: node-b
    type: socks5
    server: b.test
    port: 1081
rules:
  - MATCH,node-a
"#
        )
    }

    #[tokio::test]
    async fn prepare_defers_independent_proxy_roots() {
        let resolver = RecordingResolver::default();
        let prepared = PreparedCore::prepare(
            two_socks_config(false).as_bytes(),
            &resolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let mut hosts = resolver.hosts.lock().unwrap().clone();
        hosts.sort();
        assert!(hosts.is_empty());
        assert!(prepared.endpoint(ProxyId::new(0).unwrap()).is_none());
        assert!(prepared.endpoint(ProxyId::new(1).unwrap()).is_none());
    }

    #[cfg(feature = "outbound-socks5")]
    #[tokio::test]
    async fn prepare_defers_the_physical_chain_root() {
        let resolver = RecordingResolver::default();
        let prepared = PreparedCore::prepare(
            two_socks_config(true).as_bytes(),
            &resolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        assert!(resolver.hosts.lock().unwrap().is_empty());
        assert!(prepared.endpoint(ProxyId::new(0).unwrap()).is_none());
        assert!(prepared.endpoint(ProxyId::new(1).unwrap()).is_none());
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            2
        );
    }

    #[cfg(all(feature = "outbound-socks5", feature = "outbound-vless"))]
    #[tokio::test]
    async fn split_vless_behind_dialer_proxy_does_not_resolve_either_child_leg() {
        let yaml = r#"mixed-port: 18080
authentication:
  - measure:secret
proxies:
  - name: vless-child
    type: vless
    server: upload-child.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: upload-child.test
    alpn: [h2]
    dialer-proxy: socks-root
    xhttp-opts:
      host: upload-child.test
      path: /upload
      mode: packet-up
      download-settings:
        server: download-child.test
        port: 8443
  - name: socks-root
    type: socks5
    server: socks-root.test
    port: 1080
rules:
  - MATCH,vless-child
"#;
        let resolver = RecordingResolver::default();
        let prepared = PreparedCore::prepare(yaml.as_bytes(), &resolver, ResourceLimits::default())
            .await
            .unwrap();
        assert!(resolver.hosts.lock().unwrap().is_empty());
        let child = ProxyId::new(0).unwrap();
        assert!(prepared.endpoint(child).is_none());
        assert!(prepared.download_endpoint(child).is_none());
        assert_eq!(
            prepared.build_proxy_graph(Dialer::default()).unwrap().len(),
            2
        );
    }

    #[cfg(all(
        feature = "outbound-http",
        feature = "outbound-anytls",
        feature = "outbound-socks5",
        feature = "outbound-vless"
    ))]
    #[tokio::test]
    async fn proxy_graph_builds_protocol_combinations_and_long_chains() {
        assert_eq!(standard_tls_resumption_sessions(1), 4);
        assert_eq!(standard_tls_resumption_sessions(2), 2);
        assert_eq!(standard_tls_resumption_sessions(3), 1);
        assert_eq!(standard_tls_resumption_sessions(4), 1);
        assert_eq!(standard_tls_resumption_sessions(5), 0);
        assert_eq!(standard_tls_resumption_sessions(64), 0);

        fn vless(tag: &str) -> ProxyConfig {
            let mut proxy = Config::parse_yaml(CONFIG.as_bytes())
                .unwrap()
                .proxies
                .into_iter()
                .next()
                .unwrap();
            proxy.tag = tag.to_owned();
            proxy
        }

        fn socks5(tag: &str) -> ProxyConfig {
            ProxyConfig {
                smux: None,
                ip_version: crate::config::IpVersion::Dual,
                tag: tag.to_owned(),
                dialer_proxy: None,
                udp: false,
                protocol: ProxyProtocol::Socks5(crate::config::Socks5OutboundConfig {
                    tls: None,
                    address: "127.0.0.1".to_owned(),
                    port: 1080,
                    username: None,
                    password: None,
                }),
            }
        }

        fn anytls(tag: &str) -> ProxyConfig {
            ProxyConfig {
                smux: None,
                ip_version: crate::config::IpVersion::Dual,
                tag: tag.to_owned(),
                dialer_proxy: None,
                udp: true,
                protocol: ProxyProtocol::AnyTls(crate::config::AnyTlsOutboundConfig {
                    address: "127.0.0.1".to_owned(),
                    port: 443,
                    password: "secret".to_owned(),
                    server_name: "example.com".to_owned(),
                    tls: Default::default(),
                }),
            }
        }

        let mut mixed_security = vec![vless("tls")];
        for index in 0..8 {
            let mut reality = vless(&format!("reality-{index}"));
            let ProxyProtocol::Vless(config) = &mut reality.protocol else {
                unreachable!("vless test helper always creates VLESS")
            };
            config.security =
                crate::config::SecurityConfig::Reality(crate::config::RealityConfig {
                    support_x25519mlkem768: false,
                    client_fingerprint: None,
                    server_name: "example.com".to_owned(),
                    public_key: [7; 32],
                    short_id: vec![1, 2, 3, 4],
                    alpn: vec![b"h2".to_vec()],
                });
            mixed_security.push(reality);
        }
        mixed_security.push(anytls("anytls"));
        let (security_client_count, standard_tls_count) = security_counts(&mixed_security);
        assert_eq!(security_client_count, 10);
        assert_eq!(standard_tls_count, 2);
        assert_eq!(standard_tls_resumption_sessions(standard_tls_count), 2);

        async fn build(proxies: Vec<ProxyConfig>) -> usize {
            let mut config = Config::parse_yaml(CONFIG.as_bytes()).unwrap();
            config.proxies = proxies;
            let directory = tempdir().unwrap();
            let geodata_manager =
                GeoDataManager::open(directory.path(), Duration::from_secs(24 * 60 * 60)).unwrap();
            let prepared = PreparedCore::prepare_config(
                config,
                geodata_manager,
                &FixedResolver,
                ResourceLimits::default(),
            )
            .await
            .unwrap();
            prepared.build_proxy_graph(Dialer::default()).unwrap().len()
        }

        assert_eq!(build(vec![vless("selected")]).await, 1);
        assert_eq!(build(vec![socks5("selected")]).await, 1);
        assert_eq!(build(vec![anytls("selected")]).await, 1);

        for (mut selected, upstream) in [
            (vless("selected"), vless("upstream")),
            (vless("selected"), socks5("upstream")),
            (vless("selected"), anytls("upstream")),
            (socks5("selected"), vless("upstream")),
            (socks5("selected"), socks5("upstream")),
            (socks5("selected"), anytls("upstream")),
            (anytls("selected"), vless("upstream")),
            (anytls("selected"), socks5("upstream")),
            (anytls("selected"), anytls("upstream")),
        ] {
            // `selected -> upstream` means selected.dialer-proxy references
            // the second node; the wire path reaches upstream first.
            selected.dialer_proxy = ProxyId::new(1).map(RouteTargetId::Proxy);
            assert_eq!(build(vec![selected, upstream]).await, 2);
        }

        let mut chain = (0..6)
            .map(|index| socks5(&format!("node-{index}")))
            .collect::<Vec<_>>();
        for (index, proxy) in chain.iter_mut().take(5).enumerate() {
            proxy.dialer_proxy = ProxyId::new(index + 1).map(RouteTargetId::Proxy);
        }
        assert_eq!(build(chain).await, 6);
    }

    #[cfg(all(windows, feature = "windows-uwp"))]
    #[tokio::test]
    async fn windows_packet_adapter_runs_the_tun_runtime() {
        let prepared = PreparedCore::prepare(
            CURRENT_TUN_CONFIG
                .replace("mtu: 1500", "mtu: 1400")
                .as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let (tun, adapter) = TunIo::new(4, 1400, || Ok(())).unwrap();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();

        assert!(adapter.try_send(icmpv4_echo_request()));
        let reply = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Some(reply) = adapter.pop_egress() {
                    break reply;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Windows packet adapter did not return the ICMP reply");
        assert_eq!(reply[20], 0);

        running.stop().await.unwrap();
    }

    #[cfg(all(unix, feature = "tun"))]
    #[tokio::test]
    async fn start_tun_requires_exactly_one_tun_listener() {
        let prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        let (tun, _peer) = test_tun();
        let error = prepared
            .start_tun(tun, Dialer::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        prepared.config.inbounds.extend([
            InboundConfig::Tun(TunInboundConfig {
                tag: "tun-a".to_owned(),
                mtu: 1_500,
            }),
            InboundConfig::Tun(TunInboundConfig {
                tag: "tun-b".to_owned(),
                mtu: 1_500,
            }),
        ]);
        let (tun, _peer) = test_tun();
        let error = prepared
            .start_tun(tun, Dialer::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut prepared =
            PreparedCore::prepare(CONFIG.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        prepared
            .config
            .inbounds
            .push(InboundConfig::Tun(TunInboundConfig {
                tag: "tun".to_owned(),
                mtu: 1_500,
            }));
        let (tun, _peer) = test_tun();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();
        running.stop().await.unwrap();
    }

    #[cfg(all(unix, feature = "tun"))]
    #[tokio::test]
    async fn current_tun_enables_local_icmp_echo() {
        let prepared = PreparedCore::prepare(
            CURRENT_TUN_CONFIG.as_bytes(),
            &FixedResolver,
            ResourceLimits::default(),
        )
        .await
        .unwrap();
        let reply = tun_echo_reply(prepared)
            .await
            .expect("TUN did not answer ICMP echo");
        assert_eq!(reply[0], 0x45);
        assert_eq!(reply[8], 64);
        assert_eq!(reply[9], 1);
        assert_eq!(&reply[12..16], &[198, 51, 100, 20]);
        assert_eq!(&reply[16..20], &[192, 0, 2, 10]);
        assert_eq!(reply[20], 0);
        assert_eq!(&reply[24..], &[0x12, 0x34, 0x56, 0x78, b'o', b'd', b'd']);
    }

    #[cfg(all(unix, feature = "tun"))]
    #[tokio::test]
    async fn tun_controller_shares_lifecycle_and_reports_raw_ip_bytes() {
        let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let controller_address = reservation.local_addr().unwrap();
        drop(reservation);
        let yaml = CURRENT_TUN_CONFIG.replacen(
            "tun:\n",
            &format!("external-controller: \"{controller_address}\"\nsecret: test-token\ntun:\n"),
            1,
        );
        let prepared =
            PreparedCore::prepare(yaml.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        let stats = prepared
            .traffic_stats()
            .expect("TUN preparation allocates one statistics object");
        let (tun, peer) = test_tun();
        peer.set_nonblocking(true).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();

        let request = icmpv4_echo_request();
        peer.send(&request).await.unwrap();
        let mut reply = vec![0_u8; 1_500];
        let reply_length = tokio::time::timeout(Duration::from_millis(100), peer.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();

        let mut controller = tokio::net::TcpStream::connect(controller_address)
            .await
            .unwrap();
        controller
            .write_all(
                b"GET /traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        controller.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        let body = response.split_once("\r\n\r\n").unwrap().1;
        let snapshot = serde_json::from_str::<serde_json::Value>(body).unwrap();
        assert_eq!(snapshot["upTotal"].as_u64(), Some(request.len() as u64));
        assert_eq!(snapshot["downTotal"].as_u64(), Some(reply_length as u64));
        assert_eq!(stats.snapshot().up_total, request.len() as u64);
        assert_eq!(stats.snapshot().down_total, reply_length as u64);

        running.stop().await.unwrap();
        let reconnect = tokio::time::timeout(
            Duration::from_millis(100),
            tokio::net::TcpStream::connect(controller_address),
        )
        .await
        .unwrap();
        assert!(reconnect.is_err());
    }

    #[cfg(all(unix, feature = "tun", feature = "inbound-socks5"))]
    #[tokio::test]
    async fn socks5_and_tun_share_lifecycle_but_only_raw_ip_counts_as_traffic() {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        let yaml = format!(
            "mixed-port: {}\nipv6: false\n{CURRENT_TUN_CONFIG}",
            address.port()
        );
        drop(reserved);
        let prepared =
            PreparedCore::prepare(yaml.as_bytes(), &FixedResolver, ResourceLimits::default())
                .await
                .unwrap();
        let stats = prepared.traffic_stats().unwrap();
        let (tun, peer) = test_tun();
        peer.set_nonblocking(true).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();
        let mut control = tokio::net::TcpStream::connect(address).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut response = [0; 12];
        tokio::time::timeout(Duration::from_secs(2), control.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response[..5], [5, 0, 5, 0, 0]);
        assert_eq!(stats.snapshot().up_total, 0);
        assert_eq!(stats.snapshot().down_total, 0);
        let request = icmpv4_echo_request();
        peer.send(&request).await.unwrap();
        let mut packet = [0; 1500];
        let size = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.snapshot().up_total, request.len() as u64);
        assert_eq!(stats.snapshot().down_total, size as u64);
        running.stop().await.unwrap();
        drop(crate::inbound::listen::bind_tcp(address).unwrap());
        drop(crate::inbound::listen::bind_udp(address).unwrap());
    }

    #[cfg(all(
        feature = "tun",
        any(
            unix,
            all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
        )
    ))]
    const CURRENT_TUN_CONFIG: &str = r#"tun:
  enable: true
proxies:
  - name: proxy
    type: vless
    server: server.test
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    udp: true
    tls: true
    network: xhttp
    encryption: none
    servername: example.com
    alpn: [h2]
    xhttp-opts:
      path: /x
      mode: packet-up
rules:
  - MATCH,proxy
"#;

    #[cfg(all(unix, feature = "tun"))]
    async fn tun_echo_reply(prepared: PreparedCore) -> Option<Vec<u8>> {
        let (tun, peer) = test_tun();
        peer.set_nonblocking(true).unwrap();
        let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
        let running = prepared.start_tun(tun, Dialer::default()).await.unwrap();
        peer.send(&icmpv4_echo_request()).await.unwrap();

        let mut reply = vec![0_u8; 1_500];
        let received =
            tokio::time::timeout(Duration::from_millis(100), peer.recv(&mut reply)).await;
        running.stop().await.unwrap();
        match received {
            Ok(Ok(length)) => {
                reply.truncate(length);
                Some(reply)
            }
            Ok(Err(error)) => panic!("TUN peer receive failed: {error}"),
            Err(_) => None,
        }
    }

    #[cfg(all(
        feature = "tun",
        any(
            unix,
            all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
        )
    ))]
    fn icmpv4_echo_request() -> Vec<u8> {
        let mut message = vec![8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, b'o', b'd', b'd'];
        let checksum = test_checksum(&message);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut packet = vec![0_u8; 20 + message.len()];
        packet[0] = 0x45;
        let packet_len = u16::try_from(packet.len()).unwrap();
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 32;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        packet[20..].copy_from_slice(&message);
        let checksum = test_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[cfg(all(
        feature = "tun",
        any(
            unix,
            all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
        )
    ))]
    fn test_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        let (chunks, remainder) = bytes.as_chunks::<2>();
        for chunk in chunks {
            sum += u32::from(u16::from_be_bytes(*chunk));
        }
        if let Some(byte) = remainder.first() {
            sum += u32::from(*byte) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).unwrap()
    }

    #[cfg(all(unix, feature = "tun"))]
    fn test_tun() -> (TunIo, UnixDatagram) {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = crate::platform::TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        (TunIo::new(fd, crate::TunFraming::RawIp).unwrap(), peer)
    }
}
