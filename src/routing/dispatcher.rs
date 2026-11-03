use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use futures_util::future::select_all;
use tokio::{sync::Notify, time::Instant};

use crate::{
    config::{Network, ProxyId, RouteTargetId, RuleAction, TunConfig},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    dns::runtime::{DnsWireResponse, RuntimeDns},
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

use super::{
    GeoMatcher, ProgramEvaluation, ProxyGroups, ResolvedProxyGroupLeaf, RoutingContext, RuleSet,
    RuleTargetEffect,
    datagram_ready::{ReadyFlow, ReadyQueue},
    proxy_group::InspectedRuleTarget,
};

const UDP_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

#[async_trait]
trait RoutingDns: Send + Sync {
    fn is_enabled(&self) -> bool {
        true
    }
    fn recover_fake_ip(&self, _address: IpAddr) -> Result<Option<String>, DispatchError> {
        Ok(None)
    }
    async fn resolve_direct(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError> {
        self.resolve(host).await
    }
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError>;
    async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError>;
    async fn domain_hint(&self, address: IpAddr) -> Option<String>;
}

#[async_trait]
impl RoutingDns for RuntimeDns {
    fn recover_fake_ip(&self, address: IpAddr) -> Result<Option<String>, DispatchError> {
        RuntimeDns::recover_fake_ip(self, address).map_err(|_| DispatchError::HostUnreachable)
    }

    fn is_enabled(&self) -> bool {
        RuntimeDns::is_enabled(self)
    }
    async fn resolve_direct(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError> {
        RuntimeDns::resolve_direct(self, host)
            .await
            .map_err(runtime_dns_error)
    }
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError> {
        RuntimeDns::resolve(self, host)
            .await
            .map_err(runtime_dns_error)
    }

    async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
        RuntimeDns::exchange_retained(self, query)
            .await
            .map_err(runtime_dns_error)
    }

    async fn domain_hint(&self, address: IpAddr) -> Option<String> {
        RuntimeDns::domain_hint(self, address).await
    }
}

fn runtime_dns_error(error: crate::dns::runtime::RuntimeDnsError) -> DispatchError {
    match error {
        crate::dns::runtime::RuntimeDnsError::RuleEvaluation(failure) => {
            DispatchError::RuleEvaluation(failure)
        }
        error => DispatchError::Other(format!("runtime DNS: {error}")),
    }
}

/// Runtime registry for concrete proxy nodes.
///
/// Group-aware runtime paths use the crate-private [`RouteTargetDispatchers`]
/// name and methods while this type preserves the public node-only API.
#[derive(Clone)]
pub struct ProxyDispatchers {
    entries: Arc<DispatcherRegistry>,
}

struct DispatcherRegistry {
    proxies: Vec<Arc<dyn Dispatcher>>,
    groups: Vec<Arc<dyn Dispatcher>>,
    proxy_groups: Option<Arc<ProxyGroups>>,
}

impl std::fmt::Debug for ProxyDispatchers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyDispatchers")
            .field("len", &self.entries.proxies.len())
            .field("groups", &self.entries.groups.len())
            .finish_non_exhaustive()
    }
}

impl ProxyDispatchers {
    pub fn new(proxies: Vec<Arc<dyn Dispatcher>>) -> Result<Self, DispatchError> {
        Ok(Self {
            entries: Arc::new(DispatcherRegistry {
                proxies,
                groups: Vec::new(),
                proxy_groups: None,
            }),
        })
    }

    pub(crate) fn with_proxy_groups(
        proxies: Vec<Arc<dyn Dispatcher>>,
        proxy_groups: &Arc<ProxyGroups>,
    ) -> Result<Self, DispatchError> {
        let groups = (0..proxy_groups.len())
            .map(|index| {
                proxy_groups.dispatcher(
                    crate::config::ProxyGroupId::new(index)
                        .expect("ProxyGroupId has no count-based ceiling"),
                )
            })
            .collect();
        Ok(Self {
            entries: Arc::new(DispatcherRegistry {
                proxies,
                groups,
                proxy_groups: Some(proxy_groups.clone()),
            }),
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.proxies.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.proxies.is_empty()
    }

    pub fn get(&self, id: ProxyId) -> Result<&Arc<dyn Dispatcher>, DispatchError> {
        self.entries
            .proxies
            .get(id.index())
            .ok_or_else(|| DispatchError::Other(format!("unknown proxy id {}", id.index())))
    }

    #[cfg(test)]
    pub(crate) fn get_route(
        &self,
        id: RouteTargetId,
    ) -> Result<&Arc<dyn Dispatcher>, DispatchError> {
        match id {
            RouteTargetId::Proxy(id) => self.get(id),
            RouteTargetId::Group(id) => self.entries.groups.get(id.index()).ok_or_else(|| {
                DispatchError::Other(format!("unknown proxy group id {}", id.index()))
            }),
        }
    }

    pub(crate) fn inspect_rule_target(
        &self,
        id: RouteTargetId,
        udp: bool,
        commit: bool,
        source: Option<SocketAddr>,
        destination: Option<&Destination>,
        user: Option<&str>,
    ) -> Result<InspectedRuleTarget, DispatchError> {
        match id {
            RouteTargetId::Proxy(id) => {
                if let Some(target) = self
                    .entries
                    .proxy_groups
                    .as_ref()
                    .and_then(|groups| groups.rematch(id))
                {
                    return Ok(InspectedRuleTarget::Rematch(target.clone()));
                }
                let dispatcher = self.get(id)?.clone();
                if udp && !dispatcher.supports_udp() {
                    return Ok(InspectedRuleTarget::Unavailable);
                }
                Ok(InspectedRuleTarget::Egress(ResolvedProxyGroupLeaf {
                    chain: Vec::new(),
                    selections: Vec::new(),
                    dispatcher,
                    direct: false,
                }))
            }
            RouteTargetId::Group(id) => self
                .entries
                .proxy_groups
                .as_ref()
                .ok_or(DispatchError::NotAllowed)?
                .inspect_rule_target(id, udp, commit, source, destination, user),
        }
    }

    fn per_flow(&self, id: RouteTargetId) -> bool {
        matches!(id, RouteTargetId::Group(id) if self.entries.proxy_groups.as_ref().is_some_and(|groups| groups.contains_balance(id)))
    }
    fn resolve_for(
        &self,
        id: RouteTargetId,
        udp: bool,
        source: Option<SocketAddr>,
        destination: Option<&Destination>,
        user: Option<&str>,
    ) -> Result<ResolvedProxyGroupLeaf, DispatchError> {
        match id {
            RouteTargetId::Proxy(id) => self
                .entries
                .proxies
                .get(id.index())
                .cloned()
                .map(|dispatcher| ResolvedProxyGroupLeaf {
                    chain: Vec::new(),
                    selections: Vec::new(),
                    dispatcher,
                    direct: false,
                })
                .ok_or_else(|| DispatchError::Other(format!("unknown proxy id {}", id.index()))),
            RouteTargetId::Group(id) => self
                .entries
                .proxy_groups
                .as_ref()
                .ok_or_else(|| {
                    DispatchError::Other(format!("unknown proxy group id {}", id.index()))
                })?
                .resolve_leaf_for(id, udp, source, destination, user),
        }
    }
}

pub(crate) type RouteTargetDispatchers = ProxyDispatchers;

/// Ordered Vole router backed by named route targets, built-in DIRECT, and
/// fail-closed REJECT actions.
///
/// The outer session observer records returned transport lifetimes without
/// admitting or rejecting work. This layer creates at most one transport per
/// route target and one direct transport for each source association. TUN IP
/// flows independently pin a rule action, without owning additional IO.
pub struct RoutingDispatcher {
    route_targets: ProxyDispatchers,
    direct: Arc<dyn Dispatcher>,
    reject_drop: Arc<dyn Dispatcher>,
    dns: Option<Arc<dyn RoutingDns>>,
    ipv6: bool,
    rules: Arc<RuleSet>,
    geo_matcher: Arc<dyn GeoMatcher>,
    tun_config: TunConfig,
    sniffer: Option<Arc<crate::sniffing::Policy>>,
    tcp_concurrent: bool,
    diagnostics: Option<Arc<crate::routing::diagnostics::Diagnostics>>,
    process_mode: crate::config::FindProcessMode,
    process_dialer: Option<crate::dialer::Dialer>,
}

impl RoutingDispatcher {
    pub(crate) fn with_process_lookup(
        mut self,
        mode: crate::config::FindProcessMode,
        dialer: crate::dialer::Dialer,
    ) -> Self {
        self.process_mode = mode;
        self.process_dialer = Some(dialer);
        self
    }
    pub(crate) fn with_reject_drop(mut self, dispatcher: Arc<dyn Dispatcher>) -> Self {
        self.reject_drop = dispatcher;
        self
    }
    pub(crate) fn with_diagnostics(
        mut self,
        diagnostics: Arc<crate::routing::diagnostics::Diagnostics>,
    ) -> Self {
        self.diagnostics = Some(diagnostics);
        self
    }
    pub(crate) fn with_tcp_concurrent(mut self, enabled: bool) -> Self {
        self.tcp_concurrent = enabled;
        self
    }
    pub(crate) fn with_sniffer(mut self, config: &crate::config::SnifferConfig) -> Self {
        self.sniffer = config.enable.then(|| {
            crate::sniffing::Policy::new(Arc::new(config.clone()), self.geo_matcher.clone())
        });
        self
    }
    #[must_use]
    pub fn new(
        route_targets: ProxyDispatchers,
        direct: Arc<dyn Dispatcher>,
        dns: Option<Arc<RuntimeDns>>,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self::new_with_ipv6(route_targets, direct, dns, true, rules, geo_matcher)
    }

    #[must_use]
    pub(crate) fn new_with_ipv6(
        route_targets: ProxyDispatchers,
        direct: Arc<dyn Dispatcher>,
        dns: Option<Arc<RuntimeDns>>,
        ipv6: bool,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self {
            route_targets,
            direct,
            reject_drop: default_reject_drop(),
            dns: dns.map(|dns| dns as Arc<dyn RoutingDns>),
            ipv6,
            rules: Arc::new(rules),
            geo_matcher,
            tun_config: TunConfig::default(),
            sniffer: None,
            tcp_concurrent: false,
            diagnostics: None,
            process_mode: crate::config::FindProcessMode::Strict,
            process_dialer: None,
        }
    }

    #[cfg(test)]
    fn with_dns_service(
        proxy: Arc<dyn Dispatcher>,
        direct: Arc<dyn Dispatcher>,
        dns: Option<Arc<dyn RoutingDns>>,
        ipv6: bool,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self {
            route_targets: ProxyDispatchers::new(vec![proxy])
                .expect("test proxy registry contains one entry"),
            direct,
            reject_drop: default_reject_drop(),
            dns,
            ipv6,
            rules: Arc::new(rules),
            geo_matcher,
            sniffer: None,
            tcp_concurrent: false,
            diagnostics: None,
            process_mode: crate::config::FindProcessMode::Strict,
            process_dialer: None,
            tun_config: TunConfig {
                udp_timeout: Duration::from_secs(30),
                ..TunConfig::default()
            },
        }
    }

    #[must_use]
    pub(crate) fn with_tun_config(mut self, config: &TunConfig) -> Self {
        self.tun_config = config.clone();
        self
    }

    fn ensure_destination_allowed(&self, destination: &Destination) -> Result<(), DispatchError> {
        if !self.ipv6 && matches!(destination, Destination::Ip(address) if address.is_ipv6()) {
            return Err(DispatchError::NetworkUnreachable);
        }
        Ok(())
    }

    async fn resolve_addresses(
        &self,
        dns: &Arc<dyn RoutingDns>,
        host: &str,
    ) -> Result<Vec<IpAddr>, DispatchError> {
        let mut addresses = match dns.resolve(host).await {
            Ok(addresses) => addresses,
            Err(error @ DispatchError::RuleEvaluation(_)) => return Err(error),
            Err(_) => Vec::new(),
        };
        if !self.ipv6 {
            addresses.retain(IpAddr::is_ipv4);
        }
        Ok(addresses)
    }

    async fn route(
        &self,
        network: Network,
        inbound: (InboundKind, &crate::session::InboundMetadata),
        source: SocketAddr,
        destination: &Destination,
        sniffed_domain: Option<&str>,
        mut cached: Option<
            &mut HashMap<(RouteTargetId, Option<Destination>), CachedRouteTransport>,
        >,
    ) -> Result<RouteDecision, DispatchError> {
        let (inbound, inbound_metadata) = inbound;
        let unsaved = (business(inbound) && inbound_metadata.original.is_none())
            .then(|| inbound_metadata.facts(source, inbound, destination));
        let original = inbound_metadata.original.as_deref().or(unsaved.as_ref());
        self.ensure_destination_allowed(destination)?;
        let recovered = if matches!(
            inbound,
            InboundKind::Tun | InboundKind::Http | InboundKind::Https | InboundKind::Socks5
        ) {
            match (destination, &self.dns) {
                (Destination::Ip(address), Some(dns)) => {
                    dns.recover_fake_ip(address.ip())?
                        .map(|host| Destination::Domain {
                            host,
                            port: address.port(),
                        })
                }
                _ => None,
            }
        } else {
            None
        };
        let overridden = (network == Network::Udp
            && self
                .sniffer
                .as_ref()
                .is_some_and(|policy| policy.config.quic_override))
        .then(|| {
            sniffed_domain.map(|host| Destination::Domain {
                host: host.to_owned(),
                port: destination.port(),
            })
        })
        .flatten();
        let destination = overridden
            .as_ref()
            .or(recovered.as_ref())
            .unwrap_or(destination);
        let accepts_domain_hint = business(inbound)
            && (self.rules.uses_domain_routing()
                || self.diagnostics.is_some()
                || self
                    .route_targets
                    .entries
                    .proxy_groups
                    .as_ref()
                    .is_some_and(|groups| groups.has_balance()));
        let sniffed_domain = accepts_domain_hint.then_some(sniffed_domain).flatten();
        let dns_domain_hint = match (accepts_domain_hint, destination, &self.dns, sniffed_domain) {
            (true, Destination::Ip(address), Some(dns), None) => {
                dns.domain_hint(address.ip()).await
            }
            _ => None,
        };
        let domain_hint = sniffed_domain.or(dns_domain_hint.as_deref());
        let mut context = RoutingContext::with_domain_hint(network, destination, domain_hint)
            .map_err(|_| DispatchError::HostUnreachable)?;
        if let Some(host) = sniffed_domain {
            context.set_sniffed_domain(host);
        }

        context.set_source(source);
        context.set_inbound(inbound, inbound_metadata);
        context.enable_process_lookup(
            business(inbound)
                && self.process_mode != crate::config::FindProcessMode::Off
                && self.process_dialer.is_some(),
        );
        if business(inbound) && self.process_mode == crate::config::FindProcessMode::Always {
            self.lookup_process(&mut context, network, original).await?;
        }

        // All GeoData rules in this decision see the same immutable view.
        let snapshot = self.geo_matcher.routing_snapshot();
        let geo_matcher = snapshot.as_deref().unwrap_or(self.geo_matcher.as_ref());

        let mut resolved = None;
        let mut selected = None;
        let mut selection_error = None;
        let mut select = |action, candidate: &RoutingContext| {
            let RuleAction::Route(id) = action else {
                return RuleTargetEffect::Accept;
            };
            let metadata = candidate.domain().map_or_else(
                || destination.clone(),
                |host| Destination::Domain {
                    host: host.to_owned(),
                    port: destination.port(),
                },
            );
            let key = (
                id,
                self.route_targets.per_flow(id).then(|| destination.clone()),
            );
            let cached = cached
                .as_deref_mut()
                .and_then(|cached| cached.get(&key))
                .map(|cached| cached.leaf.clone());
            if let Some(leaf) = cached {
                // Existing UDP transports retain their selected leaf even if
                // the group's next member cannot carry UDP.
                selected = Some(Ok(leaf));
                return RuleTargetEffect::Accept;
            }
            match self.route_targets.inspect_rule_target(
                id,
                network == Network::Udp,
                true,
                Some(source),
                Some(&metadata),
                candidate.authenticated_user(),
            ) {
                Ok(InspectedRuleTarget::Rematch(_)) if !self.rules.filters_udp() => {
                    selected = Some(Err(DispatchError::NotAllowed));
                    RuleTargetEffect::Accept
                }
                Ok(InspectedRuleTarget::Rematch(target)) => RuleTargetEffect::Rematch(target),
                Ok(InspectedRuleTarget::Control(_)) if !self.rules.filters_udp() => {
                    selected = Some(Err(DispatchError::NotAllowed));
                    RuleTargetEffect::Accept
                }
                Ok(InspectedRuleTarget::Control(control)) => RuleTargetEffect::Control(control),
                Ok(InspectedRuleTarget::Egress(leaf)) => {
                    selected = Some(Ok(leaf));
                    RuleTargetEffect::Accept
                }
                Ok(InspectedRuleTarget::Unavailable) if self.rules.filters_udp() => {
                    RuleTargetEffect::Skip
                }
                Ok(InspectedRuleTarget::Unavailable) => {
                    selected = Some(Err(DispatchError::NotAllowed));
                    RuleTargetEffect::Accept
                }
                Err(error) => {
                    selection_error = Some(error);
                    RuleTargetEffect::Accept
                }
            }
        };
        let mut cursor = None;
        let evaluation = loop {
            match self.rules.evaluate_program(
                &mut context,
                geo_matcher,
                cursor.take(),
                resolved.as_deref(),
                &mut select,
            ) {
                ProgramEvaluation::NeedsProcessLookup(next) => {
                    self.lookup_process(&mut context, network, original).await?;
                    cursor = Some(next);
                }
                ProgramEvaluation::NeedsIpResolution(next) => {
                    let addresses = match (destination, &self.dns) {
                        (Destination::Domain { host, .. }, Some(dns)) => {
                            context
                                .decision()
                                .scope(self.resolve_addresses(dns, host))
                                .await?
                        }
                        _ => Vec::new(),
                    };
                    resolved = Some(addresses);
                    // Resume the exact predicate, including nested sub-rules.
                    // A process pause may follow DNS (or precede it) once.
                    cursor = Some(next);
                }
                evaluation => break evaluation,
            }
        };
        if let Some(error) = selection_error {
            return Err(error);
        }
        if let ProgramEvaluation::Failed(failure) = evaluation {
            return Err(DispatchError::RuleEvaluation(failure));
        }
        let ProgramEvaluation::Matched(rule_match) = evaluation else {
            return Err(DispatchError::Other(
                "routing rules produced no final action".to_owned(),
            ));
        };

        if business(inbound)
            && let Some(diagnostics) = &self.diagnostics
        {
            diagnostics.hit(rule_match.rule_index);
        }
        if recovered.is_some() {
            crate::dns::trace::record("fake-ip-recovery");
        }
        let routed_destination = match destination {
            Destination::Domain { host, port } => Destination::Domain {
                host: super::normalize_domain_name(host)
                    .map_err(|_| DispatchError::HostUnreachable)?,
                port: *port,
            },
            Destination::Ip(_) => destination.clone(),
        };
        let mut decision = RouteDecision {
            original: inbound_metadata.original.clone().or_else(|| {
                self.diagnostics
                    .as_ref()
                    .and_then(|_| original.cloned().map(Arc::new))
            }),
            process: context.process().cloned().unwrap_or_default(),
            rule_index: rule_match.rule_index,
            dns_mode: if recovered.is_some() {
                "fake-ip"
            } else if dns_domain_hint.is_some() {
                "mapping"
            } else {
                "normal"
            },
            metadata: context.domain().map_or_else(
                || destination.clone(),
                |host| Destination::Domain {
                    host: host.to_owned(),
                    port: destination.port(),
                },
            ),
            action: rule_match.action,
            destination: context.pinned_ip().map_or(routed_destination, |address| {
                Destination::Ip(std::net::SocketAddr::new(address, destination.port()))
            }),
            resolved_addresses: resolved,
            selected,
        };
        if decision.action == RuleAction::Direct {
            self.resolve_direct_destination(&mut decision).await?;
        }
        Ok(decision)
    }
    async fn lookup_process(
        &self,
        context: &mut RoutingContext,
        network: Network,
        original: Option<&crate::session::InboundSnapshot>,
    ) -> Result<(), DispatchError> {
        let query =
            original.and_then(|origin| crate::process::Query::from_snapshot(network, origin));
        let identity = match (query, &self.process_dialer) {
            (Some(query), Some(dialer)) => dialer
                .process_identity(query)
                .await
                .map_err(|_| DispatchError::NotAllowed)?,
            _ => Default::default(),
        };
        context.set_process(identity);
        context
            .decision()
            .check()
            .map_err(DispatchError::RuleEvaluation)
    }

    async fn resolve_direct_destination(
        &self,
        decision: &mut RouteDecision,
    ) -> Result<(), DispatchError> {
        let (host, port) = match &decision.destination {
            Destination::Domain { host, port } => (host.clone(), *port),
            Destination::Ip(_) => return Ok(()),
        };
        let address = if let Some(addresses) = decision.resolved_addresses.as_deref() {
            preferred_address(addresses)
        } else {
            let addresses = match &self.dns {
                Some(dns) => dns
                    .resolve_direct(&host)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|ip| self.ipv6 || ip.is_ipv4())
                    .collect(),
                None => Vec::new(),
            };
            let address = preferred_address(&addresses);
            decision.resolved_addresses = Some(addresses);
            address
        }
        .ok_or(DispatchError::HostUnreachable)?;
        decision.destination = Destination::Ip(std::net::SocketAddr::new(address, port));
        Ok(())
    }

    fn dns_tcp_stream(&self, dns: Arc<dyn RoutingDns>) -> BoxStream {
        crate::outbound::dns_tcp_stream(
            Arc::new(RoutingDnsExchange(Arc::downgrade(&dns))),
            tokio_util::sync::CancellationToken::new(),
            None,
        )
    }
}

fn default_reject_drop() -> Arc<dyn Dispatcher> {
    Arc::new(crate::outbound::ConnectorDispatcher::new(Arc::new(
        crate::outbound::RejectOutbound::drop_connections(),
    )))
}

struct RoutingDnsExchange(std::sync::Weak<dyn RoutingDns>);

#[async_trait]
impl crate::outbound::DnsExchange for RoutingDnsExchange {
    async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
        self.0
            .upgrade()
            .ok_or(DispatchError::HostUnreachable)?
            .exchange(query)
            .await
    }
}

struct RouteDecision {
    original: Option<Arc<crate::session::InboundSnapshot>>,
    process: crate::process::Identity,
    rule_index: usize,
    dns_mode: &'static str,
    metadata: Destination,
    action: RuleAction,
    destination: Destination,
    resolved_addresses: Option<Vec<IpAddr>>,
    selected: Option<Result<ResolvedProxyGroupLeaf, DispatchError>>,
}

fn log_route_decision(network: Network, decision: &RouteDecision) {
    let destination_port = decision.destination.port();
    match decision.action {
        RuleAction::Route(RouteTargetId::Proxy(id)) => tracing::debug!(
            ?network,
            action = "proxy",
            proxy_index = id.index(),
            destination_port,
            "routing decision"
        ),
        RuleAction::Route(RouteTargetId::Group(id)) => tracing::debug!(
            ?network,
            action = "proxy_group",
            proxy_group_index = id.index(),
            destination_port,
            "routing decision"
        ),
        RuleAction::Direct => tracing::debug!(
            ?network,
            action = "direct",
            destination_port,
            "routing decision"
        ),
        RuleAction::Reject => tracing::debug!(
            ?network,
            action = "reject",
            destination_port,
            "routing decision"
        ),
        RuleAction::RejectDrop => tracing::debug!(
            ?network,
            action = "reject_drop",
            destination_port,
            "routing decision"
        ),
    }
}

fn preferred_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| addresses.iter().copied().find(IpAddr::is_ipv6))
}

#[async_trait]
impl Dispatcher for RoutingDispatcher {
    async fn sniff_plan(
        &self,
        source: SocketAddr,
        destination: &Destination,
    ) -> Result<Option<crate::sniffing::Plan>, DispatchError> {
        let Some(policy) = self.sniffer.as_ref() else {
            return Ok(None);
        };
        let (host, mapped) = match destination {
            Destination::Domain { host, .. } => (Some(host.clone()), false),
            Destination::Ip(address) => {
                let fake = self
                    .dns
                    .as_ref()
                    .and_then(|dns| dns.recover_fake_ip(address.ip()).ok().flatten());
                if fake.is_some() {
                    (fake, false)
                } else {
                    let hint = if let Some(dns) = &self.dns {
                        dns.domain_hint(address.ip()).await
                    } else {
                        None
                    };
                    let mapped = hint.is_some();
                    (hint, mapped)
                }
            }
        };
        Ok(Some(policy.plan(
            source,
            destination,
            host.as_deref(),
            mapped,
        )?))
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        if self.diagnostics.is_some() && business(session.inbound) {
            crate::dns::trace::capture(self.connect_tcp_inner(session))
                .await
                .0
        } else {
            self.connect_tcp_inner(session).await
        }
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Ok(Box::new(self.routed_datagrams(session)))
    }
}

impl RoutingDispatcher {
    fn routed_datagrams(&self, session: DatagramSession) -> RoutedDatagramTransport {
        let managed_ready = (self.diagnostics.is_some() && business(session.inbound))
            .then(|| Arc::new(ReadyQueue::default()));
        RoutedDatagramTransport {
            router: self.clone_parts(),
            session,
            route_transports: HashMap::new(),
            fake_flows: HashMap::new(),
            managed_flows: ManagedDatagramFlows::default(),
            managed_shared: HashMap::new(),
            managed_shared_sequence: 0,
            managed_ready,
            managed_receive_buffer: Vec::new(),
            managed_next_cleanup: Instant::now() + UDP_FLOW_CLEANUP_INTERVAL,
            direct_transport: None,
            flows: DatagramRoutes::new(self.tun_config.udp_timeout),
            logged_route_actions: HashSet::new(),
            receive_wakeup: Arc::new(Notify::new()),
        }
    }

    async fn connect_tcp_inner(
        &self,
        mut session: StreamSession,
    ) -> Result<BoxStream, DispatchError> {
        if business(session.inbound) {
            session.capture_original();
        }
        self.ensure_destination_allowed(&session.destination)?;
        if session.inbound == InboundKind::Tun
            && matches!(&session.destination, Destination::Ip(address) if self.tun_config.hijacks_dns(*address))
            && let Some(dns) = self.dns.as_ref().filter(|dns| dns.is_enabled())
        {
            return Ok(self.dns_tcp_stream(dns.clone()));
        }

        let mut decision = self
            .route(
                Network::Tcp,
                (session.inbound, &session.metadata),
                session.source,
                &session.destination,
                session.sniffed_domain.as_deref(),
                None,
            )
            .await?;
        let resolved_target = decision.selected.take().transpose()?;
        if resolved_target.as_ref().is_some_and(|target| target.direct) {
            self.resolve_direct_destination(&mut decision).await?;
        }
        log_route_decision(Network::Tcp, &decision);
        let chain = resolved_target
            .as_ref()
            .map_or_else(Vec::new, |target| target.chain.clone());
        let connection = self.connection(
            Network::Tcp,
            session.inbound,
            session.source,
            &session.destination,
            session.sniffed_domain.as_deref(),
            &decision,
            chain,
        );
        let setup = async {
            let direct = decision.action == RuleAction::Direct
                || resolved_target.as_ref().is_some_and(|target| target.direct);
            if direct
                && self.tcp_concurrent
                && let Some(addresses) = &decision.resolved_addresses
                && addresses.len() > 1
            {
                let dispatcher = resolved_target
                    .as_ref()
                    .map_or(&self.direct, |target| &target.dispatcher);
                let addresses = addresses
                    .iter()
                    .map(|&ip| SocketAddr::new(ip, decision.destination.port()))
                    .collect::<Vec<_>>();
                return crate::dialer::race_connections(&addresses, None, |address| {
                    let mut attempt = session.clone();
                    attempt.destination = Destination::Ip(address);
                    attempt.sniffed_domain = None;
                    dispatcher.connect_tcp(attempt)
                })
                .await;
            }
            session.destination = decision.destination;
            session.sniffed_domain = None;
            match decision.action {
                RuleAction::Route(_) => {
                    let target = resolved_target
                        .as_ref()
                        .expect("route target was resolved before dispatch");
                    let result = target.dispatcher.connect_tcp(session).await;
                    target.report(&result);
                    result
                }
                RuleAction::Direct => self.direct.connect_tcp(session).await,
                RuleAction::Reject => Err(DispatchError::NotAllowed),
                RuleAction::RejectDrop => self.reject_drop.connect_tcp(session).await,
            }
        };
        if let Some(connection) = connection {
            let token = connection.token();
            let result = tokio::select! { biased; () = token.cancelled() => Err(DispatchError::NotAllowed), result = setup => result };
            connection.dns_path(crate::dns::trace::snapshot());
            match result {
                Ok(stream) => Ok(connection.stream(stream)),
                Err(error) => {
                    if !connection.cancelled() {
                        connection.failed(&error);
                    }
                    Err(error)
                }
            }
        } else {
            setup.await
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn connection(
        &self,
        network: Network,
        inbound: InboundKind,
        source: SocketAddr,
        original: &Destination,
        sniffed: Option<&str>,
        decision: &RouteDecision,
        chain: Vec<String>,
    ) -> Option<crate::connections::Connection> {
        if !business(inbound) {
            return None;
        }
        let diagnostics = self.diagnostics.as_ref()?;
        let mut chain = chain
            .iter()
            .map(|name| diagnostics.text(name))
            .collect::<Vec<_>>();
        if chain.is_empty() {
            chain.push(match decision.action {
                RuleAction::Direct => diagnostics.text("DIRECT"),
                RuleAction::Reject => diagnostics.text("REJECT"),
                RuleAction::RejectDrop => diagnostics.text("REJECT-DROP"),
                RuleAction::Route(RouteTargetId::Proxy(id)) => {
                    diagnostics.proxy_names[id.index()].clone()
                }
                RuleAction::Route(RouteTargetId::Group(_)) => {
                    unreachable!("group leaf supplies chain")
                }
            });
        }
        let (rule, rule_payload) = diagnostics.matched(decision.rule_index);
        let host = match &decision.metadata {
            Destination::Domain { host, .. } => diagnostics.text(host),
            _ => diagnostics.text(""),
        };
        let destination_ip = match &decision.destination {
            Destination::Ip(addr) => Some(addr.ip()),
            _ => None,
        };
        let provider_chains = diagnostics.providers(&chain);
        Some(
            diagnostics
                .connections
                .open(crate::connections::ConnectionInfo {
                    metadata: crate::connections::ConnectionMetadata {
                        network: if network == Network::Tcp {
                            "tcp"
                        } else {
                            "udp"
                        },
                        inbound_type: match inbound {
                            InboundKind::Tun => "Tun",
                            InboundKind::Http => "HTTP",
                            InboundKind::Https => "HTTPS",
                            _ => "Socks5",
                        },
                        source,
                        destination_ip,
                        destination_port: original.port(),
                        host,
                        dns_mode: decision.dns_mode,
                        sniff_host: diagnostics.text(sniffed.unwrap_or_default()),
                        process: decision.process.clone(),
                        original: decision.original.clone(),
                    },
                    chains: chain,
                    provider_chains,
                    rule,
                    rule_payload,
                    dns_path: crate::dns::trace::snapshot(),
                }),
        )
    }

    fn clone_parts(&self) -> Self {
        Self {
            route_targets: self.route_targets.clone(),
            direct: self.direct.clone(),
            reject_drop: self.reject_drop.clone(),
            dns: self.dns.clone(),
            ipv6: self.ipv6,
            rules: self.rules.clone(),
            geo_matcher: self.geo_matcher.clone(),
            tun_config: self.tun_config.clone(),
            sniffer: self.sniffer.clone(),
            tcp_concurrent: self.tcp_concurrent,
            diagnostics: self.diagnostics.clone(),
            process_mode: self.process_mode,
            process_dialer: self.process_dialer.clone(),
        }
    }
}

struct RoutedDatagramTransport {
    router: RoutingDispatcher,
    session: DatagramSession,
    route_transports: HashMap<(RouteTargetId, Option<Destination>), CachedRouteTransport>,
    fake_flows: HashMap<SocketAddr, FakeDatagramFlow>,
    managed_flows: ManagedDatagramFlows,
    managed_shared: HashMap<usize, ManagedSharedTransport>,
    managed_shared_sequence: usize,
    managed_ready: Option<Arc<ReadyQueue>>,
    managed_receive_buffer: Vec<u8>,
    managed_next_cleanup: Instant,
    direct_transport: Option<Box<dyn DatagramTransport>>,
    flows: DatagramRoutes,
    logged_route_actions: HashSet<LoggedRouteAction>,
    receive_wakeup: Arc<Notify>,
}

// Each synthetic target owns an association: two names may resolve to the same
// real endpoint, and replies must still retain their original synthetic address.
struct FakeDatagramFlow {
    transport: Box<dyn DatagramTransport>,
    remote: SocketAddr,
    last_used: Instant,
    flow_id: Option<Box<[u8]>>,
}

struct ManagedReceive {
    wake: Arc<ReadyFlow>,
    cancelled: Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>,
}

#[derive(Default)]
struct ManagedDatagramFlows {
    polled: HashMap<Destination, ManagedDatagramFlow>,
    asynchronous: HashMap<Destination, ManagedDatagramFlow>,
}
impl ManagedDatagramFlows {
    fn get(&self, key: &Destination) -> Option<&ManagedDatagramFlow> {
        self.polled.get(key).or_else(|| self.asynchronous.get(key))
    }
    fn get_mut(&mut self, key: &Destination) -> Option<&mut ManagedDatagramFlow> {
        self.polled
            .get_mut(key)
            .or_else(|| self.asynchronous.get_mut(key))
    }
    fn contains_key(&self, key: &Destination) -> bool {
        self.polled.contains_key(key) || self.asynchronous.contains_key(key)
    }
    fn insert(&mut self, key: Destination, flow: ManagedDatagramFlow) {
        if flow.receiver.is_some() {
            self.polled.insert(key, flow);
        } else {
            self.asynchronous.insert(key, flow);
        }
    }
    fn remove(&mut self, key: &Destination) -> Option<ManagedDatagramFlow> {
        self.polled
            .remove(key)
            .or_else(|| self.asynchronous.remove(key))
    }
    fn iter(&self) -> impl Iterator<Item = (&Destination, &ManagedDatagramFlow)> {
        self.polled.iter().chain(self.asynchronous.iter())
    }
    fn drain(&mut self) -> impl Iterator<Item = (Destination, ManagedDatagramFlow)> {
        self.polled.drain().chain(self.asynchronous.drain())
    }
    fn shrink(&mut self) {
        for map in [&mut self.polled, &mut self.asynchronous] {
            if map.capacity() > map.len().saturating_mul(4).max(8) {
                map.shrink_to(map.len().saturating_mul(2));
            }
        }
    }
}

struct ManagedDatagramFlow {
    receiver: Option<ManagedReceive>,
    transport: ManagedTransport,
    connection: crate::connections::Connection,
    destination: Destination,
    restore: bool,
    last_used: Instant,
    flow_id: Option<Box<[u8]>>,
}

enum ManagedTransport {
    Dedicated(Box<dyn DatagramTransport>),
    Shared(usize),
}

struct ManagedSharedTransport {
    // Keep the concrete node and its resource generation alive. Pointer
    // equality alone would permit address reuse after a provider replacement.
    dispatcher: Arc<dyn Dispatcher>,
    transport: Box<dyn DatagramTransport>,
    members: usize,
    accepting: bool,
}

enum ManagedDatagramEvent {
    Flow(Destination, Option<Result<Datagram, DispatchError>>),
    Shared(usize, Result<Datagram, DispatchError>),
}

impl Drop for ManagedDatagramFlow {
    fn drop(&mut self) {
        if let Some(receiver) = &self.receiver {
            receiver.wake.deactivate();
        }
    }
}

struct CachedRouteTransport {
    leaf: ResolvedProxyGroupLeaf,
    last_used: Instant,
    transport: Box<dyn DatagramTransport>,
    direct: bool,
}

/// Source, UDP protocol and inbound are fixed by the association owner; the
/// destination IP/port completes the five-tuple. Entries retain no DNS/GeoData.
struct DatagramRoute {
    action: RuleAction,
    last_used: Instant,
    flow_id: Option<Box<[u8]>>,
}

struct DatagramRoutes {
    entries: HashMap<SocketAddr, DatagramRoute>,
    next_cleanup: Instant,
    idle_timeout: Duration,
}

impl DatagramRoutes {
    fn new(idle_timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            next_cleanup: Instant::now() + UDP_FLOW_CLEANUP_INTERVAL,
            idle_timeout,
        }
    }

    fn expire(&mut self, now: Instant) {
        if now < self.next_cleanup {
            return;
        }
        self.next_cleanup = now + UDP_FLOW_CLEANUP_INTERVAL;
        self.entries
            .retain(|_, route| now.duration_since(route.last_used) < self.idle_timeout);
        // Entry removal alone retains buckets. Reclaim burst capacity without
        // resizing on the hot path or imposing a business-flow count ceiling.
        if self.entries.capacity() > self.entries.len().saturating_mul(4).max(8) {
            self.entries.shrink_to(self.entries.len().saturating_mul(2));
        }
    }

    fn action(&mut self, destination: SocketAddr, now: Instant) -> Option<RuleAction> {
        self.expire(now);
        let route = self.entries.get_mut(&destination)?;
        if now.duration_since(route.last_used) >= self.idle_timeout {
            self.entries.remove(&destination);
            return None;
        }
        route.last_used = now;
        Some(route.action)
    }

    fn observe_response(&mut self, destination: SocketAddr, now: Instant) {
        self.expire(now);
        if let Some(route) = self.entries.get_mut(&destination) {
            // An already expired entry is not revived by a late response.
            if now.duration_since(route.last_used) < self.idle_timeout {
                route.last_used = now;
            } else {
                self.entries.remove(&destination);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LoggedRouteAction {
    Route(RouteTargetId),
    Direct,
    Reject,
    RejectDrop,
}

impl From<RuleAction> for LoggedRouteAction {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Route(id) => Self::Route(id),
            RuleAction::Direct => Self::Direct,
            RuleAction::Reject => Self::Reject,
            RuleAction::RejectDrop => Self::RejectDrop,
        }
    }
}

impl RoutedDatagramTransport {
    fn tracked(&self) -> bool {
        self.router.diagnostics.is_some() && business(self.session.inbound)
    }

    async fn remove_managed(&mut self, key: &Destination) -> Result<(), DispatchError> {
        let Some(mut flow) = self.managed_flows.remove(key) else {
            return Ok(());
        };
        if let Some(receiver) = &flow.receiver {
            receiver.wake.deactivate();
        }
        match &mut flow.transport {
            ManagedTransport::Dedicated(transport) => transport.close().await,
            ManagedTransport::Shared(id) => {
                let shared = self.managed_shared.get_mut(id).expect("shared flow owner");
                // A later connection with this same destination must not receive
                // a delayed reply from the old generation. Existing siblings
                // keep this wire, but new destinations use a new association.
                shared.accepting = false;
                shared.members -= 1;
                if shared.members == 0 {
                    let mut shared = self.managed_shared.remove(id).expect("last shared owner");
                    shared.transport.close().await?;
                }
                Ok(())
            }
        }
    }

    async fn fail_managed_shared(&mut self, id: usize, error: &DispatchError) {
        let keys = self
            .managed_flows
            .iter()
            .filter(|(_, flow)| matches!(flow.transport, ManagedTransport::Shared(owner) if owner == id))
            .map(|(key, flow)| {
                if !flow.connection.cancelled() {
                    flow.connection.failed(error);
                }
                key.clone()
            })
            .collect::<Vec<_>>();
        for key in keys {
            let _ = self.remove_managed(&key).await;
        }
    }

    async fn open_managed_transport(
        &mut self,
        dispatcher: Arc<dyn Dispatcher>,
        connection: &crate::connections::Connection,
        share: bool,
    ) -> Result<ManagedTransport, DispatchError> {
        if share
            && let Some((&id, shared)) = self.managed_shared.iter_mut().find(|(_, shared)| {
                shared.accepting && Arc::ptr_eq(&dispatcher, &shared.dispatcher)
            })
        {
            shared.members += 1;
            return Ok(ManagedTransport::Shared(id));
        }
        let token = connection.token();
        let transport = tokio::select! {
            biased;
            () = token.cancelled() => return Err(DispatchError::NotAllowed),
            result = dispatcher.open_datagram(self.session.clone()) => result?,
        };
        if share && transport.supports_shared_destinations() {
            self.managed_shared_sequence = self
                .managed_shared_sequence
                .checked_add(1)
                .ok_or(DispatchError::NotAllowed)?;
            let id = self.managed_shared_sequence;
            self.managed_shared.insert(
                id,
                ManagedSharedTransport {
                    dispatcher,
                    transport,
                    members: 1,
                    accepting: true,
                },
            );
            Ok(ManagedTransport::Shared(id))
        } else {
            Ok(ManagedTransport::Dedicated(transport))
        }
    }

    async fn clean_managed(&mut self) {
        let now = Instant::now();
        if now < self.managed_next_cleanup {
            return;
        }
        self.managed_next_cleanup = now + UDP_FLOW_CLEANUP_INTERVAL;
        let expired = self
            .managed_flows
            .iter()
            .filter(|(_, flow)| {
                flow.connection.cancelled()
                    || flow.last_used.elapsed() >= self.router.tun_config.udp_timeout
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            let _ = self.remove_managed(&key).await;
        }
        self.managed_flows.shrink();
        if self.managed_shared.capacity() > self.managed_shared.len().saturating_mul(4).max(8) {
            self.managed_shared
                .shrink_to(self.managed_shared.len().saturating_mul(2));
        }
        self.managed_ready
            .as_ref()
            .expect("tracked receive queue")
            .shrink();
    }
    async fn send_managed(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
        self.clean_managed().await;
        let key = datagram.remote.clone();
        if self.managed_flows.get(&key).is_some_and(|flow| {
            flow.connection.cancelled()
                || flow.last_used.elapsed() >= self.router.tun_config.udp_timeout
        }) {
            let _ = self.remove_managed(&key).await;
        }
        if !self.managed_flows.contains_key(&key) {
            // Keep route setup state out of the future allocated for each cached send.
            let mut decision = Box::pin(self.router.route(
                Network::Udp,
                (self.session.inbound, &self.session.metadata),
                self.session.source,
                &key,
                datagram.sniffed_domain.as_deref(),
                None,
            ))
            .await?;
            if matches!(decision.action, RuleAction::Reject | RuleAction::RejectDrop) {
                return Ok(());
            }
            let (dispatcher, direct, chain) = match decision.action {
                RuleAction::Direct => (self.router.direct.clone(), true, Vec::new()),
                RuleAction::Route(_) => {
                    let leaf = decision
                        .selected
                        .take()
                        .expect("accepted route owns its selected leaf")?;
                    (leaf.dispatcher, leaf.direct, leaf.chain)
                }
                RuleAction::Reject | RuleAction::RejectDrop => unreachable!(),
            };
            if direct {
                self.router
                    .resolve_direct_destination(&mut decision)
                    .await?;
            }
            let restore = matches!(key, Destination::Ip(_))
                && (decision.dns_mode == "fake-ip"
                    || (datagram.sniffed_domain.is_some()
                        && self
                            .router
                            .sniffer
                            .as_ref()
                            .is_some_and(|p| p.config.quic_override)));
            if restore && let Destination::Domain { host, port } = &decision.destination {
                let dns = self
                    .router
                    .dns
                    .as_ref()
                    .ok_or(DispatchError::HostUnreachable)?;
                let addresses = self.router.resolve_addresses(dns, host).await?;
                decision.destination = Destination::Ip(SocketAddr::new(
                    preferred_address(&addresses).ok_or(DispatchError::HostUnreachable)?,
                    *port,
                ));
            }
            let connection = self
                .router
                .connection(
                    Network::Udp,
                    self.session.inbound,
                    self.session.source,
                    &key,
                    datagram.sniffed_domain.as_deref(),
                    &decision,
                    chain,
                )
                .expect("tracked business flow");
            // Only identical IP addresses can be demultiplexed without a DNS
            // alias table. Fake-IP, QUIC override and domain requests retain
            // dedicated wires, including two names resolving to one endpoint.
            let share =
                !restore && matches!(key, Destination::Ip(_)) && key == decision.destination;
            let result = self
                .open_managed_transport(dispatcher, &connection, share)
                .await;
            connection.dns_path(crate::dns::trace::snapshot());
            let transport = match result {
                Ok(transport) => transport,
                Err(error) => {
                    if !connection.cancelled() {
                        connection.failed(&error);
                    }
                    return Err(error);
                }
            };
            let polled = match &transport {
                ManagedTransport::Dedicated(transport) => transport.supports_poll_receive(),
                ManagedTransport::Shared(_) => true, // readiness owns only logical cancellation
            };
            let receiver = polled.then(|| {
                let wake = self
                    .managed_ready
                    .as_ref()
                    .expect("tracked receive queue")
                    .registration(key.clone());
                wake.enqueue();
                ManagedReceive {
                    wake,
                    cancelled: Box::pin(connection.token().cancelled_owned()),
                }
            });
            self.managed_flows.insert(
                key.clone(),
                ManagedDatagramFlow {
                    receiver,
                    transport,
                    connection,
                    destination: decision.destination,
                    restore,
                    last_used: Instant::now(),
                    flow_id: None,
                },
            );
        }
        let flow = self.managed_flows.get_mut(&key).expect("flow created");
        flow.last_used = Instant::now();
        let size = datagram.payload.len();
        datagram.remote = flow.destination.clone();
        datagram.sniffed_domain = None;
        let token = flow.connection.token();
        let (transport, shared_id) = match &mut flow.transport {
            ManagedTransport::Dedicated(transport) => (transport, None),
            ManagedTransport::Shared(id) => (
                &mut self
                    .managed_shared
                    .get_mut(id)
                    .expect("shared flow owner")
                    .transport,
                Some(*id),
            ),
        };
        let result = tokio::select! { biased; () = token.cancelled() => Err(DispatchError::NotAllowed), result = transport.send(datagram) => result };
        match &result {
            Ok(()) => flow.connection.upload(size),
            Err(error) => {
                if shared_id.is_none() && !flow.connection.cancelled() {
                    flow.connection.failed(error);
                }
                if let Some(id) = shared_id
                    && !token.is_cancelled()
                {
                    self.fail_managed_shared(id, error).await;
                } else {
                    let _ = self.remove_managed(&key).await;
                }
            }
        }
        result
    }
    fn poll_managed(
        flows: &mut HashMap<Destination, ManagedDatagramFlow>,
        ready: &ReadyQueue,
        scratch: &mut Vec<u8>,
        idle_timeout: Duration,
        context: &mut Context<'_>,
    ) -> Poll<(Destination, Option<Result<Datagram, DispatchError>>)> {
        ready.register(context.waker());
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            let Some(wake) = ready.pop() else {
                return Poll::Pending;
            };
            let Some(flow) = flows.get_mut(wake.key()) else {
                continue;
            };
            let receiver = flow.receiver.as_mut().expect("polled receiver");
            if !Arc::ptr_eq(&receiver.wake, &wake) {
                continue;
            }
            let waker = futures_util::task::waker_ref(&wake);
            let mut flow_context = Context::from_waker(&waker);
            if receiver
                .cancelled
                .as_mut()
                .poll(&mut flow_context)
                .is_ready()
                || flow.last_used.elapsed() >= idle_timeout
            {
                return Poll::Ready((wake.key().clone(), None));
            }
            let ManagedTransport::Dedicated(transport) = &mut flow.transport else {
                continue;
            };
            match transport.poll_receive(&mut flow_context, scratch) {
                Poll::Pending => {}
                Poll::Ready(Ok(mut datagram)) => {
                    wake.requeue();
                    if flow.restore {
                        if datagram.remote != flow.destination {
                            continue;
                        }
                        datagram.remote = wake.key().clone();
                    }
                    flow.connection.download(datagram.payload.len());
                    flow.last_used = Instant::now();
                    return Poll::Ready((wake.key().clone(), Some(Ok(datagram))));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready((wake.key().clone(), Some(Err(error))));
                }
            }
        }
        if !ready.is_empty() {
            context.waker().wake_by_ref();
        }
        Poll::Pending
    }

    async fn receive_managed_shared(
        transports: &mut HashMap<usize, ManagedSharedTransport>,
    ) -> (usize, Result<Datagram, DispatchError>) {
        if transports.is_empty() {
            return std::future::pending().await;
        }
        if transports.len() == 1 {
            let (&id, shared) = transports.iter_mut().next().expect("one shared transport");
            return (id, shared.transport.receive().await);
        }
        let receives = transports
            .iter_mut()
            .map(|(&id, shared)| {
                Box::pin(async move { (id, shared.transport.receive().await) })
                    as futures_util::future::BoxFuture<'_, _>
            })
            .collect::<Vec<_>>();
        select_all(receives).await.0
    }

    async fn receive_managed(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            self.clean_managed().await;
            let idle_timeout = self.router.tun_config.udp_timeout;
            let result = {
                let polled = std::future::poll_fn(|context| {
                    Self::poll_managed(
                        &mut self.managed_flows.polled,
                        self.managed_ready.as_ref().expect("tracked receive queue"),
                        &mut self.managed_receive_buffer,
                        idle_timeout,
                        context,
                    )
                });
                let asynchronous = async {
                    if self.managed_flows.asynchronous.is_empty() {
                        std::future::pending::<()>().await;
                    }
                    let receives = self.managed_flows.asynchronous.iter_mut().map(|(key, flow)| Box::pin(async move {
                        let token = flow.connection.token();
                        loop {
                            if flow.last_used.elapsed() >= idle_timeout {
                                return (key.clone(), None);
                            }
                            let ManagedTransport::Dedicated(transport) = &mut flow.transport else {
                                unreachable!("shared logical flows use cancellation readiness");
                            };
                            let result = tokio::select! { biased; () = token.cancelled() => None, result = transport.receive() => Some(result) };
                            if let Some(Ok(mut datagram)) = result {
                                if flow.last_used.elapsed() >= idle_timeout {
                                    return (key.clone(), None);
                                }
                                if flow.restore {
                                    if datagram.remote != flow.destination { continue; }
                                    datagram.remote = key.clone();
                                }
                                flow.connection.download(datagram.payload.len());
                                flow.last_used = Instant::now();
                                return (key.clone(), Some(Ok(datagram)));
                            }
                            return (key.clone(), result);
                        }
                    }) as futures_util::future::BoxFuture<'_, _>).collect::<Vec<_>>();
                    select_all(receives).await.0
                };
                let shared = Self::receive_managed_shared(&mut self.managed_shared);
                tokio::select! {
                    (key, result) = polled => Some(ManagedDatagramEvent::Flow(key, result)),
                    (key, result) = asynchronous => Some(ManagedDatagramEvent::Flow(key, result)),
                    (id, result) = shared => Some(ManagedDatagramEvent::Shared(id, result)),
                    () = tokio::time::sleep_until(self.managed_next_cleanup) => None,
                }
            };
            match result {
                Some(ManagedDatagramEvent::Flow(_, Some(Ok(datagram)))) => {
                    return Ok(datagram);
                }
                Some(ManagedDatagramEvent::Flow(key, result)) => {
                    if let Some(Err(error)) = result
                        && let Some(flow) = self.managed_flows.get(&key)
                    {
                        flow.connection.failed(&error);
                    }
                    let _ = self.remove_managed(&key).await;
                }
                Some(ManagedDatagramEvent::Shared(id, Ok(datagram))) => {
                    let key = &datagram.remote;
                    if let Some(flow) = self.managed_flows.get_mut(key)
                        && matches!(flow.transport, ManagedTransport::Shared(owner) if owner == id)
                    {
                        if flow.connection.cancelled() || flow.last_used.elapsed() >= idle_timeout {
                            let _ = self.remove_managed(key).await;
                        } else {
                            flow.connection.download(datagram.payload.len());
                            flow.last_used = Instant::now();
                            return Ok(datagram);
                        }
                    }
                }
                Some(ManagedDatagramEvent::Shared(id, Err(error))) => {
                    self.fail_managed_shared(id, &error).await
                }
                None => {}
            }
            tokio::task::consume_budget().await;
        }
    }

    async fn expire_fake_flows(&mut self) {
        let expired = self
            .route_transports
            .iter()
            .filter(|((_, destination), cached)| {
                destination.is_some()
                    && cached.last_used.elapsed() >= self.router.tun_config.udp_timeout
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            if let Some(mut cached) = self.route_transports.remove(&key) {
                let _ = cached.transport.close().await;
            }
        }

        let now = Instant::now();
        let expired: Vec<_> = self
            .fake_flows
            .iter()
            .filter_map(|(key, flow)| {
                (now.duration_since(flow.last_used) >= self.router.tun_config.udp_timeout)
                    .then_some(*key)
            })
            .collect();
        for key in expired {
            if let Some(mut flow) = self.fake_flows.remove(&key) {
                let _ = flow.transport.close().await;
            }
        }
    }

    async fn send_fake(
        &mut self,
        original: SocketAddr,
        mut datagram: Datagram,
    ) -> Result<(), DispatchError> {
        if !self.fake_flows.contains_key(&original) {
            let mut decision = Box::pin(self.router.route(
                Network::Udp,
                (self.session.inbound, &self.session.metadata),
                self.session.source,
                &datagram.remote,
                datagram.sniffed_domain.as_deref(),
                None,
            ))
            .await?;
            let (dispatcher, direct) = match decision.action {
                RuleAction::Reject | RuleAction::RejectDrop => return Ok(()),
                RuleAction::Direct => (self.router.direct.clone(), true),
                RuleAction::Route(_) => {
                    let target = decision
                        .selected
                        .take()
                        .expect("accepted route owns its selected leaf")?;
                    (target.dispatcher, target.direct)
                }
            };
            if direct {
                self.router
                    .resolve_direct_destination(&mut decision)
                    .await?;
            }
            let remote = match decision.destination {
                Destination::Ip(address) => address,
                Destination::Domain { host, port } => {
                    let dns = self
                        .router
                        .dns
                        .as_ref()
                        .ok_or(DispatchError::HostUnreachable)?;
                    let addresses = self.router.resolve_addresses(dns, &host).await?;
                    SocketAddr::new(
                        preferred_address(&addresses).ok_or(DispatchError::HostUnreachable)?,
                        port,
                    )
                }
            };
            let transport = dispatcher.open_datagram(self.session.clone()).await?;
            self.fake_flows.insert(
                original,
                FakeDatagramFlow {
                    transport,
                    remote,
                    last_used: Instant::now(),
                    flow_id: None,
                },
            );
            self.receive_wakeup.notify_one();
        }
        let flow = self
            .fake_flows
            .get_mut(&original)
            .expect("fake-IP flow inserted");
        datagram.remote = Destination::Ip(flow.remote);
        datagram.sniffed_domain = None;
        flow.last_used = Instant::now();
        flow.transport.send(datagram).await
    }

    fn should_log_route_action(&mut self, action: RuleAction) -> bool {
        self.logged_route_actions.insert(action.into())
    }

    async fn send_route(
        &mut self,
        id: RouteTargetId,
        mut decision: RouteDecision,
        mut datagram: Datagram,
    ) -> Result<(), DispatchError> {
        let key = (
            id,
            self.router
                .route_targets
                .per_flow(id)
                .then(|| datagram.remote.clone()),
        );
        let direct = self.route_transports.get(&key).map(|cached| cached.direct);
        let direct = match direct {
            Some(direct) => direct,
            None => {
                let target = match decision.selected.take() {
                    Some(target) => target?,
                    None => self.router.route_targets.resolve_for(
                        id,
                        true,
                        Some(self.session.source),
                        Some(&decision.metadata),
                        self.session.metadata.user.as_deref(),
                    )?,
                };
                let direct = target.direct;
                if direct {
                    self.router
                        .resolve_direct_destination(&mut decision)
                        .await?;
                }
                let transport = target
                    .dispatcher
                    .open_datagram(self.session.clone())
                    .await?;
                self.route_transports.insert(
                    key.clone(),
                    CachedRouteTransport {
                        transport,
                        direct,
                        leaf: target,
                        last_used: Instant::now(),
                    },
                );
                self.receive_wakeup.notify_one();
                direct
            }
        };
        if direct && !matches!(decision.destination, Destination::Ip(_)) {
            self.router
                .resolve_direct_destination(&mut decision)
                .await?;
        }
        datagram.remote = decision.destination;
        datagram.sniffed_domain = None;
        let cached = self
            .route_transports
            .get_mut(&key)
            .expect("route transport was inserted");
        cached.last_used = Instant::now();
        cached.transport.send(datagram).await
    }

    async fn send_direct(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.direct_transport.is_none() {
            self.direct_transport = Some(
                self.router
                    .direct
                    .open_datagram(self.session.clone())
                    .await?,
            );
            self.receive_wakeup.notify_one();
        }
        self.direct_transport
            .as_mut()
            .expect("direct transport initialized")
            .send(datagram)
            .await
    }

    async fn receive_inner(&mut self) -> Result<Datagram, DispatchError> {
        loop {
            // Only send/close can change these caches, and they also require
            // &mut self. The sole backend cannot change during this receive;
            // cancellation releases the borrow before another route is opened.
            if self.fake_flows.is_empty() && self.route_transports.is_empty() {
                if let Some(direct) = self.direct_transport.as_mut() {
                    return direct.receive().await;
                }
            } else if self.fake_flows.is_empty()
                && self.route_transports.len() == 1
                && self.direct_transport.is_none()
            {
                let cached = self
                    .route_transports
                    .values_mut()
                    .next()
                    .expect("the only route transport exists");
                let result = cached.transport.receive().await;
                if result.is_ok() {
                    cached.last_used = Instant::now();
                }
                return result;
            }
            let mut receives: Vec<
                futures_util::future::BoxFuture<'_, Result<Datagram, DispatchError>>,
            > = self
                .route_transports
                .values_mut()
                .map(|cached| {
                    Box::pin(async move {
                        let result = cached.transport.receive().await;
                        if result.is_ok() {
                            cached.last_used = Instant::now();
                        }
                        result
                    }) as futures_util::future::BoxFuture<'_, _>
                })
                .collect::<Vec<_>>();
            if let Some(direct) = self.direct_transport.as_mut() {
                receives.push(direct.receive());
            }
            for (original, flow) in &mut self.fake_flows {
                receives.push(Box::pin(async move {
                    loop {
                        let mut response = flow.transport.receive().await?;
                        if response.remote != Destination::Ip(flow.remote) {
                            continue;
                        }
                        response.remote = Destination::Ip(*original);
                        flow.last_used = Instant::now();
                        return Ok(response);
                    }
                }));
            }
            if receives.is_empty() {
                self.receive_wakeup.notified().await;
                continue;
            }
            tokio::select! {
                _ = self.receive_wakeup.notified() => {}
                (result, _, _) = select_all(receives) => return result,
            }
        }
    }
}

#[async_trait]
impl DatagramTransport for RoutedDatagramTransport {
    fn supports_shared_destinations(&self) -> bool {
        // Owns routing and address restoration; it is not a transparent codec.
        false
    }

    async fn send(&mut self, mut datagram: Datagram) -> Result<(), DispatchError> {
        if self.tracked() {
            return crate::dns::trace::capture(self.send_managed(datagram))
                .await
                .0;
        }
        self.expire_fake_flows().await;
        if matches!(self.session.inbound, InboundKind::Tun | InboundKind::Socks5)
            && let Destination::Ip(original) = datagram.remote
            && (self.fake_flows.contains_key(&original)
                || self
                    .router
                    .dns
                    .as_ref()
                    .map(|dns| dns.recover_fake_ip(original.ip()))
                    .transpose()?
                    .flatten()
                    .is_some()
                || (datagram.sniffed_domain.is_some()
                    && self
                        .router
                        .sniffer
                        .as_ref()
                        .is_some_and(|policy| policy.config.quic_override)))
        {
            return self.send_fake(original, datagram).await;
        }
        let now = Instant::now();
        if self.session.inbound == InboundKind::Tun {
            self.flows.expire(now);
        }
        let flow = match (self.session.inbound, &datagram.remote) {
            (InboundKind::Tun, Destination::Ip(address)) => Some(*address),
            _ => None,
        };
        let action = flow.and_then(|destination| self.flows.action(destination, now));
        let decision = if let Some(action) = action {
            RouteDecision {
                original: None,
                process: Default::default(),
                rule_index: self.router.rules.len(),
                dns_mode: "normal",
                metadata: datagram.remote.clone(),
                action,
                destination: datagram.remote.clone(),
                resolved_addresses: None,
                selected: None,
            }
        } else {
            let decision = Box::pin(self.router.route(
                Network::Udp,
                (self.session.inbound, &self.session.metadata),
                self.session.source,
                &datagram.remote,
                datagram.sniffed_domain.as_deref(),
                Some(&mut self.route_transports),
            ))
            .await?;
            if let Some(destination) = flow {
                self.flows.entries.insert(
                    destination,
                    DatagramRoute {
                        action: decision.action,
                        last_used: Instant::now(),
                        flow_id: None,
                    },
                );
            }
            decision
        };
        if self.should_log_route_action(decision.action) {
            log_route_decision(Network::Udp, &decision);
        }
        match decision.action {
            RuleAction::Route(id) => self.send_route(id, decision, datagram).await,
            RuleAction::Direct => {
                datagram.remote = decision.destination;
                datagram.sniffed_domain = None;
                self.send_direct(datagram).await
            }
            // UDP REJECT applies only to this datagram. The association stays
            // alive so a later destination can select another action.
            RuleAction::Reject | RuleAction::RejectDrop => Ok(()),
        }
    }

    async fn send_with_flow_id(
        &mut self,
        datagram: Datagram,
        flow_id: &[u8],
    ) -> Result<(), DispatchError> {
        if flow_id.is_empty() || flow_id.len() > 25 {
            return Err(DispatchError::NotAllowed);
        }
        if self.tracked() {
            let key = datagram.remote.clone();
            if self
                .managed_flows
                .get(&key)
                .is_some_and(|flow| flow.flow_id.as_deref() != Some(flow_id))
            {
                self.remove_managed(&key).await?;
            }
            self.send(datagram).await?;
            if let Some(flow) = self.managed_flows.get_mut(&key) {
                flow.flow_id = Some(flow_id.into());
            }
            return Ok(());
        }
        let flow = match (self.session.inbound, &datagram.remote) {
            (InboundKind::Tun, Destination::Ip(address)) => Some(*address),
            _ => None,
        };
        if let Some(destination) = flow {
            self.flows.expire(Instant::now());
            if self
                .flows
                .entries
                .get(&destination)
                .is_some_and(|route| route.flow_id.as_deref() != Some(flow_id))
            {
                self.flows.entries.remove(&destination);
                let keys = self
                    .route_transports
                    .keys()
                    .filter(|(_, target)| target.as_ref() == Some(&Destination::Ip(destination)))
                    .cloned()
                    .collect::<Vec<_>>();
                for key in keys {
                    if let Some(mut cached) = self.route_transports.remove(&key) {
                        cached.transport.close().await?;
                    }
                }
            }
        }
        if let Some(destination) = flow
            && self
                .fake_flows
                .get(&destination)
                .is_some_and(|flow| flow.flow_id.as_deref() != Some(flow_id))
            && let Some(mut old) = self.fake_flows.remove(&destination)
        {
            old.transport.close().await?;
        }
        self.send(datagram).await?;
        if let Some(destination) = flow
            && let Some(flow) = self.fake_flows.get_mut(&destination)
        {
            flow.flow_id = Some(flow_id.into());
        }
        if let Some(destination) = flow
            && let Some(route) = self.flows.entries.get_mut(&destination)
            && route.flow_id.as_deref() != Some(flow_id)
        {
            route.flow_id = Some(flow_id.into());
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.tracked() {
            return self.receive_managed().await;
        }
        let datagram = loop {
            self.expire_fake_flows().await;
            tokio::select! {
                result = self.receive_inner() => break result?,
                () = tokio::time::sleep(UDP_FLOW_CLEANUP_INTERVAL) => {},
            }
        };
        if self.session.inbound == InboundKind::Tun {
            let now = Instant::now();
            self.flows.expire(now);
            if let Destination::Ip(destination) = datagram.remote {
                self.flows.observe_response(destination, now);
            }
        }
        Ok(datagram)
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        let mut first_error = None;
        for (_, mut flow) in self.managed_flows.drain() {
            if let ManagedTransport::Dedicated(transport) = &mut flow.transport
                && let Err(error) = transport.close().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        for (_, mut shared) in self.managed_shared.drain() {
            if let Err(error) = shared.transport.close().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        for flow in self.fake_flows.values_mut() {
            if let Err(error) = flow.transport.close().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        self.fake_flows.clear();
        for route in self.route_transports.values_mut() {
            if let Err(error) = route.transport.close().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(direct) = &mut self.direct_transport
            && let Err(error) = direct.close().await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        self.route_transports.clear();
        self.direct_transport = None;
        self.flows.entries = HashMap::new();
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::{
        config::{
            IpCidr, PortRange, ProxyGroupId, ProxyGroupMemberConfig, ProxyGroupMemberTarget,
            ProxyId, RuleKind, RuleSpec, SelectProxyGroupConfig,
        },
        geodata::{DynamicGeoData, GeoData},
        routing::EmptyGeoMatcher,
    };
    use bytes::Bytes;

    #[derive(Default)]
    struct RecordingDispatcher {
        tcp_only: bool,
        pollable: bool,
        shareable: bool,
        receive_polls: Arc<AtomicUsize>,
        udp_closes: Arc<AtomicUsize>,
        tcp_sessions: Mutex<Vec<StreamSession>>,
        datagrams: Arc<Mutex<Vec<Datagram>>>,
        udp_opens: AtomicUsize,
    }

    #[async_trait]
    impl Dispatcher for RecordingDispatcher {
        fn supports_udp(&self) -> bool {
            !self.tcp_only
        }

        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.tcp_sessions.lock().unwrap().push(session);
            let (client, _server) = tokio::io::duplex(64);
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_opens.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(RecordingDatagrams {
                sent: self.datagrams.clone(),
                responses: VecDeque::new(),
                pollable: self.pollable,
                shareable: self.shareable,
                receive_polls: self.receive_polls.clone(),
                closes: self.udp_closes.clone(),
                receive_waker: None,
            }))
        }
    }

    struct RecordingDatagrams {
        sent: Arc<Mutex<Vec<Datagram>>>,
        responses: VecDeque<Datagram>,
        pollable: bool,
        shareable: bool,
        receive_polls: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
        receive_waker: Option<std::task::Waker>,
    }

    #[async_trait]
    impl DatagramTransport for RecordingDatagrams {
        fn supports_shared_destinations(&self) -> bool {
            self.shareable
        }

        fn supports_poll_receive(&self) -> bool {
            self.pollable
        }
        fn poll_receive(
            &mut self,
            context: &mut Context<'_>,
            _scratch: &mut Vec<u8>,
        ) -> Poll<Result<Datagram, DispatchError>> {
            self.receive_polls.fetch_add(1, Ordering::Relaxed);
            self.receive_waker = Some(context.waker().clone());
            match self.responses.pop_front() {
                Some(response) => Poll::Ready(Ok(response)),
                None => Poll::Pending,
            }
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closes.fetch_add(1, Ordering::Relaxed);
            self.receive_waker = None;
            Ok(())
        }
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            self.sent.lock().unwrap().push(datagram.clone());
            self.responses.push_back(datagram);
            if let Some(waker) = &self.receive_waker {
                waker.wake_by_ref();
            }
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if let Some(response) = self.responses.pop_front() {
                return Ok(response);
            }
            std::future::pending().await
        }
    }

    struct MockDns {
        addresses: Vec<IpAddr>,
        hint: Option<(IpAddr, String)>,
        resolved_hosts: Mutex<Vec<String>>,
        resolve_calls: AtomicUsize,
        exchange_calls: AtomicUsize,
        hint_calls: AtomicUsize,
    }

    #[derive(Default)]
    struct UpdatingDns {
        addresses: Mutex<Vec<IpAddr>>,
        hint: Mutex<Option<String>>,
    }

    #[async_trait]
    impl RoutingDns for UpdatingDns {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            Ok(self.addresses.lock().unwrap().clone())
        }

        async fn exchange(&self, _query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            Err(DispatchError::HostUnreachable)
        }

        async fn domain_hint(&self, _address: IpAddr) -> Option<String> {
            self.hint.lock().unwrap().clone()
        }
    }

    impl MockDns {
        fn new(addresses: Vec<IpAddr>) -> Self {
            Self {
                addresses,
                hint: None,
                resolved_hosts: Mutex::new(Vec::new()),
                resolve_calls: AtomicUsize::new(0),
                exchange_calls: AtomicUsize::new(0),
                hint_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl RoutingDns for MockDns {
        async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            self.resolve_calls.fetch_add(1, Ordering::Relaxed);
            self.resolved_hosts.lock().unwrap().push(host.to_owned());
            Ok(self.addresses.clone())
        }

        async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            self.exchange_calls.fetch_add(1, Ordering::Relaxed);
            Ok(DnsWireResponse::test_untracked(query.to_vec()))
        }

        async fn domain_hint(&self, address: IpAddr) -> Option<String> {
            self.hint_calls.fetch_add(1, Ordering::Relaxed);
            self.hint
                .as_ref()
                .filter(|(expected, _)| *expected == address)
                .map(|(_, domain)| domain.clone())
        }
    }

    struct BlockingDns {
        exchange_started: Notify,
        exchange_cancelled: Arc<AtomicBool>,
    }

    struct ExchangeGuard(Arc<AtomicBool>);

    impl Drop for ExchangeGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[async_trait]
    impl RoutingDns for BlockingDns {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            Ok(Vec::new())
        }

        async fn exchange(&self, _query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            let _guard = ExchangeGuard(self.exchange_cancelled.clone());
            self.exchange_started.notify_one();
            std::future::pending().await
        }

        async fn domain_hint(&self, _address: IpAddr) -> Option<String> {
            None
        }
    }

    #[derive(Default)]
    struct WireDns {
        query_types: Mutex<Vec<u16>>,
    }

    #[async_trait]
    impl RoutingDns for WireDns {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, DispatchError> {
            Ok(Vec::new())
        }

        async fn exchange(&self, query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
            let classified = crate::dns::classify_query(query)
                .map_err(|error| DispatchError::Other(error.to_string()))?;
            self.query_types
                .lock()
                .unwrap()
                .push(classified.question.query_type);
            crate::dns::synthesize_empty_response(&classified, 0)
                .map(DnsWireResponse::test_untracked)
                .map_err(|error| DispatchError::Other(error.to_string()))
        }

        async fn domain_hint(&self, _address: IpAddr) -> Option<String> {
            None
        }
    }

    fn rule(kind: RuleKind, action: RuleAction) -> RuleSpec {
        RuleSpec {
            kind,
            action,
            no_resolve: false,
        }
    }

    fn proxy_action(index: usize) -> RuleAction {
        RuleAction::Route(RouteTargetId::Proxy(ProxyId::new(index).unwrap()))
    }

    fn group_action(index: usize) -> RuleAction {
        RuleAction::Route(RouteTargetId::Group(ProxyGroupId::new(index).unwrap()))
    }

    fn select_group(
        name: &str,
        members: Vec<(&str, ProxyGroupMemberTarget)>,
    ) -> SelectProxyGroupConfig {
        SelectProxyGroupConfig {
            kind: crate::config::GroupKind::Select,
            strategy: crate::config::BalanceStrategy::default(),
            hash_key: crate::config::BalanceHashKey::default(),
            health: crate::config::HealthCheckConfig::default(),
            tolerance: 0,
            max_failed_times: 5,
            disable_udp: false,
            hidden: false,
            icon: String::new(),
            name: name.to_owned(),
            members: members
                .into_iter()
                .map(|(name, target)| ProxyGroupMemberConfig {
                    name: name.to_owned(),
                    target,
                })
                .collect(),
            initial_member: 0,
        }
    }

    fn dispatcher(
        proxy: Arc<RecordingDispatcher>,
        direct: Arc<RecordingDispatcher>,
        dns: Option<Arc<dyn RoutingDns>>,
        rules: Vec<RuleSpec>,
    ) -> RoutingDispatcher {
        dispatcher_with_ipv6(proxy, direct, dns, true, rules)
    }

    fn dispatcher_with_ipv6(
        proxy: Arc<RecordingDispatcher>,
        direct: Arc<RecordingDispatcher>,
        dns: Option<Arc<dyn RoutingDns>>,
        ipv6: bool,
        rules: Vec<RuleSpec>,
    ) -> RoutingDispatcher {
        RoutingDispatcher::with_dns_service(
            proxy,
            direct,
            dns,
            ipv6,
            RuleSet::compile(rules).unwrap(),
            Arc::new(DynamicGeoData::empty()),
        )
    }

    fn dispatcher_with_proxies(
        proxies: Vec<Arc<RecordingDispatcher>>,
        direct: Arc<RecordingDispatcher>,
        rules: Vec<RuleSpec>,
    ) -> RoutingDispatcher {
        let proxies = ProxyDispatchers::new(
            proxies
                .into_iter()
                .map(|proxy| proxy as Arc<dyn Dispatcher>)
                .collect(),
        )
        .unwrap();
        RoutingDispatcher::new(
            proxies,
            direct,
            None,
            RuleSet::compile(rules).unwrap(),
            Arc::new(EmptyGeoMatcher),
        )
    }

    #[derive(Default)]
    struct ManagedWakeCount(AtomicUsize);
    impl futures_util::task::ArcWake for ManagedWakeCount {
        fn wake_by_ref(owner: &Arc<Self>) {
            owner.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn managed_wake_fixture() -> (
        RoutedDatagramTransport,
        Arc<RecordingDispatcher>,
        Arc<crate::connections::Registry>,
    ) {
        let config =
            crate::config::Config::parse_yaml(b"mixed-port: 1080\nrules: [\"MATCH,DIRECT\"]\n")
                .unwrap();
        let direct = Arc::new(RecordingDispatcher {
            pollable: true,
            ..Default::default()
        });
        let rules = RuleSet::compile(config.rules.clone()).unwrap();
        let registry = Arc::new(crate::connections::Registry::default());
        let diagnostics = Arc::new(crate::routing::diagnostics::Diagnostics::new(
            &config,
            &rules,
            registry.clone(),
        ));
        let router = RoutingDispatcher::new(
            ProxyDispatchers::new(Vec::new()).unwrap(),
            direct.clone(),
            None,
            rules,
            Arc::new(EmptyGeoMatcher),
        )
        .with_diagnostics(diagnostics);
        (
            router.routed_datagrams(association(InboundKind::Socks5)),
            direct,
            registry,
        )
    }

    fn poll_managed_test(
        transport: &mut RoutedDatagramTransport,
        cx: &mut Context<'_>,
    ) -> Poll<(Destination, Option<Result<Datagram, DispatchError>>)> {
        RoutedDatagramTransport::poll_managed(
            &mut transport.managed_flows.polled,
            transport.managed_ready.as_ref().unwrap(),
            &mut transport.managed_receive_buffer,
            transport.router.tun_config.udp_timeout,
            cx,
        )
    }

    #[tokio::test]
    async fn managed_udp_ready_delivery_requeues_without_notifying_its_running_parent() {
        let (mut transport, direct, registry) = managed_wake_fixture();
        let endpoint = "198.51.100.1:443".parse().unwrap();
        transport.send(datagram(endpoint, b"first")).await.unwrap();
        transport.send(datagram(endpoint, b"second")).await.unwrap();
        let counter = Arc::new(ManagedWakeCount::default());
        let parent = futures_util::task::waker(counter.clone());
        let mut cx = Context::from_waker(&parent);
        let first = poll_managed_test(&mut transport, &mut cx);
        let second = poll_managed_test(&mut transport, &mut cx);
        let notified = counter.0.load(Ordering::Relaxed);
        let still_queued = !transport.managed_ready.as_ref().unwrap().is_empty();
        transport.close().await.unwrap();
        assert!(
            matches!(first, Poll::Ready((Destination::Ip(remote), Some(Ok(ref value)))) if remote == endpoint && value.payload == Bytes::from_static(b"first"))
        );
        assert!(
            matches!(second, Poll::Ready((Destination::Ip(remote), Some(Ok(ref value)))) if remote == endpoint && value.payload == Bytes::from_static(b"second"))
        );
        assert_eq!(
            notified, 0,
            "local FIFO requeue scheduled its running parent"
        );
        assert!(still_queued, "ready flow lost its next receive opportunity");
        assert!(transport.managed_ready.as_ref().unwrap().is_empty());
        assert_eq!(transport.managed_flows.iter().count(), 0);
        assert_eq!(direct.udp_closes.load(Ordering::Relaxed), 1);
        assert!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn managed_udp_pending_receive_and_controller_cancel_keep_external_wakes() {
        let (mut transport, direct, registry) = managed_wake_fixture();
        let endpoint = "198.51.100.1:443".parse().unwrap();
        transport.send(datagram(endpoint, b"first")).await.unwrap();
        let counter = Arc::new(ManagedWakeCount::default());
        let parent = futures_util::task::waker(counter.clone());
        let mut cx = Context::from_waker(&parent);
        let first = poll_managed_test(&mut transport, &mut cx);
        let idle = poll_managed_test(&mut transport, &mut cx);
        counter.0.store(0, Ordering::Relaxed);
        transport
            .send(datagram(endpoint, b"external"))
            .await
            .unwrap();
        let ready_wakes = counter.0.load(Ordering::Relaxed);
        let delivered = poll_managed_test(&mut transport, &mut cx);
        let cancel_pending = poll_managed_test(&mut transport, &mut cx);
        let snapshot = serde_json::to_value(registry.snapshot()).unwrap();
        let id = snapshot["connections"][0]["id"].as_str().unwrap();
        counter.0.store(0, Ordering::Relaxed);
        registry.close(id);
        let cancel_wakes = counter.0.load(Ordering::Relaxed);
        let cancelled = poll_managed_test(&mut transport, &mut cx);
        transport.close().await.unwrap();
        assert!(matches!(first, Poll::Ready((_, Some(Ok(_))))));
        assert!(idle.is_pending());
        assert!(
            ready_wakes > 0,
            "actual Pending lost the external receive wake"
        );
        assert!(
            matches!(delivered, Poll::Ready((Destination::Ip(remote), Some(Ok(ref value)))) if remote == endpoint && value.payload == Bytes::from_static(b"external"))
        );
        assert!(cancel_pending.is_pending());
        assert!(
            cancel_wakes > 0,
            "Controller close did not wake Pending receive"
        );
        assert!(
            matches!(cancelled, Poll::Ready((Destination::Ip(remote), None)) if remote == endpoint)
        );
        assert!(transport.managed_ready.as_ref().unwrap().is_empty());
        assert_eq!(transport.managed_flows.iter().count(), 0);
        assert_eq!(direct.udp_closes.load(Ordering::Relaxed), 1);
        assert!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn managed_udp_connections_close_one_flow_and_preserve_others() {
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
proxies:
  - {name: edge, type: socks5, server: 192.0.2.1, port: 1080, udp: true}
  - {name: other, type: socks5, server: 192.0.2.2, port: 1080, udp: true}
proxy-groups: [{name: pool, type: select, proxies: [edge, other]}]
rules: ["MATCH,pool"]
"#,
        )
        .unwrap();
        let proxy = Arc::new(RecordingDispatcher {
            shareable: true,
            ..Default::default()
        });
        let other = Arc::new(RecordingDispatcher {
            shareable: true,
            ..Default::default()
        });
        let direct = Arc::new(RecordingDispatcher::default());
        let nodes = vec![proxy.clone() as Arc<dyn Dispatcher>, other.clone()];
        let groups = ProxyGroups::new(&config.proxy_groups, nodes.clone(), direct.clone()).unwrap();
        let rules = RuleSet::compile(config.rules.clone()).unwrap();
        let registry = Arc::new(crate::connections::Registry::default());
        let diagnostics = Arc::new(crate::routing::diagnostics::Diagnostics::new(
            &config,
            &rules,
            registry.clone(),
        ));
        let router = RoutingDispatcher::new(
            ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
            direct,
            None,
            rules,
            Arc::new(EmptyGeoMatcher),
        )
        .with_diagnostics(diagnostics);
        let mut transport = router
            .open_datagram(association(InboundKind::Socks5))
            .await
            .unwrap();
        let first = "198.51.100.1:443".parse().unwrap();
        let second = "198.51.100.2:443".parse().unwrap();
        transport
            .send(datagram(first, b"stale-original"))
            .await
            .unwrap();
        transport.send(datagram(second, b"two")).await.unwrap();
        assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
        let snapshot = serde_json::to_value(registry.snapshot()).unwrap();
        let entries = snapshot["connections"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let entry = entries
            .iter()
            .find(|e| e["metadata"]["destinationIP"] == "198.51.100.1")
            .unwrap();
        assert_eq!(entry["chains"], serde_json::json!(["edge", "pool"]));
        assert_eq!(entry["rule"], "Match");
        registry.close(entry["id"].as_str().unwrap());
        groups.select("pool", "other").unwrap();
        // Recreate before reading: the old wire still has a reply for the same
        // tuple, which must not be delivered or counted on the new connection.
        transport.send(datagram(first, b"new")).await.unwrap();
        let mut replies = HashMap::new();
        for _ in 0..2 {
            let reply = transport.receive().await.unwrap();
            replies.insert(reply.remote, reply.payload);
        }
        assert_eq!(
            replies.get(&Destination::Ip(first)).unwrap().as_ref(),
            b"new"
        );
        assert_eq!(
            replies.get(&Destination::Ip(second)).unwrap().as_ref(),
            b"two"
        );
        assert_eq!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let third = "198.51.100.3:443".parse().unwrap();
        transport.send(datagram(third, b"third")).await.unwrap();
        transport.send(datagram(second, b"pinned")).await.unwrap();
        assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(other.udp_opens.load(Ordering::Relaxed), 1);
        groups.select("pool", "edge").unwrap();
        transport
            .send(datagram("198.51.100.4:443".parse().unwrap(), b"fourth"))
            .await
            .unwrap();
        assert_eq!(
            proxy.udp_opens.load(Ordering::Relaxed),
            2,
            "retired wires must reject new destinations"
        );
        let snapshot = serde_json::to_value(registry.snapshot()).unwrap();
        let first_entry = snapshot["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["metadata"]["destinationIP"] == "198.51.100.1")
            .unwrap();
        assert_eq!(first_entry["download"], 3);
        assert_eq!(first_entry["chains"], serde_json::json!(["other", "pool"]));
        groups.select("pool", "other").unwrap();
        for host in ["first.example", "second.example"] {
            transport
                .send(Datagram {
                    remote: Destination::domain(host, 53).unwrap(),
                    payload: Bytes::from_static(b"domain"),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
        }
        assert_eq!(
            other.udp_opens.load(Ordering::Relaxed),
            3,
            "domain aliases must not share a wire"
        );
        transport.close().await.unwrap();
        assert_eq!(proxy.udp_closes.load(Ordering::Relaxed), 2);
        assert_eq!(other.udp_closes.load(Ordering::Relaxed), 3);
        assert!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(feature = "outbound-trojan")]
    #[tokio::test]
    async fn managed_trojan_udp_shares_ip_destinations_and_retires_closed_members() {
        use crate::{dispatch::DatagramBudget, outbound::trojan::TrojanDatagram};

        #[derive(Default)]
        struct MemoryTrojan {
            wires: Mutex<Vec<(SocketAddr, tokio::io::DuplexStream)>>,
        }
        #[async_trait]
        impl Dispatcher for MemoryTrojan {
            async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
                Err(DispatchError::NotAllowed)
            }
            async fn open_datagram(
                &self,
                session: DatagramSession,
            ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
                let (client, peer) = tokio::io::duplex(4096);
                self.wires.lock().unwrap().push((session.source, peer));
                Ok(Box::new(TrojanDatagram::new(
                    Box::new(client),
                    DatagramBudget::new(8192, 8192),
                )))
            }
        }
        fn frame(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
            let IpAddr::V4(ip) = target.ip() else {
                panic!("fixture uses IPv4 targets");
            };
            let mut wire = vec![1];
            wire.extend_from_slice(&ip.octets());
            wire.extend_from_slice(&target.port().to_be_bytes());
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(b"\r\n");
            wire.extend_from_slice(payload);
            wire
        }
        async fn expect_wire(peer: &mut tokio::io::DuplexStream, expected: &[u8]) {
            let mut sent = vec![0; expected.len()];
            peer.read_exact(&mut sent).await.unwrap();
            assert_eq!(sent, expected);
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            let config = crate::config::Config::parse_yaml(
                br#"
proxies:
  - {name: edge, type: trojan, server: 192.0.2.1, port: 443, password: fixture, udp: true}
rules: ["MATCH,edge"]
"#,
            )
            .unwrap();
            let proxy = Arc::new(MemoryTrojan::default());
            let rules = RuleSet::compile(config.rules.clone()).unwrap();
            let registry = Arc::new(crate::connections::Registry::default());
            let diagnostics = Arc::new(crate::routing::diagnostics::Diagnostics::new(
                &config,
                &rules,
                registry.clone(),
            ));
            let router = RoutingDispatcher::new(
                ProxyDispatchers::new(vec![proxy.clone()]).unwrap(),
                Arc::new(RecordingDispatcher::default()),
                None,
                rules,
                Arc::new(EmptyGeoMatcher),
            )
            .with_diagnostics(diagnostics);
            let session = association(InboundKind::Tun);
            let mut first = router.open_datagram(session.clone()).await.unwrap();
            let mut second = router
                .open_datagram(DatagramSession::new(
                    InboundKind::Tun,
                    "127.0.0.1:10001".parse().unwrap(),
                ))
                .await
                .unwrap();
            let a = "198.51.100.1:443".parse().unwrap();
            let b = "198.51.100.2:443".parse().unwrap();
            let c = "198.51.100.1:8443".parse().unwrap();
            for (target, payload) in [(a, &b"one"[..]), (b, b"two"), (c, b"three")] {
                first.send(datagram(target, payload)).await.unwrap();
            }
            assert_eq!(
                proxy.wires.lock().unwrap().len(),
                1,
                "same-source IP targets must share the real Trojan association"
            );
            second.send(datagram(a, b"other")).await.unwrap();
            let mut peers = std::mem::take(&mut *proxy.wires.lock().unwrap());
            assert_eq!(peers.len(), 2, "different sources need independent wires");
            let (second_source, mut second_peer) = peers.pop().unwrap();
            let (first_source, mut old_peer) = peers.pop().unwrap();
            assert_eq!(first_source, session.source);
            assert_eq!(second_source.port(), 10001);
            expect_wire(
                &mut old_peer,
                &[frame(a, b"one"), frame(b, b"two"), frame(c, b"three")].concat(),
            )
            .await;
            expect_wire(&mut second_peer, &frame(a, b"other")).await;

            let snapshot = serde_json::to_value(registry.snapshot()).unwrap();
            assert_eq!(snapshot["connections"].as_array().unwrap().len(), 4);
            let closed = snapshot["connections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| {
                    entry["metadata"]["sourcePort"] == "10000"
                        && entry["metadata"]["destinationIP"] == "198.51.100.1"
                        && entry["metadata"]["destinationPort"] == "443"
                })
                .unwrap();
            registry.close(closed["id"].as_str().unwrap());
            first.send(datagram(a, b"new")).await.unwrap();
            let mut peers = std::mem::take(&mut *proxy.wires.lock().unwrap());
            assert_eq!(
                peers.len(),
                1,
                "closed members must retire their shared wire"
            );
            let (_, mut new_peer) = peers.pop().unwrap();
            expect_wire(&mut new_peer, &frame(a, b"new")).await;
            old_peer
                .write_all(&[frame(a, b"stale"), frame(b, b"sibling"), frame(c, b"port")].concat())
                .await
                .unwrap();
            new_peer.write_all(&frame(a, b"fresh")).await.unwrap();
            second_peer.write_all(&frame(a, b"separate")).await.unwrap();
            let mut replies = HashMap::new();
            for _ in 0..3 {
                let reply = first.receive().await.unwrap();
                assert!(replies.insert(reply.remote, reply.payload).is_none());
            }
            for (target, expected) in [(a, &b"fresh"[..]), (b, b"sibling"), (c, b"port")] {
                assert_eq!(replies[&Destination::Ip(target)].as_ref(), expected);
            }
            let reply = second.receive().await.unwrap();
            assert_eq!(reply.remote, Destination::Ip(a));
            assert_eq!(reply.payload.as_ref(), b"separate");
            first.close().await.unwrap();
            second.close().await.unwrap();
            assert!(
                serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            for peer in [&mut old_peer, &mut new_peer, &mut second_peer] {
                let mut remainder = Vec::new();
                peer.read_to_end(&mut remainder).await.unwrap();
                assert!(
                    remainder.is_empty(),
                    "close must release both wire directions"
                );
            }
        })
        .await
        .expect("memory-only routing must complete without peer or shutdown waits");
    }

    #[tokio::test(start_paused = true)]
    async fn managed_udp_connections_poll_only_ready_targets_and_close_pending_flow() {
        let config =
            crate::config::Config::parse_yaml(b"mixed-port: 1080\nrules: [\"MATCH,DIRECT\"]\n")
                .unwrap();
        let direct = Arc::new(RecordingDispatcher {
            pollable: true,
            ..Default::default()
        });
        let rules = RuleSet::compile(config.rules.clone()).unwrap();
        let registry = Arc::new(crate::connections::Registry::default());
        let diagnostics = Arc::new(crate::routing::diagnostics::Diagnostics::new(
            &config,
            &rules,
            registry.clone(),
        ));
        let router = RoutingDispatcher::new(
            ProxyDispatchers::new(Vec::new()).unwrap(),
            direct.clone(),
            None,
            rules,
            Arc::new(EmptyGeoMatcher),
        )
        .with_diagnostics(diagnostics);
        let mut transport = router.routed_datagrams(association(InboundKind::Socks5));
        let addresses = (0..256)
            .map(|port| SocketAddr::new("198.51.100.1".parse().unwrap(), 10000 + port))
            .collect::<Vec<_>>();
        for address in &addresses {
            transport.send(datagram(*address, b"first")).await.unwrap();
        }
        for _ in &addresses {
            transport.receive().await.unwrap();
        }
        // Register all idle readers without retaining futures across calls.
        while !transport.managed_ready.as_ref().unwrap().is_empty() {
            assert!(futures_util::poll!(transport.receive()).is_pending());
        }
        direct.receive_polls.store(0, Ordering::Relaxed);
        let deadline = transport.managed_next_cleanup;
        transport
            .send(datagram(addresses[0], b"ready"))
            .await
            .unwrap();
        assert_eq!(
            transport.receive().await.unwrap().remote,
            Destination::Ip(addresses[0])
        );
        assert_eq!(direct.receive_polls.load(Ordering::Relaxed), 1);
        assert_eq!(transport.managed_next_cleanup, deadline);
        let snapshot = serde_json::to_value(registry.snapshot()).unwrap();
        let entry = snapshot["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["metadata"]["destinationPort"] == addresses[1].port().to_string())
            .unwrap();
        registry.close(entry["id"].as_str().unwrap());
        // Cancellation wakes an idle reader immediately; no timer advance is needed.
        assert!(futures_util::poll!(transport.receive()).is_pending());
        assert!(
            transport
                .managed_flows
                .get(&Destination::Ip(addresses[1]))
                .is_none()
        );
        assert_eq!(direct.udp_closes.load(Ordering::Relaxed), 1);
        assert_eq!(Instant::now() + UDP_FLOW_CLEANUP_INTERVAL, deadline);
        transport.close().await.unwrap();
        assert_eq!(direct.udp_closes.load(Ordering::Relaxed), 256);
        assert!(transport.managed_ready.as_ref().unwrap().is_empty());
        assert!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn rematch_group_selection_routes_tcp_udp_without_control_io_or_old_flow_migration() {
        let mut config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
proxies: [{name: mark, type: rematch, target-rematch-name: phase}]
proxy-groups:
  - {name: gate, type: select, proxies: [mark,DIRECT]}
  - {name: outer, type: select, proxies: [gate], disable-udp: true}
rules: ['REMATCH-NAME,phase,REJECT', 'MATCH,outer', 'MATCH,DIRECT']
"#,
        )
        .unwrap();
        // If a rematch is mistaken for an egress, this mock would succeed and
        // expose the wrong physical path through its counters.
        let control = Arc::new(RecordingDispatcher {
            tcp_only: true,
            ..Default::default()
        });
        let direct = Arc::new(RecordingDispatcher::default());
        let nodes: Vec<Arc<dyn Dispatcher>> = vec![control.clone()];
        let selections = config
            .proxy_groups
            .iter()
            .map(|group| Arc::new(super::super::GroupSelection::new(group.initial_member)))
            .collect::<Vec<_>>();
        let groups = ProxyGroups::with_selections_and_drop(
            &config.proxy_groups,
            nodes.clone(),
            direct.clone(),
            &selections,
            direct.clone(),
            super::super::RematchTargets::new(&config.proxies),
        )
        .unwrap();
        let router = RoutingDispatcher::new(
            ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
            direct.clone(),
            None,
            RuleSet::compile_config(&mut config).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let first = "198.51.100.1:443".parse().unwrap();
        for network in [Network::Tcp, Network::Udp] {
            let decision = router
                .route(
                    network,
                    (InboundKind::Tun, &Default::default()),
                    "192.0.2.2:10000".parse().unwrap(),
                    &Destination::Ip(first),
                    None,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(decision.action, RuleAction::Reject);
        }
        assert!(matches!(
            router.connect_tcp(stream(first, InboundKind::Tun)).await,
            Err(DispatchError::NotAllowed)
        ));
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        udp.send(datagram(first, b"rejected")).await.unwrap();
        assert!(direct.datagrams.lock().unwrap().is_empty());

        groups.select("gate", "DIRECT").unwrap();
        router
            .connect_tcp(stream(first, InboundKind::Tun))
            .await
            .unwrap();
        let second = "198.51.100.2:443".parse().unwrap();
        udp.send(datagram(second, b"direct")).await.unwrap();
        groups.select("gate", "mark").unwrap();
        udp.send(datagram(second, b"established")).await.unwrap();
        udp.send(datagram(
            "198.51.100.3:443".parse().unwrap(),
            b"new-rejected",
        ))
        .await
        .unwrap();
        udp.close().await.unwrap();
        assert_eq!(direct.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(direct.datagrams.lock().unwrap().len(), 2);
        assert!(control.tcp_sessions.lock().unwrap().is_empty());
        assert_eq!(control.udp_opens.load(Ordering::Relaxed), 0);
        assert!(matches!(
            groups.resolve_leaf_for(
                crate::config::ProxyGroupId::new(0).unwrap(),
                false,
                None,
                None,
                None
            ),
            Err(DispatchError::NotAllowed)
        ));
    }

    #[tokio::test]
    async fn udp_rules_skip_incapable_targets_without_changing_explicit_modes() {
        for target in ["edge", "outer", "disabled"] {
            for mode in ["rule", "global"] {
                let mut config = crate::config::Config::parse_yaml(
                    format!(
                        r#"
mixed-port: 1080
mode: {mode}
proxies: [{{name: edge, type: socks5, server: 192.0.2.1, port: 1080}}]
proxy-groups:
  - {{name: inner, type: select, proxies: [edge]}}
  - {{name: outer, type: select, proxies: [inner]}}
  - {{name: disabled, type: select, proxies: [DIRECT], disable-udp: true}}
  - {{name: GLOBAL, type: select, proxies: [{target}]}}
rules: ["DST-PORT,443,{target}", "MATCH,DIRECT"]
"#
                    )
                    .as_bytes(),
                )
                .unwrap();
                let nodes: Vec<Arc<dyn Dispatcher>> =
                    vec![crate::dispatch::observe_handshakes_with_stats(
                        Arc::new(RecordingDispatcher {
                            tcp_only: true,
                            ..Default::default()
                        }),
                        crate::resources::RuntimeResourceStats::new("udp-capability"),
                    )];
                let direct = Arc::new(RecordingDispatcher::default());
                let groups =
                    ProxyGroups::new(&config.proxy_groups, nodes.clone(), direct.clone()).unwrap();
                let router = RoutingDispatcher::new(
                    ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
                    direct,
                    None,
                    RuleSet::compile_config(&mut config).unwrap(),
                    Arc::new(EmptyGeoMatcher),
                );
                for network in [Network::Tcp, Network::Udp] {
                    let decision = router
                        .route(
                            network,
                            (InboundKind::Socks5, &Default::default()),
                            "192.0.2.2:1234".parse().unwrap(),
                            &Destination::Ip("203.0.113.1:443".parse().unwrap()),
                            None,
                            None,
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        decision.action == RuleAction::Direct,
                        mode == "rule" && network == Network::Udp
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn routed_group_failures_notify_each_selected_group() {
        struct Failed;
        #[async_trait]
        impl Dispatcher for Failed {
            async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
                Err(DispatchError::HostUnreachable)
            }
            async fn open_datagram(
                &self,
                _: DatagramSession,
            ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
                Err(DispatchError::NetworkUnreachable)
            }
        }
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
proxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080}]
proxy-groups:
  - {name: inner, type: fallback, proxies: [edge], max-failed-times: 2}
  - {name: outer, type: fallback, proxies: [inner], max-failed-times: 2}
rules: ["MATCH,outer"]
"#,
        )
        .unwrap();
        let nodes: Vec<Arc<dyn Dispatcher>> = vec![Arc::new(Failed)];
        let direct = Arc::new(RecordingDispatcher::default());
        let groups = ProxyGroups::new(&config.proxy_groups, nodes.clone(), direct.clone()).unwrap();
        let router = RoutingDispatcher::new(
            ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
            direct,
            None,
            RuleSet::compile(config.rules).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        for attempt in 0..2 {
            let result = router
                .connect_tcp(StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::Socks5,
                    source: "192.0.2.2:5555".parse().unwrap(),
                    destination: Destination::Ip("198.51.100.1:443".parse().unwrap()),
                    sniffed_domain: None,
                })
                .await;
            assert!(matches!(result, Err(DispatchError::HostUnreachable)));
            for index in 0..2 {
                assert_eq!(groups.selection(index).take_urgent(), attempt == 1);
            }
        }
    }

    #[tokio::test]
    async fn load_balance_routes_tcp_and_pins_udp_flows() {
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
proxies:
  - {name: a, type: socks5, server: 192.0.2.10, port: 1080}
  - {name: b, type: socks5, server: 192.0.2.11, port: 1080}
proxy-groups:
  - {name: balance, type: load-balance, proxies: [a,b], strategy: round-robin}
rules: ["MATCH,balance"]
"#,
        )
        .unwrap();
        let a = Arc::new(RecordingDispatcher::default());
        let b = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let nodes: Vec<Arc<dyn Dispatcher>> = vec![a.clone(), b.clone()];
        let groups = ProxyGroups::new(&config.proxy_groups, nodes.clone(), direct.clone()).unwrap();
        let router = RoutingDispatcher::new(
            ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
            direct,
            None,
            RuleSet::compile(vec![rule(RuleKind::Match, group_action(0))]).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let source = "192.0.2.1:5555".parse().unwrap();
        let dest = Destination::Ip("198.51.100.1:443".parse().unwrap());
        for _ in 0..2 {
            router
                .connect_tcp(StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::Socks5,
                    source,
                    destination: dest.clone(),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
        }
        assert_eq!(a.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(b.tcp_sessions.lock().unwrap().len(), 1);
        let mut transport = router
            .open_datagram(DatagramSession::new(InboundKind::Socks5, source))
            .await
            .unwrap();
        let first = Datagram {
            remote: dest,
            payload: Bytes::from_static(b"x"),
            sniffed_domain: None,
        };
        transport.send(first.clone()).await.unwrap();
        groups.apply_health(0, &[None, Some(50)]);
        transport.send(first).await.unwrap();
        transport
            .send(Datagram {
                remote: Destination::Ip("198.51.100.2:443".parse().unwrap()),
                payload: Bytes::from_static(b"y"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(a.datagrams.lock().unwrap().len(), 2);
        assert_eq!(b.datagrams.lock().unwrap().len(), 1);
        assert_eq!(a.udp_opens.load(Ordering::Relaxed), 1);
        assert!(groups.select("balance", "a").is_err());
        transport.close().await.unwrap();
    }

    #[tokio::test]
    async fn ingress_rules_and_user_hash_reach_tcp_udp_with_one_leaf() {
        let mut config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
proxies:
  - {name: a, type: socks5, server: 192.0.2.10, port: 1080, udp: true}
  - {name: b, type: socks5, server: 192.0.2.11, port: 1080, udp: true}
proxy-groups:
  - {name: balance, type: load-balance, proxies: [a,b], hash-key: in-user}
rules:
  - 'AND,((IN-TYPE,HTTPS/SOCKS5),(IN-USER,Alice),(IN-PORT,1080),(SRC-IP-CIDR,192.0.2.0/24)),balance'
  - 'MATCH,REJECT'
"#,
        )
        .unwrap();
        let a = Arc::new(RecordingDispatcher::default());
        let b = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let nodes: Vec<Arc<dyn Dispatcher>> = vec![a.clone(), b.clone()];
        let groups = ProxyGroups::new(&config.proxy_groups, nodes.clone(), direct.clone()).unwrap();
        let router = RoutingDispatcher::new(
            ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
            direct,
            None,
            RuleSet::compile(config.take_runtime_rules()).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let metadata = crate::session::InboundMetadata {
            local_port: 1080,
            user: Some(Arc::from("Alice")),
            ..Default::default()
        };
        for (source, remote) in [
            ("192.0.2.1:5555", "198.51.100.1:443"),
            ("192.0.2.2:6666", "203.0.113.2:80"),
        ] {
            router
                .connect_tcp(StreamSession {
                    metadata: metadata.clone(),
                    inbound: InboundKind::Https,
                    source: source.parse().unwrap(),
                    destination: Destination::Ip(remote.parse().unwrap()),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
        }
        let counts = [
            a.tcp_sessions.lock().unwrap().len(),
            b.tcp_sessions.lock().unwrap().len(),
        ];
        assert!(counts == [2, 0] || counts == [0, 2]);
        let selected = usize::from(counts[0] == 0);
        let nodes = [a, b];
        let mut udp = router
            .open_datagram(
                DatagramSession::new(InboundKind::Socks5, "192.0.2.3:7777".parse().unwrap())
                    .with_metadata(metadata),
            )
            .await
            .unwrap();
        let datagram = Datagram {
            remote: Destination::Ip("198.51.100.3:53".parse().unwrap()),
            payload: Bytes::from_static(b"x"),
            sniffed_domain: None,
        };
        udp.send(datagram.clone()).await.unwrap();
        groups.apply_health(
            0,
            if selected == 0 {
                &[None, Some(10)]
            } else {
                &[Some(10), None]
            },
        );
        udp.send(datagram).await.unwrap();
        assert_eq!(nodes[selected].datagrams.lock().unwrap().len(), 2);
        assert_eq!(nodes[1 - selected].datagrams.lock().unwrap().len(), 0);
        udp.close().await.unwrap();
    }

    #[tokio::test]
    async fn subrule_routes_resume_dns_and_commit_one_tcp_udp_leaf() {
        let mut config = crate::config::Config::parse_yaml(br#"
mixed-port: 1080
proxies:
  - {name: a, type: socks5, server: 192.0.2.10, port: 1080}
  - {name: b, type: socks5, server: 192.0.2.11, port: 1080}
proxy-groups:
  - {name: gate, type: load-balance, proxies: [PASS-RULE,a], strategy: round-robin, disable-udp: true}
  - {name: pool, type: load-balance, proxies: [a,b], strategy: round-robin}
  - {name: GLOBAL, type: select, proxies: [PASS,pool]}
rules: ['SUB-RULE,(DST-PORT,443),child', 'MATCH,REJECT']
sub-rules:
  child: ['DST-PORT,443,gate', 'IP-CIDR,192.0.2.0/24,pool', 'MATCH,pool']
"#).unwrap();
        let mut global_config = config.clone();
        global_config.mode = crate::config::Mode::Global;
        let a = Arc::new(RecordingDispatcher::default());
        let b = Arc::new(RecordingDispatcher::default());
        let nodes: Vec<Arc<dyn Dispatcher>> = vec![a.clone(), b.clone()];
        let direct = Arc::new(RecordingDispatcher::default());
        let groups = ProxyGroups::new(&config.proxy_groups, nodes.clone(), direct.clone()).unwrap();
        let dns = Arc::new(MockDns::new(vec!["192.0.2.7".parse().unwrap()]));
        let mut router = RoutingDispatcher::new(
            ProxyDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
            direct,
            None,
            RuleSet::compile_config(&mut config).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        router.dns = Some(dns.clone());
        let source = "192.0.2.1:5555".parse().unwrap();
        for _ in 0..2 {
            router
                .connect_tcp(StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::Socks5,
                    source,
                    destination: Destination::domain("example.com", 443).unwrap(),
                    sniffed_domain: None,
                })
                .await
                .unwrap();
        }
        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 2);
        assert_eq!(a.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(b.tcp_sessions.lock().unwrap().len(), 1);
        let mut transport = router
            .open_datagram(DatagramSession::new(InboundKind::Socks5, source))
            .await
            .unwrap();
        let first = datagram("198.51.100.1:443".parse().unwrap(), b"first");
        transport.send(first.clone()).await.unwrap();
        transport.send(first).await.unwrap();
        transport
            .send(datagram("198.51.100.2:443".parse().unwrap(), b"next"))
            .await
            .unwrap();
        assert_eq!(a.datagrams.lock().unwrap().len(), 2);
        assert_eq!(b.datagrams.lock().unwrap().len(), 1);
        assert_eq!(groups.selection(0).choose(None, None), 0);
        transport.close().await.unwrap();
        let global = RoutingDispatcher::new(
            router.route_targets.clone(),
            router.direct.clone(),
            None,
            RuleSet::compile_config(&mut global_config).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        assert!(matches!(
            global
                .connect_tcp(StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::Socks5,
                    source,
                    destination: Destination::Ip("198.51.100.1:443".parse().unwrap()),
                    sniffed_domain: None
                })
                .await,
            Err(DispatchError::NotAllowed)
        ));
    }

    #[test]
    fn proxy_registry_clones_share_ownership_and_release_dependencies() {
        let proxy: Arc<dyn Dispatcher> = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let proxy_id = ProxyId::new(0).unwrap();
        let group_id = RouteTargetId::Group(ProxyGroupId::new(0).unwrap());
        let groups = ProxyGroups::new(
            &[select_group(
                "route",
                vec![(
                    "node",
                    ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(proxy_id)),
                )],
            )],
            vec![proxy.clone()],
            direct,
        )
        .unwrap();
        let registry = ProxyDispatchers::with_proxy_groups(vec![proxy.clone()], &groups).unwrap();
        let weak_proxy = Arc::downgrade(&proxy);
        let weak_groups = Arc::downgrade(&groups);
        let weak_group_dispatcher = Arc::downgrade(registry.get_route(group_id).unwrap());
        let reference_counts = (
            Arc::strong_count(&proxy),
            weak_group_dispatcher.strong_count(),
            Arc::strong_count(&groups),
        );

        let cloned = registry.clone();
        assert_eq!(
            (
                Arc::strong_count(&proxy),
                weak_group_dispatcher.strong_count(),
                Arc::strong_count(&groups),
            ),
            reference_counts,
            "cloning the registry must not clone its node or group ownership arrays"
        );
        assert!(Arc::ptr_eq(
            registry.get(proxy_id).unwrap(),
            cloned.get(proxy_id).unwrap()
        ));
        assert!(Arc::ptr_eq(
            registry.get_route(group_id).unwrap(),
            cloned.get_route(group_id).unwrap()
        ));

        drop(registry);
        drop(groups);
        drop(proxy);
        assert!(weak_proxy.upgrade().is_some());
        assert!(weak_groups.upgrade().is_some());
        assert!(cloned.get(proxy_id).unwrap().supports_udp());
        assert!(cloned.get_route(group_id).unwrap().supports_udp());

        drop(cloned);
        assert!(weak_group_dispatcher.upgrade().is_none());
        assert!(weak_groups.upgrade().is_none());
        assert!(weak_proxy.upgrade().is_none());
    }

    #[test]
    fn proxy_registry_accepts_ids_beyond_u8() {
        let proxies = (0..300)
            .map(|_| Arc::new(RecordingDispatcher::default()) as Arc<dyn Dispatcher>)
            .collect();
        let registry = ProxyDispatchers::new(proxies).unwrap();

        assert_eq!(registry.len(), 300);
        assert!(registry.get(ProxyId::new(299).unwrap()).is_ok());
        assert!(registry.get(ProxyId::new(300).unwrap()).is_err());
    }

    #[tokio::test]
    async fn group_route_snapshots_direct_dns_for_tcp() {
        let direct = Arc::new(RecordingDispatcher::default());
        let groups = ProxyGroups::new(
            &[select_group(
                "route",
                vec![("DIRECT", ProxyGroupMemberTarget::Direct)],
            )],
            Vec::new(),
            direct.clone(),
        )
        .unwrap();
        let targets = RouteTargetDispatchers::with_proxy_groups(Vec::new(), &groups).unwrap();
        let dns = Arc::new(MockDns::new(vec![IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 9,
        ))]));
        let router = RoutingDispatcher {
            route_targets: targets,
            direct: direct.clone(),
            reject_drop: default_reject_drop(),
            dns: Some(dns.clone()),
            ipv6: true,
            rules: Arc::new(
                RuleSet::compile(vec![rule(RuleKind::Match, group_action(0))]).unwrap(),
            ),
            geo_matcher: Arc::new(EmptyGeoMatcher),
            tun_config: TunConfig::default(),
            sniffer: None,
            tcp_concurrent: false,
            diagnostics: None,
            process_dialer: None,
            process_mode: crate::config::FindProcessMode::Strict,
        };

        router
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Http,
                source: "127.0.0.1:10000".parse().unwrap(),
                destination: Destination::domain("example.com", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            direct.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Ip("203.0.113.9:443".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn group_route_keeps_existing_udp_transport_after_selection_changes() {
        let first = Arc::new(RecordingDispatcher::default());
        let second = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let proxy_dispatchers = vec![
            first.clone() as Arc<dyn Dispatcher>,
            second.clone() as Arc<dyn Dispatcher>,
        ];
        let groups = ProxyGroups::new(
            &[select_group(
                "route",
                vec![
                    (
                        "first",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(0).unwrap(),
                        )),
                    ),
                    (
                        "second",
                        ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(1).unwrap(),
                        )),
                    ),
                ],
            )],
            proxy_dispatchers.clone(),
            direct.clone(),
        )
        .unwrap();
        let targets =
            RouteTargetDispatchers::with_proxy_groups(proxy_dispatchers, &groups).unwrap();
        let router = RoutingDispatcher::new(
            targets,
            direct,
            None,
            RuleSet::compile(vec![rule(RuleKind::Match, group_action(0))]).unwrap(),
            Arc::new(DynamicGeoData::empty()),
        );
        let mut old_association = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();

        old_association
            .send(datagram("192.0.2.1:443".parse().unwrap(), b"old"))
            .await
            .unwrap();
        groups.select("route", "second").unwrap();
        old_association
            .send(datagram("192.0.2.1:443".parse().unwrap(), b"still-old"))
            .await
            .unwrap();
        let mut new_association = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();
        new_association
            .send(datagram("192.0.2.1:443".parse().unwrap(), b"new"))
            .await
            .unwrap();

        assert_eq!(first.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(first.datagrams.lock().unwrap().len(), 2);
        assert_eq!(second.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(second.datagrams.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cached_udp_leaf_survives_selection_of_a_tcp_only_member() {
        for kind in ["select", "fallback", "url-test", "load-balance"] {
            for fallback in ["DIRECT", "REJECT"] {
                let mut config = crate::config::Config::parse_yaml(
                    format!(
                        r#"
mixed-port: 1080
proxies:
  - {{name: first, type: socks5, server: 192.0.2.1, port: 1080, udp: true}}
  - {{name: next, type: socks5, server: 192.0.2.2, port: 1080, udp: false}}
proxy-groups:
  - {{name: route, type: {kind}, proxies: [first, next]}}
rules: ["DST-PORT,443,route", "MATCH,{fallback}"]
"#
                    )
                    .as_bytes(),
                )
                .unwrap();
                let first = Arc::new(RecordingDispatcher::default());
                let next = Arc::new(RecordingDispatcher {
                    tcp_only: true,
                    ..Default::default()
                });
                let direct = Arc::new(RecordingDispatcher::default());
                let nodes: Vec<Arc<dyn Dispatcher>> = vec![first.clone(), next.clone()];
                let groups =
                    ProxyGroups::new(&config.proxy_groups, nodes.clone(), direct.clone()).unwrap();
                groups.apply_health(0, &[Some(10), None]);
                let router = RoutingDispatcher::new(
                    RouteTargetDispatchers::with_proxy_groups(nodes, &groups).unwrap(),
                    direct.clone(),
                    None,
                    RuleSet::compile_config(&mut config).unwrap(),
                    Arc::new(EmptyGeoMatcher),
                );
                assert!(router.diagnostics.is_none());
                let remote = "198.51.100.1:443".parse().unwrap();
                let mut established = router
                    .open_datagram(association(InboundKind::Socks5))
                    .await
                    .unwrap();
                established.send(datagram(remote, b"first")).await.unwrap();
                if kind == "select" {
                    groups.select("route", "next").unwrap();
                } else {
                    groups.apply_health(0, &[None, Some(10)]);
                }
                established
                    .send(datagram(remote, b"still-first"))
                    .await
                    .unwrap();
                assert_eq!(first.datagrams.lock().unwrap().len(), 2, "{kind}");
                assert_eq!(direct.udp_opens.load(Ordering::Relaxed), 0, "{kind}");
                for payload in [b"first".as_slice(), b"still-first"] {
                    let reply = established.receive().await.unwrap();
                    assert_eq!(reply.remote, Destination::Ip(remote));
                    assert_eq!(reply.payload.as_ref(), payload);
                }

                // Another source owns a separate association and must evaluate the
                // current group, rather than borrowing this source's cached leaf.
                let mut fresh = router
                    .open_datagram(DatagramSession::new(
                        InboundKind::Socks5,
                        "192.0.2.20:10001".parse().unwrap(),
                    ))
                    .await
                    .unwrap();
                fresh.send(datagram(remote, b"fresh-direct")).await.unwrap();
                let forwarded = usize::from(fallback == "DIRECT");
                assert_eq!(direct.datagrams.lock().unwrap().len(), forwarded, "{kind}");
                assert_eq!(first.udp_opens.load(Ordering::Relaxed), 1, "{kind}");
                assert_eq!(next.udp_opens.load(Ordering::Relaxed), 0, "{kind}");
                fresh.close().await.unwrap();
                established.close().await.unwrap();
                assert_eq!(first.udp_closes.load(Ordering::Relaxed), 1, "{kind}");
                assert_eq!(
                    direct.udp_closes.load(Ordering::Relaxed),
                    forwarded,
                    "{kind}"
                );
            }
        }
    }

    fn stream(destination: SocketAddr, inbound: InboundKind) -> StreamSession {
        StreamSession {
            metadata: Default::default(),
            inbound,
            source: "127.0.0.1:10000".parse().unwrap(),
            destination: Destination::Ip(destination),
            sniffed_domain: None,
        }
    }

    fn association(inbound: InboundKind) -> DatagramSession {
        DatagramSession::new(inbound, "127.0.0.1:10000".parse().unwrap())
    }

    fn datagram(destination: SocketAddr, payload: &'static [u8]) -> Datagram {
        Datagram {
            remote: Destination::Ip(destination),
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }

    fn wire_query(id: u16, query_type: u16) -> Vec<u8> {
        let mut query = crate::dns::build_query(id, "example.com", crate::dns::QueryType::A)
            .expect("test query is valid");
        let query_type_offset = query.len() - 4;
        query[query_type_offset..query_type_offset + 2].copy_from_slice(&query_type.to_be_bytes());
        query
    }

    #[tokio::test]
    async fn builtin_final_actions_route_tcp_and_udp_without_proxies() {
        let destination = "192.0.2.1:443".parse().unwrap();
        for action in [RuleAction::Direct, RuleAction::Reject] {
            let direct = Arc::new(RecordingDispatcher::default());
            let router = dispatcher_with_proxies(
                Vec::new(),
                direct.clone(),
                vec![rule(RuleKind::Match, action)],
            );
            let result = router
                .connect_tcp(stream(destination, InboundKind::Http))
                .await;
            if action == RuleAction::Direct {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(DispatchError::NotAllowed)));
            }
            let mut transport = router
                .open_datagram(association(InboundKind::Socks5))
                .await
                .unwrap();
            transport
                .send(datagram(destination, b"payload"))
                .await
                .unwrap();
            let expected = usize::from(action == RuleAction::Direct);
            assert_eq!(direct.tcp_sessions.lock().unwrap().len(), expected);
            assert_eq!(direct.datagrams.lock().unwrap().len(), expected);
            assert_eq!(direct.udp_opens.load(Ordering::Relaxed), expected);
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn tcp_selects_proxy_direct_and_reject() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            None,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 80, end: 80 }]),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 25, end: 25 }]),
                    RuleAction::Reject,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        router
            .connect_tcp(stream("192.0.2.1:80".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:443".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        assert!(matches!(
            router
                .connect_tcp(stream("192.0.2.1:25".parse().unwrap(), InboundKind::Http,))
                .await,
            Err(DispatchError::NotAllowed)
        ));

        assert_eq!(direct.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn ipv6_disabled_rejects_literal_tcp_and_udp_before_dispatch() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(Vec::new()));
        let router = dispatcher_with_ipv6(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            false,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 80, end: 80 }]),
                    RuleAction::Direct,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        assert!(matches!(
            router
                .connect_tcp(stream(
                    "[2001:db8::1]:443".parse().unwrap(),
                    InboundKind::Http,
                ))
                .await,
            Err(DispatchError::NetworkUnreachable)
        ));
        assert!(matches!(
            router
                .connect_tcp(stream(
                    "[2001:db8::53]:53".parse().unwrap(),
                    InboundKind::Tun,
                ))
                .await,
            Err(DispatchError::NetworkUnreachable)
        ));
        let mut udp = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();
        assert!(matches!(
            udp.send(datagram("[2001:db8::1]:80".parse().unwrap(), b"blocked",))
                .await,
            Err(DispatchError::NetworkUnreachable)
        ));

        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        assert!(direct.tcp_sessions.lock().unwrap().is_empty());
        assert!(proxy.datagrams.lock().unwrap().is_empty());
        assert!(direct.datagrams.lock().unwrap().is_empty());
        assert_eq!(dns.exchange_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn ipv6_disabled_requires_an_ipv4_result_for_direct_domains() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(vec![IpAddr::V6(
            "2001:db8::7".parse::<Ipv6Addr>().unwrap(),
        )]));
        let router = dispatcher_with_ipv6(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            false,
            vec![rule(RuleKind::Match, RuleAction::Direct)],
        );

        assert!(matches!(
            router
                .connect_tcp(StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::Http,
                    source: "127.0.0.1:10000".parse().unwrap(),
                    destination: Destination::domain("example.com", 443).unwrap(),
                    sniffed_domain: None,
                })
                .await,
            Err(DispatchError::HostUnreachable)
        ));
        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        assert!(direct.tcp_sessions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ipv6_disabled_empty_resolution_still_falls_through_to_proxy() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(vec![IpAddr::V6(
            "2001:db8::7".parse::<Ipv6Addr>().unwrap(),
        )]));
        let router = dispatcher_with_ipv6(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            false,
            vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                        prefix_len: 24,
                    }),
                    RuleAction::Direct,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        router
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Http,
                source: "127.0.0.1:10000".parse().unwrap(),
                destination: Destination::domain("example.com", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        assert!(direct.tcp_sessions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sniffed_domain_routes_tun_tcp_without_replacing_original_ip() {
        let destination: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let mut dns = MockDns::new(Vec::new());
        dns.hint = Some((destination.ip(), "stale.example".to_owned()));
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(Arc::new(dns)),
            vec![
                rule(
                    RuleKind::Domain("stale.example".to_owned()),
                    RuleAction::Reject,
                ),
                rule(
                    RuleKind::DomainSuffix("example.com".to_owned()),
                    RuleAction::Direct,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        router
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Tun,
                source: "192.0.2.10:10000".parse().unwrap(),
                destination: Destination::Ip(destination),
                sniffed_domain: Some("api.Example.COM".to_owned()),
            })
            .await
            .unwrap();

        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        let sessions = direct.tcp_sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].destination, Destination::Ip(destination));
        assert_eq!(sessions[0].sniffed_domain, None);
    }

    #[tokio::test]
    async fn sniffed_domain_routes_tun_udp_without_replacing_original_ip() {
        let destination: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let mut dns = MockDns::new(Vec::new());
        dns.hint = Some((destination.ip(), "stale.example".to_owned()));
        let dns = Arc::new(dns);
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(
                    RuleKind::Domain("stale.example".to_owned()),
                    RuleAction::Reject,
                ),
                rule(
                    RuleKind::DomainSuffix("example.com".to_owned()),
                    RuleAction::Direct,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        let mut transport = router
            .open_datagram(DatagramSession::new(
                InboundKind::Tun,
                "192.0.2.10:10000".parse().unwrap(),
            ))
            .await
            .unwrap();
        transport
            .send(Datagram {
                remote: Destination::Ip(destination),
                payload: Bytes::from_static(b"quic"),
                sniffed_domain: Some(Arc::from("api.Example.COM")),
            })
            .await
            .unwrap();

        assert!(proxy.datagrams.lock().unwrap().is_empty());
        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 0);
        let datagrams = direct.datagrams.lock().unwrap();
        assert_eq!(datagrams.len(), 1);
        assert_eq!(datagrams[0].remote, Destination::Ip(destination));
        assert_eq!(datagrams[0].sniffed_domain, None);
        assert_eq!(&datagrams[0].payload[..], b"quic");
    }

    #[tokio::test]
    async fn business_inbounds_use_sniffed_domains_without_exposing_them_to_outbounds() {
        let destination: SocketAddr = "198.51.100.8:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            None,
            vec![
                rule(RuleKind::Domain("hint.example".into()), RuleAction::Direct),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        for inbound in [InboundKind::Http, InboundKind::Socks5, InboundKind::Tun] {
            let mut session = stream(destination, inbound);
            session.sniffed_domain = Some("hint.example".into());
            router.connect_tcp(session).await.unwrap();
        }
        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        let sessions = direct.tcp_sessions.lock().unwrap();
        assert_eq!(sessions.len(), 3);
        assert!(sessions.iter().all(
            |session| session.destination == Destination::Ip(destination)
                && session.sniffed_domain.is_none()
        ));
    }

    #[tokio::test]
    async fn tun_without_domain_rules_does_not_query_dns_hints() {
        let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let mut dns = MockDns::new(Vec::new());
        dns.hint = Some((destination.ip(), "unused.example".to_owned()));
        let dns = Arc::new(dns);
        let router = dispatcher(
            proxy.clone(),
            direct,
            Some(dns.clone()),
            vec![rule(RuleKind::Match, proxy_action(0))],
        );

        router
            .connect_tcp(stream(destination, InboundKind::Tun))
            .await
            .unwrap();
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        udp.send(datagram(destination, b"tun")).await.unwrap();

        assert_eq!(dns.hint_calls.load(Ordering::Relaxed), 0);
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tcp_rules_select_dynamic_proxy_ids() {
        let proxies = (0..4)
            .map(|_| Arc::new(RecordingDispatcher::default()))
            .collect::<Vec<_>>();
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher_with_proxies(
            proxies.clone(),
            direct,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 80, end: 80 }]),
                    proxy_action(3),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 81, end: 81 }]),
                    proxy_action(2),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 82, end: 82 }]),
                    proxy_action(1),
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        router
            .connect_tcp(stream("192.0.2.1:80".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:81".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:82".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        router
            .connect_tcp(stream("192.0.2.1:443".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();

        for proxy in proxies {
            assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn one_udp_association_lazily_opens_dynamic_proxy_ids_once() {
        let proxies = (0..4)
            .map(|_| Arc::new(RecordingDispatcher::default()))
            .collect::<Vec<_>>();
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher_with_proxies(
            proxies.clone(),
            direct,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 53, end: 53 }]),
                    proxy_action(3),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange {
                        start: 123,
                        end: 123,
                    }]),
                    proxy_action(2),
                ),
                rule(
                    RuleKind::DstPorts(vec![PortRange {
                        start: 500,
                        end: 500,
                    }]),
                    proxy_action(1),
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();

        for (port, payload) in [
            (53, b"three".as_slice()),
            (123, b"two".as_slice()),
            (500, b"one".as_slice()),
            (443, b"zero".as_slice()),
            (53, b"three-again".as_slice()),
            (123, b"two-again".as_slice()),
            (500, b"one-again".as_slice()),
            (443, b"zero-again".as_slice()),
        ] {
            transport
                .send(datagram(
                    format!("192.0.2.1:{port}").parse().unwrap(),
                    payload,
                ))
                .await
                .unwrap();
        }

        for proxy in &proxies {
            assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
            assert_eq!(proxy.datagrams.lock().unwrap().len(), 2);
        }

        let mut responses = Vec::new();
        for _ in 0..8 {
            let response =
                tokio::time::timeout(std::time::Duration::from_millis(100), transport.receive())
                    .await
                    .expect("all dynamically opened proxy transports remain receivable")
                    .unwrap();
            responses.push(response.payload);
        }
        responses.sort();
        assert_eq!(
            responses,
            [
                Bytes::from_static(b"one"),
                Bytes::from_static(b"one-again"),
                Bytes::from_static(b"three"),
                Bytes::from_static(b"three-again"),
                Bytes::from_static(b"two"),
                Bytes::from_static(b"two-again"),
                Bytes::from_static(b"zero"),
                Bytes::from_static(b"zero-again"),
            ]
        );
    }

    #[tokio::test]
    async fn normalized_domain_is_reused_by_runtime_dns_and_outbound() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(vec![IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 7,
        ))]));
        let router = dispatcher(
            proxy,
            direct.clone(),
            Some(dns.clone()),
            vec![rule(RuleKind::Match, RuleAction::Direct)],
        );
        router
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Http,
                source: "127.0.0.1:10000".parse().unwrap(),
                destination: Destination::domain("例子.中国", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(
            *dns.resolved_hosts.lock().unwrap(),
            vec!["xn--fsqu00a.xn--fiqs8s"]
        );
        assert_eq!(
            direct.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Ip("203.0.113.7:443".parse().unwrap())
        );

        let proxy = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            Arc::new(RecordingDispatcher::default()),
            None,
            vec![rule(RuleKind::Match, proxy_action(0))],
        );
        router
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Http,
                source: "127.0.0.1:10001".parse().unwrap(),
                destination: Destination::domain("例子.中国", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(
            proxy.tcp_sessions.lock().unwrap()[0].destination,
            Destination::domain("xn--fsqu00a.xn--fiqs8s", 443).unwrap()
        );
    }

    #[tokio::test]
    async fn one_udp_association_lazily_uses_both_actions() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            None,
            vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        prefix_len: 8,
                    }),
                    RuleAction::Direct,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();

        transport
            .send(datagram("10.0.0.1:1234".parse().unwrap(), b"direct"))
            .await
            .unwrap();
        transport
            .send(datagram("192.0.2.1:1234".parse().unwrap(), b"proxy"))
            .await
            .unwrap();
        transport
            .send(datagram("10.0.0.2:1234".parse().unwrap(), b"direct2"))
            .await
            .unwrap();

        assert_eq!(direct.datagrams.lock().unwrap().len(), 2);
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
        assert_eq!(direct.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelled_udp_receive_can_add_another_route_and_receive_both() {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            for direct_first in [true, false] {
                let proxy = Arc::new(RecordingDispatcher::default());
                let direct = Arc::new(RecordingDispatcher::default());
                let router = dispatcher(
                    proxy.clone(),
                    direct.clone(),
                    None,
                    vec![
                        rule(
                            RuleKind::IpCidr(IpCidr {
                                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                                prefix_len: 8,
                            }),
                            RuleAction::Direct,
                        ),
                        rule(RuleKind::Match, proxy_action(0)),
                    ],
                );
                let mut transport = router
                    .open_datagram(association(InboundKind::Tun))
                    .await
                    .unwrap();
                // No backend exists yet. Dropping this receive must leave
                // the association available for its first send.
                {
                    let mut receive = transport.receive();
                    assert!(futures_util::poll!(receive.as_mut()).is_pending());
                }
                let direct_address = "10.0.0.1:1234".parse().unwrap();
                let proxy_address = "192.0.2.1:1234".parse().unwrap();
                let (first_address, next_address) = if direct_first {
                    (direct_address, proxy_address)
                } else {
                    (proxy_address, direct_address)
                };
                let first = datagram(first_address, b"first");
                transport.send(first.clone()).await.unwrap();
                assert_eq!(transport.receive().await.unwrap(), first);

                // Poll the only cached backend until pending, then cancel
                // before a send opens the other route.
                {
                    let mut receive = transport.receive();
                    assert!(futures_util::poll!(receive.as_mut()).is_pending());
                }
                let next = datagram(next_address, b"next-route");
                let previous = datagram(first_address, b"previous-route");
                transport.send(next.clone()).await.unwrap();
                transport.send(previous.clone()).await.unwrap();
                let responses = [
                    transport.receive().await.unwrap(),
                    transport.receive().await.unwrap(),
                ];
                assert!(responses.contains(&next));
                assert!(responses.contains(&previous));
                assert_eq!(direct.udp_opens.load(Ordering::Relaxed), 1);
                assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
                transport.close().await.unwrap();
            }
        })
        .await
        .expect("cancelled UDP receives did not preserve dynamic routing");
    }

    #[tokio::test]
    async fn single_udp_route_propagates_receive_errors() {
        struct FailingReceiveDispatcher;
        struct FailingReceiveDatagrams {
            fail_next: bool,
            responses: VecDeque<Datagram>,
        }

        #[async_trait]
        impl Dispatcher for FailingReceiveDispatcher {
            async fn connect_tcp(
                &self,
                _session: StreamSession,
            ) -> Result<BoxStream, DispatchError> {
                unreachable!("UDP-only mock")
            }

            async fn open_datagram(
                &self,
                _session: DatagramSession,
            ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
                Ok(Box::new(FailingReceiveDatagrams {
                    fail_next: true,
                    responses: VecDeque::new(),
                }))
            }
        }

        #[async_trait]
        impl DatagramTransport for FailingReceiveDatagrams {
            fn supports_shared_destinations(&self) -> bool {
                false
            }

            async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
                self.responses.push_back(datagram);
                Ok(())
            }

            async fn receive(&mut self) -> Result<Datagram, DispatchError> {
                if std::mem::take(&mut self.fail_next) {
                    return Err(DispatchError::ConnectionRefused);
                }
                if let Some(response) = self.responses.pop_front() {
                    return Ok(response);
                }
                std::future::pending().await
            }
        }

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            for action in [RuleAction::Direct, proxy_action(0)] {
                let backend = Arc::new(FailingReceiveDispatcher);
                let router = RoutingDispatcher::with_dns_service(
                    backend.clone(),
                    backend,
                    None,
                    true,
                    RuleSet::compile(vec![rule(RuleKind::Match, action)]).unwrap(),
                    Arc::new(EmptyGeoMatcher),
                );
                let mut transport = router
                    .open_datagram(association(InboundKind::Tun))
                    .await
                    .unwrap();
                let request = datagram("192.0.2.1:1234".parse().unwrap(), b"request");
                transport.send(request.clone()).await.unwrap();
                assert!(matches!(
                    transport.receive().await,
                    Err(DispatchError::ConnectionRefused)
                ));
                assert_eq!(transport.receive().await.unwrap(), request);
                transport.close().await.unwrap();
            }
        })
        .await
        .expect("the only UDP backend's receive error was not propagated");
    }

    #[test]
    fn udp_associations_share_the_immutable_rule_set() {
        let router = dispatcher(
            Arc::new(RecordingDispatcher::default()),
            Arc::new(RecordingDispatcher::default()),
            None,
            vec![rule(RuleKind::Match, proxy_action(0))],
        );
        let association_router = router.clone_parts();

        assert!(Arc::ptr_eq(&router.rules, &association_router.rules));
    }

    #[tokio::test]
    async fn udp_reject_drops_only_the_current_datagram() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            None,
            vec![
                rule(
                    RuleKind::DstPorts(vec![PortRange { start: 9, end: 9 }]),
                    RuleAction::Reject,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();

        transport
            .send(datagram("192.0.2.1:9".parse().unwrap(), b"drop"))
            .await
            .unwrap();
        transport
            .send(datagram("192.0.2.1:443".parse().unwrap(), b"keep"))
            .await
            .unwrap();

        assert!(direct.datagrams.lock().unwrap().is_empty());
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tun_udp_pins_each_destination_while_observing_new_flows() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(UpdatingDns::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(RuleKind::Domain("blocked.test".into()), RuleAction::Reject),
                rule(RuleKind::Domain("direct.test".into()), RuleAction::Direct),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        let first = "198.51.100.7:443".parse().unwrap();
        let second = "198.51.100.7:8443".parse().unwrap();
        let third = "198.51.100.8:443".parse().unwrap();
        *dns.hint.lock().unwrap() = Some("direct.test".into());
        udp.send(datagram(first, b"initial")).await.unwrap();
        *dns.hint.lock().unwrap() = Some("blocked.test".into());
        udp.send(datagram(second, b"reject")).await.unwrap();
        udp.send(datagram(first, b"pinned")).await.unwrap();
        *dns.hint.lock().unwrap() = None;
        udp.send(datagram(third, b"proxy")).await.unwrap();
        udp.send(datagram(second, b"still-reject")).await.unwrap();
        assert_eq!(direct.datagrams.lock().unwrap().len(), 2);
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);
        assert_eq!(direct.udp_opens.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 1);
        udp.close().await.unwrap();
    }

    #[tokio::test]
    async fn tun_udp_uses_new_hints_only_for_a_new_authenticated_flow() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(UpdatingDns::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(RuleKind::Domain("blocked.test".into()), RuleAction::Reject),
                rule(RuleKind::Domain("direct.test".into()), RuleAction::Direct),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        let destination = "198.51.100.7:443".parse().unwrap();
        for hint in [Some("direct.test"), Some("blocked.test"), None] {
            *dns.hint.lock().unwrap() = hint.map(Into::into);
            for _ in 0..2 {
                udp.send(datagram(destination, b"current")).await.unwrap();
            }
        }
        assert_eq!(direct.datagrams.lock().unwrap().len(), 6);
        assert!(proxy.datagrams.lock().unwrap().is_empty());

        *dns.hint.lock().unwrap() = Some("blocked.test".into());
        for (id, hint) in [
            (b"first".as_slice(), "blocked.test"),
            (b"second".as_slice(), "Direct.TEST."),
            (b"third".as_slice(), "not a domain"),
        ] {
            let mut request = datagram(destination, b"sniffed");
            request.sniffed_domain = Some(Arc::from(hint));
            for _ in 0..2 {
                udp.send_with_flow_id(request.clone(), id).await.unwrap();
            }
        }
        assert_eq!(direct.datagrams.lock().unwrap().len(), 8);
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 2);
        // A retransmitted authenticated Initial keeps its established action,
        // even if the tiny sniff table had to reconstruct its domain hint.
        let mut replay = datagram(destination, b"replay");
        replay.sniffed_domain = Some(Arc::from("blocked.test"));
        udp.send_with_flow_id(replay, b"third").await.unwrap();
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 3);
        for request in direct.datagrams.lock().unwrap().iter() {
            assert_eq!(request.remote, Destination::Ip(destination));
            assert!(request.sniffed_domain.is_none());
        }
    }

    #[tokio::test]
    async fn udp_geo_activation_affects_new_flows_without_retaining_old_data() {
        let dir = tempfile::tempdir().unwrap();
        // Independent Xray GeoIP fixture: cn -> 192.0.2.0/24.
        std::fs::write(
            dir.path().join("geoip.dat"),
            [
                0x0a, 14, 0x0a, 2, b'c', b'n', 0x12, 8, 0x0a, 4, 192, 0, 2, 0, 0x10, 24,
            ],
        )
        .unwrap();
        let rules = vec![
            rule(RuleKind::GeoIp("cn".into()), RuleAction::Reject),
            rule(RuleKind::Match, proxy_action(0)),
        ];
        let initial = Arc::new(GeoData::load(dir.path(), &rules).unwrap());
        let old_data = Arc::downgrade(&initial);
        let geo = Arc::new(DynamicGeoData::new(initial));
        let proxy = Arc::new(RecordingDispatcher::default());
        let router = RoutingDispatcher::new(
            ProxyDispatchers::new(vec![proxy.clone()]).unwrap(),
            Arc::new(RecordingDispatcher::default()),
            None,
            RuleSet::compile(rules).unwrap(),
            geo.clone(),
        );
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        let destination = "192.0.2.8:443".parse().unwrap();
        for _ in 0..2 {
            udp.send(datagram(destination, b"blocked")).await.unwrap();
        }
        assert!(proxy.datagrams.lock().unwrap().is_empty());
        geo.activate(Arc::new(GeoData::EMPTY));
        assert!(
            old_data.upgrade().is_none(),
            "active UDP must release obsolete GeoData"
        );
        for _ in 0..2 {
            udp.send(datagram(destination, b"still-blocked"))
                .await
                .unwrap();
        }
        assert!(proxy.datagrams.lock().unwrap().is_empty());
        for _ in 0..2 {
            udp.send(datagram("192.0.2.8:8443".parse().unwrap(), b"allowed"))
                .await
                .unwrap();
        }
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 2);
        udp.send_with_flow_id(datagram(destination, b"new-connection"), b"new")
            .await
            .unwrap();
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 3);
        udp.close().await.unwrap();
    }

    #[tokio::test]
    async fn udp_domain_destinations_observe_fresh_resolution() {
        let dns = Arc::new(UpdatingDns::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            Arc::new(RecordingDispatcher::default()),
            direct.clone(),
            Some(dns.clone()),
            vec![rule(RuleKind::Match, RuleAction::Direct)],
        );
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        for ip in ["192.0.2.1", "192.0.2.2"] {
            *dns.addresses.lock().unwrap() = vec![ip.parse().unwrap()];
            udp.send(Datagram {
                remote: Destination::domain("example.test", 443).unwrap(),
                payload: Bytes::from_static(b"fresh"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        }
        let sent = direct.datagrams.lock().unwrap();
        assert_eq!(
            sent[0].remote,
            Destination::Ip("192.0.2.1:443".parse().unwrap())
        );
        assert_eq!(
            sent[1].remote,
            Destination::Ip("192.0.2.2:443".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn tun_udp_mutable_matcher_changes_apply_to_new_flows() {
        struct MutableGeo(AtomicBool);

        impl GeoMatcher for MutableGeo {
            fn matches_geosite(&self, _code: &str, _domain: &str) -> bool {
                false
            }
            fn matches_geoip(&self, _code: &str, _address: IpAddr) -> bool {
                self.0.load(Ordering::Relaxed)
            }
        }

        let geo = Arc::new(MutableGeo(AtomicBool::new(false)));
        let proxy = Arc::new(RecordingDispatcher::default());
        let router = RoutingDispatcher::new(
            ProxyDispatchers::new(vec![proxy.clone()]).unwrap(),
            Arc::new(RecordingDispatcher::default()),
            None,
            RuleSet::compile(vec![
                rule(RuleKind::GeoIp("cn".into()), RuleAction::Reject),
                rule(RuleKind::Match, proxy_action(0)),
            ])
            .unwrap(),
            geo.clone(),
        );
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        let destination = "192.0.2.8:443".parse().unwrap();
        udp.send(datagram(destination, b"allowed")).await.unwrap();
        geo.0.store(true, Ordering::Relaxed);
        udp.send(datagram(destination, b"pinned")).await.unwrap();
        udp.send(datagram("192.0.2.8:8443".parse().unwrap(), b"blocked"))
            .await
            .unwrap();
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn udp_idle_sweep_reclaims_burst_capacity_without_a_count_limit() {
        let start = Instant::now();
        let mut routes = DatagramRoutes::new(Duration::from_secs(30));
        for port in 1..=16_384 {
            routes.entries.insert(
                SocketAddr::from(([192, 0, 2, 1], port)),
                DatagramRoute {
                    action: RuleAction::Reject,
                    last_used: start,
                    flow_id: None,
                },
            );
        }
        let burst_capacity = routes.entries.capacity();
        assert!(burst_capacity >= 16_384);
        let busy = SocketAddr::from(([192, 0, 2, 1], 1));
        assert_eq!(
            routes.action(busy, start + Duration::from_secs(25)),
            Some(RuleAction::Reject)
        );
        routes.expire(start + Duration::from_secs(35));
        assert_eq!(routes.entries.len(), 1);
        assert!(routes.entries.capacity() < burst_capacity / 4);
        routes.expire(start + Duration::from_secs(60));
        assert!(routes.entries.is_empty());
        assert!(routes.entries.capacity() <= 8);
    }

    #[tokio::test(start_paused = true)]
    async fn tun_udp_expires_idle_destinations_while_the_source_stays_active() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(UpdatingDns::default());
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(RuleKind::Domain("blocked.test".into()), RuleAction::Reject),
                rule(RuleKind::Domain("direct.test".into()), RuleAction::Direct),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        let idle = "198.51.100.7:443".parse().unwrap();
        let busy = "198.51.100.7:8443".parse().unwrap();
        *dns.hint.lock().unwrap() = Some("direct.test".into());
        udp.send(datagram(idle, b"old")).await.unwrap();
        udp.send(datagram(busy, b"busy")).await.unwrap();
        *dns.hint.lock().unwrap() = Some("blocked.test".into());
        tokio::time::advance(Duration::from_secs(25)).await;
        udp.send(datagram(busy, b"refresh")).await.unwrap();
        tokio::time::advance(Duration::from_secs(5)).await;
        udp.send(datagram(idle, b"expired")).await.unwrap();
        udp.send(datagram(busy, b"still-pinned")).await.unwrap();
        assert_eq!(direct.datagrams.lock().unwrap().len(), 4);
        assert!(proxy.datagrams.lock().unwrap().is_empty());
        udp.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn tun_udp_responses_refresh_only_their_own_flow() {
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(UpdatingDns::default());
        let router = dispatcher(
            Arc::new(RecordingDispatcher::default()),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(RuleKind::Domain("blocked.test".into()), RuleAction::Reject),
                rule(RuleKind::Match, RuleAction::Direct),
            ],
        );
        let mut udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        let reply = "198.51.100.7:443".parse().unwrap();
        let idle = "198.51.100.8:443".parse().unwrap();
        udp.send(datagram(reply, b"reply")).await.unwrap();
        udp.send(datagram(idle, b"idle")).await.unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(udp.receive().await.unwrap().remote, Destination::Ip(reply));
        *dns.hint.lock().unwrap() = Some("blocked.test".into());
        tokio::time::advance(Duration::from_secs(20)).await;
        udp.send(datagram(reply, b"still-pinned")).await.unwrap();
        udp.send(datagram(idle, b"expired")).await.unwrap();
        assert_eq!(direct.datagrams.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn tcp_dns_hijack_is_tun_only_while_udp_uses_normal_routing() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(Vec::new()));
        let router = dispatcher(
            proxy.clone(),
            direct,
            Some(dns.clone()),
            vec![rule(RuleKind::Match, proxy_action(0))],
        );

        let mut tun_udp = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        tun_udp
            .send(datagram("1.1.1.1:53".parse().unwrap(), b"udp-query"))
            .await
            .unwrap();
        let response = tun_udp.receive().await.unwrap();
        assert_eq!(&response.payload[..], b"udp-query");
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 1);

        let mut socks_udp = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();
        socks_udp
            .send(datagram("1.1.1.1:53".parse().unwrap(), b"normal"))
            .await
            .unwrap();
        assert_eq!(proxy.datagrams.lock().unwrap().len(), 2);

        let mut tun_tcp = router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Tun))
            .await
            .unwrap();
        for query in [b"first".as_slice(), b"second".as_slice()] {
            tun_tcp.write_u16(query.len() as u16).await.unwrap();
            tun_tcp.write_all(query).await.unwrap();
            assert_eq!(tun_tcp.read_u16().await.unwrap() as usize, query.len());
            let mut response = vec![0_u8; query.len()];
            tun_tcp.read_exact(&mut response).await.unwrap();
            assert_eq!(response, query);
        }

        router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Http))
            .await
            .unwrap();
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 1);
        assert_eq!(dns.exchange_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn configured_tcp_dns_targets_preserve_nonmatching_and_non_tun_routes() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(Vec::new()));
        let target = "192.0.2.53:5353".parse().unwrap();
        let router = dispatcher(
            proxy.clone(),
            Arc::new(RecordingDispatcher::default()),
            Some(dns.clone()),
            vec![rule(RuleKind::Match, proxy_action(0))],
        )
        .with_tun_config(&TunConfig {
            dns_hijack: vec![target],
            ..TunConfig::default()
        });
        for (destination, inbound) in [
            ("1.1.1.1:53".parse().unwrap(), InboundKind::Tun),
            ("192.0.2.54:5353".parse().unwrap(), InboundKind::Tun),
            (target, InboundKind::Http),
        ] {
            drop(
                router
                    .connect_tcp(stream(destination, inbound))
                    .await
                    .unwrap(),
            );
        }
        let mut hijacked = router
            .connect_tcp(stream(target, InboundKind::Tun))
            .await
            .unwrap();
        hijacked.write_u16(5).await.unwrap();
        hijacked.write_all(b"query").await.unwrap();
        assert_eq!(hijacked.read_u16().await.unwrap(), 5);
        let mut response = [0; 5];
        hijacked.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"query");
        drop(hijacked);
        let router = router.with_tun_config(&TunConfig {
            dns_hijack: Vec::new(),
            ..TunConfig::default()
        });
        drop(
            router
                .connect_tcp(stream(target, InboundKind::Tun))
                .await
                .unwrap(),
        );
        assert_eq!(proxy.tcp_sessions.lock().unwrap().len(), 4);
        assert_eq!(dns.exchange_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn configured_udp_timeout_preserves_flow_until_its_actual_idle_deadline() {
        let now = Instant::now();
        for seconds in [7, 300] {
            let mut routes = DatagramRoutes::new(Duration::from_secs(seconds));
            let target = "192.0.2.10:443".parse().unwrap();
            routes.entries.insert(
                target,
                DatagramRoute {
                    action: RuleAction::Reject,
                    last_used: now,
                    flow_id: None,
                },
            );
            assert_eq!(
                routes.action(target, now + Duration::from_secs(seconds - 1)),
                Some(RuleAction::Reject)
            );
            assert_eq!(
                routes.action(target, now + Duration::from_secs(2 * seconds - 1)),
                None
            );
        }
    }

    #[tokio::test]
    async fn tun_dns_tcp_accepts_partial_and_pipelined_mixed_qtype_frames() {
        let dns = Arc::new(WireDns::default());
        let router = dispatcher(
            Arc::new(RecordingDispatcher::default()),
            Arc::new(RecordingDispatcher::default()),
            Some(dns.clone()),
            vec![rule(RuleKind::Match, proxy_action(0))],
        );
        let mut stream = router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Tun))
            .await
            .unwrap();
        let queries = [
            wire_query(0x1001, 1),
            wire_query(0x1002, 65),
            wire_query(0x1003, 28),
            wire_query(0x1004, 16),
        ];

        let first_length = u16::try_from(queries[0].len()).unwrap().to_be_bytes();
        stream.write_all(&first_length[..1]).await.unwrap();
        stream.write_all(&first_length[1..]).await.unwrap();
        let split = queries[0].len() / 2;
        stream.write_all(&queries[0][..split]).await.unwrap();
        stream.write_all(&queries[0][split..]).await.unwrap();
        for query in &queries[1..] {
            stream.write_u16(query.len() as u16).await.unwrap();
            stream.write_all(query).await.unwrap();
        }

        for query in &queries {
            let response_length = stream.read_u16().await.unwrap() as usize;
            let mut response = vec![0_u8; response_length];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &query[..2]);
            assert_ne!(response[2] & 0x80, 0);
        }
        assert_eq!(*dns.query_types.lock().unwrap(), vec![1, 65, 28, 16]);
    }

    #[tokio::test]
    async fn dropping_a_tun_dns_tcp_stream_cancels_its_relay_query() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let exchange_cancelled = Arc::new(AtomicBool::new(false));
        let dns = Arc::new(BlockingDns {
            exchange_started: Notify::new(),
            exchange_cancelled: exchange_cancelled.clone(),
        });
        let router = dispatcher(
            proxy,
            direct,
            Some(dns.clone()),
            vec![rule(RuleKind::Match, proxy_action(0))],
        );

        let mut stream = router
            .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Tun))
            .await
            .unwrap();
        stream.write_u16(5).await.unwrap();
        stream.write_all(b"query").await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            dns.exchange_started.notified(),
        )
        .await
        .expect("DNS relay never entered the exchange");

        drop(stream);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !exchange_cancelled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the caller stream did not abort the DNS relay");
    }

    #[cfg(feature = "ffi")]
    #[test]
    fn tun_dns_tcp_relay_preserves_probe_across_workers_and_releases_on_drop() {
        use crate::resources::observation::{self, ResourceKind, ResourceProbe};

        struct ProbeDns {
            started: std::sync::mpsc::SyncSender<std::thread::ThreadId>,
        }

        #[async_trait]
        impl RoutingDns for ProbeDns {
            async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, DispatchError> {
                Ok(Vec::new())
            }

            async fn exchange(&self, _query: &[u8]) -> Result<DnsWireResponse, DispatchError> {
                let _query = observation::track(ResourceKind::Waiter);
                self.started.send(std::thread::current().id()).unwrap();
                std::future::pending().await
            }

            async fn domain_hint(&self, _address: IpAddr) -> Option<String> {
                None
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let probe = ResourceProbe::default();
        let (started, ready) = std::sync::mpsc::sync_channel(1);
        let dns = Arc::new(ProbeDns { started });
        let router = dispatcher(
            Arc::new(RecordingDispatcher::default()),
            Arc::new(RecordingDispatcher::default()),
            Some(dns),
            vec![rule(RuleKind::Match, proxy_action(0))],
        );
        let caller = std::thread::current().id();
        let stream = runtime.block_on(probe.scope(async {
            let mut stream = router
                .connect_tcp(stream("1.1.1.1:53".parse().unwrap(), InboundKind::Tun))
                .await
                .unwrap();
            stream.write_u16(5).await.unwrap();
            stream.write_all(b"query").await.unwrap();
            stream
        }));
        let relay = ready
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("DNS relay did not enter a worker thread");
        assert_ne!(caller, relay);

        assert_eq!(probe.snapshot().current(ResourceKind::Task), 1);
        assert_eq!(probe.snapshot().current(ResourceKind::Waiter), 1);
        assert_eq!(probe.snapshot().peak(ResourceKind::Waiter), 1);
        drop(stream);
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while !probe.snapshot().is_idle() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("dropped DNS relay did not release its observed resources");
        });
    }

    #[tokio::test]
    async fn lazy_resolution_preserves_rule_priority_and_pins_the_match() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let selected = IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>().unwrap());
        let dns = Arc::new(MockDns::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            selected,
        ]));
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V6("2001:db8::".parse().unwrap()),
                        prefix_len: 32,
                    }),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        prefix_len: 8,
                    }),
                    RuleAction::Reject,
                ),
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        let mut transport = router
            .open_datagram(association(InboundKind::Http))
            .await
            .unwrap();
        transport
            .send(Datagram {
                remote: Destination::domain("example.com", 443).unwrap(),
                payload: Bytes::from_static(b"payload"),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert!(proxy.datagrams.lock().unwrap().is_empty());
        let sent = direct.datagrams.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].remote,
            Destination::Ip(SocketAddr::new(selected, 443))
        );
    }

    #[tokio::test]
    async fn lazy_resolution_is_visible_to_later_no_resolve_rule() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let resolved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let dns = Arc::new(MockDns::new(vec![resolved]));
        let mut later_no_resolve = rule(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }),
            RuleAction::Direct,
        );
        later_no_resolve.no_resolve = true;
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                        prefix_len: 24,
                    }),
                    RuleAction::Reject,
                ),
                later_no_resolve,
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        router
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Http,
                source: "127.0.0.1:10000".parse().unwrap(),
                destination: Destination::domain("example.com", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        assert_eq!(
            direct.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Ip(SocketAddr::new(resolved, 443))
        );
    }

    #[tokio::test]
    async fn lazy_resolution_does_not_revisit_prior_no_resolve_rule() {
        let proxy = Arc::new(RecordingDispatcher::default());
        let direct = Arc::new(RecordingDispatcher::default());
        let selected = IpAddr::V6("2001:db8::7".parse::<Ipv6Addr>().unwrap());
        let dns = Arc::new(MockDns::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            selected,
        ]));
        let mut earlier_no_resolve = rule(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }),
            RuleAction::Reject,
        );
        earlier_no_resolve.no_resolve = true;
        let mut later_no_resolve = rule(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V6("2001:db8::".parse().unwrap()),
                prefix_len: 32,
            }),
            RuleAction::Direct,
        );
        later_no_resolve.no_resolve = true;
        let router = dispatcher(
            proxy.clone(),
            direct.clone(),
            Some(dns.clone()),
            vec![
                earlier_no_resolve,
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                        prefix_len: 24,
                    }),
                    RuleAction::Reject,
                ),
                later_no_resolve,
                rule(RuleKind::Match, proxy_action(0)),
            ],
        );

        router
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::Http,
                source: "127.0.0.1:10001".parse().unwrap(),
                destination: Destination::domain("example.com", 443).unwrap(),
                sniffed_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(dns.resolve_calls.load(Ordering::Relaxed), 1);
        assert!(proxy.tcp_sessions.lock().unwrap().is_empty());
        assert_eq!(
            direct.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Ip(SocketAddr::new(selected, 443))
        );
    }
    #[tokio::test]
    async fn fake_ip_routing_preserves_tcp_names_and_distinct_udp_reply_addresses() {
        struct FakeDns;
        #[async_trait]
        impl RoutingDns for FakeDns {
            fn recover_fake_ip(&self, address: IpAddr) -> Result<Option<String>, DispatchError> {
                Ok(match address.to_string().as_str() {
                    "198.18.0.4" => Some("one.example".into()),
                    "198.18.0.5" => Some("two.example".into()),
                    _ => None,
                })
            }
            async fn resolve(&self, _: &str) -> Result<Vec<IpAddr>, DispatchError> {
                Ok(vec!["203.0.113.10".parse().unwrap()])
            }
            async fn exchange(&self, _: &[u8]) -> Result<DnsWireResponse, DispatchError> {
                Err(DispatchError::HostUnreachable)
            }
            async fn domain_hint(&self, _: IpAddr) -> Option<String> {
                None
            }
        }
        let proxy = Arc::new(RecordingDispatcher {
            shareable: true,
            ..Default::default()
        });
        let direct = Arc::new(RecordingDispatcher::default());
        let router = dispatcher(
            proxy.clone(),
            direct,
            Some(Arc::new(FakeDns)),
            vec![rule(RuleKind::Match, proxy_action(0))],
        );
        let config = crate::config::Config::parse_yaml(
            br#"proxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080, udp: true}]
rules: ["MATCH,edge"]"#,
        )
        .unwrap();
        let registry = Arc::new(crate::connections::Registry::default());
        let diagnostics = Arc::new(crate::routing::diagnostics::Diagnostics::new(
            &config,
            &router.rules,
            registry.clone(),
        ));
        let router = router.with_diagnostics(diagnostics);
        let first: SocketAddr = "198.18.0.4:443".parse().unwrap();
        let second: SocketAddr = "198.18.0.5:443".parse().unwrap();
        let _stream = router
            .connect_tcp(stream(first, InboundKind::Tun))
            .await
            .unwrap();
        assert_eq!(
            proxy.tcp_sessions.lock().unwrap()[0].destination,
            Destination::Domain {
                host: "one.example".into(),
                port: 443
            }
        );
        drop(_stream);
        let mut udp = router
            .open_datagram(DatagramSession::new(
                InboundKind::Tun,
                "192.0.2.2:9000".parse().unwrap(),
            ))
            .await
            .unwrap();
        for (address, payload) in [(first, "one"), (second, "two")] {
            udp.send(Datagram {
                remote: Destination::Ip(address),
                payload: Bytes::from(payload),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        }
        let mut received = Vec::new();
        for _ in 0..2 {
            let packet = udp.receive().await.unwrap();
            received.push((packet.remote, packet.payload));
        }
        assert!(received.contains(&(Destination::Ip(first), Bytes::from("one"))));
        assert!(received.contains(&(Destination::Ip(second), Bytes::from("two"))));
        assert_eq!(proxy.udp_opens.load(Ordering::Relaxed), 2);
        assert!(proxy.datagrams.lock().unwrap().iter().all(|packet| packet.remote == Destination::Ip("203.0.113.10:443".parse().unwrap())));
        assert_eq!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        udp.close().await.unwrap();
        assert!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test]
    async fn quic_override_resolves_new_domain_and_restores_udp_response_target() {
        let mut config = crate::config::SnifferConfig::disabled();
        config.enable = true;
        let proxy = Arc::new(RecordingDispatcher {
            shareable: true,
            ..Default::default()
        });
        let direct = Arc::new(RecordingDispatcher::default());
        let dns = Arc::new(MockDns::new(vec!["203.0.113.8".parse().unwrap()]));
        let router = dispatcher(
            proxy.clone(),
            direct,
            Some(dns.clone()),
            vec![rule(RuleKind::Match, proxy_action(0))],
        )
        .with_sniffer(&config);
        let config = crate::config::Config::parse_yaml(
            br#"proxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080, udp: true}]
rules: ["MATCH,edge"]"#,
        )
        .unwrap();
        let registry = Arc::new(crate::connections::Registry::default());
        let diagnostics = Arc::new(crate::routing::diagnostics::Diagnostics::new(
            &config,
            &router.rules,
            registry.clone(),
        ));
        let router = router.with_diagnostics(diagnostics);
        let original = "198.51.100.4:443".parse().unwrap();
        let mut transport = router
            .open_datagram(association(InboundKind::Tun))
            .await
            .unwrap();
        let mut packet = datagram(original, b"quic");
        packet.sniffed_domain = Some("sniffed.example".into());
        transport.send(packet).await.unwrap();
        assert_eq!(
            proxy.datagrams.lock().unwrap()[0].remote,
            Destination::Ip("203.0.113.8:443".parse().unwrap())
        );
        assert_eq!(
            transport.receive().await.unwrap().remote,
            Destination::Ip(original)
        );
        let other = "198.51.100.5:443".parse().unwrap();
        let mut packet = datagram(other, b"other");
        packet.sniffed_domain = Some("alias.example".into());
        transport.send(packet).await.unwrap();
        assert_eq!(
            transport.receive().await.unwrap().remote,
            Destination::Ip(other)
        );
        assert_eq!(
            proxy.udp_opens.load(Ordering::Relaxed),
            2,
            "two original destinations mapping to one real endpoint need separate wires"
        );
        assert_eq!(
            *dns.resolved_hosts.lock().unwrap(),
            ["sniffed.example", "alias.example"]
        );
        assert_eq!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        transport.close().await.unwrap();
        assert!(
            serde_json::to_value(registry.snapshot()).unwrap()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

fn business(inbound: InboundKind) -> bool {
    matches!(
        inbound,
        InboundKind::Tun | InboundKind::Http | InboundKind::Https | InboundKind::Socks5
    )
}
