//! IP-only protocol boundaries use a runtime-owned resolver, never an implicit
//! system lookup. Proxy servers use their separate runtime DNS role.

use super::{canonicalize_name, runtime::RuntimeDns};
use crate::{dialer::Resolver, dispatch::DispatchError, session::Destination};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock, Weak},
};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

/// Per-lookup dependency depth, not a concurrent connection admission limit.
pub const MAX_RESOLUTION_DEPTH: usize = 32;

enum Source {
    Runtime(Option<Weak<RuntimeDns>>),
    Measurement(Arc<dyn Resolver>),
}

struct State {
    source: OnceLock<Source>,
    measurement_ech: OnceLock<Weak<RuntimeDns>>,
    ipv6: bool,
    cancel: CancellationToken,
}

/// Clones share only one runtime's policy and cancellation. The runtime DNS
/// link is weak, so DNS -> dispatcher -> connector cannot retain its owner.
/// Default contexts permit literal IPs but have no domain resolver.
#[derive(Clone, Default)]
pub struct ResolutionContext {
    ip_version: crate::config::IpVersion,
    inner: Option<Arc<State>>,
}

impl std::fmt::Debug for ResolutionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolutionContext").finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct ActiveResolution {
    deadline: Instant,
    names: Vec<(usize, ResolveRole, u16, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResolveRole {
    Business,
    Proxy,
    Direct,
}

tokio::task_local! {
    static ACTIVE: ActiveResolution;
}

pub(crate) fn inherited_deadline(deadline: Instant) -> Instant {
    ACTIVE
        .try_with(|active| active.deadline.min(deadline))
        .unwrap_or(deadline)
}

impl ResolutionContext {
    pub(crate) fn with_ip_version(mut self, version: crate::config::IpVersion) -> Self {
        self.ip_version = version;
        self
    }

    pub fn runtime(ipv6: bool) -> Self {
        Self {
            ip_version: crate::config::IpVersion::Dual,
            inner: Some(Arc::new(State {
                source: OnceLock::new(),
                measurement_ech: OnceLock::new(),
                ipv6,
                cancel: CancellationToken::new(),
            })),
        }
    }

    /// Called once, after graph construction has made the DNS egress available.
    pub fn bind_runtime(&self, dns: Option<&Arc<RuntimeDns>>) -> io::Result<()> {
        self.inner
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?
            .source
            .set(Source::Runtime(dns.map(Arc::downgrade)))
            .map_err(|_| io::ErrorKind::AlreadyExists.into())
    }

    /// Private measurement lifetime. Address lookup uses only the original
    /// resolver; raw ECH records use a separately owned weak DNS leaf.
    pub fn measurement(bootstrap: Arc<dyn Resolver>, ipv6: bool) -> Self {
        let context = Self::runtime(ipv6);
        let _ = context
            .inner
            .as_ref()
            .unwrap()
            .source
            .set(Source::Measurement(bootstrap));
        context
    }

    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn bind_measurement_ech(&self, dns: &Arc<RuntimeDns>) -> io::Result<()> {
        self.inner
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?
            .measurement_ech
            .set(Arc::downgrade(dns))
            .map_err(|_| io::ErrorKind::AlreadyExists.into())
    }

    pub(crate) fn resolve_ech<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Vec<u8>>> + Send + 'a>> {
        // DNS transports can establish a TLS node whose ECH query returns to
        // this boundary; erase the recursive future without spawning a task.
        Box::pin(async move {
            let name =
                canonicalize_name(name).map_err(|_| io::Error::other("invalid ECH query name"))?;
            let state = self
                .inner
                .as_ref()
                .ok_or_else(|| io::Error::other("ECH DNS source unavailable"))?;
            let dns = match state.source.get() {
                Some(Source::Runtime(dns)) => dns.as_ref().and_then(Weak::upgrade),
                Some(Source::Measurement(_)) => state.measurement_ech.get().and_then(Weak::upgrade),
                None => None,
            }
            .ok_or_else(|| io::Error::other("ECH DNS source unavailable"))?;
            let deadline = inherited_deadline(deadline);
            let key = (
                Arc::as_ptr(state) as usize,
                ResolveRole::Proxy,
                65,
                name.clone(),
            );
            let mut active = ACTIVE.try_with(Clone::clone).unwrap_or(ActiveResolution {
                deadline,
                names: Vec::new(),
            });
            if deadline <= Instant::now() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if active.names.contains(&key) || active.names.len() >= MAX_RESOLUTION_DEPTH {
                return Err(io::Error::other("recursive ECH DNS dependency"));
            }
            active.deadline = deadline;
            active.names.push(key);
            let _waiter = crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Waiter,
            );
            tokio::select! { biased;
                () = state.cancel.cancelled() => Err(io::ErrorKind::Interrupted.into()),
                result = timeout_at(deadline, ACTIVE.scope(active, dns.query_proxy_ech(&name, deadline))) => {
                    if Instant::now() >= deadline {
                        Err(io::ErrorKind::TimedOut.into())
                    } else {
                        result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
                    }
                },
            }
        })
    }

    pub fn close(&self) {
        if let Some(inner) = &self.inner {
            inner.cancel.cancel();
        }
        if let Some(dns) = self.runtime_dns() {
            dns.begin_shutdown();
        }
    }

    pub(crate) fn runtime_dns(&self) -> Option<Arc<RuntimeDns>> {
        match self.inner.as_ref()?.source.get()? {
            Source::Runtime(Some(dns)) => dns.upgrade(),
            _ => None,
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.close();
        if let Some(dns) = self.runtime_dns() {
            dns.shutdown().await;
        }
    }

    /// Resolve only when the consuming protocol requires an IP. This does not
    /// mutate the logical destination used for HTTP Host, TLS SNI or routing.
    pub async fn resolve_ip(
        &self,
        target: &Destination,
        deadline: Instant,
    ) -> Result<SocketAddr, DispatchError> {
        self.resolve_addresses(target, deadline, ResolveRole::Business)
            .await?
            .into_iter()
            .next()
            .ok_or(DispatchError::HostUnreachable)
    }

    /// A raw-IP node cannot originate a family without a configured local IP.
    /// Keep the same business DNS role, policy ordering and absolute deadline.
    #[cfg(any(feature = "outbound-wireguard", feature = "outbound-masque"))]
    pub(crate) async fn resolve_local_family(
        &self,
        target: &Destination,
        deadline: Instant,
        ipv4: bool,
        ipv6: bool,
    ) -> Result<SocketAddr, DispatchError> {
        self.resolve_addresses(target, deadline, ResolveRole::Business)
            .await?
            .into_iter()
            .find(|address| if address.is_ipv4() { ipv4 } else { ipv6 })
            .ok_or(DispatchError::HostUnreachable)
    }

    #[cfg(any(feature = "outbound-wireguard", feature = "outbound-masque"))]
    pub(crate) fn ipv6_allowed(&self) -> bool {
        self.inner.as_ref().is_none_or(|state| state.ipv6)
    }

    #[cfg(any(feature = "outbound-wireguard", feature = "outbound-masque"))]
    pub(crate) async fn resolve_node_local(
        &self,
        target: &Destination,
        deadline: Instant,
        dns: &RuntimeDns,
        ipv4: bool,
        ipv6: bool,
    ) -> Result<SocketAddr, DispatchError> {
        self.resolve_addresses_via(target, deadline, ResolveRole::Business, Some(dns))
            .await?
            .into_iter()
            .find(|address| if address.is_ipv4() { ipv4 } else { ipv6 })
            .ok_or(DispatchError::HostUnreachable)
    }

    pub async fn resolve_proxy(
        &self,
        target: &Destination,
        deadline: Instant,
    ) -> Result<crate::dialer::ResolvedEndpoint, DispatchError> {
        let addresses = self
            .resolve_addresses(target, deadline, ResolveRole::Proxy)
            .await?;
        Ok(Self::endpoint(target, addresses))
    }

    pub(crate) async fn resolve_direct(
        &self,
        target: &Destination,
        deadline: Instant,
    ) -> Result<crate::dialer::ResolvedEndpoint, DispatchError> {
        let addresses = self
            .resolve_addresses(target, deadline, ResolveRole::Direct)
            .await?;
        Ok(Self::endpoint(target, addresses))
    }

    fn endpoint(
        target: &Destination,
        addresses: Vec<SocketAddr>,
    ) -> crate::dialer::ResolvedEndpoint {
        crate::dialer::ResolvedEndpoint {
            logical_host: match target {
                Destination::Domain { host, .. } => host.clone(),
                Destination::Ip(address) => address.ip().to_string(),
            },
            port: target.port(),
            addresses,
        }
    }

    async fn resolve_addresses(
        &self,
        target: &Destination,
        deadline: Instant,
        role: ResolveRole,
    ) -> Result<Vec<SocketAddr>, DispatchError> {
        self.resolve_addresses_via(target, deadline, role, None)
            .await
    }

    fn resolve_addresses_via<'a>(
        &'a self,
        target: &'a Destination,
        deadline: Instant,
        role: ResolveRole,
        node_dns: Option<&'a RuntimeDns>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<SocketAddr>, DispatchError>> + Send + 'a>,
    > {
        // Erase this future at the resolver boundary: DNS transports may resolve
        // their own endpoints through the same context.
        Box::pin(async move {
            let deadline = inherited_deadline(deadline);
            if deadline <= Instant::now() {
                return Err(DispatchError::TimedOut);
            }
            if self
                .inner
                .as_ref()
                .is_some_and(|inner| inner.cancel.is_cancelled())
            {
                return Err(DispatchError::NotAllowed);
            }
            if let Destination::Ip(address) = target {
                if !self.ip_version.permits(address.ip())
                    || address.port() == 0
                    || (address.is_ipv6() && self.inner.as_ref().is_some_and(|inner| !inner.ipv6))
                {
                    return Err(DispatchError::HostUnreachable);
                }
                return Ok(vec![*address]);
            }
            let Destination::Domain { host, port } = target else {
                unreachable!()
            };
            let host = canonicalize_name(host).map_err(|_| DispatchError::HostUnreachable)?;
            let inner = self.inner.as_ref();
            let source = inner.and_then(|inner| inner.source.get());
            if node_dns.is_none() && source.is_none() {
                return Err(unavailable());
            }
            let identity = node_dns.map_or_else(
                || Arc::as_ptr(inner.unwrap()) as usize,
                |dns| dns as *const RuntimeDns as usize,
            );
            let key = (identity, role, 0, host.clone());
            let mut active = ACTIVE.try_with(Clone::clone).unwrap_or(ActiveResolution {
                deadline,
                names: Vec::new(),
            });
            if active.names.contains(&key) {
                return Err(DispatchError::Other("recursive DNS dependency".into()));
            }
            if active.names.len() >= MAX_RESOLUTION_DEPTH {
                return Err(DispatchError::Other("DNS dependency depth exceeded".into()));
            }
            active.deadline = deadline;
            active.names.push(key);
            let _waiter = crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Waiter,
            );
            let decision = crate::config::RuleDecision::default();
            if let Some(inner) = inner {
                decision.set_cancellation(inner.cancel.clone());
            }
            decision.set_deadline(deadline.into_std());
            let lookup = async {
                decision.check()?;
                let addresses = if let Some(dns) = node_dns {
                    dns.resolve(&host)
                        .await
                        .map_err(runtime_error)?
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, *port))
                        .collect::<Vec<_>>()
                } else {
                    match source.expect("checked resolver source") {
                        Source::Runtime(dns) => {
                            let dns = dns
                                .as_ref()
                                .and_then(Weak::upgrade)
                                .ok_or_else(unavailable)?;
                            match role {
                                ResolveRole::Business => dns.resolve(&host).await,
                                ResolveRole::Proxy => dns.resolve_proxy(&host).await,
                                ResolveRole::Direct => dns.resolve_direct(&host).await,
                            }
                            .map_err(runtime_error)?
                            .into_iter()
                            .map(|ip| SocketAddr::new(ip, *port))
                            .collect::<Vec<_>>()
                        }
                        Source::Measurement(bootstrap) => {
                            let resolved = bootstrap
                                .resolve(&host, *port)
                                .await
                                .map_err(|_| DispatchError::HostUnreachable)?;
                            if resolved.logical_host != host
                                || resolved.port != *port
                                || resolved
                                    .addresses
                                    .iter()
                                    .any(|address| address.port() != *port)
                            {
                                return Err(DispatchError::HostUnreachable);
                            }
                            resolved.addresses
                        }
                    }
                };
                let mut addresses: Vec<_> = addresses
                    .into_iter()
                    .filter(|address| inner.is_none_or(|inner| inner.ipv6) || address.is_ipv4())
                    .collect();
                self.ip_version.order(&mut addresses);
                if addresses.is_empty() {
                    Err(DispatchError::HostUnreachable)
                } else {
                    Ok(addresses)
                }
            };
            tokio::select! {
                biased;
                _ = async { if let Some(inner)=inner { inner.cancel.cancelled().await } else { std::future::pending::<()>().await } } => Err(DispatchError::NotAllowed),
                result = timeout_at(deadline, decision.scope(ACTIVE.scope(active, lookup))) => result.unwrap_or(Err(DispatchError::TimedOut)),
            }
        })
    }
}

fn runtime_error(error: super::runtime::RuntimeDnsError) -> DispatchError {
    match error {
        super::runtime::RuntimeDnsError::RuleEvaluation(failure) => {
            DispatchError::RuleEvaluation(failure)
        }
        _ => DispatchError::HostUnreachable,
    }
}

fn unavailable() -> DispatchError {
    DispatchError::Other("runtime DNS is unavailable".into())
}
