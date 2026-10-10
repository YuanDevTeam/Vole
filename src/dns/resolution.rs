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
    names: Vec<(usize, bool, String)>,
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

    /// Private measurement lifetime: no Running Session, RuntimeDns, listener,
    /// or system-fallback path is constructed by this context.
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

    pub fn close(&self) {
        if let Some(inner) = &self.inner {
            inner.cancel.cancel();
        }
    }

    /// Resolve only when the consuming protocol requires an IP. This does not
    /// mutate the logical destination used for HTTP Host, TLS SNI or routing.
    pub async fn resolve_ip(
        &self,
        target: &Destination,
        deadline: Instant,
    ) -> Result<SocketAddr, DispatchError> {
        self.resolve_addresses(target, deadline, false)
            .await?
            .into_iter()
            .next()
            .ok_or(DispatchError::HostUnreachable)
    }

    /// A raw-IP node cannot originate a family without a configured local IP.
    /// Keep the same business DNS role, policy ordering and absolute deadline.
    #[cfg(feature = "outbound-wireguard")]
    pub(crate) async fn resolve_local_family(
        &self,
        target: &Destination,
        deadline: Instant,
        ipv4: bool,
        ipv6: bool,
    ) -> Result<SocketAddr, DispatchError> {
        self.resolve_addresses(target, deadline, false)
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
        let addresses = self.resolve_addresses(target, deadline, true).await?;
        Ok(crate::dialer::ResolvedEndpoint {
            logical_host: match target {
                Destination::Domain { host, .. } => host.clone(),
                Destination::Ip(address) => address.ip().to_string(),
            },
            port: target.port(),
            addresses,
        })
    }

    async fn resolve_addresses(
        &self,
        target: &Destination,
        deadline: Instant,
        proxy: bool,
    ) -> Result<Vec<SocketAddr>, DispatchError> {
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
        let inner = self.inner.as_ref().ok_or_else(unavailable)?;
        let source = inner.source.get().ok_or_else(unavailable)?;
        let key = (Arc::as_ptr(inner) as usize, proxy, host.clone());
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
        let lookup = async {
            let addresses = match source {
                Source::Runtime(dns) => {
                    let dns = dns
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .ok_or_else(unavailable)?;
                    if proxy {
                        dns.resolve_proxy(&host).await
                    } else {
                        dns.resolve(&host).await
                    }
                    .map_err(|_| DispatchError::HostUnreachable)?
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
            };
            let mut addresses: Vec<_> = addresses
                .into_iter()
                .filter(|address| inner.ipv6 || address.is_ipv4())
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
            _ = inner.cancel.cancelled() => Err(DispatchError::NotAllowed),
            result = timeout_at(deadline, ACTIVE.scope(active, lookup)) => result.unwrap_or(Err(DispatchError::TimedOut)),
        }
    }
}

fn unavailable() -> DispatchError {
    DispatchError::Other("runtime DNS is unavailable".into())
}
