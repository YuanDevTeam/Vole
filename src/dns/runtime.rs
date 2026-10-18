//! Bounded runtime DNS service with Mihomo-compatible nameserver egress.
//!
//! Upstream domains use a separate bootstrap resolver. DNS questions never
//! become upstream routing targets; fragments select the upstream connection.

#[cfg(test)]
#[path = "tests_encrypted.rs"]
mod encrypted_tests;
#[cfg(all(test, feature = "dns-quic"))]
#[path = "tests_quic.rs"]
mod quic_tests;

#[cfg(test)]
#[path = "tests_ech.rs"]
mod ech_tests;

use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Mutex, RwLock, Semaphore, watch},
    time::{Instant as TokioInstant, sleep_until, timeout_at},
};
use tokio_util::sync::CancellationToken;

use super::policy::NameserverPolicies;
use super::{
    CacheValue, ClassifiedDnsQuery, DnsCache, DnsError, DnsMessage, DnsQueryKind, MAX_ANSWERS,
    MAX_MESSAGE_SIZE, MAX_REDIR_HOST_ENTRIES, MAX_RESPONSE_RECORDS, MIN_TTL_SECS, QueryType,
    RecordData, RedirHostHints, ValidatedOpaqueResponse, WireQuestion, build_query,
    canonicalize_name, classify_query, parse_query, parse_response, synthesize_servfail_response,
    validate_opaque_response, validate_response_identity,
};
use crate::{
    config::{
        DnsAddress, DnsConfig, DnsNameserver, DnsNameserverPolicy, DnsRoute, DnsTransport,
        HostValue, Network, RouteTargetId, RuleAction,
    },
    dispatch::{BoxStream, DispatchError, Dispatcher},
    resources::{ResourceActivity, ResourceActivityGuard, RuntimeResourceStats},
    routing::{
        EmptyGeoMatcher, GeoMatcher, ProgramEvaluation, ProxyDispatchers, RoutingContext, RuleSet,
        RuleTargetEffect,
    },
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
};

fn system_ech_config() -> DnsConfig {
    let server = DnsNameserver {
        transport: DnsTransport::Udp,
        address: DnsAddress::Source(crate::config::DnsSource::System),
        port: 53,
        route: DnsRoute::Direct,
        path: None,
        http_auth: None,
        options: Default::default(),
    };
    DnsConfig {
        enable: true,
        nameservers: vec![server.clone()],
        default_nameservers: vec![server],
        cache_max_size: 64,
        ..Default::default()
    }
}

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_RETRY_DELAY: Duration = Duration::from_secs(1);
const TCP_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_POOL_MAX_IDLE: usize = 4;
const TCP_POOL_MAX_IDLE_PER_KEY: usize = 2;
const TCP_POOL_FINAL_EVENT: &str = "runtime_dns_tcp_pool_final";
const MAX_IGNORED_UDP_RESPONSES: usize = 3;
const DNS_CLASS_IN: u16 = 1;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

fn dot_reuse_disabled(nameserver: &DnsNameserver) -> bool {
    nameserver.transport == DnsTransport::Tls && nameserver.options.disable_reuse
}

/// Errors returned by the runtime DNS service.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RuntimeDnsError {
    #[error("runtime DNS is disabled")]
    Disabled,
    #[error("DNS rule evaluation failed: {0}")]
    RuleEvaluation(#[from] crate::config::MatchFailure),
    #[error("runtime DNS has no nameserver")]
    NoNameserver,
    #[error("invalid DNS query: {0}")]
    InvalidQuery(#[source] DnsError),
    #[error("invalid DNS response: {0}")]
    InvalidResponse(#[source] DnsError),
    #[error("DNS cache rejected a validated response: {0}")]
    Cache(#[source] DnsError),
    #[error("all runtime DNS nameservers failed: {last_error}")]
    UpstreamsExhausted { last_error: Box<str> },
    #[error("runtime DNS returned response code {0}")]
    ResponseCode(u8),
}

/// Per-instance runtime resolver. Callers should normally share one instance
/// through `Arc<RuntimeDns>`.
pub struct RuntimeDns {
    enabled: bool,
    ipv6: bool,
    prefer_h3: bool,
    ipv6_timeout: Duration,
    nameservers: Box<[DnsNameserver]>,
    hosts: super::hosts::Hosts,
    fallback: crate::config::DnsFallbackConfig,
    fallback_filter: super::fallback::Filter,
    fake_config: crate::config::FakeIpConfig,
    fake_filter: super::fake_ip::Filter,
    fake_pools: Option<Arc<super::fake_ip::FakePools>>,
    bootstrap: Option<Arc<RuntimeDns>>,
    node_bootstrap: Option<super::resolution::ResolutionContext>,
    proxy_resolver: Option<Arc<RuntimeDns>>,
    direct_resolver: Option<Arc<RuntimeDns>>,
    ech_system_resolver: Option<Arc<RuntimeDns>>,
    nameserver_policies: Box<[DnsNameserverPolicy]>,
    policy_index: NameserverPolicies,
    geo_matcher: Arc<dyn GeoMatcher>,
    egress: DnsEgress,
    cache: Mutex<DnsCache>,
    cache_epoch: Arc<RwLock<u64>>,
    sources: Arc<super::source::NetworkSources>,
    source_dialer: Option<crate::dialer::Dialer>,
    source_exclusions: super::source::SourceExclusions,
    // Hint lookup and insertion are bounded synchronous work. Keep this
    // shared TUN hot path free of asynchronous mutex scheduling.
    hints: Option<Arc<StdMutex<RedirHostHints>>>,
    singleflight: Arc<SingleflightRegistry>,
    tcp_pool: Arc<TcpConnectionPool>,
    next_id: AtomicU16,
    resource_stats: RuntimeResourceStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DnsEgressKey {
    Single,
    Direct,
    Route(RouteTargetId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpPoolKey {
    upstream: DnsNameserver,
    endpoint: SocketAddr,
    egress: DnsEgressKey,
    source_generation: u64,
    source_binding: Option<super::source::DnsBinding>,
}

struct TcpConnectionPool {
    security: crate::security::SecurityContext,
    http2: Arc<super::http2::Pool<TcpPoolKey>>,
    #[cfg(feature = "dns-quic")]
    quic: Arc<super::quic::Pool<TcpPoolKey>>,
    #[cfg(feature = "dns-quic")]
    http_tcp_choices: StdMutex<Vec<(TcpPoolKey, TokioInstant)>>,
    state: Mutex<TcpPoolState>,
    max_idle: usize,
    max_idle_per_key: usize,
    reaper_running: AtomicBool,
    reaper_cancel: CancellationToken,
    stats: Arc<TcpPoolStats>,
}

#[derive(Default)]
struct TcpPoolState {
    idle: Vec<IdleTcpConnection>,
}

struct IdleTcpConnection {
    key: TcpPoolKey,
    connection: PooledTcpConnection,
    idle_since: TokioInstant,
}

struct PooledTcpConnection {
    stream: BoxStream,
    negotiated_alpn: Option<Vec<u8>>,
    _slot: TcpPhysicalSlot,
    _observation: crate::resources::observation::Guard,
}

struct TcpPhysicalSlot {
    stats: Arc<TcpPoolStats>,
}

struct TcpLease {
    key: TcpPoolKey,
    connection: Option<PooledTcpConnection>,
    reused: bool,
    busy: Option<TcpBusyGuard>,
    stats: Arc<TcpPoolStats>,
}

struct TcpBusyGuard {
    stats: Arc<TcpPoolStats>,
}

struct TcpConnectingGuard {
    stats: Arc<TcpPoolStats>,
}

#[derive(Default)]
struct TcpPoolStats {
    idle_limit: usize,
    idle_per_key_limit: usize,
    current_physical: AtomicUsize,
    peak_physical: AtomicUsize,
    current_busy: AtomicUsize,
    peak_busy: AtomicUsize,
    current_connecting: AtomicUsize,
    peak_connecting: AtomicUsize,
    current_idle: AtomicUsize,
    peak_idle: AtomicUsize,
    physical_opens: AtomicU64,
    reuse_hits: AtomicU64,
    stale_retries: AtomicU64,
    discards: AtomicU64,
    idle_expirations: AtomicU64,
    idle_evictions: AtomicU64,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpPoolSnapshot {
    current_physical: usize,
    peak_physical: usize,
    current_busy: usize,
    peak_busy: usize,
    current_connecting: usize,
    peak_connecting: usize,
    current_idle: usize,
    peak_idle: usize,
    physical_opens: u64,
    reuse_hits: u64,
    stale_retries: u64,
    discards: u64,
    idle_expirations: u64,
    idle_evictions: u64,
}

impl TcpConnectionPool {
    fn new(security: crate::security::SecurityContext) -> Arc<Self> {
        let max_idle = TCP_POOL_MAX_IDLE;
        let max_idle_per_key = TCP_POOL_MAX_IDLE_PER_KEY;
        let mut stats = TcpPoolStats::default();
        stats.idle_limit = max_idle;
        stats.idle_per_key_limit = max_idle_per_key;
        Arc::new(Self {
            security,
            http2: super::http2::Pool::new(),
            #[cfg(feature = "dns-quic")]
            quic: super::quic::Pool::new(),
            #[cfg(feature = "dns-quic")]
            http_tcp_choices: StdMutex::new(Vec::new()),
            state: Mutex::new(TcpPoolState::default()),
            max_idle,
            max_idle_per_key,
            reaper_running: AtomicBool::new(false),
            reaper_cancel: CancellationToken::new(),
            stats: Arc::new(stats),
        })
    }

    async fn checkout_for(
        self: &Arc<Self>,
        nameserver: &ResolvedNameserver,
        resolve: impl FnOnce(&TcpPoolState) -> Result<(DnsEgressKey, Arc<dyn Dispatcher>), AttemptError>,
    ) -> Result<TcpLease, AttemptError> {
        if self.http2.is_closed() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        let (key, egress, connection, expired) = {
            let mut state = self.state.lock().await;
            let expired = self.take_expired_locked(&mut state, TokioInstant::now());
            // Resolve and remove an idle connection in one transaction. The
            // callback commits a group only when this stable route key is absent.
            let (egress_key, egress) = match resolve(&state) {
                Ok(route) => route,
                Err(error) => {
                    self.record_idle_locked(&state);
                    return Err(error);
                }
            };
            let key = TcpPoolKey {
                upstream: nameserver.config.clone(),
                endpoint: nameserver.endpoint(),
                egress: egress_key,
                source_generation: nameserver.source_generation,
                source_binding: nameserver.source_binding.clone(),
            };
            let index = state
                .idle
                .iter()
                .enumerate()
                .filter(|(_, idle)| !dot_reuse_disabled(&nameserver.config) && idle.key == key)
                .max_by_key(|(_, idle)| idle.idle_since)
                .map(|(index, _)| index);
            let connection = index.map(|index| state.idle.swap_remove(index).connection);
            self.record_idle_locked(&state);
            (key, egress, connection, expired)
        };
        drop(expired);
        if let Some(connection) = connection {
            self.stats.reuse_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(TcpLease {
                key,
                connection: Some(connection),
                reused: true,
                busy: Some(TcpBusyGuard::new(Arc::clone(&self.stats))),
                stats: Arc::clone(&self.stats),
            });
        }
        let connection = self.open_connection(nameserver, &egress).await?;
        Ok(TcpLease {
            key,
            connection: Some(connection),
            reused: false,
            busy: Some(TcpBusyGuard::new(Arc::clone(&self.stats))),
            stats: Arc::clone(&self.stats),
        })
    }

    #[cfg(feature = "dns-quic")]
    fn tcp_selected(&self, key: &TcpPoolKey) -> bool {
        let mut choices = self.http_tcp_choices.lock().unwrap();
        let now = TokioInstant::now();
        choices.retain(|(_, used)| now.duration_since(*used) < TCP_POOL_IDLE_TIMEOUT);
        if let Some((_, used)) = choices.iter_mut().find(|(candidate, _)| candidate == key) {
            *used = now;
            true
        } else {
            false
        }
    }

    #[cfg(feature = "dns-quic")]
    fn select_tcp(&self, key: TcpPoolKey) {
        let mut choices = self.http_tcp_choices.lock().unwrap();
        choices.retain(|(candidate, _)| *candidate != key);
        if choices.len() == TCP_POOL_MAX_IDLE {
            choices.remove(0);
        }
        choices.push((key, TokioInstant::now()));
    }

    #[cfg(feature = "dns-quic")]
    fn forget_tcp(&self, key: &TcpPoolKey) {
        self.http_tcp_choices
            .lock()
            .unwrap()
            .retain(|(candidate, _)| candidate != key);
    }

    async fn open_connection(
        &self,
        nameserver: &ResolvedNameserver,
        egress: &Arc<dyn Dispatcher>,
    ) -> Result<PooledTcpConnection, AttemptError> {
        if self.http2.is_closed() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }
        let slot = TcpPhysicalSlot::new(Arc::clone(&self.stats));
        let connecting = TcpConnectingGuard::new(Arc::clone(&self.stats));
        let stream = egress
            .connect_tcp(StreamSession {
                metadata: Default::default(),
                inbound: InboundKind::InternalDns,
                source: internal_source(nameserver.endpoint.ip()),
                destination: Destination::Ip(nameserver.endpoint()),
                sniffed_domain: None,
            })
            .await?;
        let (stream, negotiated_alpn) = if matches!(
            nameserver.transport,
            DnsTransport::Tls | DnsTransport::Https
        ) {
            let options = crate::security::TlsClientOptions {
                certificate: crate::config::TlsCertificatePolicy {
                    verification_name: nameserver.options.verification_name.clone(),
                    skip_cert_verify: nameserver.options.skip_cert_verify,
                    fingerprint: None,
                },
                alpn: if nameserver.transport == DnsTransport::Https {
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                } else {
                    Vec::new()
                },
                ..Default::default()
            };
            crate::security::StandardTlsClient::with_options(
                &self.security,
                nameserver.address.to_string(),
                options,
                0,
                64 * 1024,
            )?
            .connect_negotiated(stream)
            .await?
        } else {
            (stream, None)
        };
        drop(connecting);
        self.stats.physical_opens.fetch_add(1, Ordering::Relaxed);
        Ok(PooledTcpConnection {
            stream,
            negotiated_alpn,
            _slot: slot,
            _observation: crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Pool,
            ),
        })
    }

    async fn replace_stale(
        &self,
        lease: &mut TcpLease,
        nameserver: &ResolvedNameserver,
        egress: &Arc<dyn Dispatcher>,
    ) -> Result<(), AttemptError> {
        if lease.connection.take().is_some() {
            lease.stats.discards.fetch_add(1, Ordering::Relaxed);
        }
        lease.busy.take();
        lease.reused = false;
        self.stats.stale_retries.fetch_add(1, Ordering::Relaxed);
        lease.connection = Some(self.open_connection(nameserver, egress).await?);
        lease.busy = Some(TcpBusyGuard::new(Arc::clone(&self.stats)));
        Ok(())
    }

    async fn check_in(self: &Arc<Self>, mut lease: TcpLease) {
        let Some(connection) = lease.connection.take() else {
            return;
        };
        lease.busy.take();
        if self.http2.is_closed() || self.max_idle == 0 || dot_reuse_disabled(&lease.key.upstream) {
            drop(connection);
            return;
        }

        let mut state = self.state.lock().await;
        let now = TokioInstant::now();
        let mut discarded = Vec::new();
        discarded.extend(self.take_expired_locked(&mut state, now));

        while state
            .idle
            .iter()
            .filter(|idle| idle.key == lease.key)
            .count()
            >= self.max_idle_per_key
        {
            let Some(index) = oldest_idle_index_for_key(&state.idle, lease.key.clone()) else {
                break;
            };
            discarded.push(state.idle.swap_remove(index).connection);
            self.stats.idle_evictions.fetch_add(1, Ordering::Relaxed);
        }
        while state.idle.len() >= self.max_idle {
            let Some(index) = oldest_idle_index(&state.idle) else {
                break;
            };
            discarded.push(state.idle.swap_remove(index).connection);
            self.stats.idle_evictions.fetch_add(1, Ordering::Relaxed);
        }

        state.idle.push(IdleTcpConnection {
            key: lease.key.clone(),
            connection,
            idle_since: now,
        });
        self.record_idle_locked(&state);
        drop(state);
        drop(discarded);
        self.ensure_reaper();
    }

    fn take_expired_locked(
        &self,
        state: &mut TcpPoolState,
        now: TokioInstant,
    ) -> Vec<PooledTcpConnection> {
        let mut expired = Vec::new();
        let mut index = 0;
        while index < state.idle.len() {
            if now.duration_since(state.idle[index].idle_since) >= TCP_POOL_IDLE_TIMEOUT {
                expired.push(state.idle.swap_remove(index).connection);
            } else {
                index += 1;
            }
        }
        if !expired.is_empty() {
            self.stats
                .idle_expirations
                .fetch_add(expired.len() as u64, Ordering::Relaxed);
        }
        expired
    }

    fn record_idle_locked(&self, state: &TcpPoolState) {
        let idle = state.idle.len();
        self.stats.current_idle.store(idle, Ordering::Release);
        self.stats.peak_idle.fetch_max(idle, Ordering::AcqRel);
    }

    fn ensure_reaper(self: &Arc<Self>) {
        if self
            .reaper_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        crate::resources::observation::spawn(Self::reap_idle(
            Arc::downgrade(self),
            self.reaper_cancel.clone(),
        ));
    }

    async fn reap_idle(pool: Weak<Self>, cancellation: CancellationToken) {
        loop {
            let Some(pool) = pool.upgrade() else {
                return;
            };
            let (next_expiration, expired) = {
                let mut state = pool.state.lock().await;
                let now = TokioInstant::now();
                let expired = pool.take_expired_locked(&mut state, now);
                let next_expiration = state
                    .idle
                    .iter()
                    .map(|idle| idle.idle_since + TCP_POOL_IDLE_TIMEOUT)
                    .min();
                pool.record_idle_locked(&state);
                if next_expiration.is_none() {
                    pool.reaper_running.store(false, Ordering::Release);
                }
                (next_expiration, expired)
            };
            drop(expired);
            let Some(next_expiration) = next_expiration else {
                return;
            };
            drop(pool);
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return,
                () = sleep_until(next_expiration) => {}
            }
        }
    }

    #[cfg(test)]
    fn snapshot(&self) -> TcpPoolSnapshot {
        TcpPoolSnapshot {
            current_physical: self.stats.current_physical.load(Ordering::Acquire),
            peak_physical: self.stats.peak_physical.load(Ordering::Acquire),
            current_busy: self.stats.current_busy.load(Ordering::Acquire),
            peak_busy: self.stats.peak_busy.load(Ordering::Acquire),
            current_connecting: self.stats.current_connecting.load(Ordering::Acquire),
            peak_connecting: self.stats.peak_connecting.load(Ordering::Acquire),
            current_idle: self.stats.current_idle.load(Ordering::Acquire),
            peak_idle: self.stats.peak_idle.load(Ordering::Acquire),
            physical_opens: self.stats.physical_opens.load(Ordering::Acquire),
            reuse_hits: self.stats.reuse_hits.load(Ordering::Acquire),
            stale_retries: self.stats.stale_retries.load(Ordering::Acquire),
            discards: self.stats.discards.load(Ordering::Acquire),
            idle_expirations: self.stats.idle_expirations.load(Ordering::Acquire),
            idle_evictions: self.stats.idle_evictions.load(Ordering::Acquire),
        }
    }
}

impl Drop for TcpConnectionPool {
    fn drop(&mut self) {
        self.http2.close();
        #[cfg(feature = "dns-quic")]
        self.quic.close();
        self.reaper_cancel.cancel();
        let idle = std::mem::take(&mut self.state.get_mut().idle);
        self.stats.current_idle.store(0, Ordering::Release);
        drop(idle);
    }
}

impl TcpPhysicalSlot {
    fn new(stats: Arc<TcpPoolStats>) -> Self {
        let current = stats.current_physical.fetch_add(1, Ordering::AcqRel) + 1;
        stats.peak_physical.fetch_max(current, Ordering::AcqRel);
        Self { stats }
    }
}

impl TcpBusyGuard {
    fn new(stats: Arc<TcpPoolStats>) -> Self {
        let current = stats.current_busy.fetch_add(1, Ordering::AcqRel) + 1;
        stats.peak_busy.fetch_max(current, Ordering::AcqRel);
        Self { stats }
    }
}

impl Drop for TcpBusyGuard {
    fn drop(&mut self) {
        self.stats.current_busy.fetch_sub(1, Ordering::AcqRel);
    }
}

impl TcpConnectingGuard {
    fn new(stats: Arc<TcpPoolStats>) -> Self {
        let current = stats.current_connecting.fetch_add(1, Ordering::AcqRel) + 1;
        stats.peak_connecting.fetch_max(current, Ordering::AcqRel);
        Self { stats }
    }
}

impl Drop for TcpConnectingGuard {
    fn drop(&mut self) {
        self.stats.current_connecting.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for TcpLease {
    fn drop(&mut self) {
        if self.connection.is_some() {
            self.stats.discards.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for TcpPhysicalSlot {
    fn drop(&mut self) {
        self.stats.current_physical.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for TcpPoolStats {
    fn drop(&mut self) {
        tracing::info!(
            idle_limit = self.idle_limit,
            idle_per_key_limit = self.idle_per_key_limit,
            current_physical = self.current_physical.load(Ordering::Acquire),
            peak_physical = self.peak_physical.load(Ordering::Acquire),
            current_busy = self.current_busy.load(Ordering::Acquire),
            peak_busy = self.peak_busy.load(Ordering::Acquire),
            current_connecting = self.current_connecting.load(Ordering::Acquire),
            peak_connecting = self.peak_connecting.load(Ordering::Acquire),
            current_idle = self.current_idle.load(Ordering::Acquire),
            peak_idle = self.peak_idle.load(Ordering::Acquire),
            physical_opens = self.physical_opens.load(Ordering::Acquire),
            reuse_hits = self.reuse_hits.load(Ordering::Acquire),
            stale_retries = self.stale_retries.load(Ordering::Acquire),
            discards = self.discards.load(Ordering::Acquire),
            idle_expirations = self.idle_expirations.load(Ordering::Acquire),
            idle_evictions = self.idle_evictions.load(Ordering::Acquire),
            event = TCP_POOL_FINAL_EVENT,
            "runtime DNS TCP pool released"
        );
    }
}

fn oldest_idle_index(idle: &[IdleTcpConnection]) -> Option<usize> {
    idle.iter()
        .enumerate()
        .min_by_key(|(_, connection)| connection.idle_since)
        .map(|(index, _)| index)
}

fn oldest_idle_index_for_key(idle: &[IdleTcpConnection], key: TcpPoolKey) -> Option<usize> {
    idle.iter()
        .enumerate()
        .filter(|(_, connection)| connection.key == key)
        .min_by_key(|(_, connection)| connection.idle_since)
        .map(|(index, _)| index)
}

type SharedDnsResult = Result<Arc<[u8]>, RuntimeDnsError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SingleflightKey {
    question: WireQuestion,
    semantics_digest: [u8; 32],
    epoch: u64,
}

impl SingleflightKey {
    fn new(query: &ClassifiedDnsQuery, epoch: u64) -> Self {
        Self {
            question: query.question.clone(),
            semantics_digest: query.semantics_digest,
            epoch,
        }
    }
}

#[derive(Debug, Clone)]
enum FlightUpdate {
    Pending,
    Complete(SharedDnsResult),
    Retry,
}

#[derive(Debug)]
struct FlightState {
    updates: watch::Sender<FlightUpdate>,
}

#[derive(Debug)]
struct SingleflightRegistry {
    flights: StdMutex<HashMap<SingleflightKey, Arc<FlightState>>>,
    resource_stats: RuntimeResourceStats,
}

enum FlightRole {
    Leader(FlightLeaderGuard),
    Follower(watch::Receiver<FlightUpdate>),
}

struct FlightLeaderGuard {
    registry: Arc<SingleflightRegistry>,
    key: SingleflightKey,
    state: Arc<FlightState>,
    activity: Option<ResourceActivityGuard>,
    completed: bool,
}

impl SingleflightRegistry {
    fn new(resource_stats: RuntimeResourceStats) -> Arc<Self> {
        Arc::new(Self {
            flights: StdMutex::new(HashMap::new()),
            resource_stats,
        })
    }

    fn join(self: &Arc<Self>, key: SingleflightKey) -> FlightRole {
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = flights.get(&key).cloned() {
            drop(flights);
            self.resource_stats.singleflight_join();
            return FlightRole::Follower(state.updates.subscribe());
        }

        let (updates, _receiver) = watch::channel(FlightUpdate::Pending);
        let state = Arc::new(FlightState { updates });
        flights.insert(key.clone(), Arc::clone(&state));
        drop(flights);
        FlightRole::Leader(FlightLeaderGuard {
            registry: Arc::clone(self),
            key,
            state,
            activity: Some(self.resource_stats.begin(ResourceActivity::Singleflight)),
            completed: false,
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    fn follower_count(&self) -> usize {
        self.flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(|state| state.updates.receiver_count())
            .sum()
    }
}

impl FlightLeaderGuard {
    fn complete(mut self, result: SharedDnsResult) {
        self.state
            .updates
            .send_replace(FlightUpdate::Complete(result));
        self.remove_current();
        self.completed = true;
        self.activity.take();
    }

    fn remove_current(&self) {
        let mut flights = self
            .registry
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if flights
            .get(&self.key)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            flights.remove(&self.key);
        }
    }
}

impl Drop for FlightLeaderGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.state.updates.send_replace(FlightUpdate::Retry);
        self.remove_current();
    }
}

async fn wait_for_flight(mut updates: watch::Receiver<FlightUpdate>) -> Option<SharedDnsResult> {
    loop {
        let update = updates.borrow().clone();
        match update {
            FlightUpdate::Complete(result) => return Some(result),
            FlightUpdate::Retry => return None,
            FlightUpdate::Pending => {}
        }
        if updates.changed().await.is_err() {
            return None;
        }
    }
}

/// Tracks one runtime-DNS query. The deadline begins before a TUN caller
/// creates the query task.
pub(crate) struct DnsQueryPermit {
    _activity: ResourceActivityGuard,
    deadline: TokioInstant,
    decision: crate::config::RuleDecision,
}

impl DnsQueryPermit {
    #[cfg(feature = "tun")]
    pub(crate) fn with_cancellation(self, token: tokio_util::sync::CancellationToken) -> Self {
        self.decision.set_cancellation(token);
        self
    }
}

/// One DNS wire response that can retain its query observation until the caller
/// has completed framing or TUN delivery.
pub(crate) struct DnsWireResponse {
    wire: Vec<u8>,
    _permit: Option<DnsQueryPermit>,
}

impl DnsWireResponse {
    fn tracked(wire: Vec<u8>, permit: DnsQueryPermit) -> Self {
        Self {
            wire,
            _permit: Some(permit),
        }
    }

    #[must_use]
    pub(crate) fn wire(&self) -> &[u8] {
        &self.wire
    }

    fn into_wire(self) -> Vec<u8> {
        self.wire
    }

    #[cfg(test)]
    pub(crate) fn test_untracked(wire: Vec<u8>) -> Self {
        Self {
            wire,
            _permit: None,
        }
    }
}

#[derive(Clone, Copy)]
enum FailureMode {
    WireServfail,
    BoundedError,
}

#[derive(Clone)]
enum DnsEgress {
    /// Kept for focused unit tests and embedders that deliberately provide one
    /// already-selected dispatcher.
    Single(Arc<dyn Dispatcher>),
    Routed {
        proxies: ProxyDispatchers,
        direct: Arc<dyn Dispatcher>,
        rules: Arc<RuleSet>,
    },
}

impl fmt::Debug for RuntimeDns {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDns")
            .field("enabled", &self.enabled)
            .field("ipv6", &self.ipv6)
            .field("nameservers", &self.nameservers)
            .field("nameserver_policies", &self.nameserver_policies)
            .field("domain_hints_enabled", &self.hints.is_some())
            .finish_non_exhaustive()
    }
}

impl RuntimeDns {
    pub(crate) fn network_sources(&self) -> Arc<super::source::NetworkSources> {
        self.sources.clone()
    }
    pub(crate) fn with_network_sources(
        mut self,
        dialer: crate::dialer::Dialer,
        exclusions: super::source::SourceExclusions,
    ) -> Self {
        self.sources = dialer.dns_sources();
        self.source_dialer = Some(dialer);
        self.source_exclusions = exclusions;
        self.share_cache_epoch(self.sources.epoch());
        self
    }
    pub(crate) fn with_mapping_from(mut self, previous: Option<&Self>) -> Self {
        if let Some(previous) = previous {
            self.hints = previous.hints.clone();
            self.sources = previous.sources.clone();
            self.share_cache_epoch(previous.cache_epoch.clone());
            if self.fake_config.enabled == previous.fake_config.enabled
                && self.fake_config.range == previous.fake_config.range
                && self.fake_config.range6 == previous.fake_config.range6
                && self.ipv6 == previous.ipv6
            {
                self.fake_pools = previous.fake_pools.clone();
            }
        }
        self
    }
    // Resource replacement consumes a freshly assembled tree. Release the
    // leaves' shared bootstrap references before mutating that owned node.
    fn share_cache_epoch(&mut self, epoch: Arc<RwLock<u64>>) {
        let mut roles = [
            self.proxy_resolver.take(),
            self.direct_resolver.take(),
            self.ech_system_resolver.take(),
        ];
        for role in roles.iter_mut().flatten() {
            Arc::get_mut(role)
                .expect("fresh DNS role is exclusively owned")
                .bootstrap = None;
        }
        if let Some(bootstrap) = &mut self.bootstrap {
            let bootstrap =
                Arc::get_mut(bootstrap).expect("fresh DNS bootstrap is exclusively owned");
            bootstrap.cache_epoch = epoch.clone();
            bootstrap.sources = self.sources.clone();
            bootstrap.source_dialer = self.source_dialer.clone();
            bootstrap.source_exclusions = self.source_exclusions.clone();
        }
        for role in roles.iter_mut().flatten() {
            let role = Arc::get_mut(role).expect("fresh DNS role is exclusively owned");
            role.cache_epoch = epoch.clone();
            role.sources = self.sources.clone();
            role.source_dialer = self.source_dialer.clone();
            role.source_exclusions = self.source_exclusions.clone();
            role.bootstrap = self.bootstrap.clone();
        }
        [
            self.proxy_resolver,
            self.direct_resolver,
            self.ech_system_resolver,
        ] = roles;
        self.cache_epoch = epoch;
    }

    /// Clears typed and wire results and redir-host hints for every DNS role.
    /// Fake-IP mappings, active queries and upstream connections stay live.
    /// Queries admitted before this boundary cannot refill cleared state.
    pub async fn flush_cache(&self) {
        let mut epoch = self.cache_epoch.write().await;
        // Advance before clearing so cancellation during shutdown cannot
        // allow an old leader to repopulate a partially cleared tree.
        *epoch = epoch.wrapping_add(1);
        self.clear_cache_tree().await;
    }

    pub(super) async fn clear_cache_tree(&self) {
        let mut pending = vec![self];
        let mut seen = HashSet::new();
        while let Some(resolver) = pending.pop() {
            if !seen.insert(std::ptr::from_ref(resolver) as usize) {
                continue;
            }
            resolver.cache.lock().await.clear();
            if let Some(hints) = &resolver.hints {
                hints
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear();
            }
            pending.extend(
                [
                    resolver.bootstrap.as_deref(),
                    resolver.proxy_resolver.as_deref(),
                    resolver.direct_resolver.as_deref(),
                    resolver.ech_system_resolver.as_deref(),
                ]
                .into_iter()
                .flatten(),
            );
        }
    }

    /// Retires multiplexed transports before outbound shutdown begins.
    pub(crate) fn begin_shutdown(&self) {
        let mut pending = vec![self];
        let mut seen = HashSet::new();
        while let Some(resolver) = pending.pop() {
            if !seen.insert(std::ptr::from_ref(resolver) as usize) {
                continue;
            }
            resolver.tcp_pool.http2.close();
            #[cfg(feature = "dns-quic")]
            resolver.tcp_pool.quic.close();
            #[cfg(feature = "dns-quic")]
            resolver.tcp_pool.http_tcp_choices.lock().unwrap().clear();
            resolver.tcp_pool.reaper_cancel.cancel();
            pending.extend(
                [
                    resolver.bootstrap.as_deref(),
                    resolver.proxy_resolver.as_deref(),
                    resolver.direct_resolver.as_deref(),
                    resolver.ech_system_resolver.as_deref(),
                ]
                .into_iter()
                .flatten(),
            );
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        let mut pending = vec![self];
        let mut seen = HashSet::new();
        while let Some(resolver) = pending.pop() {
            if !seen.insert(std::ptr::from_ref(resolver) as usize) {
                continue;
            }
            resolver.tcp_pool.http2.shutdown().await;
            #[cfg(feature = "dns-quic")]
            resolver.tcp_pool.quic.shutdown().await;
            let idle = {
                let mut state = resolver.tcp_pool.state.lock().await;
                let idle = std::mem::take(&mut state.idle);
                resolver.tcp_pool.record_idle_locked(&state);
                idle
            };
            drop(idle);
            pending.extend(
                [
                    resolver.bootstrap.as_deref(),
                    resolver.proxy_resolver.as_deref(),
                    resolver.direct_resolver.as_deref(),
                    resolver.ech_system_resolver.as_deref(),
                ]
                .into_iter()
                .flatten(),
            );
        }
    }

    pub(crate) fn with_fake_ip_store(mut self, root: Option<&std::path::Path>) -> io::Result<Self> {
        if self.enabled
            && self.fake_config.enabled
            && let Some(root) = root
        {
            self.fake_pools = Some(Arc::new(super::fake_ip::FakePools::open(
                &self.fake_config,
                self.ipv6,
                Some(&root.join("fake-ip.redb")),
            )?));
        }
        Ok(self)
    }

    pub(crate) fn recover_fake_ip(&self, address: IpAddr) -> io::Result<Option<String>> {
        self.fake_pools
            .as_ref()
            .map_or(Ok(None), |pool| pool.recover(address))
    }

    fn use_fake_ip(&self, host: &str) -> Result<bool, RuntimeDnsError> {
        if self.fake_pools.is_none() {
            return Ok(false);
        }
        let snapshot = self.geo_matcher.routing_snapshot();
        Ok(!self.fake_filter.skips(
            host,
            snapshot.as_deref().unwrap_or(self.geo_matcher.as_ref()),
            &crate::config::RuleDecision::default(),
        )?)
    }

    /// Creates a resolver whose upstream traffic uses one preselected
    /// dispatcher and no GeoData matcher. Production runtimes use
    /// [`Self::new_routed`].
    #[must_use]
    pub fn new(config: &DnsConfig, dispatcher: Arc<dyn Dispatcher>) -> Self {
        Self::new_with_geo_matcher(config, dispatcher, Arc::new(EmptyGeoMatcher))
    }

    /// A raw-IP node's private resolver uses its own data plane, while DNS
    /// server domains bootstrap through the Core's original proxy DNS role.
    #[cfg(any(feature = "outbound-wireguard", feature = "outbound-masque"))]
    pub(crate) fn new_for_node(
        config: &DnsConfig,
        dispatcher: Arc<dyn Dispatcher>,
        bootstrap: super::resolution::ResolutionContext,
        security: crate::security::SecurityContext,
    ) -> Self {
        let mut resolver = Self::assemble_leaf(
            config,
            DnsEgress::Single(dispatcher),
            Arc::new(EmptyGeoMatcher),
            config.cache_max_size,
            0,
            Arc::new(RwLock::new(0)),
            security,
        );
        resolver.node_bootstrap = Some(bootstrap);
        // No idle background reaper belongs to this private node resolver.
        // Queries remain caller-owned; the raw-IP engine owns transport stop.
        let pool = Arc::get_mut(&mut resolver.tcp_pool).expect("fresh node DNS pool");
        pool.max_idle = 0;
        pool.max_idle_per_key = 0;
        pool.http2.disable_idle();
        #[cfg(feature = "dns-quic")]
        pool.quic.disable_idle();
        let stats = Arc::get_mut(&mut pool.stats).expect("fresh node DNS counters");
        stats.idle_limit = 0;
        stats.idle_per_key_limit = 0;
        resolver
    }

    /// MASQUE keeps special system/DHCP sources physical. Share only an
    /// already protected runtime source and register the private cache without
    /// retaining that runtime or a retired resource generation.
    #[cfg(feature = "outbound-masque")]
    pub(crate) fn new_for_masque_node(
        config: &DnsConfig,
        dispatcher: Arc<dyn Dispatcher>,
        bootstrap: super::resolution::ResolutionContext,
        security: crate::security::SecurityContext,
    ) -> Arc<Self> {
        let physical = config
            .nameservers
            .iter()
            .any(|nameserver| matches!(nameserver.address, DnsAddress::Source(_)))
            .then(|| bootstrap.runtime_dns())
            .flatten();
        let mut resolver = Self::new_for_node(config, dispatcher, bootstrap, security);
        if let Some(physical) = physical.filter(|resolver| resolver.source_dialer.is_some()) {
            resolver.sources = physical.sources.clone();
            resolver.source_dialer = physical.source_dialer.clone();
            resolver.source_exclusions = physical.source_exclusions.clone();
            resolver.share_cache_epoch(physical.cache_epoch.clone());
        }
        let resolver = Arc::new(resolver);
        resolver.sources.register(&resolver);
        resolver
    }

    /// Creates a single-egress resolver with an explicit GeoData matcher.
    /// This is useful to embedders that need nameserver-policy without the
    /// built-in DIRECT/proxy dispatcher registry.
    #[must_use]
    pub fn new_with_geo_matcher(
        config: &DnsConfig,
        dispatcher: Arc<dyn Dispatcher>,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self::assemble(
            config,
            DnsEgress::Single(dispatcher),
            geo_matcher,
            config.cache_max_size,
            MAX_REDIR_HOST_ENTRIES,
            crate::security::SecurityContext::new(),
        )
    }

    /// Creates the routed resolver. `proxy` and `direct` must both sit below
    /// the business router.
    #[must_use]
    pub fn new_routed(
        config: &DnsConfig,
        proxy: Arc<dyn Dispatcher>,
        direct: Arc<dyn Dispatcher>,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self::new_routed_proxies(
            config,
            ProxyDispatchers::new(vec![proxy]).expect("single DNS proxy registry is valid"),
            direct,
            rules,
            geo_matcher,
        )
    }

    /// Creates the production routed resolver with the configured proxy graph.
    /// Every route already contains a checked `ProxyId`, so the DNS hot path
    /// performs only a checked registry lookup.
    #[must_use]
    pub fn new_routed_proxies(
        config: &DnsConfig,
        proxies: ProxyDispatchers,
        direct: Arc<dyn Dispatcher>,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
    ) -> Self {
        Self::new_routed_proxies_with_cache_limits(
            config,
            proxies,
            direct,
            rules,
            geo_matcher,
            config.cache_max_size,
            MAX_REDIR_HOST_ENTRIES,
        )
    }

    /// Creates a routed resolver with explicit retained-cache limits.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_routed_proxies_with_cache_limits(
        config: &DnsConfig,
        proxies: ProxyDispatchers,
        direct: Arc<dyn Dispatcher>,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
        address_cache_entries: usize,
        redir_host_entries: usize,
    ) -> Self {
        Self::new_routed_proxies_with_cache_limits_and_security(
            config,
            proxies,
            direct,
            rules,
            geo_matcher,
            address_cache_entries,
            redir_host_entries,
            crate::security::SecurityContext::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_routed_proxies_with_cache_limits_and_security(
        config: &DnsConfig,
        proxies: ProxyDispatchers,
        direct: Arc<dyn Dispatcher>,
        rules: RuleSet,
        geo_matcher: Arc<dyn GeoMatcher>,
        address_cache_entries: usize,
        redir_host_entries: usize,
        security: crate::security::SecurityContext,
    ) -> Self {
        debug_assert!(address_cache_entries != 0);
        Self::assemble(
            config,
            DnsEgress::Routed {
                proxies,
                direct,
                rules: Arc::new(rules),
            },
            geo_matcher,
            address_cache_entries,
            redir_host_entries,
            security,
        )
    }

    fn assemble(
        config: &DnsConfig,
        egress: DnsEgress,
        geo: Arc<dyn GeoMatcher>,
        cache: usize,
        hints: usize,
        security: crate::security::SecurityContext,
    ) -> Self {
        let sources = Arc::new(super::source::NetworkSources::default());
        let cache_epoch = sources.epoch();
        let mut bootstrap_config = config.clone();
        bootstrap_config.enable = true;
        bootstrap_config.fallback = crate::config::DnsFallbackConfig::default();
        bootstrap_config.nameservers = config.default_nameservers.clone();
        bootstrap_config.nameserver_policies.clear();
        let bootstrap = Arc::new(Self::assemble_leaf(
            &bootstrap_config,
            egress.clone(),
            geo.clone(),
            cache,
            0,
            cache_epoch.clone(),
            security.clone(),
        ));
        let mut root = Self::assemble_leaf(
            config,
            egress.clone(),
            geo.clone(),
            cache,
            hints,
            cache_epoch.clone(),
            security.clone(),
        );
        root.bootstrap = Some(bootstrap.clone());
        if config.enable && config.fake_ip.enabled {
            root.fake_pools = Some(Arc::new(
                super::fake_ip::FakePools::open(&config.fake_ip, config.ipv6, None)
                    .expect("validated fake-IP ranges"),
            ));
        }
        let role = |nameservers: &[DnsNameserver], policies: &[DnsNameserverPolicy]| {
            let mut role_config = config.clone();
            role_config.nameservers = nameservers.to_vec();
            role_config.fallback = crate::config::DnsFallbackConfig::default();
            role_config.nameserver_policies = policies.to_vec();
            let mut resolver = Self::assemble_leaf(
                &role_config,
                egress.clone(),
                geo.clone(),
                cache,
                0,
                cache_epoch.clone(),
                security.clone(),
            );
            resolver.bootstrap = Some(bootstrap.clone());
            Arc::new(resolver)
        };
        // A disabled address resolver still needs actual HTTPS records for
        // dynamic ECH. Use physical system metadata, never the default public
        // nameservers of an otherwise disabled DNS configuration.
        if !config.enable {
            let mut system = Self::assemble_leaf(
                &system_ech_config(),
                egress.clone(),
                Arc::new(EmptyGeoMatcher),
                64,
                0,
                cache_epoch.clone(),
                security.clone(),
            );
            let pool = Arc::get_mut(&mut system.tcp_pool).expect("fresh system ECH pool");
            pool.max_idle = 0;
            pool.max_idle_per_key = 0;
            pool.http2.disable_idle();
            #[cfg(feature = "dns-quic")]
            pool.quic.disable_idle();
            let stats = Arc::get_mut(&mut pool.stats).expect("fresh system ECH counters");
            stats.idle_limit = 0;
            stats.idle_per_key_limit = 0;
            root.ech_system_resolver = Some(Arc::new(system));
        }
        if !config.proxy_nameservers.is_empty() {
            root.proxy_resolver = Some(role(&config.proxy_nameservers, &config.proxy_policies));
        }
        if !config.direct_nameservers.is_empty() {
            root.direct_resolver = Some(role(
                &config.direct_nameservers,
                if config.direct_follow_policy {
                    &config.nameserver_policies
                } else {
                    &[]
                },
            ));
        }
        drop(bootstrap);
        root.sources = sources;
        root.share_cache_epoch(cache_epoch);
        root
    }

    fn assemble_leaf(
        config: &DnsConfig,
        egress: DnsEgress,
        geo_matcher: Arc<dyn GeoMatcher>,
        address_cache_entries: usize,
        redir_host_entries: usize,
        cache_epoch: Arc<RwLock<u64>>,
        security: crate::security::SecurityContext,
    ) -> Self {
        let resource_stats = RuntimeResourceStats::new("runtime_dns");
        Self {
            enabled: config.enable,
            ipv6: config.ipv6,
            prefer_h3: config.prefer_h3,
            ipv6_timeout: config.ipv6_timeout,
            hosts: super::hosts::Hosts::new(
                &config.hosts,
                config.use_hosts,
                config.use_system_hosts,
            ),
            fallback: config.fallback.clone(),
            fallback_filter: super::fallback::Filter::new(&config.fallback),
            fake_config: config.fake_ip.clone(),
            fake_filter: super::fake_ip::Filter::new(&config.fake_ip),
            fake_pools: None,
            bootstrap: None,
            node_bootstrap: None,
            proxy_resolver: None,
            direct_resolver: None,
            ech_system_resolver: None,
            nameservers: config.nameservers.clone().into_boxed_slice(),
            nameserver_policies: config.nameserver_policies.clone().into_boxed_slice(),
            policy_index: NameserverPolicies::new(&config.nameserver_policies),
            geo_matcher,
            egress,
            cache: Mutex::new(DnsCache::with_algorithm(
                address_cache_entries,
                config.cache_algorithm,
            )),
            cache_epoch,
            sources: Arc::new(super::source::NetworkSources::default()),
            source_dialer: None,
            source_exclusions: super::source::SourceExclusions::default(),
            hints: (redir_host_entries != 0).then(|| {
                Arc::new(StdMutex::new(RedirHostHints::with_max_entries(
                    redir_host_entries,
                )))
            }),
            singleflight: SingleflightRegistry::new(resource_stats.clone()),
            tcp_pool: TcpConnectionPool::new(security),
            next_id: AtomicU16::new(1),
            resource_stats,
        }
    }

    fn policy_for(
        &self,
        query: &ClassifiedDnsQuery,
    ) -> Result<Option<&[DnsNameserver]>, RuntimeDnsError> {
        let snapshot = self.geo_matcher.routing_snapshot();
        let geo = snapshot.as_deref().unwrap_or(self.geo_matcher.as_ref());
        Ok(self
            .policy_index
            .select(
                &query.question.name,
                &self.nameserver_policies,
                geo,
                &crate::config::RuleDecision::default(),
            )?
            .map(|index| self.nameserver_policies[index].nameservers.as_ref()))
    }

    fn nameservers_for(
        &self,
        query: &ClassifiedDnsQuery,
    ) -> Result<&[DnsNameserver], RuntimeDnsError> {
        Ok(self.policy_for(query)?.unwrap_or(&self.nameservers))
    }

    fn fallback_domain(&self, host: &str) -> Result<bool, RuntimeDnsError> {
        let snapshot = self.geo_matcher.routing_snapshot();
        Ok(self.fallback_filter.domain(
            host,
            snapshot.as_deref().unwrap_or(self.geo_matcher.as_ref()),
            &crate::config::RuleDecision::default(),
        )?)
    }

    fn accepts_primary(
        &self,
        result: &Result<(Vec<u8>, DnsMessage, bool), RuntimeDnsError>,
    ) -> bool {
        // Rule evaluation failures are terminal; selecting a fallback would hide them.
        if matches!(result, Err(RuntimeDnsError::RuleEvaluation(_))) {
            return true;
        }
        let Ok((_, response, _)) = result else {
            return false;
        };
        let Ok(answers) = matching_answer_set(response) else {
            return false;
        };
        let snapshot = self.geo_matcher.routing_snapshot();
        let geo = snapshot.as_deref().unwrap_or(self.geo_matcher.as_ref());
        !answers.addresses.is_empty()
            && answers
                .addresses
                .iter()
                .all(|ip| !self.fallback_filter.address(*ip, geo))
    }

    fn egress_for(
        &self,
        nameserver: &ResolvedNameserver,
        network: Network,
        reuse: impl Fn(DnsEgressKey) -> bool,
    ) -> Result<(DnsEgressKey, Arc<dyn Dispatcher>), AttemptError> {
        use crate::routing::proxy_group::InspectedRuleTarget;
        if let Some(physical) = &nameserver.physical {
            return Ok((DnsEgressKey::Direct, physical.clone()));
        }
        let DnsEgress::Routed {
            proxies,
            direct,
            rules,
        } = &self.egress
        else {
            let DnsEgress::Single(dispatcher) = &self.egress else {
                unreachable!()
            };
            return Ok((DnsEgressKey::Single, dispatcher.clone()));
        };
        let destination = match &nameserver.address {
            DnsAddress::Ip(_) => Destination::Ip(nameserver.endpoint()),
            DnsAddress::Domain(host) => {
                Destination::domain(host, nameserver.port).map_err(AttemptError::Io)?
            }
            DnsAddress::Source(_) => {
                return Err(AttemptError::Io(super::source::unavailable()));
            }
        };
        let inspect = |id| {
            proxies.inspect_rule_target(
                id,
                network == Network::Udp,
                !reuse(DnsEgressKey::Route(id)),
                Some(internal_source(nameserver.endpoint.ip())),
                Some(&destination),
                None,
            )
        };
        match nameserver.route {
            DnsRoute::Direct => Ok((DnsEgressKey::Direct, direct.clone())),
            DnsRoute::Route(id) => match inspect(id).map_err(AttemptError::Dispatch)? {
                InspectedRuleTarget::Egress(leaf) => Ok((DnsEgressKey::Route(id), leaf.dispatcher)),
                InspectedRuleTarget::Control(_) | InspectedRuleTarget::Unavailable => {
                    Err(AttemptError::Dispatch(DispatchError::NotAllowed))
                }
            },
            DnsRoute::Rules => {
                let mut context = RoutingContext::new(network, &destination)
                    .map_err(|_| AttemptError::Dispatch(DispatchError::HostUnreachable))?;
                context.pin_ip(nameserver.endpoint.ip());
                context.set_source(internal_source(nameserver.endpoint.ip()));
                let snapshot = self.geo_matcher.routing_snapshot();
                let geo = snapshot.as_deref().unwrap_or(self.geo_matcher.as_ref());
                let mut selected = None;
                let mut error = None;
                let evaluation =
                    rules.evaluate_program(&mut context, geo, None, None, |action, _| {
                        let RuleAction::Route(id) = action else {
                            return RuleTargetEffect::Accept;
                        };
                        match inspect(id) {
                            Ok(InspectedRuleTarget::Control(_)) if !rules.filters_udp() => {
                                error = Some(DispatchError::NotAllowed);
                                RuleTargetEffect::Accept
                            }
                            Ok(InspectedRuleTarget::Control(control)) => {
                                RuleTargetEffect::Control(control)
                            }
                            Ok(InspectedRuleTarget::Egress(leaf)) => {
                                selected = Some((DnsEgressKey::Route(id), leaf.dispatcher));
                                RuleTargetEffect::Accept
                            }
                            Ok(InspectedRuleTarget::Unavailable) if rules.filters_udp() => {
                                RuleTargetEffect::Skip
                            }
                            Ok(InspectedRuleTarget::Unavailable) => {
                                error = Some(DispatchError::NotAllowed);
                                RuleTargetEffect::Accept
                            }
                            Err(failure) => {
                                error = Some(failure);
                                RuleTargetEffect::Accept
                            }
                        }
                    });
                if let Some(error) = error {
                    return Err(AttemptError::Dispatch(error));
                }
                match evaluation {
                    ProgramEvaluation::Failed(failure) => {
                        Err(AttemptError::RuleEvaluation(failure))
                    }
                    ProgramEvaluation::Matched(rule_match) => match rule_match.action {
                        RuleAction::Route(_) => {
                            Ok(selected.expect("accepted DNS route owns a leaf"))
                        }
                        RuleAction::Direct => Ok((DnsEgressKey::Direct, direct.clone())),
                        RuleAction::Reject => {
                            Err(AttemptError::Dispatch(DispatchError::NotAllowed))
                        }
                    },
                    ProgramEvaluation::NeedsIpResolution(_) => {
                        Err(AttemptError::Dispatch(DispatchError::HostUnreachable))
                    }
                }
            }
        }
    }

    /// Resolves A and AAAA concurrently, retaining IPv4 first and waiting at
    /// most `dns.ipv6-timeout` for IPv6 after A completes. Dropping this future
    /// cancels both lookups; no detached query outlives its caller.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, RuntimeDnsError> {
        let decision = crate::config::RuleDecision::default();
        decision.check()?;
        let result = decision.scope(self.resolve_inner(host)).await;
        decision.check()?;
        result
    }

    async fn resolve_inner(&self, host: &str) -> Result<Vec<IpAddr>, RuntimeDnsError> {
        super::trace::record("resolve");
        let host = canonicalize_name(host).map_err(RuntimeDnsError::InvalidQuery)?;
        let host =
            match self
                .hosts
                .lookup(&host)
                .map_err(|_| RuntimeDnsError::UpstreamsExhausted {
                    last_error: "hosts alias cycle".into(),
                })? {
                HostValue::Addresses(mut addresses) => {
                    addresses.retain(|ip| self.ipv6 || ip.is_ipv4());
                    return Ok(addresses);
                }
                HostValue::Alias(host) => host,
                HostValue::Lan => {
                    return Err(RuntimeDnsError::UpstreamsExhausted {
                        last_error: "hosts snapshot unavailable".into(),
                    });
                }
            };
        if !self.enabled {
            use crate::dialer::Resolver;
            let endpoint = tokio::time::timeout(
                QUERY_TIMEOUT,
                crate::dialer::SystemResolver.resolve(&host, 53),
            )
            .await
            .map_err(|_| RuntimeDnsError::UpstreamsExhausted {
                last_error: "system resolver timed out".into(),
            })?
            .map_err(|_| RuntimeDnsError::UpstreamsExhausted {
                last_error: "system resolver failed".into(),
            })?;
            return Ok(endpoint
                .addresses
                .into_iter()
                .map(|address| address.ip())
                .filter(|ip| self.ipv6 || ip.is_ipv4())
                .collect());
        }
        let deadline = super::resolution::inherited_deadline(TokioInstant::now() + QUERY_TIMEOUT);
        let ipv4 = self.resolve_type(&host, QueryType::A, deadline);
        if !self.ipv6 {
            return match ipv4.await? {
                LookupResult::Positive(addresses) => Ok(addresses),
                LookupResult::NoData | LookupResult::NxDomain => Ok(Vec::new()),
            };
        }
        let ipv6 = self.resolve_type(&host, QueryType::Aaaa, deadline);
        tokio::pin!(ipv4, ipv6);
        let mut ipv6_result = None;
        let ipv4_result = tokio::select! {
            biased;
            result = &mut ipv4 => result,
            result = &mut ipv6 => {
                ipv6_result = Some(result);
                ipv4.await
            }
        };
        if ipv6_result.is_none() {
            let wait_until = TokioInstant::now()
                .checked_add(self.ipv6_timeout)
                .unwrap_or(deadline)
                .min(deadline);
            ipv6_result = timeout_at(wait_until, &mut ipv6).await.ok();
        }
        if let Err(RuntimeDnsError::RuleEvaluation(failure)) = &ipv4_result {
            return Err(RuntimeDnsError::RuleEvaluation(*failure));
        }
        if let Some(Err(RuntimeDnsError::RuleEvaluation(failure))) = &ipv6_result {
            return Err(RuntimeDnsError::RuleEvaluation(*failure));
        }
        let mut addresses = match ipv4_result {
            Ok(LookupResult::Positive(addresses)) => addresses,
            Ok(LookupResult::NoData | LookupResult::NxDomain) => Vec::new(),
            Err(error) => {
                return match ipv6_result {
                    Some(Ok(LookupResult::Positive(addresses))) => Ok(addresses),
                    _ => Err(error),
                };
            }
        };
        match ipv6_result {
            Some(Ok(LookupResult::Positive(mut values))) => addresses.append(&mut values),
            Some(Err(error)) if addresses.is_empty() => return Err(error),
            _ => {}
        }
        Ok(addresses)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub async fn resolve_proxy(&self, host: &str) -> Result<Vec<IpAddr>, RuntimeDnsError> {
        super::trace::record("proxy-role");
        self.proxy_resolver
            .as_deref()
            .unwrap_or(self)
            .resolve(host)
            .await
    }
    pub async fn resolve_direct(&self, host: &str) -> Result<Vec<IpAddr>, RuntimeDnsError> {
        super::trace::record("direct-role");
        self.direct_resolver
            .as_deref()
            .unwrap_or(self)
            .resolve(host)
            .await
    }
    async fn resolve_nameserver(
        &self,
        nameserver: &DnsNameserver,
    ) -> Result<ResolvedNameserver, AttemptError> {
        let physical = if let Some(interface) = &nameserver.options.interface {
            if matches!(self.egress, DnsEgress::Single(_)) {
                return Err(AttemptError::Io(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "private DNS cannot select a physical interface",
                )));
            }
            let dialer = self
                .source_dialer
                .as_ref()
                .ok_or_else(|| {
                    AttemptError::Io(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "DNS interface binding is unavailable",
                    ))
                })?
                .clone()
                .with_egress(&crate::config::EgressOptions {
                    interface: Some(interface.clone()),
                    routing_mark: 0,
                });
            dialer.validate_egress().map_err(AttemptError::Io)?;
            Some(Arc::new(crate::outbound::DirectOutbound::new(dialer)) as Arc<dyn Dispatcher>)
        } else {
            None
        };
        let address = match &nameserver.address {
            DnsAddress::Ip(ip) => *ip,
            DnsAddress::Source(_) => return Err(AttemptError::Io(super::source::unavailable())),
            DnsAddress::Domain(host) => {
                super::trace::record("bootstrap");
                if let Some(context) = &self.node_bootstrap {
                    let destination = Destination::domain(host.clone(), nameserver.port)?;
                    context
                        .resolve_proxy(
                            &destination,
                            super::resolution::inherited_deadline(
                                TokioInstant::now() + QUERY_TIMEOUT,
                            ),
                        )
                        .await?
                        .addresses
                        .into_iter()
                        .next()
                        .ok_or_else(|| io::Error::other("DNS bootstrap returned no address"))?
                        .ip()
                } else {
                    let resolver = self
                        .bootstrap
                        .as_ref()
                        .ok_or_else(|| io::Error::other("DNS bootstrap is unavailable"))?;
                    Box::pin(resolver.resolve(host))
                        .await
                        .map_err(|_| io::Error::other("DNS bootstrap failed"))?
                        .into_iter()
                        .next()
                        .ok_or_else(|| io::Error::other("DNS bootstrap returned no address"))?
                }
            }
        };
        Ok(ResolvedNameserver {
            config: nameserver.clone(),
            endpoint: SocketAddr::new(address, nameserver.port),
            physical,
            source_generation: 0,
            source_binding: None,
        })
    }

    /// Exchanges one structurally valid single-question IN query. A/AAAA keep
    /// the typed address cache and redir-host behavior; every other qtype uses
    /// the bounded opaque wire cache and never creates a routing hint.
    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, RuntimeDnsError> {
        self.exchange_retained(query)
            .await
            .map(DnsWireResponse::into_wire)
    }

    /// Node-role HTTPS query, bypassing fake-IP/hosts address middleware. The
    /// caller owns cancellation and the original absolute setup deadline.
    pub(crate) async fn query_proxy_ech(
        &self,
        name: &str,
        deadline: TokioInstant,
    ) -> io::Result<Vec<u8>> {
        let resolver = if self.enabled {
            self.proxy_resolver.as_deref().unwrap_or(self)
        } else {
            self.ech_system_resolver.as_deref().unwrap_or(self)
        };
        let query = super::build_wire_query(resolver.next_upstream_id(), name, 65)
            .map_err(|_| io::Error::other("invalid ECH DNS query"))?;
        let classified =
            classify_query(&query).map_err(|_| io::Error::other("invalid ECH DNS query"))?;
        let permit = resolver.begin_query();
        let deadline = deadline.min(permit.deadline);
        permit.decision.set_deadline(deadline.into_std());
        let exchange: std::pin::Pin<
            Box<dyn Future<Output = Result<Vec<u8>, RuntimeDnsError>> + Send + '_>,
        > = Box::pin(permit.decision.scope(async {
            permit.decision.check()?;
            resolver
                .exchange_opaque(&query, &classified, deadline, FailureMode::BoundedError)
                .await
        }));
        let response = timeout_at(deadline, exchange)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(|_| io::Error::other("ECH DNS query failed"))?;
        super::https_ech_config(&query, &response)
            .map_err(|_| io::Error::other("invalid ECH DNS response"))
    }

    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn measurement_ech(
        dialer: crate::dialer::Dialer,
        security: crate::security::SecurityContext,
    ) -> Self {
        let mut dns = Self::assemble_leaf(
            &system_ech_config(),
            DnsEgress::Single(Arc::new(crate::outbound::DirectOutbound::new(
                dialer.clone(),
            ))),
            Arc::new(EmptyGeoMatcher),
            64,
            0,
            dialer.dns_sources().epoch(),
            security,
        );
        let pool = Arc::get_mut(&mut dns.tcp_pool).expect("fresh measurement ECH pool");
        pool.max_idle = 0;
        pool.max_idle_per_key = 0;
        pool.http2.disable_idle();
        #[cfg(feature = "dns-quic")]
        pool.quic.disable_idle();
        let stats = Arc::get_mut(&mut pool.stats).expect("fresh measurement ECH counters");
        stats.idle_limit = 0;
        stats.idle_per_key_limit = 0;
        dns.with_network_sources(dialer, Default::default())
    }

    /// Controller queries inspect the upstream resolver, as in Mihomo, without
    /// the DNS listener's hosts, fake-IP or IPv6 response middleware.
    pub(crate) async fn query_upstream(&self, query: &[u8]) -> Result<Vec<u8>, RuntimeDnsError> {
        if !self.enabled {
            return Err(RuntimeDnsError::Disabled);
        }
        let classified = classify_query(query).map_err(RuntimeDnsError::InvalidQuery)?;
        let permit = self.begin_query();
        // Keep the nested resolver future type bounded at the Controller boundary.
        let exchange: std::pin::Pin<
            Box<dyn Future<Output = Result<Vec<u8>, RuntimeDnsError>> + Send + '_>,
        > = Box::pin(permit.decision.scope(async {
            permit.decision.check()?;
            self.exchange_address_upstream(
                query,
                &classified,
                permit.deadline,
                FailureMode::BoundedError,
            )
            .await
        }));
        timeout_at(permit.deadline, exchange).await.map_err(|_| {
            RuntimeDnsError::UpstreamsExhausted {
                last_error: "runtime DNS total query deadline expired".into(),
            }
        })?
    }

    /// Keeps an observed query attached to the returned wire response. TUN TCP
    /// uses this until the framed response write completes.
    pub(crate) async fn exchange_retained(
        &self,
        query: &[u8],
    ) -> Result<DnsWireResponse, RuntimeDnsError> {
        if !self.enabled {
            return Err(RuntimeDnsError::Disabled);
        }
        let classified = classify_query(query).map_err(RuntimeDnsError::InvalidQuery)?;
        let permit = self.begin_query();
        let wire = self
            .exchange_classified_admitted(query, &classified, &permit, FailureMode::WireServfail)
            .await?;
        Ok(DnsWireResponse::tracked(wire, permit))
    }

    /// Begins observing a query before the caller creates its task. This is the
    /// entry point used by the TUN DNS fast path.
    pub(crate) fn begin_query(&self) -> DnsQueryPermit {
        let deadline = TokioInstant::now() + QUERY_TIMEOUT;
        let decision = crate::config::RuleDecision::default();
        decision.set_deadline(deadline.into_std());
        DnsQueryPermit {
            _activity: self.resource_stats.begin(ResourceActivity::DnsRequest),
            deadline,
            decision,
        }
    }

    fn next_upstream_id(&self) -> u16 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    /// Exchanges a query whose lifetime is already being observed. The caller
    /// retains the permit through TUN response delivery to avoid double
    /// counting.
    pub(crate) async fn exchange_admitted(
        &self,
        query: &[u8],
        permit: &DnsQueryPermit,
    ) -> Result<Vec<u8>, RuntimeDnsError> {
        if !self.enabled {
            return Err(RuntimeDnsError::Disabled);
        }
        let classified = classify_query(query).map_err(RuntimeDnsError::InvalidQuery)?;
        self.exchange_classified_admitted(query, &classified, permit, FailureMode::WireServfail)
            .await
    }

    async fn exchange_classified_admitted(
        &self,
        query: &[u8],
        classified: &ClassifiedDnsQuery,
        permit: &DnsQueryPermit,
        failure_mode: FailureMode,
    ) -> Result<Vec<u8>, RuntimeDnsError> {
        let deadline = permit.deadline;
        // Transport variants make this future large. Keep it out of nested
        // decision/deadline and node-resolution stack frames without spawning
        // a task or changing caller-owned cancellation.
        let exchange = Box::pin(async {
            permit.decision.check()?;
            match classified.kind {
                DnsQueryKind::Address(_) => {
                    self.exchange_address(query, classified, deadline, failure_mode)
                        .await
                }
                DnsQueryKind::Opaque => {
                    if matches!(failure_mode, FailureMode::WireServfail)
                        && matches!(classified.question.query_type, 64 | 65)
                        && self.use_fake_ip(&classified.question.name)?
                    {
                        return super::synthesize_empty_response(classified, 0)
                            .map_err(RuntimeDnsError::InvalidResponse);
                    }
                    self.exchange_opaque(query, classified, deadline, failure_mode)
                        .await
                }
            }
        });
        match timeout_at(deadline, permit.decision.scope(exchange)).await {
            Ok(Err(RuntimeDnsError::RuleEvaluation(_)))
                if matches!(failure_mode, FailureMode::WireServfail) =>
            {
                Ok(synthesize_servfail_response(classified))
            }
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    timeout_ms = QUERY_TIMEOUT.as_millis(),
                    event = "runtime_dns_total_deadline",
                    "runtime DNS total query deadline expired"
                );
                match failure_mode {
                    FailureMode::WireServfail => Ok(synthesize_servfail_response(classified)),
                    FailureMode::BoundedError => Err(RuntimeDnsError::UpstreamsExhausted {
                        last_error: "runtime DNS total query deadline expired".into(),
                    }),
                }
            }
        }
    }

    fn synthetic_answer(&self, query: &DnsMessage, host: &str) -> Result<Vec<u8>, RuntimeDnsError> {
        super::trace::record("fake-ip");
        match self
            .fake_pools
            .as_ref()
            .expect("enabled fake-IP pool")
            .lookup(host, query.question.query_type == QueryType::Aaaa)
        {
            Ok(address) => {
                let mut wire = synthesize_response(
                    query,
                    &CacheValue::Positive(address.into_iter().collect()),
                    self.fake_config.ttl,
                )?;
                wire[2] |= 0x04;
                Ok(wire)
            }
            Err(_) => synthesize_response(query, &CacheValue::Negative { rcode: 2 }, 0),
        }
    }

    async fn exchange_address(
        &self,
        query: &[u8],
        classified: &ClassifiedDnsQuery,
        deadline: TokioInstant,
        failure_mode: FailureMode,
    ) -> Result<Vec<u8>, RuntimeDnsError> {
        let parsed_query = parse_query(query).map_err(RuntimeDnsError::InvalidQuery)?;

        if parsed_query.question.query_type == QueryType::Aaaa && !self.ipv6 {
            return synthesize_response(&parsed_query, &CacheValue::Negative { rcode: 0 }, 0);
        }

        let addresses = match self
            .hosts
            .lookup(&parsed_query.question.name)
            .map_err(|_| RuntimeDnsError::UpstreamsExhausted {
                last_error: "hosts alias cycle".into(),
            })? {
            HostValue::Addresses(addresses) => Some(addresses),
            HostValue::Alias(alias) if alias != parsed_query.question.name => {
                if matches!(failure_mode, FailureMode::WireServfail) && self.use_fake_ip(&alias)? {
                    return self.synthetic_answer(&parsed_query, &alias);
                }
                Some(Box::pin(self.resolve(&alias)).await?)
            }
            _ => None,
        };
        if let Some(addresses) = addresses {
            super::trace::record("hosts");
            let addresses: Vec<_> = addresses
                .into_iter()
                .filter(|ip| match parsed_query.question.query_type {
                    QueryType::A => ip.is_ipv4(),
                    QueryType::Aaaa => ip.is_ipv6(),
                })
                .collect();
            return synthesize_response(&parsed_query, &CacheValue::Positive(addresses), 600);
        }

        if matches!(failure_mode, FailureMode::WireServfail)
            && self.use_fake_ip(&parsed_query.question.name)?
        {
            return self.synthetic_answer(&parsed_query, &parsed_query.question.name);
        }

        self.exchange_address_upstream(query, classified, deadline, failure_mode)
            .await
    }

    async fn exchange_address_upstream(
        &self,
        query: &[u8],
        classified: &ClassifiedDnsQuery,
        deadline: TokioInstant,
        failure_mode: FailureMode,
    ) -> Result<Vec<u8>, RuntimeDnsError> {
        let parsed_query = parse_query(query).map_err(RuntimeDnsError::InvalidQuery)?;

        loop {
            let (role, epoch) = {
                let epoch = self.cache_epoch.read().await;
                // Keep the cache lock through registry selection. A completing
                // leader populates this cache before removing its registry
                // entry, so a caller cannot observe a miss and then create a
                // duplicate flight after that leader has disappeared.
                let mut cache = self.cache.lock().await;
                if classified.needs_wire_cache {
                    if let Some(wire) = cache.get_wire(classified, Instant::now()) {
                        super::trace::record("cache");
                        self.resource_stats.dns_cache_hit();
                        return Ok(wire);
                    }
                } else if let Some((cached, remaining_ttl)) = cache.get_with_ttl(
                    &parsed_query.question.name,
                    parsed_query.question.query_type,
                    Instant::now(),
                ) {
                    super::trace::record("cache");
                    self.resource_stats.dns_cache_hit();
                    return synthesize_response(&parsed_query, &cached, remaining_ttl);
                }
                if self.nameservers.is_empty() {
                    return finish_shared_result(
                        Err(RuntimeDnsError::NoNameserver),
                        classified,
                        failure_mode,
                    );
                }
                (
                    self.singleflight
                        .join(SingleflightKey::new(classified, *epoch)),
                    *epoch,
                )
            };
            match role {
                FlightRole::Leader(leader) => {
                    let result = self
                        .exchange_address_leader(query, classified, deadline, epoch)
                        .await
                        .map(Arc::<[u8]>::from);
                    leader.complete(result.clone());
                    return finish_shared_result(result, classified, failure_mode);
                }
                FlightRole::Follower(updates) => {
                    super::trace::record("shared-query");
                    let Some(result) = wait_for_flight(updates).await else {
                        continue;
                    };
                    return finish_shared_result(result, classified, failure_mode);
                }
            }
        }
    }

    async fn exchange_address_leader(
        &self,
        query: &[u8],
        classified: &ClassifiedDnsQuery,
        deadline: TokioInstant,
        epoch: u64,
    ) -> Result<Vec<u8>, RuntimeDnsError> {
        let upstream_query = rewrite_query_id(query, self.next_upstream_id());
        let upstream_parsed_query =
            parse_query(&upstream_query).map_err(RuntimeDnsError::InvalidQuery)?;
        let (mut response, parsed_response, cacheable) =
            if let Some(policy) = self.policy_for(classified)? {
                super::trace::record("nameserver-policy");
                self.exchange_upstreams(policy, &upstream_query, &upstream_parsed_query, deadline)
                    .await?
            } else if self.fallback.nameservers.is_empty() {
                super::trace::record("nameserver");
                self.exchange_upstreams(
                    &self.nameservers,
                    &upstream_query,
                    &upstream_parsed_query,
                    deadline,
                )
                .await?
            } else if self.fallback_domain(&classified.question.name)? {
                super::trace::record("fallback-domain");
                self.exchange_upstreams(
                    &self.fallback.nameservers,
                    &upstream_query,
                    &upstream_parsed_query,
                    deadline,
                )
                .await?
            } else {
                // Reserve the two racing queries only when fallback is used.
                // Keeping this state inline inflates every ordinary DNS flight.
                Box::pin(super::fallback::choose(
                    self.exchange_upstreams(
                        &self.nameservers,
                        &upstream_query,
                        &upstream_parsed_query,
                        deadline,
                    ),
                    self.exchange_upstreams(
                        &self.fallback.nameservers,
                        &upstream_query,
                        &upstream_parsed_query,
                        deadline,
                    ),
                    self.fallback.lazy,
                    |answer| self.accepts_primary(answer),
                ))
                .await?
            };
        if cacheable {
            self.cache_response(&parsed_response, classified, &response, epoch)
                .await?;
        }
        restore_response_id(&mut response, 0);
        Ok(response)
    }

    async fn exchange_opaque(
        &self,
        query: &[u8],
        classified: &ClassifiedDnsQuery,
        deadline: TokioInstant,
        failure_mode: FailureMode,
    ) -> Result<Vec<u8>, RuntimeDnsError> {
        loop {
            let (role, epoch) = {
                let epoch = self.cache_epoch.read().await;
                let mut cache = self.cache.lock().await;
                if let Some(response) = cache.get_opaque(classified, Instant::now()) {
                    super::trace::record("cache");
                    self.resource_stats.dns_cache_hit();
                    return Ok(response);
                }
                if self.nameservers.is_empty() {
                    return finish_shared_result(
                        Err(RuntimeDnsError::NoNameserver),
                        classified,
                        failure_mode,
                    );
                }
                (
                    self.singleflight
                        .join(SingleflightKey::new(classified, *epoch)),
                    *epoch,
                )
            };
            match role {
                FlightRole::Leader(leader) => {
                    let result = self
                        .exchange_opaque_leader(query, classified, deadline, epoch)
                        .await
                        .map(Arc::<[u8]>::from);
                    leader.complete(result.clone());
                    return finish_shared_result(result, classified, failure_mode);
                }
                FlightRole::Follower(updates) => {
                    super::trace::record("shared-query");
                    let Some(result) = wait_for_flight(updates).await else {
                        continue;
                    };
                    return finish_shared_result(result, classified, failure_mode);
                }
            }
        }
    }

    async fn exchange_opaque_leader(
        &self,
        query: &[u8],
        classified: &ClassifiedDnsQuery,
        deadline: TokioInstant,
        epoch: u64,
    ) -> Result<Vec<u8>, RuntimeDnsError> {
        let upstream_query = rewrite_query_id(query, self.next_upstream_id());
        let upstream_classified =
            classify_query(&upstream_query).map_err(RuntimeDnsError::InvalidQuery)?;
        let nameservers = self.nameservers_for(classified)?;
        let response = self
            .exchange_opaque_upstreams(nameservers, &upstream_query, &upstream_classified, deadline)
            .await?;
        {
            let current_epoch = self.cache_epoch.read().await;
            if *current_epoch == epoch {
                self.cache
                    .lock()
                    .await
                    .insert_opaque(&response, Instant::now());
            }
        }
        let mut response = response.into_wire();
        restore_response_id(&mut response, 0);
        Ok(response)
    }

    /// Returns the best-effort domain associated with an address previously
    /// resolved by this runtime.
    pub async fn domain_hint(&self, address: IpAddr) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let hints = self.hints.as_ref()?;
        hints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(address, Instant::now())
    }

    async fn resolve_type(
        &self,
        host: &str,
        query_type: QueryType,
        deadline: TokioInstant,
    ) -> Result<LookupResult, RuntimeDnsError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let query = build_query(id, host, query_type).map_err(RuntimeDnsError::InvalidQuery)?;
        let classified = classify_query(&query).map_err(RuntimeDnsError::InvalidQuery)?;
        let permit = DnsQueryPermit {
            deadline,
            ..self.begin_query()
        };
        let response = self
            .exchange_classified_admitted(&query, &classified, &permit, FailureMode::BoundedError)
            .await?;
        let parsed = parse_response(&response).map_err(RuntimeDnsError::InvalidResponse)?;
        if parsed.id != id
            || parsed.question.name != host
            || parsed.question.query_type != query_type
        {
            return Err(RuntimeDnsError::UpstreamsExhausted {
                last_error: "cached or upstream response does not match the query".into(),
            });
        }

        match parsed.rcode {
            RCODE_NOERROR => {
                let answers =
                    matching_answer_set(&parsed).map_err(RuntimeDnsError::InvalidResponse)?;
                if answers.addresses.is_empty() {
                    Ok(LookupResult::NoData)
                } else {
                    Ok(LookupResult::Positive(answers.addresses))
                }
            }
            RCODE_NXDOMAIN => Ok(LookupResult::NxDomain),
            rcode => Err(RuntimeDnsError::ResponseCode(rcode)),
        }
    }

    async fn exchange_upstreams(
        &self,
        nameservers: &[DnsNameserver],
        query: &[u8],
        parsed_query: &DnsMessage,
        deadline: TokioInstant,
    ) -> Result<(Vec<u8>, DnsMessage, bool), RuntimeDnsError> {
        let cacheable = !nameservers
            .iter()
            .any(|server| matches!(server.transport, DnsTransport::Rcode(_)));
        let permits = Semaphore::new(4);
        let (wire, response) = exchange_nameservers(
            nameservers,
            deadline,
            |nameserver| {
                self.exchange_nameserver_limited(nameserver, query, parsed_query, &permits)
            },
            |(_, response): &(Vec<u8>, DnsMessage)| {
                matches!(response.rcode, RCODE_SERVFAIL | RCODE_REFUSED)
                    .then_some(u16::from(response.rcode))
            },
        )
        .await?;
        Ok((wire, response, cacheable))
    }

    async fn exchange_opaque_upstreams(
        &self,
        nameservers: &[DnsNameserver],
        query: &[u8],
        classified: &ClassifiedDnsQuery,
        deadline: TokioInstant,
    ) -> Result<ValidatedOpaqueResponse, RuntimeDnsError> {
        let permits = Semaphore::new(4);
        exchange_nameservers(
            nameservers,
            deadline,
            |nameserver| self.exchange_opaque_nameserver(nameserver, query, classified, &permits),
            |response: &ValidatedOpaqueResponse| {
                matches!(
                    response.rcode(),
                    rcode if rcode == u16::from(RCODE_SERVFAIL)
                        || rcode == u16::from(RCODE_REFUSED)
                )
                .then_some(response.rcode())
            },
        )
        .await
    }

    #[cfg(test)]
    async fn exchange_nameserver(
        &self,
        nameserver: DnsNameserver,
        query: &[u8],
        parsed: &DnsMessage,
    ) -> Result<(Vec<u8>, DnsMessage), AttemptError> {
        self.exchange_nameserver_limited(nameserver, query, parsed, &Semaphore::new(4))
            .await
    }

    async fn exchange_nameserver_limited(
        &self,
        nameserver: DnsNameserver,
        query: &[u8],
        parsed: &DnsMessage,
        permits: &Semaphore,
    ) -> Result<(Vec<u8>, DnsMessage), AttemptError> {
        self.exchange_validated(
            nameserver,
            query,
            |wire| udp_response_matches_query(parsed, wire),
            |wire| validate_complete_response(parsed, wire),
            permits,
        )
        .await
    }

    async fn exchange_opaque_nameserver(
        &self,
        nameserver: DnsNameserver,
        query: &[u8],
        parsed: &ClassifiedDnsQuery,
        permits: &Semaphore,
    ) -> Result<ValidatedOpaqueResponse, AttemptError> {
        let local = matches!(nameserver.transport, DnsTransport::Rcode(_));
        self.exchange_validated(
            nameserver,
            query,
            |wire| udp_response_matches_classified_query(parsed, wire),
            |wire| validate_opaque_response(parsed, wire).map_err(AttemptError::from),
            permits,
        )
        .await
        .map(|(_, mut parsed)| {
            if local {
                parsed.cache_policy = super::OpaqueCachePolicy::NotCacheable;
            }
            parsed
        })
    }

    async fn exchange_validated<R, M, V>(
        &self,
        nameserver: DnsNameserver,
        query: &[u8],
        matches: M,
        validate: V,
        permits: &Semaphore,
    ) -> Result<(Vec<u8>, R), AttemptError>
    where
        M: Fn(&[u8]) -> Result<bool, AttemptError>,
        V: Fn(&[u8]) -> Result<R, AttemptError>,
    {
        if nameserver.options.disabled_types.is_empty() {
            let wrapped = super::options::with_ecs(query, &nameserver.options)?;
            return self
                .exchange_raw_validated(nameserver, &wrapped, matches, validate, permits)
                .await;
        }
        let classified = classify_query(query)?;
        if super::options::question_disabled(&nameserver.options, classified.question.query_type) {
            let mut response = super::synthesize_empty_response(&classified, RCODE_NOERROR)?;
            response[2] |= 0x04; // AA, matching Mihomo's disable-type wrapper.
            let parsed = validate(&response)?;
            return Ok((response, parsed));
        }
        let wrapped = super::options::with_ecs(query, &nameserver.options)?;
        let disabled = nameserver.options.disabled_types.clone();
        let (wire, ()) = self
            .exchange_raw_validated(
                nameserver,
                &wrapped,
                matches,
                |wire| validate(wire).map(|_| ()),
                permits,
            )
            .await?;
        let wire = super::options::filter_response(&wire, &disabled)?;
        let parsed = validate(&wire)?;
        Ok((wire, parsed))
    }

    async fn exchange_raw_validated<R, M, V>(
        &self,
        nameserver: DnsNameserver,
        query: &[u8],
        matches: M,
        validate: V,
        permits: &Semaphore,
    ) -> Result<(Vec<u8>, R), AttemptError>
    where
        M: Fn(&[u8]) -> Result<bool, AttemptError>,
        V: Fn(&[u8]) -> Result<R, AttemptError>,
    {
        if let DnsTransport::Rcode(rcode) = nameserver.transport {
            super::trace::record("rcode");
            let mut response = query.to_vec();
            let flags = u16::from_be_bytes([response[2], response[3]]);
            let flags = (flags | DNS_FLAG_RESPONSE) & !0x000f | u16::from(rcode);
            response[2..4].copy_from_slice(&flags.to_be_bytes());
            let parsed = validate(&response)?;
            return Ok((response, parsed));
        }
        if let DnsAddress::Source(source) = &nameserver.address {
            use futures_util::{StreamExt, stream};
            let selection = self
                .sources
                .select(source, self.source_dialer.as_ref(), &self.source_exclusions)
                .await?;
            let mut attempts = stream::iter(selection.endpoints.to_vec())
                .map(|endpoint| {
                    let mut config = nameserver.clone();
                    config.address = DnsAddress::Ip(endpoint.endpoint.ip());
                    config.route = DnsRoute::Direct;
                    let physical = self
                        .source_dialer
                        .as_ref()
                        .map(|dialer| {
                            dialer
                                .for_dns_source(endpoint.binding.clone(), endpoint.endpoint)
                                .map(|dialer| {
                                    Arc::new(crate::outbound::DirectOutbound::new(dialer))
                                        as Arc<dyn Dispatcher>
                                })
                        })
                        .transpose();
                    let resolved = ResolvedNameserver {
                        config,
                        endpoint: endpoint.endpoint,
                        physical: None,
                        source_generation: selection.generation,
                        source_binding: Some(endpoint.binding.clone()),
                    };
                    let matches = &matches;
                    let validate = &validate;
                    async move {
                        let mut resolved = resolved;
                        resolved.physical = physical?;
                        let _attempt = permits
                            .acquire()
                            .await
                            .map_err(|_| super::source::unavailable())?;
                        self.exchange_resolved_validated(resolved, query, matches, validate)
                            .await
                    }
                })
                .buffer_unordered(4);
            let mut last = None;
            while let Some(result) = attempts.next().await {
                match result {
                    Ok((wire, parsed))
                        if !matches!(wire[3] & 0x0f, RCODE_SERVFAIL | RCODE_REFUSED) =>
                    {
                        return Ok((wire, parsed));
                    }
                    Ok(response) => last = Some(Ok(response)),
                    Err(error) => {
                        if !matches!(last, Some(Ok(_))) {
                            last = Some(Err(error));
                        }
                    }
                }
            }
            return last.unwrap_or_else(|| Err(super::source::unavailable().into()));
        }
        super::trace::record(match nameserver.transport {
            DnsTransport::Rcode(_) => unreachable!("local response handled above"),
            DnsTransport::Udp => "udp",
            DnsTransport::Tcp => "tcp",
            DnsTransport::Tls => "tls",
            DnsTransport::Https => "https",
            DnsTransport::Http => "http",
            DnsTransport::Quic => "quic",
        });
        let server = self.resolve_nameserver(&nameserver).await?;
        let _attempt = permits
            .acquire()
            .await
            .map_err(|_| super::source::unavailable())?;
        self.exchange_resolved_validated(server, query, matches, validate)
            .await
    }

    async fn exchange_resolved_validated<R, M, V>(
        &self,
        mut server: ResolvedNameserver,
        query: &[u8],
        matches: M,
        validate: V,
    ) -> Result<(Vec<u8>, R), AttemptError>
    where
        M: Fn(&[u8]) -> Result<bool, AttemptError>,
        V: Fn(&[u8]) -> Result<R, AttemptError>,
    {
        if server.transport == DnsTransport::Quic {
            #[cfg(feature = "dns-quic")]
            return Box::pin(self.exchange_quic(&server, query, validate, super::quic::Kind::Doq))
                .await;
            #[cfg(not(feature = "dns-quic"))]
            return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        }
        if server.transport == DnsTransport::Udp {
            let (_, egress) = self.egress_for(&server, Network::Udp, |_| false)?;
            let response = self.exchange_udp(&server, &egress, query, matches).await?;
            if response.get(2).is_some_and(|flags| flags & 0x02 != 0) {
                server.config.transport = DnsTransport::Tcp;
            } else {
                let parsed = validate(&response)?;
                return Ok((response, parsed));
            }
        }
        // TCP/TLS/H3 handshake states are only needed after selecting them.
        // Keeping them inline would inflate every racing UDP attempt as well.
        Box::pin(self.exchange_tcp(&server, query, validate)).await
    }

    async fn exchange_udp<F>(
        &self,
        nameserver: &ResolvedNameserver,
        egress: &Arc<dyn Dispatcher>,
        query: &[u8],
        response_matches: F,
    ) -> Result<Vec<u8>, AttemptError>
    where
        F: Fn(&[u8]) -> Result<bool, AttemptError>,
    {
        let endpoint = nameserver.endpoint();
        let mut transport = egress
            .open_datagram(DatagramSession::new(
                InboundKind::InternalDns,
                internal_source(nameserver.endpoint.ip()),
            ))
            .await?;
        let payload = Bytes::copy_from_slice(query);
        let result = async {
            transport
                .send(Datagram {
                    remote: Destination::Ip(endpoint),
                    payload: payload.clone(),
                    sniffed_domain: None,
                })
                .await?;
            let retry_at = TokioInstant::now() + UDP_RETRY_DELAY;
            let mut retried = false;
            let mut ignored = 0_usize;

            loop {
                let response = if retried {
                    transport.receive().await?
                } else {
                    tokio::select! {
                        response = transport.receive() => response?,
                        () = sleep_until(retry_at) => {
                            tracing::debug!(
                                event = "runtime_dns_udp_resend",
                                "runtime DNS is resending on the current UDP transport"
                            );
                            transport.send(Datagram {
                                remote: Destination::Ip(endpoint),
                                payload: payload.clone(),
                                sniffed_domain: None,
                            }).await?;
                            retried = true;
                            continue;
                        }
                    }
                };

                if response.remote != Destination::Ip(endpoint) {
                    ignored += 1;
                } else {
                    if response.payload.len() > MAX_MESSAGE_SIZE {
                        return Err(AttemptError::MessageTooLarge);
                    }
                    if response_matches(&response.payload)? {
                        return Ok(response.payload.to_vec());
                    }
                    ignored += 1;
                }

                if ignored >= MAX_IGNORED_UDP_RESPONSES {
                    tracing::warn!(
                        ignored,
                        event = "runtime_dns_udp_mismatch_limit",
                        "runtime DNS UDP attempt reached the mismatched response limit"
                    );
                    return Err(AttemptError::TooManyIgnoredUdpResponses);
                }
            }
        }
        .await;
        let _ = transport.close().await;
        result
    }

    async fn exchange_tcp<R, F>(
        &self,
        nameserver: &ResolvedNameserver,
        query: &[u8],
        validate: F,
    ) -> Result<(Vec<u8>, R), AttemptError>
    where
        F: Fn(&[u8]) -> Result<R, AttemptError>,
    {
        if nameserver.transport == DnsTransport::Https {
            return self.exchange_https(nameserver, query, validate).await;
        }
        let mut lease = self
            .tcp_pool
            .checkout_for(nameserver, |state| {
                self.egress_for(nameserver, Network::Tcp, |egress| {
                    !dot_reuse_disabled(&nameserver.config)
                        && state.idle.iter().any(|idle| {
                            idle.key.upstream == nameserver.config
                                && idle.key.endpoint == nameserver.endpoint()
                                && idle.key.egress == egress
                                && idle.key.source_generation == nameserver.source_generation
                                && idle.key.source_binding == nameserver.source_binding
                        })
                })
            })
            .await?;
        let first_was_reused = lease.reused;

        let mut result = exchange_stream_validated(
            &mut lease
                .connection
                .as_mut()
                .expect("TCP lease always owns a connection")
                .stream,
            nameserver,
            query,
            &validate,
        )
        .await;
        if first_was_reused && result.as_ref().is_err_and(stale_reuse_is_retryable) {
            tracing::debug!(
                event = "runtime_dns_tcp_pool_stale_retry",
                "runtime DNS is rebuilding one stale reused TCP connection"
            );
            let (key, egress) = self.egress_for(nameserver, Network::Tcp, |_| false)?;
            lease.key.egress = key;
            self.tcp_pool
                .replace_stale(&mut lease, nameserver, &egress)
                .await?;
            result = exchange_stream_validated(
                &mut lease
                    .connection
                    .as_mut()
                    .expect("replacement TCP lease owns a connection")
                    .stream,
                nameserver,
                query,
                &validate,
            )
            .await;
        }

        let (response, validated, reusable) = result?;
        if reusable {
            self.tcp_pool.check_in(lease).await;
        }
        Ok((response, validated))
    }

    async fn exchange_https<R, F>(
        &self,
        nameserver: &ResolvedNameserver,
        query: &[u8],
        validate: F,
    ) -> Result<(Vec<u8>, R), AttemptError>
    where
        F: Fn(&[u8]) -> Result<R, AttemptError>,
    {
        #[cfg(feature = "dns-quic")]
        if nameserver.options.force_h3 {
            return self
                .exchange_quic(nameserver, query, validate, super::quic::Kind::H3)
                .await;
        }
        #[cfg(not(feature = "dns-quic"))]
        if nameserver.options.force_h3 || self.prefer_h3 {
            return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        }
        let resolve = |state: &TcpPoolState| {
            self.egress_for(nameserver, Network::Tcp, |egress| {
                let key = TcpPoolKey {
                    upstream: nameserver.config.clone(),
                    endpoint: nameserver.endpoint(),
                    egress,
                    source_generation: nameserver.source_generation,
                    source_binding: nameserver.source_binding.clone(),
                };
                self.tcp_pool.http2.has(&key) || state.idle.iter().any(|idle| idle.key == key)
            })
        };
        // Only a stale reused HTTP/1 connection gets one retry. Each fresh
        // handshake branches on actual ALPN, including a changed server choice.
        for attempt in 0..2 {
            #[cfg(feature = "dns-quic")]
            if self.prefer_h3
                && let Some(lease) = self.cached_quic(nameserver)?
            {
                let result = lease
                    .exchange(&nameserver.config, query, |wire| {
                        validate(wire)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    })
                    .await
                    .map_err(AttemptError::Io);
                return result;
            }
            let key = {
                let state = self.tcp_pool.state.lock().await;
                let (egress, _) = resolve(&state)?;
                TcpPoolKey {
                    upstream: nameserver.config.clone(),
                    endpoint: nameserver.endpoint(),
                    egress,
                    source_generation: nameserver.source_generation,
                    source_binding: nameserver.source_binding.clone(),
                }
            };
            if let Some(lease) = self.tcp_pool.http2.get(&key) {
                self.tcp_pool
                    .stats
                    .reuse_hits
                    .fetch_add(1, Ordering::Relaxed);
                let result = lease
                    .exchange(&nameserver.config, query, |wire| {
                        validate(wire)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    })
                    .await
                    .map_err(AttemptError::Io);
                #[cfg(feature = "dns-quic")]
                if result.is_err() {
                    self.tcp_pool.forget_tcp(&key);
                }
                return result;
            }
            let initialization = self.tcp_pool.http2.initialization(key.clone());
            let gate = initialization.lock().await;
            #[cfg(feature = "dns-quic")]
            if self.prefer_h3
                && let Some(lease) = self.cached_quic(nameserver)?
            {
                drop(gate);
                return lease
                    .exchange(&nameserver.config, query, |wire| {
                        validate(wire)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    })
                    .await
                    .map_err(AttemptError::Io);
            }
            if let Some(lease) = self.tcp_pool.http2.get(&key) {
                drop(gate);
                self.tcp_pool
                    .stats
                    .reuse_hits
                    .fetch_add(1, Ordering::Relaxed);
                let result = lease
                    .exchange(&nameserver.config, query, |wire| {
                        validate(wire)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    })
                    .await
                    .map_err(AttemptError::Io);
                #[cfg(feature = "dns-quic")]
                if result.is_err() {
                    self.tcp_pool.forget_tcp(&key);
                }
                return result;
            }
            #[cfg(feature = "dns-quic")]
            let mut lease = if self.prefer_h3 && !self.tcp_pool.tcp_selected(&key) {
                let mut quic = self.start_quic(nameserver, super::quic::Kind::H3)?;
                let mut tcp = Box::pin(self.tcp_pool.checkout_for(nameserver, &resolve));
                tokio::select! {
                    result = &mut tcp => match result {
                    Ok(lease) => {
                        drop(tcp);
                        quic.cancel().await;
                        self.tcp_pool.select_tcp(lease.key.clone());
                        lease
                    }
                    Err(_) => {
                        drop(tcp);
                        if let Err(error) = quic.wait_ready().await {
                            quic.cancel().await;
                            return Err(error.into());
                        }
                        let lease = quic.publish()?;
                        drop(gate);
                        return lease
                            .exchange(&nameserver.config, query, |wire| {
                                validate(wire).map_err(|error| {
                                    io::Error::new(io::ErrorKind::InvalidData, error)
                                })
                            })
                            .await
                            .map_err(AttemptError::Io);
                    }
                    },
                    result = quic.wait_ready() => match result {
                    Ok(()) => {
                        drop(tcp);
                        let lease = quic.publish()?;
                        drop(gate);
                        return lease
                            .exchange(&nameserver.config, query, |wire| {
                                validate(wire).map_err(|error| {
                                    io::Error::new(io::ErrorKind::InvalidData, error)
                                })
                            })
                            .await
                            .map_err(AttemptError::Io);
                    }
                    Err(_) => {
                        let tcp = tcp.await;
                        quic.cancel().await;
                        let lease = tcp?;
                        self.tcp_pool.select_tcp(lease.key.clone());
                        lease
                    }
                }
                }
            } else {
                self.tcp_pool.checkout_for(nameserver, &resolve).await?
            };
            #[cfg(not(feature = "dns-quic"))]
            let mut lease = self.tcp_pool.checkout_for(nameserver, &resolve).await?;
            let alpn = lease
                .connection
                .as_ref()
                .expect("TCP lease owns a connection")
                .negotiated_alpn
                .as_deref();
            if alpn == Some(b"h2") {
                let connection = lease
                    .connection
                    .take()
                    .expect("TCP lease owns a connection");
                lease.busy.take();
                let PooledTcpConnection {
                    stream,
                    _slot,
                    _observation,
                    ..
                } = connection;
                let h2 = self
                    .tcp_pool
                    .http2
                    .connect(lease.key.clone(), stream, (_slot, _observation))
                    .await?;
                drop(gate);
                let result = h2
                    .exchange(&nameserver.config, query, |wire| {
                        validate(wire)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    })
                    .await
                    .map_err(AttemptError::Io);
                #[cfg(feature = "dns-quic")]
                if result.is_err() {
                    self.tcp_pool.forget_tcp(&key);
                }
                return result;
            }
            if alpn.is_some_and(|protocol| protocol != b"http/1.1") {
                return Err(io::Error::from(io::ErrorKind::InvalidData).into());
            }
            drop(gate);
            let result = exchange_stream_validated(
                &mut lease
                    .connection
                    .as_mut()
                    .expect("TCP lease owns a connection")
                    .stream,
                nameserver,
                query,
                &validate,
            )
            .await;
            if attempt == 0 && lease.reused && result.as_ref().is_err_and(stale_reuse_is_retryable)
            {
                #[cfg(feature = "dns-quic")]
                self.tcp_pool.forget_tcp(&key);
                self.tcp_pool
                    .stats
                    .stale_retries
                    .fetch_add(1, Ordering::Relaxed);
                drop(lease);
                continue;
            }
            #[cfg(feature = "dns-quic")]
            if result.is_err() {
                self.tcp_pool.forget_tcp(&key);
            }
            let (response, validated, reusable) = result?;
            if reusable {
                self.tcp_pool.check_in(lease).await;
            }
            return Ok((response, validated));
        }
        unreachable!("stale HTTP/1 reuse retries once")
    }

    #[cfg(feature = "dns-quic")]
    fn quic_route(
        &self,
        nameserver: &ResolvedNameserver,
    ) -> Result<(TcpPoolKey, Arc<dyn Dispatcher>), AttemptError> {
        let (egress, dispatcher) = self.egress_for(nameserver, Network::Udp, |egress| {
            self.tcp_pool.quic.has(&TcpPoolKey {
                upstream: nameserver.config.clone(),
                endpoint: nameserver.endpoint(),
                egress,
                source_generation: nameserver.source_generation,
                source_binding: nameserver.source_binding.clone(),
            })
        })?;
        Ok((
            TcpPoolKey {
                upstream: nameserver.config.clone(),
                endpoint: nameserver.endpoint(),
                egress,
                source_generation: nameserver.source_generation,
                source_binding: nameserver.source_binding.clone(),
            },
            dispatcher,
        ))
    }

    #[cfg(feature = "dns-quic")]
    fn cached_quic(
        &self,
        nameserver: &ResolvedNameserver,
    ) -> Result<Option<super::quic::Lease<TcpPoolKey>>, AttemptError> {
        // UDP-disabled rules must not prevent an otherwise valid H1/H2 path.
        let Ok((key, _)) = self.quic_route(nameserver) else {
            return Ok(None);
        };
        Ok(self.tcp_pool.quic.get(&key))
    }

    #[cfg(feature = "dns-quic")]
    fn start_quic(
        &self,
        nameserver: &ResolvedNameserver,
        kind: super::quic::Kind,
    ) -> Result<super::quic::Pending<TcpPoolKey>, AttemptError> {
        let route = self.quic_route(nameserver);
        let key = route.as_ref().map_or_else(
            |_| TcpPoolKey {
                upstream: nameserver.config.clone(),
                endpoint: nameserver.endpoint(),
                egress: DnsEgressKey::Single,
                source_generation: nameserver.source_generation,
                source_binding: nameserver.source_binding.clone(),
            },
            |(key, _)| key.clone(),
        );
        let nameserver = nameserver.clone();
        let security = self.tcp_pool.security.clone();
        let open = async move {
            let (_, dispatcher) =
                route.map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
            let alpn = match kind {
                super::quic::Kind::Doq => b"doq".to_vec(),
                super::quic::Kind::H3 => b"h3".to_vec(),
            };
            let client = crate::security::StandardTlsClient::with_options(
                &security,
                nameserver.address.to_string(),
                crate::security::TlsClientOptions {
                    certificate: crate::config::TlsCertificatePolicy {
                        verification_name: nameserver.options.verification_name.clone(),
                        skip_cert_verify: nameserver.options.skip_cert_verify,
                        fingerprint: None,
                    },
                    alpn: vec![alpn.clone()],
                    required_alpn: Some(alpn),
                    versions: crate::security::TlsVersions::Tls13,
                    ..Default::default()
                },
                0,
                64 * 1024,
            )?;
            let (tls, server_name) = client.quic_config()?;
            let transport = dispatcher
                .open_datagram(DatagramSession::new(
                    InboundKind::InternalDns,
                    internal_source(nameserver.endpoint.ip()),
                ))
                .await
                .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
            let budget = transport.payload_budget(&Destination::Ip(nameserver.endpoint()));
            Ok(super::quic::Raw {
                transport,
                peer: nameserver.endpoint(),
                budget,
                tls,
                server_name,
            })
        };
        self.tcp_pool
            .quic
            .start(key, kind, open)
            .map_err(AttemptError::Io)
    }

    #[cfg(feature = "dns-quic")]
    async fn exchange_quic<R>(
        &self,
        nameserver: &ResolvedNameserver,
        query: &[u8],
        validate: impl Fn(&[u8]) -> Result<R, AttemptError>,
        kind: super::quic::Kind,
    ) -> Result<(Vec<u8>, R), AttemptError> {
        let (key, _) = self.quic_route(nameserver)?;
        let lease = if let Some(lease) = self.tcp_pool.quic.get(&key) {
            lease
        } else {
            let initialization = self.tcp_pool.quic.initialization(key.clone());
            let _gate = initialization.lock().await;
            if let Some(lease) = self.tcp_pool.quic.get(&key) {
                lease
            } else {
                self.start_quic(nameserver, kind)?.finish().await?
            }
        };
        lease
            .exchange(&nameserver.config, query, |wire| {
                validate(wire).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
            .await
            .map_err(AttemptError::Io)
    }

    async fn cache_response(
        &self,
        response: &DnsMessage,
        query: &ClassifiedDnsQuery,
        wire: &[u8],
        epoch: u64,
    ) -> Result<(), RuntimeDnsError> {
        let current_epoch = self.cache_epoch.read().await;
        if *current_epoch != epoch {
            return Ok(());
        }
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        if query.needs_wire_cache {
            let mut upstream_query = query.clone();
            upstream_query.id = response.id;
            let validated = super::validate_wire_response(&upstream_query, wire)
                .map_err(RuntimeDnsError::InvalidResponse)?;
            cache.insert_opaque(&validated, now);
        }
        let name = &response.question.name;
        let query_type = response.question.query_type;
        if response.rcode == RCODE_NXDOMAIN && !query.needs_wire_cache {
            cache
                .insert_negative(name, query_type, RCODE_NXDOMAIN, now)
                .map_err(RuntimeDnsError::Cache)?;
            return Ok(());
        }
        if response.rcode != RCODE_NOERROR {
            return Ok(());
        }

        let answers = matching_answer_set(response).map_err(RuntimeDnsError::InvalidResponse)?;
        if answers.addresses.is_empty() {
            if !query.needs_wire_cache {
                cache
                    .insert_negative(name, query_type, RCODE_NOERROR, now)
                    .map_err(RuntimeDnsError::Cache)?;
            }
            return Ok(());
        }

        let ttl = answers.ttl.unwrap_or(MIN_TTL_SECS);
        if !query.needs_wire_cache {
            cache
                .insert_positive(name, query_type, &answers.addresses, ttl, now)
                .map_err(RuntimeDnsError::Cache)?;
        }
        if let Some(hints) = &self.hints {
            let mut hints = hints
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for address in answers.addresses {
                hints
                    .insert(address, name, ttl, now)
                    .map_err(RuntimeDnsError::Cache)?;
            }
        }
        Ok(())
    }
}

async fn exchange_tcp_framed(
    stream: &mut BoxStream,
    query: &[u8],
) -> Result<Vec<u8>, AttemptError> {
    let query_length = u16::try_from(query.len()).map_err(|_| AttemptError::MessageTooLarge)?;
    stream.write_all(&query_length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let response_length = stream.read_u16().await? as usize;
    if response_length > MAX_MESSAGE_SIZE {
        return Err(AttemptError::MessageTooLarge);
    }
    let mut response = vec![0_u8; response_length];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

async fn exchange_stream_validated<R, F>(
    stream: &mut BoxStream,
    server: &ResolvedNameserver,
    query: &[u8],
    validate: &F,
) -> Result<(Vec<u8>, R, bool), AttemptError>
where
    F: Fn(&[u8]) -> Result<R, AttemptError>,
{
    if matches!(server.transport, DnsTransport::Http | DnsTransport::Https) {
        let (wire, reusable) = super::https::exchange(stream, server, query).await?;
        let response = validate(&wire)?;
        Ok((wire, response, reusable))
    } else {
        exchange_tcp_validated(stream, query, validate)
            .await
            .map(|(wire, response)| (wire, response, true))
    }
}

async fn exchange_tcp_validated<R, F>(
    stream: &mut BoxStream,
    query: &[u8],
    validate: &F,
) -> Result<(Vec<u8>, R), AttemptError>
where
    F: Fn(&[u8]) -> Result<R, AttemptError>,
{
    let response = exchange_tcp_framed(stream, query).await?;
    let validated = validate(&response)?;
    Ok((response, validated))
}

fn stale_reuse_is_retryable(error: &AttemptError) -> bool {
    matches!(error, AttemptError::Io(_) | AttemptError::ResponseMismatch)
}

fn finish_shared_result(
    result: SharedDnsResult,
    classified: &ClassifiedDnsQuery,
    failure_mode: FailureMode,
) -> Result<Vec<u8>, RuntimeDnsError> {
    match result {
        Ok(response) => {
            let mut response = response.as_ref().to_vec();
            restore_response_id(&mut response, classified.id);
            Ok(response)
        }
        Err(
            error @ (RuntimeDnsError::NoNameserver | RuntimeDnsError::UpstreamsExhausted { .. }),
        ) => match failure_mode {
            FailureMode::WireServfail => Ok(synthesize_servfail_response(classified)),
            FailureMode::BoundedError => Err(error),
        },
        Err(error) => Err(error),
    }
}

async fn exchange_nameservers<T, Attempt, AttemptFuture, RetryableResponse>(
    nameservers: &[DnsNameserver],
    deadline: TokioInstant,
    mut attempt: Attempt,
    retryable_response: RetryableResponse,
) -> Result<T, RuntimeDnsError>
where
    Attempt: FnMut(DnsNameserver) -> AttemptFuture,
    AttemptFuture: Future<Output = Result<T, AttemptError>>,
    RetryableResponse: Fn(&T) -> Option<u16>,
{
    use futures_util::{StreamExt, stream};
    if let Some(server) = nameservers
        .iter()
        .find(|server| matches!(server.transport, DnsTransport::Rcode(_)))
    {
        let result = timeout_at(deadline, Box::pin(attempt(server.clone()))).await;
        crate::config::RuleDecision::default().check()?;
        return match result {
            Ok(Ok(response)) => {
                crate::config::RuleDecision::default().check()?;
                Ok(response)
            }
            Ok(Err(AttemptError::RuleEvaluation(failure))) => {
                Err(RuntimeDnsError::RuleEvaluation(failure))
            }
            Ok(Err(error)) => Err(RuntimeDnsError::UpstreamsExhausted {
                last_error: error.summary(0),
            }),
            Err(_) => Err(RuntimeDnsError::UpstreamsExhausted {
                last_error: "local DNS response timed out".into(),
            }),
        };
    }
    let mut last_error: Box<str> = "no nameserver attempted".into();
    let mut attempts = stream::iter(nameservers.iter().cloned().enumerate())
        .map(|(index, server)| {
            let future = attempt(server);
            async move {
                (
                    index,
                    timeout_at(deadline.min(TokioInstant::now() + UPSTREAM_TIMEOUT), future).await,
                )
            }
        })
        .buffer_unordered(4);
    while let Some((index, result)) = attempts.next().await {
        crate::config::RuleDecision::default().check()?;
        match result {
            Ok(Ok(response)) if retryable_response(&response).is_none() => {
                crate::config::RuleDecision::default().check()?;
                return Ok(response);
            }
            Ok(Ok(_)) => {
                last_error = format!("nameserver {index} returned a retryable response").into()
            }
            Ok(Err(AttemptError::RuleEvaluation(failure))) => {
                return Err(RuntimeDnsError::RuleEvaluation(failure));
            }
            Ok(Err(error)) => last_error = error.summary(index),
            Err(_) => last_error = format!("nameserver {index} timed out").into(),
        }
    }
    Err(RuntimeDnsError::UpstreamsExhausted { last_error })
}

#[derive(Clone)]
struct ResolvedNameserver {
    config: DnsNameserver,
    endpoint: SocketAddr,
    physical: Option<Arc<dyn Dispatcher>>,
    source_generation: u64,
    source_binding: Option<super::source::DnsBinding>,
}
impl std::ops::Deref for ResolvedNameserver {
    type Target = DnsNameserver;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}
impl ResolvedNameserver {
    fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
}
#[cfg(test)]
impl DnsNameserver {
    fn endpoint(&self) -> SocketAddr {
        match self.address {
            DnsAddress::Ip(ip) => SocketAddr::new(ip, self.port),
            _ => panic!("test requires literal DNS endpoint"),
        }
    }
}
impl fmt::Display for DnsNameserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?}://{}:{}",
            self.transport, self.address, self.port
        )
    }
}

#[derive(Debug)]
enum LookupResult {
    Positive(Vec<IpAddr>),
    NoData,
    NxDomain,
}

#[derive(Debug, thiserror::Error)]
enum AttemptError {
    #[error("DNS rule evaluation failed: {0}")]
    RuleEvaluation(crate::config::MatchFailure),
    #[error("dispatcher failed: {0}")]
    Dispatch(DispatchError),
    #[error("stream I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid response: {0}")]
    InvalidResponse(#[from] DnsError),
    #[error("response ID or question does not match the query")]
    ResponseMismatch,
    #[error("more than three unrelated UDP responses were ignored")]
    TooManyIgnoredUdpResponses,
    #[error("DNS response exceeds 4096 bytes")]
    MessageTooLarge,
}

impl From<DispatchError> for AttemptError {
    fn from(error: DispatchError) -> Self {
        match error {
            DispatchError::RuleEvaluation(failure) => Self::RuleEvaluation(failure),
            error => Self::Dispatch(error),
        }
    }
}

impl AttemptError {
    fn category(&self) -> &'static str {
        match self {
            Self::RuleEvaluation(_) => "rule evaluation",
            Self::Dispatch(_) => "dispatcher",
            Self::Io(_) => "I/O",
            Self::InvalidResponse(_) => "invalid response",
            Self::ResponseMismatch => "response mismatch",
            Self::TooManyIgnoredUdpResponses => "too many unrelated responses",
            Self::MessageTooLarge => "response too large",
        }
    }

    fn summary(&self, nameserver_index: usize) -> Box<str> {
        format!("nameserver {nameserver_index} failed: {}", self.category()).into()
    }
}

fn udp_response_matches_query(query: &DnsMessage, response: &[u8]) -> Result<bool, AttemptError> {
    match validate_response_identity(query, response) {
        Ok(_) | Err(DnsError::TruncatedResponse) => Ok(true),
        Err(DnsError::ResponseMismatch | DnsError::NotAResponse | DnsError::UnsupportedOpcode) => {
            Ok(false)
        }
        Err(error) => Err(AttemptError::InvalidResponse(error)),
    }
}

fn udp_response_matches_classified_query(
    query: &ClassifiedDnsQuery,
    response: &[u8],
) -> Result<bool, AttemptError> {
    match validate_opaque_response(query, response) {
        Ok(_) => Ok(true),
        Err(DnsError::ResponseMismatch | DnsError::NotAResponse | DnsError::UnsupportedOpcode) => {
            Ok(false)
        }
        Err(DnsError::TruncatedResponse) => Ok(true),
        Err(error) => Err(AttemptError::InvalidResponse(error)),
    }
}

fn validate_complete_response(
    query: &DnsMessage,
    response: &[u8],
) -> Result<DnsMessage, AttemptError> {
    let parsed = parse_response(response)?;
    if parsed.id != query.id || parsed.question != query.question {
        return Err(AttemptError::ResponseMismatch);
    }
    matching_answer_set(&parsed)?;
    Ok(parsed)
}

struct MatchingAnswerSet {
    addresses: Vec<IpAddr>,
    ttl: Option<u32>,
}

/// Follows only the CNAME chain reachable from the question and accepts address
/// records owned by its terminal name. The complete response scan accepts at
/// most 64 records, while only the first 16 unique terminal addresses are
/// retained for cache and redir-host hints.
fn matching_answer_set(response: &DnsMessage) -> Result<MatchingAnswerSet, DnsError> {
    if usize::from(response.answer_count) > MAX_RESPONSE_RECORDS
        || response.answers.len() > MAX_RESPONSE_RECORDS
    {
        return Err(DnsError::TooManyAnswers);
    }
    let mut current = response.question.name.as_str();
    let mut visited = Vec::with_capacity(MAX_RESPONSE_RECORDS + 1);
    visited.push(current);
    let mut ttl = None;

    for _ in 0..MAX_RESPONSE_RECORDS {
        let mut target = None;
        let mut link_ttl = None;
        for answer in &response.answers {
            if answer.name != current {
                continue;
            }
            let RecordData::Cname(candidate) = &answer.data else {
                continue;
            };
            if target.is_some_and(|existing| existing != candidate.as_str()) {
                return Err(DnsError::InvalidCnameChain);
            }
            target = Some(candidate.as_str());
            link_ttl = Some(link_ttl.map_or(answer.ttl, |value: u32| value.min(answer.ttl)));
        }

        let Some(next) = target else {
            break;
        };
        if visited.contains(&next) {
            return Err(DnsError::InvalidCnameChain);
        }
        let link_ttl = link_ttl.expect("a CNAME target has a TTL");
        ttl = Some(ttl.map_or(link_ttl, |value: u32| value.min(link_ttl)));
        visited.push(next);
        current = next;
    }

    let mut addresses = Vec::with_capacity(response.answers.len().min(MAX_ANSWERS));
    for answer in &response.answers {
        if answer.name != current {
            continue;
        }
        let address = match (response.question.query_type, &answer.data) {
            (QueryType::A, RecordData::A(address)) => IpAddr::V4(*address),
            (QueryType::Aaaa, RecordData::Aaaa(address)) => IpAddr::V6(*address),
            _ => continue,
        };
        ttl = Some(ttl.map_or(answer.ttl, |value: u32| value.min(answer.ttl)));
        if addresses.len() < MAX_ANSWERS && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(MatchingAnswerSet { addresses, ttl })
}

fn internal_source(upstream: IpAddr) -> SocketAddr {
    match upstream {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn rewrite_query_id(query: &[u8], upstream_id: u16) -> Vec<u8> {
    debug_assert!(query.len() >= 2, "classified DNS query has a header");
    debug_assert_ne!(upstream_id, 0, "upstream DNS ID must be non-zero");
    let mut rewritten = query.to_vec();
    rewritten[..2].copy_from_slice(&upstream_id.to_be_bytes());
    rewritten
}

fn restore_response_id(response: &mut [u8], client_id: u16) {
    debug_assert!(response.len() >= 2, "validated DNS response has a header");
    response[..2].copy_from_slice(&client_id.to_be_bytes());
}

fn synthesize_response(
    query: &DnsMessage,
    value: &CacheValue,
    answer_ttl: u32,
) -> Result<Vec<u8>, RuntimeDnsError> {
    let (rcode, addresses): (u8, &[IpAddr]) = match value {
        CacheValue::Positive(addresses) => (RCODE_NOERROR, addresses),
        CacheValue::Negative { rcode } => (*rcode, &[]),
    };
    let answer_count = u16::try_from(addresses.len())
        .map_err(|_| RuntimeDnsError::Cache(DnsError::TooManyCacheAddresses))?;
    let mut response = Vec::with_capacity(64 + addresses.len() * 28);
    response.extend_from_slice(&query.id.to_be_bytes());
    let mut flags = DNS_FLAG_RESPONSE | DNS_FLAG_RECURSION_AVAILABLE | u16::from(rcode);
    if query.recursion_desired {
        flags |= DNS_FLAG_RECURSION_DESIRED;
    }
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&answer_count.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    encode_name(&query.question.name, &mut response);
    response.extend_from_slice(&(query.question.query_type as u16).to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    for address in addresses {
        response.extend_from_slice(&[0xc0, 0x0c]);
        let (record_type, record_data): (u16, &[u8]) = match address {
            IpAddr::V4(address) => (QueryType::A as u16, &address.octets()),
            IpAddr::V6(address) => (QueryType::Aaaa as u16, &address.octets()),
        };
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&answer_ttl.to_be_bytes());
        response.extend_from_slice(&(record_data.len() as u16).to_be_bytes());
        response.extend_from_slice(record_data);
    }
    if response.len() > MAX_MESSAGE_SIZE {
        return Err(RuntimeDnsError::Cache(DnsError::MessageTooLarge));
    }
    Ok(response)
}

fn encode_name(name: &str, output: &mut Vec<u8>) {
    for label in name.split('.') {
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;
    use tokio::{
        net::{TcpListener, UdpSocket},
        sync::{Notify, Semaphore},
    };

    use super::*;
    use crate::{
        config::{DnsNameserverPolicy, DnsRoute, IpCidr, RuleAction, RuleKind, RuleSpec},
        dialer::Dialer,
        dispatch::{BoxStream, DatagramTransport},
        dns::{DnsQuestion, DnsRecord, MAX_CACHE_ENTRIES},
        geodata::{DynamicGeoData, GEOSITE_FILE_NAME, GeoData},
        outbound::DirectOutbound,
        routing::{EmptyGeoMatcher, RuleSet},
    };

    #[derive(Debug)]
    struct PolicyGeoMatcher;

    impl GeoMatcher for PolicyGeoMatcher {
        fn matches_geosite(&self, code: &str, domain: &str) -> bool {
            match code {
                "private" => domain == "internal.test" || domain.ends_with(".internal.test"),
                "cn" => domain == "cn" || domain.ends_with(".cn"),
                "apple" => domain == "apple.com" || domain.ends_with(".apple.com"),
                "first" | "second" => domain == "overlap.test",
                _ => false,
            }
        }

        fn matches_geoip(&self, _code: &str, _address: IpAddr) -> bool {
            false
        }
    }

    // Publish a replacement after the first real GeoSite lookup, including
    // when that lookup uses the immutable view captured by the resolver.
    struct SwapAfterFirstGeoSiteMatch {
        inner: Arc<dyn GeoMatcher>,
        dynamic: Arc<DynamicGeoData>,
        replacement: Arc<StdMutex<Option<Arc<GeoData>>>>,
    }

    impl GeoMatcher for SwapAfterFirstGeoSiteMatch {
        fn routing_snapshot(&self) -> Option<Arc<dyn GeoMatcher>> {
            self.inner.routing_snapshot().map(|snapshot| {
                Arc::new(Self {
                    inner: snapshot,
                    dynamic: self.dynamic.clone(),
                    replacement: self.replacement.clone(),
                }) as Arc<dyn GeoMatcher>
            })
        }

        fn matches_geosite(&self, code: &str, domain: &str) -> bool {
            let matches = self.inner.matches_geosite(code, domain);
            if let Some(replacement) = self.replacement.lock().unwrap().take() {
                self.dynamic.activate(replacement);
            }
            matches
        }

        fn matches_geoip(&self, code: &str, address: IpAddr) -> bool {
            self.inner.matches_geoip(code, address)
        }
    }

    #[derive(Debug)]
    struct ResponseSpec {
        rcode: u8,
        truncated: bool,
        answers: Vec<IpAddr>,
    }

    impl ResponseSpec {
        fn answer(address: IpAddr) -> Self {
            Self {
                rcode: RCODE_NOERROR,
                truncated: false,
                answers: vec![address],
            }
        }

        fn rcode(rcode: u8) -> Self {
            Self {
                rcode,
                truncated: false,
                answers: Vec::new(),
            }
        }

        fn truncated() -> Self {
            Self {
                rcode: RCODE_NOERROR,
                truncated: true,
                answers: Vec::new(),
            }
        }
    }

    #[derive(Debug)]
    enum MockReply {
        Response(ResponseSpec),
        AfterRetry(ResponseSpec),
        MismatchesThenResponse {
            remaining: usize,
            response: ResponseSpec,
        },
        Gated {
            response: ResponseSpec,
            release: Arc<Notify>,
        },
        GatedTransportError {
            release: Arc<Notify>,
        },
        TransportError,
        Pending,
    }

    #[derive(Default)]
    struct MockDispatcher {
        udp_replies: StdMutex<VecDeque<MockReply>>,
        tcp_replies: StdMutex<VecDeque<MockReply>>,
        udp_calls: AtomicUsize,
        tcp_calls: AtomicUsize,
        udp_queries: Arc<StdMutex<Vec<u16>>>,
        tcp_queries: Arc<StdMutex<Vec<u16>>>,
        udp_ids: Arc<StdMutex<Vec<u16>>>,
        udp_payloads: Arc<StdMutex<Vec<Vec<u8>>>>,
        tcp_ids: Arc<StdMutex<Vec<u16>>>,
        udp_destinations: Arc<StdMutex<Vec<Destination>>>,
        tcp_destinations: Arc<StdMutex<Vec<Destination>>>,
        inbounds: Arc<StdMutex<Vec<InboundKind>>>,
    }

    impl MockDispatcher {
        fn with_replies(udp: Vec<MockReply>, tcp: Vec<MockReply>) -> Self {
            Self {
                udp_replies: StdMutex::new(udp.into()),
                tcp_replies: StdMutex::new(tcp.into()),
                ..Self::default()
            }
        }
    }

    enum TcpScriptReply {
        Response(ResponseSpec),
        WrongId(ResponseSpec),
        Gated {
            response: ResponseSpec,
            release: Arc<Semaphore>,
        },
    }

    #[derive(Default)]
    struct ScriptedTcpDispatcher {
        scripts: StdMutex<VecDeque<Vec<TcpScriptReply>>>,
        tcp_calls: AtomicUsize,
        tcp_queries: Arc<AtomicUsize>,
    }

    impl ScriptedTcpDispatcher {
        fn new(scripts: Vec<Vec<TcpScriptReply>>) -> Self {
            Self {
                scripts: StdMutex::new(scripts.into()),
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl Dispatcher for ScriptedTcpDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.tcp_calls.fetch_add(1, Ordering::AcqRel);
            let script = self.scripts.lock().unwrap().pop_front().ok_or_else(|| {
                DispatchError::Other("unexpected scripted TCP connection".to_owned())
            })?;
            let queries = Arc::clone(&self.tcp_queries);
            let (client, mut server) = tokio::io::duplex(MAX_MESSAGE_SIZE * 2);
            tokio::spawn(async move {
                for reply in script {
                    let Ok(length) = server.read_u16().await else {
                        return;
                    };
                    let mut query = vec![0_u8; usize::from(length)];
                    if server.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    queries.fetch_add(1, Ordering::AcqRel);
                    let (spec, wrong_id) = match reply {
                        TcpScriptReply::Response(spec) => (spec, false),
                        TcpScriptReply::WrongId(spec) => (spec, true),
                        TcpScriptReply::Gated { response, release } => {
                            if release.acquire().await.is_err() {
                                return;
                            }
                            (response, false)
                        }
                    };
                    let mut response = response_for_query(&query, &spec);
                    if wrong_id {
                        let id = u16::from_be_bytes([response[0], response[1]]).wrapping_add(1);
                        response[..2].copy_from_slice(&id.to_be_bytes());
                    }
                    if server.write_u16(response.len() as u16).await.is_err()
                        || server.write_all(&response).await.is_err()
                    {
                        return;
                    }
                }
            });
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::Other(
                "scripted TCP dispatcher does not support UDP".to_owned(),
            ))
        }
    }

    #[async_trait]
    impl Dispatcher for MockDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.tcp_calls.fetch_add(1, Ordering::AcqRel);
            self.inbounds.lock().unwrap().push(session.inbound);
            self.tcp_destinations
                .lock()
                .unwrap()
                .push(session.destination);
            let reply = self
                .tcp_replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| DispatchError::Other("unexpected mock TCP call".to_owned()))?;
            let MockReply::Response(reply) = reply else {
                return match reply {
                    MockReply::TransportError => Err(DispatchError::HostUnreachable),
                    MockReply::Pending => std::future::pending().await,
                    MockReply::Response(_) => unreachable!(),
                    MockReply::AfterRetry(_)
                    | MockReply::MismatchesThenResponse { .. }
                    | MockReply::Gated { .. }
                    | MockReply::GatedTransportError { .. } => Err(DispatchError::Other(
                        "UDP-only mock reply used for TCP".to_owned(),
                    )),
                };
            };

            let queries = self.tcp_queries.clone();
            let ids = self.tcp_ids.clone();
            let (client, mut server) = tokio::io::duplex(MAX_MESSAGE_SIZE * 2);
            tokio::spawn(async move {
                let length = server.read_u16().await.unwrap() as usize;
                let mut query = vec![0_u8; length];
                server.read_exact(&mut query).await.unwrap();
                let classified = classify_query(&query).unwrap();
                queries.lock().unwrap().push(classified.question.query_type);
                ids.lock().unwrap().push(classified.id);
                let response = response_for_query(&query, &reply);
                server.write_u16(response.len() as u16).await.unwrap();
                server.write_all(&response).await.unwrap();
            });
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.udp_calls.fetch_add(1, Ordering::AcqRel);
            self.inbounds.lock().unwrap().push(session.inbound);
            let reply = self
                .udp_replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| DispatchError::Other("unexpected mock UDP call".to_owned()))?;
            Ok(Box::new(MockDatagrams {
                reply: Some(reply),
                query: None,
                remote: None,
                queries: self.udp_queries.clone(),
                ids: self.udp_ids.clone(),
                payloads: self.udp_payloads.clone(),
                destinations: self.udp_destinations.clone(),
                send_count: 0,
            }))
        }
    }

    struct MockDatagrams {
        reply: Option<MockReply>,
        query: Option<Vec<u8>>,
        remote: Option<Destination>,
        queries: Arc<StdMutex<Vec<u16>>>,
        ids: Arc<StdMutex<Vec<u16>>>,
        payloads: Arc<StdMutex<Vec<Vec<u8>>>>,
        destinations: Arc<StdMutex<Vec<Destination>>>,
        send_count: usize,
    }

    #[async_trait]
    impl DatagramTransport for MockDatagrams {
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            self.send_count += 1;
            self.payloads
                .lock()
                .unwrap()
                .push(datagram.payload.to_vec());
            let parsed = classify_query(&datagram.payload)
                .map_err(|error| DispatchError::Other(error.to_string()))?;
            self.queries
                .lock()
                .unwrap()
                .push(parsed.question.query_type);
            self.ids.lock().unwrap().push(parsed.id);
            self.destinations
                .lock()
                .unwrap()
                .push(datagram.remote.clone());
            self.remote = Some(datagram.remote);
            self.query = Some(datagram.payload.to_vec());
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if matches!(self.reply.as_ref(), Some(MockReply::Pending)) {
                return std::future::pending().await;
            }
            if let Some(release) = self.reply.as_ref().and_then(|reply| match reply {
                MockReply::Gated { release, .. } | MockReply::GatedTransportError { release } => {
                    Some(Arc::clone(release))
                }
                _ => None,
            }) {
                release.notified().await;
            }
            if matches!(self.reply.as_ref(), Some(MockReply::AfterRetry(_))) && self.send_count < 2
            {
                return std::future::pending().await;
            }
            if let Some(MockReply::MismatchesThenResponse {
                remaining,
                response,
            }) = self.reply.as_mut()
                && *remaining != 0
            {
                *remaining -= 1;
                let query = self.query.as_ref().expect("mock receive before send");
                let mut response = response_for_query(query, response);
                let wrong_id = u16::from_be_bytes([response[0], response[1]]).wrapping_add(1);
                response[..2].copy_from_slice(&wrong_id.to_be_bytes());
                return Ok(Datagram {
                    remote: self.remote.clone().unwrap(),
                    payload: Bytes::from(response),
                    sniffed_domain: None,
                });
            }
            let reply = self.reply.take().expect("mock reply already consumed");
            let reply = match reply {
                MockReply::Response(reply)
                | MockReply::AfterRetry(reply)
                | MockReply::Gated {
                    response: reply, ..
                }
                | MockReply::MismatchesThenResponse {
                    remaining: 0,
                    response: reply,
                } => reply,
                other => {
                    return match other {
                        MockReply::TransportError => Err(DispatchError::NetworkUnreachable),
                        MockReply::GatedTransportError { .. } => {
                            Err(DispatchError::NetworkUnreachable)
                        }
                        MockReply::Pending => std::future::pending().await,
                        MockReply::Response(_)
                        | MockReply::AfterRetry(_)
                        | MockReply::Gated { .. }
                        | MockReply::MismatchesThenResponse { .. } => unreachable!(),
                    };
                }
            };
            let query = self.query.take().expect("mock receive before send");
            Ok(Datagram {
                remote: self.remote.take().unwrap(),
                payload: Bytes::from(response_for_query(&query, &reply)),
                sniffed_domain: None,
            })
        }
    }

    fn nameserver(index: u8, transport: DnsTransport) -> DnsNameserver {
        DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport,
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, index)).into(),
            port: 53,
            route: crate::config::DnsRoute::Route(crate::config::RouteTargetId::Proxy(
                crate::config::ProxyId::new(0).unwrap(),
            )),
        }
    }

    fn dns_policy(codes: &[&str], nameservers: Vec<DnsNameserver>) -> DnsNameserverPolicy {
        DnsNameserverPolicy {
            selector: crate::config::DnsPolicySelector::GeoSite(
                codes
                    .iter()
                    .map(|code| (*code).to_owned())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            nameservers: nameservers.into_boxed_slice(),
        }
    }

    fn opaque_query(id: u16, name: &str, query_type: u16) -> Vec<u8> {
        let mut query = build_query(id, name, QueryType::A).unwrap();
        let type_offset = query.len() - 4;
        query[type_offset..type_offset + 2].copy_from_slice(&query_type.to_be_bytes());
        query
    }

    fn rule(kind: RuleKind, action: RuleAction) -> RuleSpec {
        RuleSpec {
            kind,
            action,
            no_resolve: false,
        }
    }

    fn config(ipv6: bool, nameservers: Vec<DnsNameserver>) -> DnsConfig {
        DnsConfig {
            enable: true,
            ipv6,
            nameservers,
            nameserver_policies: Vec::new(),
            ..DnsConfig::default()
        }
    }

    #[test]
    fn address_query_does_not_reserve_unused_fallback_state() {
        let upstream = nameserver(1, DnsTransport::Udp);
        let resolver = RuntimeDns::new(
            &config(false, vec![upstream]),
            Arc::new(MockDispatcher::default()),
        );
        let query = build_query(7, "memory.example", QueryType::A).unwrap();
        let classified = classify_query(&query).unwrap();
        let permit = resolver.begin_query();
        let address = resolver.exchange_address(
            &query,
            &classified,
            permit.deadline,
            FailureMode::WireServfail,
        );
        let leader = resolver.exchange_address_leader(&query, &classified, permit.deadline, 0);
        // These are the production futures; constructing them opens no I/O.
        let bytes = std::mem::size_of_val(&leader);
        assert!(
            bytes <= 1024,
            "single-upstream DNS leader reserves {bytes} bytes including inactive fallback state"
        );
        let bytes = std::mem::size_of_val(&address);
        assert!(
            bytes <= 2048,
            "ordinary address query retains {bytes} bytes"
        );
    }

    #[test]
    fn udp_attempt_does_not_retain_unused_stream_handshake_state() {
        let upstream = nameserver(1, DnsTransport::Udp);
        let resolver = RuntimeDns::new(
            &config(false, vec![upstream.clone()]),
            Arc::new(MockDispatcher::default()),
        );
        let query = build_query(7, "memory.example", QueryType::A).unwrap();
        let parsed = parse_query(&query).unwrap();
        let permits = Semaphore::new(4);
        // Construct the real racing attempt without polling or opening I/O.
        let attempt = resolver.exchange_nameserver_limited(upstream, &query, &parsed, &permits);
        let bytes = std::mem::size_of_val(&attempt);
        assert!(
            bytes <= 4096,
            "UDP DNS attempt retains {bytes} bytes before selecting a transport"
        );
    }

    #[tokio::test]
    async fn classical_logical_selectors_drive_dns_policy_and_sniffing_without_egress() {
        let configuration = crate::config::Config::parse_yaml(
            br#"
rule-providers:
  domains:
    type: inline
    behavior: classical
    payload: ['AND,((DOMAIN-SUFFIX,example),(DOMAIN-KEYWORD,api))']
  blocked:
    type: inline
    behavior: classical
    payload: ['OR,((DOMAIN,skip.example),(DOMAIN,other.example))']
  addresses:
    type: inline
    behavior: classical
    payload: ['AND,((IP-CIDR,192.0.2.0/24),(NOT,((IP-CIDR,192.0.2.7/32))))']
dns:
  enable: true
  use-system-hosts: false
  nameserver: ['rcode://success']
  nameserver-policy:
    'rule-set:domains': ['rcode://refused']
sniffer:
  enable: true
  parse-pure-ip: false
  force-dns-mapping: false
  force-domain: ['rule-set:domains']
  skip-domain: ['rule-set:blocked']
  skip-src-address: ['rule-set:addresses']
  skip-dst-address: ['rule-set:addresses']
  sniff: {TLS: {ports: [443]}}
"#,
        )
        .unwrap();
        let dispatcher = Arc::new(MockDispatcher::with_replies(vec![], vec![]));
        let resolver = RuntimeDns::new(&configuration.dns, dispatcher.clone());
        for (name, expected) in [
            ("api.example", RCODE_REFUSED),
            ("www.example", RCODE_NOERROR),
        ] {
            let response = resolver
                .exchange(&build_query(9, name, QueryType::A).unwrap())
                .await
                .unwrap();
            assert_eq!(parse_response(&response).unwrap().rcode, expected);
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 0);
        let policy = crate::sniffing::Policy::new(
            Arc::new(configuration.sniffer),
            Arc::new(EmptyGeoMatcher),
        );
        let destination = Destination::Ip("203.0.113.1:443".parse().unwrap());
        let plan = policy
            .plan(
                "198.51.100.1:9000".parse().unwrap(),
                &destination,
                Some("api.example"),
                false,
            )
            .unwrap();
        assert!(plan.tcp_enabled());
        assert_eq!(plan.accepts("skip.example"), Ok(false));
        assert_eq!(plan.accepts("api.example"), Ok(true));
        for (source, destination, expected) in [
            ("192.0.2.1:9000", "203.0.113.1:443", false),
            ("192.0.2.7:9000", "203.0.113.1:443", true),
            ("198.51.100.1:9000", "192.0.2.1:443", false),
        ] {
            let plan = policy
                .plan(
                    source.parse().unwrap(),
                    &Destination::Ip(destination.parse().unwrap()),
                    Some("api.example"),
                    false,
                )
                .unwrap();
            assert_eq!(plan.tcp_enabled(), expected);
        }
    }

    #[tokio::test]
    async fn rule_budget_propagates_through_fake_ip_policy_and_sniffer_without_egress() {
        let payload = serde_json::to_string(&vec![
            "AND,((DOMAIN-REGEX,(?=never)never),(DOMAIN-SUFFIX,example))";
            16
        ])
        .unwrap();
        let configuration = crate::config::Config::parse_yaml(
            format!(
                r#"
mixed-port: 1080
rule-providers:
  left: {{type: inline, behavior: classical, payload: {payload}}}
  right: {{type: inline, behavior: classical, payload: {payload}}}
dns:
  enable: true
  use-system-hosts: false
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
  fake-ip-filter: ['rule-set:left']
  nameserver: [192.0.2.1]
  nameserver-policy:
    'rule-set:left': [192.0.2.2]
    'rule-set:right': [192.0.2.3]
sniffer:
  enable: true
  force-domain: ['+.example']
  skip-domain: ['rule-set:left,right']
  sniff: {{TLS: {{ports: [443]}}}}
"#
            )
            .as_bytes(),
        )
        .unwrap();
        let dispatcher = Arc::new(MockDispatcher::with_replies(vec![], vec![]));
        let resolver = RuntimeDns::new(&configuration.dns, dispatcher.clone());
        let query = build_query(9, "api.example", QueryType::A).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(parse_response(&response).unwrap().rcode, RCODE_SERVFAIL);
        assert!(matches!(
            resolver.resolve("api.example").await,
            Err(RuntimeDnsError::RuleEvaluation(
                crate::config::MatchFailure::Budget
            ))
        ));
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 0);
        assert_eq!(
            resolver
                .recover_fake_ip("198.18.0.2".parse().unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let policy = crate::sniffing::Policy::new(
            Arc::new(configuration.sniffer),
            Arc::new(EmptyGeoMatcher),
        );
        let plan = policy
            .plan(
                "198.51.100.1:9000".parse().unwrap(),
                &Destination::Ip("203.0.113.1:443".parse().unwrap()),
                Some("api.example"),
                false,
            )
            .unwrap();
        assert_eq!(
            plan.accepts("api.example"),
            Err(crate::config::MatchFailure::Budget)
        );
        assert_eq!(
            plan.clone().accepts("api.example"),
            Err(crate::config::MatchFailure::Budget)
        );
    }

    #[tokio::test]
    async fn upstream_wrappers_cover_system_dhcp_and_rcode_before_source_io() {
        for endpoint in ["system", "dhcp://physical1", "rcode://refused"] {
            let configuration = crate::config::Config::parse_yaml(format!("mixed-port: 1080\ndns:\n  enable: true\n  ipv6: true\n  use-system-hosts: false\n  nameserver: ['{endpoint}#ecs=192.0.2.255/25&disable-ipv6=true']\n").as_bytes()).unwrap();
            let dispatcher = Arc::new(MockDispatcher::with_replies(
                vec![MockReply::Response(ResponseSpec::answer(
                    "203.0.113.10".parse().unwrap(),
                ))],
                vec![],
            ));
            let resolver = Arc::new(RuntimeDns::new(&configuration.dns, dispatcher.clone()));
            resolver.sources.register(&resolver);
            resolver
                .sources
                .replace(dns_source_snapshot(1, "203.0.113.53"))
                .await
                .unwrap();
            let blocked = build_query(79, "blocked.example", QueryType::Aaaa).unwrap();
            let response = resolver.exchange(&blocked).await.unwrap();
            assert_eq!(response[3] & 0x0f, RCODE_NOERROR);
            assert_eq!(response[2] & 0x04, 0x04);
            assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
            let query = build_query(80, "allowed.example", QueryType::A).unwrap();
            let response = resolver.exchange(&query).await.unwrap();
            if endpoint.starts_with("rcode") {
                assert_eq!(response[3] & 0x0f, RCODE_REFUSED);
                assert_eq!(response[10..12], [0, 1]);
                assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
            } else {
                assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
                let payloads = dispatcher.udp_payloads.lock().unwrap();
                assert_eq!(
                    &payloads[0][payloads[0].len() - 12..],
                    &[0, 8, 0, 8, 0, 1, 25, 0, 192, 0, 2, 128]
                );
                let expected = if endpoint == "system" {
                    "203.0.113.53:53"
                } else {
                    "192.0.2.53:53"
                };
                assert_eq!(
                    *dispatcher.udp_destinations.lock().unwrap(),
                    vec![Destination::Ip(expected.parse().unwrap())]
                );
            }
        }
    }

    #[tokio::test]
    async fn upstream_typed_cache_separates_client_ecs_and_preserves_edns_wire() {
        let first: IpAddr = "203.0.113.1".parse().unwrap();
        let second: IpAddr = "203.0.113.2".parse().unwrap();
        let plain: IpAddr = "203.0.113.3".parse().unwrap();
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            [first, second, plain]
                .into_iter()
                .map(|address| MockReply::Response(ResponseSpec::answer(address)))
                .collect(),
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );
        let plain_query = build_query(91, "cache.example", QueryType::A).unwrap();
        for (index, (address, expected)) in [
            ("192.0.2.1", first),
            ("192.0.2.2", second),
            ("192.0.2.1", first),
        ]
        .into_iter()
        .enumerate()
        {
            let options = crate::config::DnsNameserverOptions {
                ecs: Some(crate::config::DnsEcs {
                    address: address.parse().unwrap(),
                    prefix_len: 32,
                }),
                ..Default::default()
            };
            let mut query = super::super::options::with_ecs(&plain_query, &options)
                .unwrap()
                .into_owned();
            let id = 92 + index as u16;
            query[..2].copy_from_slice(&id.to_be_bytes());
            let response = resolver.exchange(&query).await.unwrap();
            assert_eq!(parse_response(&response).unwrap().id, id);
            assert_eq!(
                matching_answer_set(&parse_response(&response).unwrap())
                    .unwrap()
                    .addresses,
                vec![expected]
            );
            assert_eq!(response[10..12], [0, 1]);
            assert_eq!(&response[response.len() - 12..], &query[query.len() - 12..]);
        }
        for _ in 0..2 {
            let response = resolver.exchange(&plain_query).await.unwrap();
            assert_eq!(
                matching_answer_set(&parse_response(&response).unwrap())
                    .unwrap()
                    .addresses,
                vec![plain]
            );
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 3);
        assert_eq!(resolver.cache.lock().await.len(), 3);
    }

    #[test]
    fn all_dns_roles_share_the_session_trust_store() {
        let mut config = config(false, vec![nameserver(1, DnsTransport::Tls)]);
        config.default_nameservers = vec![nameserver(2, DnsTransport::Tls)];
        config.proxy_nameservers = vec![nameserver(3, DnsTransport::Https)];
        config.direct_nameservers = vec![nameserver(4, DnsTransport::Https)];
        let security = crate::security::SecurityContext::new();
        let resolver = RuntimeDns::assemble(
            &config,
            DnsEgress::Single(Arc::new(MockDispatcher::default())),
            Arc::new(EmptyGeoMatcher),
            config.cache_max_size,
            0,
            security.clone(),
        );
        for role in [
            &resolver,
            resolver.bootstrap.as_deref().unwrap(),
            resolver.proxy_resolver.as_deref().unwrap(),
            resolver.direct_resolver.as_deref().unwrap(),
        ] {
            assert!(security.shares_roots_with(&role.tcp_pool.security));
        }
    }

    fn response_for_query(query: &[u8], spec: &ResponseSpec) -> Vec<u8> {
        classify_query(query).unwrap();
        let header = super::super::parse_wire_question_header(query).unwrap();
        let mut response = query[..header.records_offset].to_vec();
        let mut flags = DNS_FLAG_RESPONSE
            | DNS_FLAG_RECURSION_DESIRED
            | DNS_FLAG_RECURSION_AVAILABLE
            | u16::from(spec.rcode);
        if spec.truncated {
            flags |= 0x0200;
        }
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        let answer_count = spec.answers.len() as u16;
        response[6..8].copy_from_slice(&answer_count.to_be_bytes());
        for address in &spec.answers {
            response.extend_from_slice(&[0xc0, 0x0c]);
            match address {
                IpAddr::V4(address) => {
                    response.extend_from_slice(&(QueryType::A as u16).to_be_bytes());
                    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
                    response.extend_from_slice(&60_u32.to_be_bytes());
                    response.extend_from_slice(&4_u16.to_be_bytes());
                    response.extend_from_slice(&address.octets());
                }
                IpAddr::V6(address) => {
                    response.extend_from_slice(&(QueryType::Aaaa as u16).to_be_bytes());
                    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
                    response.extend_from_slice(&60_u32.to_be_bytes());
                    response.extend_from_slice(&16_u16.to_be_bytes());
                    response.extend_from_slice(&address.octets());
                }
            }
        }
        response.extend_from_slice(&query[header.records_offset..]);
        response
    }

    fn parsed_response_with_answers(
        name: &str,
        query_type: QueryType,
        answers: Vec<DnsRecord>,
    ) -> DnsMessage {
        let answer_count = u16::try_from(answers.len()).unwrap();
        DnsMessage {
            id: 1,
            is_response: true,
            authoritative: false,
            recursion_desired: true,
            recursion_available: true,
            rcode: RCODE_NOERROR,
            question: DnsQuestion {
                name: name.to_owned(),
                query_type,
            },
            answers,
            answer_count,
        }
    }

    #[tokio::test]
    async fn runtime_dns_separates_bootstrap_proxy_direct_and_hosts() {
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
hosts:
  '+.local.example': [192.0.2.99]
  alias.example: target.local.example
dns:
  enable: true
  use-system-hosts: false
  default-nameserver: [192.0.2.10]
  nameserver: [udp://dns.example]
  proxy-server-nameserver: [192.0.2.20]
  direct-nameserver: [192.0.2.30]
"#,
        )
        .unwrap();
        let answers: Vec<IpAddr> = ["192.0.2.1", "203.0.113.1", "203.0.113.2", "203.0.113.3"]
            .map(|ip| ip.parse().unwrap())
            .to_vec();
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            answers
                .iter()
                .copied()
                .map(|ip| MockReply::Response(ResponseSpec::answer(ip)))
                .collect(),
            vec![],
        ));
        let dns = Arc::new(RuntimeDns::new(&config.dns, dispatcher.clone()));
        assert_eq!(dns.resolve("business.example").await.unwrap(), [answers[1]]);
        let resolution = crate::dns::resolution::ResolutionContext::runtime(false);
        resolution.bind_runtime(Some(&dns)).unwrap();
        let node = Destination::domain("proxy.example", 443).unwrap();
        assert_eq!(
            resolution
                .resolve_proxy(&node, TokioInstant::now() + QUERY_TIMEOUT)
                .await
                .unwrap()
                .addresses[0]
                .ip(),
            answers[2]
        );
        assert_eq!(
            dns.resolve_direct("direct.example").await.unwrap(),
            [answers[3]]
        );
        assert_eq!(
            dns.resolve("alias.example").await.unwrap(),
            ["192.0.2.99".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            *dispatcher.udp_destinations.lock().unwrap(),
            [
                "192.0.2.10:53",
                "192.0.2.1:53",
                "192.0.2.20:53",
                "192.0.2.30:53"
            ]
            .map(|address| Destination::Ip(address.parse().unwrap()))
        );
        resolution.close();
        assert!(
            resolution
                .resolve_proxy(&node, TokioInstant::now() + QUERY_TIMEOUT)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn concurrent_upstreams_drop_the_losing_attempt() {
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Pending,
                MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR)),
            ],
            vec![],
        ));
        let dns = RuntimeDns::new(
            &config(
                false,
                vec![
                    nameserver(1, DnsTransport::Udp),
                    nameserver(2, DnsTransport::Udp),
                ],
            ),
            dispatcher.clone(),
        );
        tokio::time::timeout(Duration::from_millis(100), dns.resolve("race.example"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 2);
        assert_eq!(dns.singleflight.len(), 0);
    }

    #[tokio::test]
    async fn udp_exchange_uses_internal_context_and_fixed_ip_endpoint() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );
        let query = build_query(42, "example.com", QueryType::A).unwrap();
        let response = resolver.exchange(&query).await.unwrap();

        assert_eq!(
            matching_answer_set(&parse_response(&response).unwrap())
                .unwrap()
                .addresses,
            [address]
        );
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 0);
        assert_eq!(
            *dispatcher.udp_destinations.lock().unwrap(),
            vec![Destination::Ip("192.0.2.1:53".parse().unwrap())]
        );
        assert_eq!(
            *dispatcher.inbounds.lock().unwrap(),
            vec![InboundKind::InternalDns]
        );
    }

    #[tokio::test]
    async fn wire_queries_use_distinct_nonzero_upstream_ids_and_restore_the_client_id() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::answer(address)),
                MockReply::Response(ResponseSpec::answer(address)),
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );

        for name in ["first.example", "second.example"] {
            let query = build_query(77, name, QueryType::A).unwrap();
            let response = resolver.exchange(&query).await.unwrap();
            assert_eq!(parse_response(&response).unwrap().id, 77);
        }

        let ids = dispatcher.udp_ids.lock().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.iter().all(|id| *id != 0));
        assert_ne!(ids[0], ids[1]);
    }

    #[tokio::test]
    async fn udp_retry_reuses_one_transport_and_one_rewritten_id() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::AfterRetry(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );
        let query = build_query(0, "retry.example", QueryType::A).unwrap();
        let response = resolver.exchange(&query).await.unwrap();

        assert_eq!(parse_response(&response).unwrap().id, 0);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        let ids = dispatcher.udp_ids.lock().unwrap();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], 0);
        assert_eq!(ids[0], ids[1]);
    }

    #[tokio::test]
    async fn udp_ignores_two_mismatches_but_the_third_fails_over() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 14));
        let first_dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::MismatchesThenResponse {
                remaining: 2,
                response: ResponseSpec::answer(address),
            }],
            vec![],
        ));
        let first_resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            first_dispatcher.clone(),
        );
        let query = build_query(88, "mismatch.example", QueryType::A).unwrap();
        let response = first_resolver.exchange(&query).await.unwrap();
        assert_eq!(parse_response(&response).unwrap().id, 88);
        assert_eq!(first_dispatcher.udp_calls.load(Ordering::Acquire), 1);

        let fallback_dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::MismatchesThenResponse {
                    remaining: 3,
                    response: ResponseSpec::answer(address),
                },
                MockReply::Response(ResponseSpec::answer(address)),
            ],
            vec![],
        ));
        let fallback_resolver = RuntimeDns::new(
            &config(
                false,
                vec![
                    nameserver(1, DnsTransport::Udp),
                    nameserver(2, DnsTransport::Udp),
                ],
            ),
            fallback_dispatcher.clone(),
        );
        let response = fallback_resolver.exchange(&query).await.unwrap();
        assert_eq!(parse_response(&response).unwrap().id, 88);
        assert_eq!(fallback_dispatcher.udp_calls.load(Ordering::Acquire), 2);
    }

    #[test]
    fn typed_udp_ignores_a_mismatched_tc_response_before_retrying_matching_tc() {
        let query = build_query(88, "mismatch.example", QueryType::A).unwrap();
        let parsed_query = parse_query(&query).unwrap();
        let mut response = response_for_query(&query, &ResponseSpec::truncated());
        response[..2].copy_from_slice(&89_u16.to_be_bytes());
        assert!(!udp_response_matches_query(&parsed_query, &response).unwrap());

        response[..2].copy_from_slice(&88_u16.to_be_bytes());
        assert!(udp_response_matches_query(&parsed_query, &response).unwrap());
    }

    #[tokio::test]
    async fn configured_tcp_nameserver_uses_dns_framing() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![],
            vec![MockReply::Response(ResponseSpec::answer(address))],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            dispatcher.clone(),
        );

        assert_eq!(resolver.resolve("example.com").await.unwrap(), [address]);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            *dispatcher.tcp_destinations.lock().unwrap(),
            vec![Destination::Ip("192.0.2.1:53".parse().unwrap())]
        );
        assert_eq!(
            *dispatcher.tcp_queries.lock().unwrap(),
            vec![QueryType::A as u16]
        );
    }

    #[test]
    fn tcp_pool_resource_contract_is_stable() {
        assert_eq!(TCP_POOL_MAX_IDLE, 4);
        assert_eq!(TCP_POOL_MAX_IDLE_PER_KEY, 2);
        assert_eq!(TCP_POOL_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(TCP_POOL_FINAL_EVENT, "runtime_dns_tcp_pool_final");
    }

    #[tokio::test]
    async fn tcp_pool_reuses_one_validated_connection_across_queries() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 61));
        let dispatcher = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            dispatcher.clone(),
        );

        assert_eq!(resolver.resolve("first.example").await.unwrap(), [address]);
        assert_eq!(resolver.resolve("second.example").await.unwrap(), [address]);

        let snapshot = resolver.tcp_pool.snapshot();
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(dispatcher.tcp_queries.load(Ordering::Acquire), 2);
        assert_eq!(snapshot.physical_opens, 1);
        assert_eq!(snapshot.reuse_hits, 1);
        assert_eq!(snapshot.current_idle, 1);
        assert_eq!(snapshot.current_busy, 0);
    }

    #[tokio::test]
    async fn stale_reused_tcp_connection_rebuilds_only_once() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 62));
        let dispatcher = Arc::new(ScriptedTcpDispatcher::new(vec![
            vec![TcpScriptReply::Response(ResponseSpec::answer(address))],
            vec![TcpScriptReply::Response(ResponseSpec::answer(address))],
        ]));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            dispatcher.clone(),
        );

        assert_eq!(resolver.resolve("warm.example").await.unwrap(), [address]);
        tokio::task::yield_now().await;
        assert_eq!(resolver.resolve("retry.example").await.unwrap(), [address]);

        let snapshot = resolver.tcp_pool.snapshot();
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 2);
        assert_eq!(snapshot.stale_retries, 1);
        assert_eq!(snapshot.discards, 1);
        assert_eq!(snapshot.current_idle, 1);
    }

    #[tokio::test]
    async fn reused_tcp_id_mismatch_rebuilds_once_but_truncation_only_fails_over() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 63));
        let mismatch_dispatcher = Arc::new(ScriptedTcpDispatcher::new(vec![
            vec![
                TcpScriptReply::Response(ResponseSpec::answer(address)),
                TcpScriptReply::WrongId(ResponseSpec::answer(address)),
            ],
            vec![TcpScriptReply::Response(ResponseSpec::answer(address))],
        ]));
        let mismatch_resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            mismatch_dispatcher.clone(),
        );
        mismatch_resolver.resolve("warm.example").await.unwrap();
        assert_eq!(
            mismatch_resolver.resolve("mismatch.example").await.unwrap(),
            [address]
        );
        assert_eq!(mismatch_dispatcher.tcp_calls.load(Ordering::Acquire), 2);
        assert_eq!(mismatch_resolver.tcp_pool.snapshot().stale_retries, 1);

        let truncated_dispatcher = Arc::new(ScriptedTcpDispatcher::new(vec![
            vec![
                TcpScriptReply::Response(ResponseSpec::answer(address)),
                TcpScriptReply::Response(ResponseSpec::truncated()),
            ],
            vec![TcpScriptReply::Response(ResponseSpec::answer(address))],
        ]));
        let truncated_resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            truncated_dispatcher.clone(),
        );
        truncated_resolver.resolve("warm.example").await.unwrap();
        assert!(
            truncated_resolver
                .resolve("truncated.example")
                .await
                .is_err()
        );
        assert_eq!(
            truncated_resolver.resolve("fresh.example").await.unwrap(),
            [address]
        );
        let snapshot = truncated_resolver.tcp_pool.snapshot();
        assert_eq!(truncated_dispatcher.tcp_calls.load(Ordering::Acquire), 2);
        assert_eq!(snapshot.stale_retries, 0);
        assert_eq!(snapshot.discards, 1);
    }

    #[tokio::test]
    async fn tcp_pool_key_includes_final_egress_route() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 64));
        let direct = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let proxy = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let mut direct_nameserver = nameserver(1, DnsTransport::Tcp);
        direct_nameserver.route = DnsRoute::Direct;
        let mut proxy_nameserver = direct_nameserver.clone();
        proxy_nameserver.route = DnsRoute::Route(crate::config::RouteTargetId::Proxy(
            crate::config::ProxyId::new(0).expect("proxy zero is valid"),
        ));
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![direct_nameserver.clone()]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![rule(RuleKind::Match, RuleAction::Direct)]).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );

        for (id, name, nameserver) in [
            (1, "direct.example", direct_nameserver),
            (2, "proxy.example", proxy_nameserver),
        ] {
            let query = build_query(id, name, QueryType::A).unwrap();
            let parsed = parse_query(&query).unwrap();
            resolver
                .exchange_nameserver(nameserver, &query, &parsed)
                .await
                .unwrap();
        }

        assert_eq!(direct.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(proxy.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(resolver.tcp_pool.snapshot().current_idle, 2);
    }

    #[tokio::test]
    async fn subrule_dns_rules_keep_round_robin_for_new_physical_connections() {
        use crate::{
            config::Config,
            routing::{ProxyGroups, RouteTargetDispatchers},
        };
        let mut configured = Config::parse_yaml(br#"
mixed-port: 1080
proxies:
  - {name: a, type: socks5, server: 192.0.2.10, port: 1080}
  - {name: b, type: socks5, server: 192.0.2.11, port: 1080}
proxy-groups:
  - {name: gate, type: load-balance, proxies: [PASS-RULE,a], strategy: round-robin, disable-udp: true}
  - {name: pool, type: load-balance, proxies: [a,b], strategy: round-robin}
rules: ['SUB-RULE,(DST-PORT,53),child', 'MATCH,REJECT']
sub-rules: {child: ['MATCH,gate', 'MATCH,pool']}
"#).unwrap();
        let address = "203.0.113.65".parse().unwrap();
        let a = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let b = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let direct: Arc<dyn Dispatcher> = Arc::new(MockDispatcher::default());
        let nodes: Vec<Arc<dyn Dispatcher>> = vec![a.clone(), b.clone()];
        let groups =
            ProxyGroups::new(&configured.proxy_groups, nodes.clone(), direct.clone()).unwrap();
        let targets = RouteTargetDispatchers::with_proxy_groups(nodes, &groups).unwrap();
        let mut upstream = nameserver(1, DnsTransport::Tcp);
        upstream.route = DnsRoute::Rules;
        let resolver = RuntimeDns::new_routed_proxies(
            &config(false, vec![upstream.clone()]),
            targets,
            direct,
            RuleSet::compile_config(&mut configured).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        assert_eq!(resolver.resolve("first.example").await.unwrap(), [address]);
        assert_eq!(resolver.resolve("pooled.example").await.unwrap(), [address]);
        assert_eq!(a.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(b.tcp_calls.load(Ordering::Acquire), 0);
        tokio::task::yield_now().await;
        assert_eq!(
            resolver.resolve("rebuilt.example").await.unwrap(),
            [address]
        );
        assert_eq!(b.tcp_calls.load(Ordering::Acquire), 1);
        upstream.route = DnsRoute::Route(crate::config::RouteTargetId::Group(
            crate::config::ProxyGroupId::new(0).unwrap(),
        ));
        let server = resolver.resolve_nameserver(&upstream).await.unwrap();
        assert!(matches!(
            resolver.egress_for(&server, Network::Tcp, |_| false),
            Err(AttemptError::Dispatch(DispatchError::NotAllowed))
        ));
        assert_eq!(groups.selection(0).choose(None, None), 0);
    }

    #[tokio::test]
    async fn group_switch_keeps_dns_cache_and_tcp_pool_until_a_new_connection() {
        use crate::config::{
            ProxyGroupId, ProxyGroupMemberConfig, ProxyGroupMemberTarget, ProxyId, RouteTargetId,
            SelectProxyGroupConfig,
        };
        use crate::routing::{ProxyGroups, RouteTargetDispatchers};

        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 65));
        let old = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let new = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let direct: Arc<dyn Dispatcher> = Arc::new(MockDispatcher::default());
        let proxy_dispatchers: Vec<Arc<dyn Dispatcher>> = vec![old.clone(), new.clone()];
        let groups = ProxyGroups::new(
            &[SelectProxyGroupConfig {
                kind: crate::config::GroupKind::Select,
                strategy: crate::config::BalanceStrategy::default(),
                hash_key: crate::config::BalanceHashKey::default(),
                health: crate::config::HealthCheckConfig::default(),
                tolerance: 0,
                max_failed_times: 5,
                disable_udp: false,
                hidden: false,
                icon: String::new(),
                name: "group".to_owned(),
                members: vec![
                    ProxyGroupMemberConfig {
                        name: "old".to_owned(),
                        target: ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(0).unwrap(),
                        )),
                    },
                    ProxyGroupMemberConfig {
                        name: "new".to_owned(),
                        target: ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(1).unwrap(),
                        )),
                    },
                ],
                initial_member: 0,
            }],
            proxy_dispatchers.clone(),
            direct.clone(),
        )
        .unwrap();
        let route_targets =
            RouteTargetDispatchers::with_proxy_groups(proxy_dispatchers, &groups).unwrap();
        let group = RouteTargetId::Group(ProxyGroupId::new(0).unwrap());
        let mut upstream = nameserver(1, DnsTransport::Tcp);
        upstream.route = DnsRoute::Route(group);
        let resolver = RuntimeDns::new_routed_proxies(
            &config(false, vec![upstream]),
            route_targets,
            direct,
            RuleSet::compile(vec![rule(RuleKind::Match, RuleAction::Route(group))]).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );

        assert_eq!(resolver.resolve("cached.example").await.unwrap(), [address]);
        groups.select("group", "new").unwrap();
        assert_eq!(resolver.resolve("cached.example").await.unwrap(), [address]);
        assert_eq!(new.tcp_calls.load(Ordering::Acquire), 0);

        assert_eq!(resolver.resolve("pooled.example").await.unwrap(), [address]);
        assert_eq!(old.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(old.tcp_queries.load(Ordering::Acquire), 2);
        assert_eq!(new.tcp_calls.load(Ordering::Acquire), 0);

        tokio::task::yield_now().await;
        assert_eq!(
            resolver.resolve("rebuilt.example").await.unwrap(),
            [address]
        );
        assert_eq!(new.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(new.tcp_queries.load(Ordering::Acquire), 1);
        assert_eq!(resolver.tcp_pool.snapshot().stale_retries, 1);
    }

    #[tokio::test]
    async fn tcp_pool_allows_active_connections_above_old_ceiling_but_retains_only_two_idle() {
        const ACTIVE: usize = 12;
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 65));
        let release = Arc::new(Semaphore::new(0));
        let scripts = (0..ACTIVE)
            .map(|_| {
                vec![TcpScriptReply::Gated {
                    response: ResponseSpec::answer(address),
                    release: Arc::clone(&release),
                }]
            })
            .collect();
        let dispatcher = Arc::new(ScriptedTcpDispatcher::new(scripts));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            dispatcher.clone(),
        ));
        let nameserver = nameserver(1, DnsTransport::Tcp);
        let mut tasks = Vec::new();
        for index in 0..ACTIVE {
            let resolver = Arc::clone(&resolver);
            let nameserver = nameserver.clone();
            tasks.push(tokio::spawn(async move {
                let query = build_query(
                    u16::try_from(index + 1).unwrap(),
                    &format!("busy-{index}.example"),
                    QueryType::A,
                )
                .unwrap();
                let parsed = parse_query(&query).unwrap();
                resolver
                    .exchange_nameserver(nameserver, &query, &parsed)
                    .await
            }));
        }

        timeout_at(TokioInstant::now() + Duration::from_secs(1), async {
            while dispatcher.tcp_calls.load(Ordering::Acquire) != ACTIVE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), ACTIVE);

        release.add_permits(ACTIVE);
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        let snapshot = resolver.tcp_pool.snapshot();
        assert_eq!(snapshot.peak_physical, ACTIVE);
        assert_eq!(snapshot.peak_busy, ACTIVE);
        assert_eq!(snapshot.current_physical, 2);
        assert_eq!(snapshot.current_idle, 2);
        assert_eq!(snapshot.idle_evictions, (ACTIVE - 2) as u64);
    }

    #[tokio::test]
    async fn tcp_pool_expires_idle_and_lru_bounds_global_idle() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66));
        let dispatcher = Arc::new(ScriptedTcpDispatcher::new(
            (0..7)
                .map(|_| vec![TcpScriptReply::Response(ResponseSpec::answer(address))])
                .collect(),
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            dispatcher.clone(),
        );

        for index in 1..=5 {
            let mut upstream = nameserver(index, DnsTransport::Tcp);
            upstream.route = DnsRoute::Route(crate::config::RouteTargetId::Proxy(
                crate::config::ProxyId::new(0).expect("proxy zero is valid"),
            ));
            let query = build_query(
                u16::from(index),
                &format!("idle-{index}.example"),
                QueryType::A,
            )
            .unwrap();
            let parsed = parse_query(&query).unwrap();
            resolver
                .exchange_nameserver(upstream, &query, &parsed)
                .await
                .unwrap();
        }
        let snapshot = resolver.tcp_pool.snapshot();
        assert_eq!(snapshot.current_idle, TCP_POOL_MAX_IDLE);
        assert_eq!(snapshot.current_physical, TCP_POOL_MAX_IDLE);
        assert_eq!(snapshot.idle_evictions, 1);

        {
            let mut state = resolver.tcp_pool.state.lock().await;
            let oldest = oldest_idle_index(&state.idle).unwrap();
            state.idle[oldest].idle_since =
                TokioInstant::now() - TCP_POOL_IDLE_TIMEOUT - Duration::from_secs(1);
        }
        let upstream = nameserver(1, DnsTransport::Tcp);
        let query = build_query(99, "expired.example", QueryType::A).unwrap();
        let parsed = parse_query(&query).unwrap();
        resolver
            .exchange_nameserver(upstream, &query, &parsed)
            .await
            .unwrap();
        let snapshot = resolver.tcp_pool.snapshot();
        assert_eq!(snapshot.idle_expirations, 1);
        assert_eq!(snapshot.current_idle, TCP_POOL_MAX_IDLE);
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 6);
    }

    #[tokio::test]
    async fn dropping_runtime_dns_releases_every_idle_tcp_pool_slot() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 68));
        let dispatcher = Arc::new(ScriptedTcpDispatcher::new(vec![vec![
            TcpScriptReply::Response(ResponseSpec::answer(address)),
        ]]));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Tcp)]),
            dispatcher,
        );
        resolver.resolve("drop-pool.example").await.unwrap();
        let stats = Arc::clone(&resolver.tcp_pool.stats);
        let reaper_cancel = resolver.tcp_pool.reaper_cancel.clone();
        assert_eq!(stats.current_physical.load(Ordering::Acquire), 1);
        assert_eq!(stats.current_idle.load(Ordering::Acquire), 1);
        assert!(!reaper_cancel.is_cancelled());

        drop(resolver);

        assert!(reaper_cancel.is_cancelled());
        assert_eq!(stats.current_physical.load(Ordering::Acquire), 0);
        assert_eq!(stats.current_busy.load(Ordering::Acquire), 0);
        assert_eq!(stats.current_connecting.load(Ordering::Acquire), 0);
        assert_eq!(stats.current_idle.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn nameserver_route_selects_direct_proxy_and_endpoint_rules() {
        let answer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40));
        let ipv6_answer = IpAddr::V6("2001:db8::40".parse().unwrap());

        let direct = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(ipv6_answer))],
            vec![],
        ));
        let proxy = Arc::new(MockDispatcher::default());
        let mut direct_nameserver = nameserver(1, DnsTransport::Udp);
        direct_nameserver.route = DnsRoute::Direct;
        let resolver = RuntimeDns::new_routed(
            &config(true, vec![direct_nameserver.clone()]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![rule(
                RuleKind::Match,
                RuleAction::Route(crate::config::RouteTargetId::Proxy(
                    crate::config::ProxyId::new(0).unwrap(),
                )),
            )])
            .unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let query = build_query(1, "example.com", QueryType::Aaaa).unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 0);

        let direct = Arc::new(MockDispatcher::default());
        let proxy = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(answer))],
            vec![],
        ));
        let mut rules_nameserver = nameserver(2, DnsTransport::Udp);
        rules_nameserver.route = DnsRoute::Rules;
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![rules_nameserver.clone()]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![
                rule(
                    RuleKind::Domain("example.com".to_owned()),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Route(crate::config::RouteTargetId::Proxy(
                        crate::config::ProxyId::new(0).unwrap(),
                    )),
                ),
            ])
            .unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let query = build_query(2, "example.com", QueryType::A).unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 0);

        let direct = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(answer))],
            vec![],
        ));
        let proxy = Arc::new(MockDispatcher::default());
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![rules_nameserver.clone()]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: "192.0.2.0".parse().unwrap(),
                        prefix_len: 24,
                    }),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Route(crate::config::RouteTargetId::Proxy(
                        crate::config::ProxyId::new(0).unwrap(),
                    )),
                ),
            ])
            .unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let query = build_query(3, "not-the-routing-domain.example", QueryType::A).unwrap();
        resolver.exchange(&query).await.unwrap();
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn domain_policies_use_specificity_and_preserve_geosite_order() {
        let parsed = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
rules: ['MATCH,DIRECT']
dns:
  enable: true
  ipv6: true
  nameserver: [192.0.2.1]
  nameserver-policy:
    '+.example.test': 192.0.2.2
    '*.example.test': [192.0.2.3]
    'pin.example.test': 192.0.2.4
    'api.*.example.test': 192.0.2.5
    '.only.test': 192.0.2.6
    '*.TLD': 192.0.2.7
    'same.test': 192.0.2.8
    'SAME.TEST': 192.0.2.9
    'one.test,two.test': 192.0.2.10
    '+.override.cn': 192.0.2.11
    'GEOSITE:cn': 192.0.2.12
    'blocked.cn': 192.0.2.13
    'late.test': [192.0.2.14]
"#,
        )
        .unwrap();
        for query_type in [1, 28, 65] {
            for (domain, upstream) in [
                ("example.test", 2),
                ("one.example.test", 3),
                ("pin.example.test", 4),
                ("deep.pin.example.test", 2),
                ("api.region.example.test", 5),
                ("only.test", 1),
                ("deep.child.only.test", 6),
                ("host.tld", 7),
                ("deep.host.tld", 1),
                ("same.test", 9),
                ("one.test", 10),
                ("two.test", 10),
                ("override.cn", 11),
                ("blocked.cn", 12),
                ("late.test", 14),
                ("other.test", 1),
            ] {
                let dispatcher = Arc::new(MockDispatcher::with_replies(
                    vec![MockReply::Response(ResponseSpec::rcode(RCODE_NXDOMAIN))],
                    vec![],
                ));
                let resolver = RuntimeDns::new_with_geo_matcher(
                    &parsed.dns,
                    dispatcher.clone(),
                    Arc::new(PolicyGeoMatcher),
                );
                resolver
                    .exchange(&opaque_query(1, domain, query_type))
                    .await
                    .unwrap();
                assert_eq!(
                    *dispatcher.udp_destinations.lock().unwrap(),
                    [Destination::Ip(SocketAddr::from((
                        [192, 0, 2, upstream],
                        53
                    )))],
                    "{domain} type {query_type}",
                );
            }
        }
    }

    #[tokio::test]
    async fn dns_policy_selection_is_consistent_across_snapshot_swaps() {
        for starts_empty in [false, true] {
            for separate_policies in [false, true] {
                for query_type in [1, 65] {
                    let main = nameserver(1, DnsTransport::Udp);
                    let policy = nameserver(2, DnsTransport::Udp);
                    let mut dns_config = config(false, vec![main.clone()]);
                    dns_config.nameserver_policies = if separate_policies {
                        vec![
                            dns_policy(&["cn@ads"], vec![nameserver(3, DnsTransport::Udp)]),
                            dns_policy(&["cn"], vec![policy.clone()]),
                        ]
                    } else {
                        vec![dns_policy(&["cn@ads", "cn"], vec![policy.clone()])]
                    };
                    let root = tempfile::tempdir().unwrap();
                    // One CN Domain record: example.cn, with no attributes.
                    std::fs::write(
                        root.path().join(GEOSITE_FILE_NAME),
                        b"\x0a\x14\x0a\x02cn\x12\x0e\x08\x02\x12\x0aexample.cn",
                    )
                    .unwrap();
                    let loaded = Arc::new(
                        GeoData::load_with_dns_policies(
                            root.path(),
                            &[],
                            &dns_config.nameserver_policies,
                        )
                        .unwrap(),
                    );
                    let empty = Arc::new(GeoData::EMPTY);
                    let (initial, replacement) = if starts_empty {
                        (empty, loaded)
                    } else {
                        (loaded, empty)
                    };
                    let retired = Arc::downgrade(&initial);
                    let dynamic = Arc::new(DynamicGeoData::new(initial));
                    let matcher = Arc::new(SwapAfterFirstGeoSiteMatch {
                        inner: dynamic.clone(),
                        dynamic,
                        replacement: Arc::new(StdMutex::new(Some(replacement))),
                    });
                    let release = Arc::new(Notify::new());
                    let dispatcher = Arc::new(MockDispatcher::with_replies(
                        vec![
                            MockReply::Gated {
                                response: ResponseSpec::rcode(RCODE_NOERROR),
                                release: release.clone(),
                            },
                            MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR)),
                        ],
                        vec![],
                    ));
                    let resolver =
                        RuntimeDns::new_with_geo_matcher(&dns_config, dispatcher.clone(), matcher);
                    let query = opaque_query(60, "www.example.cn", query_type);
                    let mut exchange = std::pin::pin!(resolver.exchange(&query));
                    tokio::select! {
                        result = &mut exchange => panic!("upstream must wait for release: {result:?}"),
                        () = async {
                            while dispatcher.udp_destinations.lock().unwrap().is_empty() {
                                tokio::task::yield_now().await;
                            }
                        } => {}
                    }
                    let released_before_upstream_reply = retired.upgrade().is_none();
                    release.notify_one();
                    let response = exchange.await.unwrap();
                    assert_eq!(u16::from_be_bytes([response[0], response[1]]), 60);
                    assert_eq!(response[3] & 0x0f, RCODE_NOERROR);
                    assert!(released_before_upstream_reply);

                    let expected = if starts_empty { &main } else { &policy };
                    assert_eq!(
                        *dispatcher.udp_destinations.lock().unwrap(),
                        vec![Destination::Ip(expected.endpoint())],
                        "starts_empty={starts_empty}, separate_policies={separate_policies}, query_type={query_type}",
                    );

                    // A fresh query sees the published replacement, not the
                    // snapshot retired by the preceding policy evaluation.
                    resolver
                        .exchange(&opaque_query(61, "next.example.cn", query_type))
                        .await
                        .unwrap();
                    let next_expected = if starts_empty { &policy } else { &main };
                    assert_eq!(
                        *dispatcher.udp_destinations.lock().unwrap(),
                        vec![
                            Destination::Ip(expected.endpoint()),
                            Destination::Ip(next_expected.endpoint()),
                        ],
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn geosite_policy_selects_direct_for_address_and_opaque_queries() {
        let v4_answer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 70));
        let v6_answer = IpAddr::V6("2001:db8::70".parse().unwrap());
        let direct = Arc::new(MockDispatcher::with_replies(
            vec![],
            vec![
                MockReply::Response(ResponseSpec::answer(v4_answer)),
                MockReply::Response(ResponseSpec::answer(v4_answer)),
                MockReply::Response(ResponseSpec::answer(v4_answer)),
                MockReply::Response(ResponseSpec::answer(v6_answer)),
                MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR)),
            ],
        ));
        let proxy = Arc::new(MockDispatcher::with_replies(
            vec![],
            vec![MockReply::Response(ResponseSpec::answer(v4_answer))],
        ));
        let main = DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport: DnsTransport::Tcp,
            address: "1.1.1.1".parse().unwrap(),
            port: 53,
            route: DnsRoute::Route(crate::config::RouteTargetId::Proxy(
                crate::config::ProxyId::new(0).unwrap(),
            )),
        };
        let policy_nameserver = DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport: DnsTransport::Tcp,
            address: "223.5.5.5".parse().unwrap(),
            port: 53,
            route: DnsRoute::Direct,
        };
        let mut dns_config = config(true, vec![main.clone()]);
        dns_config.nameserver_policies = vec![dns_policy(
            &["private", "cn", "apple"],
            vec![policy_nameserver],
        )];
        let resolver = RuntimeDns::new_routed(
            &dns_config,
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![rule(
                RuleKind::Match,
                RuleAction::Route(crate::config::RouteTargetId::Proxy(
                    crate::config::ProxyId::new(0).unwrap(),
                )),
            )])
            .unwrap(),
            Arc::new(PolicyGeoMatcher),
        );

        for (id, domain) in [
            (60, "host.internal.test"),
            (61, "www.apple.com"),
            (62, "www.example.cn"),
        ] {
            resolver
                .exchange(&build_query(id, domain, QueryType::A).unwrap())
                .await
                .unwrap();
        }
        resolver
            .exchange(&build_query(63, "v6.example.cn", QueryType::Aaaa).unwrap())
            .await
            .unwrap();
        resolver
            .exchange(&opaque_query(64, "svc.example.cn", 65))
            .await
            .unwrap();
        resolver
            .exchange(&build_query(65, "unmatched.test", QueryType::A).unwrap())
            .await
            .unwrap();

        assert_eq!(direct.tcp_calls.load(Ordering::Acquire), 5);
        assert_eq!(proxy.tcp_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            *direct.tcp_destinations.lock().unwrap(),
            vec![Destination::Ip("223.5.5.5:53".parse().unwrap()); 5]
        );
        assert_eq!(
            *proxy.tcp_destinations.lock().unwrap(),
            vec![Destination::Ip("1.1.1.1:53".parse().unwrap())]
        );
    }

    #[tokio::test]
    async fn policy_order_and_failover_are_scoped_to_the_first_match() {
        let answer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 71));
        let direct = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::TransportError,
                MockReply::Response(ResponseSpec::answer(answer)),
            ],
            vec![],
        ));
        let proxy = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(answer))],
            vec![],
        ));
        let mut first = nameserver(10, DnsTransport::Udp);
        first.route = DnsRoute::Direct;
        let mut first_fallback = nameserver(11, DnsTransport::Udp);
        first_fallback.route = DnsRoute::Direct;
        let second = nameserver(12, DnsTransport::Udp);
        let mut dns_config = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        dns_config.nameserver_policies = vec![
            dns_policy(&["first"], vec![first, first_fallback]),
            dns_policy(&["second"], vec![second]),
        ];
        let resolver = RuntimeDns::new_routed(
            &dns_config,
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![rule(
                RuleKind::Match,
                RuleAction::Route(crate::config::RouteTargetId::Proxy(
                    crate::config::ProxyId::new(0).unwrap(),
                )),
            )])
            .unwrap(),
            Arc::new(PolicyGeoMatcher),
        );

        let response = resolver
            .exchange(&build_query(66, "overlap.test", QueryType::A).unwrap())
            .await
            .unwrap();
        assert_eq!(parse_response(&response).unwrap().rcode, RCODE_NOERROR);
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 2);
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 0);
        assert_eq!(
            *direct.udp_destinations.lock().unwrap(),
            [
                Destination::Ip("192.0.2.10:53".parse().unwrap()),
                Destination::Ip("192.0.2.11:53".parse().unwrap()),
            ]
        );
    }

    #[tokio::test]
    async fn policy_exhaustion_never_falls_back_to_main_for_typed_or_opaque_queries() {
        let answer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 72));
        for opaque in [false, true] {
            let direct = Arc::new(MockDispatcher::with_replies(
                vec![MockReply::TransportError],
                vec![],
            ));
            let proxy = Arc::new(MockDispatcher::with_replies(
                vec![MockReply::Response(ResponseSpec::answer(answer))],
                vec![],
            ));
            let mut policy_nameserver = nameserver(20, DnsTransport::Udp);
            policy_nameserver.route = DnsRoute::Direct;
            let mut dns_config = config(false, vec![nameserver(1, DnsTransport::Udp)]);
            dns_config.nameserver_policies = vec![dns_policy(&["cn"], vec![policy_nameserver])];
            let resolver = RuntimeDns::new_routed(
                &dns_config,
                proxy.clone(),
                direct.clone(),
                RuleSet::compile(vec![rule(
                    RuleKind::Match,
                    RuleAction::Route(crate::config::RouteTargetId::Proxy(
                        crate::config::ProxyId::new(0).unwrap(),
                    )),
                )])
                .unwrap(),
                Arc::new(PolicyGeoMatcher),
            );

            let query = if opaque {
                opaque_query(67, "failed.example.cn", 16)
            } else {
                build_query(68, "failed.example.cn", QueryType::A).unwrap()
            };
            let response = resolver.exchange(&query).await.unwrap();
            if opaque {
                assert_eq!(
                    validate_opaque_response(&classify_query(&query).unwrap(), &response)
                        .unwrap()
                        .rcode(),
                    u16::from(RCODE_SERVFAIL)
                );
            } else {
                assert_eq!(parse_response(&response).unwrap().rcode, RCODE_SERVFAIL);
            }
            assert_eq!(direct.udp_calls.load(Ordering::Acquire), 1);
            assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 0);
        }
    }

    #[tokio::test]
    async fn policy_nxdomain_is_terminal_and_ipv6_disabled_aaaa_stays_local() {
        let direct = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::rcode(RCODE_NXDOMAIN)),
                MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR)),
            ],
            vec![],
        ));
        let proxy = Arc::new(MockDispatcher::default());
        let mut first = nameserver(30, DnsTransport::Udp);
        first.route = DnsRoute::Direct;
        let mut fallback = nameserver(31, DnsTransport::Udp);
        fallback.route = DnsRoute::Direct;
        let mut dns_config = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        dns_config.nameserver_policies = vec![dns_policy(&["cn"], vec![first, fallback])];
        let resolver = RuntimeDns::new_routed(
            &dns_config,
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![rule(
                RuleKind::Match,
                RuleAction::Route(crate::config::RouteTargetId::Proxy(
                    crate::config::ProxyId::new(0).unwrap(),
                )),
            )])
            .unwrap(),
            Arc::new(PolicyGeoMatcher),
        );

        let response = resolver
            .exchange(&build_query(69, "missing.example.cn", QueryType::A).unwrap())
            .await
            .unwrap();
        assert_eq!(parse_response(&response).unwrap().rcode, RCODE_NXDOMAIN);
        let response = resolver
            .exchange(&build_query(70, "v6.example.cn", QueryType::Aaaa).unwrap())
            .await
            .unwrap();
        assert_eq!(parse_response(&response).unwrap().rcode, RCODE_NOERROR);
        assert_eq!(parse_response(&response).unwrap().answer_count, 0);
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn opaque_queries_share_proxy_tag_and_endpoint_rules_egress() {
        let proxy = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR))],
            vec![],
        ));
        let direct = Arc::new(MockDispatcher::default());
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![rule(RuleKind::Match, RuleAction::Direct)]).unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        resolver
            .exchange(&opaque_query(4, "txt.example", 16))
            .await
            .unwrap();
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 0);

        let proxy = Arc::new(MockDispatcher::default());
        let direct = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR))],
            vec![],
        ));
        let mut rules_nameserver = nameserver(2, DnsTransport::Udp);
        rules_nameserver.route = DnsRoute::Rules;
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![rules_nameserver.clone()]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![
                rule(
                    RuleKind::IpCidr(IpCidr {
                        network: "192.0.2.0".parse().unwrap(),
                        prefix_len: 24,
                    }),
                    RuleAction::Direct,
                ),
                rule(
                    RuleKind::Match,
                    RuleAction::Route(crate::config::RouteTargetId::Proxy(
                        crate::config::ProxyId::new(0).unwrap(),
                    )),
                ),
            ])
            .unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        resolver
            .exchange(&opaque_query(5, "https.example", 65))
            .await
            .unwrap();
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn direct_nameserver_round_trips_real_udp_and_tcp_sockets() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        let udp_server = tokio::spawn(async move {
            let mut query = [0_u8; MAX_MESSAGE_SIZE];
            let (length, peer) = udp.recv_from(&mut query).await.unwrap();
            let response =
                response_for_query(&query[..length], &ResponseSpec::rcode(RCODE_NOERROR));
            udp.send_to(&response, peer).await.unwrap();
        });
        let proxy = Arc::new(MockDispatcher::default());
        let direct: Arc<dyn Dispatcher> = Arc::new(DirectOutbound::new(Dialer::default()));
        let udp_nameserver = DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport: DnsTransport::Udp,
            address: udp_address.ip().into(),
            port: udp_address.port(),
            route: DnsRoute::Direct,
        };
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![udp_nameserver]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![rule(
                RuleKind::Match,
                RuleAction::Route(crate::config::RouteTargetId::Proxy(
                    crate::config::ProxyId::new(0).unwrap(),
                )),
            )])
            .unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let query = opaque_query(50, "txt.example", 16);
        let classified = classify_query(&query).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            validate_opaque_response(&classified, &response)
                .unwrap()
                .rcode(),
            u16::from(RCODE_NOERROR)
        );
        udp_server.await.unwrap();
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 0);

        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp.local_addr().unwrap();
        let tcp_server = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap() as usize;
            let mut query = vec![0_u8; length];
            stream.read_exact(&mut query).await.unwrap();
            let response = response_for_query(&query, &ResponseSpec::rcode(RCODE_NOERROR));
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let tcp_nameserver = DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport: DnsTransport::Tcp,
            address: tcp_address.ip().into(),
            port: tcp_address.port(),
            route: DnsRoute::Direct,
        };
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![tcp_nameserver]),
            proxy.clone(),
            direct,
            RuleSet::compile(vec![rule(
                RuleKind::Match,
                RuleAction::Route(crate::config::RouteTargetId::Proxy(
                    crate::config::ProxyId::new(0).unwrap(),
                )),
            )])
            .unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let query = opaque_query(51, "https.example", 65);
        let classified = classify_query(&query).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            validate_opaque_response(&classified, &response)
                .unwrap()
                .rcode(),
            u16::from(RCODE_NOERROR)
        );
        tcp_server.await.unwrap();
        assert_eq!(proxy.tcp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn rules_reject_fails_over_to_the_next_nameserver() {
        let answer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 41));
        let proxy = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(answer))],
            vec![],
        ));
        let direct = Arc::new(MockDispatcher::default());
        let mut rejected = nameserver(1, DnsTransport::Udp);
        rejected.route = DnsRoute::Rules;
        let allowed = nameserver(2, DnsTransport::Udp);
        let resolver = RuntimeDns::new_routed(
            &config(false, vec![rejected, allowed]),
            proxy.clone(),
            direct.clone(),
            RuleSet::compile(vec![
                rule(RuleKind::Network(Network::Udp), RuleAction::Reject),
                rule(
                    RuleKind::Match,
                    RuleAction::Route(crate::config::RouteTargetId::Proxy(
                        crate::config::ProxyId::new(0).unwrap(),
                    )),
                ),
            ])
            .unwrap(),
            Arc::new(EmptyGeoMatcher),
        );
        let query = build_query(4, "example.com", QueryType::A).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(parse_response(&response).unwrap().rcode, RCODE_NOERROR);
        assert_eq!(proxy.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(direct.udp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn opaque_qtypes_relay_cache_and_never_create_redir_host_hints() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::answer(address)),
                MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR)),
                MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR)),
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );

        for (id, name, query_type) in [
            (10, "txt.example", 16),
            (11, "https.example", 65),
            (12, "unknown.example", 65_400),
        ] {
            let query = opaque_query(id, name, query_type);
            let classified = classify_query(&query).unwrap();
            let response = resolver.exchange(&query).await.unwrap();
            let validated = validate_opaque_response(&classified, &response).unwrap();
            assert_eq!(validated.rcode(), u16::from(RCODE_NOERROR));
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 3);

        let cached_query = opaque_query(99, "txt.example", 16);
        let cached = resolver.exchange(&cached_query).await.unwrap();
        assert_eq!(u16::from_be_bytes([cached[0], cached[1]]), 99);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 3);
        assert_eq!(resolver.domain_hint(address).await, None);
    }

    #[tokio::test]
    async fn udp_truncation_retries_the_same_upstream_over_tcp() {
        for query_type in [1, 16] {
            let dispatcher = Arc::new(MockDispatcher::with_replies(
                vec![MockReply::Response(ResponseSpec::truncated())],
                vec![MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR))],
            ));
            let resolver = RuntimeDns::new(
                &config(false, vec![nameserver(7, DnsTransport::Udp)]),
                dispatcher.clone(),
            );
            let query = opaque_query(20, "answer.example", query_type);
            let response = resolver.exchange(&query).await.unwrap();
            assert_eq!(response[3] & 0xf, 0);
            assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
            assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 1);
            assert_eq!(
                *dispatcher.udp_destinations.lock().unwrap(),
                *dispatcher.tcp_destinations.lock().unwrap()
            );
        }
    }

    #[tokio::test]
    async fn transport_error_and_servfail_fail_over_in_order() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::TransportError,
                MockReply::Response(ResponseSpec::rcode(RCODE_SERVFAIL)),
                MockReply::Response(ResponseSpec::answer(address)),
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(
                false,
                vec![
                    nameserver(1, DnsTransport::Udp),
                    nameserver(2, DnsTransport::Udp),
                    nameserver(3, DnsTransport::Udp),
                ],
            ),
            dispatcher.clone(),
        );

        assert_eq!(resolver.resolve("example.com").await.unwrap(), [address]);
        assert_eq!(
            *dispatcher.udp_destinations.lock().unwrap(),
            vec![
                Destination::Ip("192.0.2.1:53".parse().unwrap()),
                Destination::Ip("192.0.2.2:53".parse().unwrap()),
                Destination::Ip("192.0.2.3:53".parse().unwrap()),
            ]
        );
    }

    #[tokio::test]
    async fn exhausted_upstreams_return_servfail_for_address_and_opaque_queries() {
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::TransportError, MockReply::TransportError],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(
                false,
                vec![
                    nameserver(1, DnsTransport::Udp),
                    nameserver(2, DnsTransport::Udp),
                ],
            ),
            dispatcher,
        );
        let query = build_query(30, "address.example", QueryType::A).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(parse_response(&response).unwrap().rcode, RCODE_SERVFAIL);

        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::TransportError, MockReply::TransportError],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(
                false,
                vec![
                    nameserver(1, DnsTransport::Udp),
                    nameserver(2, DnsTransport::Udp),
                ],
            ),
            dispatcher,
        );
        let query = opaque_query(31, "txt.example", 16);
        let classified = classify_query(&query).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(
            validate_opaque_response(&classified, &response)
                .unwrap()
                .rcode(),
            u16::from(RCODE_SERVFAIL)
        );
    }

    #[test]
    fn nameserver_failure_summary_does_not_expose_error_details() {
        let error = AttemptError::Dispatch(DispatchError::Other(
            "sentinel-token at 198.51.100.77:53".to_owned(),
        ));
        assert_eq!(error.summary(3).as_ref(), "nameserver 3 failed: dispatcher");
    }

    #[tokio::test]
    async fn positive_cache_and_redir_host_hint_avoid_a_second_exchange() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );

        assert_eq!(resolver.resolve("Example.COM.").await.unwrap(), [address]);
        assert_eq!(resolver.resolve("example.com").await.unwrap(), [address]);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            resolver.domain_hint(address).await,
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn concurrent_redir_host_hint_reads_and_dns_updates_complete() {
        fn require_send<T: Send>(value: T) -> T {
            value
        }

        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
        let domains = Arc::new(
            (0..64)
                .map(|index| format!("concurrent-{index}.example"))
                .collect::<Vec<_>>(),
        );
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            (0..domains.len())
                .map(|_| MockReply::Response(ResponseSpec::answer(address)))
                .collect(),
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));
        let seeded = Arc::new(Notify::new());
        let reader_started = Arc::new(Notify::new());
        let writer_done = Arc::new(AtomicBool::new(false));
        let (completed, completion) = std::sync::mpsc::channel();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut workers = Vec::new();
        for writer in [true, false] {
            let resolver = resolver.clone();
            let domains = domains.clone();
            let seeded = seeded.clone();
            let reader_started = reader_started.clone();
            let writer_done = writer_done.clone();
            let completed = completed.clone();
            workers.push(std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    runtime.block_on(require_send(async {
                        tokio::time::timeout(Duration::from_secs(1), async {
                            if writer {
                                assert_eq!(resolver.resolve(&domains[0]).await.unwrap(), [address]);
                                seeded.notify_one();
                                reader_started.notified().await;
                                for domain in domains.iter().skip(1) {
                                    assert_eq!(resolver.resolve(domain).await.unwrap(), [address]);
                                    assert_eq!(
                                        resolver.domain_hint(address).await,
                                        Some(domain.clone())
                                    );
                                    std::thread::yield_now();
                                }
                                writer_done.store(true, Ordering::Release);
                            } else {
                                seeded.notified().await;
                                assert_eq!(
                                    resolver.domain_hint(address).await,
                                    Some(domains[0].clone())
                                );
                                reader_started.notify_one();
                                while !writer_done.load(Ordering::Acquire) {
                                    let hint = resolver.domain_hint(address).await.unwrap();
                                    assert!(domains.contains(&hint));
                                    tokio::task::yield_now().await;
                                }
                            }
                        })
                        .await
                        .expect("concurrent DNS hint operations did not complete");
                    }));
                }));
                let _ = completed.send(result);
            }));
        }
        drop(completed);
        for _ in 0..workers.len() {
            let result = completion
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("concurrent DNS hint workers exceeded the test deadline");
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), domains.len());
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn zero_redir_host_capacity_disables_only_hints_not_typed_cache() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 14));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = RuntimeDns::assemble(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            DnsEgress::Single(dispatcher.clone()),
            Arc::new(EmptyGeoMatcher),
            MAX_CACHE_ENTRIES,
            0,
            crate::security::SecurityContext::new(),
        );

        assert!(resolver.hints.is_none());
        assert_eq!(resolver.resolve("example.com").await.unwrap(), [address]);
        assert_eq!(resolver.resolve("example.com").await.unwrap(), [address]);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(resolver.domain_hint(address).await, None);
    }

    #[tokio::test]
    async fn nodata_and_nxdomain_are_negative_cached_without_failover() {
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::rcode(RCODE_NOERROR)),
                MockReply::Response(ResponseSpec::rcode(RCODE_NXDOMAIN)),
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(
                false,
                vec![
                    nameserver(1, DnsTransport::Udp),
                    nameserver(2, DnsTransport::Udp),
                ],
            ),
            dispatcher.clone(),
        );

        for id in [1, 2] {
            let query = build_query(id, "nodata.example", QueryType::A).unwrap();
            let response = parse_response(&resolver.exchange(&query).await.unwrap()).unwrap();
            assert_eq!(response.id, id);
            assert_eq!(response.rcode, RCODE_NOERROR);
            assert_eq!(response.answer_count, 0);
        }
        for id in [3, 4] {
            let query = build_query(id, "missing.example", QueryType::A).unwrap();
            let response = parse_response(&resolver.exchange(&query).await.unwrap()).unwrap();
            assert_eq!(response.id, id);
            assert_eq!(response.rcode, RCODE_NXDOMAIN);
            assert_eq!(response.answer_count, 0);
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            *dispatcher.udp_destinations.lock().unwrap(),
            vec![
                Destination::Ip("192.0.2.1:53".parse().unwrap()),
                Destination::Ip("192.0.2.1:53".parse().unwrap()),
            ]
        );
    }

    #[tokio::test]
    async fn resolve_ipv6_disabled_returns_local_nodata_and_skips_aaaa() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 14));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );
        let query = build_query(0xbeef, "example.com", QueryType::Aaaa).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        let parsed = parse_response(&response).unwrap();
        assert_eq!(parsed.id, 0xbeef);
        assert_eq!(parsed.question.name, "example.com");
        assert_eq!(parsed.question.query_type, QueryType::Aaaa);
        assert_eq!(parsed.rcode, RCODE_NOERROR);
        assert_eq!(parsed.answer_count, 0);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);

        assert_eq!(resolver.resolve("example.com").await.unwrap(), [address]);
        assert_eq!(
            *dispatcher.udp_queries.lock().unwrap(),
            vec![QueryType::A as u16]
        );
    }

    #[tokio::test]
    async fn resolve_ipv6_merges_answers_with_ipv4_first() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15));
        let ipv6 = IpAddr::V6("2001:db8::15".parse().unwrap());
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::answer(ipv4)),
                MockReply::Response(ResponseSpec::answer(ipv6)),
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(true, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );

        assert_eq!(resolver.resolve("example.com").await.unwrap(), [ipv4, ipv6]);
        assert_eq!(
            *dispatcher.udp_queries.lock().unwrap(),
            vec![QueryType::A as u16, QueryType::Aaaa as u16]
        );
    }

    #[tokio::test]
    async fn resolve_ipv6_keeps_successful_answers_when_the_other_stack_fails() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15));
        let ipv6 = IpAddr::V6("2001:db8::15".parse().unwrap());
        for (replies, expected) in [
            (
                vec![
                    MockReply::Response(ResponseSpec::answer(ipv4)),
                    MockReply::TransportError,
                ],
                Some(ipv4),
            ),
            (
                vec![
                    MockReply::TransportError,
                    MockReply::Response(ResponseSpec::answer(ipv6)),
                ],
                Some(ipv6),
            ),
            (
                vec![MockReply::TransportError, MockReply::TransportError],
                None,
            ),
        ] {
            let dispatcher = Arc::new(MockDispatcher::with_replies(replies, vec![]));
            let resolver = RuntimeDns::new(
                &config(true, vec![nameserver(1, DnsTransport::Udp)]),
                dispatcher,
            );
            let result = resolver.resolve("example.com").await;
            if let Some(address) = expected {
                assert_eq!(result.unwrap(), [address]);
            } else {
                assert!(result.is_err());
            }
            assert_eq!(resolver.resource_stats.snapshot().dns_current, 0);
            assert_eq!(resolver.resource_stats.snapshot().singleflight_current, 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn resolve_ipv6_queries_concurrently_and_waits_from_ipv4_completion() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15));
        let ipv6 = IpAddr::V6("2001:db8::15".parse().unwrap());
        let release_a = Arc::new(Notify::new());
        let release_aaaa = Arc::new(Notify::new());
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Gated {
                    response: ResponseSpec::answer(ipv4),
                    release: release_a.clone(),
                },
                MockReply::Gated {
                    response: ResponseSpec::answer(ipv6),
                    release: release_aaaa.clone(),
                },
            ],
            vec![],
        ));
        let mut dns_config = config(true, vec![nameserver(1, DnsTransport::Udp)]);
        dns_config.ipv6_timeout = Duration::from_millis(50);
        let resolver = Arc::new(RuntimeDns::new(&dns_config, dispatcher.clone()));
        let lookup = tokio::spawn({
            let resolver = resolver.clone();
            async move { resolver.resolve("example.com").await }
        });
        for _ in 0..10 {
            if dispatcher.udp_queries.lock().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            *dispatcher.udp_queries.lock().unwrap(),
            [QueryType::A as u16, QueryType::Aaaa as u16]
        );
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(!lookup.is_finished());
        release_a.notify_one();
        for _ in 0..10 {
            if resolver.resource_stats.snapshot().dns_current == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(resolver.resource_stats.snapshot().dns_current, 1);
        tokio::time::advance(Duration::from_millis(49)).await;
        assert!(!lookup.is_finished());
        release_aaaa.notify_one();
        assert_eq!(lookup.await.unwrap().unwrap(), [ipv4, ipv6]);
    }

    #[tokio::test(start_paused = true)]
    async fn resolve_ipv6_timeout_releases_the_pending_query() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::answer(ipv4)),
                MockReply::Pending,
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(true, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );
        let started = TokioInstant::now();
        assert_eq!(resolver.resolve("example.com").await.unwrap(), [ipv4]);
        assert_eq!(TokioInstant::now() - started, Duration::from_millis(100));
        assert_eq!(
            *dispatcher.udp_queries.lock().unwrap(),
            [QueryType::A as u16, QueryType::Aaaa as u16]
        );
        assert_eq!(resolver.resource_stats.snapshot().dns_current, 0);
        assert_eq!(resolver.resource_stats.snapshot().singleflight_current, 0);
    }

    #[tokio::test]
    async fn resolve_ipv6_cancellation_releases_both_queries() {
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Pending, MockReply::Pending],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(true, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));
        let lookup = tokio::spawn({
            let resolver = resolver.clone();
            async move { resolver.resolve("example.com").await }
        });
        for _ in 0..10 {
            if dispatcher.udp_queries.lock().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(resolver.resource_stats.snapshot().dns_current, 2);
        lookup.abort();
        assert!(lookup.await.unwrap_err().is_cancelled());
        assert_eq!(resolver.resource_stats.snapshot().dns_current, 0);
        assert_eq!(resolver.resource_stats.snapshot().singleflight_current, 0);
    }

    #[tokio::test]
    async fn configured_tcp_tc_response_fails_over() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 18));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![],
            vec![
                MockReply::Response(ResponseSpec::truncated()),
                MockReply::Response(ResponseSpec::answer(address)),
            ],
        ));
        let resolver = RuntimeDns::new(
            &config(
                false,
                vec![
                    nameserver(7, DnsTransport::Tcp),
                    nameserver(8, DnsTransport::Tcp),
                ],
            ),
            dispatcher.clone(),
        );

        assert_eq!(resolver.resolve("example.com").await.unwrap(), [address]);
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 2);
    }

    #[test]
    fn address_selection_follows_only_the_reachable_cname_chain_and_its_ttl() {
        let selected = Ipv4Addr::new(203, 0, 113, 19);
        let response = parsed_response_with_answers(
            "alias.example",
            QueryType::A,
            vec![
                DnsRecord {
                    name: "alias.example".to_owned(),
                    ttl: 60,
                    data: RecordData::Cname("middle.example".to_owned()),
                },
                DnsRecord {
                    name: "middle.example".to_owned(),
                    ttl: 45,
                    data: RecordData::Cname("target.example".to_owned()),
                },
                DnsRecord {
                    name: "unrelated.example".to_owned(),
                    ttl: 1,
                    data: RecordData::A(Ipv4Addr::new(192, 0, 2, 200)),
                },
                DnsRecord {
                    name: "target.example".to_owned(),
                    ttl: 90,
                    data: RecordData::A(selected),
                },
            ],
        );

        let matching = matching_answer_set(&response).unwrap();
        assert_eq!(matching.addresses, [IpAddr::V4(selected)]);
        assert_eq!(matching.ttl, Some(45));
    }

    #[test]
    fn unrelated_address_owner_is_not_cached_under_the_question_name() {
        let response = parsed_response_with_answers(
            "victim.example",
            QueryType::A,
            vec![DnsRecord {
                name: "unrelated.example".to_owned(),
                ttl: 60,
                data: RecordData::A(Ipv4Addr::new(192, 0, 2, 201)),
            }],
        );

        let matching = matching_answer_set(&response).unwrap();
        assert!(matching.addresses.is_empty());
        assert_eq!(matching.ttl, None);
    }

    #[test]
    fn cname_loops_and_conflicting_targets_are_rejected() {
        let looped = parsed_response_with_answers(
            "one.example",
            QueryType::A,
            vec![
                DnsRecord {
                    name: "one.example".to_owned(),
                    ttl: 60,
                    data: RecordData::Cname("two.example".to_owned()),
                },
                DnsRecord {
                    name: "two.example".to_owned(),
                    ttl: 60,
                    data: RecordData::Cname("one.example".to_owned()),
                },
            ],
        );
        assert!(matches!(
            matching_answer_set(&looped),
            Err(DnsError::InvalidCnameChain)
        ));

        let conflicting = parsed_response_with_answers(
            "one.example",
            QueryType::A,
            vec![
                DnsRecord {
                    name: "one.example".to_owned(),
                    ttl: 60,
                    data: RecordData::Cname("two.example".to_owned()),
                },
                DnsRecord {
                    name: "one.example".to_owned(),
                    ttl: 30,
                    data: RecordData::Cname("three.example".to_owned()),
                },
            ],
        );
        assert!(matches!(
            matching_answer_set(&conflicting),
            Err(DnsError::InvalidCnameChain)
        ));
    }

    #[test]
    fn cname_selection_retains_only_sixteen_unique_addresses() {
        let answers = (0..=MAX_ANSWERS)
            .map(|index| DnsRecord {
                name: "example.com".to_owned(),
                ttl: 60,
                data: RecordData::A(Ipv4Addr::new(192, 0, 2, u8::try_from(index).unwrap())),
            })
            .collect();
        let response = parsed_response_with_answers("example.com", QueryType::A, answers);

        assert!(matches!(
            matching_answer_set(&response),
            Ok(MatchingAnswerSet { addresses, .. }) if addresses.len() == MAX_ANSWERS
        ));
    }

    #[tokio::test]
    async fn first_typed_response_keeps_all_records_while_cache_retains_sixteen_addresses() {
        let addresses = (1..=20)
            .map(|index| IpAddr::V4(Ipv4Addr::new(203, 0, 113, index)))
            .collect::<Vec<_>>();
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec {
                rcode: RCODE_NOERROR,
                truncated: false,
                answers: addresses,
            })],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );

        let first = build_query(500, "many.example", QueryType::A).unwrap();
        let first = resolver.exchange(&first).await.unwrap();
        let first = parse_response(&first).unwrap();
        assert_eq!(first.id, 500);
        assert_eq!(first.answer_count, 20);
        assert_eq!(first.answers.len(), 20);

        let cached = build_query(501, "many.example", QueryType::A).unwrap();
        let cached = resolver.exchange(&cached).await.unwrap();
        let cached = parse_response(&cached).unwrap();
        assert_eq!(cached.id, 501);
        assert_eq!(usize::from(cached.answer_count), MAX_ANSWERS);
        assert_eq!(cached.answers.len(), MAX_ANSWERS);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn eighty_identical_queries_share_one_upstream_and_restore_every_client_id() {
        const CLIENTS: usize = 80;
        let release = Arc::new(Notify::new());
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Gated {
                response: ResponseSpec::answer(address),
                release: release.clone(),
            }],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::assemble(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            DnsEgress::Single(dispatcher.clone()),
            Arc::new(EmptyGeoMatcher),
            MAX_CACHE_ENTRIES,
            MAX_REDIR_HOST_ENTRIES,
            crate::security::SecurityContext::new(),
        ));

        let mut tasks = Vec::with_capacity(CLIENTS);
        for index in 0..CLIENTS {
            let resolver = resolver.clone();
            tasks.push(tokio::spawn(async move {
                let id = 1_000 + index as u16;
                let query = build_query(id, "burst.example", QueryType::A).unwrap();
                (id, resolver.exchange(&query).await)
            }));
        }
        while resolver.resource_stats.snapshot().dns_current != CLIENTS
            || resolver.singleflight.follower_count() != CLIENTS - 1
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        release.notify_waiters();

        for task in tasks {
            let (id, result) = task.await.unwrap();
            let response = parse_response(&result.unwrap()).unwrap();
            assert_eq!(response.id, id);
            assert_eq!(matching_answer_set(&response).unwrap().addresses, [address]);
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(resolver.singleflight.len(), 0);
        let stats = resolver.resource_stats.snapshot();
        assert_eq!(stats.dns_current, 0);
        assert_eq!(stats.singleflight_current, 0);
        assert_eq!(stats.singleflight_peak, 1);
        assert_eq!(stats.singleflight_joins, CLIENTS as u64 - 1);
    }

    #[tokio::test]
    async fn opaque_queries_with_equal_semantics_share_one_upstream() {
        let release = Arc::new(Notify::new());
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Gated {
                response: ResponseSpec::rcode(RCODE_NOERROR),
                release: release.clone(),
            }],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));

        let first = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let query = opaque_query(601, "opaque-flight.example", 16);
                resolver.exchange(&query).await
            })
        };
        while dispatcher.udp_calls.load(Ordering::Acquire) != 1 {
            tokio::task::yield_now().await;
        }
        let second = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let query = opaque_query(602, "opaque-flight.example", 16);
                resolver.exchange(&query).await
            })
        };
        while resolver.singleflight.follower_count() != 1 {
            tokio::task::yield_now().await;
        }
        release.notify_waiters();

        for (id, task) in [(601, first), (602, second)] {
            let response = task.await.unwrap().unwrap();
            assert_eq!(u16::from_be_bytes([response[0], response[1]]), id);
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(resolver.singleflight.len(), 0);
    }

    #[tokio::test]
    async fn singleflight_key_keeps_distinct_wire_semantics_separate() {
        let release = Arc::new(Notify::new());
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Gated {
                    response: ResponseSpec::rcode(RCODE_NOERROR),
                    release: release.clone(),
                },
                MockReply::Gated {
                    response: ResponseSpec::rcode(RCODE_NOERROR),
                    release: release.clone(),
                },
            ],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));

        let first = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let query = opaque_query(610, "semantic.example", 16);
                resolver.exchange(&query).await
            })
        };
        let second = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let mut query = opaque_query(611, "semantic.example", 16);
                query[2..4].copy_from_slice(&0_u16.to_be_bytes());
                resolver.exchange(&query).await
            })
        };
        while dispatcher.udp_calls.load(Ordering::Acquire) != 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(resolver.singleflight.len(), 2);
        release.notify_waiters();

        assert_eq!(
            u16::from_be_bytes(first.await.unwrap().unwrap()[..2].try_into().unwrap()),
            610
        );
        assert_eq!(
            u16::from_be_bytes(second.await.unwrap().unwrap()[..2].try_into().unwrap()),
            611
        );
        assert_eq!(resolver.singleflight.len(), 0);
        assert_eq!(resolver.resource_stats.snapshot().singleflight_peak, 2);
    }

    #[tokio::test]
    async fn cancelled_leader_wakes_follower_to_reselect_without_leaking_registry_entry() {
        let release = Arc::new(Notify::new());
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 101));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Gated {
                    response: ResponseSpec::answer(address),
                    release,
                },
                MockReply::Response(ResponseSpec::answer(address)),
            ],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));

        let leader = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let query = build_query(620, "cancel.example", QueryType::A).unwrap();
                resolver.exchange(&query).await
            })
        };
        while dispatcher.udp_calls.load(Ordering::Acquire) != 1 {
            tokio::task::yield_now().await;
        }
        let follower = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let query = build_query(621, "cancel.example", QueryType::A).unwrap();
                resolver.exchange(&query).await
            })
        };
        while resolver.singleflight.follower_count() != 1 {
            tokio::task::yield_now().await;
        }

        leader.abort();
        let _ = leader.await;
        let response = tokio::time::timeout(Duration::from_secs(1), follower)
            .await
            .expect("follower must re-elect before its query deadline")
            .unwrap()
            .unwrap();
        assert_eq!(parse_response(&response).unwrap().id, 621);
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 2);
        assert_eq!(resolver.singleflight.len(), 0);
        assert_eq!(resolver.resource_stats.snapshot().singleflight_current, 0);
    }

    #[tokio::test]
    async fn shared_upstream_failure_is_mapped_by_each_callers_failure_mode() {
        let release = Arc::new(Notify::new());
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::GatedTransportError {
                release: release.clone(),
            }],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));

        let wire_caller = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let query = build_query(630, "failure.example", QueryType::A).unwrap();
                resolver.exchange(&query).await
            })
        };
        while dispatcher.udp_calls.load(Ordering::Acquire) != 1 {
            tokio::task::yield_now().await;
        }
        let bounded_caller = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.resolve("failure.example").await })
        };
        while resolver.singleflight.follower_count() != 1 {
            tokio::task::yield_now().await;
        }
        release.notify_waiters();

        let wire = wire_caller.await.unwrap().unwrap();
        assert_eq!(parse_response(&wire).unwrap().rcode, RCODE_SERVFAIL);
        assert!(matches!(
            bounded_caller.await.unwrap(),
            Err(RuntimeDnsError::UpstreamsExhausted { .. })
        ));
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(resolver.singleflight.len(), 0);
    }

    #[tokio::test]
    async fn cache_hit_does_not_create_another_singleflight_entry() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 102));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        );
        for id in [640, 641] {
            let query = build_query(id, "cache-flight.example", QueryType::A).unwrap();
            assert_eq!(
                parse_response(&resolver.exchange(&query).await.unwrap())
                    .unwrap()
                    .id,
                id
            );
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        assert_eq!(resolver.singleflight.len(), 0);
        let stats = resolver.resource_stats.snapshot();
        assert_eq!(stats.singleflight_peak, 1);
        assert_eq!(stats.singleflight_current, 0);
        assert_eq!(stats.dns_cache_hits, 1);
    }

    #[tokio::test]
    async fn dns_cache_configured_capacity_is_shared_by_address_and_opaque_questions() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 103));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            (0..5)
                .map(|_| MockReply::Response(ResponseSpec::answer(address)))
                .collect(),
            vec![],
        ));
        let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        configuration.cache_max_size = 2;
        let resolver = RuntimeDns::new(&configuration, dispatcher.clone());
        for (index, name, qtype) in [
            (0, "first.example", 1),
            (1, "opaque.example", 16),
            (2, "first.example", 1),
            (3, "second.example", 1),
            (4, "opaque.example", 16),
            (5, "first.example", 1),
        ] {
            let query = opaque_query(index, name, qtype);
            resolver.exchange(&query).await.unwrap();
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 5);
        assert_eq!(resolver.cache.lock().await.len(), 2);
        assert_eq!(resolver.singleflight.len(), 0);
    }

    #[tokio::test]
    async fn dns_cache_roles_keep_independent_results_and_eviction() {
        let addresses = (1..=5)
            .map(|last| IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)))
            .collect::<Vec<_>>();
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            addresses
                .iter()
                .map(|address| MockReply::Response(ResponseSpec::answer(*address)))
                .collect(),
            vec![],
        ));
        let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        configuration.cache_max_size = 1;
        configuration.default_nameservers = configuration.nameservers.clone();
        configuration.proxy_nameservers = configuration.nameservers.clone();
        configuration.direct_nameservers = configuration.nameservers.clone();
        let resolver = RuntimeDns::new(&configuration, dispatcher.clone());
        let roles = [
            &resolver,
            resolver.bootstrap.as_deref().unwrap(),
            resolver.proxy_resolver.as_deref().unwrap(),
            resolver.direct_resolver.as_deref().unwrap(),
        ];
        for _ in 0..2 {
            for (role, address) in roles.iter().zip(&addresses) {
                assert_eq!(role.resolve("same.example").await.unwrap(), vec![*address]);
            }
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 4);
        assert_eq!(
            resolver.resolve("new.example").await.unwrap(),
            vec![addresses[4]]
        );
        for (role, address) in roles.iter().zip(&addresses).skip(1) {
            assert_eq!(role.resolve("same.example").await.unwrap(), vec![*address]);
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 5);
    }

    fn dns_source_snapshot(
        generation: u64,
        server: &str,
    ) -> super::super::source::DnsNetworkUpdate {
        use super::super::source::*;
        DnsNetworkUpdate {
            generation,
            system: vec![SystemDnsServer {
                address: server.parse().unwrap(),
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

    #[cfg(feature = "outbound-masque")]
    #[tokio::test]
    async fn masque_node_dns_sources_share_exclusions_and_invalidate_private_cache() {
        use super::super::source::SourceExclusions;
        use crate::config::DnsSource;
        let dispatcher = Arc::new(MockDispatcher::default());
        let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        configuration.use_system_hosts = false;
        let physical = Arc::new(
            RuntimeDns::new(&configuration, dispatcher.clone()).with_network_sources(
                crate::dialer::Dialer::default(),
                SourceExclusions {
                    interface: Some("physical1".into()),
                    addresses: vec!["203.0.113.53".parse().unwrap()],
                },
            ),
        );
        let sources = physical.network_sources();
        sources.register(&physical);
        sources
            .replace(dns_source_snapshot(1, "203.0.113.53"))
            .await
            .unwrap();
        let bootstrap = super::super::resolution::ResolutionContext::runtime(false);
        bootstrap.bind_runtime(Some(&physical)).unwrap();
        configuration.nameservers = vec![DnsNameserver {
            address: DnsAddress::Source(DnsSource::System),
            ..nameserver(1, DnsTransport::Udp)
        }];
        let private = RuntimeDns::new_for_masque_node(
            &configuration,
            dispatcher.clone(),
            bootstrap,
            crate::security::SecurityContext::new(),
        );
        assert!(Arc::ptr_eq(&sources, &private.sources));
        assert!(Arc::ptr_eq(&physical.cache_epoch, &private.cache_epoch));
        assert!(private.source_dialer.is_some());
        assert!(
            private
                .sources
                .select(&DnsSource::System, None, &private.source_exclusions)
                .await
                .is_err()
        );
        assert!(
            private
                .sources
                .select(
                    &DnsSource::Dhcp("physical1".into()),
                    None,
                    &private.source_exclusions
                )
                .await
                .is_err()
        );
        assert_eq!(private.tcp_pool.max_idle, 0);
        assert_eq!(private.tcp_pool.max_idle_per_key, 0);

        let now = Instant::now();
        for resolver in [physical.as_ref(), private.as_ref()] {
            resolver
                .cache
                .lock()
                .await
                .insert(
                    "cached.example",
                    QueryType::A,
                    CacheValue::Positive(vec!["192.0.2.10".parse().unwrap()]),
                    60,
                    now,
                )
                .unwrap();
        }
        let epoch = *private.cache_epoch.read().await;
        sources
            .replace(dns_source_snapshot(2, "203.0.113.54"))
            .await
            .unwrap();
        assert_eq!(*private.cache_epoch.read().await, epoch.wrapping_add(1));
        assert!(physical.cache.lock().await.is_empty());
        assert!(private.cache.lock().await.is_empty());
        let selected = private
            .sources
            .select(&DnsSource::System, None, &private.source_exclusions)
            .await
            .unwrap();
        assert_eq!(
            selected.endpoints[0].endpoint.ip(),
            "203.0.113.54".parse::<IpAddr>().unwrap()
        );
        let weak = Arc::downgrade(&private);
        drop(private);
        assert!(weak.upgrade().is_none());
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
        assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 0);
    }

    #[cfg(feature = "outbound-masque")]
    #[tokio::test]
    async fn masque_node_dns_requires_a_physical_owner_to_inherit_sources() {
        let dispatcher = Arc::new(MockDispatcher::default());
        let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        configuration.use_system_hosts = false;
        let unbound = Arc::new(RuntimeDns::new(&configuration, dispatcher.clone()));
        unbound
            .sources
            .replace(dns_source_snapshot(1, "203.0.113.53"))
            .await
            .unwrap();
        let bootstrap = super::super::resolution::ResolutionContext::runtime(false);
        bootstrap.bind_runtime(Some(&unbound)).unwrap();
        configuration.nameservers[0].address = DnsAddress::Source(crate::config::DnsSource::System);
        let private = RuntimeDns::new_for_masque_node(
            &configuration,
            dispatcher,
            bootstrap,
            crate::security::SecurityContext::new(),
        );
        assert!(!Arc::ptr_eq(&unbound.sources, &private.sources));
        assert!(private.source_dialer.is_none());
        assert!(
            private
                .sources
                .select(
                    &crate::config::DnsSource::System,
                    None,
                    &private.source_exclusions
                )
                .await
                .is_err()
        );
        let owner = Arc::downgrade(&unbound);
        drop(unbound);
        assert!(owner.upgrade().is_none());
        assert!(
            private
                .node_bootstrap
                .as_ref()
                .unwrap()
                .runtime_dns()
                .is_none()
        );
    }

    #[tokio::test]
    async fn dns_source_routes_policy_bootstrap_and_every_role_to_physical_metadata() {
        let configuration = crate::config::Config::parse_yaml(b"mixed-port: 1080\ndns:\n  enable: true\n  use-system-hosts: false\n  default-nameserver: [system]\n  nameserver: [udp://dns.example]\n  proxy-server-nameserver: [system]\n  direct-nameserver: [system]\n  nameserver-policy: {policy.example: 'dhcp://physical1'}\n").unwrap();
        let answer: IpAddr = "203.0.113.10".parse().unwrap();
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            (0..5)
                .map(|_| MockReply::Response(ResponseSpec::answer(answer)))
                .collect(),
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(&configuration.dns, dispatcher.clone()));
        resolver.sources.register(&resolver);
        resolver
            .sources
            .replace(dns_source_snapshot(1, "203.0.113.53"))
            .await
            .unwrap();
        resolver.resolve("main.example").await.unwrap();
        resolver
            .proxy_resolver
            .as_ref()
            .unwrap()
            .resolve("proxy.example")
            .await
            .unwrap();
        resolver
            .direct_resolver
            .as_ref()
            .unwrap()
            .resolve("direct.example")
            .await
            .unwrap();
        resolver.resolve("policy.example").await.unwrap();
        let expected: Vec<Destination> = [
            "203.0.113.53",
            "203.0.113.10",
            "203.0.113.53",
            "203.0.113.53",
            "192.0.2.53",
        ]
        .into_iter()
        .map(|ip| Destination::Ip(SocketAddr::new(ip.parse().unwrap(), 53)))
        .collect();
        assert_eq!(*dispatcher.udp_destinations.lock().unwrap(), expected);
    }

    #[tokio::test]
    async fn dns_source_replacement_separates_old_flights_and_clears_every_role() {
        let old: IpAddr = "203.0.113.10".parse().unwrap();
        let new: IpAddr = "203.0.113.11".parse().unwrap();
        let release = Arc::new(Notify::new());
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Gated {
                    response: ResponseSpec::answer(old),
                    release: release.clone(),
                },
                MockReply::Response(ResponseSpec::answer(new)),
            ],
            vec![],
        ));
        let configuration = crate::config::Config::parse_yaml(b"mixed-port: 1080\ndns:\n  enable: true\n  default-nameserver: [system]\n  nameserver: [system]\n  proxy-server-nameserver: [system]\n  direct-nameserver: [system]\n").unwrap();
        let resolver = Arc::new(RuntimeDns::new(&configuration.dns, dispatcher.clone()));
        resolver.sources.register(&resolver);
        resolver
            .sources
            .replace(dns_source_snapshot(1, "203.0.113.53"))
            .await
            .unwrap();
        let query = build_query(851, "replace.example", QueryType::A).unwrap();
        let pending_query = query.clone();
        let pending_resolver = resolver.clone();
        let pending =
            tokio::spawn(async move { pending_resolver.exchange(&pending_query).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.udp_calls.load(Ordering::Acquire) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        resolver
            .sources
            .replace(dns_source_snapshot(2, "203.0.113.54"))
            .await
            .unwrap();
        assert_eq!(
            resolver.resolve("replace.example").await.unwrap(),
            vec![new]
        );
        release.notify_one();
        assert_eq!(
            pending.await.unwrap(),
            response_for_query(&query, &ResponseSpec::answer(old))
        );
        assert_eq!(
            resolver.resolve("replace.example").await.unwrap(),
            vec![new]
        );
        assert!(resolver.domain_hint(old).await.is_none());
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            *dispatcher.udp_destinations.lock().unwrap(),
            vec![
                Destination::Ip("203.0.113.53:53".parse().unwrap()),
                Destination::Ip("203.0.113.54:53".parse().unwrap())
            ]
        );
        resolver
            .sources
            .replace(dns_source_snapshot(3, "203.0.113.54"))
            .await
            .unwrap();
        for role in [
            &resolver,
            resolver.bootstrap.as_ref().unwrap(),
            resolver.proxy_resolver.as_ref().unwrap(),
            resolver.direct_resolver.as_ref().unwrap(),
        ] {
            assert!(role.cache.lock().await.is_empty());
        }
        assert!(resolver.domain_hint(new).await.is_none());
    }

    #[tokio::test]
    async fn dns_source_tcp_pool_separates_generation_and_binding_with_live_old_connections() {
        struct Combined {
            udp: Arc<MockDispatcher>,
            tcp: Arc<ScriptedTcpDispatcher>,
        }
        #[async_trait]
        impl Dispatcher for Combined {
            async fn connect_tcp(
                &self,
                session: StreamSession,
            ) -> Result<BoxStream, DispatchError> {
                self.tcp.connect_tcp(session).await
            }
            async fn open_datagram(
                &self,
                session: DatagramSession,
            ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
                self.udp.open_datagram(session).await
            }
        }
        let old: IpAddr = "203.0.113.10".parse().unwrap();
        let new: IpAddr = "203.0.113.11".parse().unwrap();
        let tcp = Arc::new(ScriptedTcpDispatcher::new(vec![
            vec![
                TcpScriptReply::Response(ResponseSpec::answer(old)),
                TcpScriptReply::Response(ResponseSpec::answer(old)),
            ],
            vec![
                TcpScriptReply::Response(ResponseSpec::answer(new)),
                TcpScriptReply::Response(ResponseSpec::answer(new)),
            ],
            vec![TcpScriptReply::Response(ResponseSpec::answer(new))],
        ]));
        let udp = Arc::new(MockDispatcher::with_replies(
            (0..3)
                .map(|_| MockReply::Response(ResponseSpec::truncated()))
                .collect(),
            vec![],
        ));
        let configuration = crate::config::Config::parse_yaml(
            b"mixed-port: 1080\ndns: {enable: true, nameserver: [system]}\n",
        )
        .unwrap();
        let resolver = Arc::new(RuntimeDns::new(
            &configuration.dns,
            Arc::new(Combined {
                udp,
                tcp: tcp.clone(),
            }),
        ));
        resolver.sources.register(&resolver);
        for (generation, expected) in [(1, old), (2, new), (3, new)] {
            let mut snapshot = dns_source_snapshot(generation, "203.0.113.53");
            if generation == 3 {
                snapshot.system[0].interface = "physical1".into();
            }
            resolver.sources.replace(snapshot).await.unwrap();
            assert_eq!(
                resolver
                    .resolve(&format!("pool{generation}.example"))
                    .await
                    .unwrap(),
                vec![expected]
            );
            assert_eq!(tcp.tcp_calls.load(Ordering::Acquire), generation as usize);
        }
        assert_eq!(resolver.tcp_pool.state.lock().await.idle.len(), 3);
    }

    #[tokio::test]
    async fn dns_source_and_literal_share_four_endpoint_attempts() {
        let release = Arc::new(Notify::new());
        let address: IpAddr = "203.0.113.10".parse().unwrap();
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            (0..4)
                .map(|_| MockReply::Gated {
                    response: ResponseSpec::answer(address),
                    release: release.clone(),
                })
                .collect(),
            vec![],
        ));
        let configuration = crate::config::Config::parse_yaml(b"mixed-port: 1080\ndns: {enable: true, nameserver: [1.1.1.1, system, system, system]}\n").unwrap();
        let resolver = Arc::new(RuntimeDns::new(&configuration.dns, dispatcher.clone()));
        let mut snapshot = dns_source_snapshot(1, "203.0.113.53");
        for server in ["203.0.113.54", "203.0.113.55"] {
            let mut entry = snapshot.system[0].clone();
            entry.address = server.parse().unwrap();
            snapshot.system.push(entry);
        }
        resolver.sources.replace(snapshot).await.unwrap();
        let querying = resolver.clone();
        let task = tokio::spawn(async move { querying.resolve("limited.example").await.unwrap() });
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.udp_calls.load(Ordering::Acquire) < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 4);
        release.notify_waiters();
        assert_eq!(task.await.unwrap(), vec![address]);
    }

    #[tokio::test]
    async fn dns_source_unavailable_does_not_use_a_public_fallback() {
        let configuration = crate::config::Config::parse_yaml(
            b"mixed-port: 1080\ndns: {enable: true, nameserver: [system]}\n",
        )
        .unwrap();
        let dispatcher = Arc::new(MockDispatcher::default());
        let resolver = RuntimeDns::new(&configuration.dns, dispatcher.clone());
        resolver
            .sources
            .replace(super::super::source::DnsNetworkUpdate {
                generation: 1,
                system: vec![],
                dhcp: vec![],
            })
            .await
            .unwrap();
        assert!(resolver.resolve("unavailable.example").await.is_err());
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dns_rcode_preserves_query_flags_and_wire_without_network_or_result_caching() {
        for rcode in 0..=5 {
            let dispatcher = Arc::new(MockDispatcher::default());
            let resolver = RuntimeDns::new(
                &config(
                    false,
                    vec![
                        nameserver(1, DnsTransport::Udp),
                        nameserver(2, DnsTransport::Rcode(rcode)),
                    ],
                ),
                dispatcher.clone(),
            );
            for query_type in [1, 16] {
                for flags in [0x0100_u16, 0x0180, 0x0010] {
                    for id in [800, 801] {
                        let mut query = opaque_query(id, "local.example", query_type);
                        query[2..4].copy_from_slice(&flags.to_be_bytes());
                        // Preserve a legal empty EDNS OPT record as well.
                        query[10..12].copy_from_slice(&1_u16.to_be_bytes());
                        query.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]);
                        let mut expected = query.clone();
                        expected[2..4].copy_from_slice(
                            &(flags | DNS_FLAG_RESPONSE | u16::from(rcode)).to_be_bytes(),
                        );
                        assert_eq!(resolver.exchange(&query).await.unwrap(), expected);
                    }
                }
            }
            assert!(resolver.cache.lock().await.is_empty());
            assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
            assert_eq!(dispatcher.tcp_calls.load(Ordering::Acquire), 0);
        }
    }

    #[tokio::test]
    async fn dns_rcode_policy_runs_after_fake_ip_allocation_and_flush_preserves_mapping() {
        let config = crate::config::Config::parse_yaml(b"mixed-port: 1080\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-filter: [real.example]\n  nameserver: [rcode://success]\n  nameserver-policy:\n    '+.example': rcode://refused\n").unwrap();
        let dispatcher = Arc::new(MockDispatcher::default());
        let resolver = RuntimeDns::new(&config.dns, dispatcher.clone());
        let fake_query = build_query(810, "fake.example", QueryType::A).unwrap();
        let fake = parse_response(&resolver.exchange(&fake_query).await.unwrap()).unwrap();
        let RecordData::A(address) = fake.answers[0].data else {
            panic!("fake A answer")
        };
        assert_eq!(fake.rcode, 0);
        let real_query = build_query(811, "real.example", QueryType::A).unwrap();
        let real = parse_response(&resolver.exchange(&real_query).await.unwrap()).unwrap();
        assert_eq!(real.rcode, RCODE_REFUSED);
        assert!(!real.recursion_available);
        resolver.flush_cache().await;
        assert_eq!(
            resolver.recover_fake_ip(address.into()).unwrap().as_deref(),
            Some("fake.example")
        );
        let after = parse_response(&resolver.exchange(&fake_query).await.unwrap()).unwrap();
        assert_eq!(after.answers[0].data, RecordData::A(address));
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dns_flush_clears_typed_wire_and_hints_in_every_role() {
        let old = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 110));
        let new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 111));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            [old, new]
                .into_iter()
                .flat_map(|address| {
                    (0..8).map(move |_| MockReply::Response(ResponseSpec::answer(address)))
                })
                .collect(),
            vec![],
        ));
        let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        configuration.default_nameservers = configuration.nameservers.clone();
        configuration.proxy_nameservers = configuration.nameservers.clone();
        configuration.direct_nameservers = configuration.nameservers.clone();
        let resolver = RuntimeDns::new(&configuration, dispatcher.clone());
        let roles = [
            &resolver,
            resolver.bootstrap.as_deref().unwrap(),
            resolver.proxy_resolver.as_deref().unwrap(),
            resolver.direct_resolver.as_deref().unwrap(),
        ];
        for (round, address) in [old, new].into_iter().enumerate() {
            for role in roles {
                for query_type in [1, 16] {
                    let query = opaque_query(820, "clear.example", query_type);
                    assert_eq!(
                        role.exchange(&query).await.unwrap(),
                        response_for_query(&query, &ResponseSpec::answer(address))
                    );
                    // Both result classes are retained without another query.
                    role.exchange(&query).await.unwrap();
                }
            }
            assert_eq!(
                dispatcher.udp_calls.load(Ordering::Acquire),
                (round + 1) * 8
            );
            assert_eq!(
                resolver.domain_hint(address).await.as_deref(),
                Some("clear.example")
            );
            resolver.flush_cache().await;
            for role in roles {
                assert!(role.cache.lock().await.is_empty());
            }
            assert!(resolver.domain_hint(address).await.is_none());
        }
    }

    #[tokio::test]
    async fn dns_flush_separates_old_flights_and_blocks_typed_wire_and_hint_refill() {
        for role_index in 0..4 {
            for query_type in [1, 16] {
                let release = Arc::new(Notify::new());
                let old = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 112));
                let new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 113));
                let dispatcher = Arc::new(MockDispatcher::with_replies(
                    vec![
                        MockReply::Gated {
                            response: ResponseSpec::answer(old),
                            release: release.clone(),
                        },
                        MockReply::Response(ResponseSpec::answer(new)),
                    ],
                    vec![],
                ));
                let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
                configuration.default_nameservers = configuration.nameservers.clone();
                configuration.proxy_nameservers = configuration.nameservers.clone();
                configuration.direct_nameservers = configuration.nameservers.clone();
                let root = Arc::new(RuntimeDns::new(&configuration, dispatcher.clone()));
                let role = match role_index {
                    0 => root.clone(),
                    1 => root.bootstrap.as_ref().unwrap().clone(),
                    2 => root.proxy_resolver.as_ref().unwrap().clone(),
                    _ => root.direct_resolver.as_ref().unwrap().clone(),
                };
                let query = opaque_query(830, "pending.example", query_type);
                let old_query = query.clone();
                let old_role = role.clone();
                let leader =
                    tokio::spawn(async move { old_role.exchange(&old_query).await.unwrap() });
                tokio::time::timeout(Duration::from_secs(1), async {
                    while dispatcher.udp_calls.load(Ordering::Acquire) != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let mut follower_query = query.clone();
                restore_response_id(&mut follower_query, 831);
                let old_follower_query = follower_query.clone();
                let old_role = role.clone();
                let follower =
                    tokio::spawn(
                        async move { old_role.exchange(&old_follower_query).await.unwrap() },
                    );
                tokio::time::timeout(Duration::from_secs(1), async {
                    while role.singleflight.follower_count() != 1 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                root.flush_cache().await;
                let fresh = role.exchange(&query).await.unwrap();
                assert_eq!(
                    fresh,
                    response_for_query(&query, &ResponseSpec::answer(new))
                );
                assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 2);
                release.notify_one();
                assert_eq!(
                    leader.await.unwrap(),
                    response_for_query(&query, &ResponseSpec::answer(old))
                );
                assert_eq!(
                    follower.await.unwrap(),
                    response_for_query(&follower_query, &ResponseSpec::answer(old))
                );
                let mut cached = role.exchange(&query).await.unwrap();
                let ttl_offset = cached.len() - 10;
                let ttl =
                    u32::from_be_bytes(cached[ttl_offset..ttl_offset + 4].try_into().unwrap());
                assert!((1..=60).contains(&ttl));
                // Cache replay decrements TTL while retaining the fresh result.
                cached[ttl_offset..ttl_offset + 4].copy_from_slice(&60_u32.to_be_bytes());
                assert_eq!(cached, fresh);
                assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 2);
                assert!(root.domain_hint(old).await.is_none());
                assert_eq!(role.singleflight.len(), 0);
            }
        }
    }

    #[tokio::test]
    async fn dns_flush_holds_one_admission_boundary_until_every_role_is_cleared() {
        let old = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 116));
        let new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 117));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::answer(old)),
                MockReply::Response(ResponseSpec::answer(new)),
            ],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));
        assert_eq!(
            resolver.resolve("barrier.example").await.unwrap(),
            vec![old]
        );
        let bootstrap_cache = resolver.bootstrap.as_ref().unwrap().cache.lock().await;
        let flushing = resolver.clone();
        let flush = tokio::spawn(async move { flushing.flush_cache().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while resolver.cache_epoch.try_read().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let querying = resolver.clone();
        let query = tokio::spawn(async move { querying.resolve("barrier.example").await.unwrap() });
        tokio::time::timeout(Duration::from_secs(1), async {
            while resolver.resource_stats.snapshot().dns_current == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!query.is_finished());
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 1);
        drop(bootstrap_cache);
        flush.await.unwrap();
        assert_eq!(query.await.unwrap(), vec![new]);
    }

    #[tokio::test]
    async fn dns_flush_blocks_old_resource_generation_from_refilling_shared_hints() {
        let release = Arc::new(Notify::new());
        let old = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 114));
        let new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 115));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Gated {
                    response: ResponseSpec::answer(old),
                    release: release.clone(),
                },
                MockReply::Response(ResponseSpec::answer(new)),
            ],
            vec![],
        ));
        let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
        configuration.proxy_nameservers = configuration.nameservers.clone();
        configuration.direct_nameservers = configuration.nameservers.clone();
        let previous = Arc::new(RuntimeDns::new(&configuration, dispatcher.clone()));
        let query = build_query(840, "generation.example", QueryType::A).unwrap();
        let old_query = query.clone();
        let old_role = previous.clone();
        let leader = tokio::spawn(async move { old_role.exchange(&old_query).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.udp_calls.load(Ordering::Acquire) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let current =
            RuntimeDns::new(&configuration, dispatcher.clone()).with_mapping_from(Some(&previous));
        for role in [
            current.bootstrap.as_deref().unwrap(),
            current.proxy_resolver.as_deref().unwrap(),
            current.direct_resolver.as_deref().unwrap(),
        ] {
            assert!(Arc::ptr_eq(&current.cache_epoch, &role.cache_epoch));
        }
        current.flush_cache().await;
        release.notify_one();
        leader.await.unwrap();
        assert!(current.domain_hint(old).await.is_none());
        assert!(previous.cache.lock().await.is_empty());
        assert_eq!(
            current.resolve("generation.example").await.unwrap(),
            vec![new]
        );
        assert_eq!(
            current.domain_hint(new).await.as_deref(),
            Some("generation.example")
        );
    }

    #[tokio::test]
    async fn dns_cache_arc_configuration_changes_actual_upstream_reuse() {
        for (algorithm, expected_calls) in [
            (crate::config::DnsCacheAlgorithm::Lru, 4),
            (crate::config::DnsCacheAlgorithm::Arc, 3),
        ] {
            let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 104));
            let dispatcher = Arc::new(MockDispatcher::with_replies(
                (0..expected_calls)
                    .map(|_| MockReply::Response(ResponseSpec::answer(address)))
                    .collect(),
                vec![],
            ));
            let mut configuration = config(false, vec![nameserver(1, DnsTransport::Udp)]);
            configuration.cache_max_size = 2;
            configuration.cache_algorithm = algorithm;
            let resolver = RuntimeDns::new(&configuration, dispatcher.clone());
            for name in [
                "a.example",
                "a.example",
                "b.example",
                "c.example",
                "a.example",
            ] {
                assert_eq!(resolver.resolve(name).await.unwrap(), vec![address]);
            }
            assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), expected_calls);
        }
    }

    #[tokio::test]
    async fn concurrent_queries_above_old_threshold_reach_upstream_without_local_rejection() {
        const REQUESTS: usize = 160;
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            (0..REQUESTS).map(|_| MockReply::Pending).collect(),
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::new(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            dispatcher.clone(),
        ));
        let mut tasks = Vec::with_capacity(REQUESTS);
        for id in 0..REQUESTS {
            let resolver = resolver.clone();
            tasks.push(tokio::spawn(async move {
                let query = build_query(
                    u16::try_from(id).unwrap(),
                    &format!("pending{id}.example"),
                    QueryType::A,
                )
                .unwrap();
                resolver.exchange(&query).await
            }));
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.udp_calls.load(Ordering::Acquire) != REQUESTS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every concurrent DNS query must reach its request-scoped UDP transport");
        assert_eq!(resolver.singleflight.len(), REQUESTS);
        let active = resolver.resource_stats.snapshot();
        assert_eq!(active.dns_current, REQUESTS);
        assert_eq!(active.dns_peak, REQUESTS);
        assert_eq!(active.singleflight_current, REQUESTS);
        assert_eq!(active.singleflight_peak, REQUESTS);

        for task in tasks {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        while resolver.resource_stats.snapshot().dns_current != 0
            || resolver.singleflight.len() != 0
        {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn pre_observed_exchange_uses_one_raii_query_guard_and_five_second_deadline() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::assemble(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            DnsEgress::Single(dispatcher),
            Arc::new(EmptyGeoMatcher),
            MAX_CACHE_ENTRIES,
            MAX_REDIR_HOST_ENTRIES,
            crate::security::SecurityContext::new(),
        ));
        let observed_at = TokioInstant::now();
        let permit = resolver.begin_query();
        assert!(permit.deadline >= observed_at + QUERY_TIMEOUT);
        assert!(permit.deadline <= TokioInstant::now() + QUERY_TIMEOUT);
        let active = resolver.resource_stats.snapshot();
        assert_eq!(active.dns_current, 1);
        assert_eq!(active.dns_peak, 1);

        let query = build_query(91, "admitted.example", QueryType::A).unwrap();
        let response = resolver.exchange_admitted(&query, &permit).await.unwrap();
        assert_eq!(parse_response(&response).unwrap().id, 91);
        drop(permit);
        assert_eq!(resolver.resource_stats.snapshot().dns_current, 0);
    }

    #[tokio::test]
    async fn retained_wire_response_holds_query_observation_until_the_caller_drops_it() {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 91));
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![MockReply::Response(ResponseSpec::answer(address))],
            vec![],
        ));
        let resolver = Arc::new(RuntimeDns::assemble(
            &config(false, vec![nameserver(1, DnsTransport::Udp)]),
            DnsEgress::Single(dispatcher),
            Arc::new(EmptyGeoMatcher),
            MAX_CACHE_ENTRIES,
            MAX_REDIR_HOST_ENTRIES,
            crate::security::SecurityContext::new(),
        ));
        let query = build_query(92, "retained.example", QueryType::A).unwrap();

        let response = resolver.exchange_retained(&query).await.unwrap();
        assert_eq!(parse_response(response.wire()).unwrap().id, 92);
        assert_eq!(resolver.resource_stats.snapshot().dns_current, 1);

        drop(response);
        assert_eq!(resolver.resource_stats.snapshot().dns_current, 0);
    }
    #[tokio::test]
    async fn fake_ip_answers_recover_names_and_keep_internal_resolution_real() {
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
hosts:
  alias.example: synthetic.example
  fixed.example: 192.0.2.9
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter: [real.example]
  fake-ip-ttl: 0
  nameserver: [192.0.2.1]
  use-system-hosts: false
"#,
        )
        .unwrap();
        let real: IpAddr = "203.0.113.7".parse().unwrap();
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::answer(real)),
                MockReply::Response(ResponseSpec::answer(real)),
                MockReply::Response(ResponseSpec::answer(real)),
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(&config.dns, dispatcher.clone());
        for name in ["synthetic.example", "alias.example"] {
            let wire = resolver
                .exchange(&build_query(10, name, QueryType::A).unwrap())
                .await
                .unwrap();
            let answer = parse_response(&wire).unwrap();
            assert!(answer.authoritative);
            assert!(answer.answers.iter().all(|record| record.ttl == 1));
            let address = matching_answer_set(&answer).unwrap().addresses[0];
            assert_eq!(address, "198.18.0.4".parse::<IpAddr>().unwrap());
            assert_eq!(
                resolver.recover_fake_ip(address).unwrap().as_deref(),
                Some("synthetic.example")
            );
        }
        assert_eq!(dispatcher.udp_calls.load(Ordering::Acquire), 0);
        assert_eq!(resolver.resolve("synthetic.example").await.unwrap(), [real]);
        for name in ["synthetic.example", "fixed.example"] {
            let wire = resolver
                .query_upstream(&build_query(10, name, QueryType::A).unwrap())
                .await
                .unwrap();
            assert_eq!(
                matching_answer_set(&parse_response(&wire).unwrap())
                    .unwrap()
                    .addresses,
                [real]
            );
        }
        let wire = resolver
            .exchange(&build_query(11, "real.example", QueryType::A).unwrap())
            .await
            .unwrap();
        assert_eq!(
            matching_answer_set(&parse_response(&wire).unwrap())
                .unwrap()
                .addresses,
            [real]
        );
        let updated = RuntimeDns::new(&config.dns, dispatcher).with_mapping_from(Some(&resolver));
        assert_eq!(
            updated
                .recover_fake_ip("198.18.0.4".parse().unwrap())
                .unwrap()
                .as_deref(),
            Some("synthetic.example")
        );
        assert!(
            updated
                .recover_fake_ip("198.18.0.9".parse().unwrap())
                .is_err()
        );
    }
    #[tokio::test]
    async fn dns_fallback_obeys_policy_domains_and_answer_filters() {
        let config = crate::config::Config::parse_yaml(
            br#"
mixed-port: 1080
dns:
  enable: true
  use-system-hosts: false
  nameserver: [192.0.2.1]
  fallback: [192.0.2.2]
  fallback-lazy-query: true
  fallback-filter:
    geoip: false
    ipcidr: [203.0.113.0/24]
    domain: ['+.fallback.example']
  nameserver-policy:
    policy.fallback.example: 192.0.2.3
"#,
        )
        .unwrap();
        let filtered: IpAddr = "203.0.113.10".parse().unwrap();
        let accepted: IpAddr = "192.0.2.30".parse().unwrap();
        for (host, answers, endpoints, expected) in [
            (
                "ordinary.example",
                vec![filtered, accepted],
                vec![1, 2],
                accepted,
            ),
            ("only.fallback.example", vec![accepted], vec![2], accepted),
            ("policy.fallback.example", vec![filtered], vec![3], filtered),
            ("accepted.example", vec![accepted], vec![1], accepted),
        ] {
            let dispatcher = Arc::new(MockDispatcher::with_replies(
                answers
                    .into_iter()
                    .map(|ip| MockReply::Response(ResponseSpec::answer(ip)))
                    .collect(),
                vec![],
            ));
            let resolver = RuntimeDns::new(&config.dns, dispatcher.clone());
            assert_eq!(resolver.resolve(host).await.unwrap(), [expected]);
            assert_eq!(
                *dispatcher.udp_destinations.lock().unwrap(),
                endpoints
                    .into_iter()
                    .map(|last| Destination::Ip(SocketAddr::from(([192, 0, 2, last], 53))))
                    .collect::<Vec<_>>()
            );
        }
        // Empty successful answers also trigger fallback.
        let dispatcher = Arc::new(MockDispatcher::with_replies(
            vec![
                MockReply::Response(ResponseSpec::rcode(RCODE_NXDOMAIN)),
                MockReply::Response(ResponseSpec::answer(accepted)),
            ],
            vec![],
        ));
        let resolver = RuntimeDns::new(&config.dns, dispatcher);
        assert_eq!(resolver.resolve("empty.example").await.unwrap(), [accepted]);
    }
}
