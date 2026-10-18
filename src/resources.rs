#[cfg(any(test, feature = "interop-test"))]
pub mod case_events;
pub mod observation;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const RESOURCE_SUMMARY_INTERVAL: Duration = Duration::from_secs(30);
const FIRST_PACKET_QUEUE_DROP: u64 = 1 << 0;
const FIRST_UDP_ASSOCIATION_QUEUE_DROP: u64 = 1 << 1;
const FIRST_DNS_QUEUE_DROP: u64 = 1 << 2;
const FIRST_SINGLEFLIGHT_JOIN: u64 = 1 << 3;
const FIRST_DNS_CACHE_HIT: u64 = 1 << 4;
const FIRST_UDP_RESPONSE_QUEUE_DROP: u64 = 1 << 5;

/// Fixed-schema, runtime-owned resource telemetry.
///
/// Every field has one statically assigned atomic. There is deliberately no
/// label map, destination key, domain name, address, UUID, configuration, or
/// payload in this object. Clones share one runtime component's counters and
/// the final owner emits a bounded summary before the storage is released.
///
/// Activity counters are observations only. They never reject, delay, or
/// otherwise alter runtime work.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeResourceStats {
    inner: Arc<RuntimeResourceStatsInner>,
}

#[derive(Debug)]
struct RuntimeResourceStatsInner {
    scope: &'static str,
    started: Instant,
    last_summary_seconds: AtomicU64,
    first_events: AtomicU64,
    final_emitted: AtomicBool,
    dns_requests: ActivityStats,
    singleflight: ActivityStats,
    tcp_sessions: ActivityStats,
    udp_associations: ActivityStats,
    handshakes: ActivityStats,
    singleflight_joins: AtomicU64,
    dns_cache_hits: AtomicU64,
    packet_queue_drops: AtomicU64,
    udp_queue_drops: AtomicU64,
    udp_association_queue_drops: AtomicU64,
    udp_response_queue_drops: AtomicU64,
    dns_queue_drops: AtomicU64,
}

#[derive(Debug, Default)]
struct ActivityStats {
    current: AtomicUsize,
    peak: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceActivity {
    DnsRequest,
    Singleflight,
    TcpSession,
    UdpAssociation,
    Handshake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceQueue {
    Packet,
    UdpAssociation,
    UdpResponse,
    Dns,
}

/// RAII accounting for one live runtime activity.
#[derive(Debug)]
pub(crate) struct ResourceActivityGuard {
    stats: RuntimeResourceStats,
    activity: ResourceActivity,
    _observation: observation::Guard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct RuntimeResourceSnapshot {
    pub(crate) dns_current: usize,
    pub(crate) dns_peak: usize,
    pub(crate) singleflight_current: usize,
    pub(crate) singleflight_peak: usize,
    pub(crate) tcp_current: usize,
    pub(crate) tcp_peak: usize,
    pub(crate) udp_current: usize,
    pub(crate) udp_peak: usize,
    pub(crate) handshake_current: usize,
    pub(crate) handshake_peak: usize,
    pub(crate) singleflight_joins: u64,
    pub(crate) dns_cache_hits: u64,
    pub(crate) packet_queue_drops: u64,
    pub(crate) udp_queue_drops: u64,
    pub(crate) udp_association_queue_drops: u64,
    pub(crate) udp_response_queue_drops: u64,
    pub(crate) dns_queue_drops: u64,
}

impl RuntimeResourceStats {
    #[must_use]
    pub(crate) fn new(scope: &'static str) -> Self {
        Self {
            inner: Arc::new(RuntimeResourceStatsInner {
                scope,
                started: Instant::now(),
                last_summary_seconds: AtomicU64::new(0),
                first_events: AtomicU64::new(0),
                final_emitted: AtomicBool::new(false),
                dns_requests: ActivityStats::default(),
                singleflight: ActivityStats::default(),
                tcp_sessions: ActivityStats::default(),
                udp_associations: ActivityStats::default(),
                handshakes: ActivityStats::default(),
                singleflight_joins: AtomicU64::new(0),
                dns_cache_hits: AtomicU64::new(0),
                packet_queue_drops: AtomicU64::new(0),
                udp_queue_drops: AtomicU64::new(0),
                udp_association_queue_drops: AtomicU64::new(0),
                udp_response_queue_drops: AtomicU64::new(0),
                dns_queue_drops: AtomicU64::new(0),
            }),
        }
    }

    /// Starts a pure observation guard for one live activity.
    #[must_use]
    pub(crate) fn begin(&self, activity: ResourceActivity) -> ResourceActivityGuard {
        let stats = self.activity(activity);
        let current = stats.current.fetch_add(1, Ordering::AcqRel) + 1;
        stats.peak.fetch_max(current, Ordering::Relaxed);
        self.maybe_log_periodic();
        ResourceActivityGuard {
            stats: self.clone(),
            activity,
            _observation: observation::track(match activity {
                ResourceActivity::DnsRequest | ResourceActivity::Singleflight => {
                    observation::ResourceKind::Waiter
                }
                ResourceActivity::TcpSession => observation::ResourceKind::Session,
                ResourceActivity::UdpAssociation => observation::ResourceKind::Association,
                ResourceActivity::Handshake => observation::ResourceKind::Handshake,
            }),
        }
    }

    pub(crate) fn singleflight_join(&self) {
        let joins = self
            .inner
            .singleflight_joins
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if self.mark_first(FIRST_SINGLEFLIGHT_JOIN) {
            let stats = self.activity(ResourceActivity::Singleflight);
            tracing::info!(
                event = "runtime_dns_singleflight_join",
                scope = self.inner.scope,
                current = stats.current.load(Ordering::Acquire),
                peak = stats.peak.load(Ordering::Acquire),
                joins,
                "runtime DNS query joined an existing flight"
            );
        }
        self.maybe_log_periodic();
    }

    pub(crate) fn dns_cache_hit(&self) {
        let hits = self.inner.dns_cache_hits.fetch_add(1, Ordering::Relaxed) + 1;
        if self.mark_first(FIRST_DNS_CACHE_HIT) {
            tracing::debug!(
                event = "runtime_dns_cache_hit",
                scope = self.inner.scope,
                hits,
                "runtime DNS cache served a query"
            );
        }
        self.maybe_log_periodic();
    }

    pub(crate) fn queue_drop(&self, queue: ResourceQueue, limit: usize) {
        if matches!(
            queue,
            ResourceQueue::UdpAssociation | ResourceQueue::UdpResponse
        ) {
            self.inner.udp_queue_drops.fetch_add(1, Ordering::Relaxed);
        }
        let (counter, first) = match queue {
            ResourceQueue::Packet => (&self.inner.packet_queue_drops, FIRST_PACKET_QUEUE_DROP),
            ResourceQueue::UdpAssociation => (
                &self.inner.udp_association_queue_drops,
                FIRST_UDP_ASSOCIATION_QUEUE_DROP,
            ),
            ResourceQueue::UdpResponse => (
                &self.inner.udp_response_queue_drops,
                FIRST_UDP_RESPONSE_QUEUE_DROP,
            ),
            ResourceQueue::Dns => (&self.inner.dns_queue_drops, FIRST_DNS_QUEUE_DROP),
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if self.mark_first(first) {
            match queue {
                ResourceQueue::Packet => tracing::warn!(
                    event = "tun_packet_queue_drop",
                    scope = self.inner.scope,
                    limit,
                    "runtime queue dropped an item for the first time"
                ),
                ResourceQueue::UdpAssociation => tracing::warn!(
                    event = "tun_udp_association_drop",
                    scope = self.inner.scope,
                    limit,
                    "runtime queue dropped an item for the first time"
                ),
                ResourceQueue::UdpResponse => tracing::warn!(
                    event = "tun_udp_response_drop",
                    scope = self.inner.scope,
                    limit,
                    "runtime queue dropped an item for the first time"
                ),
                ResourceQueue::Dns => tracing::warn!(
                    event = "runtime_dns_response_drop",
                    scope = self.inner.scope,
                    limit,
                    dns_queue_drops = counter.load(Ordering::Relaxed),
                    "runtime queue dropped an item for the first time"
                ),
            }
        }
        self.maybe_log_periodic();
    }

    pub(crate) fn log_final(&self) {
        if !self.inner.final_emitted.swap(true, Ordering::AcqRel) {
            self.log_summary("resource_stats_final");
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn snapshot(&self) -> RuntimeResourceSnapshot {
        RuntimeResourceSnapshot {
            dns_current: self.current(ResourceActivity::DnsRequest),
            dns_peak: self.peak(ResourceActivity::DnsRequest),
            singleflight_current: self.current(ResourceActivity::Singleflight),
            singleflight_peak: self.peak(ResourceActivity::Singleflight),
            tcp_current: self.current(ResourceActivity::TcpSession),
            tcp_peak: self.peak(ResourceActivity::TcpSession),
            udp_current: self.current(ResourceActivity::UdpAssociation),
            udp_peak: self.peak(ResourceActivity::UdpAssociation),
            handshake_current: self.current(ResourceActivity::Handshake),
            handshake_peak: self.peak(ResourceActivity::Handshake),
            singleflight_joins: self.inner.singleflight_joins.load(Ordering::Acquire),
            dns_cache_hits: self.inner.dns_cache_hits.load(Ordering::Acquire),
            packet_queue_drops: self.inner.packet_queue_drops.load(Ordering::Acquire),
            udp_queue_drops: self.inner.udp_queue_drops.load(Ordering::Acquire),
            udp_association_queue_drops: self
                .inner
                .udp_association_queue_drops
                .load(Ordering::Acquire),
            udp_response_queue_drops: self.inner.udp_response_queue_drops.load(Ordering::Acquire),
            dns_queue_drops: self.inner.dns_queue_drops.load(Ordering::Acquire),
        }
    }

    fn activity(&self, activity: ResourceActivity) -> &ActivityStats {
        match activity {
            ResourceActivity::DnsRequest => &self.inner.dns_requests,
            ResourceActivity::Singleflight => &self.inner.singleflight,
            ResourceActivity::TcpSession => &self.inner.tcp_sessions,
            ResourceActivity::UdpAssociation => &self.inner.udp_associations,
            ResourceActivity::Handshake => &self.inner.handshakes,
        }
    }

    #[cfg(test)]
    fn current(&self, activity: ResourceActivity) -> usize {
        self.activity(activity).current.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn peak(&self, activity: ResourceActivity) -> usize {
        self.activity(activity).peak.load(Ordering::Acquire)
    }

    fn mark_first(&self, bit: u64) -> bool {
        self.inner.first_events.fetch_or(bit, Ordering::AcqRel) & bit == 0
    }

    fn maybe_log_periodic(&self) {
        let elapsed = self.inner.started.elapsed().as_secs();
        if elapsed < RESOURCE_SUMMARY_INTERVAL.as_secs() {
            return;
        }
        let interval = RESOURCE_SUMMARY_INTERVAL.as_secs();
        let bucket = elapsed / interval;
        let mut previous = self.inner.last_summary_seconds.load(Ordering::Acquire);
        while previous < bucket {
            match self.inner.last_summary_seconds.compare_exchange_weak(
                previous,
                bucket,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.log_summary("resource_stats_periodic");
                    return;
                }
                Err(observed) => previous = observed,
            }
        }
    }

    fn log_summary(&self, event: &'static str) {
        self.inner.log_summary(event);
    }
}

impl RuntimeResourceStatsInner {
    fn log_summary(&self, event: &'static str) {
        tracing::info!(
            event,
            scope = self.scope,
            dns_current = self.dns_requests.current.load(Ordering::Acquire),
            dns_peak = self.dns_requests.peak.load(Ordering::Acquire),
            singleflight_current = self.singleflight.current.load(Ordering::Acquire),
            singleflight_peak = self.singleflight.peak.load(Ordering::Acquire),
            singleflight_joins = self.singleflight_joins.load(Ordering::Acquire),
            dns_cache_hits = self.dns_cache_hits.load(Ordering::Acquire),
            tcp_current = self.tcp_sessions.current.load(Ordering::Acquire),
            tcp_peak = self.tcp_sessions.peak.load(Ordering::Acquire),
            udp_current = self.udp_associations.current.load(Ordering::Acquire),
            udp_peak = self.udp_associations.peak.load(Ordering::Acquire),
            handshake_current = self.handshakes.current.load(Ordering::Acquire),
            handshake_peak = self.handshakes.peak.load(Ordering::Acquire),
            packet_queue_drops = self.packet_queue_drops.load(Ordering::Acquire),
            udp_queue_drops = self.udp_queue_drops.load(Ordering::Acquire),
            udp_association_queue_drops = self.udp_association_queue_drops.load(Ordering::Acquire),
            udp_response_queue_drops = self.udp_response_queue_drops.load(Ordering::Acquire),
            dns_queue_drops = self.dns_queue_drops.load(Ordering::Acquire),
            "runtime resource statistics"
        );
    }
}

impl Drop for RuntimeResourceStatsInner {
    fn drop(&mut self) {
        if !self.final_emitted.swap(true, Ordering::AcqRel) {
            self.log_summary("resource_stats_final");
        }
    }
}

impl Drop for ResourceActivityGuard {
    fn drop(&mut self) {
        let previous = self
            .stats
            .activity(self.activity)
            .current
            .fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "runtime resource counter underflow");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_resource_stats_are_observational_and_use_raii_current_counts() {
        let stats = RuntimeResourceStats::new("test_runtime");
        let dns = stats.begin(ResourceActivity::DnsRequest);
        let tcp = stats.begin(ResourceActivity::TcpSession);
        let udp = stats.begin(ResourceActivity::UdpAssociation);
        let handshake = stats.begin(ResourceActivity::Handshake);
        let singleflight = stats.begin(ResourceActivity::Singleflight);
        stats.singleflight_join();
        stats.dns_cache_hit();
        stats.queue_drop(ResourceQueue::Packet, 32);
        stats.queue_drop(ResourceQueue::UdpAssociation, 64);
        stats.queue_drop(ResourceQueue::UdpResponse, 1024);
        stats.queue_drop(ResourceQueue::Dns, 16);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.dns_current, 1);
        assert_eq!(snapshot.dns_peak, 1);
        assert_eq!(snapshot.singleflight_current, 1);
        assert_eq!(snapshot.singleflight_peak, 1);
        assert_eq!(snapshot.tcp_current, 1);
        assert_eq!(snapshot.tcp_peak, 1);
        assert_eq!(snapshot.udp_current, 1);
        assert_eq!(snapshot.udp_peak, 1);
        assert_eq!(snapshot.handshake_current, 1);
        assert_eq!(snapshot.handshake_peak, 1);
        assert_eq!(snapshot.singleflight_joins, 1);
        assert_eq!(snapshot.dns_cache_hits, 1);
        assert_eq!(snapshot.packet_queue_drops, 1);
        assert_eq!(snapshot.udp_queue_drops, 2);
        assert_eq!(snapshot.udp_association_queue_drops, 1);
        assert_eq!(snapshot.udp_response_queue_drops, 1);
        assert_eq!(snapshot.dns_queue_drops, 1);

        drop((dns, tcp, udp, handshake, singleflight));
        let released = stats.snapshot();
        assert_eq!(released.dns_current, 0);
        assert_eq!(released.singleflight_current, 0);
        assert_eq!(released.tcp_current, 0);
        assert_eq!(released.udp_current, 0);
        assert_eq!(released.handshake_current, 0);
        stats.log_final();
    }
}
