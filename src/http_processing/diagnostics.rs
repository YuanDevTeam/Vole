//! Fixed-size, process-lifetime HTTP diagnostics; no traffic data or reset API.
//!
//! Only `http-diagnostics` builds retain counters. Concurrent snapshots are
//! independently sampled atomics, not a transaction; use a quiescent snapshot
//! after the real stop barrier for lifecycle conservation checks.

#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(feature = "http-diagnostics", target_vendor = "apple")),
    allow(dead_code)
)]
pub(crate) enum Counter {
    ScriptMatched,
    SkipAsteriskBody,
    SkipBodyUnavailable,
    SkipTextUnavailable,
    SkipInputUnrepresentable,
    SkipCallBuffers,
    CallBuffersRequested,
    CallBuffersAdmitted,
    CallBuffersBudgetRejected,
    CallBuffersAllocationRejected,
    QueueRequested,
    QueueAcquired,
    QueueTimeout,
    QueueCancelled,
    QueueFailed,
    EvaluationEntered,
    EvaluationSucceeded,
    EvaluationTimedOut,
    EvaluationCancelled,
    EvaluationFailed,
    BackendFatal,
    OutputAccepted,
    OutputRejected,
    OutputTerminal,
    BodyReserveSucceeded,
    BodyReserveRejected,
    CollectorNativeRequested,
    CollectorSharedRequested,
    CollectorAdmitted,
    CollectorFinished,
    NativeTransformRequested,
    NativeTransformFinished,
    ContextCreated,
    ContextReleased,
    BridgeInputRejected,
    BridgeExportRejected,
    BridgeGuardInvalid,
    AsciiViewRequested,
    AsciiViewAdmitted,
    AsciiViewBudgetFallback,
    LiteralReplaceRequested,
    LiteralReplaceAdmitted,
    LiteralReplaceBudgetFallback,
    LiteralReplaceSemanticFallback,
    LiteralReplaceApiFallback,
    PlatformWarmupRequested,
    PlatformWarmupStarted,
    PlatformWarmupSucceeded,
    PlatformWarmupFailed,
    PlatformWarmupContextCreated,
    PlatformWarmupContextReleased,
    JscSelected,
    PlanSelected,
    PlanInputFallback,
    PlanAstFallback,
    PlanBuffersRejected,
    PlanEntered,
    PlanSucceeded,
    PlanTimedOut,
    PlanCancelled,
    PlanFailed,
    JscOwnerStarted,
    JscOwnerJoined,
    PlanOwnerStarted,
    PlanOwnerJoined,
    PlanFinalRecipeEntered,
    PlanFinalDagEntered,
    PlanInlineEntered,
    PlanInlineReturned,
    PlanInlinePanicked,
    PlanInlineCpuUnavailable,
    PlanHeaderGuardEntered,
    PlanHeaderGuardTail,
    PlanHeaderGuardPass,
    PlanHeaderGuardAbort,
    PlanFinalSingleStepEntered,
    PlanOutputPendingAdmitted,
    PlanOutputQueueFailed,
    PlanOutputPayloadBudgetRejected,
    // Platform TUN write observations share the existing diagnostic no-op.
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteSingleSendAttempts,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteSingleEnobufsErrors,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteSingleSleep1msRequests,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteSingleAcceptedPackets,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteSingleWouldBlock,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteBatchSendAttempts,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteBatchEnobufsErrors,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteBatchSleep1msRequests,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteBatchAcceptedPackets,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunWriteBatchWouldBlock,
    // Read outcomes and netstack handoff are different packet boundaries.
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunIngressReadOkPackets,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunIngressReadInvalidPacketOutcomes,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunIngressMtuExceededDrops,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunIngressNetstackAcceptedPackets,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunIngressNetstackBackpressureDrops,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunIngressIpv4DeclaredLengthExceedsReadSlice,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunIngressIpv6DeclaredLengthExceedsReadSlice,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverDrivePasses,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverTcpEntryVisits,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverAppRxBytes,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverAppTxBytes,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverNoDataProgressPasses,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverWaitIngress,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverWaitNotify,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    TunNetstackDriverWaitTimer,
    #[cfg_attr(
        not(all(
            feature = "http-js-quickjs",
            any(target_os = "android", target_os = "linux", windows)
        )),
        allow(dead_code)
    )]
    QuickjsEngineEntered,
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(feature = "http-diagnostics", target_vendor = "apple")),
    allow(dead_code)
)]
pub(crate) enum Timing {
    Queue,
    Evaluation,
    ContextRelease,
    FinalParse,
    ScopedOwner,
    JscScopedOwner,
    PlanScopedOwner,
    PlanInlineDispatchWall,
    PlanInlineWall,
    PlanInlineThreadCpu,
}

#[derive(Clone, Copy)]
pub(crate) enum BodyPoint {
    NativeAdmission,
    SharedAdmission,
    Collection,
    NativeDecode,
    SharedDecode,
    NativeTransform,
    HeaderFinalize,
}

#[inline]
pub(crate) fn increment(counter: Counter) {
    #[cfg(feature = "http-diagnostics")]
    enabled::STATS.increment(counter);
    #[cfg(not(feature = "http-diagnostics"))]
    let _ = counter;
}

#[cfg(feature = "http-diagnostics")]
#[cfg_attr(not(feature = "tun"), allow(dead_code))]
#[inline]
pub(crate) fn add_counter(counter: Counter, value: u64) {
    enabled::STATS.add_counter(counter, value);
}

// Observation only: a complete base header's declared length exceeds the
// actual read slice. This is not an IP validator or proof of transport loss.
#[inline]
#[cfg_attr(not(feature = "tun"), allow(dead_code))]
pub(crate) fn record_tun_ingress_header(packet: &[u8]) {
    #[cfg(feature = "http-diagnostics")]
    if let Some(counter) = tun_ingress_header_length_counter(packet) {
        increment(counter);
    }
    #[cfg(not(feature = "http-diagnostics"))]
    let _ = packet;
}

#[cfg(feature = "http-diagnostics")]
#[cfg_attr(not(feature = "tun"), allow(dead_code))]
fn tun_ingress_header_length_counter(packet: &[u8]) -> Option<Counter> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            (declared > packet.len())
                .then_some(Counter::TunIngressIpv4DeclaredLengthExceedsReadSlice)
        }
        Some(6) if packet.len() >= 40 => {
            let declared = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            (declared > packet.len())
                .then_some(Counter::TunIngressIpv6DeclaredLengthExceedsReadSlice)
        }
        _ => None,
    }
}

#[inline]
pub(crate) fn body_reserved(bytes: usize, single_budget_used: usize) {
    #[cfg(feature = "http-diagnostics")]
    enabled::STATS.body_reserved(bytes, single_budget_used);
    #[cfg(not(feature = "http-diagnostics"))]
    let _ = (bytes, single_budget_used);
}

#[inline]
pub(crate) fn body_released(bytes: usize) {
    #[cfg(feature = "http-diagnostics")]
    enabled::STATS
        .body_current
        .fetch_sub(bytes as u64, std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(feature = "http-diagnostics"))]
    let _ = bytes;
}

#[inline]
pub(crate) fn call_buffers_requested(input: usize, output: usize, bridge: usize) {
    #[cfg(feature = "http-diagnostics")]
    enabled::STATS.call_buffers_requested(input, output, bridge);
    #[cfg(not(feature = "http-diagnostics"))]
    let _ = (input, output, bridge);
}

#[inline]
pub(crate) fn body_bypass(point: BodyPoint, reason: super::body::Bypass) {
    #[cfg(feature = "http-diagnostics")]
    enabled::STATS.body_bypass(point, reason);
    #[cfg(not(feature = "http-diagnostics"))]
    let _ = (point, reason);
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
#[inline]
pub(crate) fn context_created() {
    #[cfg(feature = "http-diagnostics")]
    {
        use std::sync::atomic::Ordering;
        increment(Counter::ContextCreated);
        let current = enabled::STATS
            .context_current
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        enabled::STATS
            .context_peak
            .fetch_max(current, Ordering::Relaxed);
    }
}

#[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
#[inline]
pub(crate) fn context_released() {
    #[cfg(feature = "http-diagnostics")]
    {
        increment(Counter::ContextReleased);
        enabled::STATS
            .context_current
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(feature = "inbound-http")]
pub(crate) struct QueueGuard {
    #[cfg(feature = "http-diagnostics")]
    started: std::time::Instant,
    #[cfg(feature = "http-diagnostics")]
    finished: bool,
}
#[cfg(feature = "inbound-http")]
impl QueueGuard {
    #[inline]
    pub(crate) fn new() -> Self {
        #[cfg(feature = "http-diagnostics")]
        {
            use std::sync::atomic::Ordering;
            increment(Counter::QueueRequested);
            let current = enabled::STATS.queue_current.fetch_add(1, Ordering::Relaxed) + 1;
            enabled::STATS
                .queue_peak
                .fetch_max(current, Ordering::Relaxed);
        }
        Self {
            #[cfg(feature = "http-diagnostics")]
            started: std::time::Instant::now(),
            #[cfg(feature = "http-diagnostics")]
            finished: false,
        }
    }
    #[inline]
    pub(crate) fn acquired(&mut self) {
        #[cfg(feature = "http-diagnostics")]
        {
            self.finish();
            increment(Counter::QueueAcquired);
        }
    }
    #[inline]
    pub(crate) fn failed(&mut self, kind: std::io::ErrorKind) {
        #[cfg(feature = "http-diagnostics")]
        {
            let counter = match kind {
                std::io::ErrorKind::TimedOut => Counter::QueueTimeout,
                std::io::ErrorKind::Interrupted => Counter::QueueCancelled,
                _ => Counter::QueueFailed,
            };
            self.finish();
            increment(counter);
        }
        #[cfg(not(feature = "http-diagnostics"))]
        let _ = kind;
    }
    #[cfg(feature = "http-diagnostics")]
    fn finish(&mut self) {
        self.finished = true;
        enabled::STATS
            .queue_current
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        enabled::STATS.timings[Timing::Queue as usize].record(self.started.elapsed().as_micros());
    }
}
#[cfg(feature = "inbound-http")]
impl Drop for QueueGuard {
    fn drop(&mut self) {
        #[cfg(feature = "http-diagnostics")]
        if !self.finished {
            self.failed(std::io::ErrorKind::Interrupted);
        }
    }
}

#[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
#[inline]
pub(crate) fn timing(kind: Timing, micros: u128) {
    #[cfg(feature = "http-diagnostics")]
    enabled::STATS.timings[kind as usize].record(micros);
    #[cfg(not(feature = "http-diagnostics"))]
    let _ = (kind, micros);
}

#[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
#[inline]
pub(crate) fn evaluation_finished(
    stages: [u128; 6],
    seen: u8,
    overall: u128,
    ticks: usize,
    succeeded: bool,
) {
    enabled::STATS.evaluation_finished(stages, seen, overall, ticks, succeeded);
}

/// Diagnostic-build-only, process-lifetime counters. No URL, script identity,
/// configuration, headers, body, certificate or private key is retained.
#[cfg(feature = "http-diagnostics")]
pub fn snapshot() -> serde_json::Value {
    let value = enabled::STATS.snapshot();
    #[cfg(all(feature = "inbound-http", target_vendor = "apple"))]
    {
        let mut value = value;
        value["scopedScriptOwner"] = super::scripts::scoped_owner_qos_snapshot();
        value
    }
    #[cfg(not(all(feature = "inbound-http", target_vendor = "apple")))]
    {
        value
    }
}

#[cfg(feature = "http-diagnostics")]
mod enabled {
    use super::{BodyPoint, Counter};
    use crate::http_processing::body::Bypass;
    use serde_json::{Map, Value, json};
    use std::sync::atomic::{AtomicU64, Ordering};

    const COUNTERS: [&str; 105] = [
        "scriptMatched",
        "skipAsteriskBody",
        "skipBodyUnavailable",
        "skipTextUnavailable",
        "skipInputUnrepresentable",
        "skipCallBuffers",
        "callBuffersRequested",
        "callBuffersAdmitted",
        "callBuffersBudgetRejected",
        "callBuffersAllocationRejected",
        "queueRequested",
        "queueAcquired",
        "queueTimeout",
        "queueCancelled",
        "queueFailed",
        "evaluationEntered",
        "evaluationSucceeded",
        "evaluationTimedOut",
        "evaluationCancelled",
        "evaluationFailed",
        "backendFatal",
        "outputAccepted",
        "outputRejected",
        "outputTerminal",
        "bodyReserveSucceeded",
        "bodyReserveRejected",
        "collectorNativeRequested",
        "collectorSharedRequested",
        "collectorAdmitted",
        "collectorFinished",
        "nativeTransformRequested",
        "nativeTransformFinished",
        "contextCreated",
        "contextReleased",
        "bridgeInputRejected",
        "bridgeExportRejected",
        "bridgeGuardInvalid",
        "asciiViewRequested",
        "asciiViewAdmitted",
        "asciiViewBudgetFallback",
        "literalReplaceRequested",
        "literalReplaceAdmitted",
        "literalReplaceBudgetFallback",
        "literalReplaceSemanticFallback",
        "literalReplaceApiFallback",
        "platformWarmupRequested",
        "platformWarmupStarted",
        "platformWarmupSucceeded",
        "platformWarmupFailed",
        "platformWarmupContextCreated",
        "platformWarmupContextReleased",
        "jscSelected",
        "planSelected",
        "planInputFallback",
        "planAstFallback",
        "planBuffersRejected",
        "planEntered",
        "planSucceeded",
        "planTimedOut",
        "planCancelled",
        "planFailed",
        "jscOwnerStarted",
        "jscOwnerJoined",
        "planOwnerStarted",
        "planOwnerJoined",
        "planFinalRecipeEntered",
        "planFinalDagEntered",
        "planInlineEntered",
        "planInlineReturned",
        "planInlinePanicked",
        "planInlineCpuUnavailable",
        "planHeaderGuardEntered",
        "planHeaderGuardTail",
        "planHeaderGuardPass",
        "planHeaderGuardAbort",
        "planFinalSingleStepEntered",
        "planOutputPendingAdmitted",
        "planOutputQueueFailed",
        "planOutputPayloadBudgetRejected",
        "tunWriteSingleSendAttempts",
        "tunWriteSingleEnobufsErrors",
        "tunWriteSingleSleep1msRequests",
        "tunWriteSingleAcceptedPackets",
        "tunWriteSingleWouldBlock",
        "tunWriteBatchSendAttempts",
        "tunWriteBatchEnobufsErrors",
        "tunWriteBatchSleep1msRequests",
        "tunWriteBatchAcceptedPackets",
        "tunWriteBatchWouldBlock",
        "tunIngressReadOkPackets",
        "tunIngressReadInvalidPacketOutcomes",
        "tunIngressMtuExceededDrops",
        "tunIngressNetstackAcceptedPackets",
        "tunIngressNetstackBackpressureDrops",
        "tunIngressIpv4DeclaredLengthExceedsReadSlice",
        "tunIngressIpv6DeclaredLengthExceedsReadSlice",
        "tunNetstackDriverDrivePasses",
        "tunNetstackDriverTcpEntryVisits",
        "tunNetstackDriverAppRxBytes",
        "tunNetstackDriverAppTxBytes",
        "tunNetstackDriverNoDataProgressPasses",
        "tunNetstackDriverWaitIngress",
        "tunNetstackDriverWaitNotify",
        "tunNetstackDriverWaitTimer",
        "quickjsEngineEntered",
    ];
    const TIMINGS: [&str; 10] = [
        "queue",
        "evaluation",
        "contextRelease",
        "finalParse",
        "scopedOwner",
        "jscScopedOwner",
        "planScopedOwner",
        "planInlineDispatchWall",
        "planInlineWall",
        "planInlineThreadCpu",
    ];
    const STAGES: [&str; 6] = [
        "contextAndCallback",
        "prelude",
        "program",
        "input",
        "invokeAndFinish",
        "export",
    ];
    const BODY_POINTS: [&str; 7] = [
        "nativeAdmission",
        "sharedAdmission",
        "collection",
        "nativeDecode",
        "sharedDecode",
        "nativeTransform",
        "headerFinalize",
    ];
    const REASONS: [&str; 11] = [
        "noRules",
        "forbiddenBody",
        "streaming",
        "trailers",
        "charset",
        "encoding",
        "identityExcluded",
        "budget",
        "size",
        "invalidText",
        "transform",
    ];

    fn reason_index(reason: Bypass) -> usize {
        match reason {
            Bypass::NoRules => 0,
            Bypass::ForbiddenBody => 1,
            Bypass::Streaming => 2,
            Bypass::Trailers => 3,
            Bypass::Charset => 4,
            Bypass::Encoding => 5,
            Bypass::IdentityExcluded => 6,
            Bypass::Budget => 7,
            Bypass::Size => 8,
            Bypass::InvalidText => 9,
            Bypass::Transform => 10,
        }
    }

    // Saturation affects only telemetry and cannot wrap an accumulated time or
    // byte count. Gauges instead follow balanced actual owner admission/drop.
    fn add(target: &AtomicU64, value: u64) {
        let _ = target.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            Some(old.saturating_add(value))
        });
    }
    fn load(target: &AtomicU64) -> u64 {
        target.load(Ordering::Relaxed)
    }
    fn bounded(value: u128) -> u64 {
        value.min(u128::from(u64::MAX)) as u64
    }
    pub(super) struct Aggregate {
        count: AtomicU64,
        total: AtomicU64,
        max: AtomicU64,
    }
    impl Aggregate {
        const fn new() -> Self {
            Self {
                count: AtomicU64::new(0),
                total: AtomicU64::new(0),
                max: AtomicU64::new(0),
            }
        }
        pub(super) fn record(&self, value: u128) {
            add(&self.count, 1);
            let value = bounded(value);
            add(&self.total, value);
            self.max.fetch_max(value, Ordering::Relaxed);
        }
        fn snapshot(&self) -> Value {
            json!({"count": load(&self.count), "total": load(&self.total), "max": load(&self.max)})
        }
    }

    pub(super) struct Stats {
        counters: [AtomicU64; COUNTERS.len()],
        pub(super) timings: [Aggregate; TIMINGS.len()],
        stages: [[Aggregate; STAGES.len()]; 2],
        requested: [Aggregate; 3],
        ticks: Aggregate,
        bypasses: [[AtomicU64; REASONS.len()]; BODY_POINTS.len()],
        pub(super) body_current: AtomicU64,
        body_peak: AtomicU64,
        body_max_single_budget: AtomicU64,
        pub(super) context_current: AtomicU64,
        pub(super) context_peak: AtomicU64,
        pub(super) queue_current: AtomicU64,
        pub(super) queue_peak: AtomicU64,
    }
    impl Stats {
        const fn new() -> Self {
            Self {
                counters: [const { AtomicU64::new(0) }; COUNTERS.len()],
                timings: [const { Aggregate::new() }; TIMINGS.len()],
                stages: [const { [const { Aggregate::new() }; STAGES.len()] }; 2],
                requested: [const { Aggregate::new() }; 3],
                ticks: Aggregate::new(),
                bypasses: [const { [const { AtomicU64::new(0) }; REASONS.len()] };
                    BODY_POINTS.len()],
                body_current: AtomicU64::new(0),
                body_peak: AtomicU64::new(0),
                body_max_single_budget: AtomicU64::new(0),
                context_current: AtomicU64::new(0),
                context_peak: AtomicU64::new(0),
                queue_current: AtomicU64::new(0),
                queue_peak: AtomicU64::new(0),
            }
        }
        pub(super) fn add_counter(&self, counter: Counter, value: u64) {
            add(&self.counters[counter as usize], value);
        }
        pub(super) fn increment(&self, counter: Counter) {
            add(&self.counters[counter as usize], 1);
        }
        pub(super) fn body_reserved(&self, bytes: usize, single_budget_used: usize) {
            self.increment(Counter::BodyReserveSucceeded);
            let current = self
                .body_current
                .fetch_add(bytes as u64, Ordering::Relaxed)
                .saturating_add(bytes as u64);
            self.body_peak.fetch_max(current, Ordering::Relaxed);
            self.body_max_single_budget
                .fetch_max(single_budget_used as u64, Ordering::Relaxed);
        }
        pub(super) fn call_buffers_requested(&self, input: usize, output: usize, bridge: usize) {
            self.increment(Counter::CallBuffersRequested);
            for (stat, bytes) in self.requested.iter().zip([input, output, bridge]) {
                stat.record(bytes as u128);
            }
        }
        pub(super) fn body_bypass(&self, point: BodyPoint, reason: Bypass) {
            add(&self.bypasses[point as usize][reason_index(reason)], 1);
        }
        #[cfg(any(test, target_vendor = "apple"))]
        pub(super) fn evaluation_finished(
            &self,
            stages: [u128; 6],
            seen: u8,
            overall: u128,
            ticks: usize,
            succeeded: bool,
        ) {
            self.timings[super::Timing::Evaluation as usize].record(overall);
            self.ticks.record(ticks as u128);
            let outcome = usize::from(!succeeded);
            for (index, micros) in stages.into_iter().enumerate() {
                if seen & (1 << index) != 0 {
                    self.stages[outcome][index].record(micros);
                }
            }
        }
        pub(super) fn snapshot(&self) -> Value {
            let counters: Map<String, Value> = COUNTERS
                .iter()
                .zip(&self.counters)
                .map(|(key, value)| ((*key).into(), load(value).into()))
                .collect();
            let timings: Map<String, Value> = TIMINGS
                .iter()
                .zip(&self.timings)
                .map(|(key, value)| ((*key).into(), value.snapshot()))
                .collect();
            let stages: Map<String, Value> = STAGES.iter().enumerate().map(|(i, key)| ((*key).into(), json!({"succeeded": self.stages[0][i].snapshot(), "failed": self.stages[1][i].snapshot()}))).collect();
            let bypasses: Map<String, Value> = BODY_POINTS
                .iter()
                .zip(&self.bypasses)
                .map(|(point, values)| {
                    let reasons: Map<String, Value> = REASONS
                        .iter()
                        .zip(values)
                        .map(|(reason, value)| ((*reason).into(), load(value).into()))
                        .collect();
                    ((*point).into(), reasons.into())
                })
                .collect();
            json!({
                "scope": "process-lifetime; fixed counters; atomic fields sampled independently",
                "units": {"timings": "microseconds", "stages": "microseconds", "callBuffers": "reserved bytes requested", "bodyWorkspace": "reservation bytes, not VM heap or RSS"},
                "counters": counters,
                "queue": {"current": load(&self.queue_current), "peak": load(&self.queue_peak)},
                "contexts": {"current": load(&self.context_current), "peak": load(&self.context_peak), "kind": "JSGlobalContext; current implementation creates a unique group per context"},
                "timings": timings,
                "stages": stages,
                "ticks": self.ticks.snapshot(),
                "bodyWorkspace": {"current": load(&self.body_current), "peak": load(&self.body_peak), "maxSingleBudget": load(&self.body_max_single_budget), "scope": "current/peak are process-wide shadow telemetry; transient ordering can overstate peak; maxSingleBudget uses actual successful admission"},
                "callBuffers": {"input": self.requested[0].snapshot(), "maximumOutput": self.requested[1].snapshot(), "bridgeWorkspace": self.requested[2].snapshot(), "admission": "single atomic combined reservation; failure does not identify a single component"},
                "bodyBypasses": bypasses,
            })
        }
    }
    pub(super) static STATS: Stats = Stats::new();

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn local_stats_preserve_components_and_combined_rejection() {
            let stats = Stats::new();
            stats.call_buffers_requested(64, 256, 128);
            stats.increment(Counter::CallBuffersBudgetRejected);
            let value = stats.snapshot();
            assert_eq!(value["callBuffers"]["input"]["total"], 64);
            assert_eq!(value["callBuffers"]["maximumOutput"]["total"], 256);
            assert_eq!(value["callBuffers"]["bridgeWorkspace"]["total"], 128);
            assert_eq!(value["counters"]["callBuffersBudgetRejected"], 1);
            assert_eq!(value["counters"]["callBuffersAdmitted"], 0);
        }

        #[test]
        fn local_gauges_balance_independent_reservations_and_stage_outcomes() {
            let stats = Stats::new();
            stats.body_reserved(100, 100);
            stats.body_reserved(20, 120);
            stats.body_current.fetch_sub(100, Ordering::Relaxed);
            assert_eq!(stats.snapshot()["bodyWorkspace"]["current"], 20);
            stats.body_current.fetch_sub(20, Ordering::Relaxed);
            stats.evaluation_finished([2, 3, 5, 7, 11, 13], 0b11_1111, 50, 80, true);
            stats.evaluation_finished([17, 19, 0, 0, 0, 0], 0b00_0011, 40, 0, false);
            let value = stats.snapshot();
            assert_eq!(value["bodyWorkspace"]["current"], 0);
            assert_eq!(value["bodyWorkspace"]["peak"], 120);
            assert_eq!(value["stages"]["prelude"]["succeeded"]["total"], 3);
            assert_eq!(value["stages"]["prelude"]["failed"]["total"], 19);
            assert_eq!(value["stages"]["program"]["failed"]["count"], 0);
            assert_eq!(value["timings"]["evaluation"]["total"], 90);
            assert_eq!(value["ticks"]["max"], 80);
        }

        #[test]
        fn telemetry_saturates_without_affecting_owner_gauges() {
            let total = AtomicU64::new(u64::MAX - 1);
            add(&total, 3);
            assert_eq!(load(&total), u64::MAX);
        }

        #[test]
        fn tun_ingress_ipv4_declared_length_is_observational_only() {
            let mut packet = [0u8; 24];
            packet[0] = 0x45;
            for declared in [0u16, 19, 20, 23, 24] {
                packet[2..4].copy_from_slice(&declared.to_be_bytes());
                assert!(matches!(
                    super::super::tun_ingress_header_length_counter(&packet),
                    None
                ));
            }
            packet[2..4].copy_from_slice(&25u16.to_be_bytes());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&packet),
                Some(super::super::Counter::TunIngressIpv4DeclaredLengthExceedsReadSlice)
            ));
            // IHL/options validity is outside this observation. Only the complete
            // twenty-byte base and version select the declared-length comparison.
            packet[0] = 0x4f;
            packet[2..4].copy_from_slice(&24u16.to_be_bytes());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&packet),
                None
            ));
            packet[2..4].copy_from_slice(&25u16.to_be_bytes());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&packet),
                Some(super::super::Counter::TunIngressIpv4DeclaredLengthExceedsReadSlice)
            ));
        }

        #[test]
        fn tun_ingress_length_uses_read_slice_not_vec_capacity_or_backing() {
            let mut ipv4 = Vec::with_capacity(4096);
            ipv4.resize(20, 0u8);
            ipv4[0] = 0x45;
            ipv4[2..4].copy_from_slice(&21u16.to_be_bytes());
            assert!(ipv4.capacity() > ipv4.len());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&ipv4),
                Some(super::super::Counter::TunIngressIpv4DeclaredLengthExceedsReadSlice)
            ));
            ipv4.resize(32, 0);
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&ipv4),
                None
            ));
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&ipv4[..20]),
                Some(super::super::Counter::TunIngressIpv4DeclaredLengthExceedsReadSlice)
            ));

            let mut ipv6 = Vec::with_capacity(4096);
            ipv6.resize(40, 0u8);
            ipv6[0] = 0x60;
            ipv6[4..6].copy_from_slice(&1u16.to_be_bytes());
            assert!(ipv6.capacity() > ipv6.len());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&ipv6),
                Some(super::super::Counter::TunIngressIpv6DeclaredLengthExceedsReadSlice)
            ));
            ipv6.resize(41, 0);
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&ipv6),
                None
            ));
        }

        #[test]
        fn tun_ingress_length_requires_complete_base_headers_and_known_version() {
            for len in 0..20 {
                let mut packet = vec![0u8; len];
                if let Some(first) = packet.first_mut() {
                    *first = 0x45;
                }
                if len >= 4 {
                    packet[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
                }
                assert!(matches!(
                    super::super::tun_ingress_header_length_counter(&packet),
                    None
                ));
            }
            for len in 0..40 {
                let mut packet = vec![0u8; len];
                if let Some(first) = packet.first_mut() {
                    *first = 0x60;
                }
                if len >= 6 {
                    packet[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
                }
                assert!(matches!(
                    super::super::tun_ingress_header_length_counter(&packet),
                    None
                ));
            }
            for version in [0u8, 1, 5, 7, 15] {
                let mut packet = [0xffu8; 40];
                packet[0] = version << 4;
                assert!(matches!(
                    super::super::tun_ingress_header_length_counter(&packet),
                    None
                ));
            }
        }

        #[test]
        fn tun_ingress_ipv6_declared_length_adds_base_without_u16_wrap_or_jumbo_guess() {
            let mut packet = [0u8; 48];
            packet[0] = 0x60;
            for payload in [0u16, 1, 7, 8] {
                packet[4..6].copy_from_slice(&payload.to_be_bytes());
                assert!(matches!(
                    super::super::tun_ingress_header_length_counter(&packet),
                    None
                ));
            }
            packet[4..6].copy_from_slice(&9u16.to_be_bytes());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&packet),
                Some(super::super::Counter::TunIngressIpv6DeclaredLengthExceedsReadSlice)
            ));
            packet[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&packet),
                Some(super::super::Counter::TunIngressIpv6DeclaredLengthExceedsReadSlice)
            ));

            // Zero-filled synthetic storage; declared length is 65535 + 40 in usize,
            // not u16 arithmetic. Equality and one-byte-short remain distinct.
            let mut maximum = vec![0u8; usize::from(u16::MAX) + 40];
            maximum[0] = 0x60;
            maximum[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&maximum),
                None
            ));
            maximum.truncate(maximum.len() - 1);
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&maximum),
                Some(super::super::Counter::TunIngressIpv6DeclaredLengthExceedsReadSlice)
            ));
            // payload_length = 0 does not inspect or infer a Jumbo Payload option.
            maximum[4..6].copy_from_slice(&0u16.to_be_bytes());
            assert!(matches!(
                super::super::tun_ingress_header_length_counter(&maximum),
                None
            ));
        }
    }
}
