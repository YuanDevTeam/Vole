// Copyright (c) 2012, 2015 The Chromium Authors. All rights reserved.
// Portions adapted from Google's CubicBytes and HybridSlowStart.
// BSD-3-Clause; see LICENSE.chromium and README.md in this directory.
// Vole's packet-feedback adapter is independently written.

use std::{
    any::Any,
    sync::Arc,
    time::{Duration, Instant},
};

use quinn::congestion::{
    Controller, ControllerFactory, ControllerMetrics, FeedbackBatch, PacingPolicy, PacketFeedback,
    PacketInfo,
};
use quinn_proto::RttEstimator;

const INITIAL_PACKETS: u64 = 32;
const MAX_PACKETS: u64 = 20_000;
const CUBIC_MSS: u64 = 1280;

/// The two loss-based algorithms share the reference consumer's 32-packet
/// initial window; its `cwnd` and BBR profile do not configure these modes.
#[derive(Debug)]
pub struct LossConfigFactory {
    reno: bool,
}

impl LossConfigFactory {
    pub fn new(reno: bool) -> Self {
        Self { reno }
    }
}

impl ControllerFactory for LossConfigFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(LossController::new(self.reno, current_mtu))
    }
}

#[derive(Clone, Default)]
struct CubicCurve {
    epoch: Option<Instant>,
    last_maximum: u64,
    tcp_window: u64,
    origin: u64,
    origin_time: u64,
}

impl CubicCurve {
    fn lost(&mut self, window: u64) -> u64 {
        self.last_maximum = if window.saturating_add(CUBIC_MSS) < self.last_maximum {
            (0.85_f32 * window as f32) as u64
        } else {
            window
        };
        self.epoch = None;
        (0.7_f32 * window as f32) as u64
    }

    fn acknowledged(&mut self, now: Instant, bytes: u64, window: u64, min_rtt: Duration) -> u64 {
        let epoch = *self.epoch.get_or_insert_with(|| {
            self.tcp_window = window;
            if self.last_maximum <= window {
                self.origin = window;
                self.origin_time = 0;
            } else {
                self.origin = self.last_maximum;
                let factor = (1_u64 << 40) / 410 / CUBIC_MSS;
                self.origin_time =
                    (factor as f64 * (self.last_maximum - window) as f64).cbrt() as u64;
            }
            now
        });
        // Integer arithmetic follows the bytes-mode cubic curve's 2^10 time
        // scale. Saturation protects long idle periods without retaining them.
        let elapsed = ((now
            .saturating_duration_since(epoch)
            .saturating_add(min_rtt)
            .as_micros()
            .saturating_mul(1024))
            / 1_000_000)
            .min(u128::from(u64::MAX)) as u64;
        let distance = u128::from(elapsed.abs_diff(self.origin_time));
        let delta = (distance
            .saturating_pow(3)
            .saturating_mul(410)
            .saturating_mul(u128::from(CUBIC_MSS))
            >> 40)
            .min(u128::from(u64::MAX)) as u64;
        let target = if elapsed > self.origin_time {
            self.origin.saturating_add(delta)
        } else {
            self.origin.saturating_sub(delta)
        };
        let target = target.min(window.saturating_add(bytes / 2));
        let alpha = 3.0_f32 * (1.0 - 0.7_f32) / (1.0 + 0.7_f32);
        let increment =
            (bytes as f32 * alpha * CUBIC_MSS as f32 / self.tcp_window.max(1) as f32) as u64;
        self.tcp_window = self.tcp_window.saturating_add(increment);
        target.max(self.tcp_window)
    }
}

#[derive(Clone, Default)]
struct HybridSlowStart {
    round_end: Option<u64>,
    samples: u32,
    round_min: Option<Duration>,
    found: bool,
}

impl HybridSlowStart {
    fn sample(&mut self, latest: Duration, minimum: Duration, last_sent: u64, window: u64) -> bool {
        if self.round_end.is_none() {
            self.round_end = Some(last_sent);
            self.samples = 0;
            self.round_min = None;
        }
        if self.found {
            return true;
        }
        self.samples = self.samples.saturating_add(1);
        if self.samples <= 8 {
            self.round_min = Some(
                self.round_min
                    .map_or(latest, |previous| previous.min(latest)),
            );
        }
        if self.samples == 8 {
            let threshold =
                (minimum / 8).clamp(Duration::from_millis(4), Duration::from_millis(16));
            self.found = self
                .round_min
                .is_some_and(|sample| sample > minimum.saturating_add(threshold));
        }
        window >= 16 && self.found
    }

    fn acknowledged(&mut self, sample_id: u64) {
        // The frozen reference ends the receive round strictly past its last
        // sent ID. IDs are unique across QUIC packet-number spaces here.
        if self.round_end.is_some_and(|end| sample_id > end) {
            self.round_end = None;
        }
    }
}

#[derive(Clone)]
struct LossController {
    reno: bool,
    mtu: u64,
    initial_window: u64,
    window: u64,
    ssthresh: u64,
    largest_sent: u64,
    largest_acked: u64,
    recovery_boundary: Option<u64>,
    reno_acks: u64,
    curve: CubicCurve,
    slow_start: HybridSlowStart,
    pending_acks: u64,
    pending_bytes: u64,
    pending_loss: Option<u64>,
    smoothed_rtt: Option<Duration>,
    minimum_rtt: Duration,
}

impl LossController {
    fn new(reno: bool, mtu: u16) -> Self {
        let initial_window = INITIAL_PACKETS * u64::from(mtu);
        Self {
            reno,
            mtu: u64::from(mtu),
            initial_window,
            window: initial_window,
            ssthresh: u64::MAX,
            largest_sent: 0,
            largest_acked: 0,
            recovery_boundary: None,
            reno_acks: 0,
            curve: CubicCurve::default(),
            slow_start: HybridSlowStart::default(),
            pending_acks: 0,
            pending_bytes: 0,
            pending_loss: None,
            smoothed_rtt: None,
            minimum_rtt: Duration::from_millis(100),
        }
    }

    fn in_slow_start(&self) -> bool {
        self.window < self.ssthresh
    }

    fn window_limited(&self, in_flight: u64) -> bool {
        in_flight >= self.window
            || (self.in_slow_start() && in_flight > self.window / 2)
            || self.window.saturating_sub(in_flight) <= 3 * self.mtu
    }

    fn grow(&mut self, now: Instant, count: u64, bytes: u64, in_flight: u64) {
        if count == 0 {
            return;
        }
        if !self.window_limited(in_flight) {
            self.curve.epoch = None;
            return;
        }
        let maximum = MAX_PACKETS * self.mtu;
        if self.window >= maximum {
            return;
        }
        if self.in_slow_start() {
            // The reference reevaluates application limitation after every
            // packet ACK as the window grows, even within one ACK frame.
            for _ in 0..count {
                if self.window >= maximum || !self.window_limited(in_flight) {
                    break;
                }
                self.window = self.window.saturating_add(self.mtu).min(maximum);
            }
        } else if self.reno {
            self.reno_acks = self.reno_acks.saturating_add(count);
            // A batch may contain several windows; consume each window's ACK
            // count with that window's size, retaining the partial remainder.
            while self.reno_acks >= (self.window / self.mtu).max(1) && self.window < maximum {
                self.reno_acks -= (self.window / self.mtu).max(1);
                self.window = self.window.saturating_add(self.mtu).min(maximum);
            }
        } else {
            self.window = self
                .curve
                .acknowledged(now, bytes, self.window, self.minimum_rtt)
                .min(maximum);
        }
    }

    fn reduce(&mut self, packet: u64) -> bool {
        if self
            .recovery_boundary
            .is_some_and(|boundary| packet <= boundary)
        {
            return false;
        }
        self.window = if self.reno {
            (self.window as f64 * 0.7) as u64
        } else {
            self.curve.lost(self.window)
        };
        self.window = self.window.max(2 * self.mtu);
        self.ssthresh = self.window;
        self.recovery_boundary = Some(self.largest_sent);
        self.reno_acks = 0;
        true
    }

    fn complete_feedback(
        &mut self,
        now: Instant,
        batch: FeedbackBatch,
        smoothed: Duration,
        latest: Duration,
        minimum: Duration,
    ) {
        // Establish recovery before this batch's ACKs can grow its window.
        let mut cutback = self
            .pending_loss
            .take()
            .is_some_and(|packet| self.reduce(packet));
        if batch.ecn_congestion {
            if let Some(packet) = batch.largest_acked_sample_id {
                cutback |= self.reduce(packet);
            }
        }
        if cutback {
            self.pending_acks = 0;
            self.pending_bytes = 0;
        }
        self.minimum_rtt = minimum;
        if batch.rtt_updated {
            self.smoothed_rtt = Some(smoothed);
            if self.in_slow_start()
                && self.slow_start.sample(
                    latest,
                    minimum,
                    self.largest_sent,
                    self.window / self.mtu,
                )
            {
                self.ssthresh = self.window;
            }
        }
        self.grow(
            now,
            self.pending_acks,
            self.pending_bytes,
            batch.prior_in_flight,
        );
        if let Some(packet) = batch.largest_acked_sample_id {
            self.slow_start.acknowledged(packet);
        }
        self.pending_acks = 0;
        self.pending_bytes = 0;
    }
}

impl Controller for LossController {
    fn packet_feedback_enabled(&self) -> bool {
        true
    }

    fn on_packet_sent(&mut self, packet: PacketInfo, _prior_in_flight: u64, _app_limited: bool) {
        if packet.congestion_bytes != 0 {
            self.largest_sent = self.largest_sent.max(packet.sample_id);
        }
    }

    fn on_packet_feedback(&mut self, _now: Instant, packet: PacketInfo, feedback: PacketFeedback) {
        if packet.congestion_bytes == 0 {
            return;
        }
        match feedback {
            PacketFeedback::Acked => {
                self.largest_acked = self.largest_acked.max(packet.sample_id);
                if self
                    .recovery_boundary
                    .is_none_or(|boundary| self.largest_acked > boundary)
                {
                    self.pending_acks = self.pending_acks.saturating_add(1);
                    self.pending_bytes = self.pending_bytes.saturating_add(packet.congestion_bytes);
                }
            }
            PacketFeedback::Lost => {
                self.pending_loss = Some(
                    self.pending_loss
                        .map_or(packet.sample_id, |previous| previous.max(packet.sample_id)),
                );
            }
            PacketFeedback::Discarded => {}
        }
    }

    fn on_feedback_end(&mut self, now: Instant, batch: FeedbackBatch, rtt: &RttEstimator) {
        self.complete_feedback(now, batch, rtt.get(), rtt.latest(), rtt.min());
    }

    // New packet feedback includes every real ACK/loss; legacy aggregate
    // callbacks remain no-ops to avoid applying an event twice.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _persistent: bool,
        _lost: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let was_minimum = self.window == self.mtu * 2;
        self.mtu = u64::from(new_mtu);
        if was_minimum {
            self.window = self.mtu * 2;
        }
    }

    fn pacing_policy(&self) -> Option<PacingPolicy> {
        let rate = self.smoothed_rtt.map_or(u64::MAX, |rtt| {
            (u128::from(self.window)
                .saturating_mul(1_000_000_000)
                .saturating_mul(5)
                / rtt.as_nanos().max(1)
                / 4)
            .min(u128::from(u64::MAX)) as u64
        });
        Some(PacingPolicy {
            rate_bytes_per_second: rate,
            burst_bytes: ((u128::from(rate) * 2 / 1000).min(u128::from(u64::MAX)) as u64)
                .max(10 * self.mtu),
            min_delay: Duration::from_millis(1),
        })
    }

    fn window(&self) -> u64 {
        self.window
    }
    fn initial_window(&self) -> u64 {
        self.initial_window
    }
    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window;
        metrics.ssthresh = Some(self.ssthresh);
        metrics.pacing_rate = self
            .pacing_policy()
            .map(|policy| policy.rate_bytes_per_second.saturating_mul(8));
        metrics
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        let mut cloned = self.clone();
        // NAT rebinding retains the congestion model but starts with no
        // tracked packets; feedback already assigned to the old path stays there.
        cloned.pending_acks = 0;
        cloned.pending_bytes = 0;
        cloned.pending_loss = None;
        Box::new(cloned)
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::congestion::PacketSpace;

    fn packet(now: Instant, id: u64) -> PacketInfo {
        PacketInfo {
            sample_id: id,
            packet_number: id,
            space: PacketSpace::Data,
            path_generation: 0,
            time_sent: now,
            congestion_bytes: 1200,
            ack_eliciting: true,
        }
    }

    #[test]
    fn quic_meta_loss_windows_recovery_and_pacing_are_consumed() {
        let now = Instant::now();
        for reno in [false, true] {
            let mut controller = LossController::new(reno, 1200);
            assert_eq!(controller.initial_window(), 32 * 1200);
            controller.on_packet_sent(packet(now, 1), 0, false);
            controller.grow(now, 1, 1200, 32 * 1200);
            assert_eq!(controller.window(), 33 * 1200);
            controller.smoothed_rtt = Some(Duration::from_millis(100));
            let policy = controller.pacing_policy().unwrap();
            assert_eq!(policy.rate_bytes_per_second, 495_000);
            assert_eq!(policy.burst_bytes, 12_000);
            assert_eq!(policy.min_delay, Duration::from_millis(1));
            controller.reduce(1);
            assert_eq!(controller.window(), (39_600_f64 * 0.7) as u64);
            let reduced = controller.window();
            controller.reduce(1);
            assert_eq!(controller.window(), reduced);
            controller.on_packet_feedback(now, packet(now, 1), PacketFeedback::Acked);
            assert_eq!(controller.pending_acks, 0);
            controller.on_packet_sent(packet(now, 2), reduced, false);
            controller.on_packet_feedback(now, packet(now, 2), PacketFeedback::Acked);
            assert_eq!(controller.pending_acks, 1);
            controller.on_packet_feedback(now, packet(now, 3), PacketFeedback::Discarded);
            assert_eq!(controller.pending_loss, None);
            controller.on_packet_feedback(now, packet(now, 4), PacketFeedback::Lost);
            let cloned = controller
                .clone_box()
                .into_any()
                .downcast::<LossController>()
                .unwrap();
            assert_eq!(cloned.window, controller.window);
            assert_eq!(cloned.pending_acks, 0);
            assert_eq!(cloned.pending_bytes, 0);
            assert_eq!(cloned.pending_loss, None);
            assert_eq!(controller.pending_acks, 1);
            assert_eq!(controller.pending_loss, Some(4));
        }
    }

    #[test]
    fn quic_meta_cubic_curve_and_hybrid_rtt_exit_do_not_store_packets() {
        let now = Instant::now();
        let mut curve = CubicCurve::default();
        assert_eq!(curve.lost(32_000), 22_400);
        let next = curve.acknowledged(now, 1280, 22_400, Duration::from_millis(100));
        assert!(next > 22_400 && next <= 23_040);
        let mut start = HybridSlowStart::default();
        for i in 0..8 {
            assert_eq!(
                start.sample(
                    Duration::from_millis(130),
                    Duration::from_millis(100),
                    32,
                    32
                ),
                i == 7
            );
        }
        // The controller stores only aggregate counters, never a packet span.
        assert!(std::mem::size_of::<LossController>() < 512);
    }

    #[test]
    fn quic_meta_loss_batch_recovers_from_sample_zero_and_ignores_old_ecn() {
        let now = Instant::now();
        let rtt = Duration::from_millis(100);
        for reno in [false, true] {
            let mut controller = LossController::new(reno, 1200);
            controller.on_packet_sent(packet(now, 0), 0, false);
            controller.on_packet_feedback(now, packet(now, 0), PacketFeedback::Acked);
            controller.complete_feedback(
                now,
                FeedbackBatch {
                    prior_in_flight: 32 * 1200,
                    acked_bytes: 1200,
                    largest_acked_sample_id: Some(0),
                    ..Default::default()
                },
                rtt,
                rtt,
                rtt,
            );
            assert_eq!(controller.window(), 33 * 1200);
            for id in 1..=30 {
                controller.on_packet_sent(packet(now, id), 0, false);
            }
            for id in 1..=16 {
                controller.on_packet_feedback(now, packet(now, id), PacketFeedback::Acked);
            }
            controller.on_packet_feedback(now, packet(now, 17), PacketFeedback::Lost);
            controller.complete_feedback(
                now,
                FeedbackBatch {
                    prior_in_flight: 33 * 1200,
                    acked_bytes: 16 * 1200,
                    lost_bytes: 1200,
                    largest_acked_sample_id: Some(16),
                    ..Default::default()
                },
                rtt,
                rtt,
                rtt,
            );
            assert_eq!(controller.window(), 27_720);
            controller.on_packet_sent(packet(now, 31), 0, false);
            controller.complete_feedback(
                now,
                FeedbackBatch {
                    prior_in_flight: 1200,
                    ecn_congestion: true,
                    largest_acked_sample_id: Some(16),
                    ..Default::default()
                },
                rtt,
                rtt,
                rtt,
            );
            assert_eq!(controller.window(), 27_720);

            let mut first_loss = LossController::new(reno, 1200);
            first_loss.on_packet_sent(packet(now, 0), 0, false);
            first_loss.on_packet_feedback(now, packet(now, 0), PacketFeedback::Lost);
            first_loss.complete_feedback(
                now,
                FeedbackBatch {
                    prior_in_flight: 1200,
                    lost_bytes: 1200,
                    ..Default::default()
                },
                rtt,
                rtt,
                rtt,
            );
            assert_eq!(first_loss.window(), 26_880);

            let mut half_window = LossController::new(reno, 1200);
            half_window.grow(now, 17, 17 * 1200, 17 * 1200);
            assert_eq!(half_window.window(), 34 * 1200);
        }
    }
}
