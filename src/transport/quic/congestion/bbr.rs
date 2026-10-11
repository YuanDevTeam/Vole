// Copyright 2016 The Chromium Authors. All rights reserved.
// Derived from Google QUIC BbrSender; BSD-3-Clause, see LICENSE.chromium.
// The separately identified Meta consumer adaptations are described in README.md.

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

use super::{
    filter::MaxFilter,
    sampler::{Sampler, SendState, delivered, rate},
};

const GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BbrVersion {
    V1,
    V2,
}

#[derive(Clone, Copy, Debug)]
struct Parameters {
    high_gain: f64,
    high_cwnd_gain: f64,
    cwnd_gain: f64,
    startup_rounds: u64,
    drain_to_target: bool,
    detect_overshooting: bool,
    loss_multiplier: u64,
    startup_ack_aggregation: bool,
    expire_startup_ack_aggregation: bool,
    overestimate_avoidance: bool,
    reduce_extra_on_bandwidth_increase: bool,
}

impl Parameters {
    fn new(version: BbrVersion, profile: &str) -> Self {
        let mut value = Self {
            high_gain: 2.885,
            high_cwnd_gain: 2.0,
            cwnd_gain: 2.0,
            startup_rounds: 3,
            drain_to_target: false,
            detect_overshooting: false,
            loss_multiplier: 2,
            startup_ack_aggregation: false,
            expire_startup_ack_aggregation: false,
            overestimate_avoidance: false,
            reduce_extra_on_bandwidth_increase: false,
        };
        if version == BbrVersion::V1 {
            value.high_gain = 2.77;
            value.high_cwnd_gain = 2.77;
            return value;
        }
        match profile {
            "conservative" => {
                value.high_gain = 2.25;
                value.high_cwnd_gain = 1.75;
                value.cwnd_gain = 1.75;
                value.startup_rounds = 2;
                value.drain_to_target = true;
                value.detect_overshooting = true;
                value.loss_multiplier = 1;
                value.overestimate_avoidance = true;
                value.reduce_extra_on_bandwidth_increase = true;
            }
            "aggressive" => {
                value.high_gain = 3.0;
                value.high_cwnd_gain = 2.25;
                value.cwnd_gain = 2.5;
                value.startup_rounds = 4;
                value.startup_ack_aggregation = true;
                value.expire_startup_ack_aggregation = true;
            }
            _ => {}
        }
        value
    }
}

#[derive(Clone, Debug)]
pub struct BbrConfigFactory {
    version: BbrVersion,
    initial_packets: i64,
    parameters: Parameters,
}

impl BbrConfigFactory {
    pub fn new(version: BbrVersion, cwnd: i64, profile: &str) -> Self {
        Self {
            version,
            initial_packets: if cwnd == 0 { 32 } else { cwnd },
            parameters: Parameters::new(version, profile),
        }
    }
}

impl ControllerFactory for BbrConfigFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr::new(&self, now, current_mtu))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Startup,
    Drain,
    ProbeBandwidth,
    ProbeRtt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Recovery {
    None,
    Conservation,
    Growth,
}

#[derive(Clone, Debug)]
struct Bbr {
    version: BbrVersion,
    parameters: Parameters,
    sampler: Sampler,
    bandwidth: MaxFilter<u64>,
    mode: Mode,
    recovery: Recovery,
    mtu: u64,
    initial_window: i64,
    congestion_window: i64,
    max_window: i64,
    recovery_window: i64,
    in_flight: u64,
    last_sent: Option<u64>,
    round_end: Option<u64>,
    round: u64,
    recovery_end: Option<u64>,
    loss_events_in_round: u64,
    lost_in_round: u64,
    full_bandwidth: bool,
    rounds_without_growth: u64,
    bandwidth_last_round: u64,
    last_sample_app_limited: bool,
    has_non_app_limited_sample: bool,
    min_rtt: Option<Duration>,
    min_rtt_time: Option<Instant>,
    fallback_rtt: Duration,
    smoothed_rtt: Option<Duration>,
    pacing_rate: u64,
    pacing_gain: f64,
    congestion_gain: f64,
    cycle: usize,
    cycle_start: Instant,
    exiting_quiescence: bool,
    exit_probe_rtt: Option<Instant>,
    probe_rtt_round_passed: bool,
    overshooting_losses: u64,
    min_pacing_window: i64,
    // Feedback is consumed as a single event: losses first, ACKs in send order.
    // Capacity follows actual retired packets, never their numerical span.
    feedback: Vec<(PacketInfo, PacketFeedback)>,
}

impl Bbr {
    fn new(config: &BbrConfigFactory, now: Instant, mtu: u16) -> Self {
        let parameters = config.parameters;
        let legacy = config.version == BbrVersion::V1;
        // The v1 consumer constructs byte windows with a fixed 1280-byte MSS.
        let initial_window =
            config
                .initial_packets
                .wrapping_mul(if legacy { 1280 } else { i64::from(mtu) });
        Self {
            version: config.version,
            parameters,
            sampler: Sampler::new(
                legacy,
                parameters.overestimate_avoidance,
                parameters.reduce_extra_on_bandwidth_increase,
            ),
            bandwidth: MaxFilter::new(10, 0),
            mode: Mode::Startup,
            recovery: Recovery::None,
            mtu: u64::from(mtu),
            initial_window,
            congestion_window: initial_window,
            max_window: i64::from(mtu) * if legacy { 10_000 } else { 20_000 },
            recovery_window: if legacy {
                1280 * 10_000
            } else {
                i64::from(mtu) * 20_000
            },
            in_flight: 0,
            last_sent: None,
            round_end: None,
            round: 0,
            recovery_end: None,
            loss_events_in_round: 0,
            lost_in_round: 0,
            full_bandwidth: false,
            rounds_without_growth: 0,
            bandwidth_last_round: 0,
            last_sample_app_limited: false,
            has_non_app_limited_sample: false,
            min_rtt: None,
            min_rtt_time: None,
            fallback_rtt: Duration::from_millis(100),
            smoothed_rtt: None,
            pacing_rate: 0,
            pacing_gain: if legacy { 1.0 } else { parameters.high_gain },
            congestion_gain: if legacy {
                1.0
            } else {
                parameters.high_cwnd_gain
            },
            cycle: 0,
            cycle_start: now,
            exiting_quiescence: false,
            exit_probe_rtt: None,
            probe_rtt_round_passed: false,
            overshooting_losses: 0,
            min_pacing_window: initial_window,
            feedback: Vec::new(),
        }
    }

    fn minimum_window(&self) -> i64 {
        if self.version == BbrVersion::V1 {
            // Frozen Meta v1 consumer: its initial_window is already in bytes.
            (self.mtu as i64).wrapping_mul(self.initial_window)
        } else {
            4 * self.mtu as i64
        }
    }

    fn signed_window(&self) -> i64 {
        if self.mode == Mode::ProbeRtt {
            return self.minimum_window();
        }
        if self.recovery != Recovery::None {
            self.congestion_window.min(self.recovery_window)
        } else {
            self.congestion_window
        }
    }

    fn min_rtt(&self) -> Duration {
        self.min_rtt.unwrap_or(self.fallback_rtt)
    }

    fn estimate(&self) -> u64 {
        if self.version == BbrVersion::V1 {
            let Some(rtt) = self.smoothed_rtt.filter(|rtt| !rtt.is_zero()) else {
                return u64::MAX;
            };
            // Meta's public estimator returns bits/s using signed byte-count
            // conversion and the Go multiplication/division order.
            ((self.signed_window() as u64).wrapping_mul(1_000_000_000)
                / (rtt.as_nanos() as u64).max(1))
            .wrapping_mul(8)
        } else {
            self.bandwidth.best()
        }
    }

    fn target_window(&self, gain: f64) -> i64 {
        let bdp = if self.version == BbrVersion::V1 {
            (self.min_rtt().as_nanos() as i64).wrapping_mul(self.estimate() as i64)
        } else {
            delivered(self.estimate(), self.min_rtt()) as i64
        };
        let mut target = (gain * bdp as f64) as i64;
        if target == 0 {
            target = (gain * self.initial_window as f64) as i64;
        }
        target.max(self.minimum_window())
    }

    fn update_round(&mut self, acked: u64) -> bool {
        if self.round_end.is_none_or(|end| acked > end) {
            self.round = self.round.saturating_add(1);
            self.round_end = self.last_sent;
            return true;
        }
        false
    }

    fn update_recovery(&mut self, acked: u64, has_loss: bool, round_start: bool) {
        if self.version == BbrVersion::V2 && !self.full_bandwidth {
            return;
        }
        if has_loss {
            self.recovery_end = self.last_sent;
        }
        match self.recovery {
            Recovery::None if has_loss => {
                self.recovery = Recovery::Conservation;
                self.recovery_window = 0;
                self.round_end = self.last_sent;
            }
            Recovery::Conservation | Recovery::Growth => {
                if round_start {
                    self.recovery = Recovery::Growth;
                }
                if !has_loss && self.recovery_end.is_some_and(|end| acked > end) {
                    self.recovery = Recovery::None;
                }
            }
            _ => {}
        }
    }

    fn update_min_rtt(&mut self, now: Instant, sample: Duration) -> bool {
        let expired = self
            .min_rtt_time
            .is_some_and(|time| now.saturating_duration_since(time) > MIN_RTT_EXPIRY);
        if expired || self.min_rtt.is_none_or(|minimum| sample < minimum) {
            self.min_rtt = Some(sample);
            self.min_rtt_time = Some(now);
        }
        expired
    }

    fn enter_startup(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.parameters.high_gain;
        self.congestion_gain = self.parameters.high_cwnd_gain;
    }

    fn enter_probe_bandwidth(&mut self, now: Instant) {
        self.mode = Mode::ProbeBandwidth;
        self.congestion_gain = self.parameters.cwnd_gain;
        let offset = rand::random::<u64>() % 7;
        self.cycle = if offset >= 1 { offset as usize + 1 } else { 0 };
        self.cycle_start = now;
        self.pacing_gain = GAIN_CYCLE[self.cycle];
    }

    fn advance_cycle(&mut self, now: Instant, prior_in_flight: u64, has_losses: bool) {
        let mut advance = now.saturating_duration_since(self.cycle_start) > self.min_rtt();
        if self.pacing_gain > 1.0
            && !has_losses
            && (prior_in_flight as i64) < self.target_window(self.pacing_gain)
        {
            advance = false;
        }
        if self.pacing_gain < 1.0 && self.in_flight as i64 <= self.target_window(1.0) {
            advance = true;
        }
        if !advance {
            return;
        }
        self.cycle = (self.cycle + 1) % GAIN_CYCLE.len();
        self.cycle_start = now;
        if self.parameters.drain_to_target
            && self.pacing_gain < 1.0
            && GAIN_CYCLE[self.cycle] == 1.0
            && self.in_flight as i64 > self.target_window(1.0)
        {
            return;
        }
        self.pacing_gain = GAIN_CYCLE[self.cycle];
    }

    fn check_full_bandwidth(&mut self, state: Option<SendState>) {
        if self.last_sample_app_limited {
            return;
        }
        if self.estimate() as f64 >= self.bandwidth_last_round as f64 * 1.25 {
            self.bandwidth_last_round = self.estimate();
            self.rounds_without_growth = 0;
            if self.parameters.expire_startup_ack_aggregation {
                self.sampler.reset_ack_height(self.round);
            }
            return;
        }
        self.rounds_without_growth = self.rounds_without_growth.saturating_add(1);
        let loss_exit = self.version == BbrVersion::V2
            && self.loss_events_in_round >= 8
            && state.is_some_and(|state| {
                state.in_flight > 0 && self.lost_in_round as f64 > state.in_flight as f64 * 0.02
            });
        if self.rounds_without_growth >= self.parameters.startup_rounds || loss_exit {
            self.full_bandwidth = true;
        }
    }

    fn startup_or_drain(&mut self, now: Instant) {
        if self.mode == Mode::Startup && self.full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = 1.0 / self.parameters.high_gain;
            self.congestion_gain = self.parameters.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && self.in_flight as i64 <= self.target_window(1.0) {
            self.enter_probe_bandwidth(now);
        }
    }

    fn probe_rtt(&mut self, now: Instant, round_start: bool, expired: bool) {
        if expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            self.exit_probe_rtt = None;
        }
        if self.mode == Mode::ProbeRtt {
            self.sampler.on_app_limited();
            match self.exit_probe_rtt {
                None if (self.in_flight as i64)
                    < self.minimum_window().wrapping_add(self.mtu as i64) =>
                {
                    self.exit_probe_rtt = Some(now + PROBE_RTT_TIME);
                    self.probe_rtt_round_passed = false;
                }
                Some(exit) => {
                    self.probe_rtt_round_passed |= round_start;
                    if now >= exit && self.probe_rtt_round_passed {
                        self.min_rtt_time = Some(now);
                        if self.full_bandwidth {
                            self.enter_probe_bandwidth(now);
                        } else {
                            self.enter_startup();
                        }
                    }
                }
                _ => {}
            }
        }
        self.exiting_quiescence = false;
    }

    fn calculate_pacing(&mut self, lost: u64, native_min_rtt: Option<Duration>) {
        let estimate = self.estimate();
        if estimate == 0 {
            return;
        }
        let target = (self.pacing_gain * estimate as f64) as u64;
        if self.full_bandwidth {
            self.pacing_rate = target;
            return;
        }
        if self.pacing_rate == 0 {
            if let Some(rtt) = native_min_rtt.filter(|rtt| !rtt.is_zero()) {
                self.pacing_rate = rate(self.initial_window.max(0) as u64, rtt);
                if self.version == BbrVersion::V1 {
                    self.pacing_rate = self.pacing_rate.wrapping_mul(8);
                }
                return;
            }
        }
        if self.parameters.detect_overshooting {
            self.overshooting_losses = self.overshooting_losses.saturating_add(lost);
            if self.pacing_rate > target
                && self.overshooting_losses > 0
                && (self.has_non_app_limited_sample
                    || self
                        .overshooting_losses
                        .saturating_mul(self.parameters.loss_multiplier)
                        as i64
                        > self.initial_window)
            {
                self.pacing_rate =
                    target.max(rate(self.min_pacing_window.max(0) as u64, self.min_rtt()));
                self.overshooting_losses = 0;
                self.parameters.detect_overshooting = false;
            }
        }
        self.pacing_rate = self.pacing_rate.max(target);
    }

    fn calculate_window(&mut self, acked: u64, extra: u64) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target = self.target_window(self.congestion_gain);
        if self.full_bandwidth {
            target = target.wrapping_add(self.sampler.max_ack_height());
        } else if self.parameters.startup_ack_aggregation {
            target = target.wrapping_add(extra as i64);
        }
        if self.full_bandwidth {
            self.congestion_window = target.min(self.congestion_window.wrapping_add(acked as i64));
        } else if self.congestion_window < target
            || (self.sampler.acked as i64) < self.initial_window
        {
            self.congestion_window = self.congestion_window.wrapping_add(acked as i64);
        }
        // Deliberately preserve this order; v1's derived minimum can exceed max.
        self.congestion_window = self
            .congestion_window
            .max(self.minimum_window())
            .min(self.max_window);
    }

    fn calculate_recovery_window(&mut self, acked: u64, lost: u64) {
        if self.recovery == Recovery::None {
            return;
        }
        let response = (self.in_flight as i64).wrapping_add(acked as i64);
        if self.recovery_window == 0 {
            self.recovery_window = response.max(self.minimum_window());
            return;
        }
        self.recovery_window = if self.recovery_window >= lost as i64 {
            self.recovery_window.wrapping_sub(lost as i64)
        } else {
            self.mtu as i64
        };
        if self.recovery == Recovery::Growth {
            self.recovery_window = self.recovery_window.wrapping_add(acked as i64);
        }
        self.recovery_window = self
            .recovery_window
            .max(response)
            .max(self.minimum_window());
    }

    fn finish_feedback(
        &mut self,
        now: Instant,
        batch: FeedbackBatch,
        native_min: Option<Duration>,
        smoothed: Option<Duration>,
    ) {
        self.in_flight = batch.in_flight;
        if let Some(smoothed) = smoothed {
            self.smoothed_rtt = Some(smoothed);
        }
        if self.version == BbrVersion::V2 {
            if let Some(minimum) = native_min.filter(|rtt| !rtt.is_zero()) {
                self.fallback_rtt = minimum;
            }
        }
        self.feedback.sort_unstable_by_key(|(packet, kind)| {
            (
                if *kind == PacketFeedback::Lost { 0 } else { 1 },
                packet.sample_id,
            )
        });
        let acked_before = self.sampler.acked;
        let lost_before = self.sampler.lost;
        let bandwidth_before = self.bandwidth.best();
        let largest_ack = self
            .feedback
            .iter()
            .filter(|(_, kind)| *kind == PacketFeedback::Acked)
            .map(|(p, _)| p.sample_id)
            .max();
        let round_start = largest_ack.is_some_and(|acked| self.update_round(acked));
        let has_loss = self
            .feedback
            .iter()
            .any(|(_, kind)| *kind == PacketFeedback::Lost);
        if self.version == BbrVersion::V2 {
            if let Some(acked) = largest_ack {
                self.update_recovery(acked, has_loss, round_start);
            }
        }
        let mut last_state = None;
        let mut last_state_id = None;
        let mut event_bandwidth = 0;
        let mut event_app_limited = false;
        let mut minimum_rtt: Option<Duration> = None;
        for (packet, kind) in &self.feedback {
            if *kind == PacketFeedback::Lost {
                if let Some(state) = self.sampler.on_lost(packet.sample_id) {
                    if last_state_id.is_none_or(|last| packet.sample_id > last) {
                        last_state = Some(state);
                        last_state_id = Some(packet.sample_id);
                    }
                }
                continue;
            }
            let sample = self.sampler.on_ack(now, packet.sample_id);
            let bandwidth = if self.version == BbrVersion::V1 {
                sample.bandwidth.wrapping_mul(8)
            } else {
                sample.bandwidth
            };
            if let Some(rtt) = sample.rtt {
                minimum_rtt = Some(minimum_rtt.map_or(rtt, |previous| previous.min(rtt)));
            }
            if self.version == BbrVersion::V1 {
                let app_limited = sample.state.is_some_and(|state| state.app_limited);
                self.last_sample_app_limited = app_limited;
                self.has_non_app_limited_sample |= !app_limited;
                if !app_limited || bandwidth > self.estimate() {
                    self.bandwidth.update(bandwidth, self.round);
                }
            }
            if let Some(state) = sample.state {
                if last_state_id.is_none_or(|last| packet.sample_id > last) {
                    last_state = Some(state);
                    last_state_id = Some(packet.sample_id);
                }
                if bandwidth > event_bandwidth {
                    event_bandwidth = bandwidth;
                    event_app_limited = state.app_limited;
                }
            }
        }
        self.feedback.clear();
        if self.version == BbrVersion::V2 {
            if let Some(state) = last_state {
                self.last_sample_app_limited = state.app_limited;
                self.has_non_app_limited_sample |= !state.app_limited;
            }
            if self.sampler.acked != acked_before
                && (!event_app_limited || event_bandwidth > self.bandwidth.best())
            {
                self.bandwidth.update(event_bandwidth, self.round);
            }
        } else if let Some(acked) = largest_ack {
            self.update_recovery(acked, has_loss, round_start);
        }
        let expired = minimum_rtt.is_some_and(|sample| self.update_min_rtt(now, sample));
        let acked = self.sampler.acked.saturating_sub(acked_before);
        let lost = self.sampler.lost.saturating_sub(lost_before);
        let aggregation_bandwidth = if self.version == BbrVersion::V1 {
            self.bandwidth.best()
        } else {
            bandwidth_before.max(event_bandwidth)
        };
        let extra = self.sampler.end_ack_event(
            now,
            aggregation_bandwidth,
            event_bandwidth > bandwidth_before,
            self.round,
            acked,
        );
        if has_loss {
            self.loss_events_in_round = self.loss_events_in_round.saturating_add(1);
            self.lost_in_round = self.lost_in_round.saturating_add(lost);
        }
        if self.mode == Mode::ProbeBandwidth {
            self.advance_cycle(now, batch.prior_in_flight, has_loss);
        }
        if round_start && !self.full_bandwidth {
            self.check_full_bandwidth(last_state);
        }
        self.startup_or_drain(now);
        self.probe_rtt(now, round_start, expired);
        self.calculate_pacing(lost, native_min);
        self.calculate_window(acked, extra);
        self.calculate_recovery_window(acked, lost);
        if self.version == BbrVersion::V2 && round_start {
            self.loss_events_in_round = 0;
            self.lost_in_round = 0;
        }
        if batch.app_limited && (batch.in_flight as i64) < self.signed_window() {
            self.sampler.on_app_limited();
        }
    }

    fn policy(&self) -> PacingPolicy {
        let min_delay = Duration::from_millis(1);
        let bytes_per_second = if self.version == BbrVersion::V1 {
            (self.estimate() / 8).wrapping_mul(5) / 4
        } else {
            let pacing = if self.pacing_rate == 0 {
                (self.parameters.high_gain
                    * rate(self.initial_window.max(0) as u64, self.min_rtt()) as f64)
                    as u64
            } else {
                self.pacing_rate
            };
            pacing.max(65_536)
        }
        .max(1);
        let burst_interval = if self.version == BbrVersion::V1 {
            Duration::from_millis(2)
        } else {
            min_delay * 4
        };
        PacingPolicy {
            rate_bytes_per_second: bytes_per_second,
            burst_bytes: delivered(bytes_per_second, burst_interval).max(10 * self.mtu),
            min_delay,
        }
    }
}

impl Controller for Bbr {
    fn packet_feedback_enabled(&self) -> bool {
        true
    }

    fn on_packet_sent(&mut self, packet: PacketInfo, prior_in_flight: u64, app_limited: bool) {
        self.last_sent = Some(packet.sample_id);
        if prior_in_flight == 0 && self.sampler.app_limited {
            self.exiting_quiescence = true;
        }
        self.sampler.on_sent(packet, prior_in_flight);
        self.in_flight = prior_in_flight.saturating_add(packet.congestion_bytes);
        if app_limited && (self.in_flight as i64) < self.signed_window() {
            self.sampler.on_app_limited();
        }
    }

    fn on_packet_feedback(&mut self, _now: Instant, packet: PacketInfo, feedback: PacketFeedback) {
        if feedback == PacketFeedback::Discarded {
            self.sampler.on_neutered(packet.sample_id);
        } else if packet.ack_eliciting && packet.congestion_bytes > 0 {
            self.feedback.push((packet, feedback));
        }
    }

    fn on_feedback_end(&mut self, now: Instant, batch: FeedbackBatch, rtt: &RttEstimator) {
        self.finish_feedback(
            now,
            batch,
            batch.rtt_updated.then(|| rtt.min()),
            batch.rtt_updated.then(|| rtt.get()),
        );
    }

    // Real loss has already been supplied by the packet feedback contract.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _persistent: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let old = self.mtu;
        let new = u64::from(new_mtu);
        if old == new || new == 0 {
            return;
        }
        if self.version == BbrVersion::V2 {
            let scale =
                |window: i64| ((i128::from(window) * i128::from(new)) / i128::from(old)) as i64;
            self.initial_window = scale(self.initial_window);
            self.congestion_window = scale(self.congestion_window);
            self.max_window = scale(self.max_window);
            self.recovery_window = scale(self.recovery_window);
            self.min_pacing_window = scale(self.min_pacing_window);
            self.mtu = new;
        } else {
            let was_minimum = self.congestion_window == self.minimum_window();
            self.mtu = new;
            self.max_window = new as i64 * 10_000;
            if was_minimum {
                self.congestion_window = self.minimum_window();
            }
        }
    }

    fn window(&self) -> u64 {
        self.signed_window().max(0) as u64
    }
    fn initial_window(&self) -> u64 {
        self.initial_window.max(0) as u64
    }
    fn pacing_policy(&self) -> Option<PacingPolicy> {
        Some(self.policy())
    }
    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.policy().rate_bytes_per_second.saturating_mul(8));
        metrics
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        // A migrated Quinn path has no outstanding packets. Old-path feedback
        // cannot retire snapshots in this clone, so only retain model estimates.
        let mut next = self.clone();
        next.sampler.reset_for_new_path();
        next.feedback.clear();
        next.in_flight = 0;
        next.last_sent = None;
        next.round_end = None;
        next.recovery = Recovery::None;
        next.recovery_end = None;
        next.recovery_window = next.max_window;
        next.loss_events_in_round = 0;
        next.lost_in_round = 0;
        next.overshooting_losses = 0;
        next.last_sample_app_limited = true;
        next.has_non_app_limited_sample = false;
        next.exiting_quiescence = false;
        next.exit_probe_rtt = None;
        next.probe_rtt_round_passed = false;
        Box::new(next)
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::congestion::PacketSpace;

    fn sender(version: BbrVersion, profile: &str, now: Instant) -> Bbr {
        Bbr::new(&BbrConfigFactory::new(version, 0, profile), now, 1200)
    }

    fn packet(id: u64, now: Instant) -> PacketInfo {
        PacketInfo {
            sample_id: id,
            packet_number: id % 17,
            space: PacketSpace::Data,
            path_generation: 0,
            time_sent: now,
            congestion_bytes: 1200,
            ack_eliciting: true,
        }
    }

    fn feedback(
        sender: &mut Bbr,
        now: Instant,
        packets: &[(PacketInfo, PacketFeedback)],
        remaining: u64,
    ) {
        let mut batch = FeedbackBatch {
            prior_in_flight: sender.in_flight,
            in_flight: remaining,
            ..FeedbackBatch::default()
        };
        for &(packet, kind) in packets {
            sender.on_packet_feedback(now, packet, kind);
            match kind {
                PacketFeedback::Acked => {
                    batch.acked_bytes += packet.congestion_bytes;
                    batch.largest_acked_sample_id = Some(
                        batch
                            .largest_acked_sample_id
                            .map_or(packet.sample_id, |id| id.max(packet.sample_id)),
                    );
                }
                PacketFeedback::Lost => batch.lost_bytes += packet.congestion_bytes,
                PacketFeedback::Discarded => batch.discarded_bytes += packet.congestion_bytes,
            }
        }
        sender.finish_feedback(
            now,
            batch,
            Some(Duration::from_millis(100)),
            Some(Duration::from_millis(100)),
        );
    }

    #[test]
    fn sample_zero_and_abandoned_packets_have_distinct_delivery_accounting() {
        let now = Instant::now();
        let mut bbr = sender(BbrVersion::V2, "standard", now);
        let zero = packet(0, now);
        let abandoned = packet(u64::MAX / 2, now);
        bbr.on_packet_sent(zero, 0, false);
        bbr.on_packet_sent(abandoned, 1200, false);
        feedback(
            &mut bbr,
            now + Duration::from_millis(100),
            &[
                (abandoned, PacketFeedback::Discarded),
                (zero, PacketFeedback::Acked),
            ],
            0,
        );
        assert_eq!(bbr.round, 1);
        assert_eq!(bbr.round_end, Some(abandoned.sample_id));
        assert_eq!(bbr.sampler.acked, 1200);
        assert_eq!(bbr.sampler.lost, 0);
        assert_eq!(bbr.sampler.neutered, 1200);
        assert_eq!(bbr.bandwidth.best(), 12_000);
        assert_eq!(bbr.sampler.outstanding_len(), 0);
    }

    #[test]
    fn stable_delivery_reaches_full_bandwidth_at_each_profiles_round_threshold() {
        let now = Instant::now();
        for (profile, expected_rounds, expected_window) in [
            ("conservative", 4, 16_800),
            ("standard", 5, 19_200),
            ("aggressive", 6, 24_000),
        ] {
            let mut bbr = sender(BbrVersion::V2, profile, now);
            let mut rounds = 0;
            while !bbr.full_bandwidth {
                assert!(rounds < 10, "startup did not finish for {profile}");
                let sent = now + Duration::from_millis(rounds * 200);
                let packets: Vec<_> = (0..8)
                    .map(|offset| {
                        let packet = packet(rounds * 8 + offset, sent);
                        bbr.on_packet_sent(packet, offset * 1200, false);
                        (packet, PacketFeedback::Acked)
                    })
                    .collect();
                feedback(&mut bbr, sent + Duration::from_millis(100), &packets, 0);
                rounds += 1;
            }
            assert_eq!(rounds, expected_rounds, "{profile}");
            assert_eq!(bbr.mode, Mode::ProbeBandwidth);
            assert_eq!(bbr.bandwidth.best(), 96_000);
            assert_eq!(bbr.window(), expected_window, "{profile}");
            assert_eq!(bbr.sampler.outstanding_len(), 0);
        }
    }

    #[test]
    fn probe_rtt_requires_a_drained_flight_then_duration_and_an_additional_round() {
        let now = Instant::now();
        let mut bbr = sender(BbrVersion::V2, "standard", now);
        bbr.full_bandwidth = true;
        bbr.min_rtt = Some(Duration::from_millis(100));
        bbr.min_rtt_time = Some(now);
        bbr.in_flight = 10_000;
        let expired_at = now + Duration::from_secs(11);
        let expired = bbr.update_min_rtt(expired_at, Duration::from_millis(100));
        bbr.probe_rtt(expired_at, true, expired);
        assert_eq!(bbr.mode, Mode::ProbeRtt);
        assert_eq!(bbr.window(), 4800);
        assert!(bbr.exit_probe_rtt.is_none());
        bbr.in_flight = 4800;
        bbr.probe_rtt(expired_at, true, false);
        assert!(!bbr.probe_rtt_round_passed);
        bbr.probe_rtt(expired_at + Duration::from_millis(200), false, false);
        assert_eq!(bbr.mode, Mode::ProbeRtt);
        bbr.probe_rtt(expired_at + Duration::from_millis(201), true, false);
        assert_eq!(bbr.mode, Mode::ProbeBandwidth);
        assert_eq!(
            bbr.min_rtt_time,
            Some(expired_at + Duration::from_millis(201))
        );
    }

    #[test]
    fn gain_cycle_has_eight_phases_and_conservative_drain_waits_for_bdp() {
        let now = Instant::now();
        let mut bbr = sender(BbrVersion::V2, "conservative", now);
        bbr.bandwidth.update(120_000, 1);
        bbr.min_rtt = Some(Duration::from_millis(100));
        bbr.mode = Mode::ProbeBandwidth;
        bbr.cycle = 0;
        bbr.pacing_gain = GAIN_CYCLE[0];
        bbr.in_flight = 24_000;
        bbr.advance_cycle(now + Duration::from_millis(101), 24_000, false);
        assert_eq!(bbr.pacing_gain, 0.75);
        bbr.advance_cycle(now + Duration::from_millis(202), 24_000, false);
        assert_eq!(bbr.pacing_gain, 0.75);
        bbr.in_flight = 12_000;
        bbr.advance_cycle(now + Duration::from_millis(203), 12_000, false);
        assert_eq!(bbr.pacing_gain, 1.0);
        let first = bbr.cycle;
        for phase in 1..=8 {
            let time = now + Duration::from_millis(203 + phase * 101);
            bbr.in_flight = 12_000;
            bbr.advance_cycle(time, 24_000, false);
            assert_eq!(bbr.pacing_gain, GAIN_CYCLE[bbr.cycle]);
        }
        assert_eq!(bbr.cycle, first);
    }

    #[test]
    fn ack_and_loss_batch_conserves_packets_once_and_recovers_after_new_delivery() {
        let now = Instant::now();
        let mut bbr = sender(BbrVersion::V2, "standard", now);
        bbr.full_bandwidth = true;
        let first = packet(0, now);
        let second = packet(1, now);
        bbr.on_packet_sent(first, 0, false);
        bbr.on_packet_sent(second, 1200, false);
        feedback(
            &mut bbr,
            now + Duration::from_millis(100),
            &[
                (first, PacketFeedback::Acked),
                (second, PacketFeedback::Lost),
            ],
            0,
        );
        assert_eq!(bbr.recovery, Recovery::Conservation);
        assert_eq!(bbr.recovery_end, Some(1));
        assert_eq!(bbr.recovery_window, 4800);
        bbr.on_congestion_event(now, now, false, 1200);
        assert_eq!(bbr.sampler.lost, 1200);
        let third = packet(2, now + Duration::from_millis(110));
        bbr.on_packet_sent(third, 0, false);
        feedback(
            &mut bbr,
            now + Duration::from_millis(210),
            &[(third, PacketFeedback::Acked)],
            0,
        );
        assert_eq!(bbr.recovery, Recovery::None);
        assert_eq!(bbr.sampler.acked, 2400);
        assert_eq!(bbr.sampler.outstanding_len(), 0);
    }

    #[test]
    fn legacy_consumer_keeps_initial_mss_window_clamp_and_profile_noop() {
        let now = Instant::now();
        let mut bbr = sender(BbrVersion::V1, "aggressive", now);
        assert_eq!(bbr.initial_window(), 32 * 1280);
        assert_eq!(bbr.pacing_gain, 1.0);
        assert_eq!(bbr.parameters.high_gain, 2.77);
        assert!(!bbr.parameters.startup_ack_aggregation);
        bbr.calculate_window(1200, 0);
        assert_eq!(bbr.window(), 10_000 * 1200);
        bbr.mode = Mode::ProbeRtt;
        assert_eq!(bbr.window(), 32 * 1280 * 1200);
        bbr.on_mtu_update(1400);
        assert_eq!(bbr.initial_window(), 32 * 1280);
        assert_eq!(bbr.window(), 32 * 1280 * 1400);
        let negative = Bbr::new(
            &BbrConfigFactory::new(BbrVersion::V1, -1, "standard"),
            now,
            1200,
        );
        assert_eq!(negative.initial_window, -1280);
        assert_eq!(negative.window(), 0);
    }

    #[test]
    fn current_mtu_scales_windows_and_explicit_pacing_keeps_floor_and_burst() {
        let now = Instant::now();
        let mut bbr = sender(BbrVersion::V2, "standard", now);
        bbr.congestion_window = 12_000;
        bbr.recovery_window = 6000;
        bbr.on_mtu_update(1500);
        assert_eq!(bbr.initial_window(), 48_000);
        assert_eq!(bbr.window(), 15_000);
        assert_eq!(bbr.recovery_window, 7500);
        bbr.pacing_rate = 1;
        assert_eq!(bbr.policy().rate_bytes_per_second, 65_536);
        assert_eq!(bbr.policy().burst_bytes, 15_000);
        bbr.pacing_rate = 10_000_000;
        assert_eq!(bbr.policy().burst_bytes, 40_000);
        assert_eq!(bbr.policy().min_delay, Duration::from_millis(1));
    }

    #[test]
    fn migration_keeps_the_model_and_releases_old_path_packet_state() {
        let now = Instant::now();
        let mut original = sender(BbrVersion::V2, "conservative", now);
        original.bandwidth.update(120_000, 1);
        original.full_bandwidth = true;
        original.congestion_window = 24_000;
        let old = packet(0, now);
        original.on_packet_sent(old, 0, false);
        original.on_packet_feedback(now, old, PacketFeedback::Acked);
        let mut migrated = *original.clone_box().into_any().downcast::<Bbr>().unwrap();
        assert_eq!(migrated.window(), original.window());
        assert_eq!(migrated.bandwidth.best(), original.bandwidth.best());
        assert_eq!(migrated.sampler.outstanding_len(), 0);
        assert!(migrated.feedback.is_empty());
        assert!(migrated.round_end.is_none());
        let new = packet(1, now + Duration::from_millis(200));
        migrated.on_packet_sent(new, 0, false);
        feedback(
            &mut migrated,
            now + Duration::from_millis(300),
            &[(new, PacketFeedback::Acked)],
            0,
        );
        assert_eq!(migrated.sampler.acked, 1200);
        assert_eq!(migrated.sampler.lost, 0);
        assert_eq!(migrated.sampler.outstanding_len(), 0);
        assert_eq!(original.sampler.outstanding_len(), 1);
    }
}
