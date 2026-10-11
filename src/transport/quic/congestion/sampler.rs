// Copyright 2016 The Chromium Authors. All rights reserved.
// Derived from Google QUIC bandwidth_sampler.{cc,h}; BSD-3-Clause.
// See LICENSE.chromium and README.md for revisions and ownership adaptations.

use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use quinn::congestion::PacketInfo;

use super::filter::{FilterValue, MaxFilter};

pub(super) fn rate(bytes: u64, elapsed: Duration) -> u64 {
    if elapsed.is_zero() {
        return u64::MAX;
    }
    ((u128::from(bytes) * 1_000_000_000) / elapsed.as_nanos()).min(u128::from(u64::MAX)) as u64
}

pub(super) fn delivered(rate: u64, elapsed: Duration) -> u64 {
    (u128::from(rate).saturating_mul(elapsed.as_nanos()) / 1_000_000_000).min(u128::from(u64::MAX))
        as u64
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SendState {
    pub(super) app_limited: bool,
    pub(super) sent: u64,
    pub(super) acked: u64,
    pub(super) in_flight: u64,
}

#[derive(Clone, Copy, Debug)]
struct SentPacket {
    packet: PacketInfo,
    state: SendState,
    sent_at_last_ack: u64,
    last_ack_sent: Option<Instant>,
    last_ack_time: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Sample {
    pub(super) bandwidth: u64,
    pub(super) rtt: Option<Duration>,
    pub(super) state: Option<SendState>,
}

#[derive(Clone, Copy, Debug)]
struct AckPoint {
    time: Instant,
    acked: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct AckHeight {
    extra: i64,
    acked: u64,
    elapsed: Duration,
    round: u64,
}

impl FilterValue for AckHeight {
    fn height(self) -> u64 {
        self.extra as u64
    }
    fn at_least(self, other: Self) -> bool {
        self.extra >= other.extra
    }
}

#[derive(Clone, Debug)]
pub(super) struct Sampler {
    pub(super) sent: u64,
    pub(super) acked: u64,
    pub(super) lost: u64,
    pub(super) neutered: u64,
    pub(super) app_limited: bool,
    end_app_limited: Option<u64>,
    last_sent: Option<u64>,
    sent_at_last_ack: u64,
    last_ack_sent: Option<Instant>,
    last_ack_time: Option<Instant>,
    // Actual outstanding packets only; never an array indexed by packet number.
    outstanding: BTreeMap<u64, SentPacket>,
    // ACK-counter snapshots referenced by live packets. A0 intervals without a
    // reference cannot affect any outstanding sample and can be released.
    ack_references: BTreeMap<u64, usize>,
    recent_ack: [Option<AckPoint>; 2],
    a0: VecDeque<AckPoint>,
    overestimate_avoidance: bool,
    reduce_extra_on_bandwidth_increase: bool,
    legacy: bool,
    ack_height: MaxFilter<AckHeight>,
    aggregation_start: Option<Instant>,
    aggregation_bytes: u64,
}

impl Sampler {
    pub(super) fn new(legacy: bool, overestimate: bool, reduce_extra: bool) -> Self {
        Self {
            sent: 0,
            acked: 0,
            lost: 0,
            neutered: 0,
            app_limited: !legacy,
            end_app_limited: None,
            last_sent: None,
            sent_at_last_ack: 0,
            last_ack_sent: None,
            last_ack_time: None,
            outstanding: BTreeMap::new(),
            ack_references: BTreeMap::new(),
            recent_ack: [None; 2],
            a0: VecDeque::new(),
            overestimate_avoidance: overestimate,
            reduce_extra_on_bandwidth_increase: reduce_extra,
            legacy,
            ack_height: MaxFilter::new(10, AckHeight::default()),
            aggregation_start: None,
            aggregation_bytes: 0,
        }
    }

    pub(super) fn reset_for_new_path(&mut self) {
        let ack_height = self.ack_height.clone();
        *self = Self::new(
            self.legacy,
            self.overestimate_avoidance,
            self.reduce_extra_on_bandwidth_increase,
        );
        self.ack_height = ack_height;
    }

    pub(super) fn on_sent(&mut self, packet: PacketInfo, prior_in_flight: u64) {
        self.last_sent = Some(packet.sample_id);
        if !packet.ack_eliciting || packet.congestion_bytes == 0 {
            return;
        }
        if self.outstanding.contains_key(&packet.sample_id) {
            return;
        }
        self.sent = self.sent.saturating_add(packet.congestion_bytes);
        if prior_in_flight == 0 {
            self.last_ack_time = Some(packet.time_sent);
            self.last_ack_sent = Some(packet.time_sent);
            self.sent_at_last_ack = self.sent;
            if self.overestimate_avoidance {
                self.recent_ack = [None; 2];
                self.update_ack_point(packet.time_sent);
                self.a0.clear();
                self.a0.push_back(self.recent_ack[1].unwrap());
            }
        }
        if self.legacy && self.aggregation_start.is_none() {
            self.aggregation_start = Some(packet.time_sent);
        }
        if self.overestimate_avoidance {
            *self.ack_references.entry(self.acked).or_default() += 1;
        }
        self.outstanding.insert(
            packet.sample_id,
            SentPacket {
                packet,
                state: SendState {
                    app_limited: self.app_limited,
                    sent: self.sent,
                    acked: self.acked,
                    in_flight: prior_in_flight.saturating_add(packet.congestion_bytes),
                },
                sent_at_last_ack: self.sent_at_last_ack,
                last_ack_sent: self.last_ack_sent,
                last_ack_time: self.last_ack_time,
            },
        );
    }

    pub(super) fn on_app_limited(&mut self) {
        self.app_limited = true;
        self.end_app_limited = self.last_sent;
    }

    pub(super) fn on_lost(&mut self, id: u64) -> Option<SendState> {
        let packet = self.outstanding.remove(&id)?;
        self.release_ack_reference(packet.state.acked);
        self.lost = self.lost.saturating_add(packet.packet.congestion_bytes);
        Some(packet.state)
    }

    pub(super) fn on_neutered(&mut self, id: u64) {
        if let Some(packet) = self.outstanding.remove(&id) {
            self.release_ack_reference(packet.state.acked);
            self.neutered = self.neutered.saturating_add(packet.packet.congestion_bytes);
        }
    }

    fn update_ack_point(&mut self, now: Instant) {
        match self.recent_ack[1] {
            Some(recent) if now == recent.time => {}
            Some(recent) if now < recent.time => {}
            _ => self.recent_ack[0] = self.recent_ack[1],
        }
        self.recent_ack[1] = Some(AckPoint {
            time: now,
            acked: self.acked,
        });
    }

    fn choose_a0(&mut self, total_acked: u64) -> Option<AckPoint> {
        while self.a0.len() > 1 && self.a0[1].acked <= total_acked {
            self.a0.pop_front();
        }
        self.a0.front().copied()
    }

    fn release_ack_reference(&mut self, acked: u64) {
        if let Some(count) = self.ack_references.get_mut(&acked) {
            *count -= 1;
            if *count == 0 {
                self.ack_references.remove(&acked);
            }
        }
    }

    fn prune_ack_points(&mut self) {
        // The last point is needed by future sends; each earlier interval is
        // useful only if a live packet's send-time ACK counter falls inside it.
        // This is an ownership change, not a maximum-number-of-packets limit.
        let mut index = 0;
        while index + 1 < self.a0.len() {
            let start = if index == 0 { 0 } else { self.a0[index].acked };
            let end = self.a0[index + 1].acked;
            if start >= end || self.ack_references.range(start..end).next().is_none() {
                self.a0.remove(index);
            } else {
                index += 1;
            }
        }
    }

    pub(super) fn on_ack(&mut self, now: Instant, id: u64) -> Sample {
        let Some(packet) = self.outstanding.remove(&id) else {
            return Sample::default();
        };
        self.release_ack_reference(packet.state.acked);
        self.acked = self.acked.saturating_add(packet.packet.congestion_bytes);
        self.sent_at_last_ack = packet.state.sent;
        self.last_ack_sent = Some(packet.packet.time_sent);
        self.last_ack_time = Some(now);
        if self.overestimate_avoidance {
            self.update_ack_point(now);
        }
        if self.app_limited && self.end_app_limited.is_none_or(|end| id > end) {
            self.app_limited = false;
        }
        let Some(last_sent) = packet.last_ack_sent else {
            return Sample::default();
        };
        let Some(last_ack) = packet.last_ack_time else {
            return Sample::default();
        };
        let send_rate = if packet.packet.time_sent > last_sent {
            rate(
                packet.state.sent.saturating_sub(packet.sent_at_last_ack),
                packet.packet.time_sent - last_sent,
            )
        } else {
            u64::MAX
        };
        let fallback = AckPoint {
            time: last_ack,
            acked: packet.state.acked,
        };
        let a0 = if self.overestimate_avoidance {
            self.choose_a0(packet.state.acked).unwrap_or(fallback)
        } else {
            fallback
        };
        if now <= a0.time {
            return Sample::default();
        }
        Sample {
            bandwidth: send_rate.min(rate(self.acked.saturating_sub(a0.acked), now - a0.time)),
            rtt: now
                .checked_duration_since(packet.packet.time_sent)
                .filter(|rtt| !rtt.is_zero()),
            state: Some(packet.state),
        }
    }

    pub(super) fn max_ack_height(&self) -> i64 {
        self.ack_height.best().extra
    }

    pub(super) fn reset_ack_height(&mut self, round: u64) {
        self.ack_height.reset(AckHeight::default(), round);
    }

    pub(super) fn end_ack_event(
        &mut self,
        now: Instant,
        bandwidth: u64,
        is_new_max: bool,
        round: u64,
        newly_acked: u64,
    ) -> u64 {
        if newly_acked == 0 {
            self.prune_ack_points();
            return 0;
        }
        if self.reduce_extra_on_bandwidth_increase && is_new_max {
            let previous = self.ack_height.values();
            self.ack_height.clear();
            for (mut event, _) in previous {
                let expected = delivered(bandwidth, event.elapsed);
                if expected < event.acked {
                    event.extra = (event.acked - expected) as i64;
                    self.ack_height.update(event, event.round);
                }
            }
        }
        let elapsed = self
            .aggregation_start
            .map_or(Duration::ZERO, |start| now.saturating_duration_since(start));
        // The old Meta consumer multiplies bits/s by nanoseconds directly.
        // Keep its signed byte-count arithmetic separate from Google's units.
        if self.legacy {
            let expected = (bandwidth as i64).wrapping_mul(elapsed.as_nanos() as i64);
            if (self.aggregation_bytes as i64) <= expected {
                self.aggregation_start = Some(now);
                self.aggregation_bytes = newly_acked;
                return 0;
            }
            self.aggregation_bytes = self.aggregation_bytes.wrapping_add(newly_acked);
            let extra = (self.aggregation_bytes as i64).wrapping_sub(expected);
            self.ack_height.update(
                AckHeight {
                    extra,
                    ..AckHeight::default()
                },
                round,
            );
            return extra as u64;
        }
        let expected = delivered(bandwidth, elapsed);
        let threshold = if self.overestimate_avoidance { 2 } else { 1 };
        let extra = if self.aggregation_start.is_none()
            || self.aggregation_bytes <= expected.saturating_mul(threshold)
        {
            self.aggregation_start = Some(now);
            self.aggregation_bytes = newly_acked;
            0
        } else {
            self.aggregation_bytes = self.aggregation_bytes.saturating_add(newly_acked);
            let extra = self.aggregation_bytes.saturating_sub(expected);
            self.ack_height.update(
                AckHeight {
                    extra: extra as i64,
                    acked: self.aggregation_bytes,
                    elapsed,
                    round: 0,
                },
                round,
            );
            extra
        };
        if self.overestimate_avoidance && extra == 0 {
            if let Some(point) = self.recent_ack[0]
                .filter(|p| p.acked != 0)
                .or(self.recent_ack[1])
            {
                if self
                    .a0
                    .back()
                    .is_none_or(|last| last.acked != point.acked || last.time != point.time)
                {
                    self.a0.push_back(point);
                }
            }
        }
        self.prune_ack_points();
        extra
    }

    #[cfg(test)]
    pub(super) fn outstanding_len(&self) -> usize {
        self.outstanding.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::congestion::PacketSpace;

    fn packet(id: u64, now: Instant, bytes: u64) -> PacketInfo {
        PacketInfo {
            sample_id: id,
            packet_number: id,
            space: PacketSpace::Data,
            path_generation: 0,
            time_sent: now,
            congestion_bytes: bytes,
            ack_eliciting: bytes != 0,
        }
    }

    #[test]
    fn sparse_ids_sample_real_delivery_and_neutering_does_not_count_as_delivery() {
        let now = Instant::now();
        let mut sampler = Sampler::new(false, true, true);
        sampler.on_sent(packet(1, now, 1200), 0);
        sampler.on_sent(
            packet(1_000_000_000, now + Duration::from_millis(1), 1200),
            1200,
        );
        let sample = sampler.on_ack(now + Duration::from_millis(100), 1);
        assert_eq!(sample.bandwidth, 12_000);
        assert_eq!(sample.rtt, Some(Duration::from_millis(100)));
        sampler.on_neutered(1_000_000_000);
        assert_eq!(sampler.acked, 1200);
        assert_eq!(sampler.neutered, 1200);
        assert_eq!(sampler.lost, 0);
        assert_eq!(sampler.outstanding_len(), 0);
    }

    #[test]
    fn delivery_is_capped_by_send_slope_after_ack_compression() {
        let now = Instant::now();
        let mut sampler = Sampler::new(true, false, false);
        sampler.on_sent(packet(0, now, 1200), 0);
        sampler.on_ack(now + Duration::from_millis(100), 0);
        sampler.on_sent(packet(1, now + Duration::from_millis(200), 1200), 0);
        sampler.on_sent(packet(2, now + Duration::from_millis(300), 1200), 1200);
        sampler.on_ack(now + Duration::from_millis(400), 1);
        let sample = sampler.on_ack(now + Duration::from_millis(400), 2);
        assert_eq!(sample.bandwidth, 12_000);
    }

    #[test]
    fn every_retired_packet_is_released_even_across_large_identifier_gaps() {
        let now = Instant::now();
        let mut sampler = Sampler::new(false, true, true);
        for n in 0..10_000_u64 {
            let sent = now + Duration::from_millis(n * 100);
            let id = n * 1_000_000;
            sampler.on_sent(packet(id, sent, 1200), 0);
            if n % 2 == 0 {
                sampler.on_lost(id);
            } else {
                sampler.on_neutered(id);
            }
            assert_eq!(sampler.outstanding_len(), 0);
        }
        assert_eq!(sampler.lost, 6_000_000);
        assert_eq!(sampler.neutered, 6_000_000);
    }

    #[test]
    fn one_unacknowledged_old_packet_does_not_retain_unbounded_ack_history() {
        let now = Instant::now();
        let mut sampler = Sampler::new(false, true, true);
        sampler.on_sent(packet(0, now, 1200), 0);
        for id in 1..=10_000 {
            let sent = now + Duration::from_millis(id * 100);
            sampler.on_sent(packet(id, sent, 1200), 1200);
            let ack = sent + Duration::from_millis(50);
            let sample = sampler.on_ack(ack, id);
            sampler.end_ack_event(ack, sample.bandwidth, false, id, 1200);
            assert_eq!(sampler.outstanding_len(), 1);
            assert!(sampler.a0.len() <= 2);
            assert_eq!(sampler.ack_references.len(), 1);
        }
        sampler.on_neutered(0);
        sampler.end_ack_event(now + Duration::from_secs(1001), 24_000, false, 10_001, 0);
        assert!(sampler.ack_references.is_empty());
        assert!(sampler.a0.len() <= 1);
        assert_eq!(sampler.acked, 12_000_000);
        assert_eq!(sampler.neutered, 1200);
    }

    #[test]
    fn increased_bandwidth_recalculates_previously_aggregated_ack_height() {
        let now = Instant::now();
        let mut sampler = Sampler::new(false, true, true);
        sampler.end_ack_event(now, 10_000, false, 1, 1200);
        assert_eq!(
            sampler.end_ack_event(now + Duration::from_millis(1), 10_000, false, 1, 1200),
            2390
        );
        assert_eq!(sampler.max_ack_height(), 2390);
        sampler.end_ack_event(now + Duration::from_millis(2), 2_000_000, true, 2, 1200);
        assert_eq!(sampler.max_ack_height(), 400);
    }
}
