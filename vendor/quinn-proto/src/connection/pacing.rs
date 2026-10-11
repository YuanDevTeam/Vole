//! Pacing of packet transmissions.

use crate::{congestion::PacingPolicy, Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    prev: Instant,
    explicit: bool,
    fractional_tokens: u128,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
            explicit: false,
            fractional_tokens: 0,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Debit actual wire bytes, including ACK-only packets, for explicit policies.
    pub(super) fn on_transmit_policy(
        &mut self,
        now: Instant,
        packet_length: u16,
        mtu: u16,
        policy: PacingPolicy,
    ) {
        self.refill_policy(now, mtu, policy);
        self.tokens = self.tokens.saturating_sub(packet_length.into());
    }

    fn refill_policy(&mut self, now: Instant, mtu: u16, policy: PacingPolicy) {
        let capacity = policy.burst_bytes.max(mtu.into());
        if !self.explicit {
            self.explicit = true;
            self.capacity = capacity;
            self.tokens = capacity;
            self.prev = now;
            self.fractional_tokens = 0;
            return;
        }
        let elapsed = now.checked_duration_since(self.prev).unwrap_or_default();
        let refill = elapsed
            .as_nanos()
            .saturating_mul(policy.rate_bytes_per_second.max(1).into())
            .saturating_add(self.fractional_tokens);
        let added = (refill / 1_000_000_000).min(u64::MAX.into()) as u64;
        self.capacity = capacity;
        self.tokens = self.tokens.saturating_add(added).min(capacity);
        self.fractional_tokens = if self.tokens == capacity {
            0
        } else {
            refill % 1_000_000_000
        };
        self.prev = now;
    }

    /// An explicit rate replaces, rather than multiplies, the legacy window/RTT rate.
    pub(super) fn delay_policy(
        &mut self,
        bytes_to_send: u64,
        mtu: u16,
        now: Instant,
        policy: PacingPolicy,
    ) -> Option<Instant> {
        self.refill_policy(now, mtu, policy);
        if self.tokens >= bytes_to_send {
            return None;
        }
        let deficit = u128::from(bytes_to_send - self.tokens) * 1_000_000_000;
        let rate = u128::from(policy.rate_bytes_per_second.max(1));
        let nanos = deficit
            .saturating_sub(self.fractional_tokens)
            .div_ceil(rate);
        let delay = Duration::from_nanos(nanos.min(u64::MAX.into()) as u64).max(policy.min_delay);
        Some(now + delay)
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        if window != self.last_window || mtu != self.last_mtu {
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu);

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = window as f64 * 1.25 * elapsed_rtts;
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as _)
            .min(self.capacity);

        self.prev = now;

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vole_explicit_pacing_uses_rate_and_wire_budget_even_with_a_large_window() {
        let now = Instant::now();
        let policy = PacingPolicy {
            rate_bytes_per_second: 1_000,
            burst_bytes: 2_000,
            min_delay: Duration::from_millis(1),
        };
        let mut pacer = Pacer::new(Duration::ZERO, u64::MAX, 1_000, now);
        assert_eq!(pacer.delay_policy(1_000, 1_000, now, policy), None);
        pacer.on_transmit_policy(now, 1_000, 1_000, policy);
        // This debit also represents a wire packet with zero congestion bytes.
        pacer.on_transmit_policy(now, 1_000, 1_000, policy);
        assert_eq!(
            pacer.delay_policy(1_000, 1_000, now, policy),
            Some(now + Duration::from_secs(1))
        );
        assert_eq!(
            pacer.delay_policy(1_000, 1_000, now + Duration::from_millis(999), policy),
            Some(now + Duration::from_secs(1))
        );
        assert_eq!(
            pacer.delay_policy(1_000, 1_000, now + Duration::from_secs(1), policy),
            None
        );
        pacer.on_transmit_policy(now + Duration::from_secs(1), 1_000, 1_000, policy);
        let faster = PacingPolicy {
            rate_bytes_per_second: 4_000,
            ..policy
        };
        assert_eq!(
            pacer.delay_policy(1_000, 1_000, now + Duration::from_secs(1), faster),
            Some(now + Duration::from_millis(1_250))
        );
    }

    #[test]
    fn vole_explicit_pacing_preserves_fractional_tokens_and_rounds_deadline_up() {
        let now = Instant::now();
        let policy = PacingPolicy {
            rate_bytes_per_second: 3,
            burst_bytes: 10,
            min_delay: Duration::ZERO,
        };
        let mut pacer = Pacer::new(Duration::from_millis(50), 1_000, 1, now);
        pacer.on_transmit_policy(now, 10, 1, policy);
        let deadline = now + Duration::from_nanos(333_333_334);
        assert_eq!(pacer.delay_policy(1, 1, now, policy), Some(deadline));
        assert_eq!(
            pacer.delay_policy(1, 1, now + Duration::from_nanos(333_333_333), policy),
            Some(deadline)
        );
        assert_eq!(pacer.delay_policy(1, 1, deadline, policy), None);
    }

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }
}
