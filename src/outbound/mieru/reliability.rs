//! Timer-free models for Mieru's reliable carrier. The driver owns packets and permits.
//!
//! The RTT estimator and CUBIC equation are implemented independently from their
//! mathematical definitions, with Mieru's segment units and timing profile.
//! https://www.rfc-editor.org/rfc/rfc6298
//! https://www.rfc-editor.org/rfc/rfc9438
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct Rtt {
    estimate: Option<(Duration, Duration)>,
}

impl Rtt {
    pub fn new() -> Self {
        Self { estimate: None }
    }

    pub fn update(&mut self, sample: Duration) {
        if sample.is_zero() || sample.as_nanos() >= i64::MAX as u128 {
            return;
        }
        self.estimate = Some(match self.estimate {
            None => (sample, sample / 2),
            Some((delay, variation)) => {
                // The peer's profile quantizes subsequent estimates to whole
                // microseconds, performing the weighted sums in float32.
                let delta = delay.abs_diff(sample).as_micros() as f32;
                let variation = variation.as_micros() as f32 * 0.75 + delta * 0.25;
                let delay = delay.as_micros() as f32 * 0.875 + sample.as_micros() as f32 * 0.125;
                (
                    Duration::from_micros(delay as u64),
                    Duration::from_micros(variation as u64),
                )
            }
        });
    }

    pub fn rto(&self) -> Duration {
        let Some((delay, variation)) = self.estimate else {
            return Duration::from_secs(2);
        };
        let base = delay
            .saturating_add(variation.saturating_mul(4).max(Duration::from_millis(10)))
            .saturating_add(Duration::from_millis(1));
        scale(base, 1.5)
    }

    pub fn retransmit_delay(&self, tx_count: u32) -> Duration {
        // Count includes the first transmission. The legacy duration cast
        // truncates the exponential multiplier before it scales the RTO.
        scale(self.rto(), 1.5_f64.powf(f64::from(tx_count)).floor()).min(Duration::from_secs(10))
    }
}

fn scale(duration: Duration, multiplier: f64) -> Duration {
    let nanos = (duration.as_nanos() as f64 * multiplier) as u128;
    Duration::new(
        (nanos / 1_000_000_000).min(u64::MAX as u128) as u64,
        (nanos % 1_000_000_000) as u32,
    )
}

struct Recovery {
    peak: u32,
    began: Instant,
    acknowledged: u64,
}

pub(super) struct Cubic {
    segments: u32,
    recovery: Option<Recovery>,
}

impl Cubic {
    pub fn new() -> Self {
        Self {
            segments: 16,
            recovery: None,
        }
    }

    pub fn window(&self) -> u32 {
        self.segments
    }

    pub fn on_ack(&mut self, now: Instant) -> u32 {
        self.segments = match self.recovery.as_mut() {
            None => self.segments.saturating_add(1),
            Some(recovery) => {
                recovery.acknowledged = recovery.acknowledged.saturating_add(1);
                let origin = (f64::from(recovery.peak) * 0.3 / 0.4).cbrt();
                let elapsed = now.saturating_duration_since(recovery.began).as_secs_f64();
                let curve = 0.4 * (elapsed - origin).powi(3) + f64::from(recovery.peak);
                (curve as u32)
                    .saturating_add(u32::try_from(recovery.acknowledged / 16).unwrap_or(u32::MAX))
            }
        }
        .clamp(16, 4096);
        self.segments
    }

    pub fn on_loss(&mut self, now: Instant) -> u32 {
        self.recovery = Some(Recovery {
            peak: self.segments,
            began: now,
            acknowledged: 0,
        });
        self.segments = ((f64::from(self.segments) * 0.7) as u32).clamp(16, 4096);
        self.segments
    }

    pub fn on_timeout(&mut self) -> u32 {
        *self = Self::new();
        self.segments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mieru_rtt_quantization_and_retransmission_profile() {
        let mut rtt = Rtt::new();
        assert_eq!(rtt.rto(), Duration::from_secs(2));
        assert_eq!(
            (1..=5)
                .map(|count| rtt.retransmit_delay(count).as_millis())
                .collect::<Vec<_>>(),
            [2000, 4000, 6000, 10000, 10000]
        );
        // Independent Python float32/whole-microsecond calculations. The first
        // fractional-microsecond sample also distinguishes truncation from rounding.
        for (sample, expected) in [
            (100_000_015, 451_500_064),
            (80_000_000, 402_750_000),
            (140_000_000, 410_718_000),
        ] {
            rtt.update(Duration::from_nanos(sample));
            assert_eq!(rtt.rto(), Duration::from_nanos(expected));
        }
        let previous = rtt.rto();
        rtt.update(Duration::ZERO);
        assert_eq!(rtt.rto(), previous);
        assert_eq!(rtt.retransmit_delay(20), Duration::from_secs(10));
    }

    #[test]
    fn mieru_segment_cubic_loss_time_growth_and_timeout() {
        let mut cubic = Cubic::new();
        let now = Instant::now();
        for _ in 0..48 {
            cubic.on_ack(now);
        }
        assert_eq!(cubic.window(), 64);
        assert_eq!(cubic.on_loss(now), 44);
        for _ in 0..16 {
            cubic.on_ack(now);
        }
        // Evaluated independently from the public polynomial at peak 64.
        assert_eq!(cubic.window(), 45);
        for (seconds, expected) in [(1, 57), (3, 64), (10, 168)] {
            assert_eq!(cubic.on_ack(now + Duration::from_secs(seconds)), expected);
        }
        assert_eq!(cubic.on_ack(now + Duration::from_secs(100)), 4096);
        assert_eq!(cubic.on_timeout(), 16);
        assert_eq!(cubic.on_ack(now), 17);
    }
}
