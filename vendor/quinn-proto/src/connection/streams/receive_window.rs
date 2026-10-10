// Vole additions, independently implemented; SPDX-License-Identifier: MIT
use crate::Instant;
use std::time::Duration;

/// A receive-credit size is not an offset and does not reserve memory. Growth
/// is driven by consumed bytes after the first incoming frame, never by sender
/// throughput alone. Arithmetic cannot exceed QUIC's representable credit.
#[derive(Debug)]
pub(crate) struct ReceiveWindow {
    pub current: u64,
    pub maximum: u64,
    consumed: u64,
    epoch_consumed: u64,
    epoch: Option<Instant>,
}

impl ReceiveWindow {
    pub(crate) fn new(initial: u64, maximum: u64) -> Self {
        Self {
            current: initial,
            maximum,
            consumed: 0,
            epoch_consumed: 0,
            epoch: None,
        }
    }

    pub(crate) fn received(&mut self, now: Instant) {
        self.epoch.get_or_insert(now);
    }

    pub(crate) fn consume(&mut self, bytes: u64, now: Instant, rtt: Duration) -> u64 {
        self.consumed = self.consumed.saturating_add(bytes);
        let Some(epoch) = self.epoch else {
            return 0;
        };
        let consumed = self.consumed - self.epoch_consumed;
        if consumed <= self.current / 2 || rtt.is_zero() {
            return 0;
        }
        let elapsed = now.saturating_duration_since(epoch).as_nanos();
        let fast = elapsed.saturating_mul(u128::from(self.current))
            < rtt
                .as_nanos()
                .saturating_mul(4)
                .saturating_mul(u128::from(consumed));
        let previous = self.current;
        if fast && self.maximum > self.current {
            self.current = self.current.saturating_mul(2).min(self.maximum);
        }
        self.epoch = Some(now);
        self.epoch_consumed = self.consumed;
        self.current - previous
    }

    pub(crate) fn ensure_minimum(&mut self, minimum: u64, now: Instant) -> u64 {
        let previous = self.current;
        if minimum > self.current {
            self.current = self.current.max(minimum.min(self.maximum));
            self.epoch = Some(now);
            self.epoch_consumed = self.consumed;
        }
        self.current - previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vole_adaptive_credit_grows_only_after_fast_consumption_and_caps() {
        let now = Instant::now();
        let rtt = Duration::from_millis(100);
        let mut window = ReceiveWindow::new(100, 350);
        window.received(now);
        assert_eq!(window.consume(50, now + rtt, rtt), 0);
        assert_eq!(window.consume(1, now + rtt, rtt), 100);
        assert_eq!(window.current, 200);
        assert_eq!(window.consume(101, now + rtt * 2, rtt), 150);
        assert_eq!(window.current, 350);
        assert_eq!(window.consume(176, now + rtt * 3, rtt), 0);
        let mut slow = ReceiveWindow::new(100, 400);
        slow.received(now);
        assert_eq!(slow.consume(51, now + rtt * 3, rtt), 0);
        assert_eq!(slow.current, 100);
        let mut fixed = ReceiveWindow::new(100, 100);
        fixed.received(now);
        assert_eq!(fixed.consume(100, now, rtt), 0);
        assert_eq!(fixed.ensure_minimum(500, now), 0);
        let mut above = ReceiveWindow::new(300, 100);
        above.received(now);
        assert_eq!(above.consume(151, now + rtt, rtt), 0);
        assert_eq!(above.ensure_minimum(500, now), 0);
        assert_eq!(above.current, 300);
    }
}
