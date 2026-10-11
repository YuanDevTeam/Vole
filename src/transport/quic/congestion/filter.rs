// Copyright 2016 The Chromium Authors. All rights reserved.
// Derived from Google QUIC windowed_filter.h; BSD-3-Clause, see LICENSE.chromium.

/// Chromium's three-estimate maximum filter. Storage is constant, even when
/// round numbers or packet identifiers are sparse.
#[derive(Clone, Debug)]
pub(super) struct MaxFilter<T> {
    window: u64,
    zero: T,
    estimates: [(T, u64); 3],
}

pub(super) trait FilterValue: Copy {
    fn height(self) -> u64;
    fn at_least(self, other: Self) -> bool {
        self.height() >= other.height()
    }
}

impl FilterValue for u64 {
    fn height(self) -> u64 {
        self
    }
}

impl<T: FilterValue> MaxFilter<T> {
    pub(super) fn new(window: u64, zero: T) -> Self {
        Self {
            window,
            zero,
            estimates: [(zero, 0); 3],
        }
    }

    pub(super) fn best(&self) -> T {
        self.estimates[0].0
    }

    pub(super) fn values(&self) -> [(T, u64); 3] {
        self.estimates
    }

    pub(super) fn reset(&mut self, value: T, time: u64) {
        self.estimates = [(value, time); 3];
    }

    pub(super) fn clear(&mut self) {
        self.reset(self.zero, 0);
    }

    pub(super) fn update(&mut self, value: T, time: u64) {
        if self.estimates[0].0.height() == self.zero.height()
            || value.at_least(self.estimates[0].0)
            || time.saturating_sub(self.estimates[2].1) > self.window
        {
            self.reset(value, time);
            return;
        }
        if value.at_least(self.estimates[1].0) {
            self.estimates[1] = (value, time);
            self.estimates[2] = self.estimates[1];
        } else if value.at_least(self.estimates[2].0) {
            self.estimates[2] = (value, time);
        }
        if time.saturating_sub(self.estimates[0].1) > self.window {
            self.estimates[0] = self.estimates[1];
            self.estimates[1] = self.estimates[2];
            self.estimates[2] = (value, time);
            if time.saturating_sub(self.estimates[0].1) > self.window {
                self.estimates[0] = self.estimates[1];
                self.estimates[1] = self.estimates[2];
            }
            return;
        }
        if self.estimates[1].0.height() == self.estimates[0].0.height()
            && time.saturating_sub(self.estimates[1].1) > self.window >> 2
        {
            self.estimates[1] = (value, time);
            self.estimates[2] = (value, time);
            return;
        }
        if self.estimates[2].0.height() == self.estimates[1].0.height()
            && time.saturating_sub(self.estimates[2].1) > self.window >> 1
        {
            self.estimates[2] = (value, time);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MaxFilter;

    #[test]
    fn historical_peak_expires_without_packet_number_sized_storage() {
        let mut filter = MaxFilter::new(10, 0_u64);
        filter.update(100, 1);
        filter.update(60, 4);
        filter.update(40, 8);
        filter.update(20, 12);
        assert_eq!(filter.best(), 60);
        filter.update(10, u64::MAX - 1);
        assert_eq!(filter.best(), 10);
        assert_eq!(filter.values().len(), 3);
    }
}
