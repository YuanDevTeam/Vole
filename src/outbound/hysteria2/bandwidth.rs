use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory, CubicConfig},
};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Default)]
struct Bucket {
    last: Option<Instant>,
    credit: u128,
    rate: u64,
}
impl Bucket {
    fn claim(&mut self, now: Instant, bytes: usize, rate: u64, mtu: u16) -> Duration {
        if rate == 0 {
            self.last = None;
            return Duration::ZERO;
        }
        // Credits are byte-nanoseconds: fractional tokens survive repeated
        // polls, with no floating-point rounding or truncating low rates.
        let capacity = u128::from((u64::from(mtu) * 10).max(rate / 250)) * 1_000_000_000;
        self.credit = match self.last {
            None => capacity,
            Some(last) => self
                .credit
                .saturating_add(
                    now.saturating_duration_since(last)
                        .as_nanos()
                        .saturating_mul(u128::from(self.rate)),
                )
                .min(capacity),
        };
        self.last = Some(now);
        self.rate = rate;
        let cost = (bytes as u128) * 1_000_000_000;
        if self.credit >= cost {
            self.credit -= cost;
            return Duration::ZERO;
        }
        Duration::from_nanos(
            (cost - self.credit)
                .div_ceil(u128::from(rate))
                .min(u128::from(u64::MAX)) as u64,
        )
    }
}

/// Rate zero uses official Quinn CUBIC. A positive negotiated rate installs Brutal's
/// fixed-rate window policy and a separate wire-byte pacer. Quinn's own cwnd
/// pacer is retained, but is not relied on as a configured bandwidth limit.
pub(super) struct Bandwidth {
    pub rate: AtomicU64,
    ratio: AtomicU64,
    pacer: Arc<Pacer>,
}
#[derive(Default)]
pub(super) struct Pacer {
    bucket: Mutex<Bucket>,
}
impl Default for Bandwidth {
    fn default() -> Self {
        Self::with_pacer(Arc::new(Pacer::default()))
    }
}
impl Bandwidth {
    pub fn with_pacer(pacer: Arc<Pacer>) -> Self {
        Self {
            rate: AtomicU64::new(0),
            ratio: AtomicU64::new(1_000_000),
            pacer,
        }
    }
    pub fn wrap(
        self: &Arc<Self>,
        inner: Box<dyn DatagramTransport>,
        mtu: u16,
    ) -> Box<dyn DatagramTransport> {
        Box::new(Paced {
            inner,
            bandwidth: self.clone(),
            mtu,
        })
    }
    fn compensated(&self) -> u64 {
        let rate = self.rate.load(Ordering::Relaxed);
        ((u128::from(rate) * 1_000_000) / u128::from(self.ratio.load(Ordering::Relaxed)))
            .min(u128::from(u64::MAX)) as u64
    }
    pub async fn pace(&self, bytes: usize, mtu: u16) {
        loop {
            let rate = self.compensated();
            if rate == 0 {
                return;
            }
            let delay = self.pacer.bucket.lock().unwrap().claim(
                tokio::time::Instant::now().into_std(),
                bytes,
                rate,
                mtu,
            );
            if delay.is_zero() {
                return;
            }
            tokio::time::sleep(delay).await;
        }
    }
}

struct Paced {
    inner: Box<dyn DatagramTransport>,
    bandwidth: Arc<Bandwidth>,
    mtu: u16,
}
#[async_trait]
impl DatagramTransport for Paced {
    fn supports_poll_receive(&self) -> bool {
        self.inner.supports_poll_receive()
    }
    fn poll_receive(
        &mut self,
        context: &mut std::task::Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> std::task::Poll<Result<Datagram, DispatchError>> {
        self.inner.poll_receive(context, scratch)
    }
    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        self.inner.payload_budget(peer)
    }
    fn send_owned(
        &mut self,
        packet: Datagram,
    ) -> Result<crate::dispatch::OwnedDatagramSend, Datagram> {
        let bytes = packet.payload.len();
        let send = self.inner.send_owned(packet)?;
        let bandwidth = self.bandwidth.clone();
        let mtu = self.mtu;
        Ok(Box::pin(async move {
            bandwidth.pace(bytes, mtu).await;
            send.await
        }))
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        self.bandwidth.pace(packet.payload.len(), self.mtu).await;
        self.inner.send(packet).await
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.inner.receive().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.inner.close().await
    }
}
impl ControllerFactory for Bandwidth {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(Switchable {
            automatic: Arc::new(CubicConfig::default()).build(now, mtu),
            shared: self,
            start: now,
            slots: [Slot::default(); 5],
            mtu,
            rtt: Duration::ZERO,
        })
    }
}
#[derive(Clone, Copy, Default)]
struct Slot {
    second: u64,
    acknowledged: u64,
    lost: u64,
}
struct Switchable {
    automatic: Box<dyn Controller>,
    shared: Arc<Bandwidth>,
    start: Instant,
    slots: [Slot; 5],
    mtu: u16,
    rtt: Duration,
}
impl Switchable {
    fn sample(&mut self, now: Instant, acknowledged: u64, lost: u64) {
        let second = now.saturating_duration_since(self.start).as_secs();
        let slot = &mut self.slots[(second % 5) as usize];
        if slot.second != second {
            *slot = Slot {
                second,
                ..Default::default()
            };
        }
        slot.acknowledged = slot.acknowledged.saturating_add(acknowledged);
        slot.lost = slot.lost.saturating_add(lost);
        let (ack, loss) = self
            .slots
            .iter()
            .filter(|slot| second.saturating_sub(slot.second) < 5)
            .fold((0_u64, 0_u64), |(a, l), slot| {
                (
                    a.saturating_add(slot.acknowledged),
                    l.saturating_add(slot.lost),
                )
            });
        let total = ack.saturating_add(loss);
        let ratio = if total < 50 {
            1_000_000
        } else {
            ((u128::from(ack) * 1_000_000 / u128::from(total)) as u64).max(800_000)
        };
        self.shared.ratio.store(ratio, Ordering::Relaxed);
    }
}
impl Controller for Switchable {
    fn on_sent(&mut self, now: Instant, bytes: u64, packet: u64) {
        self.automatic.on_sent(now, bytes, packet);
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        limited: bool,
        rtt: &RttEstimator,
    ) {
        self.automatic.on_ack(now, sent, bytes, limited, rtt);
        self.rtt = rtt.get();
        self.sample(now, u64::from(bytes > 0), 0);
    }
    fn on_end_acks(&mut self, now: Instant, flight: u64, limited: bool, largest: Option<u64>) {
        self.automatic.on_end_acks(now, flight, limited, largest);
    }
    fn on_congestion_event(&mut self, now: Instant, sent: Instant, persistent: bool, lost: u64) {
        self.automatic
            .on_congestion_event(now, sent, persistent, lost);
        self.sample(now, 0, lost.div_ceil(u64::from(self.mtu)));
    }
    fn on_mtu_update(&mut self, mtu: u16) {
        self.mtu = mtu;
        self.automatic.on_mtu_update(mtu);
    }
    fn window(&self) -> u64 {
        if self.shared.rate.load(Ordering::Relaxed) == 0 {
            return self.automatic.window();
        }
        // Keep enough flight space for Quinn's delayed ACKs at very low RTT.
        // The independent wire pacer, not this floor, enforces the exact rate.
        ((self.shared.compensated() as f64 * self.rtt.as_secs_f64() * 2.0) as u64)
            .max(10240)
            .max(u64::from(self.mtu) * 2)
    }
    fn initial_window(&self) -> u64 {
        self.automatic.initial_window()
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            automatic: self.automatic.clone_box(),
            shared: self.shared.clone(),
            start: self.start,
            slots: self.slots,
            mtu: self.mtu,
            rtt: self.rtt,
        })
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

pub(super) fn negotiate(up: u64, server: &[u8]) -> io::Result<u64> {
    if server == b"auto" {
        return Ok(0);
    }
    if server.is_empty() || !server.iter().all(u8::is_ascii_digit) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let server: u64 = std::str::from_utf8(server)
        .map_err(|_| io::ErrorKind::InvalidData)?
        .parse()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    Ok(if up == 0 {
        0
    } else if server == 0 {
        up
    } else {
        up.min(server)
    })
}

#[cfg(test)]
mod tests {
    #[tokio::test(start_paused = true)]
    async fn sibling_connections_share_one_wire_credit_bucket() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "HYSTERIA2-UNIT",
            "sibling_connections_share_one_wire_credit_bucket",
        );
        let pacer = std::sync::Arc::new(super::Pacer::default());
        let first = super::Bandwidth::with_pacer(pacer.clone());
        let second = super::Bandwidth::with_pacer(pacer.clone());
        for connection in [&first, &second] {
            connection
                .rate
                .store(125000, std::sync::atomic::Ordering::Relaxed);
            for _ in 0..5 {
                connection.pace(1400, 1400).await;
            }
        }
        // An automatic connection must not reset the fixed-rate budget.
        super::Bandwidth::with_pacer(pacer).pace(1400, 1400).await;
        let mut pending = Box::pin(first.pace(1400, 1400));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        tokio::time::advance(std::time::Duration::from_millis(12)).await;
        assert!(futures_util::poll!(pending.as_mut()).is_ready());
    }

    #[test]
    fn pacer_limits_actual_bytes_after_one_bounded_burst() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "HYSTERIA2-UNIT",
            "pacer_limits_actual_bytes_after_one_bounded_burst",
        );
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut bucket = super::Bucket::default();
        for _ in 0..10 {
            assert_eq!(bucket.claim(now, 1400, 125000, 1400), Duration::ZERO);
        }
        assert_eq!(
            bucket.claim(now, 1400, 125000, 1400),
            Duration::from_micros(11200)
        );
        assert_eq!(
            bucket.claim(now + Duration::from_micros(11200), 1400, 125000, 1400),
            Duration::ZERO
        );
        // A change in loss compensation must not grant another initial burst.
        assert!(
            bucket.claim(now + Duration::from_micros(11200), 1400, 156250, 1400) > Duration::ZERO
        );
    }
    #[test]
    fn bandwidth_negotiation_obeys_auto_and_the_lower_positive_limit() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "HYSTERIA2-UNIT",
            "bandwidth_negotiation_obeys_auto_and_the_lower_positive_limit",
        );
        for (up, response, expected) in [
            (0, "0", 0),
            (0, "100000", 0),
            (250000, "auto", 0),
            (250000, "0", 250000),
            (250000, "125000", 125000),
            (125000, "250000", 125000),
        ] {
            assert_eq!(super::negotiate(up, response.as_bytes()).unwrap(), expected);
        }
        for invalid in [
            "",
            "-1",
            "+1",
            "1Mbps",
            "Auto",
            " 0",
            "18446744073709551616",
        ] {
            assert!(super::negotiate(0, invalid.as_bytes()).is_err());
        }
    }
}
