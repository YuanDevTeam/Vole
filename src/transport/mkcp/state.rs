//! Reliable-stream state. Bytes and packet entries are both locally bounded.
use super::{Shared, wire};
use crate::config::MkcpOptions;
use bytes::{Buf, Bytes};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::time::Instant;

const PACKETS: usize = 16_384;
pub(super) fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
struct Sending {
    number: u32,
    payload: Bytes,
    at: Instant,
    transmissions: u32,
}
pub(super) struct State {
    options: MkcpOptions,
    pub conv: u16,
    pub mss: usize,
    created: Instant,
    last_incoming: Instant,
    last_ping: Instant,
    next_tick: Instant,
    rto: Duration,
    srtt: u32,
    variation: u32,
    cwnd: usize,
    flight: usize,
    loss_at: Instant,
    tx: VecDeque<Sending>,
    tx_bytes: usize,
    tx_limit: usize,
    tx_slots: usize,
    next_send: u32,
    remote_upper: u32,
    rate_bytes: u64,
    tokens: u64,
    reorder: BTreeMap<u32, Bytes>,
    pub ready: VecDeque<Bytes>,
    rx_bytes: usize,
    rx_limit: usize,
    rx_mss: usize,
    rx_slots: usize,
    next_receive: u32,
    receive_upper: u32,
    acks: BTreeMap<u32, u32>,
    acks_per_packet: usize,
    ack_dirty: bool,
    ack_at: Instant,
    pub app_end: bool,
    peer_close: bool,
    peer_terminate: bool,
    closing: Option<Instant>,
    shared: Arc<Shared>,
}
impl State {
    pub fn new(
        options: MkcpOptions,
        mtu: usize,
        receive_limit: usize,
        pipe: usize,
        shared: Arc<Shared>,
    ) -> std::io::Result<Self> {
        let now = Instant::now();
        let mss = mtu
            .checked_sub(options.overhead() + wire::DATA_HEADER)
            .filter(|n| *n > 0)
            .ok_or_else(|| std::io::Error::other("mKCP upstream packet budget is too small"))?;
        let rx_mss = receive_limit
            .checked_sub(options.overhead() + wire::DATA_HEADER)
            .filter(|n| *n > 0)
            .ok_or_else(|| std::io::Error::other("mKCP receive budget is too small"))?;
        let acks_per_packet = mtu
            .checked_sub(options.overhead() + wire::ACK_HEADER)
            .map(|n| n / 4)
            .filter(|n| *n > 0)
            .ok_or_else(|| std::io::Error::other("mKCP upstream ACK budget is too small"))?
            .min(wire::ACKS);
        let tx_limit = options
            .write_buffer
            .checked_sub(pipe + mss)
            .filter(|n| *n >= mss)
            .ok_or_else(|| std::io::Error::other("mKCP write budget is too small"))?;
        let rx_limit = options
            .read_buffer
            .checked_sub(pipe + 2 * receive_limit)
            .filter(|n| *n >= rx_mss)
            .ok_or_else(|| std::io::Error::other("mKCP read budget is too small"))?;
        let capacity =
            |mib: u32| (u64::from(mib) * 1024 * 1024 * u64::from(options.tti) / 1000).max(1);
        let rate_bytes = capacity(options.uplink_capacity);
        let tx_slots = (rate_bytes / mtu as u64)
            .max(8)
            .min((tx_limit / mss).min(PACKETS) as u64) as usize;
        let rx_slots = (capacity(options.downlink_capacity) / mtu as u64)
            .max(8)
            .min((rx_limit / rx_mss).min(PACKETS) as u64) as usize;
        Ok(Self {
            conv: rand::random(),
            mss,
            created: now,
            last_incoming: now,
            last_ping: now,
            next_tick: now,
            rto: Duration::from_millis(100),
            srtt: 0,
            variation: 0,
            cwnd: tx_slots.min(32),
            flight: 0,
            loss_at: now,
            tx: VecDeque::new(),
            tx_bytes: 0,
            tx_limit,
            tx_slots,
            next_send: 0,
            remote_upper: 32,
            rate_bytes,
            tokens: rate_bytes,
            reorder: BTreeMap::new(),
            ready: VecDeque::new(),
            rx_bytes: 0,
            rx_limit,
            rx_mss,
            rx_slots,
            next_receive: 0,
            receive_upper: rx_slots as u32,
            acks: BTreeMap::new(),
            acks_per_packet,
            ack_dirty: false,
            ack_at: now,
            app_end: false,
            peer_close: false,
            peer_terminate: false,
            closing: None,
            shared,
            options,
        })
    }
    pub fn read_capacity(&self) -> usize {
        if self.app_end || self.peer_close || self.tx.len() >= PACKETS {
            0
        } else {
            self.tx_limit.saturating_sub(self.tx_bytes).min(self.mss)
        }
    }
    pub fn queue(&mut self, bytes: &[u8]) {
        debug_assert!(!bytes.is_empty() && bytes.len() <= self.read_capacity());
        self.tx_bytes += bytes.len();
        self.tx.push_back(Sending {
            number: self.next_send,
            payload: Bytes::copy_from_slice(bytes),
            at: Instant::now(),
            transmissions: 0,
        });
        self.next_send = self.next_send.wrapping_add(1);
    }
    pub fn delivered(&mut self, n: usize) {
        self.rx_bytes -= n;
        let front = self.ready.front_mut().unwrap();
        front.advance(n);
        if front.is_empty() {
            self.ready.pop_front();
        }
        self.update_credit();
    }
    fn update_credit(&mut self) {
        let count = (self.rx_limit.saturating_sub(self.rx_bytes) / self.rx_mss).min(self.rx_slots);
        let upper = self.next_receive.wrapping_add(count as u32);
        if before(self.receive_upper, upper) {
            self.receive_upper = upper;
            self.ack_dirty = true;
        }
    }
    fn elapsed(&self, now: Instant) -> u32 {
        now.saturating_duration_since(self.created).as_millis() as u32
    }
    fn first_unacked(&self) -> u32 {
        self.tx.front().map_or(self.next_send, |seg| seg.number)
    }
    fn accepted(&mut self, number: u32) {
        let Some(index) = self.tx.iter().position(|seg| seg.number == number) else {
            return;
        };
        // Never accept an ACK for bytes not yet put on this UDP path.
        if self.tx[index].transmissions == 0 {
            return;
        }
        let seg = self.tx.remove(index).unwrap();
        self.tx_bytes -= seg.payload.len();
        self.flight = self.flight.saturating_sub(1);
        self.shared
            .acked
            .fetch_add(seg.payload.len() as u64, Ordering::Release);
        self.shared.writer.wake();
        if self.options.congestion {
            self.cwnd = (self.cwnd + 1).min(self.tx_slots);
        }
    }
    fn accepted_before(&mut self, next: u32) {
        if before(self.next_send, next) {
            return;
        }
        while self
            .tx
            .front()
            .is_some_and(|seg| before(seg.number, next) && seg.transmissions != 0)
        {
            let number = self.tx.front().unwrap().number;
            self.accepted(number);
        }
    }
    fn sample_rtt(&mut self, time: u32, now: Instant) {
        let sample = self.elapsed(now).wrapping_sub(time);
        if sample == 0 || sample >= 10_000 {
            return;
        }
        if self.srtt == 0 {
            self.srtt = sample;
            self.variation = sample / 2;
        } else {
            self.variation = (3 * self.variation + self.srtt.abs_diff(sample)) / 4;
            self.srtt = (7 * self.srtt + sample) / 8;
        }
        self.rto = Duration::from_millis(u64::from(
            (self.srtt + 4 * self.variation).clamp(self.options.tti, 10_000),
        ));
    }
    pub fn input(&mut self, segment: wire::Segment<'_>, now: Instant) {
        let option = match &segment {
            wire::Segment::Data { option, .. }
            | wire::Segment::Ack { option, .. }
            | wire::Segment::Control { option, .. } => *option,
        };
        if option & 1 != 0 {
            self.peer_close = true;
        }
        self.last_incoming = now;
        match segment {
            wire::Segment::Data {
                time,
                number,
                sending_next,
                payload,
                ..
            } => {
                self.acks.retain(|number, _| !before(*number, sending_next));
                self.ack_dirty = true;
                if before(number, self.next_receive) {
                    return;
                }
                if !before(number, self.receive_upper) || payload.len() > self.rx_mss {
                    return;
                }
                if self.reorder.contains_key(&number) {
                    self.acks.insert(number, time);
                    return;
                }
                if self.reorder.len() + self.ready.len() >= PACKETS
                    || self
                        .rx_bytes
                        .checked_add(payload.len())
                        .is_none_or(|n| n > self.rx_limit)
                {
                    return;
                }
                self.rx_bytes += payload.len();
                self.reorder.insert(number, Bytes::copy_from_slice(payload));
                self.acks.insert(number, time);
                while let Some(bytes) = self.reorder.remove(&self.next_receive) {
                    self.next_receive = self.next_receive.wrapping_add(1);
                    if !bytes.is_empty() {
                        self.ready.push_back(bytes);
                    }
                }
                self.update_credit();
            }
            wire::Segment::Ack {
                window,
                next,
                time,
                numbers,
                ..
            } => {
                if before(self.remote_upper, window)
                    && window.wrapping_sub(self.first_unacked()) < 0x8000_0000
                {
                    self.remote_upper = window;
                }
                let old = self.tx_bytes;
                self.accepted_before(next);
                for number in numbers.chunks_exact(4) {
                    self.accepted(u32::from_be_bytes(number.try_into().unwrap()));
                }
                if self.tx_bytes < old {
                    self.sample_rtt(time, now);
                }
            }
            wire::Segment::Control {
                command,
                sending_next,
                receiving_next,
                rto,
                ..
            } => {
                self.acks.retain(|number, _| !before(*number, sending_next));
                self.accepted_before(receiving_next);
                if self.srtt == 0 && rto > 0 && rto <= 10_000 {
                    self.rto = Duration::from_millis(u64::from(rto.max(self.options.tti)));
                }
                self.ack_dirty = true;
                if command == 2 {
                    self.peer_terminate = true;
                    self.peer_close = true;
                }
            }
        }
    }
    pub fn tick_at(&self) -> Instant {
        if self.ack_dirty {
            self.next_tick.min(self.ack_at)
        } else {
            self.next_tick
        }
    }
    pub fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_incoming) >= Duration::from_secs(30)
            || self
                .closing
                .is_some_and(|at| now.saturating_duration_since(at) >= Duration::from_secs(8))
    }
    pub fn finished(&self) -> bool {
        self.peer_terminate && self.ready.is_empty() && self.reorder.is_empty()
    }
    pub fn next(&mut self, now: Instant) -> Option<Vec<u8>> {
        if now >= self.next_tick {
            self.tokens = self.rate_bytes;
            self.next_tick = now + Duration::from_millis(u64::from(self.options.tti));
        }
        let option = u8::from(self.app_end || self.peer_close);
        if self.ack_dirty && now >= self.ack_at {
            let mut numbers = Vec::new();
            let mut time = 0;
            while numbers.len() < self.acks_per_packet {
                let Some((number, timestamp)) = self.acks.pop_first() else {
                    break;
                };
                numbers.push(number);
                time = timestamp;
            }
            self.ack_dirty = !self.acks.is_empty();
            self.ack_at = now + Duration::from_millis(u64::from(self.options.tti));
            return Some(wire::ack(
                self.conv,
                option,
                self.receive_upper,
                self.next_receive,
                time,
                &numbers,
            ));
        }
        if (self.app_end || self.peer_terminate) && self.tx.is_empty() {
            self.closing.get_or_insert(now);
            if now.saturating_duration_since(self.last_ping)
                >= Duration::from_millis(u64::from(self.options.tti))
            {
                self.last_ping = now;
                return Some(self.terminate());
            }
        }
        let now_ms = self.elapsed(now);
        let first = self.first_unacked();
        let cwnd = if self.options.congestion {
            self.cwnd
        } else {
            self.tx_slots
        };
        for seg in &mut self.tx {
            if !before(seg.number, self.remote_upper) {
                continue;
            }
            if seg.transmissions == 0 && self.flight >= cwnd {
                continue;
            }
            if seg.transmissions != 0 && now < seg.at {
                continue;
            }
            let cost = (self.options.overhead() + wire::DATA_HEADER + seg.payload.len()) as u64;
            if self.tokens < cost {
                continue;
            }
            self.tokens -= cost;
            if seg.transmissions == 0 {
                self.flight += 1;
            } else if self.options.congestion
                && now.saturating_duration_since(self.loss_at) >= self.rto
            {
                self.cwnd = (self.cwnd / 2).max(1);
                self.loss_at = now;
            }
            seg.transmissions = seg.transmissions.saturating_add(1);
            seg.at = now + self.rto.mul_f64(f64::from(seg.transmissions.min(4)));
            return Some(wire::data(
                self.conv,
                option,
                now_ms,
                seg.number,
                first,
                &seg.payload,
            ));
        }
        if now.saturating_duration_since(self.last_ping) >= Duration::from_secs(3) {
            self.last_ping = now;
            return Some(wire::control(
                self.conv,
                3,
                option,
                first,
                self.next_receive,
                self.rto.as_millis() as u32,
            ));
        }
        None
    }
    pub fn terminate(&self) -> Vec<u8> {
        wire::control(
            self.conv,
            2,
            1,
            self.first_unacked(),
            self.next_receive,
            self.rto.as_millis() as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> State {
        State::new(
            MkcpOptions::default(),
            1350,
            1350,
            2700,
            Arc::new(Shared::default()),
        )
        .unwrap()
    }
    #[test]
    fn mkcp_reordering_duplicates_and_read_budget_are_bounded() {
        let mut state = state();
        let now = Instant::now();
        state.input(
            wire::Segment::Data {
                option: 0,
                time: 1,
                number: 1,
                sending_next: 0,
                payload: b"second",
            },
            now,
        );
        assert!(state.ready.is_empty());
        state.input(
            wire::Segment::Data {
                option: 0,
                time: 2,
                number: 0,
                sending_next: 0,
                payload: b"first",
            },
            now,
        );
        assert_eq!(state.ready[0], b"first".as_slice());
        assert_eq!(state.ready[1], b"second".as_slice());
        let bytes = state.rx_bytes;
        state.input(
            wire::Segment::Data {
                option: 0,
                time: 1,
                number: 1,
                sending_next: 0,
                payload: b"second",
            },
            now,
        );
        assert_eq!(state.rx_bytes, bytes);
        state.delivered(2);
        assert_eq!(state.ready[0], b"rst".as_slice());
        assert_eq!(state.rx_bytes, bytes - 2);
        let huge = vec![0u8; state.rx_mss + 1];
        state.input(
            wire::Segment::Data {
                option: 0,
                time: 1,
                number: 2,
                sending_next: 0,
                payload: &huge,
            },
            now,
        );
        assert_eq!(state.rx_bytes, bytes - 2);
    }
    #[test]
    fn mkcp_ack_confirmations_and_loss_retransmit_keep_one_payload() {
        let mut state = state();
        let now = Instant::now();
        state.queue(b"payload");
        let first = state.next(now).unwrap();
        assert!(matches!(
            wire::parse(&first, state.conv),
            Some((wire::Segment::Data { number: 0, .. }, _))
        ));
        assert!(state.next(now).is_none());
        let retry = state.next(now + Duration::from_millis(101)).unwrap();
        assert_eq!(state.tx.len(), 1);
        assert_eq!(state.tx_bytes, 7);
        assert!(matches!(
            wire::parse(&retry, state.conv),
            Some((wire::Segment::Data { number: 0, .. }, _))
        ));
        state.input(
            wire::Segment::Ack {
                option: 0,
                window: 100,
                next: 1,
                time: 100,
                numbers: &[],
            },
            now + Duration::from_millis(102),
        );
        assert!(state.tx.is_empty());
        assert_eq!(state.shared.acked.load(Ordering::Acquire), 7);
        assert!(before(u32::MAX, 0));
        assert!(!before(0, u32::MAX));
    }
}
