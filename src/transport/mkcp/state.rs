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
// Bound producer prefetch without changing configured wire flight credit.
const TX_PREFETCH_BYTES: usize = 256 * 1024;
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
            self.tx_limit
                .min(TX_PREFETCH_BYTES)
                .saturating_sub(self.tx_bytes)
                .min(self.mss)
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
                for number in numbers.as_chunks::<4>().0 {
                    self.accepted(u32::from_be_bytes(*number));
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
        // CLOSE advertises our application end. A peer CLOSE only stops new
        // local writes; reflecting it would make a ReadyToClose peer terminate
        // before its remaining reply segments have been retransmitted.
        let option = u8::from(self.app_end);
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

    #[test]
    fn mkcp_peer_close_keeps_ack_and_retransmit_open_until_own_application_end() {
        let mut state = state();
        let now = Instant::now();
        state.queue(b"request");
        let sent = state.next(now).unwrap();
        assert!(matches!(
            wire::parse(&sent, state.conv),
            Some((
                wire::Segment::Data {
                    option: 0,
                    number: 0,
                    ..
                },
                _
            ))
        ));

        // An independently closing peer can still owe a lost earlier reply.
        // Receiving its final-number segment first must preserve that hole.
        state.input(
            wire::Segment::Data {
                option: 1,
                time: 1,
                number: 1,
                sending_next: 0,
                payload: b"tail",
            },
            now,
        );
        assert!(state.peer_close);
        assert!(!state.app_end);
        assert!(state.ready.is_empty());
        assert_eq!(state.reorder.len(), 1);
        assert_eq!(state.read_capacity(), 0);
        let ack = state.next(now).unwrap();
        assert!(
            matches!(
                wire::parse(&ack, state.conv),
                Some((wire::Segment::Ack { option: 0, next: 0, numbers, .. }, _))
                    if numbers == 1u32.to_be_bytes().as_slice()
            ),
            "a remote CLOSE is not our CLOSE acknowledgement"
        );

        // Existing locally queued bytes remain eligible for retransmission,
        // but also must not pretend the local application closed.
        let retry = state.next(now + Duration::from_millis(101)).unwrap();
        assert!(matches!(
            wire::parse(&retry, state.conv),
            Some((wire::Segment::Data { option: 0, number: 0, payload, .. }, _))
                if payload == b"request"
        ));
        assert_eq!(state.tx.len(), 1);
        assert_eq!(state.tx_bytes, 7);

        // The peer's missing retransmission completes the exact reply in
        // order even though its CLOSE was observed before these bytes.
        state.input(
            wire::Segment::Data {
                option: 1,
                time: 2,
                number: 0,
                sending_next: 0,
                payload: b"head",
            },
            now + Duration::from_millis(102),
        );
        let mut reply = Vec::new();
        while let Some(bytes) = state.ready.front().cloned() {
            reply.extend_from_slice(&bytes);
            state.delivered(bytes.len());
        }
        assert_eq!(reply, b"headtail");
        assert_eq!(state.rx_bytes, 0);
        assert!(state.reorder.is_empty());
        assert!(!state.finished());
        let ack = state.next(now + Duration::from_millis(102)).unwrap();
        assert!(matches!(
            wire::parse(&ack, state.conv),
            Some((
                wire::Segment::Ack {
                    option: 0,
                    next: 2,
                    ..
                },
                _
            ))
        ));

        // Local application EOF still advertises CLOSE on its next ACK and
        // pending DATA. Once our DATA is confirmed, termination keeps the
        // existing bounded closing deadline.
        state.app_end = true;
        state.input(
            wire::Segment::Control {
                command: 3,
                option: 1,
                sending_next: 0,
                receiving_next: 0,
                rto: 100,
            },
            now + Duration::from_millis(200),
        );
        let ack = state.next(now + Duration::from_millis(200)).unwrap();
        assert!(matches!(
            wire::parse(&ack, state.conv),
            Some((
                wire::Segment::Ack {
                    option: 1,
                    next: 2,
                    ..
                },
                _
            ))
        ));
        let retry = state.next(now + Duration::from_millis(302)).unwrap();
        assert!(matches!(
            wire::parse(&retry, state.conv),
            Some((wire::Segment::Data { option: 1, number: 0, payload, .. }, _))
                if payload == b"request"
        ));
        state.input(
            wire::Segment::Ack {
                option: 0,
                window: 100,
                next: 1,
                time: 0,
                numbers: &[],
            },
            now + Duration::from_millis(303),
        );
        let terminate = state.next(now + Duration::from_millis(303)).unwrap();
        assert!(matches!(
            wire::parse(&terminate, state.conv),
            Some((
                wire::Segment::Control {
                    command: 2,
                    option: 1,
                    ..
                },
                _
            ))
        ));
        assert!(!state.expired(now + Duration::from_secs(8)));
        assert!(state.expired(now + Duration::from_secs(9)));
    }

    #[tokio::test(start_paused = true)]
    async fn mkcp_memory_prefetch_backpressure_resumes_and_flushes() {
        use super::super::{
            connect,
            tests::{packets, reply},
        };
        use crate::session::Destination;
        use tokio::{io::AsyncWriteExt, sync::oneshot, time::timeout};
        use tokio_util::{sync::CancellationToken, task::TaskTracker};

        // A lower configured budget remains lower; a 1 MiB budget gains only
        // the prefetch cap, not a different configured wire-flight allowance.
        for (write_buffer, payload_len, slots) in [
            (64 * 1024, 128 * 1024 + 17, 47),
            (1024 * 1024, 512 * 1024 + 17, 801),
        ] {
            let options = MkcpOptions {
                tti: 20,
                uplink_capacity: 256,
                downlink_capacity: 256,
                read_buffer: 1024 * 1024,
                write_buffer,
                seed: Arc::from("memory queue"),
                ..MkcpOptions::default()
            };
            let state = State::new(
                options.clone(),
                1350,
                1362,
                2700,
                Arc::new(Shared::default()),
            )
            .unwrap();
            assert_eq!(state.mss, 1304);
            assert_eq!(state.tx_limit, write_buffer - 2700 - state.mss);
            assert_eq!(
                state.tx_slots, slots,
                "prefetch must not shrink configured wire flight"
            );
            drop(state);

            let expected: Vec<u8> = (0..payload_len).map(|n| (n % 251) as u8).collect();
            let (transport, mut incoming, output, closed) = packets();
            let address = "192.0.2.1:443".parse().unwrap();
            let peer = Destination::Ip(address);
            let mut codec = wire::Codec::new(&options).unwrap();
            let (initial_tx, initial_rx) = oneshot::channel();
            let (release_tx, mut release_rx) = oneshot::channel();
            let worker = tokio::spawn(async move {
                let mut initial_tx = Some(initial_tx);
                let mut released = false;
                let mut next = 0u32;
                let mut last_time = 0;
                let mut conversation = None;
                let mut reorder = BTreeMap::new();
                let mut bytes = Vec::new();
                loop {
                    tokio::select! {
                        result = &mut release_rx, if !released => {
                            result.unwrap();
                            released = true;
                            reply(&output, &mut codec, &peer,
                                wire::ack(conversation.unwrap(), 0, next.wrapping_add(1024), next, last_time, &[])).await;
                        }
                        packet = incoming.recv() => {
                            let Some(packet) = packet else { break; };
                            let plain = codec.open(&packet.payload, 1362).unwrap();
                            let conv = u16::from_be_bytes(plain[..2].try_into().unwrap());
                            conversation = Some(conv);
                            let (segment, size) = wire::parse(&plain, conv).unwrap();
                            assert_eq!(size, plain.len());
                            match segment {
                                wire::Segment::Data { number, time, payload, .. } => {
                                    last_time = time;
                                    if !before(number, next) {
                                        reorder.entry(number).or_insert_with(|| payload.to_vec());
                                    }
                                    while let Some(payload) = reorder.remove(&next) {
                                        bytes.extend_from_slice(&payload);
                                        next = next.wrapping_add(1);
                                    }
                                    // Consume initial wire credit, then hold every ACK.
                                    if next >= 32 && let Some(sender) = initial_tx.take() {
                                        sender.send(()).unwrap();
                                    }
                                    if released {
                                        reply(&output, &mut codec, &peer,
                                            wire::ack(conv, 0, next.wrapping_add(1024), next, time, &[number])).await;
                                    }
                                }
                                wire::Segment::Control { command: 2, .. } => break,
                                _ => {}
                            }
                        }
                    }
                }
                assert!(reorder.is_empty());
                bytes
            });

            let tasks = TaskTracker::new();
            let cancel = CancellationToken::new();
            let mut stream = connect(
                Box::new(transport),
                address,
                options,
                cancel.clone(),
                &tasks,
            )
            .unwrap();
            let payload = expected.clone();
            let (written_tx, mut written_rx) = oneshot::channel();
            let writer = tokio::spawn(async move {
                stream.write_all(&payload).await.unwrap();
                written_tx.send(()).unwrap();
                stream.flush().await.unwrap();
                stream
            });
            timeout(Duration::from_secs(1), initial_rx)
                .await
                .unwrap()
                .unwrap();
            assert!(
                timeout(Duration::from_millis(20), &mut written_rx)
                    .await
                    .is_err(),
                "application writes must backpressure before ACK, including smaller configured budgets"
            );
            release_tx.send(()).unwrap();
            let stream = timeout(Duration::from_secs(3), writer)
                .await
                .unwrap()
                .unwrap();
            written_rx.await.unwrap();
            drop(stream);
            tasks.close();
            timeout(Duration::from_secs(1), tasks.wait()).await.unwrap();
            let received = timeout(Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, expected);
            assert!(cancel.is_cancelled());
            assert!(closed.load(Ordering::Acquire));
        }
    }
}
