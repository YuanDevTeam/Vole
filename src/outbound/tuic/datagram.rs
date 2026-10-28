//! Per-connection associations; bounded per-association reassembly and delivery.
use super::wire::{self, Fragment};
use crate::{
    config::TuicUdpMode,
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    resources::observation::{self, ResourceKind},
    session::{Datagram, Destination},
    transport::quic::OwnedRuntime,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const TTL: Duration = Duration::from_secs(crate::limits::TUIC_FRAGMENT_TTL_SECONDS as u64);
const NATIVE_RECEIVE_EVENTS: usize = 512;

pub(super) struct Registry {
    state: Mutex<State>,
    mode: TuicUdpMode,
    native_payload_limit: u16,
    native_send_message_limit: usize,
}
#[derive(Default)]
struct State {
    next: u32,
    closed: bool,
    entries: HashMap<u16, Registration>,
}
struct Registration {
    _lease: super::activity::Lease,
    sender: mpsc::Sender<Datagram>,
    budget: u16,
    pending: Reassembly,
    _observation: observation::Guard,
}
impl Registry {
    #[cfg(test)]
    pub fn new(mode: TuicUdpMode) -> Self {
        Self::with_limit(
            mode,
            1252,
            crate::transport::quic::datagram_payload_limit(1281),
        )
    }
    pub fn with_limit(
        mode: TuicUdpMode,
        native_payload_limit: u16,
        native_send_message_limit: usize,
    ) -> Self {
        Self {
            state: Mutex::new(State::default()),
            mode,
            native_payload_limit,
            native_send_message_limit,
        }
    }
    fn payload_budget(&self, address_len: usize, message_limit: usize) -> DatagramBudget {
        let space = message_limit.saturating_sub(10 + address_len);
        DatagramBudget::new(
            space
                .min(if self.mode == TuicUdpMode::Quic {
                    usize::MAX
                } else {
                    self.native_payload_limit as usize
                })
                .saturating_mul(255)
                .min(u16::MAX as usize) as u16,
            u16::MAX,
        )
    }
    fn payload_limit(
        &self,
        address_len: usize,
        payload_size: usize,
        message_limit: usize,
    ) -> usize {
        if self.mode == TuicUdpMode::Quic {
            return usize::MAX;
        }
        let configured = self.native_payload_limit as usize;
        if payload_size <= configured
            && payload_size.saturating_add(10 + address_len) <= message_limit
        {
            configured
        } else {
            // A path-limited native retry reserves the IPv6 worst-case header,
            // independently of the actual first packet destination family.
            configured.min(message_limit.saturating_sub(29))
        }
    }
    pub fn open(
        self: &Arc<Self>,
        connection: quinn::Connection,
        cancel: CancellationToken,
        runtime: Arc<OwnedRuntime>,
        budget: DatagramBudget,
        lease: super::activity::Lease,
    ) -> Result<Option<Box<dyn DatagramTransport>>, DispatchError> {
        let mut state = self.state.lock().unwrap();
        if state.closed || cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        if state.next > u16::MAX as u32 {
            return Ok(None);
        }
        let id = state.next as u16;
        state.next += 1;
        let (sender, receiver) = mpsc::channel(crate::limits::TUIC_UDP_QUEUE);
        state.entries.insert(
            id,
            Registration {
                _lease: lease,
                sender,
                budget: budget.receive(),
                pending: Reassembly::default(),
                _observation: observation::track(ResourceKind::Association),
            },
        );
        Ok(Some(Box::new(Transport {
            id,
            packet: 0,
            connection,
            cancel,
            runtime,
            registry: self.clone(),
            receiver,
            budget,
            sent: false,
            closed: false,
            closing: None,
        })))
    }
    pub fn exhausted(&self) -> bool {
        self.state.lock().unwrap().next > u16::MAX as u32
    }
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.entries.clear();
    }
    fn budget(&self, id: u16) -> Option<u16> {
        self.state
            .lock()
            .unwrap()
            .entries
            .get(&id)
            .map(|entry| entry.budget)
    }
    fn deliver(&self, fragment: Fragment) {
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.entries.get_mut(&fragment.association)
            && let Some(datagram) =
                entry
                    .pending
                    .push(fragment, Instant::now(), entry.budget as usize)
        {
            let _ = entry.sender.try_send(datagram);
            observation::observe_queue(
                observation::QueueKind::TuicUdp,
                entry.sender.max_capacity() - entry.sender.capacity(),
                crate::limits::TUIC_UDP_QUEUE,
            );
        }
    }
    fn expire(&self) {
        for entry in self.state.lock().unwrap().entries.values_mut() {
            entry.pending.expire(Instant::now());
        }
    }
}

struct Transport {
    id: u16,
    packet: u16,
    connection: quinn::Connection,
    cancel: CancellationToken,
    runtime: Arc<OwnedRuntime>,
    registry: Arc<Registry>,
    receiver: mpsc::Receiver<Datagram>,
    budget: DatagramBudget,
    sent: bool,
    closed: bool,
    closing: Option<oneshot::Receiver<()>>,
}

impl Transport {
    fn close_local(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let present = self
            .registry
            .state
            .lock()
            .unwrap()
            .entries
            .remove(&self.id)
            .is_some();
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
        if present && self.sent && !self.cancel.is_cancelled() {
            let connection = self.connection.clone();
            let id = self.id;
            let (done, wait) = oneshot::channel();
            self.closing = Some(wait);
            // Cancellation of close/Drop cannot orphan a control task. Quinn's
            // owned runtime joins or cancels it during node Stop.
            let _ = self.runtime.spawn_owned(async move {
                let _ = tokio::time::timeout(crate::transport::quic::CLOSE_TIMEOUT, async {
                    let mut stream = connection.open_uni().await.map_err(super::failure)?;
                    let [hi, lo] = id.to_be_bytes();
                    AsyncWriteExt::write_all(&mut stream, &[5, 3, hi, lo]).await?;
                    stream.finish().map_err(super::failure)
                })
                .await;
                let _ = done.send(());
            });
        }
    }
    fn message_limit(&self) -> usize {
        match self.registry.mode {
            TuicUdpMode::Native => self
                .connection
                .max_datagram_size()
                .unwrap_or(0)
                .min(self.registry.native_send_message_limit),
            TuicUdpMode::Quic => u16::MAX as usize + 10 + 259,
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.close_local();
    }
}

#[async_trait]
impl DatagramTransport for Transport {
    fn supports_shared_destinations(&self) -> bool {
        // Both modes carry a per-packet address and consume an ID before
        // awaiting capacity. Cancelling a partial QUIC send resets that stream;
        // the router owns target and cancellation identity.
        true
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        let budget = match wire::address_len(peer) {
            Ok(address_len) => self
                .registry
                .payload_budget(address_len, self.message_limit()),
            Err(_) => DatagramBudget::new(0, u16::MAX),
        };
        budget.intersect(self.budget)
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.closed || self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        let address_len = wire::address_len(&datagram.remote)?;
        // Snapshot this logical send once; Quinn still validates the current
        // path when each fragment is sent. Never cache the limit across sends.
        let message_limit = self.message_limit();
        let budget = self
            .registry
            .payload_budget(address_len, message_limit)
            .intersect(self.budget);
        if datagram.payload.len() > budget.transmit() as usize {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let packets = wire::packets_with_payload_limit(
            self.id,
            self.packet,
            &datagram.remote,
            &datagram.payload,
            message_limit,
            self.registry
                .payload_limit(address_len, datagram.payload.len(), message_limit),
        )?;
        // Consume the ID before the first await: cancelling a partial send
        // never reuses that unfinished packet or replays its business bytes.
        self.packet = self.packet.wrapping_add(1);
        self.sent = true;
        for (index, packet) in packets.into_iter().enumerate() {
            tokio::select! { biased;
                ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
                result=async {
                    match self.registry.mode {
                        TuicUdpMode::Native=>self.connection.send_datagram_wait(packet).await.map_err(super::failure),
                        TuicUdpMode::Quic=>{
                            let stream=self.connection.open_uni().await.map_err(super::failure)?;
                            let mut stream=UniSend(Some(stream));
                            AsyncWriteExt::write_all(stream.0.as_mut().unwrap(),&packet).await.map_err(super::failure)?;
                            stream.0.take().unwrap().finish().map_err(super::failure)
                        }
                    }
                } => result?,
            }
            if (index + 1) % crate::limits::IO_POLL_BUDGET == 0 {
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.closed {
            return Err(DispatchError::NotAllowed);
        }
        tokio::select! { biased;
            ()=self.cancel.cancelled()=>Err(DispatchError::NotAllowed),
            packet=self.receiver.recv()=>packet.ok_or(DispatchError::ConnectionRefused),
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.close_local();
        if let Some(wait) = self.closing.as_mut() {
            let _ = wait.await;
        }
        self.closing = None;
        Ok(())
    }
}
struct UniSend(Option<quinn::SendStream>);
impl Drop for UniSend {
    fn drop(&mut self) {
        if let Some(mut stream) = self.0.take() {
            let _ = stream.reset(0_u8.into());
        }
    }
}

struct Pending {
    peer: Option<Destination>,
    pieces: Vec<Option<Bytes>>,
    bytes: usize,
    received: usize,
    expires: Instant,
    _observation: observation::Guard,
}
#[derive(Default)]
struct Reassembly {
    packets: HashMap<u16, Pending>,
    bytes: usize,
}
impl Reassembly {
    fn remove(&mut self, id: u16) -> Option<Pending> {
        let p = self.packets.remove(&id)?;
        self.bytes -= p.bytes;
        Some(p)
    }
    fn expire(&mut self, now: Instant) {
        self.packets.retain(|_, p| {
            if p.expires <= now {
                self.bytes -= p.bytes;
                false
            } else {
                true
            }
        });
    }
    fn push(&mut self, f: Fragment, now: Instant, budget: usize) -> Option<Datagram> {
        self.expire(now);
        if f.payload.len() > budget {
            return None;
        }
        if f.count == 1 {
            self.remove(f.packet);
            return Some(Datagram {
                remote: f.peer?,
                payload: f.payload,
                sniffed_domain: None,
            });
        }
        if !self.packets.contains_key(&f.packet) {
            if self.packets.len() >= crate::limits::TUIC_PENDING_PACKETS {
                // An abandoned partial must not block fresh packets until TTL.
                // Expiry is fixed at admission, so its order also identifies
                // the oldest retained partial without another queue or clock.
                let oldest = self
                    .packets
                    .iter()
                    .min_by_key(|(packet, pending)| (pending.expires, **packet))
                    .map(|(&packet, _)| packet);
                if let Some(packet) = oldest {
                    self.remove(packet);
                }
            }
            self.packets.insert(
                f.packet,
                Pending {
                    peer: None,
                    pieces: vec![None; f.count as usize],
                    bytes: 0,
                    received: 0,
                    expires: now + TTL,
                    _observation: observation::track(ResourceKind::Reassembly),
                },
            );
        }
        let p = self.packets.get_mut(&f.packet).unwrap();
        if p.pieces.len() != f.count as usize
            || (f.index == 0 && p.peer.is_some() && p.peer != f.peer)
        {
            self.remove(f.packet);
            return None;
        }
        if let Some(previous) = &p.pieces[f.index as usize] {
            if previous != &f.payload {
                self.remove(f.packet);
            }
            return None;
        }
        if p.bytes + f.payload.len() > budget
            || self.bytes + f.payload.len() > crate::limits::TUIC_PENDING_BYTES
        {
            self.remove(f.packet);
            return None;
        }
        if f.index == 0 {
            p.peer = f.peer;
        }
        p.bytes += f.payload.len();
        self.bytes += f.payload.len();
        p.received += 1;
        p.pieces[f.index as usize] = Some(f.payload);
        if p.received != p.pieces.len() {
            return None;
        }
        let p = self.remove(f.packet).unwrap();
        let mut payload = Vec::with_capacity(p.bytes);
        for piece in p.pieces {
            payload.extend_from_slice(&piece.unwrap());
        }
        Some(Datagram {
            remote: p.peer?,
            payload: payload.into(),
            sniffed_domain: None,
        })
    }
}

pub(super) async fn receive(
    connection: &quinn::Connection,
    registry: &Registry,
) -> Result<(), DispatchError> {
    let mut streams = FuturesUnordered::new();
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let poll_budget = if registry.mode == TuicUdpMode::Native {
        NATIVE_RECEIVE_EVENTS
    } else {
        crate::limits::IO_POLL_BUDGET
    };
    let mut count = 0;
    loop {
        tokio::select! {
            _=expiry.tick()=>registry.expire(),
            result=connection.read_datagram()=>{
                let raw=result.map_err(|_|DispatchError::ConnectionRefused)?;
                // A peer's fragmentation is independent of our send frame
                // limit. The physical adapter already enforces its RX budget.
                // Reject unknown associations and excess declared payload
                // before allocating an address or reassembly state.
                if registry.mode==TuicUdpMode::Native
                    && raw.len()<=crate::limits::TUIC_QUIC_PAYLOAD
                    && let Some(header)=raw.get(..10)
                    && let Some(budget)=registry.budget(u16::from_be_bytes([header[2],header[3]]))
                    && u16::from_be_bytes([header[8],header[9]])<=budget
                    && let Ok(fragment)=wire::decode(raw)
                { registry.deliver(fragment); }
            },
            stream=connection.accept_uni(),if streams.len()<crate::limits::TUIC_CONTROL_READERS=>{
                let stream=stream.map_err(|_|DispatchError::ConnectionRefused)?;
                if registry.mode==TuicUdpMode::Quic {
                    streams.push(tokio::time::timeout(TTL,wire::read_packet(stream,|id|registry.budget(id))));
                }
            },
            Some(result)=streams.next(),if !streams.is_empty()=>{
                if let Ok(Ok(fragment))=result { registry.deliver(fragment); }
            },
        }
        count += 1;
        if count % poll_budget == 0 {
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_snapshot_preserves_native_path_retry_and_configured_fragment_limits() {
        let registry = Registry::with_limit(TuicUdpMode::Native, 1252, 1200);
        for (peer, length, expected) in [
            (
                Destination::Ip("192.0.2.1:53".parse().unwrap()),
                1183,
                vec![1183],
            ),
            (
                Destination::Ip("192.0.2.1:53".parse().unwrap()),
                1184,
                vec![1171, 13],
            ),
            (
                Destination::Ip("[::1]:53".parse().unwrap()),
                1171,
                vec![1171],
            ),
            (
                Destination::Ip("[::1]:53".parse().unwrap()),
                1172,
                vec![1171, 1],
            ),
        ] {
            let address_len = wire::address_len(&peer).unwrap();
            let payload = vec![0x5a; length];
            let packets = wire::packets_with_payload_limit(
                7,
                u16::MAX,
                &peer,
                &payload,
                1200,
                registry.payload_limit(address_len, length, 1200),
            )
            .unwrap();
            let decoded: Vec<_> = packets
                .into_iter()
                .map(|p| wire::decode(p).unwrap())
                .collect();
            assert_eq!(
                decoded.iter().map(|p| p.payload.len()).collect::<Vec<_>>(),
                expected
            );
            assert_eq!(decoded[0].peer.as_ref(), Some(&peer));
            assert!(decoded.iter().skip(1).all(|p| p.peer.is_none()));
            assert!(
                decoded
                    .iter()
                    .all(|p| p.association == 7 && p.packet == u16::MAX)
            );
            assert_eq!(
                decoded
                    .iter()
                    .flat_map(|p| p.payload.iter().copied())
                    .collect::<Vec<_>>(),
                payload
            );
        }
        let configured = Registry::with_limit(TuicUdpMode::Native, 1000, 1200);
        assert_eq!(configured.payload_limit(7, 1001, 1200), 1000);
        let conservative = Registry::with_limit(TuicUdpMode::Native, 1252, 30);
        assert_eq!(conservative.payload_limit(7, 13, 30), 1252);
        assert_eq!(conservative.payload_limit(7, 14, 30), 1);
    }

    #[test]
    fn message_snapshot_preserves_directional_budgets_empty_frames_and_quic_limit() {
        let native = Registry::with_limit(TuicUdpMode::Native, 1, 1200);
        assert_eq!(
            native.payload_budget(7, 1200),
            DatagramBudget::new(255, u16::MAX)
        );
        assert_eq!(
            native.payload_budget(7, 17),
            DatagramBudget::new(0, u16::MAX)
        );
        let caller = DatagramBudget::new(200, 1200);
        assert_eq!(
            native.payload_budget(7, 1200).intersect(caller),
            DatagramBudget::new(200, 1200)
        );
        let peer = Destination::Ip("192.0.2.1:53".parse().unwrap());
        let empty =
            wire::packets_with_payload_limit(1, 2, &peer, &[], 17, native.payload_limit(7, 0, 17))
                .unwrap();
        assert_eq!(empty.len(), 1);
        assert_eq!(
            empty[0].as_ref(),
            b"\x05\x02\x00\x01\x00\x02\x01\x00\x00\x00\x01\xc0\x00\x02\x01\x00\x35"
        );
        assert!(
            wire::packets_with_payload_limit(1, 2, &peer, &[], 16, native.payload_limit(7, 0, 16),)
                .is_err()
        );
        let quic = Registry::with_limit(TuicUdpMode::Quic, 1, 1200);
        assert_eq!(
            quic.payload_budget(259, u16::MAX as usize + 10 + 259),
            DatagramBudget::new(u16::MAX, u16::MAX)
        );
        assert_eq!(quic.payload_limit(259, u16::MAX as usize, 1200), usize::MAX);
    }
    fn fragment(id: u16, index: u8, payload: Bytes) -> Fragment {
        Fragment {
            association: 0,
            packet: id,
            count: 2,
            index,
            peer: if index == 0 {
                Some(Destination::domain("x", 80).unwrap())
            } else {
                None
            },
            payload,
        }
    }
    #[test]
    fn shared_native_partial_fragments_keep_destination_and_packet_id_boundaries() {
        let first = Destination::Ip("198.51.100.1:443".parse().unwrap());
        let second = Destination::Ip("[2001:db8::2]:8443".parse().unwrap());
        let old =
            wire::packets_with_payload_limit(7, u16::MAX, &first, b"old-tail", 64, 4).unwrap();
        let fresh = wire::packets_with_payload_limit(7, 0, &second, b"new-body", 64, 4).unwrap();
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        // Model a send cancelled after its first complete native fragment.
        // The next ID may wrap, but must retain its independent destination.
        assert!(
            reassembly
                .push(wire::decode(old[0].clone()).unwrap(), now, 8)
                .is_none()
        );
        assert!(
            reassembly
                .push(wire::decode(fresh[1].clone()).unwrap(), now, 8)
                .is_none()
        );
        let packet = reassembly
            .push(wire::decode(fresh[0].clone()).unwrap(), now, 8)
            .unwrap();
        assert_eq!(packet.remote, second);
        assert_eq!(packet.payload, b"new-body"[..]);
        assert_eq!(reassembly.packets.len(), 1);
        reassembly.expire(now + TTL);
        assert!(reassembly.packets.is_empty());
        assert_eq!(reassembly.bytes, 0);
        // A late tail cannot borrow the later packet's address or payload.
        assert!(
            reassembly
                .push(wire::decode(old[1].clone()).unwrap(), now + TTL, 8)
                .is_none()
        );
    }

    #[test]
    fn reassembly_releases_completed_ids_and_orders_duplicates_without_cross_packet_mix() {
        let _case = crate::resources::case_events::Case::new("TUIC-UNIT", "reassembly_order");
        let mut r = Reassembly::default();
        let now = Instant::now();
        for id in [65535, 0, 65535] {
            assert!(
                r.push(fragment(id, 1, Bytes::from_static(b"tail")), now, 8)
                    .is_none()
            );
            assert!(
                r.push(fragment(id, 1, Bytes::from_static(b"tail")), now, 8)
                    .is_none()
            );
            assert_eq!(r.bytes, 4);
            let packet = r
                .push(fragment(id, 0, Bytes::from_static(b"head")), now, 8)
                .unwrap();
            assert_eq!(packet.payload, b"headtail"[..]);
            assert_eq!(packet.remote, Destination::domain("x", 80).unwrap());
            assert!(r.packets.is_empty());
            assert_eq!(r.bytes, 0);
        }
        r.push(fragment(0, 1, Bytes::from_static(b"a")), now, 8);
        r.push(fragment(0, 1, Bytes::from_static(b"b")), now, 8);
        assert!(r.packets.is_empty());
    }
    #[test]
    fn fresh_packet_progresses_when_old_partial_slots_are_full() {
        let _case =
            crate::resources::case_events::Case::new("TUIC-UNIT", "reassembly_fresh_progress");
        let now = Instant::now();
        let mut r = Reassembly::default();
        for id in 0..crate::limits::TUIC_PENDING_PACKETS {
            assert!(
                r.push(
                    fragment(id as u16, 0, Bytes::from_static(b"x")),
                    now + Duration::from_nanos(id as u64),
                    1200,
                )
                .is_none()
            );
        }
        assert_eq!(r.packets.len(), crate::limits::TUIC_PENDING_PACKETS);
        assert_eq!(r.bytes, crate::limits::TUIC_PENDING_PACKETS);
        let id = crate::limits::TUIC_PENDING_PACKETS as u16;
        let target = Destination::Ip("198.51.100.2:443".parse().unwrap());
        let mut head = fragment(id, 0, Bytes::from_static(b"fresh-"));
        head.peer = Some(target.clone());
        assert!(r.push(head, now + Duration::from_millis(1), 1200).is_none());
        let packet = r
            .push(
                fragment(id, 1, Bytes::from_static(b"payload")),
                now + Duration::from_millis(2),
                1200,
            )
            .expect("a fresh complete packet must progress before old partials expire");
        assert_eq!(packet.remote, target);
        assert_eq!(packet.payload, b"fresh-payload"[..]);
        assert!(!r.packets.contains_key(&0));
        assert!(r.packets.contains_key(&1));
        assert!(!r.packets.contains_key(&id));
        assert_eq!(r.packets.len(), crate::limits::TUIC_PENDING_PACKETS - 1);
        assert_eq!(r.bytes, crate::limits::TUIC_PENDING_PACKETS - 1);
    }
    #[test]
    fn partial_packets_expire_and_both_resource_bounds_are_per_association() {
        let _case = crate::resources::case_events::Case::new("TUIC-UNIT", "reassembly_limits");
        let now = Instant::now();
        let mut r = Reassembly::default();
        for id in 0..65 {
            r.push(fragment(id, 1, Bytes::new()), now, 65535);
        }
        assert_eq!(r.packets.len(), 64);
        assert_eq!(r.bytes, 0);
        let mut other = Reassembly::default();
        other.push(fragment(64, 0, Bytes::new()), now, 65535);
        assert_eq!(other.packets.len(), 1);
        r.expire(now + TTL - Duration::from_nanos(1));
        assert_eq!(r.packets.len(), 64);
        r.expire(now + TTL);
        assert!(r.packets.is_empty());
        for id in 0..4 {
            r.push(fragment(id, 1, vec![1; 65535].into()), now, 65535);
        }
        r.push(fragment(4, 1, Bytes::from_static(b"1234")), now, 65535);
        assert_eq!(r.bytes, 256 * 1024);
        r.push(fragment(5, 1, Bytes::from_static(b"x")), now, 65535);
        assert_eq!(r.bytes, 256 * 1024);
        assert!(!r.packets.contains_key(&5));
        // Packet-level budget is independent from the owner-wide byte cap.
        other.push(fragment(3, 0, Bytes::from_static(b"ab")), now, 2);
        assert!(
            other
                .push(fragment(3, 1, Bytes::from_static(b"x")), now, 2)
                .is_none()
        );
        assert!(!other.packets.contains_key(&3));
        r.expire(now + TTL);
        assert_eq!(r.bytes, 0);
    }
    #[test]
    fn unknown_associations_do_not_allocate_and_full_queues_drop_complete_packets() {
        let _case = crate::resources::case_events::Case::new("TUIC-UNIT", "delivery_limits");
        let probe = observation::ResourceProbe::default();
        probe.scope_sync(|| {
            let registry = Registry::new(TuicUdpMode::Native);
            registry.deliver(fragment(0, 1, Bytes::from_static(b"x")));
            assert!(probe.snapshot().is_idle());
            let (sender, mut receiver) = mpsc::channel(crate::limits::TUIC_UDP_QUEUE);
            registry.state.lock().unwrap().entries.insert(
                0,
                Registration {
                    _lease: Arc::new(super::super::activity::Activity::default()).acquire(),
                    sender,
                    budget: 1,
                    pending: Reassembly::default(),
                    _observation: observation::track(ResourceKind::Association),
                },
            );
            for byte in 0..33 {
                let mut f = fragment(byte, 0, vec![byte as u8].into());
                f.count = 1;
                registry.deliver(f);
            }
            let mut count = 0;
            while let Ok(packet) = receiver.try_recv() {
                assert_eq!(packet.payload, vec![count]);
                count += 1;
            }
            assert_eq!(count, 32);
            let mut f = fragment(0, 0, Bytes::from_static(b"xx"));
            f.count = 1;
            registry.deliver(f);
            assert!(receiver.try_recv().is_err());
            registry.close();
            assert!(probe.snapshot().is_idle());
            let queue = probe
                .queues()
                .into_iter()
                .find(|q| q.kind == observation::QueueKind::TuicUdp)
                .unwrap();
            assert_eq!((queue.peak, queue.capacity), (32, 32));
        });
    }
}
