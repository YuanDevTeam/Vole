//! Raw QUIC DATAGRAM sessions; authenticated connection ownership stays in the node.
use crate::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    resources::observation::{self, ResourceKind},
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

// Both the official native implementation and Mihomo bound relay payloads to
// 4096 bytes. udp-mtu is the *fragment message* budget, not this payload limit.
pub(super) const MAX_PAYLOAD: usize = crate::limits::HY2_UDP_PAYLOAD;
const QUEUE: usize = crate::limits::HY2_UDP_QUEUE;
const PENDING_PACKETS: usize = crate::limits::HY2_PENDING_PACKETS;
const PENDING_BYTES: usize = crate::limits::HY2_PENDING_BYTES;
const TTL: Duration = Duration::from_secs(crate::limits::HY2_FRAGMENT_TTL_SECONDS as u64);

#[derive(Default)]
pub(super) struct Registry {
    next: AtomicU32,
    entries: Mutex<HashMap<u32, Registration>>,
}
struct Registration {
    sender: mpsc::Sender<Datagram>,
    budget: u16,
    _observation: observation::Guard,
}

impl Registry {
    pub fn open(
        self: &Arc<Self>,
        connection: quinn::Connection,
        cancel: CancellationToken,
        mtu: u16,
        budget: DatagramBudget,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let id = self
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| DispatchError::NotAllowed)?;
        let (sender, receiver) = mpsc::channel(QUEUE);
        let mut entries = self.entries.lock().unwrap();
        if cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        entries.insert(
            id,
            Registration {
                sender,
                budget: budget.receive(),
                _observation: observation::track(ResourceKind::Association),
            },
        );
        Ok(Box::new(Transport {
            id,
            packet: 0,
            connection,
            cancel,
            registry: self.clone(),
            receiver,
            mtu,
            budget,
            closed: false,
        }))
    }
    pub fn close(&self) {
        self.entries.lock().unwrap().clear();
    }
}

struct Transport {
    id: u32,
    packet: u16,
    connection: quinn::Connection,
    cancel: CancellationToken,
    registry: Arc<Registry>,
    receiver: mpsc::Receiver<Datagram>,
    mtu: u16,
    budget: DatagramBudget,
    closed: bool,
}
impl Transport {
    fn close_local(&mut self) {
        self.closed = true;
        self.registry.entries.lock().unwrap().remove(&self.id);
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
    }
    fn message_budget(&self) -> usize {
        self.connection
            .max_datagram_size()
            .unwrap_or(0)
            .min(usize::from(self.mtu))
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
        // A session ID owns a multi-target UDP socket, not one destination.
        // Each complete message carries the reply source for demultiplexing.
        true
    }

    fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
        let space = self.message_budget().saturating_sub(header(peer).len());
        DatagramBudget::new((space * 255).min(MAX_PAYLOAD) as u16, MAX_PAYLOAD as u16)
            .intersect(self.budget)
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.closed || self.cancel.is_cancelled() {
            return Err(DispatchError::NotAllowed);
        }
        if datagram.payload.len() > usize::from(self.payload_budget(&datagram.remote).transmit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria2 datagram exceeds payload budget",
            )
            .into());
        }
        let packets = encode(
            self.id,
            self.packet,
            &datagram.remote,
            &datagram.payload,
            self.message_budget(),
        )?;
        self.packet = self.packet.wrapping_add(1);
        for (index, packet) in packets.into_iter().enumerate() {
            tokio::select! {biased;
                () = self.cancel.cancelled() => return Err(DispatchError::NotAllowed),
                result = self.connection.send_datagram_wait(packet) => result.map_err(|_| DispatchError::ConnectionRefused)?,
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
        tokio::select! {biased;
            () = self.cancel.cancelled() => Err(DispatchError::NotAllowed),
            received = self.receiver.recv() => received.ok_or(DispatchError::ConnectionRefused),
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.close_local();
        Ok(())
    }
}

fn header(peer: &Destination) -> Vec<u8> {
    let address = peer.authority();
    let mut header = vec![0; 8];
    super::wire::encode_varint(address.len() as u64, &mut header);
    header.extend_from_slice(address.as_bytes());
    header
}

fn encode(
    session: u32,
    packet: u16,
    peer: &Destination,
    payload: &[u8],
    mtu: usize,
) -> io::Result<Vec<Bytes>> {
    if payload.len() > MAX_PAYLOAD || peer.port() == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut header = header(peer);
    let space = mtu
        .checked_sub(header.len())
        .filter(|space| *space > 0)
        .ok_or(io::ErrorKind::InvalidInput)?;
    let count = payload.len().max(1).div_ceil(space);
    if count > 255 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    header[..4].copy_from_slice(&session.to_be_bytes());
    header[4..6].copy_from_slice(&packet.to_be_bytes());
    header[7] = count as u8;
    let mut messages = Vec::with_capacity(count);
    for index in 0..count {
        let mut bytes = header.clone();
        bytes[6] = index as u8;
        bytes.extend_from_slice(
            &payload[(index * space).min(payload.len())..((index + 1) * space).min(payload.len())],
        );
        messages.push(bytes.into());
    }
    Ok(messages)
}

struct Fragment {
    session: u32,
    packet: u16,
    index: u8,
    count: u8,
    peer: Destination,
    payload: Bytes,
}
fn decode(mut bytes: Bytes) -> io::Result<Fragment> {
    if bytes.len() < 9 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let session = bytes.get_u32();
    let packet = bytes.get_u16();
    let index = bytes.get_u8();
    let count = bytes.get_u8();
    // In an unfragmented packet, the protocol says fragment and packet IDs
    // are irrelevant. Do not reject peers which use a nonzero fragment ID.
    if count == 0 || (count > 1 && index >= count) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let first = bytes.get_u8();
    let size = 1_usize << (first >> 6);
    if bytes.len() < size - 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut length = u64::from(first & 0x3f);
    for _ in 1..size {
        length = (length << 8) | u64::from(bytes.get_u8());
    }
    if length == 0 || length > 512 || bytes.len() < length as usize {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let address = bytes.split_to(length as usize);
    let address = std::str::from_utf8(&address).map_err(|_| io::ErrorKind::InvalidData)?;
    let peer = Destination::from_authority(address).map_err(|_| io::ErrorKind::InvalidData)?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Fragment {
        session,
        packet,
        index,
        count,
        peer,
        payload: bytes,
    })
}

struct Pending {
    peer: Destination,
    expires: Instant,
    pieces: Vec<Option<Bytes>>,
    bytes: usize,
    received: usize,
    _observation: observation::Guard,
}
#[derive(Default)]
struct Reassembly {
    packets: HashMap<(u32, u16), Pending>,
    bytes: usize,
}
impl Reassembly {
    fn remove(&mut self, key: &(u32, u16)) -> Option<Pending> {
        let packet = self.packets.remove(key)?;
        self.bytes -= packet.bytes;
        Some(packet)
    }
    fn expire(&mut self, now: Instant, live: impl Fn(u32) -> bool) {
        self.packets.retain(|&(session, _), packet| {
            let keep = packet.expires > now && live(session);
            if !keep {
                self.bytes -= packet.bytes;
            }
            keep
        });
    }
    fn push(&mut self, fragment: Fragment, now: Instant, budget: usize) -> Option<Datagram> {
        if fragment.payload.len() > budget {
            return None;
        }
        if fragment.count == 1 {
            return Some(Datagram {
                remote: fragment.peer,
                payload: fragment.payload,
                sniffed_domain: None,
            });
        }
        let key = (fragment.session, fragment.packet);
        if self
            .packets
            .get(&key)
            .is_some_and(|packet| packet.expires <= now)
        {
            self.remove(&key);
        }
        if !self.packets.contains_key(&key) {
            if self.packets.len() >= PENDING_PACKETS {
                return None;
            }
            self.packets.insert(
                key,
                Pending {
                    peer: fragment.peer.clone(),
                    expires: now + TTL,
                    pieces: vec![None; usize::from(fragment.count)],
                    bytes: 0,
                    received: 0,
                    _observation: observation::track(ResourceKind::Reassembly),
                },
            );
        }
        let packet = self.packets.get_mut(&key).unwrap();
        if packet.peer != fragment.peer || packet.pieces.len() != usize::from(fragment.count) {
            self.remove(&key);
            return None;
        }
        if let Some(prior) = &packet.pieces[usize::from(fragment.index)] {
            if prior != &fragment.payload {
                self.remove(&key);
            }
            return None;
        }
        if packet.bytes + fragment.payload.len() > budget.min(MAX_PAYLOAD)
            || self.bytes + fragment.payload.len() > PENDING_BYTES
        {
            self.remove(&key);
            return None;
        }
        self.bytes += fragment.payload.len();
        packet.bytes += fragment.payload.len();
        packet.received += 1;
        packet.pieces[usize::from(fragment.index)] = Some(fragment.payload);
        if packet.received != packet.pieces.len() {
            return None;
        }
        let packet = self.remove(&key).unwrap();
        let mut payload = Vec::with_capacity(packet.bytes);
        for piece in packet.pieces {
            payload.extend_from_slice(&piece.unwrap());
        }
        // A Packet ID only identifies an unfinished assembly, not a replay
        // nonce. Native Hysteria uses random u16 IDs; like Mihomo, release the
        // completed ID immediately so a later legal reply is not suppressed.
        Some(Datagram {
            remote: packet.peer,
            payload: payload.into(),
            sniffed_domain: None,
        })
    }
}

pub(super) async fn receive(
    connection: &quinn::Connection,
    registry: &Registry,
) -> Result<(), DispatchError> {
    let mut pending = Reassembly::default();
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut processed = 0;
    loop {
        let raw = tokio::select! {biased;
            _ = timer.tick() => {
                let entries = registry.entries.lock().unwrap();
                pending.expire(Instant::now(), |id| entries.contains_key(&id));
                continue;
            },
            data = connection.read_datagram() => data.map_err(|_| DispatchError::ConnectionRefused)?,
        };
        // Malformed/unknown/full packets are dropped, never queued without a
        // live local association and never allowed to fail sibling sessions.
        {
            if let Ok(fragment) = decode(raw) {
                let entries = registry.entries.lock().unwrap();
                if let Some(entry) = entries.get(&fragment.session)
                    && let Some(datagram) =
                        pending.push(fragment, Instant::now(), usize::from(entry.budget))
                    && let Ok(permit) = entry.sender.try_reserve()
                {
                    crate::resources::observation::observe_queue(
                        crate::resources::observation::QueueKind::Hysteria2Udp,
                        crate::limits::HY2_UDP_QUEUE - entry.sender.capacity(),
                        crate::limits::HY2_UDP_QUEUE,
                    );
                    permit.send(datagram);
                }
            }
        }
        processed += 1;
        if processed == crate::limits::IO_POLL_BUDGET {
            processed = 0;
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_wire_round_trips_at_budget_and_bounds_malformed_fragments() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "HYSTERIA2-UNIT",
            "udp_wire_round_trips_at_budget_and_bounds_malformed_fragments",
        );
        let peer = Destination::domain("x", 1).unwrap();
        let literal = Bytes::from_static(b"\0\0\0\x01\0\x02\0\x01\x03x:1payload");
        assert_eq!(
            encode(1, 2, &peer, b"payload", 1197).unwrap(),
            vec![literal.clone()]
        );
        let parsed = decode(literal).unwrap();
        assert_eq!((parsed.session, parsed.packet, parsed.count), (1, 2, 1));
        assert_eq!(parsed.payload, b"payload"[..]);
        assert_eq!(parsed.peer, peer);
        for size in [0, 1, 64, 512, 1200, 4096] {
            for mtu in [64, 1197, 1400] {
                let payload = vec![7; size];
                let frames = encode(1, 3, &peer, &payload, mtu).unwrap();
                assert!(frames.iter().all(|frame| frame.len() <= mtu));
                let mut state = Reassembly::default();
                let mut result = None;
                for frame in frames.into_iter().rev() {
                    result = state
                        .push(decode(frame).unwrap(), Instant::now(), 4096)
                        .or(result);
                }
                assert_eq!(result.unwrap().payload, payload);
                assert_eq!(state.bytes, 0);
            }
        }
        assert!(encode(1, 3, &peer, &vec![0; 4097], 1400).is_err());
        assert!(encode(1, 3, &peer, b"x", 12).is_err());
        for bad in [
            b"".as_slice(),
            b"\0\0\0\0\0\0\0\0\x01x",
            b"\0\0\0\0\0\0\x02\x02\x03x:1",
            b"\0\0\0\0\0\0\0\x01\xff",
            b"\0\0\0\0\0\0\0\x01\x40\x00",
            b"\0\0\0\0\0\0\0\x01\x01x",
        ] {
            assert!(decode(Bytes::copy_from_slice(bad)).is_err());
        }
    }

    #[test]
    fn udp_reassembly_isolates_sources_duplicates_counts_bytes_and_expiry() {
        #[cfg(feature = "interop-test")]
        let _case = crate::resources::case_events::Case::new(
            "HYSTERIA2-UNIT",
            "udp_reassembly_isolates_sources_duplicates_counts_bytes_and_expiry",
        );
        let now = Instant::now();
        let peer = Destination::domain("x", 1).unwrap();
        let frames = encode(1, 2, &peer, &[5; 100], 64).unwrap();
        let mut state = Reassembly::default();
        assert!(
            state
                .push(decode(frames[1].clone()).unwrap(), now, 100)
                .is_none()
        );
        assert!(
            state
                .push(decode(frames[1].clone()).unwrap(), now, 100)
                .is_none()
        );
        assert_eq!(
            state
                .push(decode(frames[0].clone()).unwrap(), now, 100)
                .unwrap()
                .payload,
            [5; 100][..]
        );
        // Duplicate pieces of an unfinished packet are ignored above; once
        // delivered, the ID may immediately identify another full datagram.
        assert!(
            state
                .push(decode(frames[0].clone()).unwrap(), now, 100)
                .is_none()
        );
        assert_eq!(
            state
                .push(decode(frames[1].clone()).unwrap(), now, 100)
                .unwrap()
                .payload,
            [5; 100][..]
        );
        state.expire(now + TTL, |_| true);
        assert!(
            state
                .push(decode(frames[0].clone()).unwrap(), now + TTL, 99)
                .is_none()
        );
        assert!(
            state
                .push(decode(frames[1].clone()).unwrap(), now + TTL, 99)
                .is_none()
        );
        assert!(state.packets.is_empty());
        for mutation in [0, 1, 2] {
            assert!(
                state
                    .push(decode(frames[0].clone()).unwrap(), now, 4096)
                    .is_none()
            );
            let mut bad = decode(frames[0].clone()).unwrap();
            match mutation {
                0 => bad.peer = Destination::domain("other", 1).unwrap(),
                1 => bad.count += 1,
                _ => bad.payload = Bytes::from_static(b"different"),
            }
            assert!(state.push(bad, now, 4096).is_none());
            assert!(state.packets.is_empty());
            assert_eq!(state.bytes, 0);
        }
        for session in 0..64 {
            assert!(
                state
                    .push(
                        Fragment {
                            session,
                            packet: 9,
                            index: 0,
                            count: 2,
                            peer: peer.clone(),
                            payload: vec![0; 4096].into()
                        },
                        now,
                        4096
                    )
                    .is_none()
            );
        }
        assert_eq!(state.packets.len(), 64);
        assert_eq!(state.bytes, 256 * 1024);
        assert!(
            state
                .push(
                    Fragment {
                        session: 65,
                        packet: 9,
                        index: 0,
                        count: 2,
                        peer: peer.clone(),
                        payload: Bytes::from_static(b"x")
                    },
                    now,
                    4096
                )
                .is_none()
        );
        assert_eq!(state.packets.len(), 64);
        state.expire(now + Duration::from_secs(4), |session| session != 0);
        assert_eq!(state.packets.len(), 63);
        assert_eq!(state.bytes, 63 * 4096);
        state.expire(now + TTL, |_| true);
        assert!(state.packets.is_empty());
        assert_eq!(state.bytes, 0);
    }
}
