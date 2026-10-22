//! Reliable UDP carrier. One owned driver serializes physical IO and all timers.
//! Datagram loss never advances the receiver or releases unacknowledged bytes.
use super::{
    crypto,
    pattern::{EffectivePattern, NonceState},
    reliability::{Cubic, Rtt},
    stream::{ReceivedChunk, State, closed},
    tcp::{Shared, WriterCommand},
    wire::{
        DataKind, DataMetadata, Frame, Metadata, PacketDecoder, PacketEncoder, SessionKind,
        SessionMetadata,
    },
};
use crate::{
    config::{MieruOutboundConfig, MieruTransport},
    dispatch::{DatagramBudget, DatagramTransport},
    outbound::{DatagramRequest, EstablishContext, UpstreamPath, server_destination},
    resources::observation::{self, ResourceKind},
    session::{Datagram, DatagramSession, Destination, StreamSession},
};
use bytes::Bytes;
use futures_util::FutureExt;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::{Duration, Instant, timeout_at},
};
const MTU: u16 = 1400;
const EMPTY_OVERHEAD: usize = super::wire::PACKET_HEADER_LEN;
const DATA_OVERHEAD: usize = super::wire::PACKET_OVERHEAD;
const SEGMENTS: usize = 4096;
const TX_LIMIT: u32 = 20;
const ACK_DELAY: Duration = Duration::from_millis(1);
const FIRST_CHECK: Duration = Duration::from_millis(10);
const RECEIVE_BATCH: u8 = 8;
const OUTPUT_QUANTUM: usize = 8;

struct WriteLease {
    _bytes: OwnedSemaphorePermit,
    remaining: AtomicUsize,
    done: Mutex<Option<oneshot::Sender<io::Result<()>>>>,
}
impl WriteLease {
    fn sent(&self) {
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1
            && let Some(done) = self.done.lock().unwrap().take()
        {
            let _ = done.send(Ok(()));
        }
    }
}
impl Drop for WriteLease {
    fn drop(&mut self) {
        if let Some(done) = self.done.get_mut().unwrap().take() {
            let _ = done.send(Err(closed()));
        }
    }
}
struct Segment {
    metadata: Metadata,
    payload: Bytes,
    lease: Option<Arc<WriteLease>>,
    sent: Option<Instant>,
    tx_count: u32,
    ack_count: u32,
}
struct Inbound {
    frame: Frame,
    permit: OwnedSemaphorePermit,
}
// The physical driver may retain one authenticated packet independently of
// application byte credit. Copying bounds the retained allocation by RX MTU,
// even when an upstream supplied a slice backed by a larger allocation.
struct Partial {
    session_id: u32,
    sequence: u32,
    payload: Bytes,
    offset: usize,
}
struct PacketPattern<'a> {
    pattern: &'a EffectivePattern,
    nonce: NonceState,
    wire_budget: usize,
    remaining: usize,
    truncated: bool,
}
struct Reliable {
    state: Arc<State>,
    pending: VecDeque<Segment>,
    outstanding: BTreeMap<u32, Segment>,
    reorder: BTreeMap<u32, Inbound>,
    // Authenticated pending DATA and application unread bytes own separate
    // bounded leases. A blocked reader must not spend the missing head's credit.
    reorder_bytes: Arc<Semaphore>,
    established: bool,
    remote_window: u32,
    rtt: Rtt,
    cubic: Cubic,
    ack_due: Option<Instant>,
    heartbeat: Instant,
    heartbeat_interval: Duration,
    first_check: Option<Instant>,
    last_window: u16,
    receive_chunk: usize,
    // A remote Close must not truncate the one already authenticated packet
    // being delivered through a smaller application byte budget.
    remote_close: Option<bool>,
}
fn heartbeat_interval() -> Duration {
    Duration::from_millis(4000 + rand::random_range(0..=2000u64))
}
fn sequence(metadata: Metadata) -> u32 {
    match metadata {
        Metadata::Session(m) => m.sequence,
        Metadata::Data(m) => m.sequence,
    }
}
fn session_id(metadata: Metadata) -> u32 {
    match metadata {
        Metadata::Session(m) => m.session_id,
        Metadata::Data(m) => m.session_id,
    }
}
fn close_metadata(state: &State, kind: SessionKind) -> Metadata {
    Metadata::Session(SessionMetadata {
        kind,
        session_id: state.id,
        sequence: state.sequence.fetch_add(1, Ordering::AcqRel),
        status: 0,
    })
}
impl Reliable {
    fn new(state: Arc<State>, receive_chunk: usize) -> Self {
        let now = Instant::now();
        let interval = heartbeat_interval();
        let reorder_bytes = Arc::new(Semaphore::new(state.receive_capacity()));
        Self {
            state,
            reorder_bytes,
            pending: VecDeque::new(),
            outstanding: BTreeMap::new(),
            reorder: BTreeMap::new(),
            established: false,
            remote_window: 16,
            rtt: Rtt::new(),
            cubic: Cubic::new(),
            ack_due: None,
            heartbeat: now + interval,
            heartbeat_interval: interval,
            first_check: None,
            last_window: 0,
            receive_chunk,
            remote_close: None,
        }
    }
    fn small_budget(&self) -> bool {
        self.state.receive_capacity() < self.receive_chunk
    }
    fn window(&self, partial_available: bool) -> u16 {
        let count = self.reorder.len() + self.state.unread_segments();
        let segment_space = SEGMENTS.saturating_sub(count);
        let small_budget = self.small_budget();
        let bytes = if small_budget {
            self.state.receive_bytes.available_permits()
        } else {
            self.reorder_bytes.available_permits()
        };
        let byte_space = if small_budget {
            // A single physical parser slot, plus real app byte credit,
            // permits incremental delivery without pretending the queue can
            // buffer a complete peer segment. While occupied, advertise zero.
            usize::from(partial_available && bytes > 0)
        } else {
            bytes / self.receive_chunk
        };
        segment_space.min(byte_space).min(u16::MAX as usize) as u16
    }
    fn request_ack(&mut self, now: Instant) {
        let due = now + ACK_DELAY;
        self.ack_due = Some(self.ack_due.map_or(due, |old| old.min(due)));
    }
    fn enqueue(&mut self, command: WriterCommand, chunk: usize, allow_piggyback: bool) {
        let first = !self.state.opened.swap(true, Ordering::AcqRel);
        let piggyback = first
            && allow_piggyback
            && command.piggyback
            && command.data.len() <= 1024
            && command.data.len() <= chunk;
        let count = if piggyback {
            1
        } else {
            command.data.len().div_ceil(chunk)
        };
        let lease = Arc::new(WriteLease {
            _bytes: command._bytes,
            remaining: AtomicUsize::new(count),
            done: Mutex::new(Some(command.done)),
        });
        if first {
            let metadata = Metadata::Session(SessionMetadata {
                kind: SessionKind::OpenRequest,
                session_id: self.state.id,
                sequence: self.state.sequence.fetch_add(1, Ordering::AcqRel),
                status: 0,
            });
            self.pending.push_back(Segment {
                metadata,
                payload: if piggyback {
                    command.data.clone()
                } else {
                    Bytes::new()
                },
                lease: if piggyback { Some(lease.clone()) } else { None },
                sent: None,
                tx_count: 0,
                ack_count: 0,
            });
        }
        if !piggyback {
            let fragments = command.data.len().div_ceil(chunk);
            for (index, part) in command.data.chunks(chunk).enumerate() {
                let start = index * chunk;
                let metadata = Metadata::Data(DataMetadata {
                    kind: DataKind::ClientData,
                    session_id: self.state.id,
                    sequence: self.state.sequence.fetch_add(1, Ordering::AcqRel),
                    unack_sequence: self.state.next_receive.load(Ordering::Acquire),
                    window: 0,
                    fragment: (fragments - index - 1) as u8,
                });
                self.pending.push_back(Segment {
                    metadata,
                    payload: command.data.slice(start..start + part.len()),
                    lease: Some(lease.clone()),
                    sent: None,
                    tx_count: 0,
                    ack_count: 0,
                });
            }
        }
    }
    fn acknowledge(&mut self, unack: u32, window: u16, only_ack: bool, now: Instant) {
        while self
            .outstanding
            .first_key_value()
            .is_some_and(|(seq, _)| *seq < unack)
        {
            let (_, segment) = self.outstanding.pop_first().unwrap();
            self.rtt
                .update(now.saturating_duration_since(segment.sent.unwrap()));
            self.cubic.on_ack(now);
        }
        self.remote_window = u32::from(window);
        if only_ack && let Some(segment) = self.outstanding.get_mut(&unack) {
            segment.ack_count = segment.ack_count.saturating_add(1);
        }
    }
    fn input(&mut self, frame: Frame, now: Instant, partial: &mut Option<Partial>) {
        if self.remote_close.is_some() {
            return;
        }
        if let Metadata::Data(meta) = frame.metadata {
            self.acknowledge(
                meta.unack_sequence,
                meta.window,
                meta.kind == DataKind::ServerAck,
                now,
            );
            if meta.kind == DataKind::ServerAck {
                return;
            }
        }
        self.request_ack(now);
        let seq = sequence(frame.metadata);
        let next_receive = self.state.next_receive.load(Ordering::Acquire);
        if seq < next_receive || self.reorder.contains_key(&seq) {
            return;
        }
        if partial
            .as_ref()
            .is_some_and(|pending| pending.session_id == self.state.id && pending.sequence == seq)
        {
            return; // A retransmission must never deliver the prefix twice.
        }
        let segment_limit = SEGMENTS - usize::from(seq != next_receive);
        if self.reorder.len() + self.state.unread_segments() >= segment_limit {
            return;
        }
        if self.small_budget() && !frame.payload.is_empty() {
            // Future DATA must not consume the byte credit needed by the
            // missing preceding frame. Its peer retains it until cumulative ACK.
            if seq != self.state.next_receive.load(Ordering::Acquire) || partial.is_some() {
                return;
            }
            if matches!(frame.metadata,Metadata::Session(meta) if meta.kind==SessionKind::OpenResponse)
            {
                self.established = true;
            }
            *partial = Some(Partial {
                session_id: self.state.id,
                sequence: seq,
                payload: Bytes::copy_from_slice(&frame.payload),
                offset: 0,
            });
            return;
        }
        // Tiny budgets keep the existing physical Partial slot and app leases.
        // Normal DATA first owns reorder credit, independent of app unread bytes.
        let receive_bytes = if self.small_budget() {
            &self.state.receive_bytes
        } else {
            &self.reorder_bytes
        };
        if !frame.payload.is_empty() {
            let reserve = if seq == next_receive {
                0
            } else {
                self.receive_chunk
            };
            let required = frame.payload.len().saturating_add(reserve);
            let available = receive_bytes.available_permits();
            if available < required {
                let reclaimable = self
                    .reorder
                    .iter()
                    .rev()
                    .take_while(|(queued, _)| **queued > seq)
                    .map(|(_, inbound)| inbound.frame.payload.len())
                    .sum::<usize>();
                if available.saturating_add(reclaimable) < required {
                    return;
                }
                while receive_bytes.available_permits() < required
                    && self
                        .reorder
                        .last_key_value()
                        .is_some_and(|(queued, _)| *queued > seq)
                {
                    drop(self.reorder.pop_last());
                }
            }
        }
        let Ok(permit) = receive_bytes
            .clone()
            .try_acquire_many_owned(frame.payload.len() as u32)
        else {
            return;
        };
        if matches!(frame.metadata,Metadata::Session(meta) if meta.kind==SessionKind::OpenResponse)
        {
            self.established = true;
        }
        self.reorder.insert(seq, Inbound { frame, permit });
        self.deliver_contiguous();
    }
    fn deliver_contiguous(&mut self) -> bool {
        let mut advanced = false;
        if self.small_budget() {
            // Preserve the tiny path's existing app permit ownership exactly.
            while let Some(inbound) = self
                .reorder
                .remove(&self.state.next_receive.load(Ordering::Acquire))
            {
                self.state.next_receive.fetch_add(1, Ordering::AcqRel);
                self.state.deliver_reserved(ReceivedChunk {
                    bytes: inbound.frame.payload,
                    permit: inbound.permit,
                });
                advanced = true;
            }
            return advanced;
        }
        loop {
            let next = self.state.next_receive.load(Ordering::Acquire);
            let Some(inbound) = self.reorder.get(&next) else {
                break;
            };
            let Ok(permit) = self
                .state
                .receive_bytes
                .clone()
                .try_acquire_many_owned(inbound.frame.payload.len() as u32)
            else {
                break;
            };
            // Clone only the Bytes handle, retaining the same allocation and
            // reorder lease until the app enqueue has actually committed.
            let delivered = self.state.try_deliver_reserved(ReceivedChunk {
                bytes: inbound.frame.payload.clone(),
                permit,
            });
            if !delivered {
                break;
            }
            drop(self.reorder.remove(&next));
            // The cumulative ACK commits only bytes actually queued for the app.
            self.state.next_receive.fetch_add(1, Ordering::AcqRel);
            advanced = true;
        }
        advanced
    }
    fn retain_contiguous_on_close(&mut self) {
        let mut next = self.state.next_receive.load(Ordering::Acquire);
        let mut gap = false;
        self.reorder.retain(|sequence, _| {
            if gap || *sequence != next {
                gap = true;
                return false;
            }
            next = next.wrapping_add(1);
            true
        });
    }
    fn next_deadline(&self, now: Instant) -> Instant {
        let mut next = now + Duration::from_secs(5);
        if self.remote_close.is_some() {
            return next;
        }
        if let Some(first) = self.first_check {
            next = next.min(first);
        }
        for segment in self.outstanding.values() {
            let due = if segment.ack_count >= 3 && segment.tx_count <= 1 {
                now
            } else {
                segment.sent.unwrap() + self.rtt.retransmit_delay(segment.tx_count)
            };
            next = next.min(due);
        }
        if self.established {
            next = next.min(self.heartbeat);
            if let Some(ack) = self.ack_due {
                next = next.min(ack);
            }
        }
        next
    }
}

fn advance_partial(
    partial: &mut Option<Partial>,
    sessions: &mut BTreeMap<u32, Reliable>,
) -> Option<u32> {
    let pending = partial.as_mut()?;
    let Some(state) = sessions.get_mut(&pending.session_id) else {
        *partial = None;
        return None;
    };
    if state.state.cancel.is_cancelled() {
        *partial = None;
        return None;
    }
    let count = (pending.payload.len() - pending.offset)
        .min(state.state.receive_capacity())
        .min(state.state.receive_bytes.available_permits());
    if count == 0 {
        return None;
    }
    let Ok(permit) = state
        .state
        .receive_bytes
        .clone()
        .try_acquire_many_owned(count as u32)
    else {
        return None;
    };
    state.state.deliver_reserved(ReceivedChunk {
        // Never let an app chunk retain the larger parser allocation.
        bytes: Bytes::copy_from_slice(&pending.payload[pending.offset..pending.offset + count]),
        permit,
    });
    pending.offset += count;
    if pending.offset == pending.payload.len() {
        debug_assert_eq!(
            state.state.next_receive.load(Ordering::Acquire),
            pending.sequence
        );
        state.state.next_receive.fetch_add(1, Ordering::AcqRel);
        state.deliver_contiguous();
        state.request_ack(Instant::now());
        if let Some(failure) = state.remote_close {
            state.state.finish(failure);
            let id = pending.session_id;
            *partial = None;
            sessions.remove(&id);
            return Some(id);
        }
        *partial = None;
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn drive(
    config: &MieruOutboundConfig,
    upstream: &UpstreamPath,
    pattern: &EffectivePattern,
    session: StreamSession,
    context: EstablishContext,
    shared: &Arc<Shared>,
    commands: mpsc::Receiver<WriterCommand>,
    ready: oneshot::Sender<io::Result<()>>,
) {
    let setup = async {
        let _guard = observation::track(ResourceKind::Handshake);
        let port = rand::random_range(config.port..=config.port_end);
        let server = server_destination(&config.address, port)?;
        let upstream = upstream.for_server(&server, true);
        let destination = upstream
            .datagram_server(&server, &context)
            .await
            .map_err(|_| closed())?;
        let peer = context
            .resolve_ip(&destination)
            .await
            .map_err(|_| closed())?;
        let mut datagram = DatagramSession::new(session.inbound, session.source);
        datagram.metadata = session.metadata;
        let request = DatagramRequest::new(datagram).with_udp_receive_buffer_size(512 * 1024);
        let transport = upstream
            .open_datagram(request.with_budget(DatagramBudget::new(MTU, MTU)), &context)
            .await
            .map_err(|_| closed())?;
        let peer = Destination::Ip(peer);
        let budget = DatagramBudget::new(MTU, MTU).intersect(transport.payload_budget(&peer));
        if usize::from(budget.transmit()) <= DATA_OVERHEAD
            || usize::from(budget.receive()) < EMPTY_OVERHEAD
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mieru UDP path budget is too small",
            ));
        }
        let chunk = pattern
            .plaintext_fragment_limit(MieruTransport::Udp, usize::from(budget.transmit()))?;
        shared.set_maximum_write((chunk * 255).min(32768));
        let key = Arc::new(crypto::derive_key(
            &config.username,
            &config.password,
            super::tcp::now()?,
        ));
        Ok((
            transport,
            peer,
            budget,
            PacketEncoder::new(key.clone()),
            PacketDecoder::new(key),
        ))
    };
    let result = tokio::select! {biased;()=shared.cancel.cancelled()=>Err(closed()),result=timeout_at(context.deadline(),setup)=>result.map_err(|_|io::Error::from(io::ErrorKind::TimedOut)).and_then(|result|result)};
    match result {
        Ok((mut transport, peer, budget, encoder, decoder)) => {
            if ready.send(Ok(())).is_ok() {
                let _ = run(
                    &mut *transport,
                    &peer,
                    budget,
                    &encoder,
                    &decoder,
                    &config.username,
                    pattern,
                    shared,
                    commands,
                )
                .await;
            }
            shared.fail();
            let _ = tokio::time::timeout(Duration::from_secs(1), transport.close()).await;
        }
        Err(error) => {
            let _ = ready.send(Err(error));
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn send(
    transport: &mut dyn DatagramTransport,
    peer: &Destination,
    encoder: &PacketEncoder,
    username: &str,
    shared: &Shared,
    pattern: &mut PacketPattern<'_>,
    metadata: Metadata,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> io::Result<()> {
    let mut nonce = rand::random();
    pattern
        .pattern
        .rewrite_nonce(&mut pattern.nonce, &mut nonce, MieruTransport::Udp);
    let nonce = crypto::make_client_nonce(username, nonce);
    let prepared = pattern.pattern.prepare_frame(
        metadata,
        payload.len(),
        MieruTransport::Udp,
        pattern.wire_budget,
    )?;
    encoder.encode_frame(
        metadata,
        payload,
        prepared.encoding(),
        nonce,
        super::tcp::now()?,
        output,
    )?;
    tokio::select! {biased;()=shared.cancel.cancelled()=>return Err(closed()),result=tokio::time::timeout(Duration::from_secs(10),transport.send(Datagram{remote:peer.clone(),payload:Bytes::copy_from_slice(output),sniffed_domain:None}))=>result.map_err(|_|io::ErrorKind::TimedOut)?.map_err(|_|closed())?}
    pattern.remaining -= 1;
    shared.count_output(output.len());
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn output(
    transport: &mut dyn DatagramTransport,
    peer: &Destination,
    encoder: &PacketEncoder,
    username: &str,
    shared: &Shared,
    pattern: &mut PacketPattern<'_>,
    state: &mut Reliable,
    partial_available: bool,
    buffer: &mut Vec<u8>,
) -> io::Result<bool> {
    let now = Instant::now();
    let mut had_timeout = false;
    let mut had_loss = false;
    let mut new_sent = 0u32;
    state.first_check = None;
    if state.established && (state.ack_due.is_some_and(|due| now >= due) || now >= state.heartbeat)
    {
        if pattern.remaining == 0 {
            pattern.truncated = true;
            return Ok(true);
        }
        let window = state.window(partial_available);
        let metadata = Metadata::Data(DataMetadata {
            kind: DataKind::ClientAck,
            session_id: state.state.id,
            sequence: state.state.sequence.load(Ordering::Acquire).wrapping_sub(1),
            unack_sequence: state.state.next_receive.load(Ordering::Acquire),
            window,
            fragment: 0,
        });
        send(
            transport,
            peer,
            encoder,
            username,
            shared,
            pattern,
            metadata,
            &[],
            buffer,
        )
        .await?;
        state.last_window = window;
        state.ack_due = None;
        state.heartbeat_interval = heartbeat_interval();
        state.heartbeat = Instant::now() + state.heartbeat_interval;
    }
    for segment in state.outstanding.values_mut() {
        let fast = segment.ack_count >= 3 && segment.tx_count <= 1;
        let timeout = now >= segment.sent.unwrap() + state.rtt.retransmit_delay(segment.tx_count);
        if !fast && !timeout {
            continue;
        }
        if pattern.remaining == 0 {
            pattern.truncated = true;
            break;
        }
        if segment.tx_count >= TX_LIMIT {
            return Ok(false);
        }
        if let Metadata::Data(ref mut meta) = segment.metadata {
            meta.unack_sequence = state.state.next_receive.load(Ordering::Acquire);
            meta.window = state.last_window;
        }
        send(
            transport,
            peer,
            encoder,
            username,
            shared,
            pattern,
            segment.metadata,
            &segment.payload,
            buffer,
        )
        .await?;
        had_loss |= fast;
        had_timeout |= !fast;
        segment.ack_count = 0;
        segment.tx_count += 1;
        segment.sent = Some(Instant::now());
        state.heartbeat = segment.sent.unwrap() + state.heartbeat_interval;
    }
    if had_timeout {
        state.cubic.on_timeout();
    } else if had_loss {
        state.cubic.on_loss(now);
    }
    if pattern.truncated {
        return Ok(true);
    }
    let available = state
        .cubic
        .window()
        .saturating_sub(state.outstanding.len() as u32)
        .min(state.remote_window);
    loop {
        if new_sent >= available || state.outstanding.len() >= SEGMENTS - 1 {
            break;
        }
        let Some(front) = state.pending.front() else {
            break;
        };
        if !state.established && matches!(front.metadata, Metadata::Data(_)) {
            break;
        }
        if pattern.remaining == 0 {
            pattern.truncated = true;
            break;
        }
        let mut segment = state.pending.pop_front().unwrap();
        if let Metadata::Data(ref mut meta) = segment.metadata {
            meta.unack_sequence = state.state.next_receive.load(Ordering::Acquire);
            meta.window = state.window(partial_available);
        }
        send(
            transport,
            peer,
            encoder,
            username,
            shared,
            pattern,
            segment.metadata,
            &segment.payload,
            buffer,
        )
        .await?;
        segment.sent = Some(Instant::now());
        state.heartbeat = segment.sent.unwrap() + state.heartbeat_interval;
        segment.tx_count = 1;
        if let Metadata::Data(meta) = segment.metadata {
            state.last_window = meta.window;
        }
        if let Some(lease) = &segment.lease {
            lease.sent();
        }
        if state.outstanding.is_empty() {
            state.first_check = Some(Instant::now() + FIRST_CHECK);
        }
        state
            .outstanding
            .insert(sequence(segment.metadata), segment);
        new_sent += 1;
    }
    Ok(true)
}
fn valid_direction(metadata: Metadata) -> bool {
    match metadata {
        Metadata::Data(m) => matches!(m.kind, DataKind::ServerData | DataKind::ServerAck),
        Metadata::Session(m) => matches!(
            m.kind,
            SessionKind::OpenResponse | SessionKind::CloseRequest | SessionKind::CloseResponse
        ),
    }
}
fn input_command(
    command: WriterCommand,
    sessions: &mut BTreeMap<u32, Reliable>,
    chunk: usize,
    receive_chunk: usize,
    allow_piggyback: bool,
) {
    if command.state.cancel.is_cancelled() {
        let _ = command.done.send(Err(closed()));
        return;
    }
    let state = sessions
        .entry(command.state.id)
        .or_insert_with(|| Reliable::new(command.state.clone(), receive_chunk));
    if state.remote_close.is_some() {
        let _ = command.done.send(Err(closed()));
    } else {
        state.enqueue(command, chunk, allow_piggyback);
    }
}

#[allow(clippy::too_many_arguments)]
async fn input_packet(
    packet: Datagram,
    transport: &mut dyn DatagramTransport,
    peer: &Destination,
    budget: DatagramBudget,
    encoder: &PacketEncoder,
    decoder: &PacketDecoder,
    username: &str,
    shared: &Shared,
    pattern: &mut PacketPattern<'_>,
    sessions: &mut BTreeMap<u32, Reliable>,
    partial: &mut Option<Partial>,
    buffer: &mut Vec<u8>,
) -> io::Result<bool> {
    if &packet.remote != peer || packet.payload.len() > usize::from(budget.receive()) {
        return Ok(false);
    }
    shared.count_input(packet.payload.len());
    let frame = match decoder.decode_frame(packet.payload, super::tcp::now()?) {
        Ok(frame) => frame,
        Err(_) => return Ok(false),
    };
    if !valid_direction(frame.metadata) {
        return Ok(false);
    }
    let id = session_id(frame.metadata);
    if let Some(state) = sessions.get_mut(&id) {
        match frame.metadata {
            Metadata::Session(meta)
                if matches!(
                    meta.kind,
                    SessionKind::CloseRequest | SessionKind::CloseResponse
                ) =>
            {
                if meta.kind == SessionKind::CloseRequest {
                    let metadata = close_metadata(&state.state, SessionKind::CloseResponse);
                    send(
                        transport,
                        peer,
                        encoder,
                        username,
                        shared,
                        pattern,
                        metadata,
                        &[],
                        buffer,
                    )
                    .await?;
                }
                if partial
                    .as_ref()
                    .is_some_and(|pending| pending.session_id == id)
                {
                    state.remote_close =
                        Some(state.remote_close.unwrap_or(false) || meta.status != 0);
                    state.pending.clear();
                    state.outstanding.clear();
                    state.reorder.clear();
                } else if !state.small_budget() {
                    state.remote_close =
                        Some(state.remote_close.unwrap_or(false) || meta.status != 0);
                    state.pending.clear();
                    state.outstanding.clear();
                    // Preserve only the accepted contiguous prefix. A gap
                    // cannot be repaired after the peer has closed.
                    state.retain_contiguous_on_close();
                } else {
                    state.state.finish(meta.status != 0);
                    sessions.remove(&id);
                    shared.sessions.lock().unwrap().remove(&id);
                }
            }
            _ => state.input(frame, Instant::now(), partial),
        }
    } else if let Metadata::Data(meta) = frame.metadata {
        let close = Metadata::Session(SessionMetadata {
            kind: SessionKind::CloseRequest,
            session_id: id,
            sequence: meta.unack_sequence,
            status: 0,
        });
        send(
            transport,
            peer,
            encoder,
            username,
            shared,
            pattern,
            close,
            &[],
            buffer,
        )
        .await?;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn run(
    transport: &mut dyn DatagramTransport,
    peer: &Destination,
    budget: DatagramBudget,
    encoder: &PacketEncoder,
    decoder: &PacketDecoder,
    username: &str,
    pattern: &EffectivePattern,
    shared: &Shared,
    mut commands: mpsc::Receiver<WriterCommand>,
) -> io::Result<()> {
    let chunk =
        pattern.plaintext_fragment_limit(MieruTransport::Udp, usize::from(budget.transmit()))?;
    let mut packet_pattern = PacketPattern {
        pattern,
        nonce: NonceState::new(),
        wire_budget: usize::from(budget.transmit()),
        remaining: OUTPUT_QUANTUM,
        truncated: false,
    };
    let receive_chunk = usize::from(budget.receive())
        .saturating_sub(DATA_OVERHEAD)
        .max(1);
    let mut sessions = BTreeMap::<u32, Reliable>::new();
    let mut partial = None;
    let mut buffer = Vec::with_capacity(usize::from(budget.transmit()));
    // Give application readers a turn before a ready burst consumes their credit.
    let mut received_since_yield = 0u8;
    let mut has_output = false;
    let mut last_output = None;
    'driver: loop {
        // Direct receive requires its first successful physical send.
        has_output |= packet_pattern.remaining < OUTPUT_QUANTUM;
        packet_pattern.remaining = OUTPUT_QUANTUM;
        packet_pattern.truncated = false;
        if let Some(id) = advance_partial(&mut partial, &mut sessions) {
            shared.sessions.lock().unwrap().remove(&id);
        }
        let now = Instant::now();
        let deadline = sessions
            .values()
            .map(|state| state.next_deadline(now))
            .min()
            .unwrap_or(now + Duration::from_secs(5))
            .min(now + Duration::from_secs(5));
        let mut received = None;
        tokio::select! {biased;
            ()=shared.cancel.cancelled()=>return Ok(()),
            command=commands.recv()=>{let Some(command)=command else{return Ok(());};input_command(command,&mut sessions,chunk,receive_chunk,!pattern.low_entropy_enabled());},
            ()=shared.activity.notified()=>{},
            ()=tokio::time::sleep_until(deadline)=>{},
            packet=transport.receive(),if !sessions.is_empty()=>{received=Some(packet.map_err(|_|closed())?);}
        }
        let mut received_in_turn = 0u8;
        while received_in_turn < RECEIVE_BATCH {
            if shared.cancel.is_cancelled() {
                return Ok(());
            }
            let selected_receive = received.is_some();
            let packet = if let Some(packet) = received.take() {
                packet
            } else if has_output && !sessions.is_empty() {
                // The receive contract permits dropping a pending future. A
                // ready Datagram owns its complete payload before we borrow TX.
                let Some(packet) = transport
                    .receive()
                    .now_or_never()
                    .transpose()
                    .map_err(|_| closed())?
                else {
                    break;
                };
                packet
            } else {
                break;
            };
            received_in_turn += 1;
            received_since_yield += 1;
            if received_since_yield == RECEIVE_BATCH {
                received_since_yield = 0;
                tokio::task::yield_now().await;
            }
            if shared.cancel.is_cancelled() {
                return Ok(());
            }
            if !input_packet(
                packet,
                transport,
                peer,
                budget,
                encoder,
                decoder,
                username,
                shared,
                &mut packet_pattern,
                &mut sessions,
                &mut partial,
                &mut buffer,
            )
            .await?
            {
                if selected_receive {
                    continue 'driver;
                }
                // An extra invalid packet must not discard the selected
                // command or due timer's output turn.
                continue;
            }
        }
        if let Some(id) = advance_partial(&mut partial, &mut sessions) {
            shared.sessions.lock().unwrap().remove(&id);
        }
        shared.reap_unopened();
        if shared.clean() {
            return Ok(());
        }
        let mut ids: Vec<_> = sessions.keys().copied().collect();
        if let Some(last) = last_output {
            let first = ids.partition_point(|id| *id <= last);
            ids.rotate_left(first);
        }
        for id in ids {
            if packet_pattern.remaining == 0 {
                packet_pattern.truncated = true;
                break;
            }
            last_output = Some(id);
            let state = sessions.get_mut(&id).unwrap();
            if state.state.cancel.is_cancelled() {
                if state.remote_close.is_none() && state.state.opened.load(Ordering::Acquire) {
                    let metadata = close_metadata(&state.state, SessionKind::CloseRequest);
                    send(
                        transport,
                        peer,
                        encoder,
                        username,
                        shared,
                        &mut packet_pattern,
                        metadata,
                        &[],
                        &mut buffer,
                    )
                    .await?;
                }
                sessions.remove(&id);
                shared.sessions.lock().unwrap().remove(&id);
                continue;
            }
            // App reads notify this driver. Retry delivery before every window
            // calculation, including when the window floor would stay unchanged.
            if !state.small_budget() && state.deliver_contiguous() {
                state.request_ack(Instant::now());
            }
            if let Some(failure) = state.remote_close {
                // finish cancels State and excludes it from carrier liveness.
                // Defer it until retained normal DATA has entered the app queue.
                if !state.small_budget() && state.reorder.is_empty() {
                    state.state.finish(failure);
                    sessions.remove(&id);
                    shared.sessions.lock().unwrap().remove(&id);
                }
                continue;
            }
            if state.window(partial.is_none()) != state.last_window {
                state.request_ack(Instant::now());
            }
            if !output(
                transport,
                peer,
                encoder,
                username,
                shared,
                &mut packet_pattern,
                state,
                partial.is_none(),
                &mut buffer,
            )
            .await?
            {
                state.state.finish(true);
                let metadata = close_metadata(&state.state, SessionKind::CloseRequest);
                send(
                    transport,
                    peer,
                    encoder,
                    username,
                    shared,
                    &mut packet_pattern,
                    metadata,
                    &[],
                    &mut buffer,
                )
                .await?;
                sessions.remove(&id);
                shared.sessions.lock().unwrap().remove(&id);
            }
            if packet_pattern.truncated {
                break;
            }
        }
        if packet_pattern.truncated {
            shared.activity.notify_one();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::super::wire::Padding;
    use super::*;
    use crate::{
        dispatch::DispatchError,
        outbound::OutboundConnector,
        resources::observation::ResourceProbe,
        session::{DatagramSession, InboundKind},
    };
    use async_trait::async_trait;
    use std::sync::atomic::AtomicBool;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        task::JoinHandle,
    };
    use tokio_util::{sync::CancellationToken, task::TaskTracker};
    struct Peer {
        drop_open: bool,
        drop_response: bool,
        response_dropped: AtomicBool,
        response_transmissions: AtomicUsize,
        large_response: bool,
        close_after_response: bool,
        close_replied: tokio::sync::Notify,
        stall: bool,
        tasks: TaskTracker,
        cancel: CancellationToken,
        opens: AtomicUsize,
        nonces: Mutex<Vec<[u8; 24]>>,
        transmit_limit: u16,
        received: Mutex<Vec<(u8, usize, usize)>>,
    }
    struct Memory {
        input: mpsc::Receiver<Datagram>,
        output: mpsc::Sender<Datagram>,
        cancel: CancellationToken,
        task: Option<JoinHandle<()>>,
        budget: DatagramBudget,
    }
    #[async_trait]
    impl DatagramTransport for Memory {
        fn supports_shared_destinations(&self) -> bool {
            false
        }

        fn payload_budget(&self, _: &Destination) -> DatagramBudget {
            self.budget
        }
        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            self.output
                .send(packet)
                .await
                .map_err(|_| DispatchError::NotAllowed)
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.input.recv().await.ok_or(DispatchError::NotAllowed)
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.cancel.cancel();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            Ok(())
        }
    }
    impl Drop for Memory {
        fn drop(&mut self) {
            self.cancel.cancel();
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }
    impl Peer {
        fn new(drop_open: bool, stall: bool) -> Arc<Self> {
            Self::with_response_loss(drop_open, false, stall)
        }
        fn with_response_loss(drop_open: bool, drop_response: bool, stall: bool) -> Arc<Self> {
            Arc::new(Self {
                drop_open,
                drop_response,
                response_dropped: AtomicBool::new(false),
                response_transmissions: AtomicUsize::new(0),
                large_response: false,
                close_after_response: false,
                close_replied: tokio::sync::Notify::new(),
                stall,
                tasks: TaskTracker::new(),
                cancel: CancellationToken::new(),
                opens: AtomicUsize::new(0),
                nonces: Mutex::new(Vec::new()),
                transmit_limit: MTU,
                received: Mutex::new(Vec::new()),
            })
        }
        async fn stop(&self) {
            self.cancel.cancel();
            self.tasks.close();
            self.tasks.wait().await;
        }
    }
    #[async_trait]
    impl OutboundConnector for Arc<Peer> {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            _context: &EstablishContext,
        ) -> Result<crate::outbound::ConnectedStream, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
        async fn open_datagram(
            &self,
            _request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            let (output, incoming) = mpsc::channel(64);
            let (outgoing, input) = mpsc::channel(64);
            let cancel = self.cancel.child_token();
            let server_cancel = cancel.clone();
            let peer = self.clone();
            let task=self.tasks.spawn(observation::task(async move{tokio::select!{()=server_cancel.cancelled()=>{},_=serve(&peer,incoming,outgoing)=>{}}}));
            Ok(Box::new(Memory {
                input,
                output,
                cancel,
                task: Some(task),
                budget: DatagramBudget::new(self.transmit_limit, MTU),
            }))
        }
    }
    struct ServerSession {
        next: u32,
        client_next: u32,
        request: Vec<u8>,
        ready: bool,
        pending: BTreeMap<u32, Frame>,
        peer: Destination,
        outstanding: BTreeMap<u32, ServerSegment>,
        rtt: Rtt,
        ack_due: Option<Instant>,
    }
    struct ServerSegment {
        metadata: Metadata,
        payload: Bytes,
        sent: Instant,
        transmissions: u32,
    }
    impl ServerSession {
        fn acknowledge(&mut self, next_missing: u32, now: Instant) {
            while self
                .outstanding
                .first_key_value()
                .is_some_and(|(sequence, _)| *sequence < next_missing)
            {
                let (_, sent) = self.outstanding.pop_first().unwrap();
                self.rtt.update(now.saturating_duration_since(sent.sent));
            }
        }
        fn deadline(&self) -> Instant {
            self.outstanding
                .values()
                .map(|segment| segment.sent + self.rtt.retransmit_delay(segment.transmissions))
                .chain(self.ack_due)
                .min()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(10))
        }
    }
    async fn emit(
        send: &mpsc::Sender<Datagram>,
        encoder: &PacketEncoder,
        peer: &Destination,
        metadata: Metadata,
        payload: &[u8],
        duplicate: bool,
    ) -> io::Result<()> {
        let mut packet = Vec::new();
        encoder.encode_frame(
            metadata,
            payload,
            Padding {
                prefix: &[],
                suffix: &[],
            },
            rand::random(),
            super::super::tcp::now()?,
            &mut packet,
        )?;
        let datagram = Datagram {
            remote: peer.clone(),
            payload: packet.into(),
            sniffed_domain: None,
        };
        if duplicate {
            let mut wrong = Vec::new();
            encoder.encode_frame(
                metadata,
                b"wrong source",
                Padding {
                    prefix: &[],
                    suffix: &[],
                },
                rand::random(),
                super::super::tcp::now()?,
                &mut wrong,
            )?;
            send.send(Datagram {
                remote: Destination::Ip("192.0.2.99:2000".parse().unwrap()),
                payload: wrong.into(),
                sniffed_domain: None,
            })
            .await
            .map_err(|_| closed())?;
            send.send(datagram.clone()).await.map_err(|_| closed())?;
        }
        send.send(datagram).await.map_err(|_| closed())
    }
    async fn emit_server(
        peer: &Peer,
        send: &mpsc::Sender<Datagram>,
        encoder: &PacketEncoder,
        remote: &Destination,
        metadata: Metadata,
        payload: &[u8],
        duplicate: bool,
    ) -> io::Result<()> {
        if matches!(metadata, Metadata::Session(m) if m.kind == SessionKind::OpenResponse) {
            peer.response_transmissions.fetch_add(1, Ordering::Relaxed);
        }
        if peer.drop_response && !peer.response_dropped.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        emit(send, encoder, remote, metadata, payload, duplicate).await
    }
    async fn emit_reliable(
        peer: &Peer,
        send: &mpsc::Sender<Datagram>,
        encoder: &PacketEncoder,
        state: &mut ServerSession,
        metadata: Metadata,
        payload: &[u8],
        duplicate: bool,
    ) -> io::Result<()> {
        state.outstanding.insert(
            sequence(metadata),
            ServerSegment {
                metadata,
                payload: Bytes::copy_from_slice(payload),
                sent: Instant::now(),
                transmissions: 1,
            },
        );
        emit_server(
            peer,
            send,
            encoder,
            &state.peer,
            metadata,
            payload,
            duplicate,
        )
        .await
    }
    async fn serve(
        peer: &Peer,
        mut receive: mpsc::Receiver<Datagram>,
        send: mpsc::Sender<Datagram>,
    ) -> io::Result<()> {
        let key = Arc::new(crypto::derive_key(
            "vole",
            "fixture-password",
            super::super::tcp::now()?,
        ));
        let decoder = PacketDecoder::new(key.clone());
        let header_cipher = crypto::PacketCipher::new(key.clone());
        let encoder = PacketEncoder::new(key);
        let mut sessions = BTreeMap::<u32, ServerSession>::new();
        let mut dropped = false;
        loop {
            let deadline = sessions
                .values()
                .map(ServerSession::deadline)
                .min()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(10));
            let packet = tokio::select! {
                packet = receive.recv() => {
                    let Some(packet) = packet else { return Ok(()); };
                    packet
                },
                () = tokio::time::sleep_until(deadline) => {
                    let now = Instant::now();
                    for (&id, state) in &mut sessions {
                        // Reference output ordering: due retransmissions, then
                        // independent cumulative ACKs. Re-encode every retry.
                        for segment in state.outstanding.values_mut() {
                            if now < segment.sent + state.rtt.retransmit_delay(segment.transmissions) {
                                continue;
                            }
                            assert!(segment.transmissions < 20);
                            if let Metadata::Data(ref mut metadata) = segment.metadata {
                                metadata.unack_sequence = state.client_next;
                            }
                            emit_server(peer, &send, &encoder, &state.peer, segment.metadata, &segment.payload, false).await?;
                            segment.sent = Instant::now();
                            segment.transmissions += 1;
                        }
                        if state.ack_due.is_some_and(|due| now >= due) {
                            emit_server(peer, &send, &encoder, &state.peer, Metadata::Data(DataMetadata {
                                kind: DataKind::ServerAck,
                                session_id: id,
                                sequence: state.next.saturating_sub(1),
                                unack_sequence: state.client_next,
                                window: 64,
                                fragment: 0,
                            }), &[], false).await?;
                            state.ack_due = None;
                        }
                    }
                    continue;
                }
            };
            let mut nonce = [0; 24];
            nonce.copy_from_slice(&packet.payload[..24]);
            peer.nonces.lock().unwrap().push(nonce);
            let wire_len = packet.payload.len();
            let mut header = packet.payload[24..56].to_vec();
            let mut tag = [0; 16];
            tag.copy_from_slice(&packet.payload[56..72]);
            header_cipher.open(nonce, &mut header, tag)?;
            let frame = decoder.decode_frame(packet.payload, super::super::tcp::now()?)?;
            peer.received
                .lock()
                .unwrap()
                .push((header[0], wire_len, frame.payload.len()));
            let id = session_id(frame.metadata);
            if matches!(frame.metadata,Metadata::Session(m) if m.kind==SessionKind::CloseResponse) {
                peer.close_replied.notify_one();
                sessions.remove(&id);
                continue;
            }
            if matches!(frame.metadata,Metadata::Session(m) if m.kind==SessionKind::OpenRequest) {
                peer.opens.fetch_add(1, Ordering::Relaxed);
                if peer.stall {
                    continue;
                }
                if peer.drop_open && !dropped {
                    dropped = true;
                    continue;
                }
                if !sessions.contains_key(&id) {
                    sessions.insert(
                        id,
                        ServerSession {
                            next: 1,
                            client_next: 0,
                            request: Vec::new(),
                            ready: false,
                            pending: BTreeMap::new(),
                            peer: packet.remote.clone(),
                            outstanding: BTreeMap::new(),
                            rtt: Rtt::new(),
                            ack_due: None,
                        },
                    );
                    emit_reliable(
                        peer,
                        &send,
                        &encoder,
                        sessions.get_mut(&id).unwrap(),
                        Metadata::Session(SessionMetadata {
                            kind: SessionKind::OpenResponse,
                            session_id: id,
                            sequence: 0,
                            status: 0,
                        }),
                        &[],
                        false,
                    )
                    .await?;
                }
            }
            let Some(state) = sessions.get_mut(&id) else {
                continue;
            };
            if let Metadata::Data(metadata) = frame.metadata {
                state.acknowledge(metadata.unack_sequence, Instant::now());
            }
            if let Metadata::Session(m) = frame.metadata {
                if m.kind == SessionKind::CloseRequest {
                    emit(
                        &send,
                        &encoder,
                        &packet.remote,
                        Metadata::Session(SessionMetadata {
                            kind: SessionKind::CloseResponse,
                            session_id: id,
                            sequence: state.next,
                            status: 0,
                        }),
                        &[],
                        false,
                    )
                    .await?;
                    sessions.remove(&id);
                    continue;
                }
            }
            if matches!(frame.metadata,Metadata::Data(m) if m.kind==DataKind::ClientAck) {
                continue;
            }
            let seq = sequence(frame.metadata);
            if seq >= state.client_next {
                state.pending.entry(seq).or_insert(frame);
            }
            let mut body = Vec::new();
            while let Some(frame) = state.pending.remove(&state.client_next) {
                state.client_next += 1;
                body.extend_from_slice(&frame.payload);
            }
            let due = Instant::now() + Duration::from_millis(1);
            state.ack_due = Some(state.ack_due.map_or(due, |previous| previous.min(due)));
            if body.is_empty() {
                continue;
            }
            if !state.ready {
                state.request.extend_from_slice(&body);
                if state.request.len() < 10 {
                    continue;
                }
                let command = state.request[1];
                assert!(command == 1 || command == 3);
                let mut address = &state.request[3..];
                crate::socks5::read_destination(&mut address, true).await?;
                let header = state.request.len() - address.len();
                body = state.request.split_off(header);
                state.ready = true;
                let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                let metadata = Metadata::Data(DataMetadata {
                    kind: DataKind::ServerData,
                    session_id: id,
                    sequence: state.next,
                    unack_sequence: state.client_next,
                    window: 64,
                    fragment: 0,
                });
                state.next += 1;
                if peer.large_response {
                    reply.extend_from_slice(&[0x91; 128]);
                    if !peer.close_after_response {
                        let future = Metadata::Data(DataMetadata {
                            kind: DataKind::ServerData,
                            session_id: id,
                            sequence: state.next,
                            unack_sequence: state.client_next,
                            window: 64,
                            fragment: 0,
                        });
                        state.next += 1;
                        // A future small frame must not steal all credit from the
                        // preceding frame, which is larger than the app queue.
                        emit_reliable(peer, &send, &encoder, state, future, &[0x92; 4], false)
                            .await?;
                    }
                }
                emit_reliable(
                    peer,
                    &send,
                    &encoder,
                    state,
                    metadata,
                    &reply,
                    peer.large_response && !peer.close_after_response,
                )
                .await?;
                if peer.close_after_response {
                    emit(
                        &send,
                        &encoder,
                        &packet.remote,
                        Metadata::Session(SessionMetadata {
                            kind: SessionKind::CloseRequest,
                            session_id: id,
                            sequence: state.next,
                            status: 0,
                        }),
                        &[],
                        false,
                    )
                    .await?;
                    sessions.remove(&id);
                    continue;
                }
            }
            if !body.is_empty() {
                let parts: Vec<_> = body.chunks(1000).collect();
                let mut frames = Vec::new();
                for part in parts {
                    let meta = Metadata::Data(DataMetadata {
                        kind: DataKind::ServerData,
                        session_id: id,
                        sequence: state.next,
                        unack_sequence: state.client_next,
                        window: 64,
                        fragment: 0,
                    });
                    state.next += 1;
                    frames.push((meta, part));
                }
                for (meta, part) in frames.into_iter().rev() {
                    emit_reliable(peer, &send, &encoder, state, meta, part, true).await?;
                }
            }
        }
    }
    fn config() -> MieruOutboundConfig {
        let mut c = super::super::tests::config(crate::config::MieruHandshake::NoWait);
        c.address = "127.0.0.1".into();
        c.transport = crate::config::MieruTransport::Udp;
        c
    }
    #[tokio::test]
    async fn mieru_udp_pattern_consumes_nonce_low_entropy_and_actual_path_budget() {
        // Independently encoded MODE32 pattern with no padding/control
        // fragmentation; fixed nonce prefix applies to every UDP attempt.
        const PATTERN: &str = "CAAaBAgAEAAiEAgDEAEYACAAKgZhYWJiY2MqBAgAEAAyBAgBEAA=";
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut peer = Peer::new(true, false);
                Arc::get_mut(&mut peer).unwrap().transmit_limit = 128;
                let mut configuration = config();
                configuration.traffic_pattern = Some(PATTERN.into());
                let node = super::super::MieruOutbound::new(
                    &configuration,
                    UpstreamPath::proxy(Arc::new(peer.clone())),
                    4096,
                )
                .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let mut stream = node
                    .connect_stream(super::super::tests::session(), &context)
                    .await
                    .unwrap()
                    .io;
                super::super::tests::echo(&mut stream, &vec![0x69; 400]).await;
                assert!(
                    peer.opens.load(Ordering::Acquire) >= 2,
                    "OPEN loss was not retried"
                );
                {
                    let received = peer.received.lock().unwrap();
                    assert!(received.iter().all(|(_, wire_len, _)| *wire_len <= 128));
                    let data: Vec<_> = received
                        .iter()
                        .filter(|(protocol, _, _)| *protocol == 10)
                        .collect();
                    assert!(!data.is_empty(), "production DATA did not use low entropy");
                    assert!(data.iter().all(|(_, _, payload_len)| *payload_len <= 20));
                    assert!(
                        received
                            .iter()
                            .filter(|(protocol, _, _)| *protocol == 2)
                            .all(|(_, _, size)| *size == 0)
                    );
                    let nonces = peer.nonces.lock().unwrap();
                    assert!(nonces.iter().all(|nonce| nonce[..3] == [0xaa, 0xbb, 0xcc]));
                    assert!(nonces.iter().all(|nonce| {
                        nonce[20..] == crypto::make_client_nonce("vole", *nonce)[20..]
                    }));
                    assert!(nonces.windows(2).all(|pair| pair[0] != pair[1]));
                }
                drop(stream);
                node.shutdown().await;
                drop(node);
                peer.stop().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test]
    async fn mieru_udp_remote_close_preserves_small_budget_partial_frame() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut peer = Peer::new(false, false);
                let fixture = Arc::get_mut(&mut peer).unwrap();
                fixture.large_response = true;
                fixture.close_after_response = true;
                let mut configuration = config();
                configuration.handshake_mode = crate::config::MieruHandshake::Standard;
                configuration.multiplexing = crate::config::MieruMultiplexing::Off;
                let node = super::super::MieruOutbound::new(
                    &configuration,
                    UpstreamPath::proxy(Arc::new(peer.clone())),
                    8,
                )
                .unwrap();
                let result: io::Result<crate::dispatch::BoxStream> = async {
                    let context = EstablishContext::with_timeout(Duration::from_secs(5));
                    let mut stream = node
                        .connect_stream(super::super::tests::session(), &context)
                        .await
                        .map_err(io::Error::other)?
                        .io;
                    // This response witnesses that remote Close was consumed
                    // before the app releases credit for the remaining DATA.
                    tokio::time::timeout(Duration::from_secs(1), peer.close_replied.notified())
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)?;
                    let mut got = [0; 128];
                    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut got))
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)??;
                    assert_eq!(got, [0x91; 128]);
                    let mut last = [0];
                    let count =
                        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut last))
                            .await
                            .map_err(|_| io::ErrorKind::TimedOut)??;
                    assert_eq!(count, 0, "remote close did not finish after DATA");
                    drop(stream);
                    let context = EstablishContext::with_timeout(Duration::from_secs(5));
                    let stream = node
                        .connect_stream(super::super::tests::session(), &context)
                        .await
                        .map_err(io::Error::other)?
                        .io;
                    tokio::time::timeout(Duration::from_secs(1), peer.close_replied.notified())
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)?;
                    // Keep a remotely closed partial frame unread. Node Stop
                    // must still cancel and join without waiting for byte credit.
                    Ok(stream)
                }
                .await;
                let failure = result.as_ref().err().map(ToString::to_string);
                tokio::time::timeout(Duration::from_secs(2), node.shutdown())
                    .await
                    .unwrap();
                drop(result);
                drop(node);
                peer.stop().await;
                assert!(
                    failure.is_none(),
                    "remote Close lost DATA tail: {failure:?}"
                );
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test]
    async fn mieru_udp_small_byte_budget_delivers_large_reordered_frames_and_stops() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let mut peer = Peer::new(false, false);
                Arc::get_mut(&mut peer).unwrap().large_response = true;
                let mut configuration = config();
                configuration.handshake_mode = crate::config::MieruHandshake::Standard;
                configuration.multiplexing = crate::config::MieruMultiplexing::Off;
                let node = super::super::MieruOutbound::new(
                    &configuration,
                    UpstreamPath::proxy(Arc::new(peer.clone())),
                    8,
                )
                .unwrap();
                let result: io::Result<crate::dispatch::BoxStream> = async {
                    let context = EstablishContext::with_timeout(Duration::from_secs(5));
                    let mut stream = node
                        .connect_stream(super::super::tests::session(), &context)
                        .await
                        .map_err(io::Error::other)?
                        .io;
                    let mut expected = vec![0x91; 128];
                    expected.extend_from_slice(&[0x92; 4]);
                    let mut got = vec![0; expected.len()];
                    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut got))
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)??;
                    if got != expected {
                        return Err(io::Error::other(
                            "small-budget frame was reordered or duplicated",
                        ));
                    }
                    let data = b"small-budget roundtrip";
                    stream.write_all(data).await?;
                    let mut echo = vec![0; data.len()];
                    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)??;
                    if echo != data {
                        return Err(io::Error::other("small-budget business bytes changed"));
                    }
                    drop(stream);
                    let context = EstablishContext::with_timeout(Duration::from_secs(5));
                    // Leave the server-first frame partially unread so Stop must
                    // release both queued byte permits and the physical frame slot.
                    Ok(node
                        .connect_stream(super::super::tests::session(), &context)
                        .await
                        .map_err(io::Error::other)?
                        .io)
                }
                .await;
                let failure = result.as_ref().err().map(ToString::to_string);
                tokio::time::timeout(Duration::from_secs(2), node.shutdown())
                    .await
                    .unwrap();
                drop(result);
                drop(node);
                peer.stop().await;
                assert!(
                    failure.is_none(),
                    "capacity 8 UDP stream failed: {failure:?}"
                );
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[test]
    fn mieru_udp_reorder_gap_keeps_receive_credit() {
        const CHUNK: usize = 32;
        const CAPACITY: usize = 3 * CHUNK;
        let cancellation = CancellationToken::new();
        let state = State::new(
            1,
            CAPACITY,
            &cancellation,
            Arc::new(tokio::sync::Notify::new()),
        );
        let mut reliable = Reliable::new(state.clone(), CHUNK);
        let mut partial = None;
        reliable.input(
            Frame {
                metadata: Metadata::Session(SessionMetadata {
                    kind: SessionKind::OpenResponse,
                    session_id: 1,
                    sequence: 0,
                    status: 0,
                }),
                payload: Bytes::new(),
            },
            Instant::now(),
            &mut partial,
        );
        let frame = |sequence: u32| Frame {
            metadata: Metadata::Data(DataMetadata {
                kind: DataKind::ServerData,
                session_id: 1,
                sequence,
                unack_sequence: 0,
                window: 16,
                fragment: 0,
            }),
            payload: Bytes::from(vec![sequence as u8; CHUNK]),
        };
        assert!(!reliable.small_budget());
        // A missing seq1 followed by a burst of future DATA must not consume
        // the credit seq1 needs to unblock the actual receive queue.
        for sequence in 2..=4 {
            reliable.input(frame(sequence), Instant::now(), &mut partial);
        }
        assert_eq!(state.next_receive.load(Ordering::Acquire), 1);
        reliable.input(frame(1), Instant::now(), &mut partial);
        assert_eq!(
            state.next_receive.load(Ordering::Acquire),
            4,
            "future DATA exhausted the missing segment's receive credit"
        );
        let waker = futures_util::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        for sequence in 1..=3 {
            let mut bytes = [0; CHUNK];
            let mut read = tokio::io::ReadBuf::new(&mut bytes);
            assert!(matches!(
                state.poll_read(&mut context, &mut read),
                std::task::Poll::Ready(Ok(()))
            ));
            assert_eq!(read.filled(), &[sequence; CHUNK]);
        }
        assert_eq!(state.receive_bytes.available_permits(), CAPACITY);
        // The future seq4 may be dropped to keep the missing-segment credit.
        // Its real retransmission succeeds once application reads free bytes.
        reliable.input(frame(4), Instant::now(), &mut partial);
        let mut bytes = [0; CHUNK];
        let mut read = tokio::io::ReadBuf::new(&mut bytes);
        assert!(matches!(
            state.poll_read(&mut context, &mut read),
            std::task::Poll::Ready(Ok(()))
        ));
        assert_eq!(read.filled(), &[4; CHUNK]);
        assert_eq!(state.next_receive.load(Ordering::Acquire), 5);
        assert!(reliable.reorder.is_empty());
        assert!(partial.is_none());
        assert_eq!(state.receive_bytes.available_permits(), CAPACITY);
        state.close();
    }

    #[test]
    fn mieru_udp_partial_slot_keeps_byte_credit_and_control_live() {
        let cancellation = CancellationToken::new();
        let state = State::new(1, 8, &cancellation, Arc::new(tokio::sync::Notify::new()));
        let mut sessions = BTreeMap::from([(1, Reliable::new(state.clone(), 1312))]);
        let mut partial = None;
        let data = |sequence, payload: Bytes| Frame {
            metadata: Metadata::Data(DataMetadata {
                kind: DataKind::ServerData,
                session_id: 1,
                sequence,
                unack_sequence: 0,
                window: 64,
                fragment: 0,
            }),
            payload,
        };
        assert_eq!(sessions[&1].window(true), 1);
        sessions.get_mut(&1).unwrap().input(
            data(1, Bytes::from_static(b"late")),
            Instant::now(),
            &mut partial,
        );
        assert_eq!(state.receive_bytes.available_permits(), 8);
        assert!(sessions[&1].reorder.is_empty());
        let expected = b"abcdefghijklmnopqrstuvwxyz12";
        let mut allocation = vec![0; 8192];
        allocation[1024..1024 + expected.len()].copy_from_slice(expected);
        let large = Bytes::from(allocation).slice(1024..1024 + expected.len());
        let original = large.as_ptr();
        sessions
            .get_mut(&1)
            .unwrap()
            .input(data(0, large), Instant::now(), &mut partial);
        assert_ne!(partial.as_ref().unwrap().payload.as_ptr(), original);
        let _ = advance_partial(&mut partial, &mut sessions);
        assert_eq!(state.receive_bytes.available_permits(), 0);
        assert_eq!(state.next_receive.load(Ordering::Acquire), 0);
        assert_eq!(sessions[&1].window(false), 0);
        sessions.get_mut(&1).unwrap().input(
            data(0, Bytes::copy_from_slice(expected)),
            Instant::now(),
            &mut partial,
        );
        assert_eq!(partial.as_ref().unwrap().offset, 8);
        sessions.get_mut(&1).unwrap().input(
            Frame {
                metadata: Metadata::Session(SessionMetadata {
                    kind: SessionKind::OpenResponse,
                    session_id: 1,
                    sequence: 1,
                    status: 0,
                }),
                payload: Bytes::new(),
            },
            Instant::now(),
            &mut partial,
        );
        sessions.get_mut(&1).unwrap().input(
            Frame {
                metadata: Metadata::Data(DataMetadata {
                    kind: DataKind::ServerAck,
                    session_id: 1,
                    sequence: 1,
                    unack_sequence: 0,
                    window: 77,
                    fragment: 0,
                }),
                payload: Bytes::new(),
            },
            Instant::now(),
            &mut partial,
        );
        assert!(sessions[&1].established);
        assert_eq!(sessions[&1].remote_window, 77);
        let waker = futures_util::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        let mut got = Vec::new();
        loop {
            let mut bytes = [0; 8];
            let mut buffer = tokio::io::ReadBuf::new(&mut bytes);
            assert!(matches!(
                state.poll_read(&mut context, &mut buffer),
                std::task::Poll::Ready(Ok(()))
            ));
            got.extend_from_slice(buffer.filled());
            assert_eq!(state.receive_bytes.available_permits(), 8);
            if partial.is_none() {
                break;
            }
            let _ = advance_partial(&mut partial, &mut sessions);
        }
        assert_eq!(got, expected);
        assert_eq!(state.next_receive.load(Ordering::Acquire), 2);
        sessions.get_mut(&1).unwrap().input(
            data(2, Bytes::copy_from_slice(expected)),
            Instant::now(),
            &mut partial,
        );
        let _ = advance_partial(&mut partial, &mut sessions);
        state.close();
        let _ = advance_partial(&mut partial, &mut sessions);
        assert!(partial.is_none());
        assert_eq!(state.receive_bytes.available_permits(), 8);
    }
    #[tokio::test]
    async fn mieru_udp_standard_recovers_first_packet_loss_in_both_directions() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let peer = Peer::with_response_loss(true, true, false);
                let mut configuration = config();
                configuration.handshake_mode = crate::config::MieruHandshake::Standard;
                let node = super::super::MieruOutbound::new(
                    &configuration,
                    UpstreamPath::proxy(Arc::new(peer.clone())),
                    32768,
                )
                .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(10));
                let result = node
                    .connect_stream(super::super::tests::session(), &context)
                    .await;
                assert!(
                    peer.opens.load(Ordering::Relaxed) >= 2,
                    "client first OPEN was not retried"
                );
                assert!(
                    peer.response_dropped.load(Ordering::Acquire),
                    "server first response was not dropped"
                );
                assert!(
                    peer.response_transmissions.load(Ordering::Relaxed) >= 2,
                    "server OPEN response was not retried"
                );
                let mut stream = result
                    .expect("STANDARD SOCKS handshake failed under one loss per direction")
                    .io;
                super::super::tests::echo(&mut stream, b"standard double-loss echo").await;
                drop(stream);
                node.shutdown().await;
                drop(node);
                peer.stop().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test]
    async fn mieru_udp_lost_open_reorders_duplicate_data_and_business_packets() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let peer = Peer::new(true, false);
                let node = super::super::MieruOutbound::new(
                    &config(),
                    UpstreamPath::proxy(Arc::new(peer.clone())),
                    32768,
                )
                .unwrap();
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let mut stream = node
                    .connect_stream(super::super::tests::session(), &context)
                    .await
                    .unwrap()
                    .io;
                let data: Vec<_> = (0..5000).map(|i| (i % 251) as u8).collect();
                tokio::time::timeout(Duration::from_secs(8), async {
                    stream.write_all(&data).await.unwrap();
                    let mut got = vec![0; data.len()];
                    stream.read_exact(&mut got).await.unwrap();
                    assert_eq!(got, data);
                })
                .await
                .unwrap();
                assert!(peer.opens.load(Ordering::Relaxed) >= 2);
                let nonces = peer.nonces.lock().unwrap().clone();
                assert_eq!(
                    nonces.len(),
                    nonces
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                );
                let request = DatagramRequest::new(DatagramSession::new(
                    InboundKind::Socks5,
                    "192.0.2.10:1000".parse().unwrap(),
                ));
                let mut packet = node.open_datagram(request, &context).await.unwrap();
                let payload = Bytes::from(vec![9; 1200]);
                let remote = Destination::Ip("198.51.100.1:53".parse().unwrap());
                packet
                    .send(Datagram {
                        remote: remote.clone(),
                        payload: payload.clone(),
                        sniffed_domain: None,
                    })
                    .await
                    .unwrap();
                let echoed = tokio::time::timeout(Duration::from_secs(3), packet.receive())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(echoed.payload, payload);
                assert_eq!(echoed.remote, remote);
                packet.close().await.unwrap();
                drop(packet);
                drop(stream);
                node.shutdown().await;
                drop(node);
                peer.stop().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test]
    async fn mieru_udp_stop_releases_unacked_bytes_and_open_deadline() {
        let probe = ResourceProbe::default();
        probe.scope(async{
            let peer=Peer::new(false,true);let node=super::super::MieruOutbound::new(&config(),UpstreamPath::proxy(Arc::new(peer.clone())),32768).unwrap();let context=EstablishContext::with_timeout(Duration::from_secs(5));let mut stream=node.connect_stream(super::super::tests::session(),&context).await.unwrap().io;let data=vec![1;32768];{let writing=stream.write_all(&data);tokio::pin!(writing);tokio::select!{result=&mut writing=>panic!("unacknowledged opening unexpectedly wrote: {result:?}"),()=tokio::time::sleep(Duration::from_millis(20))=>{}}
            tokio::time::timeout(Duration::from_secs(2),node.shutdown()).await.unwrap();assert!(writing.await.is_err());}drop(stream);drop(node);peer.stop().await;
        }).await;
        assert!(probe.snapshot().is_idle());
    }
    #[tokio::test]
    async fn mieru_udp_reorder_unread_and_unacknowledged_credit_are_independent() {
        let cancellation = CancellationToken::new();
        let state = State::new(1, 8, &cancellation, Arc::new(tokio::sync::Notify::new()));
        let mut reliable = Reliable::new(state.clone(), 2);
        let mut partial = None;
        let frame = |sequence, bytes: &'static [u8]| Frame {
            metadata: Metadata::Data(DataMetadata {
                kind: DataKind::ServerData,
                session_id: 1,
                sequence,
                unack_sequence: 0,
                window: 16,
                fragment: 0,
            }),
            payload: Bytes::from_static(bytes),
        };
        reliable.input(frame(1, b"AAAA"), Instant::now(), &mut partial);
        assert_eq!(state.receive_bytes.available_permits(), 8);
        assert_eq!(reliable.reorder_bytes.available_permits(), 4);
        reliable.input(frame(0, b"BBBB"), Instant::now(), &mut partial);
        assert!(reliable.reorder.is_empty());
        assert_eq!(state.receive_bytes.available_permits(), 0);
        assert_eq!(reliable.reorder_bytes.available_permits(), 8);
        assert_eq!(reliable.window(true), 4);
        reliable.input(frame(1, b"wrong"), Instant::now(), &mut partial);
        let mut buffer = [0; 4];
        let mut read = tokio::io::ReadBuf::new(&mut buffer);
        futures_util::future::poll_fn(|cx| state.poll_read(cx, &mut read))
            .await
            .unwrap();
        assert_eq!(buffer, *b"BBBB");
        assert_eq!(state.receive_bytes.available_permits(), 4);
        let mut read = tokio::io::ReadBuf::new(&mut buffer);
        futures_util::future::poll_fn(|cx| state.poll_read(cx, &mut read))
            .await
            .unwrap();
        assert_eq!(buffer, *b"AAAA");
        assert_eq!(state.receive_bytes.available_permits(), 8);
        let permits = Arc::new(tokio::sync::Semaphore::new(8));
        let permit = permits.clone().acquire_many_owned(8).await.unwrap();
        let (done, result) = oneshot::channel();
        reliable.enqueue(
            WriterCommand {
                state: state.clone(),
                data: Bytes::from_static(b"12345678"),
                piggyback: true,
                done,
                _bytes: permit,
            },
            2,
            true,
        );
        while let Some(mut segment) = reliable.pending.pop_front() {
            segment.sent = Some(Instant::now());
            segment.tx_count = 1;
            if let Some(lease) = &segment.lease {
                lease.sent();
            }
            reliable
                .outstanding
                .insert(sequence(segment.metadata), segment);
        }
        result.await.unwrap().unwrap();
        assert_eq!(permits.available_permits(), 0);
        reliable.acknowledge(3, 16, true, Instant::now());
        assert_eq!(permits.available_permits(), 0);
        reliable.acknowledge(3, 16, true, Instant::now());
        reliable.acknowledge(3, 16, true, Instant::now());
        assert_eq!(reliable.outstanding.get(&3).unwrap().ack_count, 3);
        reliable.acknowledge(5, 16, true, Instant::now());
        assert_eq!(permits.available_permits(), 8);
        state.close();
        drop(reliable);
        drop(state);
    }
}

#[cfg(test)]
include!("udp_split_receive_tests.rs");

#[cfg(test)]
include!("udp_balanced_driver_tests.rs");
