//! Bounded Linux real-Echo owner. DIRECT only; no rule graph or target tasks.
use crate::{
    config::IpCidr,
    dialer::{Dialer, PhysicalPing, PingReceipt},
    platform::TunIo,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use std::{io, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{
    EchoPacketClass, EchoPacketView, Packet, classify_echo_request, encode_echo_reply_into,
    parse_echo_reply_body,
};

pub(crate) const ECHO_QUEUE: usize = 8;
const MAX_PENDING: usize = 64;
const MAX_PACKET: usize = 2048;
const HOUSEKEEPING: Duration = Duration::from_millis(250);
const IDLE_SOCKET: Duration = Duration::from_secs(10);

use super::{EchoOffer, QueuedEchoResponse};
pub(crate) struct EchoOptions {
    dialer: Dialer,
    local_prefixes: Vec<IpCidr>,
    fake_ranges: [Option<IpCidr>; 2],
    timeout: Duration,
    disabled: bool,
}
impl EchoOptions {
    pub(crate) async fn prepare(
        dialer: Dialer,
        tun: Arc<TunIo>,
        fake_ranges: [Option<IpCidr>; 2],
        timeout: Duration,
        disabled: bool,
    ) -> io::Result<Self> {
        // No query, permission test or socket creation for explicitly disabled forwarding.
        let local_prefixes = if disabled {
            Vec::new()
        } else {
            dialer.ping_tun_prefixes(tun).await?
        };
        Ok(Self {
            dialer,
            local_prefixes,
            fake_ranges,
            timeout,
            disabled,
        })
    }
}
struct Request {
    source: IpAddr,
    destination: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
}
pub(crate) struct EchoIngress {
    sender: mpsc::Sender<Request>,
    permits: Arc<Semaphore>,
    local_prefixes: Vec<IpCidr>,
    fake_ranges: [Option<IpCidr>; 2],
    timeout: Duration,
    disabled: bool,
    max_packet: usize,
}
impl EchoIngress {
    // Nonblocking: physical failures/pressure are consumed and cannot become
    // synthetic successful replies. Recognized invalid Echo is consumed; genuine
    // non-Echo/error packets keep the existing netstack path.
    pub(crate) fn offer(&self, packet: &[u8]) -> EchoOffer {
        let view = match classify_echo_request(packet) {
            EchoPacketClass::NotEcho => return EchoOffer::NotEcho,
            EchoPacketClass::Rejected => return EchoOffer::Consumed,
            EchoPacketClass::Request(view) => view,
        };
        if self.disabled
            || self
                .local_prefixes
                .iter()
                .any(|p| p.contains(view.destination))
            || self
                .fake_ranges
                .iter()
                .flatten()
                .any(|p| p.contains(view.destination))
        {
            return EchoOffer::LocalSynthetic;
        }
        if packet.len() > self.max_packet || self.sender.is_closed() {
            return EchoOffer::Consumed;
        }
        let Ok(slot) = self.sender.try_reserve() else {
            return EchoOffer::Consumed;
        };
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return EchoOffer::Consumed;
        };
        let request = Request {
            source: view.source,
            destination: view.destination,
            identifier: view.identifier,
            sequence: view.sequence,
            payload: view.payload.to_vec(),
            deadline: match Instant::now().checked_add(self.timeout) {
                Some(d) => d,
                None => return EchoOffer::Consumed,
            },
            permit,
        };
        // A full queue drops the one bounded request and its permit here.
        slot.send(request);
        EchoOffer::Consumed
    }
}
struct Pending {
    family: usize,
    wire_id: u16,
    wire_sequence: u16,
    source: IpAddr,
    destination: IpAddr,
    identifier: u16,
    sequence: u16,
    payload_len: usize,
    payload_hash: [u8; 32],
    deadline: Instant,
    permit: OwnedSemaphorePermit,
}
struct Family {
    socket: Option<PhysicalPing>,
    loopback: bool,
    next_identifier: u16,
    identifiers_issued: u32,
    next_sequence: u32,
    used_at: Instant,
}
impl Family {
    fn new() -> Self {
        Self {
            socket: None,
            loopback: false,
            next_identifier: rand::random::<u16>().max(1),
            identifiers_issued: 0,
            next_sequence: 0,
            used_at: Instant::now(),
        }
    }
    fn reserve_identifier(&mut self) -> Option<u16> {
        if self.identifiers_issued == u32::from(u16::MAX) {
            return None;
        }
        let id = self.next_identifier;
        self.next_identifier = id.wrapping_add(1).max(1);
        self.identifiers_issued += 1;
        Some(id)
    }
}
pub(crate) struct EchoDriver {
    dialer: Dialer,
    requests: mpsc::Receiver<Request>,
    responses: mpsc::Sender<QueuedEchoResponse>,
    families: [Family; 2],
    pending: [Option<Pending>; MAX_PENDING],
    max_packet: usize,
}
pub(crate) fn channel(
    options: EchoOptions,
    mtu: usize,
) -> (EchoIngress, mpsc::Receiver<QueuedEchoResponse>, EchoDriver) {
    let (sender, requests) = mpsc::channel(ECHO_QUEUE);
    let (responses, receiver) = mpsc::channel(ECHO_QUEUE);
    let max_packet = mtu.min(MAX_PACKET);
    let ingress = EchoIngress {
        sender,
        permits: Arc::new(Semaphore::new(MAX_PENDING)),
        local_prefixes: options.local_prefixes,
        fake_ranges: options.fake_ranges,
        timeout: options.timeout,
        disabled: options.disabled,
        max_packet,
    };
    let driver = EchoDriver {
        dialer: options.dialer,
        requests,
        responses,
        families: [Family::new(), Family::new()],
        pending: std::array::from_fn(|_| None),
        max_packet,
    };
    (ingress, receiver, driver)
}
enum Event {
    Stop,
    Tick,
    Request(Option<Request>),
    Received(usize, io::Result<PingReceipt>),
}
async fn receive(socket: Option<&PhysicalPing>, bytes: &mut [u8]) -> io::Result<PingReceipt> {
    match socket {
        Some(socket) => socket.recv(bytes).await,
        None => std::future::pending().await,
    }
}
impl EchoDriver {
    pub(crate) async fn run(mut self, cancellation: CancellationToken) -> io::Result<()> {
        let mut tick = tokio::time::interval(HOUSEKEEPING);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut v4 = [0u8; MAX_PACKET];
        let mut v6 = [0u8; MAX_PACKET];
        loop {
            // Cancellation-safe recvmsg runs only when selected readiness is polled;
            // the received bytes and metadata are consumed by this sole owner.
            if cancellation.is_cancelled() {
                return Ok(());
            }
            let event = tokio::select! {
                () = cancellation.cancelled() => Event::Stop,
                _ = tick.tick() => Event::Tick,
                request = self.requests.recv() => Event::Request(request),
                result = receive(self.families[0].socket.as_ref(), &mut v4) => Event::Received(0, result),
                result = receive(self.families[1].socket.as_ref(), &mut v6) => Event::Received(1, result),
            };
            match event {
                Event::Stop | Event::Request(None) => return Ok(()),
                Event::Tick => self.expire(),
                Event::Request(Some(request)) => self.send(request, &cancellation).await,
                Event::Received(family, Ok(receipt)) => {
                    let bytes = if family == 0 {
                        &v4[..receipt.length]
                    } else {
                        &v6[..receipt.length]
                    };
                    self.reply(family, receipt, bytes);
                }
                Event::Received(_, Err(error)) if error.kind() == io::ErrorKind::InvalidData => {}
                Event::Received(family, Err(error)) => {
                    tracing::debug!(family, error = %error, "closing failed physical ICMP socket");
                    self.close_family(family);
                }
            }
            // Incoming Echo floods cannot monopolize ready sockets/queues.
            tokio::task::consume_budget().await;
        }
    }
    fn has_pending(&self, family: usize) -> bool {
        self.pending.iter().flatten().any(|p| p.family == family)
    }
    fn close_family(&mut self, family: usize) {
        self.families[family].socket = None;
        for item in &mut self.pending {
            if item.as_ref().is_some_and(|p| p.family == family) {
                *item = None;
            }
        }
    }
    fn expire(&mut self) {
        let now = Instant::now();
        for item in &mut self.pending {
            if item.as_ref().is_some_and(|p| now >= p.deadline) {
                *item = None;
            }
        }
        for family in 0..2 {
            if !self.has_pending(family)
                && now.duration_since(self.families[family].used_at) >= IDLE_SOCKET
            {
                self.families[family].socket = None;
            }
        }
    }
    async fn ensure_socket(&mut self, family: usize, destination: IpAddr) -> io::Result<()> {
        self.dialer.permit_ping_destination(destination)?;
        let change = self.families[family].loopback != destination.is_loopback()
            || self.families[family].next_sequence > u32::from(u16::MAX);
        if change {
            // Never rebind/reconfigure a socket with unrelated in-flight probes.
            if self.has_pending(family) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.families[family].socket = None;
        }
        if self.families[family].socket.is_some() {
            return Ok(());
        }
        for _ in 0..32 {
            let identifier = self.families[family].reserve_identifier().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "ICMP wire identity space exhausted",
                )
            })?;
            match self.dialer.bind_ping_for(destination, identifier).await {
                Ok(socket) => {
                    self.families[family].socket = Some(socket);
                    self.families[family].loopback = destination.is_loopback();
                    self.families[family].next_sequence = 0;
                    return Ok(());
                }
                Err(error) if error.raw_os_error() == Some(libc::EADDRINUSE) => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::ErrorKind::AddrInUse.into())
    }
    async fn send(&mut self, request: Request, cancellation: &CancellationToken) {
        self.expire();
        if Instant::now() >= request.deadline {
            return;
        }
        let Some(slot) = self.pending.iter().position(Option::is_none) else {
            return;
        };
        let family = usize::from(request.destination.is_ipv6());
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            result = self.ensure_socket(family, request.destination) => result,
        };
        if let Err(error) = result {
            // EPERM/EACCES are real installation-policy failures, not API absence
            // and never a reason to forge a local success or raise privileges.
            tracing::debug!(family, error = %error, "physical ICMP admission failed");
            return;
        }
        if Instant::now() >= request.deadline {
            return;
        }
        let state = &mut self.families[family];
        let socket = state.socket.as_ref().expect("initialized ping socket");
        let wire_id = socket.identifier;
        let wire_sequence = state.next_sequence as u16;
        state.next_sequence += 1;
        state.used_at = Instant::now();
        let mut body = Vec::with_capacity(8 + request.payload.len());
        body.extend_from_slice(&[if family == 0 { 8 } else { 128 }, 0, 0, 0]);
        body.extend_from_slice(&wire_id.to_be_bytes());
        body.extend_from_slice(&wire_sequence.to_be_bytes());
        body.extend_from_slice(&request.payload);
        if family == 0 {
            let checksum = checksum(&body);
            body[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        // Linux ping-v6 computes the ICMPv6 pseudoheader checksum after selecting
        // the physical source. The physical reply is independently checked below.
        let sent = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            result = tokio::time::timeout_at(request.deadline, socket.send(request.destination, &body)) => result,
        };
        if !matches!(sent, Ok(Ok(()))) {
            return;
        }
        self.pending[slot] = Some(Pending {
            family,
            wire_id,
            wire_sequence,
            source: request.source,
            destination: request.destination,
            identifier: request.identifier,
            sequence: request.sequence,
            payload_len: request.payload.len(),
            payload_hash: Sha256::digest(&request.payload).into(),
            deadline: request.deadline,
            permit: request.permit,
        });
        // request.payload/body drop here: pending retains metadata/hash only.
    }
    fn reply(&mut self, family: usize, receipt: PingReceipt, bytes: &[u8]) {
        if receipt.interface == 0 {
            return;
        }
        let Some(view) = parse_echo_reply_body(receipt.peer, receipt.local, bytes) else {
            return;
        };
        let Some(slot) = self.pending.iter().position(|p| {
            p.as_ref().is_some_and(|p| {
                p.family == family
                    && p.wire_id == view.identifier
                    && p.wire_sequence == view.sequence
            })
        }) else {
            return;
        };
        let pending = self.pending[slot].as_ref().unwrap();
        if Instant::now() >= pending.deadline
            || view.source != pending.destination
            || view.payload.len() != pending.payload_len
            || <[u8; 32]>::from(Sha256::digest(view.payload)) != pending.payload_hash
        {
            return;
        }
        let pending = self.pending[slot].take().unwrap();
        let reply = EchoPacketView {
            source: pending.destination,
            destination: pending.source,
            identifier: pending.identifier,
            sequence: pending.sequence,
            payload: view.payload,
        };
        let mut frame = Vec::new();
        if encode_echo_reply_into(&reply, self.max_packet, &mut frame).is_err() {
            return;
        }
        let _ = self.responses.try_send(QueuedEchoResponse {
            packet: Packet::new(Bytes::from(frame)),
            permit: pending.permit,
        });
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (EchoIngress, mpsc::Receiver<QueuedEchoResponse>, EchoDriver) {
        channel(
            EchoOptions {
                dialer: Dialer::default(),
                local_prefixes: vec![IpCidr {
                    network: "10.0.0.0".parse().unwrap(),
                    prefix_len: 24,
                }],
                fake_ranges: [
                    Some(IpCidr {
                        network: "198.18.0.0".parse().unwrap(),
                        prefix_len: 16,
                    }),
                    None,
                ],
                timeout: Duration::from_secs(10),
                disabled: false,
            },
            1500,
        )
    }
    fn request(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 31];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&31u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&33u16.to_be_bytes());
        packet[26..28].copy_from_slice(&9u16.to_be_bytes());
        packet[28..].copy_from_slice(b"odd");
        let icmp = checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp.to_be_bytes());
        let ip = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip.to_be_bytes());
        packet
    }
    fn response(payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 8 + payload.len()];
        body[4..6].copy_from_slice(&17u16.to_be_bytes());
        body[6..8].copy_from_slice(&3u16.to_be_bytes());
        body[8..].copy_from_slice(payload);
        let value = checksum(&body);
        body[2..4].copy_from_slice(&value.to_be_bytes());
        body
    }
    fn install_pending(ingress: &EchoIngress, driver: &mut EchoDriver) {
        driver.pending[0] = Some(Pending {
            family: 0,
            wire_id: 17,
            wire_sequence: 3,
            source: "10.0.0.2".parse().unwrap(),
            destination: "203.0.113.9".parse().unwrap(),
            identifier: 33,
            sequence: 9,
            payload_len: 3,
            payload_hash: Sha256::digest(b"odd").into(),
            deadline: Instant::now() + Duration::from_secs(10),
            permit: ingress.permits.clone().try_acquire_owned().unwrap(),
        });
    }
    #[test]
    fn bounded_admission_and_local_cases_do_not_open_sockets() {
        let (mut ingress, _responses, mut driver) = setup();
        assert_eq!(
            ingress.offer(&request([10, 0, 0, 99])),
            EchoOffer::LocalSynthetic
        );
        assert_eq!(
            ingress.offer(&request([198, 18, 7, 99])),
            EchoOffer::LocalSynthetic
        );
        for _ in 0..ECHO_QUEUE + 1 {
            assert_eq!(
                ingress.offer(&request([203, 0, 113, 9])),
                EchoOffer::Consumed
            );
        }
        assert_eq!(
            ingress.permits.available_permits(),
            MAX_PENDING - ECHO_QUEUE
        );
        for _ in 0..ECHO_QUEUE {
            drop(driver.requests.try_recv().unwrap());
        }
        assert!(driver.requests.try_recv().is_err());
        assert_eq!(ingress.permits.available_permits(), MAX_PENDING);
        let mut bad = request([10, 0, 0, 99]);
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(ingress.offer(&bad), EchoOffer::Consumed);
        ingress.disabled = true;
        assert_eq!(
            ingress.offer(&request([203, 0, 113, 9])),
            EchoOffer::LocalSynthetic
        );
        assert!(driver.families.iter().all(|f| f.socket.is_none()));
    }
    #[test]
    fn only_valid_origin_body_identity_and_unexpired_reply_owns_the_permit() {
        let (ingress, mut responses, mut driver) = setup();
        install_pending(&ingress, &mut driver);
        let body = response(b"odd");
        let receipt = PingReceipt {
            length: body.len(),
            peer: "203.0.113.9".parse().unwrap(),
            local: "192.0.2.100".parse().unwrap(),
            interface: 2,
        };
        driver.reply(
            0,
            PingReceipt {
                peer: "203.0.113.10".parse().unwrap(),
                ..receipt
            },
            &body,
        );
        let mut corrupt = body.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        driver.reply(0, receipt, &corrupt);
        driver.reply(0, receipt, &response(b"bad"));
        assert!(driver.pending[0].is_some());
        assert!(responses.try_recv().is_err());
        driver.reply(0, receipt, &body);
        assert!(driver.pending[0].is_none());
        let reply = responses.try_recv().unwrap();
        let decoded = parse_echo_reply_body(
            "203.0.113.9".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            &reply.packet.data()[20..],
        )
        .unwrap();
        assert_eq!(
            (decoded.identifier, decoded.sequence, decoded.payload),
            (33, 9, &b"odd"[..])
        );
        assert_eq!(ingress.permits.available_permits(), MAX_PENDING - 1);
        driver.reply(0, receipt, &body);
        assert!(responses.try_recv().is_err());
        drop(reply);
        assert_eq!(ingress.permits.available_permits(), MAX_PENDING);
        install_pending(&ingress, &mut driver);
        driver.pending[0].as_mut().unwrap().deadline = Instant::now();
        driver.reply(0, receipt, &body);
        assert!(responses.try_recv().is_err());
        driver.expire();
        assert_eq!(ingress.permits.available_permits(), MAX_PENDING);
    }
    #[test]
    fn wire_identifiers_do_not_repeat_on_rollover() {
        let mut family = Family::new();
        family.next_identifier = u16::MAX;
        assert_eq!(family.reserve_identifier(), Some(u16::MAX));
        assert_eq!(family.reserve_identifier(), Some(1));
        family.identifiers_issued = u32::from(u16::MAX);
        assert_eq!(family.reserve_identifier(), None);
    }
    #[tokio::test]
    async fn cancelled_owner_drops_input_and_pending_without_creating_a_socket() {
        let (ingress, _responses, mut driver) = setup();
        install_pending(&ingress, &mut driver);
        assert_eq!(
            ingress.offer(&request([203, 0, 113, 9])),
            EchoOffer::Consumed
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        driver.run(cancellation).await.unwrap();
        assert_eq!(ingress.permits.available_permits(), MAX_PENDING);
    }

    #[test]
    fn oversized_real_echo_drops_without_consuming_queue_or_pending_capacity() {
        let (ingress, _responses, mut driver) = setup();
        let mut packet = request([203, 0, 113, 9]);
        packet.resize(1501, 0x35);
        packet[2..4].copy_from_slice(&1501u16.to_be_bytes());
        packet[22..24].fill(0);
        let icmp = checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp.to_be_bytes());
        packet[10..12].fill(0);
        let ip = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip.to_be_bytes());
        assert_eq!(ingress.offer(&packet), EchoOffer::Consumed);
        assert!(driver.requests.try_recv().is_err());
        assert_eq!(ingress.permits.available_permits(), MAX_PENDING);
        assert!(driver.families.iter().all(|f| f.socket.is_none()));
    }
}
