//! Bounded packet-layer TCP adaptation around the unmodified smoltcp engine.
//! The TCP socket continues to own ACK, retransmission and congestion state.

use std::collections::VecDeque;

use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};

use crate::{Packet, pmtu::PathMtuHint, tcp::FlowKey};

/// Exhaustion forgets older optimizations; it never authorizes unseen bytes.
const CACHE_ENTRIES: usize = 64;

#[derive(Clone, Copy)]
struct TcpView {
    flow: FlowKey,
    ip_len: usize,
    tcp_len: usize,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload_len: usize,
}

impl TcpView {
    fn parse(bytes: &[u8], verify_checksum: bool) -> Option<Self> {
        let (source, destination, ip_len) = match bytes.first()? >> 4 {
            4 => {
                let ip = Ipv4Packet::new_checked(bytes).ok()?;
                if usize::from(ip.total_len()) != bytes.len()
                    || ip.next_header() != IpProtocol::Tcp
                    || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
                    || (verify_checksum && !ip.verify_checksum())
                {
                    return None;
                }
                (
                    ip.src_addr().into(),
                    ip.dst_addr().into(),
                    usize::from(ip.header_len()),
                )
            }
            6 => {
                let ip = Ipv6Packet::new_checked(bytes).ok()?;
                if ip.total_len() != bytes.len() || ip.next_header() != IpProtocol::Tcp {
                    return None;
                }
                (ip.src_addr().into(), ip.dst_addr().into(), 40)
            }
            _ => return None,
        };
        let tcp = TcpPacket::new_checked(&bytes[ip_len..]).ok()?;
        if verify_checksum && !tcp.verify_checksum(&source, &destination) {
            return None;
        }
        let tcp_len = usize::from(tcp.header_len());
        Some(Self {
            flow: FlowKey {
                source: std::net::SocketAddr::new(source.into(), tcp.src_port()),
                destination: std::net::SocketAddr::new(destination.into(), tcp.dst_port()),
            },
            ip_len,
            tcp_len,
            sequence: u32::from_be_bytes(bytes[ip_len + 4..ip_len + 8].try_into().ok()?),
            acknowledgment: u32::from_be_bytes(bytes[ip_len + 8..ip_len + 12].try_into().ok()?),
            flags: bytes[ip_len + 13],
            payload_len: bytes.len().checked_sub(ip_len + tcp_len)?,
        })
    }
}

/// At most one original packet is retained while the bounded output drains.
/// Options are copied unchanged; FIN/PSH belong to the last segment and CWR
/// belongs to the first. IPv6 extensions and IP fragmentation are not split.
pub(crate) struct PendingSegments {
    original: Packet,
    view: TcpView,
    offset: usize,
}

impl PendingSegments {
    pub(crate) fn new(original: Packet) -> Option<Self> {
        let view = TcpView::parse(original.data(), false)?;
        Some(Self {
            original,
            view,
            offset: 0,
        })
    }

    pub(crate) fn flow(&self) -> FlowKey {
        self.view.flow
    }

    pub(crate) fn next(&mut self, budget: usize) -> Option<Packet> {
        if self.offset >= self.view.payload_len
            || (self.view.flow.source.is_ipv6() && budget < 1280)
            // SYN/RST/URG need special sequence or urgent-pointer semantics;
            // fail closed rather than fragmenting such an oversized packet.
            || self.view.flags & (2 | 4 | 32) != 0
        {
            return None;
        }
        let header_len = self.view.ip_len + self.view.tcp_len;
        let capacity = budget
            .checked_sub(header_len)
            .filter(|length| *length != 0)?;
        let length = capacity.min(self.view.payload_len - self.offset);
        let mut bytes = Vec::with_capacity(header_len + length);
        bytes.extend_from_slice(&self.original.data()[..header_len]);
        bytes.extend_from_slice(
            &self.original.data()[header_len + self.offset..header_len + self.offset + length],
        );
        let sequence = self
            .view
            .sequence
            .wrapping_add(u32::try_from(self.offset).ok()?);
        bytes[self.view.ip_len + 4..self.view.ip_len + 8].copy_from_slice(&sequence.to_be_bytes());
        if self.offset != 0 {
            bytes[self.view.ip_len + 13] &= !0x80;
        }
        self.offset += length;
        if self.offset != self.view.payload_len {
            bytes[self.view.ip_len + 13] &= !(1 | 8);
        }
        let packet_len = bytes.len();
        if self.view.flow.source.is_ipv4() {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
            ip.set_total_len(u16::try_from(packet_len).ok()?);
            ip.fill_checksum();
        } else {
            Ipv6Packet::new_unchecked(&mut bytes)
                .set_payload_len(u16::try_from(packet_len - 40).ok()?);
        }
        TcpPacket::new_unchecked(&mut bytes[self.view.ip_len..]).fill_checksum(
            &self.view.flow.source.ip().into(),
            &self.view.flow.destination.ip().into(),
        );
        Some(Packet::new(bytes))
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.offset >= self.view.payload_len
    }
}

#[derive(Clone, Copy)]
struct SentRange {
    flow: FlowKey,
    first: u32,
    end: u32,
}

#[derive(Clone, Copy)]
struct Path {
    flow: FlowKey,
    mtu: usize,
}

#[derive(Clone, Copy)]
struct Acknowledgment {
    flow: FlowKey,
    sequence: u32,
}

/// Quotes must identify an actually emitted and still unacknowledged range.
/// Only active client mode allocates this bounded metadata; it stores no body.
#[derive(Default)]
pub(crate) struct PathMtu {
    sent: VecDeque<SentRange>,
    paths: VecDeque<Path>,
    acknowledgments: VecDeque<Acknowledgment>,
}

impl PathMtu {
    pub(crate) fn emitted(&mut self, packet: &Packet) {
        let Some(view) = TcpView::parse(packet.data(), false) else {
            return;
        };
        let length =
            view.payload_len + usize::from(view.flags & 1 != 0) + usize::from(view.flags & 2 != 0);
        if length == 0 {
            return;
        }
        let Ok(length) = u32::try_from(length) else {
            return;
        };
        let mut first = view.sequence;
        let end = first.wrapping_add(length);
        if let Some(ack) = self
            .acknowledgments
            .iter()
            .find(|ack| ack.flow == view.flow)
        {
            // A retransmitted original can still be waiting for output when
            // its previous copy is ACKed. Do not re-authorize those bytes.
            if at_or_after(ack.sequence, end) {
                return;
            }
            if in_range(ack.sequence, first, end) {
                first = ack.sequence;
            }
        }
        if self.sent.len() == CACHE_ENTRIES {
            self.sent.pop_front();
        }
        self.sent.push_back(SentRange {
            flow: view.flow,
            first,
            end,
        });
    }

    pub(crate) fn acknowledge(&mut self, packet: &Packet) {
        // Egress is trusted smoltcp output. Ingress must pass both checksums
        // before it can revoke or trim the quote authorization metadata.
        let Some(view) = TcpView::parse(packet.data(), true) else {
            return;
        };
        if view.flags & 16 == 0 {
            return;
        }
        let flow = reverse(view.flow);
        // Only a range previously exposed to the peer can seed its ACK
        // watermark. ACKs outside it may revoke optimization metadata below,
        // but cannot create a lasting reference for queued, unsent bytes.
        if self.sent.iter().any(|sent| {
            sent.flow == flow
                && (in_range(view.acknowledgment, sent.first, sent.end)
                    || view.acknowledgment == sent.end)
        }) {
            if let Some(ack) = self.acknowledgments.iter_mut().find(|ack| ack.flow == flow) {
                if at_or_after(view.acknowledgment, ack.sequence) {
                    ack.sequence = view.acknowledgment;
                }
            } else {
                if self.acknowledgments.len() == CACHE_ENTRIES {
                    self.acknowledgments.pop_front();
                }
                self.acknowledgments.push_back(Acknowledgment {
                    flow,
                    sequence: view.acknowledgment,
                });
            }
        }
        for sent in &mut self.sent {
            if sent.flow == flow && in_range(view.acknowledgment, sent.first, sent.end) {
                sent.first = view.acknowledgment;
            }
        }
        self.sent
            .retain(|sent| sent.flow != flow || !at_or_after(view.acknowledgment, sent.end));
    }

    pub(crate) fn budget(&self, flow: FlowKey, initial_mtu: usize) -> usize {
        self.paths
            .iter()
            .find(|path| path.flow == flow)
            .map_or(initial_mtu, |path| path.mtu.min(initial_mtu))
    }

    pub(crate) fn apply(&mut self, hint: PathMtuHint, initial_mtu: usize) -> bool {
        let flow = FlowKey {
            source: hint.local,
            destination: hint.remote,
        };
        if hint.outer_destination != hint.local.ip()
            || hint.mtu < if hint.local.is_ipv6() { 1280 } else { 68 }
            || hint.mtu >= self.budget(flow, initial_mtu)
            || !self
                .sent
                .iter()
                .any(|sent| sent.flow == flow && in_range(hint.sequence, sent.first, sent.end))
        {
            return false;
        }
        self.paths.retain(|path| path.flow != flow);
        if self.paths.len() == CACHE_ENTRIES {
            self.paths.pop_front();
        }
        self.paths.push_back(Path {
            flow,
            mtu: hint.mtu,
        });
        true
    }

    pub(crate) fn forget(&mut self, flow: FlowKey) {
        self.sent.retain(|sent| sent.flow != flow);
        self.paths.retain(|path| path.flow != flow);
        self.acknowledgments.retain(|ack| ack.flow != flow);
    }
}

pub(crate) fn reverse(flow: FlowKey) -> FlowKey {
    FlowKey {
        source: flow.destination,
        destination: flow.source,
    }
}

fn in_range(value: u32, first: u32, end: u32) -> bool {
    value.wrapping_sub(first) < end.wrapping_sub(first)
}

fn at_or_after(value: u32, reference: u32) -> bool {
    value.wrapping_sub(reference).cast_signed() >= 0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn flow(ipv6: bool, port: u16) -> FlowKey {
        if ipv6 {
            FlowKey {
                source: format!("[2001:db8::2]:{port}").parse().unwrap(),
                destination: "[2001:db8:1::2]:443".parse().unwrap(),
            }
        } else {
            FlowKey {
                source: format!("10.23.0.2:{port}").parse().unwrap(),
                destination: "198.51.100.2:443".parse().unwrap(),
            }
        }
    }

    pub(crate) fn tcp_packet(
        flow: FlowKey,
        sequence: u32,
        ack: u32,
        flags: u8,
        size: usize,
    ) -> Packet {
        let ip_len = if flow.source.is_ipv6() { 40 } else { 24 };
        let tcp_len = 32;
        let mut bytes = vec![0; ip_len + tcp_len + size];
        let packet_len = bytes.len();
        if let (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) =
            (flow.source.ip(), flow.destination.ip())
        {
            bytes[0] = 0x46;
            bytes[2..4].copy_from_slice(&u16::try_from(packet_len).unwrap().to_be_bytes());
            bytes[6] = 0x40;
            bytes[8] = 64;
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&destination.octets());
            bytes[20..24].copy_from_slice(&[1, 1, 0, 0]);
            Ipv4Packet::new_unchecked(&mut bytes).fill_checksum();
        } else if let (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) =
            (flow.source.ip(), flow.destination.ip())
        {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&u16::try_from(packet_len - 40).unwrap().to_be_bytes());
            bytes[6] = 6;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
        }
        bytes[ip_len..ip_len + 2].copy_from_slice(&flow.source.port().to_be_bytes());
        bytes[ip_len + 2..ip_len + 4].copy_from_slice(&flow.destination.port().to_be_bytes());
        bytes[ip_len + 4..ip_len + 8].copy_from_slice(&sequence.to_be_bytes());
        bytes[ip_len + 8..ip_len + 12].copy_from_slice(&ack.to_be_bytes());
        bytes[ip_len + 12] = 0x80;
        bytes[ip_len + 13] = flags;
        bytes[ip_len + 14..ip_len + 16].copy_from_slice(&32768_u16.to_be_bytes());
        bytes[ip_len + 20..ip_len + 32].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 9, 0, 0, 0, 8]);
        for (index, byte) in bytes[ip_len + tcp_len..].iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).unwrap();
        }
        TcpPacket::new_unchecked(&mut bytes[ip_len..])
            .fill_checksum(&flow.source.ip().into(), &flow.destination.ip().into());
        Packet::new(bytes)
    }

    pub(crate) fn hint(packet: &Packet, mtu: usize) -> PathMtuHint {
        let view = TcpView::parse(packet.data(), true).unwrap();
        PathMtuHint {
            outer_destination: view.flow.source.ip(),
            local: view.flow.source,
            remote: view.flow.destination,
            sequence: view.sequence,
            mtu,
        }
    }

    #[test]
    fn segments_preserve_content_options_checksum_flags_and_wrap() {
        for (ipv6, budget) in [(false, 576), (true, 1280)] {
            let original = tcp_packet(flow(ipv6, 4000), u32::MAX - 300, 91, 0xd9, 7000);
            let original_view = TcpView::parse(original.data(), true).unwrap();
            let mut pending = PendingSegments::new(original.clone()).unwrap();
            let mut received = Vec::new();
            let mut first = true;
            while let Some(segment) = pending.next(budget) {
                assert!(segment.len() <= budget);
                let view = TcpView::parse(segment.data(), true).unwrap();
                assert_eq!(view.flow, original_view.flow);
                assert_eq!(
                    view.sequence,
                    original_view
                        .sequence
                        .wrapping_add(u32::try_from(received.len()).unwrap())
                );
                assert_eq!(view.acknowledgment, 91);
                assert_eq!(view.flags & 0x80 != 0, first);
                assert_eq!(
                    view.flags & (1 | 8),
                    if pending.is_finished() { 1 | 8 } else { 0 }
                );
                assert_ne!(view.flags & (16 | 64), 0);
                let header_end = view.ip_len + view.tcp_len;
                assert_eq!(
                    &segment.data()[view.ip_len + 20..header_end],
                    &original.data()[view.ip_len + 20..header_end]
                );
                if !ipv6 {
                    assert_eq!(&segment.data()[20..24], &original.data()[20..24]);
                }
                received.extend_from_slice(&segment.data()[header_end..]);
                first = false;
            }
            assert_eq!(
                received,
                original.data()[original_view.ip_len + original_view.tcp_len..]
            );
            assert!(pending.is_finished());
        }
    }

    #[test]
    fn changing_budget_and_unsupported_ip_modes_fail_closed() {
        let original = tcp_packet(flow(false, 4000), 100, 91, 0x10, 7000);
        let mut pending = PendingSegments::new(original).unwrap();
        assert_eq!(pending.next(1280).unwrap().len(), 1280);
        let second = pending.next(576).unwrap();
        assert_eq!(second.len(), 576);
        assert_eq!(
            TcpView::parse(second.data(), true).unwrap().sequence,
            100 + 1280 - 56
        );
        for flags in [2, 4, 32] {
            let mut pending =
                PendingSegments::new(tcp_packet(flow(false, 4000), 100, 91, flags, 7000)).unwrap();
            assert!(pending.next(576).is_none());
        }
        let ipv6 = tcp_packet(flow(true, 4000), 100, 91, 16, 7000);
        assert!(
            PendingSegments::new(ipv6.clone())
                .unwrap()
                .next(1279)
                .is_none()
        );
        let mut extension = ipv6.data().to_vec();
        extension[6] = 60;
        assert!(PendingSegments::new(Packet::new(extension)).is_none());
        let mut fragmented = tcp_packet(flow(false, 4000), 100, 91, 16, 7000)
            .data()
            .to_vec();
        fragmented[6] |= 0x20;
        assert!(PendingSegments::new(Packet::new(fragmented)).is_none());
    }

    #[test]
    fn quotes_require_emitted_unacked_ranges_and_isolate_flows() {
        for ipv6 in [false, true] {
            let mut paths = PathMtu::default();
            let original = tcp_packet(flow(ipv6, 4000), u32::MAX - 300, 91, 0x10, 1400);
            let original_hint = hint(&original, if ipv6 { 1280 } else { 576 });
            assert!(!paths.apply(original_hint, 1500));
            paths.emitted(&original);
            let mut wrong = original_hint;
            wrong.remote.set_port(444);
            assert!(!paths.apply(wrong, 1500));
            wrong = original_hint;
            wrong.sequence = original_hint.sequence.wrapping_add(1400);
            assert!(!paths.apply(wrong, 1500));
            let partial_ack = original_hint.sequence.wrapping_add(500);
            paths.acknowledge(&tcp_packet(
                reverse(flow(ipv6, 4000)),
                91,
                partial_ack,
                16,
                0,
            ));
            assert!(!paths.apply(original_hint, 1500));
            let mut tail_hint = original_hint;
            tail_hint.sequence = partial_ack;
            assert!(paths.apply(tail_hint, 1500));
            assert_eq!(paths.budget(flow(ipv6, 4001), 1500), 1500);
            let final_ack = original_hint.sequence.wrapping_add(1400);
            paths.acknowledge(&tcp_packet(reverse(flow(ipv6, 4000)), 91, final_ack, 16, 0));
            paths.emitted(&original); // previously queued retransmit copy
            tail_hint.mtu -= if ipv6 { 0 } else { 100 };
            assert!(!paths.apply(tail_hint, 1500));
            paths.forget(flow(ipv6, 4000));
            assert_eq!(paths.budget(flow(ipv6, 4000), 1500), 1500);
            assert!(
                paths.sent.is_empty() && paths.paths.is_empty() && paths.acknowledgments.is_empty()
            );
            // Tuple reuse starts without the predecessor's ACK watermark.
            paths.emitted(&original);
            assert!(paths.apply(original_hint, 1500));
        }
    }

    #[test]
    fn caches_remain_bounded_and_eviction_cannot_authorize_old_quotes() {
        let mut paths = PathMtu::default();
        for port in 4000..4200 {
            let packet = tcp_packet(flow(false, port), 100, 91, 16, 1400);
            paths.emitted(&packet);
            assert!(paths.apply(hint(&packet, 1280), 1500));
            paths.acknowledge(&tcp_packet(reverse(flow(false, port)), 91, 101, 16, 0));
            assert!(paths.sent.len() <= CACHE_ENTRIES);
            assert!(paths.paths.len() <= CACHE_ENTRIES);
            assert!(paths.acknowledgments.len() <= CACHE_ENTRIES);
        }
        assert_eq!(paths.sent.len(), CACHE_ENTRIES);
        assert_eq!(paths.paths.len(), CACHE_ENTRIES);
        assert_eq!(paths.acknowledgments.len(), CACHE_ENTRIES);
        let old = tcp_packet(flow(false, 4000), 100, 91, 16, 1400);
        assert!(!paths.apply(hint(&old, 1000), 1500));
        assert_eq!(paths.budget(flow(false, 4000), 1500), 1500);
    }
}
