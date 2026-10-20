//! Checked Echo wire helpers. No socket, task, DNS or routing ownership.
use std::net::{IpAddr, Ipv4Addr};

use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpProtocol, IpRepr, Ipv4Packet,
        Ipv4Repr, Ipv6Packet, Ipv6Repr,
    },
};

/// The addresses here are the actual endpoints of this packet direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchoPacketView<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EchoPacketError {
    #[error("Echo packet endpoints use different address families")]
    AddressFamily,
    #[error("Echo packet exceeds the current raw-IP MTU")]
    Mtu,
}

/// Recognized Echo failures and unsupported raw-IP shapes cannot fall through
/// to the existing synthetic responder. Other ICMP/error/PMTU remains `NotEcho`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoPacketClass<'a> {
    NotEcho,
    Rejected,
    Request(EchoPacketView<'a>),
}
#[must_use]
pub fn classify_echo_request(bytes: &[u8]) -> EchoPacketClass<'_> {
    let recognized = match bytes.first().map(|b| b >> 4) {
        Some(4) if bytes.get(9) == Some(&1) => {
            // Includes non-initial fragments: no reassembly or local success.
            if bytes.len() < 20 || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0 {
                return EchoPacketClass::Rejected;
            }
            let offset = usize::from(bytes[0] & 15) * 4;
            if offset < 20 {
                return EchoPacketClass::Rejected;
            }
            match bytes.get(offset) {
                Some(8) => true,
                None => return EchoPacketClass::Rejected,
                _ => false,
            }
        }
        Some(6) => match bytes.get(6) {
            Some(58) => match bytes.get(40) {
                Some(128) => true,
                None => return EchoPacketClass::Rejected,
                _ => false,
            },
            // The existing netstack dispatches the base next_header only and
            // does not implement these extension chains, including PMTU in
            // one. Make that unsupported-shape drop explicit before autoEcho.
            Some(0 | 43 | 44 | 50 | 51 | 60) => return EchoPacketClass::Rejected,
            _ => false,
        },
        _ => false,
    };
    if !recognized {
        return EchoPacketClass::NotEcho;
    }
    parse_echo_request_view(bytes).map_or(EchoPacketClass::Rejected, EchoPacketClass::Request)
}

/// Classify only a complete, checksum-valid, unfragmented unicast Echo Request.
/// None leaves ownership and dispatch of the original packet with the caller.
#[must_use]
pub fn parse_echo_request_view(bytes: &[u8]) -> Option<EchoPacketView<'_>> {
    parse_echo_view(bytes, false)
}

fn unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST,
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

fn parse_echo_view(bytes: &[u8], reply: bool) -> Option<EchoPacketView<'_>> {
    let caps = ChecksumCapabilities::default();
    let (source, destination, identifier, sequence, payload) = match bytes.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(bytes).ok()?;
            if ip.next_header() != IpProtocol::Icmp
                || usize::from(ip.total_len()) != bytes.len()
                || ip.more_frags()
                || ip.frag_offset() != 0
            {
                return None;
            }
            let repr = Ipv4Repr::parse(&ip, &caps).ok()?;
            if repr.next_header != IpProtocol::Icmp {
                return None;
            }
            let icmp = Icmpv4Packet::new_checked(ip.payload()).ok()?;
            let (identifier, sequence, payload) = match Icmpv4Repr::parse(&icmp, &caps).ok()? {
                Icmpv4Repr::EchoRequest {
                    ident,
                    seq_no,
                    data,
                } if !reply => (ident, seq_no, data),
                Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                } if reply => (ident, seq_no, data),
                _ => return None,
            };
            (
                repr.src_addr.into(),
                repr.dst_addr.into(),
                identifier,
                sequence,
                payload,
            )
        }
        6 => {
            let ip = Ipv6Packet::new_checked(bytes).ok()?;
            if ip.total_len() != bytes.len() || ip.next_header() != IpProtocol::Icmpv6 {
                return None;
            }
            let repr = Ipv6Repr::parse(&ip).ok()?;
            let icmp = Icmpv6Packet::new_checked(ip.payload()).ok()?;
            let (identifier, sequence, payload) =
                match Icmpv6Repr::parse(&repr.src_addr, &repr.dst_addr, &icmp, &caps).ok()? {
                    Icmpv6Repr::EchoRequest {
                        ident,
                        seq_no,
                        data,
                    } if !reply => (ident, seq_no, data),
                    Icmpv6Repr::EchoReply {
                        ident,
                        seq_no,
                        data,
                    } if reply => (ident, seq_no, data),
                    _ => return None,
                };
            (
                repr.src_addr.into(),
                repr.dst_addr.into(),
                identifier,
                sequence,
                payload,
            )
        }
        _ => return None,
    };
    if !unicast(source) || !unicast(destination) {
        return None;
    }
    Some(EchoPacketView {
        source,
        destination,
        identifier,
        sequence,
        payload,
    })
}

/// Validate a body returned by a Linux DGRAM ICMP socket. `source` comes from
/// recvmsg's peer sockaddr, `destination` from `IP_PKTINFO/IPV6_PKTINFO`. The IPv6
/// checksum therefore uses physical addresses, never the original TUN tuple.
#[must_use]
pub fn parse_echo_reply_body(
    source: IpAddr,
    destination: IpAddr,
    bytes: &[u8],
) -> Option<EchoPacketView<'_>> {
    if !unicast(source) || !unicast(destination) {
        return None;
    }
    let caps = ChecksumCapabilities::default();
    let (identifier, sequence, payload) = match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            let packet = Icmpv4Packet::new_checked(bytes).ok()?;
            match Icmpv4Repr::parse(&packet, &caps).ok()? {
                Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                } => (ident, seq_no, data),
                _ => return None,
            }
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let packet = Icmpv6Packet::new_checked(bytes).ok()?;
            match Icmpv6Repr::parse(&src, &dst, &packet, &caps).ok()? {
                Icmpv6Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                } => (ident, seq_no, data),
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(EchoPacketView {
        source,
        destination,
        identifier,
        sequence,
        payload,
    })
}

/// Build a reply from the peer-validated Echo body and the retained TUN tuple.
/// The caller supplies reply-direction endpoints, not the original request.
/// Allocation happens only after address-family and complete length checks.
///
/// # Errors
/// Returns an error if the address families differ or the complete packet
/// exceeds the raw-IP MTU or IP length limit.
pub fn encode_echo_reply_into(
    packet: &EchoPacketView<'_>,
    mtu: usize,
    frame: &mut Vec<u8>,
) -> Result<(), EchoPacketError> {
    emit_echo(packet, true, mtu, frame)
}

fn emit_echo(
    packet: &EchoPacketView<'_>,
    reply: bool,
    mtu: usize,
    frame: &mut Vec<u8>,
) -> Result<(), EchoPacketError> {
    if packet.source.is_ipv4() != packet.destination.is_ipv4() {
        return Err(EchoPacketError::AddressFamily);
    }
    let body_len = 8usize
        .checked_add(packet.payload.len())
        .ok_or(EchoPacketError::Mtu)?;
    let header_len = if packet.source.is_ipv4() {
        20usize
    } else {
        40usize
    };
    let packet_len = header_len
        .checked_add(body_len)
        .ok_or(EchoPacketError::Mtu)?;
    if packet_len > mtu || packet_len > usize::from(u16::MAX) {
        return Err(EchoPacketError::Mtu);
    }
    let protocol = if packet.source.is_ipv4() {
        IpProtocol::Icmp
    } else {
        IpProtocol::Icmpv6
    };
    let ip = IpRepr::new(
        packet.source.into(),
        packet.destination.into(),
        protocol,
        body_len,
        64,
    );
    let caps = ChecksumCapabilities::default();
    frame.clear();
    frame.resize(packet_len, 0);
    ip.emit(&mut frame[..], &caps);
    match (packet.source, packet.destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            let repr = if reply {
                Icmpv4Repr::EchoReply {
                    ident: packet.identifier,
                    seq_no: packet.sequence,
                    data: packet.payload,
                }
            } else {
                Icmpv4Repr::EchoRequest {
                    ident: packet.identifier,
                    seq_no: packet.sequence,
                    data: packet.payload,
                }
            };
            repr.emit(
                &mut Icmpv4Packet::new_unchecked(&mut frame[header_len..]),
                &caps,
            );
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let repr = if reply {
                Icmpv6Repr::EchoReply {
                    ident: packet.identifier,
                    seq_no: packet.sequence,
                    data: packet.payload,
                }
            } else {
                Icmpv6Repr::EchoRequest {
                    ident: packet.identifier,
                    seq_no: packet.sequence,
                    data: packet.payload,
                }
            };
            repr.emit(
                &source,
                &destination,
                &mut Icmpv6Packet::new_unchecked(&mut frame[header_len..]),
                &caps,
            );
        }
        _ => return Err(EchoPacketError::AddressFamily),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(ipv6: bool, payload: &[u8]) -> EchoPacketView<'_> {
        EchoPacketView {
            source: if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            destination: if ipv6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
            identifier: 0xfedc,
            sequence: 0xabcd,
            payload,
        }
    }

    #[test]
    fn checked_echo_preserves_tuple_identity_odd_payload_and_both_checksums() {
        for ipv6 in [false, true] {
            for payload in [&b""[..], &b"a"[..], &b"odd-payload"[..]] {
                let view = request(ipv6, payload);
                let mut input = Vec::new();
                emit_echo(&view, false, 1500, &mut input).unwrap();
                let parsed = parse_echo_request_view(&input).unwrap();
                assert_eq!(parsed, view);
                assert_eq!(
                    classify_echo_request(&input),
                    EchoPacketClass::Request(view)
                );
                let reply = EchoPacketView {
                    source: parsed.destination,
                    destination: parsed.source,
                    ..parsed
                };
                let mut frame = Vec::new();
                encode_echo_reply_into(&reply, 1500, &mut frame).unwrap();
                assert_eq!(parse_echo_view(&frame, true), Some(reply));
                let header = if ipv6 { 40 } else { 20 };
                assert_eq!(
                    parse_echo_reply_body(reply.source, reply.destination, &frame[header..]),
                    Some(reply)
                );
                assert!(parse_echo_request_view(&frame).is_none());
            }
        }
    }

    #[test]
    fn malformed_echo_never_becomes_a_valid_forwarding_request() {
        for ipv6 in [false, true] {
            let mut valid = Vec::new();
            emit_echo(&request(ipv6, b"odd"), false, 1500, &mut valid).unwrap();
            let mut bad_checksum = valid.clone();
            *bad_checksum.last_mut().unwrap() ^= 1;
            assert!(parse_echo_request_view(&bad_checksum).is_none());
            assert_eq!(
                classify_echo_request(&bad_checksum),
                EchoPacketClass::Rejected
            );
            let mut trailing = valid.clone();
            trailing.push(0);
            assert!(parse_echo_request_view(&trailing).is_none());
            assert!(parse_echo_request_view(&valid[..valid.len() - 1]).is_none());
        }
        let mut fragmented = Vec::new();
        emit_echo(&request(false, b"x"), false, 1500, &mut fragmented).unwrap();
        fragmented[6] |= 0x20;
        Ipv4Packet::new_unchecked(&mut fragmented[..]).fill_checksum();
        assert!(parse_echo_request_view(&fragmented).is_none());
        assert_eq!(
            classify_echo_request(&fragmented),
            EchoPacketClass::Rejected
        );
        let mut extension = vec![0u8; 56];
        extension[0] = 0x60;
        extension[6] = 44;
        extension[40] = 58;
        extension[48] = 128;
        assert_eq!(classify_echo_request(&extension), EchoPacketClass::Rejected);
    }

    #[test]
    fn reply_allocation_is_rejected_before_touching_the_existing_frame() {
        let packet = request(true, b"payload");
        let mut frame = vec![1, 2, 3];
        let before_capacity = frame.capacity();
        assert_eq!(
            encode_echo_reply_into(&packet, 1, &mut frame),
            Err(EchoPacketError::Mtu)
        );
        assert_eq!(frame, [1, 2, 3]);
        assert_eq!(frame.capacity(), before_capacity);
    }

    #[test]
    fn invalid_echo_code_is_dropped_but_non_echo_errors_keep_the_original_path() {
        let mut packet = Vec::new();
        emit_echo(&request(false, b"odd"), false, 1500, &mut packet).unwrap();
        packet[21] = 1;
        Icmpv4Packet::new_unchecked(&mut packet[20..]).fill_checksum();
        assert_eq!(classify_echo_request(&packet), EchoPacketClass::Rejected);
        packet[20] = 3;
        packet[21] = 4;
        Icmpv4Packet::new_unchecked(&mut packet[20..]).fill_checksum();
        assert_eq!(classify_echo_request(&packet), EchoPacketClass::NotEcho);
    }
}
