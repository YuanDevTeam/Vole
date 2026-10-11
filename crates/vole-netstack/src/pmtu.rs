//! Client-only ICMP path feedback. Parsing borrows the packet and allocates no
//! state; the active socket owns tuple/sequence correlation and its path MTU.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::Packet;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV4: u8 = 1;
const ICMPV6: u8 = 58;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathMtuHint {
    pub outer_destination: IpAddr,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub sequence: u32,
    pub mtu: usize,
}

/// Parses a complete ICMP Fragmentation Needed / Packet Too Big message and
/// its possibly truncated TCP quotation. An embedded original IP total length
/// can exceed the quotation length; eight TCP bytes suffice for correlation.
///
/// The caller must match the outer destination and local/remote tuple against
/// an active client socket. That socket must validate the quoted sequence
/// against actually emitted output before accepting any MTU reduction.
#[must_use]
pub fn parse_path_mtu_hint(packet: &[u8]) -> Option<PathMtuHint> {
    let outer = complete_ip(packet)?;
    let icmp = outer.payload;
    if icmp.len() < 8 || !unicast(outer.source) || !unicast(outer.destination) {
        return None;
    }
    let (mtu, quote) = match (outer.source, outer.protocol, icmp[0], icmp[1]) {
        (IpAddr::V4(_), ICMPV4, 3, 4) => {
            if checksum(icmp) != 0 {
                return None;
            }
            let quote = &icmp[8..];
            let mut mtu = usize::from(u16::from_be_bytes([icmp[6], icmp[7]]));
            if mtu == 0 {
                mtu = legacy_ipv4_mtu(quote)?;
            }
            (mtu.max(68), quote)
        }
        (IpAddr::V6(_), ICMPV6, 2, 0) => {
            if transport_checksum(outer.source, outer.destination, ICMPV6, icmp) != 0 {
                return None;
            }
            let mtu = usize::try_from(u32::from_be_bytes(icmp[4..8].try_into().ok()?)).ok()?;
            // The frozen client reference discards this hint instead of
            // replacing it with the IPv6 minimum link MTU.
            if mtu < 1_280 {
                return None;
            }
            (mtu, &icmp[8..])
        }
        _ => return None,
    };
    let quoted = quoted_ip(quote)?;
    if quoted.protocol != TCP
        || quoted.payload.len() < 8
        || quoted.source.is_ipv4() != outer.source.is_ipv4()
        || !unicast(quoted.source)
        || !unicast(quoted.destination)
    {
        return None;
    }
    let tcp = quoted.payload;
    Some(PathMtuHint {
        outer_destination: outer.destination,
        local: SocketAddr::new(quoted.source, u16::from_be_bytes([tcp[0], tcp[1]])),
        remote: SocketAddr::new(quoted.destination, u16::from_be_bytes([tcp[2], tcp[3]])),
        sequence: u32::from_be_bytes(tcp[4..8].try_into().ok()?),
        mtu,
    })
}

/// Creates local too-big feedback for a complete emitted TCP/UDP packet that
/// the controlled packet transport cannot carry. The quotation is bounded by
/// the IPv4 576-byte / IPv6 1280-byte ICMP packet size and preserves the bytes
/// used for active-flow correlation. No host packet or network I/O is performed.
#[must_use]
pub fn build_packet_too_big(quoted: &[u8], mtu: usize) -> Option<Packet> {
    let original = complete_ip(quoted)?;
    if !matches!(original.protocol, TCP | UDP)
        || original.payload.len() < 8
        || !unicast(original.source)
        || !unicast(original.destination)
        || quoted.len() <= mtu
    {
        return None;
    }
    match (original.source, original.destination) {
        (IpAddr::V4(local), IpAddr::V4(remote)) => {
            let mtu = u16::try_from(mtu.max(68)).ok()?;
            let quote_len = quoted.len().min(576 - 20 - 8);
            let total_len = 20 + 8 + quote_len;
            let mut bytes = vec![0; total_len];
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&u16::try_from(total_len).ok()?.to_be_bytes());
            bytes[8] = 64;
            bytes[9] = ICMPV4;
            bytes[12..16].copy_from_slice(&remote.octets());
            bytes[16..20].copy_from_slice(&local.octets());
            bytes[20] = 3;
            bytes[21] = 4;
            bytes[26..28].copy_from_slice(&mtu.to_be_bytes());
            bytes[28..].copy_from_slice(&quoted[..quote_len]);
            let icmp_checksum = checksum(&bytes[20..]);
            bytes[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
            let ip_checksum = checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
            Some(Packet::new(bytes))
        }
        (IpAddr::V6(local), IpAddr::V6(remote)) => {
            if mtu < 1_280 {
                return None;
            }
            let mtu = u32::try_from(mtu).ok()?;
            let quote_len = quoted.len().min(1_280 - 40 - 8);
            // A very long quoted extension chain cannot supply the required
            // transport prefix within the permitted ICMP packet size.
            if quoted_ip(&quoted[..quote_len])?.payload.len() < 8 {
                return None;
            }
            let payload_len = 8 + quote_len;
            let mut bytes = vec![0; 40 + payload_len];
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&u16::try_from(payload_len).ok()?.to_be_bytes());
            bytes[6] = ICMPV6;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&remote.octets());
            bytes[24..40].copy_from_slice(&local.octets());
            bytes[40] = 2;
            bytes[44..48].copy_from_slice(&mtu.to_be_bytes());
            bytes[48..].copy_from_slice(&quoted[..quote_len]);
            let value = transport_checksum(remote.into(), local.into(), ICMPV6, &bytes[40..]);
            bytes[42..44].copy_from_slice(&value.to_be_bytes());
            Some(Packet::new(bytes))
        }
        _ => None,
    }
}

struct IpView<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: &'a [u8],
}

fn complete_ip(bytes: &[u8]) -> Option<IpView<'_>> {
    match bytes.first()? >> 4 {
        4 => {
            if bytes.len() < 20 {
                return None;
            }
            let header_len = usize::from(bytes[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if header_len < 20
                || header_len > bytes.len()
                || total_len != bytes.len()
                || checksum(&bytes[..header_len]) != 0
                || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
            {
                return None;
            }
            ipv4_view(bytes, header_len)
        }
        6 => {
            if bytes.len() < 40
                || 40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) != bytes.len()
            {
                return None;
            }
            ipv6_view(bytes, false)
        }
        _ => None,
    }
}

fn quoted_ip(bytes: &[u8]) -> Option<IpView<'_>> {
    match bytes.first()? >> 4 {
        4 => {
            if bytes.len() < 20 {
                return None;
            }
            let header_len = usize::from(bytes[0] & 0x0f) * 4;
            if header_len < 20
                || header_len > bytes.len()
                || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff != 0
            {
                return None;
            }
            // RFC ICMP quotations commonly omit the original TCP body; no
            // full-packet length or transport checksum is available here.
            ipv4_view(bytes, header_len)
        }
        6 if bytes.len() >= 40 => ipv6_view(bytes, true),
        _ => None,
    }
}

fn ipv4_view(bytes: &[u8], header_len: usize) -> Option<IpView<'_>> {
    Some(IpView {
        source: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).ok()?).into(),
        destination: Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).ok()?).into(),
        protocol: bytes[9],
        payload: &bytes[header_len..],
    })
}

fn ipv6_view(bytes: &[u8], quoted: bool) -> Option<IpView<'_>> {
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?);
    if source.to_ipv4_mapped().is_some() || destination.to_ipv4_mapped().is_some() {
        return None;
    }
    let mut next = bytes[6];
    let mut offset: usize = 40;
    loop {
        match next {
            0 | 43 | 60 | 135 | 51 => {
                let header = bytes.get(offset..offset.checked_add(2)?)?;
                let length = if next == 51 {
                    (usize::from(header[1]) + 2) * 4
                } else {
                    (usize::from(header[1]) + 1) * 8
                };
                offset = offset.checked_add(length)?;
                if offset > bytes.len() {
                    return None;
                }
                next = header[0];
            }
            44 => {
                let header = bytes.get(offset..offset.checked_add(8)?)?;
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                if fragment & 0xfff8 != 0 || (!quoted && fragment & 1 != 0) {
                    return None;
                }
                next = header[0];
                offset += 8;
            }
            _ => {
                return Some(IpView {
                    source: source.into(),
                    destination: destination.into(),
                    protocol: next,
                    payload: &bytes[offset..],
                });
            }
        }
    }
}

fn unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast())
}

fn legacy_ipv4_mtu(quote: &[u8]) -> Option<usize> {
    if quote.len() < 20 || quote[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(quote[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([quote[2], quote[3]]));
    if header_len < 20 || total_len < header_len {
        return None;
    }
    Some(
        [
            65_535, 32_000, 17_914, 8_166, 4_352, 2_002, 1_492, 1_006, 508, 296, 68,
        ]
        .into_iter()
        .find(|plateau| *plateau < total_len)
        .unwrap_or(68),
    )
}

fn sum_words(bytes: &[u8]) -> u32 {
    let (words, remainder) = bytes.as_chunks::<2>();
    let mut sum = words
        .iter()
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    if let Some(last) = remainder.first() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}

fn checksum(bytes: &[u8]) -> u16 {
    fold_checksum(sum_words(bytes))
}

fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = sum_words(payload) + u32::from(protocol);
    if let (IpAddr::V6(source), IpAddr::V6(destination)) = (source, destination) {
        sum += sum_words(&source.octets()) + sum_words(&destination.octets());
        // The caller's complete ordinary IPv6 packet bounds this conversion.
        let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        sum += (length >> 16) + (length & 0xffff);
    }
    fold_checksum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emitted_packet(ipv6: bool, size: usize) -> Vec<u8> {
        let header_len = if ipv6 { 40 } else { 20 };
        let mut bytes = vec![0; size];
        if ipv6 {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&u16::try_from(size - 40).unwrap().to_be_bytes());
            bytes[6] = TCP;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&"2001:db8:1::2".parse::<Ipv6Addr>().unwrap().octets());
            bytes[24..40].copy_from_slice(&"2001:db8:2::9".parse::<Ipv6Addr>().unwrap().octets());
        } else {
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&u16::try_from(size).unwrap().to_be_bytes());
            bytes[6] = 0x40;
            bytes[8] = 64;
            bytes[9] = TCP;
            bytes[12..16].copy_from_slice(&[10, 23, 0, 2]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 9]);
            let value = checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&value.to_be_bytes());
        }
        bytes[header_len..header_len + 2].copy_from_slice(&49_152_u16.to_be_bytes());
        bytes[header_len + 2..header_len + 4].copy_from_slice(&443_u16.to_be_bytes());
        bytes[header_len + 4..header_len + 8].copy_from_slice(&0xffff_fffe_u32.to_be_bytes());
        bytes[header_len + 12] = 0x50;
        bytes
    }

    fn repair_ipv4(bytes: &mut [u8]) {
        let length = u16::try_from(bytes.len()).unwrap();
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[10..12].fill(0);
        bytes[22..24].fill(0);
        let value = checksum(&bytes[20..]);
        bytes[22..24].copy_from_slice(&value.to_be_bytes());
        let value = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn real_truncated_icmp_quote_preserves_tuple_sequence_and_checksum_policy() {
        for (ipv6, mtu, maximum) in [(false, 296, 576), (true, 1280, 1280)] {
            let original = emitted_packet(ipv6, 1500);
            let reply = build_packet_too_big(&original, mtu).unwrap();
            assert_eq!(reply.len(), maximum);
            // Independently check generated checksums using smoltcp's wire
            // decoder, rather than relying only on this module's parser.
            if ipv6 {
                let ip = smoltcp::wire::Ipv6Packet::new_checked(reply.data()).unwrap();
                let icmp = smoltcp::wire::Icmpv6Packet::new_checked(ip.payload()).unwrap();
                assert!(icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
            } else {
                let ip = smoltcp::wire::Ipv4Packet::new_checked(reply.data()).unwrap();
                assert!(ip.verify_checksum());
                let icmp = smoltcp::wire::Icmpv4Packet::new_checked(ip.payload()).unwrap();
                assert!(icmp.verify_checksum());
            }
            let hint = parse_path_mtu_hint(reply.data()).unwrap();
            assert_eq!(hint.mtu, mtu);
            assert_eq!(hint.sequence, 0xffff_fffe);
            assert_eq!(hint.local.port(), 49_152);
            assert_eq!(hint.remote.port(), 443);
            assert_eq!(hint.outer_destination, hint.local.ip());
            let mut corrupt = reply.data().to_vec();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(parse_path_mtu_hint(&corrupt).is_none());
            assert!(parse_path_mtu_hint(&reply.data()[..reply.len() - 1]).is_none());
        }
        // RFC 792 permits an original IPv4 header plus eight TCP bytes only,
        // even though the embedded total length continues to say 1500.
        let original = emitted_packet(false, 1500);
        let mut minimal = build_packet_too_big(&original, 68).unwrap().data()[..56].to_vec();
        repair_ipv4(&mut minimal);
        assert_eq!(parse_path_mtu_hint(&minimal).unwrap().mtu, 68);
        minimal[26..28].fill(0);
        repair_ipv4(&mut minimal);
        assert_eq!(parse_path_mtu_hint(&minimal).unwrap().mtu, 1492);
        minimal[28 + 6..28 + 8].copy_from_slice(&1_u16.to_be_bytes());
        repair_ipv4(&mut minimal);
        assert!(parse_path_mtu_hint(&minimal).is_none());
    }

    #[test]
    fn ipv6_under_minimum_and_truncated_extension_quotes_have_real_semantics() {
        let original = emitted_packet(true, 1500);
        assert!(build_packet_too_big(&original, 1279).is_none());
        let mut bytes = build_packet_too_big(&original, 1280)
            .unwrap()
            .data()
            .to_vec();
        bytes[44..48].copy_from_slice(&1279_u32.to_be_bytes());
        bytes[42..44].fill(0);
        let outer = complete_ip(&bytes).unwrap();
        let value = transport_checksum(outer.source, outer.destination, ICMPV6, outer.payload);
        bytes[42..44].copy_from_slice(&value.to_be_bytes());
        assert!(parse_path_mtu_hint(&bytes).is_none());

        // A quoted first IPv6 fragment can expose TCP's tuple and sequence;
        // a non-first fragment cannot. Only the eight-byte TCP prefix remains.
        let mut quote = original[..40].to_vec();
        quote[6] = 44;
        quote.extend_from_slice(&[TCP, 0, 0, 1, 0, 0, 0, 9]);
        quote.extend_from_slice(&original[40..48]);
        assert_eq!(quoted_ip(&quote).unwrap().payload.len(), 8);
        quote[43] = 9;
        assert!(quoted_ip(&quote).is_none());
        assert!(quoted_ip(&quote[..47]).is_none());
    }
}
