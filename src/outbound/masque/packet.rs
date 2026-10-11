//! Bounded raw-IP validation at the CONNECT-IP packet boundary.
use bytes::{Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use vole_netstack::{ClientConfig, MAX_RECEIVE_PACKET_SIZE};

struct IpPacket<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    header_len: usize,
    payload: &'a [u8],
    fragmented: bool,
}

/// One router hop. Shared input is copied only when mutation requires it.
pub(super) fn outgoing(raw: Bytes) -> Option<Bytes> {
    let packet = parse(&raw)?;
    let header_len = packet.header_len;
    let offset = if packet.source.is_ipv4() { 8 } else { 7 };
    if raw[offset] <= 1 {
        return None;
    }
    let mut raw = raw
        .try_into_mut()
        .unwrap_or_else(|bytes| BytesMut::from(bytes.as_ref()));
    raw[offset] -= 1;
    if offset == 8 {
        raw[10..12].fill(0);
        let checksum = checksum(&raw[..header_len]);
        raw[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
    Some(raw.freeze())
}

pub(super) fn incoming(raw: &[u8], client: &ClientConfig) -> bool {
    if raw.len() > client.receive_packet_limit {
        return false;
    }
    let Some(packet) = parse(raw) else {
        return false;
    };
    if !client.contains_address(packet.destination) {
        return false;
    }
    if packet.protocol == 17 {
        return !packet.fragmented && valid_udp(&packet);
    }
    // The active TCP stack validates TCP checksum and state itself. ICMP PMTU
    // parsing similarly verifies its own message and quoted active tuple.
    true
}

fn parse(raw: &[u8]) -> Option<IpPacket<'_>> {
    if raw.len() > MAX_RECEIVE_PACKET_SIZE {
        return None;
    }
    match raw.first()? >> 4 {
        4 => {
            if raw.len() < 20 {
                return None;
            }
            let header_len = usize::from(raw[0] & 15) * 4;
            if header_len < 20
                || header_len > raw.len()
                || usize::from(u16::from_be_bytes([raw[2], raw[3]])) != raw.len()
                || checksum(&raw[..header_len]) != 0
            {
                return None;
            }
            let source = Ipv4Addr::from(<[u8; 4]>::try_from(&raw[12..16]).ok()?);
            let destination = Ipv4Addr::from(<[u8; 4]>::try_from(&raw[16..20]).ok()?);
            Some(IpPacket {
                source: source.into(),
                destination: destination.into(),
                protocol: raw[9],
                header_len,
                payload: &raw[header_len..],
                fragmented: u16::from_be_bytes([raw[6], raw[7]]) & 0x3fff != 0,
            })
        }
        6 => {
            if raw.len() < 40 || 40 + usize::from(u16::from_be_bytes([raw[4], raw[5]])) != raw.len()
            {
                return None;
            }
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?);
            let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).ok()?);
            if source.to_ipv4_mapped().is_some() || destination.to_ipv4_mapped().is_some() {
                return None;
            }
            Some(IpPacket {
                source: source.into(),
                destination: destination.into(),
                protocol: raw[6],
                header_len: 40,
                payload: &raw[40..],
                // A Fragment header is not a direct UDP packet. The current
                // raw-client router has no IPv6 extension-header UDP decoder.
                fragmented: raw[6] == 44,
            })
        }
        _ => None,
    }
}

fn valid_udp(ip: &IpPacket<'_>) -> bool {
    let udp = ip.payload;
    if udp.len() < 8 || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len() {
        return false;
    }
    let advertised = u16::from_be_bytes([udp[6], udp[7]]);
    if advertised == 0 {
        return ip.source.is_ipv4();
    }
    let mut sum = 0;
    match (ip.source, ip.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            add(&mut sum, &source.octets());
            add(&mut sum, &destination.octets());
            add(&mut sum, &[0, 17]);
            add(&mut sum, &u16::try_from(udp.len()).unwrap().to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            add(&mut sum, &source.octets());
            add(&mut sum, &destination.octets());
            add(&mut sum, &u32::try_from(udp.len()).unwrap().to_be_bytes());
            add(&mut sum, &[0, 0, 0, 17]);
        }
        _ => return false,
    }
    add(&mut sum, udp);
    finish(sum) == 0
}

fn add(sum: &mut u32, bytes: &[u8]) {
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        *sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(last) = words.remainder().first() {
        *sum += u32::from(*last) << 8;
    }
}

fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits u16")
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0;
    add(&mut sum, bytes);
    finish(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vole_netstack::{ClientPrefix, UdpDatagram, encode_udp_packet_into, parse_udp_packet_view};

    fn client() -> ClientConfig {
        ClientConfig {
            prefixes: [
                Some(ClientPrefix {
                    address: "10.0.0.2".parse().unwrap(),
                    prefix_len: 24,
                }),
                Some(ClientPrefix {
                    address: "fd00::2".parse().unwrap(),
                    prefix_len: 64,
                }),
            ],
            receive_packet_limit: 65575,
            path_mtu_discovery: true,
        }
        .validate(1280)
        .unwrap()
    }

    fn udp(ipv6: bool) -> Bytes {
        let (source, destination) = if ipv6 {
            ("[2001:db8::1]:53", "[fd00::2]:12345")
        } else {
            ("192.0.2.1:53", "10.0.0.2:12345")
        };
        let mut bytes = Vec::new();
        encode_udp_packet_into(
            &UdpDatagram::new(
                source.parse().unwrap(),
                destination.parse().unwrap(),
                Bytes::from_static(b"reply"),
            ),
            1500,
            &mut bytes,
        )
        .unwrap();
        bytes.into()
    }

    #[test]
    fn masque_ip_packets_validate_udp_and_preserve_checksums_across_one_hop() {
        for ipv6 in [false, true] {
            let raw = udp(ipv6);
            assert!(incoming(&raw, &client()));
            let original = raw.clone();
            let decremented = outgoing(raw).unwrap();
            assert!(incoming(&decremented, &client()));
            let view = parse_udp_packet_view(&decremented).unwrap();
            assert_eq!(view.payload, b"reply");
            let offset = if ipv6 { 7 } else { 8 };
            assert_eq!(decremented[offset], original[offset] - 1);
            assert_eq!(
                original[offset], 64,
                "mutating a shared packet changed its owner"
            );
            let mut corrupt = original.to_vec();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(!incoming(&corrupt, &client()));
            assert!(!incoming(&original[..original.len() - 1], &client()));
            let mut exhausted = original.to_vec();
            exhausted[offset] = 1;
            if !ipv6 {
                exhausted[10..12].fill(0);
                let value = checksum(&exhausted[..20]);
                exhausted[10..12].copy_from_slice(&value.to_be_bytes());
            }
            assert!(outgoing(exhausted.into()).is_none());
        }
    }

    #[test]
    fn masque_ip_ingress_enforces_local_destination_udp_family_and_receive_budget() {
        for ipv6 in [false, true] {
            let original = udp(ipv6);
            let mut no_udp_checksum = original.to_vec();
            let udp_offset = if ipv6 { 40 } else { 20 };
            no_udp_checksum[udp_offset + 6..udp_offset + 8].fill(0);
            assert_eq!(incoming(&no_udp_checksum, &client()), !ipv6);
            let limited = ClientConfig {
                receive_packet_limit: original.len() - 1,
                ..client()
            };
            assert!(!incoming(&original, &limited));
            let mut other_client = client();
            other_client.prefixes = [
                Some(ClientPrefix {
                    address: if ipv6 { "fd00::3" } else { "10.0.0.3" }.parse().unwrap(),
                    prefix_len: if ipv6 { 64 } else { 24 },
                }),
                None,
            ];
            assert!(!incoming(&original, &other_client));
        }
        let mut fragment = udp(false).to_vec();
        fragment[6] = 0x20;
        fragment[10..12].fill(0);
        let value = checksum(&fragment[..20]);
        fragment[10..12].copy_from_slice(&value.to_be_bytes());
        assert!(!incoming(&fragment, &client()));
    }
}
