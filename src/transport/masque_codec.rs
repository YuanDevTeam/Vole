//! Bounded MASQUE framing from RFC 9000, RFC 9297, RFC 9298 and RFC 9484.
//! Capsule DATAGRAM values remain opaque: the request owner supplies the
//! HTTP Datagram context where required by its negotiated protocol.

use bytes::Bytes;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub(crate) const DATAGRAM: u64 = 0;
pub(crate) const ADDRESS_ASSIGN: u64 = 1;
pub(crate) const ADDRESS_REQUEST: u64 = 2;
pub(crate) const ROUTE_ADVERTISEMENT: u64 = 3;
pub(crate) const MAX_VARINT: u64 = (1 << 62) - 1;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid MASQUE framing")
}

pub(crate) fn varint_len(value: u64) -> io::Result<usize> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX_VARINT => Ok(8),
        _ => Err(invalid()),
    }
}

pub(crate) fn encode_varint(value: u64, output: &mut Vec<u8>) -> io::Result<()> {
    let len = varint_len(value)?;
    let start = output.len();
    output.extend_from_slice(&value.to_be_bytes()[8 - len..]);
    output[start] |= match len {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
    Ok(())
}

/// An incomplete integer is not an error. QUIC permits non-minimal encoding.
pub(crate) fn decode_varint(input: &[u8]) -> io::Result<Option<(u64, usize)>> {
    let Some(first) = input.first() else {
        return Ok(None);
    };
    let len = 1 << (first >> 6);
    if input.len() < len {
        return Ok(None);
    }
    let value = input[1..len]
        .iter()
        .fold(u64::from(first & 0x3f), |v, byte| {
            (v << 8) | u64::from(*byte)
        });
    Ok(Some((value, len)))
}

fn quarter_stream_id(raw_request_stream_id: u64) -> io::Result<u64> {
    if raw_request_stream_id > MAX_VARINT || raw_request_stream_id & 3 != 0 {
        return Err(invalid());
    }
    Ok(raw_request_stream_id / 4)
}

pub(crate) fn encode_h3_datagram(
    raw_request_stream_id: u64,
    payload: &[u8],
    wire_budget: usize,
) -> io::Result<Bytes> {
    let quarter = quarter_stream_id(raw_request_stream_id)?;
    let len = varint_len(quarter)?
        .checked_add(1)
        .and_then(|header| header.checked_add(payload.len()))
        .filter(|len| *len <= wire_budget)
        .ok_or_else(invalid)?;
    let mut output = Vec::with_capacity(len);
    encode_varint(quarter, &mut output)?;
    output.push(0); // Context ID zero, encoded in its shortest representation.
    output.extend_from_slice(payload);
    Ok(Bytes::from(output))
}

pub(crate) fn decode_h3_datagram(
    input: &[u8],
    expected_raw_request_stream_id: u64,
    wire_budget: usize,
) -> io::Result<&[u8]> {
    let expected = quarter_stream_id(expected_raw_request_stream_id)?;
    if input.len() > wire_budget {
        return Err(invalid());
    }
    let (quarter, consumed) = decode_varint(input)?.ok_or_else(invalid)?;
    if quarter > (MAX_VARINT / 4) || quarter != expected {
        return Err(invalid());
    }
    let (context, context_len) = decode_varint(&input[consumed..])?.ok_or_else(invalid)?;
    if context != 0 {
        return Err(invalid());
    }
    Ok(&input[consumed + context_len..])
}

pub(crate) struct Capsule {
    pub(crate) kind: u64,
    pub(crate) value: Bytes,
}

impl std::fmt::Debug for Capsule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueCapsule")
            .field("kind", &self.kind)
            .field("value_len", &self.value.len())
            .finish()
    }
}

pub(crate) fn encode_capsule(kind: u64, value: &[u8], max_value_len: usize) -> io::Result<Bytes> {
    if value.len() > max_value_len {
        return Err(invalid());
    }
    let value_len = u64::try_from(value.len()).map_err(|_| invalid())?;
    let len = varint_len(kind)?
        .checked_add(varint_len(value_len)?)
        .and_then(|header| header.checked_add(value.len()))
        .ok_or_else(invalid)?;
    let mut output = Vec::with_capacity(len);
    encode_varint(kind, &mut output)?;
    encode_varint(value_len, &mut output)?;
    output.extend_from_slice(value);
    Ok(Bytes::from(output))
}

/// One incremental parser owns at most one capsule value and an eight-byte
/// integer prefix. Unknown values are discarded without allocation. A failed
/// parser is retired; its partial bytes cannot be interpreted as a new capsule.
pub(crate) struct CapsuleDecoder {
    max_value_len: usize,
    kind: Option<u64>,
    length: Option<usize>,
    remaining: usize,
    integer: [u8; 8],
    integer_len: usize,
    value: Vec<u8>,
    retired: bool,
}

impl CapsuleDecoder {
    pub(crate) fn new(max_value_len: usize) -> Self {
        Self {
            max_value_len,
            kind: None,
            length: None,
            remaining: 0,
            integer: [0; 8],
            integer_len: 0,
            value: Vec::new(),
            retired: false,
        }
    }

    /// Consume a prefix and return at most one complete known capsule. The
    /// caller retains any unconsumed suffix. Completing an unknown capsule
    /// returns its consumed byte count with no capsule.
    pub(crate) fn feed(&mut self, input: &[u8]) -> io::Result<(usize, Option<Capsule>)> {
        if self.retired {
            return Err(invalid());
        }
        let result = self.feed_inner(input);
        if result.is_err() {
            self.retired = true;
            self.value = Vec::new();
        }
        result
    }

    fn feed_inner(&mut self, input: &[u8]) -> io::Result<(usize, Option<Capsule>)> {
        let mut consumed = 0;
        if self.kind.is_none() {
            let (count, kind) = self.read_integer(&input[consumed..])?;
            consumed += count;
            let Some(kind) = kind else {
                return Ok((consumed, None));
            };
            self.kind = Some(kind);
        }
        if self.length.is_none() {
            let (count, length) = self.read_integer(&input[consumed..])?;
            consumed += count;
            let Some(length) = length else {
                return Ok((consumed, None));
            };
            let length = usize::try_from(length).map_err(|_| invalid())?;
            if length > self.max_value_len {
                return Err(invalid());
            }
            self.length = Some(length);
            self.remaining = length;
            if self.known() {
                self.value = Vec::with_capacity(length);
            }
        }
        let count = self.remaining.min(input.len() - consumed);
        if self.known() {
            self.value
                .extend_from_slice(&input[consumed..consumed + count]);
        }
        consumed += count;
        self.remaining -= count;
        if self.remaining != 0 {
            return Ok((consumed, None));
        }
        let kind = self.kind.take().expect("capsule type read");
        self.length = None;
        let capsule = matches!(
            kind,
            DATAGRAM | ADDRESS_ASSIGN | ADDRESS_REQUEST | ROUTE_ADVERTISEMENT
        )
        .then(|| Capsule {
            kind,
            value: Bytes::from(std::mem::take(&mut self.value)),
        });
        Ok((consumed, capsule))
    }

    fn known(&self) -> bool {
        matches!(
            self.kind,
            Some(DATAGRAM | ADDRESS_ASSIGN | ADDRESS_REQUEST | ROUTE_ADVERTISEMENT)
        )
    }

    fn read_integer(&mut self, input: &[u8]) -> io::Result<(usize, Option<u64>)> {
        let mut consumed = 0;
        while consumed < input.len() {
            self.integer[self.integer_len] = input[consumed];
            self.integer_len += 1;
            consumed += 1;
            if let Some((value, _)) = decode_varint(&self.integer[..self.integer_len])? {
                self.integer_len = 0;
                return Ok((consumed, Some(value)));
            }
        }
        Ok((consumed, None))
    }

    /// Check end-of-stream without accepting a truncated header or value.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.retired || self.kind.is_some() || self.integer_len != 0 {
            self.retired = true;
            self.value = Vec::new();
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated MASQUE capsule",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressPrefix {
    pub(crate) request_id: u64,
    pub(crate) address: IpAddr,
    pub(crate) prefix_len: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) start: IpAddr,
    pub(crate) end: IpAddr,
    pub(crate) protocol: u8,
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
    let value = input.get(..count).ok_or_else(invalid)?;
    *input = &input[count..];
    Ok(value)
}

fn read_address(input: &mut &[u8], family: u8) -> io::Result<IpAddr> {
    match family {
        4 => Ok(
            Ipv4Addr::from(<[u8; 4]>::try_from(take(input, 4)?).expect("address length")).into(),
        ),
        6 => Ok(
            Ipv6Addr::from(<[u8; 16]>::try_from(take(input, 16)?).expect("address length")).into(),
        ),
        _ => Err(invalid()),
    }
}

/// Wire prefixes must be masked. Configured local addresses are a separate
/// consumer and must not be passed through this capsule-specific parser.
pub(crate) fn parse_addresses(
    kind: u64,
    mut input: &[u8],
    max_entries: usize,
) -> io::Result<Vec<AddressPrefix>> {
    if !matches!(kind, ADDRESS_ASSIGN | ADDRESS_REQUEST)
        || (kind == ADDRESS_REQUEST && input.is_empty())
    {
        return Err(invalid());
    }
    let mut prefixes = Vec::new();
    while !input.is_empty() {
        if prefixes.len() >= max_entries {
            return Err(invalid());
        }
        let (request_id, consumed) = decode_varint(input)?.ok_or_else(invalid)?;
        input = &input[consumed..];
        if kind == ADDRESS_REQUEST && request_id == 0 {
            return Err(invalid());
        }
        let family = take(&mut input, 1)?[0];
        let address = read_address(&mut input, family)?;
        let prefix_len = take(&mut input, 1)?[0];
        let (bits, value) = match address {
            IpAddr::V4(address) => (32, u128::from(u32::from(address))),
            IpAddr::V6(address) => (128, u128::from(address)),
        };
        if usize::from(prefix_len) > bits {
            return Err(invalid());
        }
        let host_bits = bits - usize::from(prefix_len);
        let host_mask = if host_bits == 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        if value & host_mask != 0 {
            return Err(invalid());
        }
        prefixes.push(AddressPrefix {
            request_id,
            address,
            prefix_len,
        });
    }
    Ok(prefixes)
}

/// Retain each route as advertised. The frozen reference consumer checks
/// individual ranges, without imposing an additional cross-entry ordering.
pub(crate) fn parse_routes(mut input: &[u8], max_entries: usize) -> io::Result<Vec<Route>> {
    let mut routes = Vec::new();
    while !input.is_empty() {
        if routes.len() >= max_entries {
            return Err(invalid());
        }
        let family = take(&mut input, 1)?[0];
        let start = read_address(&mut input, family)?;
        let end = read_address(&mut input, family)?;
        if start > end {
            return Err(invalid());
        }
        let protocol = take(&mut input, 1)?[0];
        routes.push(Route {
            start,
            end,
            protocol,
        });
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masque_varint_and_h3_datagram_wire_vectors_preserve_actual_stream_association() {
        for (value, expected) in [
            (37, vec![0x25]),
            (15_293, vec![0x7b, 0xbd]),
            (494_878_333, vec![0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652,
                vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ] {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).unwrap();
            assert_eq!(encoded, expected);
            for prefix in 0..expected.len() {
                assert!(decode_varint(&expected[..prefix]).unwrap().is_none());
            }
            assert_eq!(
                decode_varint(&expected).unwrap(),
                Some((value, expected.len()))
            );
        }
        assert!(encode_varint(1 << 62, &mut Vec::new()).is_err());
        let framed = encode_h3_datagram(256, b"udp", 6).unwrap();
        assert_eq!(framed.as_ref(), &[0x40, 0x40, 0, b'u', b'd', b'p']);
        assert_eq!(decode_h3_datagram(&framed, 256, 6).unwrap(), b"udp");
        assert!(decode_h3_datagram(&framed, 252, 6).is_err());
        assert!(encode_h3_datagram(1, b"", 8).is_err());
        assert!(encode_h3_datagram(256, b"udp", 5).is_err());
        assert_eq!(decode_h3_datagram(&[0x40, 0, 0x40, 0], 0, 4).unwrap(), b"");
        assert!(decode_h3_datagram(&[0, 1], 0, 2).is_err());
        assert!(decode_h3_datagram(&[0xff; 8], 0, 8).is_err());
    }

    #[test]
    fn masque_capsule_incremental_split_coalesced_and_unknown_skip_stay_bounded() {
        let mut encoded = encode_capsule(64, &[0xaa; 64], 64).unwrap().to_vec();
        encoded.extend_from_slice(&encode_capsule(DATAGRAM, &[0, 0xde, 0xad], 64).unwrap());
        encoded.extend_from_slice(&encode_capsule(ADDRESS_ASSIGN, b"", 64).unwrap());
        for split in 1..encoded.len() {
            let mut decoder = CapsuleDecoder::new(64);
            let mut received = Vec::new();
            for chunk in encoded.chunks(split) {
                let mut input = chunk;
                while !input.is_empty() {
                    let (consumed, capsule) = decoder.feed(input).unwrap();
                    assert!(consumed > 0);
                    input = &input[consumed..];
                    if let Some(capsule) = capsule {
                        received.push(capsule);
                    }
                    assert!(decoder.value.capacity() <= 64);
                }
            }
            decoder.finish().unwrap();
            assert_eq!(received.len(), 2);
            assert_eq!(received[0].kind, DATAGRAM);
            assert_eq!(received[0].value.as_ref(), &[0, 0xde, 0xad]);
            assert_eq!(received[1].kind, ADDRESS_ASSIGN);
            assert!(received[1].value.is_empty());
        }
        let mut decoder = CapsuleDecoder::new(63);
        assert!(decoder.feed(&encoded).is_err());
        assert_eq!(decoder.value.capacity(), 0);
        assert!(decoder.feed(&[0, 0]).is_err());
        let mut decoder = CapsuleDecoder::new(64);
        decoder.feed(&[0, 3, 0]).unwrap();
        assert_eq!(
            decoder.finish().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn masque_control_capsules_preserve_both_families_rejections_and_route_protocols() {
        // RFC9484 entries: unsolicited IPv4 /24, requested IPv6 /128 rejection.
        let mut addresses = vec![0, 4, 192, 0, 2, 0, 24, 7, 6];
        addresses.extend_from_slice(&[0; 16]);
        addresses.push(128);
        let assigned = parse_addresses(ADDRESS_ASSIGN, &addresses, 2).unwrap();
        assert_eq!(assigned.len(), 2);
        assert_eq!(assigned[0].address, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
        assert_eq!(assigned[1].request_id, 7);
        assert_eq!(assigned[1].prefix_len, 128);
        assert!(assigned[1].address.is_unspecified());
        assert!(parse_addresses(ADDRESS_ASSIGN, &addresses, 1).is_err());
        assert!(parse_addresses(ADDRESS_REQUEST, &addresses, 2).is_err());
        assert!(parse_addresses(ADDRESS_REQUEST, b"", 2).is_err());
        assert!(parse_addresses(ADDRESS_ASSIGN, &[0, 4, 192, 0, 2, 1, 24], 2).is_err());
        assert!(parse_addresses(ADDRESS_REQUEST, &[1, 4, 0, 0, 0, 0, 32], 1).is_ok());
        let routes = [4, 192, 0, 2, 1, 192, 0, 2, 9, 17];
        let decoded = parse_routes(&routes, 1).unwrap();
        assert_eq!(decoded[0].protocol, 17);
        assert!(parse_routes(&routes[..8], 1).is_err());
        assert!(parse_routes(&[4, 192, 0, 2, 9, 192, 0, 2, 1, 0], 1).is_err());
        assert!(parse_routes(b"", 0).unwrap().is_empty());
    }
}
