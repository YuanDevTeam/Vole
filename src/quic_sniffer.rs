//! Bounded QUIC Initial sniffing shared by TUN and authorized SOCKS5 UDP.
//!
//! Only public QUIC Initial keys are used. Decryption is advisory and operates
//! on scratch buffers; the intercepted datagram remains owned by the caller for
//! exact replay after routing has been selected.

use std::ops::Range;

use rustls::{
    Side,
    crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    quic::{DirectionalKeys, Version},
};

use crate::tcp_sniffer::{ParseOutcome, parse_client_hello};

pub(crate) const QUIC_SNIFF_MAX_CRYPTO_BYTES: usize = 16 * 1024;
const QUIC_SNIFF_MAX_RANGES: usize = 64;
const QUIC_SNIFF_MAX_ACK_RANGES: u64 = 64;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const LONG_HEADER: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const PACKET_TYPE_MASK: u8 = 0x30;
const PACKET_NUMBER_LENGTH_MASK: u8 = 0x03;
const CLIENT_HELLO: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QuicSniffOutcome {
    NeedMoreData,
    Matched(String),
    EchExtensionPresent,
    NotMatched,
    LimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    fn from_wire(value: u32) -> Option<Self> {
        match value {
            QUIC_V1 => Some(Self::V1),
            QUIC_V2 => Some(Self::V2),
            _ => None,
        }
    }

    const fn rustls(self) -> Version {
        match self {
            Self::V1 => Version::V1,
            Self::V2 => Version::V2,
        }
    }

    const fn initial_packet_type(self) -> u8 {
        match self {
            Self::V1 => 0,
            Self::V2 => 1,
        }
    }

    const fn retry_packet_type(self) -> u8 {
        match self {
            Self::V1 => 3,
            Self::V2 => 0,
        }
    }
}

struct InitialContext {
    wire_version: u32,
    keys: DirectionalKeys,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicConnectionKey {
    wire_version: u32,
    destination_connection_id: Box<[u8]>,
}

impl QuicConnectionKey {
    /// An exact, allocation-free identity for an authenticated Initial flow.
    /// Length is explicit so zero padding cannot alias a different DCID.
    pub(crate) fn routing_identity(&self) -> [u8; 25] {
        let mut identity = [0; 25];
        identity[..4].copy_from_slice(&self.wire_version.to_be_bytes());
        let length = self.destination_connection_id.len();
        identity[4] = u8::try_from(length).expect("parsed QUIC DCIDs fit in 20 bytes");
        identity[5..5 + length].copy_from_slice(&self.destination_connection_id);
        identity
    }
}

enum QuicConnectionObservation {
    Initial(QuicConnectionKey),
    UnsupportedVersion,
    None,
}

struct LongHeader<'a> {
    wire_version: u32,
    version: QuicVersion,
    destination_connection_id: &'a [u8],
    packet_type: u8,
    initial: Option<InitialPacket>,
    packet_end: Option<usize>,
}

struct InitialPacket {
    packet_number_offset: usize,
    packet_end: usize,
}

/// Stateful reassembler for one QUIC connection attempt.
pub(crate) struct QuicSniffer {
    initial: Option<InitialContext>,
    authenticated_initial_in_last_ingest: bool,
    largest_packet_number: Option<u64>,
    crypto: Vec<u8>,
    ranges: Vec<Range<usize>>,
}

impl QuicSniffer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            initial: None,
            authenticated_initial_in_last_ingest: false,
            largest_packet_number: None,
            crypto: Vec::new(),
            ranges: Vec::new(),
        }
    }

    /// Observes every parseable long-header packet coalesced into one
    /// client-to-server UDP datagram.
    pub(crate) fn ingest(&mut self, datagram: &[u8]) -> QuicSniffOutcome {
        self.authenticated_initial_in_last_ingest = false;
        let mut datagram_offset = 0;
        let mut parsed_packet = false;
        let mut datagram_connection: Option<(u32, Box<[u8]>)> = None;
        while datagram_offset < datagram.len() {
            let packet_bytes = &datagram[datagram_offset..];
            let header = match parse_long_header(packet_bytes) {
                Ok(header) => header,
                // A short-header packet may legally end a coalesced datagram.
                // Preserve Initial CRYPTO already authenticated above it.
                Err(()) if parsed_packet => break,
                Err(()) => return QuicSniffOutcome::NotMatched,
            };
            parsed_packet = true;
            if let Some((wire_version, destination_connection_id)) = &datagram_connection {
                if *wire_version != header.wire_version
                    || destination_connection_id.as_ref() != header.destination_connection_id
                {
                    // RFC 9000 requires coalesced packets to use the same
                    // destination connection ID. Ignore a foreign suffix
                    // without discarding authenticated CRYPTO from the prefix.
                    break;
                }
            } else {
                datagram_connection =
                    Some((header.wire_version, header.destination_connection_id.into()));
            }
            if header.packet_type == header.version.retry_packet_type() {
                if datagram_offset == 0 {
                    return QuicSniffOutcome::NotMatched;
                }
                break;
            }
            if let Some(packet) = header.initial {
                let outcome = self.ingest_initial(
                    packet_bytes,
                    &packet,
                    header.wire_version,
                    header.version,
                    header.destination_connection_id,
                );
                if outcome != QuicSniffOutcome::NeedMoreData {
                    return outcome;
                }
            }
            let Some(packet_end) = header.packet_end else {
                break;
            };
            if packet_end == 0 {
                return QuicSniffOutcome::NotMatched;
            }
            datagram_offset = match datagram_offset.checked_add(packet_end) {
                Some(offset) if offset <= datagram.len() => offset,
                _ => return QuicSniffOutcome::NotMatched,
            };
        }
        self.try_client_hello()
    }

    /// Reports whether the most recent `ingest` call authenticated at least
    /// one Initial packet with the active Initial packet-protection keys.
    #[must_use]
    pub(crate) const fn authenticated_initial_in_last_ingest(&self) -> bool {
        self.authenticated_initial_in_last_ingest
    }

    fn ingest_initial(
        &mut self,
        packet_bytes: &[u8],
        packet: &InitialPacket,
        wire_version: u32,
        version: QuicVersion,
        destination_connection_id: &[u8],
    ) -> QuicSniffOutcome {
        let decrypted = if let Some(context) = &self.initial {
            if context.wire_version != wire_version {
                return QuicSniffOutcome::NotMatched;
            }
            decrypt_initial(
                packet_bytes,
                packet,
                &context.keys,
                self.largest_packet_number,
            )
        } else {
            let keys = initial_client_keys(destination_connection_id, version.rustls());
            let decrypted =
                decrypt_initial(packet_bytes, packet, &keys, self.largest_packet_number);
            if decrypted.is_ok() {
                self.initial = Some(InitialContext { wire_version, keys });
            }
            decrypted
        };
        let plaintext = match decrypted {
            Ok((packet_number, plaintext)) => {
                self.largest_packet_number = Some(
                    self.largest_packet_number
                        .map_or(packet_number, |largest| largest.max(packet_number)),
                );
                plaintext
            }
            Err(()) => return QuicSniffOutcome::NotMatched,
        };
        self.authenticated_initial_in_last_ingest = true;

        match self.read_frames(&plaintext) {
            QuicSniffOutcome::NeedMoreData => self.try_client_hello(),
            outcome => outcome,
        }
    }

    fn read_frames(&mut self, plaintext: &[u8]) -> QuicSniffOutcome {
        let mut cursor = 0;
        while cursor < plaintext.len() {
            let frame_type = match read_varint(plaintext, &mut cursor) {
                Some(value) => value,
                None => return QuicSniffOutcome::NotMatched,
            };
            match frame_type {
                0x00 | 0x01 => {}
                0x02 | 0x03 => {
                    if !skip_ack_frame(
                        plaintext,
                        &mut cursor,
                        frame_type == 0x03,
                        QUIC_SNIFF_MAX_ACK_RANGES,
                    ) {
                        return QuicSniffOutcome::NotMatched;
                    }
                }
                0x06 => {
                    let Some(offset) = read_varint(plaintext, &mut cursor)
                        .and_then(|value| usize::try_from(value).ok())
                    else {
                        return QuicSniffOutcome::NotMatched;
                    };
                    let Some(length) = read_varint(plaintext, &mut cursor)
                        .and_then(|value| usize::try_from(value).ok())
                    else {
                        return QuicSniffOutcome::NotMatched;
                    };
                    let Some(end) = offset.checked_add(length) else {
                        return QuicSniffOutcome::LimitReached;
                    };
                    if end > QUIC_SNIFF_MAX_CRYPTO_BYTES {
                        return QuicSniffOutcome::LimitReached;
                    }
                    let Some(data_end) = cursor.checked_add(length) else {
                        return QuicSniffOutcome::NotMatched;
                    };
                    let Some(data) = plaintext.get(cursor..data_end) else {
                        return QuicSniffOutcome::NotMatched;
                    };
                    if let Err(outcome) = self.insert_crypto(offset, data) {
                        return outcome;
                    }
                    cursor = data_end;
                }
                0x1c => {
                    if !skip_connection_close(plaintext, &mut cursor) {
                        return QuicSniffOutcome::NotMatched;
                    }
                }
                _ => return QuicSniffOutcome::NotMatched,
            }
        }
        QuicSniffOutcome::NeedMoreData
    }

    fn insert_crypto(&mut self, offset: usize, data: &[u8]) -> Result<(), QuicSniffOutcome> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset + data.len();
        for range in &self.ranges {
            let overlap_start = offset.max(range.start);
            let overlap_end = end.min(range.end);
            if overlap_start < overlap_end {
                let old = &self.crypto[overlap_start..overlap_end];
                let new = &data[overlap_start - offset..overlap_end - offset];
                if old != new {
                    return Err(QuicSniffOutcome::NotMatched);
                }
            }
        }

        let mut ranges = self.ranges.clone();
        ranges.push(offset..end);
        merge_ranges(&mut ranges);
        if ranges.len() > QUIC_SNIFF_MAX_RANGES {
            return Err(QuicSniffOutcome::LimitReached);
        }
        if self.crypto.len() < end {
            self.crypto.resize(end, 0);
        }
        self.crypto[offset..end].copy_from_slice(data);
        self.ranges = ranges;
        Ok(())
    }

    fn try_client_hello(&self) -> QuicSniffOutcome {
        let Some(contiguous) = self
            .ranges
            .first()
            .filter(|range| range.start == 0)
            .map(|range| range.end)
        else {
            return QuicSniffOutcome::NeedMoreData;
        };
        if contiguous < 4 {
            return QuicSniffOutcome::NeedMoreData;
        }
        if self.crypto[0] != CLIENT_HELLO {
            return QuicSniffOutcome::NotMatched;
        }
        let declared = (usize::from(self.crypto[1]) << 16)
            | (usize::from(self.crypto[2]) << 8)
            | usize::from(self.crypto[3]);
        let Some(total) = declared.checked_add(4) else {
            return QuicSniffOutcome::LimitReached;
        };
        if total > QUIC_SNIFF_MAX_CRYPTO_BYTES {
            return QuicSniffOutcome::LimitReached;
        }
        if contiguous < total {
            return QuicSniffOutcome::NeedMoreData;
        }
        match parse_client_hello(&self.crypto[..total]) {
            ParseOutcome::Matched(domain) => QuicSniffOutcome::Matched(domain),
            ParseOutcome::EchExtensionPresent => QuicSniffOutcome::EchExtensionPresent,
            ParseOutcome::NeedMoreData | ParseOutcome::NotMatched => QuicSniffOutcome::NotMatched,
        }
    }
}

/// Returns the first standard v1/v2 Initial identity in a QUIC datagram.
///
/// Non-Initial long headers and short-header traffic deliberately return no
/// candidate. Coalesced 0-RTT or Handshake packets are skipped using their
/// explicit packet lengths so a following Initial can still be identified.
pub(crate) fn quic_connection_key(datagram: &[u8]) -> Option<QuicConnectionKey> {
    match quic_connection_observation(datagram) {
        QuicConnectionObservation::Initial(key) => Some(key),
        QuicConnectionObservation::UnsupportedVersion | QuicConnectionObservation::None => None,
    }
}

/// Detects a structurally bounded long header carrying an unsupported,
/// non-zero QUIC version.
pub(crate) fn quic_has_unsupported_version(datagram: &[u8]) -> bool {
    matches!(
        quic_connection_observation(datagram),
        QuicConnectionObservation::UnsupportedVersion
    )
}

fn quic_connection_observation(datagram: &[u8]) -> QuicConnectionObservation {
    let mut offset = 0;
    while offset < datagram.len() {
        let packet = &datagram[offset..];
        let Some(first) = packet.first() else {
            return QuicConnectionObservation::None;
        };
        if first & (LONG_HEADER | FIXED_BIT) != LONG_HEADER | FIXED_BIT {
            return QuicConnectionObservation::None;
        }
        let Some(wire_version) = packet
            .get(1..5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
        else {
            return QuicConnectionObservation::None;
        };
        if wire_version != 0 && QuicVersion::from_wire(wire_version).is_none() {
            let Some(destination_connection_id_length) = packet.get(5).copied().map(usize::from)
            else {
                return QuicConnectionObservation::None;
            };
            if !(1..=20).contains(&destination_connection_id_length)
                || packet
                    .get(6..6 + destination_connection_id_length)
                    .is_none()
            {
                return QuicConnectionObservation::None;
            }
            return QuicConnectionObservation::UnsupportedVersion;
        }
        let Ok(header) = parse_long_header(packet) else {
            return QuicConnectionObservation::None;
        };
        if header.initial.is_some() {
            return QuicConnectionObservation::Initial(QuicConnectionKey {
                wire_version: header.wire_version,
                destination_connection_id: header.destination_connection_id.into(),
            });
        }
        let Some(packet_end) = header.packet_end else {
            return QuicConnectionObservation::None;
        };
        if packet_end == 0 {
            return QuicConnectionObservation::None;
        }
        let Some(next_offset) = offset.checked_add(packet_end) else {
            return QuicConnectionObservation::None;
        };
        offset = next_offset;
    }
    QuicConnectionObservation::None
}

fn initial_client_keys(destination_connection_id: &[u8], version: Version) -> DirectionalKeys {
    let suite = TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("selected cipher suite is TLS 1.3")
        .quic_suite()
        .expect("AES-128-GCM suite supports QUIC");
    // From the server's perspective, `remote` decrypts the client's Initial.
    suite
        .keys(destination_connection_id, Side::Server, version)
        .remote
}

fn parse_long_header(datagram: &[u8]) -> Result<LongHeader<'_>, ()> {
    let first = *datagram.first().ok_or(())?;
    if first & (LONG_HEADER | FIXED_BIT) != LONG_HEADER | FIXED_BIT {
        return Err(());
    }
    let wire_version =
        u32::from_be_bytes(datagram.get(1..5).ok_or(())?.try_into().map_err(|_| ())?);
    let version = QuicVersion::from_wire(wire_version).ok_or(())?;
    let packet_type = (first & PACKET_TYPE_MASK) >> 4;

    let mut cursor = 5;
    let destination_connection_id_length = usize::from(*datagram.get(cursor).ok_or(())?);
    cursor += 1;
    if !(1..=20).contains(&destination_connection_id_length) {
        return Err(());
    }
    let destination_connection_id_end = cursor
        .checked_add(destination_connection_id_length)
        .ok_or(())?;
    let destination_connection_id = datagram
        .get(cursor..destination_connection_id_end)
        .ok_or(())?;
    cursor = destination_connection_id_end;

    let source_connection_id_length = usize::from(*datagram.get(cursor).ok_or(())?);
    cursor += 1;
    if source_connection_id_length > 20 {
        return Err(());
    }
    cursor = cursor
        .checked_add(source_connection_id_length)
        .filter(|end| *end <= datagram.len())
        .ok_or(())?;

    if packet_type != version.initial_packet_type() {
        let packet_end = if packet_type == version.retry_packet_type() {
            None
        } else {
            let packet_length = read_varint(datagram, &mut cursor)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(())?;
            Some(
                cursor
                    .checked_add(packet_length)
                    .filter(|end| *end <= datagram.len())
                    .ok_or(())?,
            )
        };
        return Ok(LongHeader {
            wire_version,
            version,
            destination_connection_id,
            packet_type,
            initial: None,
            packet_end,
        });
    }

    let token_length = read_varint(datagram, &mut cursor)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(())?;
    cursor = cursor
        .checked_add(token_length)
        .filter(|end| *end <= datagram.len())
        .ok_or(())?;
    let packet_length = read_varint(datagram, &mut cursor)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(())?;
    let packet_number_offset = cursor;
    let packet_end = packet_number_offset
        .checked_add(packet_length)
        .filter(|end| *end <= datagram.len())
        .ok_or(())?;
    if packet_length < 1 + 16 {
        return Err(());
    }

    Ok(LongHeader {
        wire_version,
        version,
        destination_connection_id,
        packet_type,
        initial: Some(InitialPacket {
            packet_number_offset,
            packet_end,
        }),
        packet_end: Some(packet_end),
    })
}

fn decrypt_initial(
    datagram: &[u8],
    packet: &InitialPacket,
    keys: &DirectionalKeys,
    largest_packet_number: Option<u64>,
) -> Result<(u64, Vec<u8>), ()> {
    let sample_length = keys.header.sample_len();
    let sample_start = packet.packet_number_offset.checked_add(4).ok_or(())?;
    let sample_end = sample_start.checked_add(sample_length).ok_or(())?;
    let sample = datagram
        .get(sample_start..sample_end)
        .filter(|_| sample_end <= packet.packet_end)
        .ok_or(())?;

    let protected_header_end = packet
        .packet_number_offset
        .checked_add(4)
        .filter(|end| *end <= packet.packet_end)
        .ok_or(())?;
    let mut header = datagram.get(..protected_header_end).ok_or(())?.to_vec();
    let (first, remainder) = header.split_first_mut().ok_or(())?;
    let packet_number_start = packet.packet_number_offset.checked_sub(1).ok_or(())?;
    let packet_number = remainder
        .get_mut(packet_number_start..packet_number_start + 4)
        .ok_or(())?;
    keys.header
        .decrypt_in_place(sample, first, packet_number)
        .map_err(|_| ())?;

    let packet_number_length = usize::from(*first & PACKET_NUMBER_LENGTH_MASK) + 1;
    let header_end = packet
        .packet_number_offset
        .checked_add(packet_number_length)
        .ok_or(())?;
    header.truncate(header_end);
    let truncated_packet_number = header
        .get(packet.packet_number_offset..header_end)
        .ok_or(())?
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    let packet_number = reconstruct_packet_number(
        largest_packet_number,
        truncated_packet_number,
        packet_number_length,
    );

    let mut payload = datagram
        .get(header_end..packet.packet_end)
        .ok_or(())?
        .to_vec();
    let plaintext_length = {
        let plaintext = keys
            .packet
            .decrypt_in_place(packet_number, &header, &mut payload)
            .map_err(|_| ())?;
        plaintext.len()
    };
    payload.truncate(plaintext_length);
    Ok((packet_number, payload))
}

fn reconstruct_packet_number(largest: Option<u64>, truncated: u64, encoded_length: usize) -> u64 {
    let expected = largest.map_or(0, |value| value.saturating_add(1));
    let packet_number_bits = encoded_length * 8;
    let window = 1_u64 << packet_number_bits;
    let half_window = window / 2;
    let mask = window - 1;
    let mut candidate = (expected & !mask) | truncated;
    if candidate.saturating_add(half_window) <= expected
        && candidate < (1_u64 << 62).saturating_sub(window)
    {
        candidate += window;
    } else if candidate > expected.saturating_add(half_window) && candidate >= window {
        candidate -= window;
    }
    candidate
}

fn read_varint(input: &[u8], cursor: &mut usize) -> Option<u64> {
    let first = *input.get(*cursor)?;
    let length = 1_usize << (first >> 6);
    let end = cursor.checked_add(length)?;
    let bytes = input.get(*cursor..end)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *cursor = end;
    Some(value)
}

fn skip_ack_frame(input: &[u8], cursor: &mut usize, ecn: bool, maximum_ranges: u64) -> bool {
    if read_varint(input, cursor).is_none() || read_varint(input, cursor).is_none() {
        return false;
    }
    let Some(range_count) = read_varint(input, cursor) else {
        return false;
    };
    // ACK Range Count excludes the mandatory First ACK Range. Keep the
    // configured bound on the total number of ranges, not only the trailing
    // Gap/ACK Range pairs.
    if range_count >= maximum_ranges || read_varint(input, cursor).is_none() {
        return false;
    }
    for _ in 0..range_count {
        if read_varint(input, cursor).is_none() || read_varint(input, cursor).is_none() {
            return false;
        }
    }
    if ecn {
        for _ in 0..3 {
            if read_varint(input, cursor).is_none() {
                return false;
            }
        }
    }
    true
}

fn skip_connection_close(input: &[u8], cursor: &mut usize) -> bool {
    if read_varint(input, cursor).is_none() || read_varint(input, cursor).is_none() {
        return false;
    }
    let Some(reason_length) =
        read_varint(input, cursor).and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(end) = cursor.checked_add(reason_length) else {
        return false;
    };
    if end > input.len() {
        return false;
    }
    *cursor = end;
    true
}

fn merge_ranges(ranges: &mut Vec<Range<usize>>) {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DCID: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digits = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(digits, 16).unwrap()
            })
            .collect()
    }

    fn tls_extension(extension_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut extension = Vec::new();
        extension.extend_from_slice(&extension_type.to_be_bytes());
        extension.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        extension.extend_from_slice(payload);
        extension
    }

    fn server_name_extension(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut names = Vec::new();
        names.extend_from_slice(&u16::try_from(host.len() + 3).unwrap().to_be_bytes());
        names.push(0);
        names.extend_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
        names.extend_from_slice(host);
        tls_extension(0, &names)
    }

    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = vec![CLIENT_HELLO];
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        handshake.extend_from_slice(&length[1..]);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn write_varint(value: u64, output: &mut Vec<u8>) {
        if value < (1 << 6) {
            output.push(value as u8);
        } else if value < (1 << 14) {
            output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
        } else if value < (1 << 30) {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
        } else {
            panic!("test value exceeds the four-byte QUIC varint range");
        }
    }

    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        write_varint(offset as u64, &mut frame);
        write_varint(data.len() as u64, &mut frame);
        frame.extend_from_slice(data);
        frame
    }

    fn initial_packet(
        version: QuicVersion,
        packet_number: u64,
        packet_number_length: usize,
        plaintext: &[u8],
    ) -> Vec<u8> {
        initial_packet_with_token(version, packet_number, packet_number_length, &[], plaintext)
    }

    fn initial_packet_with_token(
        version: QuicVersion,
        packet_number: u64,
        packet_number_length: usize,
        token: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        initial_packet_with_connection_ids(
            version,
            TEST_DCID,
            TEST_DCID,
            packet_number,
            packet_number_length,
            token,
            plaintext,
        )
    }

    fn initial_packet_with_connection_ids(
        version: QuicVersion,
        key_destination_connection_id: &[u8],
        header_destination_connection_id: &[u8],
        packet_number: u64,
        packet_number_length: usize,
        token: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let rustls_version = version.rustls();
        let keys = TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap()
            .keys(key_destination_connection_id, Side::Client, rustls_version)
            .local;
        let first = LONG_HEADER
            | FIXED_BIT
            | (version.initial_packet_type() << 4)
            | u8::try_from(packet_number_length - 1).unwrap();
        let mut header = vec![first];
        let wire_version = match version {
            QuicVersion::V1 => QUIC_V1,
            QuicVersion::V2 => QUIC_V2,
        };
        header.extend_from_slice(&wire_version.to_be_bytes());
        header.push(header_destination_connection_id.len() as u8);
        header.extend_from_slice(header_destination_connection_id);
        header.push(0);
        write_varint(token.len() as u64, &mut header);
        header.extend_from_slice(token);
        let protected_length = packet_number_length + plaintext.len() + keys.packet.tag_len();
        write_varint(protected_length as u64, &mut header);
        let packet_number_offset = header.len();
        let packet_number_bytes = packet_number.to_be_bytes();
        header.extend_from_slice(
            &packet_number_bytes[packet_number_bytes.len() - packet_number_length..],
        );

        let mut encrypted = plaintext.to_vec();
        let tag = keys
            .packet
            .encrypt_in_place(packet_number, &header, &mut encrypted)
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&encrypted);
        packet.extend_from_slice(tag.as_ref());

        let sample_start = packet_number_offset + 4;
        let sample_end = sample_start + keys.header.sample_len();
        let sample = packet[sample_start..sample_end].to_vec();
        let (first, remainder) = packet.split_first_mut().unwrap();
        keys.header
            .encrypt_in_place(
                &sample,
                first,
                &mut remainder
                    [packet_number_offset - 1..packet_number_offset - 1 + packet_number_length],
            )
            .unwrap();
        packet
    }

    fn zero_rtt_packet(version: QuicVersion) -> Vec<u8> {
        let packet_type = match version {
            QuicVersion::V1 => 1,
            QuicVersion::V2 => 2,
        };
        non_initial_packet(version, packet_type, TEST_DCID)
    }

    fn handshake_packet(version: QuicVersion) -> Vec<u8> {
        let packet_type = match version {
            QuicVersion::V1 => 2,
            QuicVersion::V2 => 3,
        };
        non_initial_packet(version, packet_type, TEST_DCID)
    }

    fn non_initial_packet(
        version: QuicVersion,
        packet_type: u8,
        destination_connection_id: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![LONG_HEADER | FIXED_BIT | (packet_type << 4)];
        packet.extend_from_slice(
            &match version {
                QuicVersion::V1 => QUIC_V1,
                QuicVersion::V2 => QUIC_V2,
            }
            .to_be_bytes(),
        );
        packet.push(destination_connection_id.len() as u8);
        packet.extend_from_slice(destination_connection_id);
        packet.push(0);
        write_varint(17, &mut packet);
        packet.extend_from_slice(&[0; 17]);
        packet
    }

    #[test]
    fn v1_and_v2_initial_extract_the_same_normalized_sni() {
        let hello = client_hello(&server_name_extension("ExAmPlE.COM"));
        let frame = crypto_frame(0, &hello);
        for version in [QuicVersion::V1, QuicVersion::V2] {
            let packet = initial_packet(version, 0, 2, &frame);
            let original = packet.clone();
            assert_eq!(
                QuicSniffer::new().ingest(&packet),
                QuicSniffOutcome::Matched("example.com".to_owned())
            );
            assert_eq!(packet, original);
        }
    }

    #[test]
    fn independent_v1_wire_fixture_extracts_sni() {
        // Generated independently with Node.js/OpenSSL HKDF, AES-128-GCM and
        // AES-ECB primitives. The derived key/IV/HP values were cross-checked
        // against RFC 9001 Appendix A.1 before freezing this wire packet.
        let packet = decode_hex(concat!(
            "c800000001088394c8f03e515708000040595e46b4519e9b7ca367c0a55e84",
            "d79966d2330101efba41060aa067ae7f8b3711a51d64f57f551a66486d0627",
            "fb13e5e574e9027dd731e3ab76abddd08746006656843523999473e2d8488b",
            "fd35327f2885052cf927afe46548"
        ));
        assert_eq!(
            QuicSniffer::new().ingest(&packet),
            QuicSniffOutcome::Matched("wire.example".to_owned())
        );
    }

    #[test]
    fn token_and_three_or_four_byte_packet_numbers_are_supported() {
        let hello = client_hello(&server_name_extension("token.example"));
        let frame = crypto_frame(0, &hello);
        for (version, packet_number, packet_number_length) in [
            (QuicVersion::V1, 0x01_02_03, 3),
            (QuicVersion::V2, 0x01_02_03_04, 4),
        ] {
            assert_eq!(
                QuicSniffer::new().ingest(&initial_packet_with_token(
                    version,
                    packet_number,
                    packet_number_length,
                    &[0xde, 0xad, 0xbe, 0xef],
                    &frame,
                )),
                QuicSniffOutcome::Matched("token.example".to_owned())
            );
        }
    }

    #[test]
    fn crypto_fragments_reassemble_out_of_order_and_retransmit_safely() {
        let hello = client_hello(&server_name_extension("fragmented.example"));
        let split = hello.len() / 2;
        let first = initial_packet(QuicVersion::V1, 255, 1, &crypto_frame(0, &hello[..split]));
        let second = initial_packet(
            QuicVersion::V1,
            256,
            2,
            &crypto_frame(split, &hello[split..]),
        );
        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.ingest(&second), QuicSniffOutcome::NeedMoreData);
        assert_eq!(sniffer.ingest(&second), QuicSniffOutcome::NeedMoreData);
        assert_eq!(
            sniffer.ingest(&first),
            QuicSniffOutcome::Matched("fragmented.example".to_owned())
        );
    }

    #[test]
    fn authenticated_initial_keys_survive_a_header_dcid_rotation() {
        const ROTATED_DCID: &[u8] = b"rotated!";

        let hello = client_hello(&server_name_extension("rotated.example"));
        let split = hello.len() / 2;
        let first = initial_packet_with_connection_ids(
            QuicVersion::V1,
            TEST_DCID,
            TEST_DCID,
            0,
            1,
            &[],
            &crypto_frame(0, &hello[..split]),
        );
        let second = initial_packet_with_connection_ids(
            QuicVersion::V1,
            TEST_DCID,
            ROTATED_DCID,
            1,
            1,
            &[],
            &crypto_frame(split, &hello[split..]),
        );
        assert_ne!(
            quic_connection_key(&first),
            quic_connection_key(&second),
            "the wire headers must expose distinct connection candidates"
        );

        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.ingest(&first), QuicSniffOutcome::NeedMoreData);
        assert!(sniffer.authenticated_initial_in_last_ingest());
        assert_eq!(
            sniffer.ingest(&second),
            QuicSniffOutcome::Matched("rotated.example".to_owned())
        );
        assert!(
            sniffer.authenticated_initial_in_last_ingest(),
            "the rotated header DCID must authenticate with the original Initial keys"
        );
    }

    #[test]
    fn coalesced_initial_packets_both_contribute_crypto_fragments() {
        let hello = client_hello(&server_name_extension("coalesced.example"));
        let split = hello.len() / 2;
        let first = initial_packet(QuicVersion::V2, 0, 1, &crypto_frame(0, &hello[..split]));
        let second = initial_packet(QuicVersion::V2, 1, 1, &crypto_frame(split, &hello[split..]));
        let mut datagram = first;
        datagram.extend_from_slice(&second);
        assert_eq!(
            QuicSniffer::new().ingest(&datagram),
            QuicSniffOutcome::Matched("coalesced.example".to_owned())
        );
    }

    #[test]
    fn connection_candidates_ignore_non_initial_packets_and_scan_coalesced_initials() {
        for version in [QuicVersion::V1, QuicVersion::V2] {
            assert!(quic_connection_key(&zero_rtt_packet(version)).is_none());
            assert!(quic_connection_key(&handshake_packet(version)).is_none());

            let initial = initial_packet(version, 0, 1, &[0x00; 4]);
            let expected = quic_connection_key(&initial).expect("Initial candidate missing");
            let mut coalesced = zero_rtt_packet(version);
            coalesced.extend_from_slice(&initial);
            assert_eq!(quic_connection_key(&coalesced), Some(expected));
        }
    }

    #[test]
    fn unknown_nonzero_versions_are_unsupported_observations() {
        let mut unknown = zero_rtt_packet(QuicVersion::V1);
        unknown[1..5].copy_from_slice(&0xface_b00c_u32.to_be_bytes());
        assert!(quic_connection_key(&unknown).is_none());
        assert!(quic_has_unsupported_version(&unknown));

        let mut version_negotiation = unknown;
        version_negotiation[1..5].fill(0);
        assert!(!quic_has_unsupported_version(&version_negotiation));
    }

    #[test]
    fn coalesced_zero_rtt_before_initial_does_not_hide_client_hello() {
        let hello = client_hello(&server_name_extension("after-zero-rtt.example"));
        let mut datagram = zero_rtt_packet(QuicVersion::V1);
        datagram.extend_from_slice(&initial_packet(
            QuicVersion::V1,
            0,
            1,
            &crypto_frame(0, &hello),
        ));
        assert_eq!(
            QuicSniffer::new().ingest(&datagram),
            QuicSniffOutcome::Matched("after-zero-rtt.example".to_owned())
        );
    }

    #[test]
    fn unauthenticated_zero_rtt_does_not_bind_later_initial_keys() {
        let mut unrelated = zero_rtt_packet(QuicVersion::V1);
        unrelated[6] ^= 0xff;
        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.ingest(&unrelated), QuicSniffOutcome::NeedMoreData);
        let hello = client_hello(&server_name_extension("authenticated.example"));
        assert_eq!(
            sniffer.ingest(&initial_packet(
                QuicVersion::V1,
                0,
                1,
                &crypto_frame(0, &hello),
            )),
            QuicSniffOutcome::Matched("authenticated.example".to_owned())
        );
    }

    #[test]
    fn foreign_coalesced_suffix_does_not_discard_authenticated_prefix() {
        let hello = client_hello(&server_name_extension("prefix.example"));
        let split = hello.len() / 2;
        let first = initial_packet(QuicVersion::V1, 0, 1, &crypto_frame(0, &hello[..split]));
        let mut foreign =
            initial_packet(QuicVersion::V1, 1, 1, &crypto_frame(split, &hello[split..]));
        foreign[6] ^= 0xff;
        let mut coalesced = first;
        coalesced.extend_from_slice(&foreign);

        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.ingest(&coalesced), QuicSniffOutcome::NeedMoreData);
        assert_eq!(
            sniffer.ingest(&initial_packet(
                QuicVersion::V1,
                1,
                1,
                &crypto_frame(split, &hello[split..]),
            )),
            QuicSniffOutcome::Matched("prefix.example".to_owned())
        );
    }

    #[test]
    fn conflicting_crypto_overlap_is_rejected() {
        let hello = client_hello(&server_name_extension("overlap.example"));
        let mut conflicting = hello.clone();
        conflicting[10] ^= 0xff;
        let mut sniffer = QuicSniffer::new();
        assert_eq!(
            sniffer.ingest(&initial_packet(
                QuicVersion::V1,
                0,
                1,
                &crypto_frame(0, &hello[..20]),
            )),
            QuicSniffOutcome::NeedMoreData
        );
        assert_eq!(
            sniffer.ingest(&initial_packet(
                QuicVersion::V1,
                1,
                1,
                &crypto_frame(10, &conflicting[10..30]),
            )),
            QuicSniffOutcome::NotMatched
        );
    }

    #[test]
    fn ech_suppresses_the_outer_quic_sni() {
        let extensions = [
            server_name_extension("outer.example"),
            tls_extension(0xfe0d, &[0x00, 0xaa, 0xbb]),
        ]
        .concat();
        let packet = initial_packet(
            QuicVersion::V2,
            0,
            1,
            &crypto_frame(0, &client_hello(&extensions)),
        );
        assert_eq!(
            QuicSniffer::new().ingest(&packet),
            QuicSniffOutcome::EchExtensionPresent
        );
    }

    #[test]
    fn malformed_unknown_and_oversize_inputs_fail_open() {
        assert_eq!(
            QuicSniffer::new().ingest(b"not quic"),
            QuicSniffOutcome::NotMatched
        );
        let mut authenticated = initial_packet(
            QuicVersion::V1,
            0,
            1,
            &crypto_frame(0, &client_hello(&server_name_extension("valid.example"))),
        );
        *authenticated.last_mut().unwrap() ^= 1;
        assert_eq!(
            QuicSniffer::new().ingest(&authenticated),
            QuicSniffOutcome::NotMatched
        );
        let empty_at_limit = initial_packet(
            QuicVersion::V1,
            0,
            1,
            &crypto_frame(QUIC_SNIFF_MAX_CRYPTO_BYTES, &[]),
        );
        let mut empty_sniffer = QuicSniffer::new();
        assert_eq!(
            empty_sniffer.ingest(&empty_at_limit),
            QuicSniffOutcome::NeedMoreData
        );
        assert!(empty_sniffer.crypto.is_empty());
        assert!(empty_sniffer.ranges.is_empty());
        let beyond = initial_packet(
            QuicVersion::V1,
            0,
            1,
            &crypto_frame(QUIC_SNIFF_MAX_CRYPTO_BYTES, &[1]),
        );
        assert_eq!(
            QuicSniffer::new().ingest(&beyond),
            QuicSniffOutcome::LimitReached
        );
    }

    #[test]
    fn crypto_range_limit_is_checked_before_committing_the_sixty_fifth_range() {
        let mut sniffer = QuicSniffer::new();
        for index in 0..QUIC_SNIFF_MAX_RANGES {
            let data = if index == 0 { CLIENT_HELLO } else { 0xaa };
            assert_eq!(
                sniffer.ingest(&initial_packet(
                    QuicVersion::V1,
                    index as u64,
                    1,
                    &crypto_frame(index * 2, &[data]),
                )),
                QuicSniffOutcome::NeedMoreData
            );
        }
        let ranges_before = sniffer.ranges.clone();
        let crypto_before = sniffer.crypto.clone();
        assert_eq!(
            sniffer.ingest(&initial_packet(
                QuicVersion::V1,
                QUIC_SNIFF_MAX_RANGES as u64,
                1,
                &crypto_frame(QUIC_SNIFF_MAX_RANGES * 2, &[0xbb]),
            )),
            QuicSniffOutcome::LimitReached
        );
        assert_eq!(sniffer.ranges, ranges_before);
        assert_eq!(sniffer.crypto, crypto_before);
    }

    #[test]
    fn packet_number_reconstruction_handles_truncation_boundaries() {
        assert_eq!(reconstruct_packet_number(Some(255), 0, 1), 256);
        assert_eq!(reconstruct_packet_number(Some(256), 255, 1), 255);
        assert_eq!(reconstruct_packet_number(None, 7, 1), 7);
    }

    #[test]
    fn quic_varint_parser_is_strictly_bounded() {
        for (encoded, expected) in [
            (vec![37], 37),
            (vec![0x7b, 0xbd], 15_293),
            (vec![0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
        ] {
            let mut cursor = 0;
            assert_eq!(read_varint(&encoded, &mut cursor), Some(expected));
            assert_eq!(cursor, encoded.len());
        }
        let mut cursor = 0;
        assert_eq!(read_varint(&[0x40], &mut cursor), None);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn ack_range_limit_counts_the_mandatory_first_range() {
        fn ack_payload(additional_ranges: u64) -> Vec<u8> {
            let mut payload = Vec::new();
            write_varint(0, &mut payload); // Largest Acknowledged
            write_varint(0, &mut payload); // ACK Delay
            write_varint(additional_ranges, &mut payload);
            write_varint(0, &mut payload); // First ACK Range
            for _ in 0..additional_ranges {
                write_varint(0, &mut payload); // Gap
                write_varint(0, &mut payload); // ACK Range
            }
            payload
        }

        let maximum_additional_ranges = QUIC_SNIFF_MAX_ACK_RANGES - 1;
        let accepted = ack_payload(maximum_additional_ranges);
        let mut cursor = 0;
        assert!(skip_ack_frame(
            &accepted,
            &mut cursor,
            false,
            QUIC_SNIFF_MAX_ACK_RANGES,
        ));
        assert_eq!(cursor, accepted.len());

        let rejected = ack_payload(QUIC_SNIFF_MAX_ACK_RANGES);
        let mut cursor = 0;
        assert!(!skip_ack_frame(
            &rejected,
            &mut cursor,
            false,
            QUIC_SNIFF_MAX_ACK_RANGES,
        ));
    }
}
