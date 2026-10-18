//! Passive, bounded HTTP/2 authority extraction; bytes are never consumed here.
use super::{ParseOutcome, TCP_SNIFF_MAX_BYTES, normalize_host_header};

pub(super) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAME: usize = 16_384;
const MAX_HEADERS: usize = 128;

pub(super) fn sniff(input: &[u8]) -> ParseOutcome {
    let mut cursor = PREFACE.len();
    let mut first = true;
    let mut header_stream = None;
    let mut block = Vec::new();
    for _ in 0..MAX_HEADERS {
        let Some(header) = input.get(cursor..cursor + 9) else {
            return ParseOutcome::NeedMoreData;
        };
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        let kind = header[3];
        let flags = header[4];
        let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
        if length > MAX_FRAME || (first && (kind != 4 || flags & 1 != 0)) {
            return ParseOutcome::NotMatched;
        }
        if kind == 4 && (stream != 0 || (flags & 1 != 0 && length != 0) || length % 6 != 0) {
            return ParseOutcome::NotMatched;
        }
        if let Some(active) = header_stream {
            if kind != 9 || stream != active {
                return ParseOutcome::NotMatched;
            }
        } else if kind == 9 || (kind == 1 && (stream == 0 || stream % 2 == 0)) {
            return ParseOutcome::NotMatched;
        }
        cursor += 9;
        if cursor + length > TCP_SNIFF_MAX_BYTES {
            return ParseOutcome::NotMatched;
        }
        let Some(payload) = input.get(cursor..cursor + length) else {
            return ParseOutcome::NeedMoreData;
        };
        first = false;
        cursor += length;
        if header_stream.is_none() && kind != 1 {
            continue;
        }
        header_stream = Some(stream);
        let mut start = 0;
        let mut end = payload.len();
        if kind == 1 {
            if flags & 8 != 0 {
                let Some(padding) = payload.first().copied() else {
                    return ParseOutcome::NotMatched;
                };
                start = 1;
                let Some(unpadded) = end.checked_sub(usize::from(padding)) else {
                    return ParseOutcome::NotMatched;
                };
                end = unpadded;
            }
            if flags & 0x20 != 0 {
                start += 5;
            }
        }
        if start > end || block.len() + end - start > TCP_SNIFF_MAX_BYTES {
            return ParseOutcome::NotMatched;
        }
        block.extend_from_slice(&payload[start..end]);
        if flags & 4 != 0 {
            return authority(block);
        }
    }
    ParseOutcome::NotMatched
}

fn authority(mut block: Vec<u8>) -> ParseOutcome {
    let mut decoder = httlib_hpack::Decoder::with_dynamic_size(4_096);
    let mut field = Vec::with_capacity(1);
    let mut authority = None;
    let mut host = None;
    let mut decoded = 0usize;
    for _ in 0..MAX_HEADERS {
        if block.is_empty() {
            return authority
                .or(host)
                .map_or(ParseOutcome::NotMatched, ParseOutcome::Matched);
        }
        // The official codec assumes that literal strings and integer
        // continuations are present. Validate their complete encoded boundaries
        // before handing it untrusted bytes; malformed sniffing must fail open.
        if instruction_length(&block).is_none() {
            return ParseOutcome::NotMatched;
        }
        let before = block.len();
        if decoder.decode_exact(&mut block, &mut field).is_err() || block.len() == before {
            return ParseOutcome::NotMatched;
        }
        if let Some((name, value, _)) = field.pop() {
            decoded = decoded
                .saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(32);
            if decoded > TCP_SNIFF_MAX_BYTES {
                return ParseOutcome::NotMatched;
            }
            let slot = match name.as_slice() {
                b":authority" => &mut authority,
                b"host" => &mut host,
                _ => continue,
            };
            if slot.is_some() {
                return ParseOutcome::NotMatched;
            }
            let Some(value) = normalize_host_header(&value) else {
                return ParseOutcome::NotMatched;
            };
            *slot = Some(value);
        }
    }
    ParseOutcome::NotMatched
}

fn instruction_length(bytes: &[u8]) -> Option<usize> {
    let first = *bytes.first()?;
    if first & 0x80 != 0 {
        return integer(bytes, 7).map(|(_, length)| length);
    }
    if first & 0xe0 == 0x20 {
        return integer(bytes, 5).map(|(_, length)| length);
    }
    let (index, mut cursor) = integer(bytes, if first & 0x40 != 0 { 6 } else { 4 })?;
    if index == 0 {
        cursor += string_length(bytes.get(cursor..)?)?;
    }
    cursor += string_length(bytes.get(cursor..)?)?;
    Some(cursor)
}

fn integer(bytes: &[u8], prefix: u8) -> Option<(u32, usize)> {
    let mask = (1u32 << prefix) - 1;
    let mut value = u32::from(*bytes.first()?) & mask;
    if value < mask {
        return Some((value, 1));
    }
    for cursor in 1..5 {
        let byte = *bytes.get(cursor)?;
        value = value.checked_add(u32::from(byte & 0x7f).checked_shl((cursor as u32 - 1) * 7)?)?;
        if byte & 0x80 == 0 {
            return Some((value, cursor + 1));
        }
    }
    None
}

fn string_length(bytes: &[u8]) -> Option<usize> {
    let (length, prefix) = integer(bytes, 7)?;
    let total = prefix.checked_add(length as usize)?;
    (total <= bytes.len()).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        value.extend_from_slice(&[kind, flags]);
        value.extend_from_slice(&stream.to_be_bytes());
        value.extend_from_slice(payload);
        value
    }

    fn request(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frame(4, 0, 0, &[]));
        for frame in frames {
            bytes.extend(frame);
        }
        bytes
    }

    // RFC 7541 C.4.1: Huffman-encoded www.example.com, indexed :authority.
    const AUTHORITY: &[u8] = &[
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];

    #[test]
    fn h2_sniff_reassembles_huffman_authority_and_rejects_interleaving() {
        let good = request(&[
            frame(1, 0, 1, &AUTHORITY[..6]),
            frame(9, 4, 1, &AUTHORITY[6..]),
        ]);
        assert_eq!(
            sniff(&good),
            ParseOutcome::Matched("www.example.com".into())
        );
        for length in PREFACE.len()..good.len() {
            assert_eq!(sniff(&good[..length]), ParseOutcome::NeedMoreData);
        }
        let interleaved = request(&[
            frame(1, 0, 1, &AUTHORITY[..6]),
            frame(4, 0, 0, &[]),
            frame(9, 4, 1, &AUTHORITY[6..]),
        ]);
        assert_eq!(sniff(&interleaved), ParseOutcome::NotMatched);
        let wrong_stream = request(&[
            frame(1, 0, 1, &AUTHORITY[..6]),
            frame(9, 4, 3, &AUTHORITY[6..]),
        ]);
        assert_eq!(sniff(&wrong_stream), ParseOutcome::NotMatched);
    }

    #[test]
    fn h2_sniff_rejects_ambiguous_or_oversized_headers_before_large_payloads() {
        let mut duplicate = AUTHORITY.to_vec();
        duplicate.push(0xbe); // dynamic-table index 62 repeats :authority.
        assert_eq!(
            sniff(&request(&[frame(1, 4, 1, &duplicate)])),
            ParseOutcome::NotMatched
        );
        // Table-size update to 4097 exceeds the initial peer table budget.
        assert_eq!(authority(vec![0x3f, 0xe2, 0x1f]), ParseOutcome::NotMatched);
        let mut oversized = request(&[]);
        oversized.extend_from_slice(&[0, 0x40, 1, 1, 4, 0, 0, 0, 1]);
        assert_eq!(sniff(&oversized), ParseOutcome::NotMatched);
        let mut padded = vec![4];
        padded.extend(AUTHORITY);
        padded.extend_from_slice(&[0; 4]);
        assert_eq!(
            sniff(&request(&[frame(1, 12, 1, &padded)])),
            ParseOutcome::Matched("www.example.com".into())
        );
    }

    #[test]
    fn h2_sniff_checks_truncated_literals_and_integers_before_the_codec() {
        for first in 0..=255 {
            let _ = authority(vec![first]);
            let _ = authority(vec![first, 0xff]);
        }
        for malformed in [
            vec![0x00],
            vec![0x40],
            vec![0x00, 0x01, b'x'],
            vec![0x00, 0x01, b'x', 0xff],
            vec![0xff],
            vec![0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert_eq!(authority(malformed), ParseOutcome::NotMatched);
        }
        for length in 1..AUTHORITY.len() {
            assert_eq!(
                authority(AUTHORITY[..length].to_vec()),
                ParseOutcome::NotMatched
            );
        }
    }

    #[tokio::test]
    async fn h2_sniff_replays_the_exact_preface_and_frames() {
        use tokio::io::AsyncWriteExt as _;
        let bytes = request(&[frame(1, 4, 1, AUTHORITY)]);
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        sender.write_all(&bytes).await.unwrap();
        let mut parser = super::super::TcpSniffer::new(super::super::SniffProtocol::Http);
        assert!(matches!(
            parser.sniff(&mut receiver).await.unwrap(),
            super::super::SniffOutcome::Matched { domain, .. } if domain == "www.example.com"
        ));
        assert_eq!(parser.into_buffered(), bytes);
    }
}
