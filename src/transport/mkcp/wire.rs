//! Independent mKCP wire adapter, matching the public v2ray/Mihomo protocol.
//! conv is u16 and integers are big-endian: this is not standard KCP wire.
use crate::config::{MkcpHeader, MkcpOptions};
use ring::aead;
use sha2::{Digest, Sha256};
use std::io;

pub(super) const DATA_HEADER: usize = 18;
pub(super) const ACK_HEADER: usize = 17;
pub(super) const CONTROL_HEADER: usize = 16;
pub(super) const ACKS: usize = 128;
pub(super) enum Segment<'a> {
    Data {
        option: u8,
        time: u32,
        number: u32,
        sending_next: u32,
        payload: &'a [u8],
    },
    Ack {
        option: u8,
        window: u32,
        next: u32,
        time: u32,
        numbers: &'a [u8],
    },
    Control {
        command: u8,
        option: u8,
        sending_next: u32,
        receiving_next: u32,
        rto: u32,
    },
}
pub(super) struct Header {
    kind: MkcpHeader,
    sequence: u32,
    identity: u16,
    length: u16,
}
impl Header {
    fn new(kind: MkcpHeader) -> Self {
        Self {
            kind,
            sequence: rand::random(),
            identity: rand::random(),
            length: 17,
        }
    }
    fn write(&mut self, out: &mut [u8]) {
        match self.kind {
            MkcpHeader::None => {}
            MkcpHeader::Srtp => {
                self.sequence = self.sequence.wrapping_add(1);
                out[..2].copy_from_slice(&0xb5e8u16.to_be_bytes());
                out[2..4].copy_from_slice(&(self.sequence as u16).to_be_bytes());
            }
            MkcpHeader::Utp => {
                out[..2].copy_from_slice(&self.identity.to_be_bytes());
                out[2] = 1;
                out[3] = 0;
            }
            MkcpHeader::WechatVideo => {
                self.sequence = self.sequence.wrapping_add(1);
                out[..2].copy_from_slice(&[0xa1, 8]);
                out[2..6].copy_from_slice(&self.sequence.to_be_bytes());
                out[6..].copy_from_slice(&[0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            MkcpHeader::Dtls => {
                out[..3].copy_from_slice(&[23, 254, 253]);
                out[3..5].copy_from_slice(&self.identity.to_be_bytes());
                out[5..7].fill(0);
                out[7..11].copy_from_slice(&self.sequence.to_be_bytes());
                self.sequence = self.sequence.wrapping_add(1);
                out[11..13].copy_from_slice(&self.length.to_be_bytes());
                self.length += 17;
                if self.length > 100 {
                    self.length -= 50;
                }
            }
            MkcpHeader::Wireguard => out.copy_from_slice(&[4, 0, 0, 0]),
        }
    }
}
pub(super) struct Codec {
    header: Header,
    key: Option<aead::LessSafeKey>,
    limit: usize,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid mKCP packet")
}
fn fnv(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}
impl Codec {
    pub fn new(options: &MkcpOptions) -> io::Result<Self> {
        let key = if options.seed.is_empty() {
            None
        } else {
            let hash = Sha256::digest(options.seed.as_bytes());
            Some(aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_128_GCM, &hash[..16]).map_err(|_| invalid())?,
            ))
        };
        Ok(Self {
            header: Header::new(options.header),
            key,
            limit: usize::from(options.mtu),
        })
    }
    pub fn seal(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let header = self.header.kind.size();
        let overhead = header + if self.key.is_some() { 28 } else { 6 };
        if plain
            .len()
            .checked_add(overhead)
            .is_none_or(|size| size > self.limit)
        {
            return Err(invalid());
        }
        let mut output = vec![0u8; header];
        self.header.write(&mut output);
        if let Some(key) = &self.key {
            let nonce: [u8; 12] = rand::random();
            output.extend_from_slice(&nonce);
            let begin = output.len();
            output.extend_from_slice(plain);
            let tag = key
                .seal_in_place_separate_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::empty(),
                    &mut output[begin..],
                )
                .map_err(|_| invalid())?;
            output.extend_from_slice(tag.as_ref());
        } else {
            let begin = output.len();
            output.extend_from_slice(&[0; 4]);
            output.extend_from_slice(&(plain.len() as u16).to_be_bytes());
            output.extend_from_slice(plain);
            let hash = fnv(&output[begin + 4..]);
            output[begin..begin + 4].copy_from_slice(&hash.to_be_bytes());
            for i in begin + 4..output.len() {
                output[i] ^= output[i - 4];
            }
        }
        Ok(output)
    }
    pub fn open(&self, packet: &[u8], receive_limit: usize) -> io::Result<Vec<u8>> {
        let header = self.header.kind.size();
        if packet.len() > receive_limit
            || packet.len() <= header + if self.key.is_some() { 28 } else { 6 }
        {
            return Err(invalid());
        }
        let packet = &packet[header..];
        if let Some(key) = &self.key {
            let nonce: [u8; 12] = packet[..12].try_into().map_err(|_| invalid())?;
            let mut plain = packet[12..].to_vec();
            let size = key
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::empty(),
                    &mut plain,
                )
                .map_err(|_| invalid())?
                .len();
            plain.truncate(size);
            Ok(plain)
        } else {
            let mut plain = packet.to_vec();
            for i in (4..plain.len()).rev() {
                plain[i] ^= plain[i - 4];
            }
            if u32::from_be_bytes(plain[..4].try_into().unwrap()) != fnv(&plain[4..])
                || usize::from(u16::from_be_bytes(plain[4..6].try_into().unwrap()))
                    != plain.len() - 6
            {
                return Err(invalid());
            }
            plain.drain(..6);
            Ok(plain)
        }
    }
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
pub(super) fn parse(bytes: &[u8], conv: u16) -> Option<(Segment<'_>, usize)> {
    if bytes.len() < 4
        || u16::from_be_bytes(bytes[..2].try_into().ok()?) != conv
        || bytes[3] & !1 != 0
    {
        return None;
    }
    let option = bytes[3];
    Some(match bytes[2] {
        1 => {
            if bytes.len() < DATA_HEADER {
                return None;
            }
            let size = usize::from(u16::from_be_bytes(bytes[16..18].try_into().ok()?));
            let payload = bytes.get(DATA_HEADER..DATA_HEADER + size)?;
            (
                Segment::Data {
                    option,
                    time: u32_at(bytes, 4),
                    number: u32_at(bytes, 8),
                    sending_next: u32_at(bytes, 12),
                    payload,
                },
                DATA_HEADER + size,
            )
        }
        0 => {
            if bytes.len() < ACK_HEADER {
                return None;
            }
            let count = usize::from(bytes[16]);
            let numbers = bytes.get(ACK_HEADER..ACK_HEADER + 4 * count)?;
            (
                Segment::Ack {
                    option,
                    window: u32_at(bytes, 4),
                    next: u32_at(bytes, 8),
                    time: u32_at(bytes, 12),
                    numbers,
                },
                ACK_HEADER + 4 * count,
            )
        }
        command @ (2 | 3) => {
            if bytes.len() < CONTROL_HEADER {
                return None;
            }
            (
                Segment::Control {
                    command,
                    option,
                    sending_next: u32_at(bytes, 4),
                    receiving_next: u32_at(bytes, 8),
                    rto: u32_at(bytes, 12),
                },
                CONTROL_HEADER,
            )
        }
        _ => return None,
    })
}
pub(super) fn data(
    conv: u16,
    option: u8,
    time: u32,
    number: u32,
    sending_next: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_HEADER + payload.len());
    out.extend_from_slice(&conv.to_be_bytes());
    out.extend_from_slice(&[1, option]);
    out.extend_from_slice(&time.to_be_bytes());
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&sending_next.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
pub(super) fn ack(
    conv: u16,
    option: u8,
    window: u32,
    next: u32,
    time: u32,
    numbers: &[u32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACK_HEADER + 4 * numbers.len());
    out.extend_from_slice(&conv.to_be_bytes());
    out.extend_from_slice(&[0, option]);
    out.extend_from_slice(&window.to_be_bytes());
    out.extend_from_slice(&next.to_be_bytes());
    out.extend_from_slice(&time.to_be_bytes());
    out.push(numbers.len() as u8);
    for number in numbers {
        out.extend_from_slice(&number.to_be_bytes());
    }
    out
}
pub(super) fn control(
    conv: u16,
    command: u8,
    option: u8,
    sending_next: u32,
    receiving_next: u32,
    rto: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTROL_HEADER);
    out.extend_from_slice(&conv.to_be_bytes());
    out.extend_from_slice(&[command, option]);
    out.extend_from_slice(&sending_next.to_be_bytes());
    out.extend_from_slice(&receiving_next.to_be_bytes());
    out.extend_from_slice(&rto.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mkcp_simple_authenticator_has_a_fixed_public_wire_vector() {
        // conv=0x1234, data, timestamp=0x10203040, SN=7, sendingNext=3,
        // body="abc"; BE length then FNV-1a and four-byte XOR chaining.
        let plain = data(0x1234, 0, 0x10203040, 7, 3, b"abc");
        let expected = b"\x01\x4b\x8e\xbc\x01\x5e\x9c\x88\x00\x5e\x8c\xa8\x30\x1e\x8c\xa8\x30\x19\x8c\xa8\x30\x1a\x8c\xab\x51\x78\xef";
        let mut codec = Codec::new(&MkcpOptions::default()).unwrap();
        assert_eq!(codec.seal(&plain).unwrap(), expected);
        assert_eq!(codec.open(expected, 1350).unwrap(), plain);
    }
    #[test]
    fn mkcp_wire_distinguishes_seed_and_preserves_all_headers() {
        for header in [
            MkcpHeader::None,
            MkcpHeader::Srtp,
            MkcpHeader::Utp,
            MkcpHeader::WechatVideo,
            MkcpHeader::Dtls,
            MkcpHeader::Wireguard,
        ] {
            for seed in ["", "seed"] {
                let options = MkcpOptions {
                    header,
                    seed: seed.into(),
                    ..Default::default()
                };
                let mut codec = Codec::new(&options).unwrap();
                let plain = data(0x1234, 0, 7, 8, 9, b"payload");
                let mut packet = codec.seal(&plain).unwrap();
                assert_eq!(
                    codec
                        .open(&packet, usize::from(options.peer_receive_limit()))
                        .unwrap(),
                    plain
                );
                let last = packet.len() - 1;
                packet[last] ^= 1;
                assert!(
                    codec
                        .open(&packet, usize::from(options.peer_receive_limit()))
                        .is_err()
                );
            }
        }
    }
    #[test]
    fn mkcp_segments_are_checked_before_allocating_payloads() {
        let plain = data(0x1234, 1, 7, 8, 9, b"payload");
        assert_eq!(&plain[..4], &[0x12, 0x34, 1, 1]);
        for end in 0..plain.len() {
            assert!(parse(&plain[..end], 0x1234).is_none());
        }
        assert!(parse(&plain, 0x1235).is_none());
        assert!(matches!(
            parse(&plain, 0x1234),
            Some((
                Segment::Data {
                    payload: b"payload",
                    ..
                },
                25
            ))
        ));
        let numbers = [1, 2, 100];
        assert!(matches!(
            parse(&ack(1, 0, 20, 3, 9, &numbers), 1),
            Some((Segment::Ack { .. }, 29))
        ));
    }
}
