//! Public RFC5389 XOR-MAPPED-ADDRESS and Hysteria Realm punch wire.
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub(super) fn stun_request(id: [u8; 12]) -> Vec<u8> {
    let mut out = vec![0, 1, 0, 0];
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&id);
    out
}
pub(super) fn stun_response(bytes: &[u8], id: &[u8; 12]) -> Option<SocketAddr> {
    if bytes.len() < 20 || bytes[..2] != [1, 1] || bytes[4..8] != COOKIE || bytes[8..20] != *id {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(bytes[2..4].try_into().ok()?));
    if length % 4 != 0 || 20 + length > bytes.len() {
        return None;
    }
    let mut body = &bytes[20..20 + length];
    while body.len() >= 4 {
        let kind = u16::from_be_bytes(body[..2].try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(body[2..4].try_into().ok()?));
        let padded = (len + 3) & !3;
        if 4 + padded > body.len() {
            return None;
        }
        let value = &body[4..4 + len];
        body = &body[4 + padded..];
        if kind != 0x20 {
            continue;
        }
        if value.len() < 4 {
            return None;
        }
        let port = u16::from_be_bytes(value[2..4].try_into().ok()?) ^ 0x2112;
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&COOKIE);
        key[4..].copy_from_slice(id);
        let ip = match (value[1], value.len()) {
            (1, 8) => {
                let b: [u8; 4] = std::array::from_fn(|n| value[4 + n] ^ key[n]);
                IpAddr::V4(Ipv4Addr::from(b))
            }
            (2, 20) => {
                let b: [u8; 16] = std::array::from_fn(|n| value[4 + n] ^ key[n]);
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return None,
        };
        return (port != 0 && !ip.is_unspecified() && !ip.is_multicast())
            .then_some(SocketAddr::new(ip, port));
    }
    None
}
#[derive(Clone)]
pub(super) struct Metadata {
    pub nonce: [u8; 16],
    pub key: [u8; 32],
}
fn mask(bytes: &mut [u8], salt: &[u8], key: &[u8; 32]) {
    let mut hash = Sha256::new();
    hash.update(key);
    hash.update(salt);
    let hash = hash.finalize();
    for (n, b) in bytes.iter_mut().enumerate() {
        *b ^= hash[n % 32];
    }
}
pub(super) fn encode(kind: u8, meta: &Metadata) -> Vec<u8> {
    let padding = rand::random_range(0..=1024);
    let mut out = vec![0; 8 + 25 + padding];
    rand::fill(out.as_mut_slice());
    out[8..16].copy_from_slice(b"HYRLMv1\0");
    out[16] = kind;
    out[17..33].copy_from_slice(&meta.nonce);
    let (salt, body) = out.split_at_mut(8);
    mask(body, salt, &meta.key);
    out
}
pub(super) fn decode(bytes: &[u8], meta: &Metadata) -> Option<u8> {
    if !(33..=1057).contains(&bytes.len()) {
        return None;
    }
    // Only the fixed header is needed; random padding never allocates.
    let mut body: [u8; 25] = bytes[8..33].try_into().ok()?;
    mask(&mut body, &bytes[..8], &meta.key);
    (body[..8] == *b"HYRLMv1\0" && matches!(body[8], 1 | 2) && body[9..25] == meta.nonce)
        .then_some(body[8])
}
pub(super) fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[usize::from(b >> 4)] as char);
        out.push(H[usize::from(b & 15)] as char);
    }
    out
}
pub(super) fn unhex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (n, b) in value.as_bytes().chunks_exact(2).enumerate() {
        fn digit(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        }
        out[n] = (digit(b[0])? << 4) | digit(b[1])?;
    }
    Some(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn realm_stun_matches_transaction_and_checked_ipv4_ipv6_attributes() {
        let id = [7; 12];
        for address in [
            "192.0.2.10:40000".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:40001".parse().unwrap(),
        ] {
            let mut bytes = stun_request(id);
            bytes[..2].copy_from_slice(&[1, 1]);
            let mut attr = vec![0, 0x20, 0, 0, 0, if address.is_ipv4() { 1 } else { 2 }];
            attr.extend_from_slice(&(address.port() ^ 0x2112).to_be_bytes());
            let ip = match address.ip() {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut key = COOKIE.to_vec();
            key.extend_from_slice(&id);
            for (n, b) in ip.iter().enumerate() {
                attr.push(*b ^ key[n]);
            }
            let len = (attr.len() - 4) as u16;
            attr[2..4].copy_from_slice(&len.to_be_bytes());
            bytes[2..4].copy_from_slice(&(attr.len() as u16).to_be_bytes());
            bytes.extend(attr);
            assert_eq!(stun_response(&bytes, &id), Some(address));
            assert_eq!(stun_response(&bytes, &[8; 12]), None);
            for n in 0..bytes.len() {
                assert_eq!(stun_response(&bytes[..n], &id), None);
            }
        }
    }
    #[test]
    fn realm_punch_has_bounded_padding_and_checks_magic_nonce_key() {
        let meta = Metadata {
            nonce: [3; 16],
            key: [9; 32],
        };
        for kind in [1, 2] {
            let bytes = encode(kind, &meta);
            assert!((33..=1057).contains(&bytes.len()));
            assert_eq!(decode(&bytes, &meta), Some(kind));
            assert_eq!(
                decode(
                    &bytes,
                    &Metadata {
                        nonce: [4; 16],
                        key: [9; 32]
                    }
                ),
                None
            );
            assert_eq!(
                decode(
                    &bytes,
                    &Metadata {
                        nonce: [3; 16],
                        key: [8; 32]
                    }
                ),
                None
            );
        }
    }
}
