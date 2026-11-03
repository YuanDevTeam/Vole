//! SIP022 UDP packet-layer adaptation over official public packet ciphers.
//!
//! Field layout and EIH were checked against shadowsocks-rust 1.25.0 (MIT)
//! and the Shadowsocks 2022 specifications. Crypto implementations remain in
//! shadowsocks::crypto::v2::udp; this adapter owns framing and bounded lifetimes.
use super::datagram::MAX_WIRE_PACKET;
use aes::{
    Aes128, Aes256, Block,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use bytes::{BufMut, BytesMut};
use shadowsocks::{
    ServerConfig,
    context::Context,
    crypto::{CipherKind, v2::udp::UdpCipher},
    relay::{socks5::Address, udprelay::options::UdpSocketControlData},
};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

const TAG: usize = 16;
const ID_PAIR: usize = 16;
const RESPONSE_HEADER: usize = 35;
const MAX_PADDING: usize = 900;

pub(super) fn is_chacha(config: &ServerConfig) -> bool {
    config.method() == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
}

fn nonce_len(config: &ServerConfig) -> usize {
    if is_chacha(config) { 24 } else { 0 }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Shadowsocks UDP packet")
}

fn timestamp() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| invalid())
}

fn aes_header(method: CipherKind, key: &[u8], bytes: &mut [u8], decrypt: bool) -> io::Result<()> {
    let block = <&mut Block>::try_from(bytes).map_err(|_| invalid())?;
    match method {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
            let aes = Aes128::new_from_slice(key).map_err(|_| invalid())?;
            if decrypt {
                aes.decrypt_block(block);
            } else {
                aes.encrypt_block(block);
            }
        }
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            let aes = Aes256::new_from_slice(key).map_err(|_| invalid())?;
            if decrypt {
                aes.decrypt_block(block);
            } else {
                aes.encrypt_block(block);
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

pub(super) fn encode_request(
    context: &Context,
    config: &ServerConfig,
    cipher: &UdpCipher,
    target: &Address,
    control: &UdpSocketControlData,
    payload: &[u8],
) -> io::Result<BytesMut> {
    let nonce = nonce_len(config);
    let identities = config.identity_keys();
    let eih = if is_chacha(config) {
        0
    } else {
        identities.len().checked_mul(16).ok_or_else(invalid)?
    };
    // Preserve the existing maximum-padding check for empty requests. All
    // possible padding bytes are initialized before the wire buffer is cleared.
    let padding_limit = if payload.is_empty() { MAX_PADDING } else { 0 };
    let maximum = nonce
        .checked_add(43)
        .and_then(|n| n.checked_add(eih))
        .and_then(|n| n.checked_add(target.serialized_len()))
        .and_then(|n| n.checked_add(payload.len()))
        .and_then(|n| n.checked_add(padding_limit))
        .filter(|n| *n <= MAX_WIRE_PACKET)
        .ok_or_else(invalid)?;
    let padding = if payload.is_empty() {
        rand::random_range(0..=MAX_PADDING)
    } else {
        0
    };
    let mut wire = if payload.is_empty() {
        let mut initialized = BytesMut::zeroed(maximum);
        rand::fill(&mut initialized[..]);
        initialized.clear();
        initialized
    } else {
        BytesMut::with_capacity(maximum)
    };
    if nonce != 0 {
        wire.resize(nonce, 0);
        context.generate_nonce(config.method(), &mut wire[..nonce], false);
    }
    let mut ids = [0u8; ID_PAIR];
    ids[..8].copy_from_slice(&control.client_session_id.to_be_bytes());
    ids[8..].copy_from_slice(&control.packet_id.to_be_bytes());
    wire.extend_from_slice(&ids);
    if eih != 0 {
        for (index, identity) in identities.iter().enumerate() {
            let next = identities
                .get(index + 1)
                .map_or(config.key(), |key| key.as_ref());
            let digest = blake3::hash(next);
            let mut block = ids;
            for (byte, hash) in block.iter_mut().zip(&digest.as_bytes()[..16]) {
                *byte ^= *hash;
            }
            aes_header(config.method(), identity, &mut block, false)?;
            wire.extend_from_slice(&block);
        }
    }
    wire.put_u8(0);
    wire.put_u64(timestamp()?);
    wire.put_u16(padding as u16);
    let start = wire.len();
    wire.resize(start + padding, 0);
    rand::fill(&mut wire[start..]);
    target.write_to_buf(&mut wire);
    wire.extend_from_slice(payload);
    wire.resize(wire.len() + TAG, 0);
    if nonce != 0 {
        let (nonce, message) = wire.split_at_mut(nonce);
        cipher.encrypt_packet(nonce, message);
    } else {
        cipher.encrypt_packet(&ids[4..], &mut wire[ID_PAIR + eih..]);
        let header_key = identities.first().map_or(config.key(), |key| key.as_ref());
        aes_header(config.method(), header_key, &mut wire[..ID_PAIR], false)?;
    }
    if wire.len() > MAX_WIRE_PACKET {
        return Err(invalid());
    }
    Ok(wire)
}

// AES's visible header supplies only a tentative session ID. It is NOT an
// authenticated cache key: callers may use a temporary cipher, then promote it
// only after every packet/control/address/replay check succeeds.
pub(super) fn prepare_response(
    config: &ServerConfig,
    packet: &mut [u8],
) -> io::Result<Option<u64>> {
    if packet.len() < nonce_len(config) + RESPONSE_HEADER + TAG {
        return Err(invalid());
    }
    if is_chacha(config) {
        return Ok(None);
    }
    aes_header(config.method(), config.key(), &mut packet[..ID_PAIR], true)?;
    Ok(Some(u64::from_be_bytes(packet[..8].try_into().unwrap())))
}

pub(super) fn decode_response(
    config: &ServerConfig,
    cipher: &UdpCipher,
    packet: &mut [u8],
) -> io::Result<(usize, Address, UdpSocketControlData)> {
    let nonce = nonce_len(config);
    if packet.len() < nonce + RESPONSE_HEADER + TAG {
        return Err(invalid());
    }
    let authenticated = if nonce != 0 {
        let (nonce, message) = packet.split_at_mut(nonce);
        cipher.decrypt_packet(nonce, message)
    } else {
        let (header, message) = packet.split_at_mut(ID_PAIR);
        cipher.decrypt_packet(&header[4..], message)
    };
    if !authenticated {
        return Err(invalid());
    }
    let message = &packet[nonce..packet.len() - TAG];
    if message[16] != 1 {
        return Err(invalid());
    }
    let time = u64::from_be_bytes(message[17..25].try_into().unwrap());
    if timestamp()?.abs_diff(time) > 30 {
        return Err(invalid());
    }
    let padding = usize::from(u16::from_be_bytes(message[33..35].try_into().unwrap()));
    let address = message
        .get(RESPONSE_HEADER + padding..)
        .ok_or_else(invalid)?;
    let mut cursor = io::Cursor::new(address);
    let source = Address::read_cursor(&mut cursor).map_err(|_| invalid())?;
    let mut control = UdpSocketControlData::default();
    control.server_session_id = u64::from_be_bytes(message[..8].try_into().unwrap());
    control.packet_id = u64::from_be_bytes(message[8..16].try_into().unwrap());
    control.client_session_id = u64::from_be_bytes(message[25..33].try_into().unwrap());
    let start = nonce + RESPONSE_HEADER + padding + cursor.position() as usize;
    let end = packet.len() - TAG;
    let size = end.checked_sub(start).ok_or_else(invalid)?;
    packet.copy_within(start..end, 0);
    Ok((size, source, control))
}
