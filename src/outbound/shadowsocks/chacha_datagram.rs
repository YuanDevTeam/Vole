//! SIP022 ChaCha UDP response decoding over the official packet cipher.
//!
//! shadowsocks 1.25's ProxySocket caches a cipher under the first encrypted eight
//! message bytes before authentication. For ChaCha those bytes are random per
//! packet, while the cipher uses only the PSK. Keep one cipher per association
//! instead of populating that thread-local cache with each received packet.
use shadowsocks::{
    ServerConfig,
    crypto::{CipherKind, v2::udp::ChaCha20Poly1305Cipher},
    relay::{socks5::Address, udprelay::options::UdpSocketControlData},
};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

const NONCE: usize = 24;
const TAG: usize = 16;
// Server session / packet / role / timestamp / client session / padding size.
const RESPONSE_HEADER: usize = 8 + 8 + 1 + 8 + 8 + 2;

pub(super) struct Decoder(ChaCha20Poly1305Cipher);

impl Decoder {
    pub(super) fn new(config: &ServerConfig) -> Option<Self> {
        (config.method() == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
            .then(|| Self(ChaCha20Poly1305Cipher::new(config.key())))
    }

    pub(super) fn decode(
        &self,
        packet: &mut [u8],
    ) -> io::Result<(usize, Address, UdpSocketControlData)> {
        if packet.len() < NONCE + RESPONSE_HEADER + TAG {
            return Err(invalid());
        }
        let (nonce, message) = packet.split_at_mut(NONCE);
        if !self.0.decrypt_packet(nonce, message) {
            return Err(invalid());
        }
        let message = &message[..message.len() - TAG];
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
        let start = NONCE + RESPONSE_HEADER + padding + cursor.position() as usize;
        let end = packet.len() - TAG;
        let size = end.checked_sub(start).ok_or_else(invalid)?;
        packet.copy_within(start..end, 0);
        Ok((size, source, control))
    }
}

fn timestamp() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| invalid())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Shadowsocks UDP packet")
}
