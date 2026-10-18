//! kcptun packet envelopes. Payload confidentiality/authentication remains SS2022.
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use salsa20::cipher::{KeyIvInit, StreamCipher};
use std::io;
use zeroize::Zeroizing;
const IV: [u8; 16] = [
    167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107,
];
trait EncryptBlock: Send + Sync {
    fn size(&self) -> usize;
    fn encrypt(&self, block: &mut [u8]);
}
struct Cipher<B>(B);
impl<B: BlockCipherEncrypt + Send + Sync> EncryptBlock for Cipher<B> {
    fn size(&self) -> usize {
        B::block_size()
    }
    fn encrypt(&self, data: &mut [u8]) {
        let mut block = Block::<B>::default();
        block.copy_from_slice(data);
        self.0.encrypt_block(&mut block);
        data.copy_from_slice(&block);
    }
}
// The published TEA transformation uses two Feistel half-rounds per cycle.
// kcptun selects 16 half-rounds (8 cycles), rather than standard TEA's 64.
struct Tea(Zeroizing<[u32; 4]>);
impl EncryptBlock for Tea {
    fn size(&self) -> usize {
        8
    }
    fn encrypt(&self, block: &mut [u8]) {
        let mut left = u32::from_be_bytes(block[..4].try_into().unwrap());
        let mut right = u32::from_be_bytes(block[4..8].try_into().unwrap());
        let mut sum = 0u32;
        for _ in 0..8 {
            sum = sum.wrapping_add(0x9e3779b9);
            left = left.wrapping_add(
                (right << 4).wrapping_add(self.0[0])
                    ^ right.wrapping_add(sum)
                    ^ (right >> 5).wrapping_add(self.0[1]),
            );
            right = right.wrapping_add(
                (left << 4).wrapping_add(self.0[2])
                    ^ left.wrapping_add(sum)
                    ^ (left >> 5).wrapping_add(self.0[3]),
            );
        }
        block[..4].copy_from_slice(&left.to_be_bytes());
        block[4..].copy_from_slice(&right.to_be_bytes());
    }
}
enum Mode {
    Null,
    None,
    Cfb(Box<dyn EncryptBlock>),
    Xor(Zeroizing<Vec<u8>>),
    Salsa(Zeroizing<[u8; 32]>),
    Gcm(Box<ring::aead::LessSafeKey>),
}
pub(super) struct PacketCrypt(Mode);
impl PacketCrypt {
    pub(super) fn new(password: &str, kind: &str) -> io::Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        boring::pkcs5::pbkdf2_hmac(
            password.as_bytes(),
            b"kcp-go",
            4096,
            boring::hash::MessageDigest::sha1(),
            key.as_mut(),
        )
        .map_err(io::Error::other)?;
        macro_rules! block {
            ($cipher:ty,$key:expr) => {
                Mode::Cfb(Box::new(Cipher(
                    <$cipher>::new_from_slice($key).map_err(|_| invalid())?,
                )))
            };
        }
        let mode = match kind {
            "null" => Mode::Null,
            "none" => Mode::None,
            "aes" => block!(aes::Aes256, key.as_ref()),
            "aes-128" => block!(aes::Aes128, &key[..16]),
            "aes-192" => block!(aes::Aes192, &key[..24]),
            "twofish" => block!(twofish::Twofish, key.as_ref()),
            "blowfish" => block!(blowfish::Blowfish, key.as_ref()),
            "cast5" => block!(cast5::Cast5, &key[..16]),
            "3des" => block!(des::TdesEde3, &key[..24]),
            "xtea" => block!(xtea::Xtea, &key[..16]),
            "tea" => Mode::Cfb(Box::new(Tea(Zeroizing::new(std::array::from_fn(|i| {
                u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap())
            }))))),
            "salsa20" => Mode::Salsa(key),
            "xor" => {
                let mut table = Zeroizing::new(vec![0; 1500]);
                boring::pkcs5::pbkdf2_hmac(
                    key.as_ref(),
                    b"sH3CIVoF#rWLtJo6",
                    32,
                    boring::hash::MessageDigest::sha1(),
                    &mut table,
                )
                .map_err(io::Error::other)?;
                Mode::Xor(table)
            }
            "aes-128-gcm" => Mode::Gcm(Box::new(ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key[..16])
                    .map_err(|_| invalid())?,
            ))),
            _ => return Err(invalid()),
        };
        Ok(Self(mode))
    }
    pub(super) fn overhead(&self) -> usize {
        match self.0 {
            Mode::Null => 0,
            Mode::Gcm(_) => 28,
            _ => 20,
        }
    }
    pub(super) fn seal(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if packet.len() + self.overhead() > 1500 {
            return Err(invalid());
        }
        if matches!(self.0, Mode::Null) {
            return Ok(packet.to_vec());
        }
        if let Mode::Gcm(key) = &self.0 {
            let mut nonce = [0; 12];
            rand::fill(&mut nonce);
            let mut encrypted = packet.to_vec();
            key.seal_in_place_append_tag(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::empty(),
                &mut encrypted,
            )
            .map_err(|_| invalid())?;
            let mut wire = nonce.to_vec();
            wire.extend(encrypted);
            return Ok(wire);
        }
        let mut wire = vec![0; 20];
        rand::fill(&mut wire[..16]);
        wire[16..20].copy_from_slice(&crc32fast::hash(packet).to_le_bytes());
        wire.extend_from_slice(packet);
        self.transform(&mut wire, false)?;
        Ok(wire)
    }
    pub(super) fn open(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() < self.overhead() || wire.len() > 1500 {
            return None;
        }
        if matches!(self.0, Mode::Null) {
            return Some(wire.to_vec());
        }
        if let Mode::Gcm(key) = &self.0 {
            let nonce = ring::aead::Nonce::assume_unique_for_key(wire[..12].try_into().ok()?);
            let mut data = wire[12..].to_vec();
            let len = key
                .open_in_place(nonce, ring::aead::Aad::empty(), &mut data)
                .ok()?
                .len();
            data.truncate(len);
            return Some(data);
        }
        let mut data = wire.to_vec();
        self.transform(&mut data, true).ok()?;
        let checksum = u32::from_le_bytes(data[16..20].try_into().ok()?);
        if crc32fast::hash(&data[20..]) != checksum {
            return None;
        }
        Some(data.split_off(20))
    }
    fn transform(&self, wire: &mut [u8], decrypt: bool) -> io::Result<()> {
        match &self.0 {
            Mode::None => {}
            Mode::Xor(table) => {
                for (byte, key) in wire.iter_mut().zip(table.iter()) {
                    *byte ^= key;
                }
            }
            Mode::Salsa(key) => {
                let nonce: [u8; 8] = wire[..8].try_into().unwrap();
                let mut cipher = salsa20::Salsa20::new((&**key).into(), (&nonce).into());
                cipher.apply_keystream(&mut wire[8..]);
            }
            Mode::Cfb(cipher) => {
                let size = cipher.size();
                let mut state = IV[..size].to_vec();
                for chunk in wire.chunks_mut(size) {
                    cipher.encrypt(&mut state);
                    let mut ciphertext = [0; 16];
                    if decrypt {
                        ciphertext[..chunk.len()].copy_from_slice(chunk);
                    }
                    for (value, pad) in chunk.iter_mut().zip(&state) {
                        *value ^= pad;
                    }
                    if !decrypt {
                        ciphertext[..chunk.len()].copy_from_slice(chunk);
                    }
                    state[..chunk.len()].copy_from_slice(&ciphertext[..chunk.len()]);
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid kcptun cryptographic envelope",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_ciphers_round_trip_and_envelopes_reject_corruption() {
        for kind in [
            "null",
            "none",
            "tea",
            "xor",
            "aes",
            "aes-128",
            "aes-192",
            "blowfish",
            "twofish",
            "cast5",
            "3des",
            "xtea",
            "salsa20",
            "aes-128-gcm",
        ] {
            let cipher = PacketCrypt::new("synthetic-packet-key", kind).unwrap();
            for size in [24, 31, 32, 33, 511, 1400] {
                let payload = vec![7; size];
                let mut wire = cipher.seal(&payload).unwrap();
                assert_eq!(cipher.open(&wire).unwrap(), payload);
                if kind != "null" {
                    let last = wire.last_mut().unwrap();
                    *last ^= 1;
                    assert!(cipher.open(&wire).is_none());
                }
            }
        }
    }
}
