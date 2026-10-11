//! Mieru v3 wire cryptography, implemented from the public protocol specification.
//! https://github.com/enfein/mieru/blob/v3.38.1/docs/protocol.md
//! This module contains no translated Go implementation.
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use std::{fmt, io, num::NonZeroU32, sync::Arc};
use zeroize::Zeroizing;

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

/// One immutable, physical-carrier key. Both directions share it, with separate nonce state.
/// The dependency's zeroize feature erases its key when the final owner is dropped.
pub(crate) struct Key(XChaCha20Poly1305);

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MieruKey(..)")
    }
}

/// Select the current rounded two-minute epoch once, when creating a physical carrier.
pub(crate) fn derive_key(username: &str, password: &str, unix_secs: u64) -> Key {
    let material = key_material(username, password, unix_secs);
    Key(XChaCha20Poly1305::new_from_slice(material.as_ref()).expect("32-byte Mieru key"))
}

fn key_material(username: &str, password: &str, unix_secs: u64) -> Zeroizing<[u8; 32]> {
    let password_hash: Zeroizing<[u8; 32]> = Zeroizing::new(
        Sha256::new()
            .chain_update(password.as_bytes())
            .chain_update([0])
            .chain_update(username.as_bytes())
            .finalize()
            .into(),
    );
    // Use a wider intermediate; the protocol stores the rounded epoch as a uint64.
    let rounded = ((u128::from(unix_secs) + 60) / 120 * 120) as u64;
    let salt = Sha256::digest(rounded.to_be_bytes());
    let mut material = Zeroizing::new([0; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(64).expect("nonzero Mieru iteration count"),
        &salt,
        password_hash.as_ref(),
        material.as_mut(),
    );
    material
}

/// Apply the authenticated user's lookup hint after generating or transforming the nonce.
/// Randomness and future traffic-pattern policy belong to the physical carrier's creator.
pub(crate) fn make_client_nonce(username: &str, mut random: [u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
    let hint = Sha256::new()
        .chain_update(username.as_bytes())
        .chain_update(&random[..16])
        .finalize();
    random[20..].copy_from_slice(&hint[..4]);
    random
}

/// A single TCP direction; deliberately not Clone so a used nonce cursor cannot be forked.
pub(super) struct ImplicitCipher {
    key: Arc<Key>,
    nonce: [u8; NONCE_LEN],
    used: bool,
    exhausted: bool,
}

impl ImplicitCipher {
    pub(super) fn new(key: Arc<Key>, nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            key,
            nonce,
            used: false,
            exhausted: false,
        }
    }

    fn next_nonce(&mut self) -> io::Result<XNonce> {
        if self.exhausted {
            return Err(io::Error::other("Mieru nonce exhausted"));
        }
        if self.used {
            let mut overflow = true;
            for byte in self.nonce.iter_mut().rev() {
                let (next, carry) = byte.overflowing_add(1);
                *byte = next;
                if !carry {
                    overflow = false;
                    break;
                }
            }
            if overflow {
                self.exhausted = true;
                return Err(io::Error::other("Mieru nonce exhausted"));
            }
        }
        self.used = true;
        Ok(self.nonce.into())
    }

    pub(super) fn seal(&mut self, plaintext: &mut [u8]) -> io::Result<[u8; TAG_LEN]> {
        let nonce = self.next_nonce()?;
        self.key
            .0
            .encrypt_inout_detached(&nonce, b"", plaintext.into())
            .map(Into::into)
            .map_err(|_| io::Error::other("Mieru encryption failed"))
    }

    pub(super) fn open(&mut self, ciphertext: &mut [u8], tag: [u8; TAG_LEN]) -> io::Result<()> {
        let nonce = self.next_nonce()?;
        self.key
            .0
            .decrypt_inout_detached(&nonce, b"", ciphertext.into(), &Tag::from(tag))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mieru authentication failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0, "fixture contains a partial byte");
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid fixture hex"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn protocol_kdf_and_user_hint_vectors() {
        // Independently generated with Python hashlib SHA256/PBKDF2, using protocol inputs.
        assert_eq!(
            &key_material("vole", "fixture-password", 1_700_000_000)[..],
            hex("0f3c9ee5bf9ea6a8cde5563da147adaa7a00dde4e3ee8dc267524f13738ba3c8")
        );
        assert_eq!(
            &key_material("vole", "fixture-password", 59)[..],
            hex("0d03d2861c28e529babee004fa2d8e9c9e1796e73a49dbc260f246cc600b3090")
        );
        assert_eq!(
            &key_material("vole", "fixture-password", 60)[..],
            hex("d04f1135685786b90cf5ecad72803e7c9f359f69e8a16caf8bca58e9113c3d04")
        );
        let nonce = make_client_nonce("vole", std::array::from_fn(|index| index as u8));
        assert_eq!(
            nonce.as_slice(),
            hex("000102030405060708090a0b0c0d0e0f101112135b65f257")
        );
        let debug = format!("{:?}", derive_key("vole", "fixture-password", 60));
        assert_eq!(debug, "MieruKey(..)");
    }

    #[test]
    fn big_endian_nonce_carry_and_exhaustion() {
        let key = Arc::new(derive_key("vole", "fixture-password", 60));
        let mut nonce = [0; NONCE_LEN];
        nonce[22] = 0x12;
        nonce[23] = 0xff;
        let mut cipher = ImplicitCipher::new(key.clone(), nonce);
        assert_eq!(cipher.next_nonce().unwrap().as_slice(), nonce);
        nonce[22] = 0x13;
        nonce[23] = 0;
        assert_eq!(cipher.next_nonce().unwrap().as_slice(), nonce);
        let mut exhausted = ImplicitCipher::new(key, [0xff; NONCE_LEN]);
        exhausted.next_nonce().unwrap();
        assert!(exhausted.next_nonce().is_err());
        assert!(exhausted.next_nonce().is_err());
    }
}
