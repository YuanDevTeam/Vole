//! VMess's nested-HMAC KDF composes SHA-256; this is not HKDF or a sequence
//! of ordinary HMAC digests. The path entries select nested hash functions.
use std::io;

use md5::Md5;
use ring::{aead, rand::SecureRandom};
use sha2::{Digest, Sha256};

pub(super) fn error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid VMess authentication")
}

pub(super) fn random(output: &mut [u8]) -> io::Result<()> {
    ring::rand::SystemRandom::new()
        .fill(output)
        .map_err(|_| io::Error::other("VMess entropy unavailable"))
}

pub(super) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    fn hash(keys: &[&[u8]], input: &[u8]) -> [u8; 32] {
        let Some((key, parents)) = keys.split_last() else {
            return Sha256::digest(input).into();
        };
        let mut pad = [0; 64];
        if key.len() > 64 {
            pad[..32].copy_from_slice(&hash(parents, key));
        } else {
            pad[..key.len()].copy_from_slice(key);
        }
        let mut inner = Vec::with_capacity(64 + input.len());
        inner.extend(pad.iter().map(|byte| byte ^ 0x36));
        inner.extend_from_slice(input);
        let inner = hash(parents, &inner);
        let mut outer = [0; 96];
        for (out, byte) in outer[..64].iter_mut().zip(pad) {
            *out = byte ^ 0x5c;
        }
        outer[64..].copy_from_slice(&inner);
        hash(parents, &outer)
    }
    let mut keys = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF".as_slice());
    keys.extend_from_slice(path);
    hash(&keys, key)
}

pub(super) fn aead_key(cipher: super::BodyCipher, key: &[u8; 16]) -> aead::LessSafeKey {
    let (algorithm, material) = match cipher {
        super::BodyCipher::Chacha20Poly1305 => {
            let first = Md5::digest(key);
            let second = Md5::digest(first);
            (
                &aead::CHACHA20_POLY1305,
                [first.as_slice(), second.as_slice()].concat(),
            )
        }
        _ => (&aead::AES_128_GCM, key.to_vec()),
    };
    aead::LessSafeKey::new(
        aead::UnboundKey::new(algorithm, &material).expect("fixed AEAD key length"),
    )
}

pub(super) fn seal(
    key: &aead::LessSafeKey,
    nonce: [u8; 12],
    aad: &[u8],
    data: &mut Vec<u8>,
) -> io::Result<()> {
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        data,
    )
    .map_err(|_| error())
}

pub(super) fn open<'a>(
    key: &aead::LessSafeKey,
    nonce: [u8; 12],
    aad: &[u8],
    data: &'a mut [u8],
) -> io::Result<&'a mut [u8]> {
    key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        data,
    )
    .map_err(|_| error())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independently_published_nested_hmac_vectors() {
        assert_eq!(
            kdf(b"test", &[b"AES Auth ID Encryption"]),
            [
                149, 109, 253, 20, 158, 39, 112, 199, 28, 74, 3, 106, 99, 8, 234, 59, 64, 172, 126,
                5, 155, 28, 59, 21, 220, 196, 241, 54, 138, 5, 71, 107
            ]
        );
        assert_eq!(
            kdf(
                b"test",
                &[
                    b"AEAD Resp Header Len Key",
                    b"AEAD Resp Header Len IV",
                    b"AEAD Resp Header Key"
                ]
            ),
            [
                243, 80, 193, 249, 151, 10, 93, 168, 117, 239, 214, 89, 161, 130, 122, 81, 238,
                177, 51, 113, 21, 74, 73, 212, 199, 41, 75, 155, 49, 55, 217, 226
            ]
        );
    }
}
