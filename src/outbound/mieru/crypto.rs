//! Mieru v3 wire cryptography, implemented from the public protocol specification.
//! https://github.com/enfein/mieru/blob/v3.38.1/docs/protocol.md
//! This module contains no translated Go implementation.
use boring::aead::{AeadCtx, Algorithm};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use std::{fmt, io, num::NonZeroU32, sync::Arc};
use zeroize::Zeroizing;

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

/// One immutable, physical-carrier key. Both directions share it, with separate nonce state.
/// The dependency's zeroize feature erases its key when the final owner is dropped.
pub(crate) struct Key(XChaCha20Poly1305);

impl Key {
    fn seal(&self, nonce: &XNonce, plaintext: &mut [u8]) -> io::Result<[u8; TAG_LEN]> {
        self.0
            .encrypt_inout_detached(nonce, b"", plaintext.into())
            .map(Into::into)
            .map_err(|_| io::Error::other("Mieru encryption failed"))
    }

    fn open(&self, nonce: &XNonce, ciphertext: &mut [u8], tag: [u8; TAG_LEN]) -> io::Result<()> {
        self.0
            .decrypt_inout_detached(nonce, b"", ciphertext.into(), &Tag::from(tag))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Mieru authentication failed"))
    }
}

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

/// Derive one UDP physical-carrier key; the temporary material is erased after
/// the two independently owned packet ciphers have copied it during setup.
pub(super) fn derive_packet_key(
    username: &str,
    password: &str,
    unix_secs: u64,
) -> Zeroizing<[u8; 32]> {
    key_material(username, password, unix_secs)
}

/// Stateless UDP encryption with an explicit nonce and a setup-selected backend.
/// Backend selection is independent of low-entropy wire encoding.
pub(super) enum PacketCipher {
    Native(AeadCtx),
    Rust(Key),
}

impl PacketCipher {
    pub(super) fn new(key: &[u8; 32], low_entropy: bool) -> io::Result<Self> {
        if low_entropy {
            Ok(Self::Rust(Key(XChaCha20Poly1305::new(&(*key).into()))))
        } else {
            AeadCtx::new(&Algorithm::xchacha20_poly1305(), key, TAG_LEN)
                .map(Self::Native)
                .map_err(io::Error::other)
        }
    }

    pub(super) fn seal(
        &mut self,
        nonce: [u8; NONCE_LEN],
        plaintext: &mut [u8],
    ) -> io::Result<[u8; TAG_LEN]> {
        match self {
            Self::Rust(key) => key.seal(&nonce.into(), plaintext),
            Self::Native(context) => {
                let mut tag = [0; TAG_LEN];
                context
                    .seal_in_place_mut(&nonce, plaintext, &mut tag, b"")
                    .map_err(|_| io::Error::other("Mieru encryption failed"))?;
                Ok(tag)
            }
        }
    }

    pub(super) fn open(
        &mut self,
        nonce: [u8; NONCE_LEN],
        ciphertext: &mut [u8],
        tag: [u8; TAG_LEN],
    ) -> io::Result<()> {
        match self {
            Self::Rust(key) => key.open(&nonce.into(), ciphertext, tag),
            Self::Native(context) => context
                .open_in_place_mut(&nonce, ciphertext, &tag, b"")
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Mieru authentication failed")
                }),
        }
    }
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
        self.key.seal(&nonce, plaintext)
    }

    pub(super) fn open(&mut self, ciphertext: &mut [u8], tag: [u8; TAG_LEN]) -> io::Result<()> {
        let nonce = self.next_nonce()?;
        self.key.open(&nonce, ciphertext, tag)
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
    fn udp_native_matches_reference_wire_and_rejects_bad_tags() {
        use super::super::wire::{
            DataKind, DataMetadata, METADATA_LEN, Metadata, PACKET_HEADER_LEN, PacketDecoder,
            PacketEncoder, Padding, SessionKind, SessionMetadata,
        };
        use bytes::Bytes;

        const TIME: u64 = 1_700_000_000;
        let material = derive_packet_key("vole", "fixture-password", TIME);
        let reference = derive_key("vole", "fixture-password", TIME);
        for low_entropy in [false, true] {
            let mut encoder = PacketEncoder::new(&material, low_entropy).unwrap();
            let mut decoder = PacketDecoder::new(&material, low_entropy).unwrap();
            for nonce in [[0; NONCE_LEN], [0xff; NONCE_LEN]] {
                for payload in [b"".as_slice(), b"native/reference UDP body".as_slice()] {
                    let metadata = if payload.is_empty() {
                        Metadata::Session(SessionMetadata {
                            kind: SessionKind::OpenResponse,
                            session_id: 7,
                            sequence: 0,
                            status: 0,
                        })
                    } else {
                        Metadata::Data(DataMetadata {
                            kind: DataKind::ServerData,
                            session_id: 7,
                            sequence: 1,
                            unack_sequence: 2,
                            window: 16,
                            fragment: 0,
                        })
                    };
                    let mut native_wire = Vec::new();
                    encoder
                        .encode_frame(
                            metadata,
                            payload,
                            Padding::default(),
                            nonce,
                            TIME,
                            &mut native_wire,
                        )
                        .unwrap();
                    assert_eq!(
                        native_wire.len(),
                        PACKET_HEADER_LEN
                            + payload.len()
                            + if payload.is_empty() { 0 } else { TAG_LEN }
                    );
                    let mut plain_header: [u8; METADATA_LEN] = native_wire
                        [NONCE_LEN..NONCE_LEN + METADATA_LEN]
                        .try_into()
                        .unwrap();
                    reference
                        .open(
                            &nonce.into(),
                            &mut plain_header,
                            native_wire[NONCE_LEN + METADATA_LEN..PACKET_HEADER_LEN]
                                .try_into()
                                .unwrap(),
                        )
                        .unwrap();
                    let header_tag = reference.seal(&nonce.into(), &mut plain_header).unwrap();
                    let mut reference_wire = nonce.to_vec();
                    reference_wire.extend_from_slice(&plain_header);
                    reference_wire.extend_from_slice(&header_tag);
                    if !payload.is_empty() {
                        let mut body = payload.to_vec();
                        let body_tag = reference.seal(&nonce.into(), &mut body).unwrap();
                        reference_wire.extend_from_slice(&body);
                        reference_wire.extend_from_slice(&body_tag);
                    }
                    assert_eq!(native_wire, reference_wire);
                    let received = decoder
                        .decode_frame(Bytes::from(reference_wire.clone()), TIME)
                        .unwrap();
                    assert_eq!(received.metadata, metadata);
                    assert_eq!(received.payload.as_ref(), payload);

                    let mut bad_tag = reference_wire.clone();
                    bad_tag[PACKET_HEADER_LEN - 1] ^= 1;
                    assert_eq!(
                        decoder
                            .decode_frame(Bytes::from(bad_tag), TIME)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::InvalidData
                    );
                    let mut bad_nonce = reference_wire.clone();
                    bad_nonce[0] ^= 1;
                    assert_eq!(
                        decoder
                            .decode_frame(Bytes::from(bad_nonce), TIME)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::InvalidData
                    );
                    if !payload.is_empty() {
                        let mut bad_body_tag = reference_wire.clone();
                        *bad_body_tag.last_mut().unwrap() ^= 1;
                        assert_eq!(
                            decoder
                                .decode_frame(Bytes::from(bad_body_tag), TIME)
                                .unwrap_err()
                                .kind(),
                            io::ErrorKind::InvalidData
                        );
                    }
                    // Packet authentication failure never poisons the fixed-key UDP context.
                    assert_eq!(
                        decoder
                            .decode_frame(Bytes::from(reference_wire), TIME)
                            .unwrap()
                            .payload
                            .as_ref(),
                        payload
                    );
                }
            }
        }
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
