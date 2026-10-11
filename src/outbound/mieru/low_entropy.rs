//! In-place bit packing for Mieru's low-entropy body representation.
//! The AEAD tag stays outside this representation. Metadata describes the
//! number of source bytes, a repeated half-mask, and per-chunk rotation.
use super::wire::{LowEntropyEncoding, MAX_DATA_PAYLOAD};
use std::io;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Mieru low-entropy body")
}

impl LowEntropyEncoding {
    pub(super) fn source_bytes(self) -> io::Result<usize> {
        match self.mode {
            1..=4 => Ok(usize::from(self.mode) + 3),
            _ => Err(invalid()),
        }
    }

    fn validate(self) -> io::Result<usize> {
        let count = self.source_bytes()?;
        if self.half_mask.count_ones() != (count * 4) as u32
            || !(self.rotation <= 15 || (self.rotation % 16 == 0 && self.rotation <= 240))
            || self.padding_bit > 1
        {
            return Err(invalid());
        }
        Ok(count)
    }

    pub(super) fn encoded_len(self, source_len: usize) -> io::Result<usize> {
        let count = self.validate()?;
        let len = source_len
            .div_ceil(count)
            .checked_mul(8)
            .ok_or_else(invalid)?;
        if source_len > MAX_DATA_PAYLOAD || len > usize::from(u16::MAX) {
            return Err(invalid());
        }
        Ok(len)
    }

    fn mask(self, chunk: usize) -> u64 {
        let mask = u64::from(self.half_mask) * 0x1_0000_0001;
        let chunk = (chunk % 64) as u32;
        if self.rotation <= 15 {
            mask.rotate_right(chunk * u32::from(self.rotation))
        } else {
            mask.rotate_left(chunk * u32::from(self.rotation / 16))
        }
    }

    /// The source begins at offset zero. Working backward leaves unread
    /// source chunks intact while expanding them into the existing buffer.
    pub(super) fn expand(self, body: &mut [u8], source_len: usize) -> io::Result<()> {
        let encoded_len = self.encoded_len(source_len)?;
        if body.len() != encoded_len {
            return Err(invalid());
        }
        let count = self.source_bytes()?;
        for chunk in (0..source_len.div_ceil(count)).rev() {
            let offset = chunk * count;
            let len = (source_len - offset).min(count);
            let source = body[offset..offset + len]
                .iter()
                .fold(0u64, |word, byte| word << 8 | u64::from(*byte));
            let mask = self.mask(chunk);
            let mut encoded = deposit(source, mask);
            if self.padding_bit == 1 {
                // A partial final source chunk has fewer data bits than its
                // mask. Those remaining positions are uniform padding too.
                encoded |= !deposit((1u64 << (len * 8)) - 1, mask);
            }
            body[chunk * 8..chunk * 8 + 8].copy_from_slice(&encoded.to_be_bytes());
        }
        Ok(())
    }

    /// Compact authenticated-length ciphertext before AEAD verification.
    /// Every non-data bit must have the polarity inferred from the first chunk.
    pub(super) fn compact(self, body: &mut [u8], source_len: usize) -> io::Result<()> {
        if body.len() != self.encoded_len(source_len)? {
            return Err(invalid());
        }
        let count = self.source_bytes()?;
        let mut polarity = None;
        for chunk in 0..source_len.div_ceil(count) {
            let offset = chunk * count;
            let len = (source_len - offset).min(count);
            let word = u64::from_be_bytes(body[chunk * 8..chunk * 8 + 8].try_into().unwrap());
            let mask = self.mask(chunk);
            let padding_mask = !deposit((1u64 << (len * 8)) - 1, mask);
            let padding = word & padding_mask;
            let bit = if padding == 0 {
                false
            } else if padding == padding_mask {
                true
            } else {
                return Err(invalid());
            };
            if polarity.is_some_and(|previous| previous != bit) {
                return Err(invalid());
            }
            polarity = Some(bit);
            let decoded = extract(word, mask).to_be_bytes();
            body[offset..offset + len].copy_from_slice(&decoded[8 - len..]);
        }
        Ok(())
    }
}

fn deposit(mut source: u64, mut positions: u64) -> u64 {
    let mut result = 0;
    while positions != 0 {
        let position = positions & positions.wrapping_neg();
        if source & 1 != 0 {
            result |= position;
        }
        source >>= 1;
        positions &= positions - 1;
    }
    result
}

fn extract(source: u64, mut positions: u64) -> u64 {
    let mut result = 0;
    let mut bit = 1;
    while positions != 0 {
        let position = positions & positions.wrapping_neg();
        if source & position != 0 {
            result |= bit;
        }
        bit <<= 1;
        positions &= positions - 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid vector"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn mieru_low_entropy_independent_bit_position_vectors() {
        // Independently enumerated bit positions, including partial source
        // chunks and a rotated 40-bit mask. These are ciphertext-body inputs.
        for (input, mode, mask, rotation, expected) in [
            (
                "12345678",
                1,
                0x0f0f0f0f,
                0,
                ["0102030405060708", "f1f2f3f4f5f6f7f8"],
            ),
            (
                "123456",
                1,
                0x0f0f0f0f,
                0,
                ["0000010203040506", "fffff1f2f3f4f5f6"],
            ),
            (
                "001122334455667788",
                2,
                0x00fffff0,
                3,
                [
                    "000011200023344000000aac000cef10",
                    "ff00112fff23344fffffeaadffecef11",
                ],
            ),
        ] {
            let source = hex(input);
            for padding_bit in 0..=1 {
                let encoding = LowEntropyEncoding {
                    mode,
                    half_mask: mask,
                    rotation,
                    padding_bit,
                };
                let mut body = vec![0; encoding.encoded_len(source.len()).unwrap()];
                body[..source.len()].copy_from_slice(&source);
                encoding.expand(&mut body, source.len()).unwrap();
                assert_eq!(body, hex(expected[usize::from(padding_bit)]));
                encoding.compact(&mut body, source.len()).unwrap();
                assert_eq!(&body[..source.len()], source);
            }
        }
    }

    #[test]
    fn mieru_low_entropy_rejects_nonuniform_padding_and_keeps_wire_bounds() {
        let encoding = LowEntropyEncoding {
            mode: 1,
            half_mask: 0x0f0f0f0f,
            rotation: 16,
            padding_bit: 0,
        };
        let mut body = vec![0; encoding.encoded_len(7).unwrap()];
        body[..7].copy_from_slice(b"example");
        encoding.expand(&mut body, 7).unwrap();
        let mask = encoding.mask(1);
        let unused = !deposit((1u64 << 24) - 1, mask);
        let position = unused & unused.wrapping_neg();
        let word = u64::from_be_bytes(body[8..16].try_into().unwrap()) | position;
        body[8..16].copy_from_slice(&word.to_be_bytes());
        assert!(encoding.compact(&mut body, 7).is_err());
        assert_eq!(encoding.encoded_len(32764).unwrap(), 65528);
        assert!(encoding.encoded_len(32765).is_err());
        assert!(
            LowEntropyEncoding {
                rotation: 17,
                ..encoding
            }
            .encoded_len(1)
            .is_err()
        );
        assert!(
            LowEntropyEncoding {
                half_mask: 1,
                ..encoding
            }
            .encoded_len(1)
            .is_err()
        );
    }
}
