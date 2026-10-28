//! In-place bit packing for Mieru's low-entropy body representation.
//! The AEAD tag stays outside this representation. Metadata describes the
//! number of source bytes, a repeated half-mask, and per-chunk rotation.
use super::wire::{LowEntropyEncoding, MAX_DATA_PAYLOAD};
use std::io;

// Keep tiny bodies on the original per-bit path; no public configuration.
const PLANNED_SOURCE_MIN: usize = 32;

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
            || !(self.rotation <= 15 || (self.rotation.is_multiple_of(16) && self.rotation <= 240))
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
        let plan = (source_len >= PLANNED_SOURCE_MIN).then(|| PackingPlan::new(self.half_mask));
        for chunk in (0..source_len.div_ceil(count)).rev() {
            let offset = chunk * count;
            let len = (source_len - offset).min(count);
            let source = body[offset..offset + len]
                .iter()
                .fold(0u64, |word, byte| word << 8 | u64::from(*byte));
            let mask = self.mask(chunk);
            let mut encoded = match &plan {
                Some(plan) => plan.deposit(source, packing_phase(self.rotation, chunk)),
                None => deposit(source, mask),
            };
            if self.padding_bit == 1 {
                // A partial final source chunk has fewer data bits than its
                // mask. Those remaining positions are uniform padding too.
                let data_mask = if len == count {
                    mask
                } else {
                    match &plan {
                        Some(plan) => plan
                            .deposit((1u64 << (len * 8)) - 1, packing_phase(self.rotation, chunk)),
                        None => deposit((1u64 << (len * 8)) - 1, mask),
                    }
                };
                encoded |= !data_mask;
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
        let plan = (source_len >= PLANNED_SOURCE_MIN).then(|| PackingPlan::new(self.half_mask));
        let mut polarity = None;
        for chunk in 0..source_len.div_ceil(count) {
            let offset = chunk * count;
            let len = (source_len - offset).min(count);
            let word = u64::from_be_bytes(body[chunk * 8..chunk * 8 + 8].try_into().unwrap());
            let mask = self.mask(chunk);
            let data_mask = if len == count {
                mask
            } else {
                match &plan {
                    Some(plan) => {
                        plan.deposit((1u64 << (len * 8)) - 1, packing_phase(self.rotation, chunk))
                    }
                    None => deposit((1u64 << (len * 8)) - 1, mask),
                }
            };
            let padding_mask = !data_mask;
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
            let decoded = match &plan {
                Some(plan) => plan.extract(word, packing_phase(self.rotation, chunk)),
                None => extract(word, mask),
            }
            .to_be_bytes();
            body[offset..offset + len].copy_from_slice(&decoded[8 - len..]);
        }
        Ok(())
    }
}

// Per-frame stable bit-movement plan. A repeated half-mask has period at most
// 32; a packed k-bit rotation lets this one plan serve every phase. These
// fixed scalars/arrays own no heap and are never cached across frame calls.
#[derive(Clone, Copy)]
struct PackingPlan {
    moves: [u64; 6],
    mask: u64,
    // prefix_ones[r] is popcount(mask & low_bits(r)), for 0 <= r < 32.
    prefix_ones: [u8; 32],
    source_bits: u8,
}

fn low_bits(n: u32) -> u64 {
    (1u64 << n) - 1
}

impl PackingPlan {
    fn new(half_mask: u32) -> Self {
        let mask = u64::from(half_mask) | (u64::from(half_mask) << 32);
        let mut moves = [0u64; 6];
        let mut m = mask;
        let mut holes = (!m) << 1;
        for (i, movement) in moves.iter_mut().enumerate() {
            let mut p = holes ^ (holes << 1);
            p ^= p << 2;
            p ^= p << 4;
            p ^= p << 8;
            p ^= p << 16;
            p ^= p << 32;
            *movement = p & m;
            m = (m ^ *movement) | (*movement >> (1u32 << i));
            holes &= !p;
        }
        let mut prefix_ones = [0u8; 32];
        let mut count = 0u8;
        for (bit, prefix) in prefix_ones.iter_mut().enumerate() {
            *prefix = count;
            count += ((half_mask >> bit) & 1) as u8;
        }
        Self {
            moves,
            mask,
            prefix_ones,
            source_bits: mask.count_ones() as u8,
        }
    }

    #[inline]
    fn extract_base(&self, mut word: u64) -> u64 {
        word &= self.mask;
        for (i, movement) in self.moves.iter().enumerate() {
            let value = word & *movement;
            word = (word ^ value) | (value >> (1u32 << i));
        }
        word
    }

    #[inline]
    fn deposit_base(&self, mut word: u64) -> u64 {
        word &= low_bits(u32::from(self.source_bits));
        for (i, movement) in self.moves.iter().enumerate().rev() {
            let distance = 1u32 << i;
            let value = word & (*movement >> distance);
            word = (word ^ value) | (value << distance);
        }
        word & self.mask
    }

    #[inline]
    fn deposit(&self, word: u64, right: u32) -> u64 {
        let width = u32::from(self.source_bits);
        let wrap = u32::from(self.prefix_ones[right as usize]);
        let word = word & low_bits(width);
        // Width is 32/40/48/56; wrap=0 is valid without a shift by 64.
        let packed = ((word << wrap) | (word >> (width - wrap))) & low_bits(width);
        self.deposit_base(packed).rotate_right(right)
    }

    #[inline]
    fn extract(&self, word: u64, right: u32) -> u64 {
        let width = u32::from(self.source_bits);
        let wrap = u32::from(self.prefix_ones[right as usize]);
        let packed = self.extract_base(word.rotate_left(right));
        ((packed >> wrap) | (packed << (width - wrap))) & low_bits(width)
    }
}

#[inline]
fn packing_phase(rotation: u8, chunk: usize) -> u32 {
    let step = if rotation <= 15 {
        rotation
    } else {
        rotation / 16
    };
    let right = ((chunk as u32 & 31) * u32::from(step)) & 31;
    if rotation <= 15 {
        right
    } else {
        0u32.wrapping_sub(right) & 31
    }
}

fn deposit(mut source: u64, mut positions: u64) -> u64 {
    let mut result = 0;
    while positions != 0 {
        let position = positions.isolate_lowest_one();
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
        let position = positions.isolate_lowest_one();
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
    // Frozen pre-plan codec bodies from 17eb, using the unchanged private
    // per-bit deposit/extract oracle. Test-only: never a runtime second codec.
    fn bit_oracle_expand(
        e: LowEntropyEncoding,
        body: &mut [u8],
        source_len: usize,
    ) -> io::Result<()> {
        let encoded_len = e.encoded_len(source_len)?;
        if body.len() != encoded_len {
            return Err(invalid());
        }
        let count = e.source_bytes()?;
        for chunk in (0..source_len.div_ceil(count)).rev() {
            let offset = chunk * count;
            let len = (source_len - offset).min(count);
            let source = body[offset..offset + len]
                .iter()
                .fold(0u64, |word, byte| word << 8 | u64::from(*byte));
            let mask = e.mask(chunk);
            let mut encoded = deposit(source, mask);
            if e.padding_bit == 1 {
                // A partial final source chunk has fewer data bits than its
                // mask. Those remaining positions are uniform padding too.
                let data_mask = if len == count {
                    mask
                } else {
                    deposit((1u64 << (len * 8)) - 1, mask)
                };
                encoded |= !data_mask;
            }
            body[chunk * 8..chunk * 8 + 8].copy_from_slice(&encoded.to_be_bytes());
        }
        Ok(())
    }
    fn bit_oracle_compact(
        e: LowEntropyEncoding,
        body: &mut [u8],
        source_len: usize,
    ) -> io::Result<()> {
        if body.len() != e.encoded_len(source_len)? {
            return Err(invalid());
        }
        let count = e.source_bytes()?;
        let mut polarity = None;
        for chunk in 0..source_len.div_ceil(count) {
            let offset = chunk * count;
            let len = (source_len - offset).min(count);
            let word = u64::from_be_bytes(body[chunk * 8..chunk * 8 + 8].try_into().unwrap());
            let mask = e.mask(chunk);
            let data_mask = if len == count {
                mask
            } else {
                deposit((1u64 << (len * 8)) - 1, mask)
            };
            let padding_mask = !data_mask;
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

    fn planned_test_next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }
    fn planned_test_payload(len: usize, salt: u64) -> Vec<u8> {
        let mut state = salt | 1;
        (0..len)
            .map(|_| planned_test_next(&mut state) as u8)
            .collect()
    }
    fn planned_test_masks(mode: u8) -> Vec<u32> {
        let ones = (u32::from(mode) + 3) * 4;
        let low = (1u32 << ones) - 1;
        let mut masks = vec![low, low << (32 - ones)];
        let mut spread = 0;
        for i in 0..ones {
            spread |= 1u32 << ((i * 17) & 31);
        }
        masks.push(spread);
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(mode);
        for _ in 0..8 {
            let mut order = [0u8; 32];
            for (i, bit) in order.iter_mut().enumerate() {
                *bit = i as u8;
            }
            for i in (1..order.len()).rev() {
                let other = planned_test_next(&mut state) as usize % (i + 1);
                order.swap(i, other);
            }
            masks.push(
                order[..ones as usize]
                    .iter()
                    .fold(0u32, |mask, bit| mask | (1u32 << u32::from(*bit))),
            );
        }
        masks.sort_unstable();
        masks.dedup();
        masks
    }
    fn planned_test_rotations() -> Vec<u8> {
        (0..=15).chain((1..=15).map(|r| r * 16)).collect()
    }
    fn planned_test_compare(e: LowEntropyEncoding, source: &[u8]) {
        let mut original = vec![0u8; e.encoded_len(source.len()).unwrap()];
        original[..source.len()].copy_from_slice(source);
        let mut planned = original.clone();
        bit_oracle_expand(e, &mut original, source.len()).unwrap();
        e.expand(&mut planned, source.len()).unwrap();
        assert_eq!(
            planned,
            original,
            "mode={} rotation={} pad={} bytes={}",
            e.mode,
            e.rotation,
            e.padding_bit,
            source.len()
        );
        // Cross-decode, so a matching encoder/decoder defect cannot self-hide.
        bit_oracle_compact(e, &mut planned, source.len()).unwrap();
        e.compact(&mut original, source.len()).unwrap();
        assert_eq!(&planned[..source.len()], source);
        assert_eq!(&original[..source.len()], source);
    }

    #[test]
    fn mieru_low_entropy_planned_codec_matches_bit_oracle_across_modes_masks_rotations() {
        for mode in 1..=4 {
            let count = usize::from(mode) + 3;
            for half_mask in planned_test_masks(mode) {
                for rotation in planned_test_rotations() {
                    for padding_bit in 0..=1 {
                        let encoding = LowEntropyEncoding {
                            mode,
                            half_mask,
                            rotation,
                            padding_bit,
                        };
                        // Cover all 32 phases and the repeat with real frame APIs.
                        planned_test_compare(
                            encoding,
                            &planned_test_payload(count * 33, u64::from(half_mask)),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn mieru_low_entropy_plan_threshold_partial_and_protocol_boundaries() {
        for mode in 1..=4 {
            let count = usize::from(mode) + 3;
            let half_mask = ((1u32 << ((u32::from(mode) + 3) * 4)) - 1).rotate_left(11);
            for rotation in planned_test_rotations() {
                for padding_bit in 0..=1 {
                    let encoding = LowEntropyEncoding {
                        mode,
                        half_mask,
                        rotation,
                        padding_bit,
                    };
                    for len in 0..=PLANNED_SOURCE_MIN + count {
                        planned_test_compare(encoding, &planned_test_payload(len, len as u64 + 5));
                    }
                    for tail in 0..count {
                        let len = count * 32 + tail;
                        planned_test_compare(encoding, &planned_test_payload(len, tail as u64 + 9));
                    }
                }
            }
            let limit = if mode == 1 { 32764 } else { MAX_DATA_PAYLOAD };
            for rotation in [0, 7, 16, 240] {
                for padding_bit in 0..=1 {
                    let encoding = LowEntropyEncoding {
                        mode,
                        half_mask,
                        rotation,
                        padding_bit,
                    };
                    for len in [limit - 1, limit] {
                        planned_test_compare(encoding, &planned_test_payload(len, len as u64));
                    }
                    for len in [limit + 1, MAX_DATA_PAYLOAD + 1] {
                        assert!(encoding.expand(&mut [], len).is_err());
                        assert!(encoding.compact(&mut [], len).is_err());
                    }
                }
            }
        }
        let valid = LowEntropyEncoding {
            mode: 1,
            half_mask: 0x0f0f0f0f,
            rotation: 7,
            padding_bit: 0,
        };
        for invalid in [
            LowEntropyEncoding { mode: 0, ..valid },
            LowEntropyEncoding { mode: 5, ..valid },
            LowEntropyEncoding {
                half_mask: 1,
                ..valid
            },
            LowEntropyEncoding {
                rotation: 17,
                ..valid
            },
            LowEntropyEncoding {
                rotation: 255,
                ..valid
            },
            LowEntropyEncoding {
                padding_bit: 2,
                ..valid
            },
        ] {
            for len in [0, 1, 31, 32, 33] {
                assert!(invalid.expand(&mut [], len).is_err());
                assert!(invalid.compact(&mut [], len).is_err());
            }
        }
        for len in [31, 32, 33] {
            let exact = valid.encoded_len(len).unwrap();
            for malformed in [exact - 1, exact + 1] {
                assert!(valid.expand(&mut vec![0; malformed], len).is_err());
                assert!(valid.compact(&mut vec![0; malformed], len).is_err());
            }
        }
    }

    #[test]
    fn mieru_low_entropy_planned_padding_rejects_every_nondata_bit() {
        for mode in 1..=4 {
            let count = usize::from(mode) + 3;
            let half_mask = ((1u32 << ((u32::from(mode) + 3) * 4)) - 1).rotate_left(11);
            for rotation in planned_test_rotations() {
                for padding_bit in 0..=1 {
                    let encoding = LowEntropyEncoding {
                        mode,
                        half_mask,
                        rotation,
                        padding_bit,
                    };
                    let len = count * 32 + 1;
                    let mut good = vec![0; encoding.encoded_len(len).unwrap()];
                    good[..len].copy_from_slice(&planned_test_payload(len, 91));
                    bit_oracle_expand(encoding, &mut good, len).unwrap();
                    for chunk in [0usize, 31, 32] {
                        let data_len = if chunk == 32 { 1 } else { count };
                        // Unchanged per-bit oracle defines every actual data position.
                        let data_mask = deposit((1u64 << (data_len * 8)) - 1, encoding.mask(chunk));
                        let offset = chunk * 8;
                        let original_word =
                            u64::from_be_bytes(good[offset..offset + 8].try_into().unwrap());
                        for bit in 0..64 {
                            if data_mask & (1u64 << bit) != 0 {
                                continue;
                            }
                            let mut bad = good.clone();
                            bad[offset..offset + 8]
                                .copy_from_slice(&(original_word ^ (1u64 << bit)).to_be_bytes());
                            assert!(bit_oracle_compact(encoding, &mut bad.clone(), len).is_err());
                            assert!(encoding.compact(&mut bad, len).is_err());
                        }
                        // An internally uniform later chunk still cannot change frame polarity.
                        if chunk != 0 {
                            let mut bad = good.clone();
                            bad[offset..offset + 8]
                                .copy_from_slice(&(original_word ^ !data_mask).to_be_bytes());
                            assert!(bit_oracle_compact(encoding, &mut bad.clone(), len).is_err());
                            assert!(encoding.compact(&mut bad, len).is_err());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn mieru_low_entropy_planned_codec_independent_golden_vectors() {
        for padding_bit in 0..=1 {
            let encoding = LowEntropyEncoding {
                mode: 1,
                half_mask: 0x0f0f0f0f,
                rotation: 0,
                padding_bit,
            };
            let mut source = hex("12345678").repeat(8);
            let full = if padding_bit == 0 {
                "0102030405060708"
            } else {
                "f1f2f3f4f5f6f7f8"
            };
            let mut expected = hex(full).repeat(8);
            // Both threshold/full and a partial tail are independently enumerated.
            for tail in [false, true] {
                if tail {
                    source.push(0x12);
                    expected.extend(hex(if padding_bit == 0 {
                        "0000000000000102"
                    } else {
                        "fffffffffffff1f2"
                    }));
                }
                let mut body = vec![0; encoding.encoded_len(source.len()).unwrap()];
                body[..source.len()].copy_from_slice(&source);
                encoding.expand(&mut body, source.len()).unwrap();
                assert_eq!(body, expected);
                encoding.compact(&mut body, source.len()).unwrap();
                assert_eq!(&body[..source.len()], &source);
            }
            // Existing rotated40 golden is placed after one full phase cycle.
            let encoding = LowEntropyEncoding {
                mode: 2,
                half_mask: 0x00fffff0,
                rotation: 3,
                padding_bit,
            };
            let mut source = vec![0; 5 * 32];
            source.extend(hex("001122334455667788"));
            let mut expected = Vec::new();
            let base = u64::from(encoding.half_mask) * 0x1_0000_0001;
            for chunk in 0..32 {
                let word = if padding_bit == 0 {
                    0
                } else {
                    !base.rotate_right(chunk * 3)
                };
                expected.extend_from_slice(&word.to_be_bytes());
            }
            expected.extend(hex(if padding_bit == 0 {
                "000011200023344000000aac000cef10"
            } else {
                "ff00112fff23344fffffeaadffecef11"
            }));
            let mut body = vec![0; encoding.encoded_len(source.len()).unwrap()];
            body[..source.len()].copy_from_slice(&source);
            encoding.expand(&mut body, source.len()).unwrap();
            assert_eq!(body, expected);
            encoding.compact(&mut body, source.len()).unwrap();
            assert_eq!(&body[..source.len()], &source);
        }
    }

    #[test]
    fn mieru_low_entropy_plan_stays_stack_bounded() {
        assert!(std::mem::size_of::<PackingPlan>() <= 100);
        assert!(std::mem::size_of::<Option<PackingPlan>>() <= 112);
    }
}
