//! Native traffic-pattern policies for the public Mieru v3 wire format.
//! Protobuf field numbers and behavior target the SDK 3.38.0 consumed by Mihomo.
//! This independent implementation contains no copied protobuf or Go source.
use super::wire::{
    BodyEncoding, DataKind, FrameEncoding, LowEntropyEncoding, MAX_CONTROL_PAYLOAD,
    MAX_DATA_PAYLOAD, Metadata, PACKET_OVERHEAD, Padding,
};
use crate::config::MieruTransport;
use base64::{Engine as _, alphabet, engine::general_purpose};
use prost::Message;
use rand::RngExt as _;
use sha2::{Digest, Sha256};
use std::{io, ops::Range, time::Duration};

const PROFILE_VERSION: &[u8] = b"3.38.0";
const PADDING_LIMIT: usize = 255;
const COMMON_64: &[u8; 64] = b"CCOzB3KKr9NDAgVnJcCn9ib37T1JH6vRSVx8YaNnXbfo6yFU1EHPy2r3D5LM1Qi4";

// Independent definitions of the public field-number/type contract. Optional
// scalars retain absence separately from zero, including unknown nonce enums.
#[derive(Clone, PartialEq, Message)]
struct RawPattern {
    #[prost(int32, optional, tag = "1")]
    seed: Option<i32>,
    #[prost(bool, optional, tag = "2")]
    unlock_all: Option<bool>,
    #[prost(message, optional, tag = "3")]
    fragment: Option<RawFragment>,
    #[prost(message, optional, tag = "4")]
    nonce: Option<RawNonce>,
    #[prost(message, optional, tag = "5")]
    padding: Option<RawPadding>,
    #[prost(message, optional, tag = "6")]
    low_entropy: Option<RawLowEntropy>,
}

#[derive(Clone, PartialEq, Message)]
struct RawFragment {
    #[prost(bool, optional, tag = "1")]
    enable: Option<bool>,
    #[prost(int32, optional, tag = "2")]
    max_sleep_ms: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct RawNonce {
    #[prost(int32, optional, tag = "1")]
    kind: Option<i32>,
    #[prost(bool, optional, tag = "2")]
    all_udp: Option<bool>,
    #[prost(int32, optional, tag = "3")]
    minimum: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    maximum: Option<i32>,
    #[prost(string, repeated, tag = "5")]
    fixed: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct RawPadding {
    #[prost(int32, optional, tag = "1")]
    middle: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    end: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct RawLowEntropy {
    #[prost(int32, optional, tag = "1")]
    mode: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    rotation: Option<i32>,
}

fn invalid_pattern() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid Mieru traffic-pattern")
}

fn fixed_hash(bytes: &[u8], versioned: bool) -> u32 {
    let mut hash = Sha256::new();
    hash.update(bytes);
    if versioned {
        hash.update(b" ");
        hash.update(PROFILE_VERSION);
    }
    let digest = hash.finalize();
    u32::from_be_bytes([digest[0] & 0x7f, digest[1], digest[2], digest[3]])
}

/// One factory snapshot, shared by defaults, padding polarity and idle timeout.
#[derive(Clone, Copy)]
pub(crate) struct HostProfile(u32);

impl HostProfile {
    pub(crate) fn capture() -> Self {
        Self(fixed_hash(
            &hostname::get().unwrap_or_default().into_encoded_bytes(),
            true,
        ))
    }

    pub(crate) fn fixed_int(self, upper: u32) -> u32 {
        if upper == 0 { 0 } else { self.0 % upper }
    }
}

fn decode_raw(encoded: &str) -> io::Result<RawPattern> {
    // Go's StdEncoding permits CR/LF and noncanonical unused tail bits, while
    // still requiring padded standard base64 and rejecting other whitespace.
    let clean: Vec<_> = encoded
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    let engine = general_purpose::GeneralPurpose::new(
        &alphabet::STANDARD,
        general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let bytes = engine.decode(clean).map_err(|_| invalid_pattern())?;
    let raw = RawPattern::decode(bytes.as_slice()).map_err(|_| invalid_pattern())?;
    validate(&raw)?;
    Ok(raw)
}

fn valid_range(value: Option<i32>, maximum: i32) -> bool {
    value.is_none_or(|value| (0..=maximum).contains(&value))
}

fn valid_rotation(value: i32) -> bool {
    (0..=15).contains(&value) || (16..=240).contains(&value) && value % 16 == 0
}

fn validate(raw: &RawPattern) -> io::Result<()> {
    if raw
        .fragment
        .as_ref()
        .is_some_and(|v| !valid_range(v.max_sleep_ms, 100))
        || raw
            .padding
            .as_ref()
            .is_some_and(|v| !valid_range(v.middle, 255) || !valid_range(v.end, 255))
        || raw.low_entropy.as_ref().is_some_and(|v| {
            !valid_range(v.mode, 4) || v.rotation.is_some_and(|n| !valid_rotation(n))
        })
    {
        return Err(invalid_pattern());
    }
    if let Some(nonce) = &raw.nonce {
        if !valid_range(nonce.minimum, 12)
            || !valid_range(nonce.maximum, 12)
            || nonce.minimum.zip(nonce.maximum).is_some_and(|(a, b)| a > b)
        {
            return Err(invalid_pattern());
        }
        for value in &nonce.fixed {
            decode_prefix(value)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_raw(encoded: &str) -> crate::Result<()> {
    decode_raw(encoded)
        .map(|_| ())
        .map_err(|_| crate::error::VoleError::InvalidConfig("invalid Mieru traffic-pattern".into()))
}

struct NoncePrefix {
    bytes: [u8; 12],
    len: usize,
}

fn decode_prefix(value: &str) -> io::Result<NoncePrefix> {
    if value.len() > 24 || !value.len().is_multiple_of(2) {
        return Err(invalid_pattern());
    }
    let mut result = NoncePrefix {
        bytes: [0; 12],
        len: value.len() / 2,
    };
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        result.bytes[index] = digit(pair[0])
            .zip(digit(pair[1]))
            .map(|(a, b)| a * 16 + b)
            .ok_or_else(invalid_pattern)?;
    }
    Ok(result)
}

/// Immutable policy; all per-carrier mutation lives in NonceState or the driver.
pub(crate) struct EffectivePattern {
    fragment: bool,
    max_sleep_ms: u64,
    nonce_kind: i32,
    all_udp: bool,
    nonce_min: usize,
    nonce_max: usize,
    fixed_nonce: Vec<NoncePrefix>,
    middle: usize,
    end: usize,
    low_mode: u8,
    rotation: u8,
    padding_bit: u8,
    ascii_run: usize,
    control_entropy: bool,
}

impl EffectivePattern {
    pub(crate) fn compile(
        encoded: Option<&str>,
        host: HostProfile,
        username: &str,
    ) -> io::Result<Self> {
        let raw = decode_raw(encoded.unwrap_or_default())?;
        let seed = raw.seed.unwrap_or(host.fixed_int(i32::MAX as u32) as i32);
        let unlocked = raw.unlock_all.unwrap_or(false);
        let implicit = |name: &str, upper: u32| {
            if upper == 0 {
                0
            } else {
                fixed_hash(format!("{seed}:{name}").as_bytes(), false) % upper
            }
        };
        let fragment = raw.fragment.unwrap_or_default();
        let nonce = raw.nonce.unwrap_or_default();
        let padding = raw.padding.unwrap_or_default();
        let low = raw.low_entropy.unwrap_or_default();
        let nonce_min = nonce.minimum.unwrap_or_else(|| {
            if unlocked {
                implicit("nonce.minLen", 13) as i32
            } else {
                6 + implicit("nonce.minLen", 7) as i32
            }
        });
        let nonce_max = nonce.maximum.unwrap_or_else(|| {
            nonce_min + implicit("nonce.maxLen", (13 - nonce_min) as u32) as i32
        });
        let rotation = low.rotation.unwrap_or_else(|| {
            let value = implicit("lowEntropy.maskRotation", 31) as i32;
            if value <= 15 {
                value
            } else {
                (value - 15) * 16
            }
        });
        Ok(Self {
            fragment: fragment
                .enable
                .unwrap_or_else(|| unlocked && implicit("tcpFragment.enable", 2) == 1),
            max_sleep_ms: fragment.max_sleep_ms.unwrap_or_else(|| {
                if unlocked {
                    1 + implicit("tcpFragment.maxSleepMs", 100) as i32
                } else {
                    0
                }
            }) as u64,
            nonce_kind: nonce.kind.unwrap_or_else(|| {
                if unlocked {
                    implicit("nonce.type", 3) as i32
                } else {
                    1 + implicit("nonce.type", 2) as i32
                }
            }),
            all_udp: nonce
                .all_udp
                .unwrap_or_else(|| implicit("nonce.applyToAllUDPPacket", 2) == 1),
            nonce_min: nonce_min as usize,
            nonce_max: nonce_max as usize,
            fixed_nonce: nonce
                .fixed
                .iter()
                .map(|value| decode_prefix(value))
                .collect::<io::Result<_>>()?,
            middle: padding.middle.unwrap_or_else(|| {
                (implicit("padding.maxMiddlePaddingLen", 256) as i32 - 128).max(0)
            }) as usize,
            end: padding.end.unwrap_or_else(|| {
                if unlocked {
                    implicit("padding.maxEndPaddingLen", 256) as i32
                } else {
                    255
                }
            }) as usize,
            low_mode: low.mode.unwrap_or_else(|| {
                if unlocked {
                    implicit("lowEntropy.mode", 5) as i32
                } else {
                    0
                }
            }) as u8,
            rotation: rotation as u8,
            padding_bit: host.fixed_int(2) as u8,
            ascii_run: 24 + host.fixed_int(17) as usize,
            control_entropy: fixed_hash(username.as_bytes(), true) % 2 != 0,
        })
    }

    pub(crate) fn low_entropy_enabled(&self) -> bool {
        self.low_mode != 0
    }

    fn body(&self, random: &mut impl PatternRandom) -> io::Result<BodyEncoding> {
        if !self.low_entropy_enabled() {
            return Ok(BodyEncoding::Plain);
        }
        let count = 12 + usize::from(self.low_mode) * 4;
        let mut mask = 0u32;
        let mut needed = count;
        // Sampling without replacement gives each mask of this population the
        // same probability, without an allocation or an unbounded rejection loop.
        for bit in 0..32 {
            if random.uniform(32 - bit) < needed {
                mask |= 1 << bit;
                needed -= 1;
            }
        }
        Ok(BodyEncoding::LowEntropy(LowEntropyEncoding {
            mode: self.low_mode,
            half_mask: mask,
            rotation: self.rotation,
            padding_bit: self.padding_bit,
        }))
    }

    pub(crate) fn plaintext_fragment_limit(
        &self,
        transport: MieruTransport,
        wire_budget: usize,
    ) -> io::Result<usize> {
        let available = match transport {
            MieruTransport::Tcp => u16::MAX as usize,
            MieruTransport::Udp => wire_budget
                .checked_sub(PACKET_OVERHEAD)
                .ok_or_else(invalid_pattern)?,
        }
        .min(u16::MAX as usize);
        let maximum = if self.low_entropy_enabled() {
            let source = 3 + usize::from(self.low_mode);
            available / 8 * source
        } else {
            available
        };
        let maximum = maximum.min(MAX_DATA_PAYLOAD);
        if maximum == 0 {
            return Err(invalid_pattern());
        }
        Ok(maximum)
    }

    pub(crate) fn prepare_frame(
        &self,
        metadata: Metadata,
        plain_len: usize,
        transport: MieruTransport,
        wire_budget: usize,
    ) -> io::Result<PreparedFrame> {
        self.prepare_with(
            metadata,
            plain_len,
            transport,
            wire_budget,
            &mut rand::rng(),
        )
    }

    fn prepare_with(
        &self,
        metadata: Metadata,
        plain_len: usize,
        transport: MieruTransport,
        wire_budget: usize,
        random: &mut impl PatternRandom,
    ) -> io::Result<PreparedFrame> {
        let control = matches!(metadata, Metadata::Session(_));
        if plain_len
            > if control {
                MAX_CONTROL_PAYLOAD
            } else {
                MAX_DATA_PAYLOAD
            }
        {
            return Err(invalid_pattern());
        }
        let data = matches!(metadata, Metadata::Data(v) if matches!(v.kind, DataKind::ClientData | DataKind::ServerData));
        let body = if data && plain_len != 0 {
            self.body(random)?
        } else {
            BodyEncoding::Plain
        };
        let body_len = body.encoded_len(plain_len)?;
        let available = match transport {
            MieruTransport::Tcp => usize::MAX,
            MieruTransport::Udp => wire_budget
                .checked_sub(PACKET_OVERHEAD + body_len)
                .ok_or_else(invalid_pattern)?,
        };
        let mut result = PreparedFrame {
            prefix: [0; 255],
            suffix: [0; 255],
            prefix_len: 0,
            suffix_len: 0,
            body,
        };
        if control {
            let cap = self.end.min(available);
            result.suffix_len = if self.control_entropy {
                let surrogate_len = if transport == MieruTransport::Tcp {
                    64
                } else {
                    88
                } + plain_len;
                let mut ones = 0;
                let mut remaining = surrogate_len;
                let mut scratch = [0u8; 256];
                while remaining != 0 {
                    let len = remaining.min(scratch.len());
                    random.fill(&mut scratch[..len]);
                    ones += scratch[..len]
                        .iter()
                        .map(|b| b.count_ones() as usize)
                        .sum::<usize>();
                    remaining -= len;
                }
                entropy_padding(&mut result.suffix[..cap], surrogate_len * 8, ones, random)
            } else {
                ascii_padding(&mut result.suffix[..cap], self.ascii_run.min(cap), random)
            };
        } else {
            let cap = self.middle.min(available);
            result.prefix_len = ascii_padding(&mut result.prefix[..cap], 0, random);
            let cap = self.end.min(available.saturating_sub(result.prefix_len));
            result.suffix_len = ascii_padding(&mut result.suffix[..cap], 0, random);
        }
        Ok(result)
    }

    pub(crate) fn control_chunks(&self, frame_len: usize) -> ControlChunks {
        ControlChunks {
            frame_len,
            position: 0,
            fragmented: self.fragment,
            max_sleep_ms: self.max_sleep_ms,
        }
    }

    pub(crate) fn rewrite_nonce(
        &self,
        state: &mut NonceState,
        nonce: &mut [u8; 24],
        transport: MieruTransport,
    ) {
        self.rewrite_with(state, nonce, transport, &mut rand::rng());
    }

    fn rewrite_with(
        &self,
        state: &mut NonceState,
        nonce: &mut [u8; 24],
        transport: MieruTransport,
        random: &mut impl PatternRandom,
    ) {
        if !state.first && (transport == MieruTransport::Tcp || !self.all_udp) {
            return;
        }
        state.first = false;
        match self.nonce_kind {
            1 | 2 => {
                // Explicit maximum can be below an implicitly generated minimum.
                // Raw validation precedes defaults; the actual consumer clamps it.
                let min = self.nonce_min.min(self.nonce_max);
                let len = if min == self.nonce_max {
                    min
                } else {
                    min + random.uniform(self.nonce_max - min + 1)
                };
                if self.nonce_kind == 1 {
                    printable(&mut nonce[..len], random);
                } else {
                    for b in &mut nonce[..len] {
                        *b = COMMON_64[usize::from(*b & 63)];
                    }
                }
            }
            3 if !self.fixed_nonce.is_empty() => {
                let prefix = &self.fixed_nonce[random.uniform(self.fixed_nonce.len())];
                nonce[..prefix.len].copy_from_slice(&prefix.bytes[..prefix.len]);
            }
            _ => {}
        }
    }
}

pub(crate) struct NonceState {
    first: bool,
}
impl NonceState {
    pub(crate) fn new() -> Self {
        Self { first: true }
    }
}

/// Temporary stack-owned padding and one immutable body descriptor.
pub(crate) struct PreparedFrame {
    prefix: [u8; PADDING_LIMIT],
    suffix: [u8; PADDING_LIMIT],
    prefix_len: usize,
    suffix_len: usize,
    body: BodyEncoding,
}
impl PreparedFrame {
    pub(crate) fn encoding(&self) -> FrameEncoding<'_> {
        FrameEncoding {
            padding: Padding {
                prefix: &self.prefix[..self.prefix_len],
                suffix: &self.suffix[..self.suffix_len],
            },
            body: self.body,
        }
    }
}

pub(crate) struct WriteChunk {
    pub(crate) range: Range<usize>,
    pub(crate) delay_after: Duration,
}
pub(crate) struct ControlChunks {
    frame_len: usize,
    position: usize,
    fragmented: bool,
    max_sleep_ms: u64,
}
impl Iterator for ControlChunks {
    type Item = WriteChunk;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_with(&mut rand::rng())
    }
}
impl ControlChunks {
    fn next_with(&mut self, random: &mut impl PatternRandom) -> Option<WriteChunk> {
        if self.position == self.frame_len {
            return None;
        }
        let (len, delay_after) = if self.fragmented {
            let min = (self.frame_len as f64).sqrt() as usize + 1;
            let max = min.max(self.frame_len / 2);
            let len = (min + random.uniform(max - min + 1)).min(self.frame_len - self.position);
            // The reference sleeps after every piece, including the final one.
            let delay = if self.max_sleep_ms == 0 {
                0
            } else {
                random.uniform(self.max_sleep_ms as usize + 1) as u64
            };
            (len, Duration::from_millis(delay))
        } else {
            (self.frame_len - self.position, Duration::ZERO)
        };
        let start = self.position;
        self.position += len;
        Some(WriteChunk {
            range: start..self.position,
            delay_after,
        })
    }
}

trait PatternRandom {
    fn uniform(&mut self, upper: usize) -> usize;
    fn unit(&mut self) -> f64;
    fn fill(&mut self, bytes: &mut [u8]);
}
impl<R: rand::Rng + ?Sized> PatternRandom for R {
    fn uniform(&mut self, upper: usize) -> usize {
        self.random_range(0..upper)
    }
    fn unit(&mut self) -> f64 {
        self.random()
    }
    fn fill(&mut self, bytes: &mut [u8]) {
        rand::RngExt::fill(self, bytes);
    }
}

fn biased_int(random: &mut impl PatternRandom, upper: usize) -> usize {
    let scale = random.unit();
    (random.uniform(upper + 1) as f64 * (scale * scale * scale).sqrt()) as usize
}

fn printable(bytes: &mut [u8], random: &mut impl PatternRandom) {
    for byte in bytes {
        if (32..=126).contains(byte) {
            continue;
        }
        if (32..=126).contains(&(*byte & 127)) {
            *byte &= 127;
            continue;
        }
        loop {
            let mut draw = [0; 2];
            random.fill(&mut draw);
            let draw = u16::from_be_bytes(draw);
            if draw < 65_455 {
                *byte = 32 + (draw % 95) as u8;
                break;
            }
        }
    }
}

fn ascii_padding(output: &mut [u8], run: usize, random: &mut impl PatternRandom) -> usize {
    let len = run + biased_int(random, output.len() - run + 1);
    random.fill(&mut output[..len]);
    let start = if len > run {
        random.uniform(len - run)
    } else {
        0
    };
    printable(&mut output[start..start + run], random);
    len
}

fn entropy_padding(
    output: &mut [u8],
    bits: usize,
    ones: usize,
    random: &mut impl PatternRandom,
) -> usize {
    let zeros = bits - ones;
    let minority_one = ones < zeros;
    let minority = ones.min(zeros);
    let minimum_bits = (minority as f64 / 0.325 - bits as f64).max(0.0) as usize;
    let minimum = minimum_bits.div_ceil(8);
    let len = if minimum >= output.len() {
        output.len()
    } else {
        minimum + biased_int(random, output.len() - minimum + 1)
    };
    output[..len].fill(if minority_one { 0 } else { 255 });
    let flips = (((bits + len * 8) as f64 * 0.325) as usize)
        .saturating_sub(minority)
        .min(len * 8);
    // Repeated positions are intentional; deduplication changes camouflage.
    for _ in 0..flips {
        let bit = random.uniform(len * 8);
        if minority_one {
            output[bit / 8] |= 1 << (bit % 8);
        } else {
            output[bit / 8] &= !(1 << (bit % 8));
        }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::super::{
        crypto::make_client_nonce,
        wire::{DataMetadata, SessionKind, SessionMetadata},
    };
    use super::*;
    use std::collections::VecDeque;

    // Hand-encoded protobuf fields, independent of prost's encoder. Both set
    // fixed aabbcc nonce, zero padding, mode 32 and rotation zero. Only TCP
    // enables control fragmentation; max sleep is explicitly zero.
    const TCP: &str = "CAAaBAgBEAAiEAgDEAEYACAAKgZhYWJiY2MqBAgAEAAyBAgBEAA=";
    const UDP: &str = "CAAaBAgAEAAiEAgDEAEYACAAKgZhYWJiY2MqBAgAEAAyBAgBEAA=";
    fn host() -> HostProfile {
        HostProfile(fixed_hash(b"vole-fixture", true))
    }
    fn frame() -> Metadata {
        Metadata::Data(DataMetadata {
            kind: DataKind::ClientData,
            session_id: 1,
            sequence: 0,
            unack_sequence: 0,
            window: 16,
            fragment: 0,
        })
    }
    fn control() -> Metadata {
        Metadata::Session(SessionMetadata {
            kind: SessionKind::OpenRequest,
            session_id: 1,
            sequence: 0,
            status: 0,
        })
    }
    struct FixedRandom {
        draws: VecDeque<usize>,
        bytes: VecDeque<u8>,
        fallback_byte: u8,
        fraction: f64,
    }
    impl Default for FixedRandom {
        fn default() -> Self {
            Self {
                draws: VecDeque::new(),
                bytes: VecDeque::new(),
                fallback_byte: 0x55,
                fraction: 0.25,
            }
        }
    }
    impl PatternRandom for FixedRandom {
        fn uniform(&mut self, upper: usize) -> usize {
            let value = self.draws.pop_front().unwrap_or(0);
            assert!(value < upper);
            value
        }
        fn unit(&mut self) -> f64 {
            self.fraction
        }
        fn fill(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                *byte = self.bytes.pop_front().unwrap_or(self.fallback_byte);
            }
        }
    }

    #[test]
    fn implicit_profile_uses_host_version_and_scalar_presence() {
        assert_eq!(host().0, 1_090_847_407);
        assert_eq!(host().fixed_int(17), 9);
        let default = EffectivePattern::compile(None, host(), "bob").unwrap();
        assert!(!default.fragment && !default.all_udp);
        assert_eq!(
            (default.nonce_kind, default.nonce_min, default.nonce_max),
            (2, 12, 12)
        );
        assert_eq!(
            (
                default.middle,
                default.end,
                default.low_mode,
                default.rotation
            ),
            (96, 255, 0, 48)
        );
        assert_eq!((default.ascii_run, default.padding_bit), (33, 1));
        let explicit = EffectivePattern::compile(Some(TCP), host(), "bob").unwrap();
        assert!(explicit.fragment && explicit.all_udp && explicit.low_entropy_enabled());
        assert_eq!(
            (
                explicit.nonce_min,
                explicit.nonce_max,
                explicit.middle,
                explicit.end
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(explicit.rotation, 0);
        // unlockAll=true does not overwrite a present false/zero. Signed seed
        // participates in its decimal implicit hint without extra restrictions.
        let raw = RawPattern {
            seed: Some(-1),
            unlock_all: Some(true),
            fragment: Some(RawFragment {
                enable: Some(false),
                max_sleep_ms: Some(0),
            }),
            ..Default::default()
        };
        let encoded = general_purpose::STANDARD.encode(raw.encode_to_vec());
        let signed = EffectivePattern::compile(Some(&encoded), host(), "bob").unwrap();
        assert!(!signed.fragment);
        assert_eq!(
            (
                signed.max_sleep_ms,
                signed.nonce_kind,
                signed.nonce_min,
                signed.end,
                signed.low_mode
            ),
            (0, 1, 9, 63, 3)
        );
    }

    #[test]
    fn base64_and_raw_validation_preserve_upstream_boundaries() {
        let raw = decode_raw("C\r\nAB=").unwrap();
        assert_eq!(raw.seed, Some(0)); // noncanonical unused tail bits accepted
        assert!(decode_raw("C AB=").is_err());
        assert!(decode_raw("CAA").is_err()); // StdEncoding requires padding
        // An unknown nonce enum is a no-op, not an enum validation failure.
        let raw = RawPattern {
            nonce: Some(RawNonce {
                kind: Some(99),
                maximum: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let encoded = general_purpose::STANDARD.encode(raw.encode_to_vec());
        validate_raw(&encoded).unwrap();
        let pattern = EffectivePattern::compile(Some(&encoded), host(), "bob").unwrap();
        assert!(pattern.nonce_min > pattern.nonce_max);
        let mut nonce = [7; 24];
        let mut state = NonceState::new();
        pattern.rewrite_with(
            &mut state,
            &mut nonce,
            MieruTransport::Udp,
            &mut FixedRandom::default(),
        );
        assert_eq!(nonce, [7; 24]);
        assert!(!state.first);
        // Only the relationship between two explicit nonce bounds is checked.
        let mut raw = raw;
        raw.nonce.as_mut().unwrap().minimum = Some(1);
        assert!(validate(&raw).is_err());
        assert!(
            validate(&RawPattern {
                low_entropy: Some(RawLowEntropy {
                    mode: Some(1),
                    rotation: Some(17)
                }),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            validate(&RawPattern {
                nonce: Some(RawNonce {
                    fixed: vec!["0x".into()],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn fixed_nonce_applies_per_physical_carrier_and_preserves_user_hint() {
        let mut pattern = EffectivePattern::compile(Some(UDP), host(), "vole").unwrap();
        let raw: [u8; 24] = std::array::from_fn(|i| i as u8);
        let mut state = NonceState::new();
        let mut nonce = raw;
        pattern.rewrite_with(
            &mut state,
            &mut nonce,
            MieruTransport::Udp,
            &mut FixedRandom::default(),
        );
        assert_eq!(&nonce[..3], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(&nonce[3..], &raw[3..]);
        let nonce = make_client_nonce("vole", nonce);
        assert_eq!(&nonce[20..], &[0x4e, 0x5b, 0xb3, 0xbf]);
        pattern.all_udp = false;
        let mut next = raw;
        pattern.rewrite_with(
            &mut state,
            &mut next,
            MieruTransport::Udp,
            &mut FixedRandom::default(),
        );
        assert_eq!(next, raw);
        let mut fresh = NonceState::new();
        pattern.rewrite_with(
            &mut fresh,
            &mut next,
            MieruTransport::Udp,
            &mut FixedRandom::default(),
        );
        assert_eq!(&next[..3], &[0xaa, 0xbb, 0xcc]);
        // A fresh UDP attempt still follows apply-all; TCP generates one
        // explicit patterned nonce, then its cipher increments internally.
        pattern.all_udp = true;
        let mut next = raw;
        pattern.rewrite_with(
            &mut state,
            &mut next,
            MieruTransport::Udp,
            &mut FixedRandom::default(),
        );
        assert_eq!(&next[..3], &[0xaa, 0xbb, 0xcc]);
        let mut next = raw;
        pattern.rewrite_with(
            &mut state,
            &mut next,
            MieruTransport::Tcp,
            &mut FixedRandom::default(),
        );
        assert_eq!(next, raw);
    }

    #[test]
    fn printable_and_subset_nonce_vectors_are_independent_of_padding_bias() {
        let mut pattern = EffectivePattern::compile(Some(UDP), host(), "vole").unwrap();
        pattern.nonce_kind = 1;
        pattern.nonce_min = 8;
        pattern.nonce_max = 8;
        let mut nonce: [u8; 24] = std::array::from_fn(|i| i as u8);
        nonce[..8].copy_from_slice(&[0x20, 0x7e, 0xa0, 0xfe, 0x1f, 0x7f, 0xff, 0]);
        let mut random = FixedRandom {
            bytes: VecDeque::from([0xff, 0xaf, 0, 0, 0, 94, 0, 95, 0, 189]),
            ..Default::default()
        };
        pattern.rewrite_with(
            &mut NonceState::new(),
            &mut nonce,
            MieruTransport::Udp,
            &mut random,
        );
        assert_eq!(
            &nonce[..8],
            &[0x20, 0x7e, 0x20, 0x7e, 0x20, 0x7e, 0x20, 0x7e]
        );
        assert_eq!(
            &make_client_nonce("vole", nonce)[20..],
            &[0xb8, 0xd8, 0xa2, 0x30]
        );
        pattern.nonce_kind = 2;
        pattern.nonce_min = 6;
        pattern.nonce_max = 6;
        nonce = std::array::from_fn(|i| i as u8);
        nonce[..6].copy_from_slice(&[0, 1, 2, 63, 64, 255]);
        pattern.rewrite_with(
            &mut NonceState::new(),
            &mut nonce,
            MieruTransport::Udp,
            &mut FixedRandom::default(),
        );
        assert_eq!(&nonce[..6], b"CCO4C4");
        assert_eq!(
            &make_client_nonce("vole", nonce)[20..],
            &[0xbd, 0xcc, 0xc2, 0xa8]
        );
    }

    #[test]
    fn control_padding_uses_username_version_and_both_recommended_strategies() {
        assert_eq!(fixed_hash(b"alice", true), 391_071_193);
        assert_eq!(fixed_hash(b"bob", true), 1_310_367_922);
        let ascii = EffectivePattern::compile(None, host(), "bob").unwrap();
        let prepared = ascii
            .prepare_with(
                control(),
                0,
                MieruTransport::Tcp,
                usize::MAX,
                &mut FixedRandom::default(),
            )
            .unwrap();
        assert!(prepared.encoding().padding.prefix.is_empty());
        assert_eq!(prepared.encoding().padding.suffix, &[0x55; 33]);
        let entropy = EffectivePattern::compile(None, host(), "alice").unwrap();
        let mut random = FixedRandom {
            draws: VecDeque::from([200]),
            ..Default::default()
        };
        let prepared = entropy
            .prepare_with(control(), 0, MieruTransport::Tcp, usize::MAX, &mut random)
            .unwrap();
        let suffix = prepared.encoding().padding.suffix;
        assert_eq!(suffix.len(), 60);
        assert_eq!(suffix[0], 0xfe); // all 66 flips target position zero
        assert!(suffix[1..].iter().all(|byte| *byte == 0xff));
        let mut output = [0; 1];
        // x=0 gives no minimum padding. Select length one explicitly:
        // floor(2 * sqrt(0.999^3))=1, then repeat bit position zero.
        let mut random = FixedRandom {
            draws: VecDeque::from([2]),
            fraction: 0.999,
            ..Default::default()
        };
        assert_eq!(entropy_padding(&mut output, 32, 0, &mut random), 1);
        assert_eq!(output, [1]);
        assert_eq!(
            entropy_padding(&mut [], 32, 16, &mut FixedRandom::default()),
            0
        );
    }

    #[test]
    fn low_entropy_fragment_and_padding_share_the_real_udp_budget() {
        let mut pattern = EffectivePattern::compile(Some(UDP), host(), "vole").unwrap();
        for (mode, source) in [(1, 4), (2, 5), (3, 6), (4, 7)] {
            pattern.low_mode = mode;
            assert_eq!(
                pattern
                    .plaintext_fragment_limit(MieruTransport::Udp, 96)
                    .unwrap(),
                source
            );
            assert_eq!(
                pattern
                    .plaintext_fragment_limit(MieruTransport::Udp, 128)
                    .unwrap(),
                5 * source
            );
            let prepared = pattern
                .prepare_with(
                    frame(),
                    source,
                    MieruTransport::Udp,
                    96,
                    &mut FixedRandom::default(),
                )
                .unwrap();
            let BodyEncoding::LowEntropy(body) = prepared.encoding().body else {
                panic!("expected LE");
            };
            assert_eq!(body.half_mask.count_ones(), 12 + u32::from(mode) * 4);
            assert_eq!(body.encoded_len(source).unwrap(), 8);
            assert!(
                pattern
                    .prepare_frame(frame(), source + 1, MieruTransport::Udp, 96)
                    .is_err()
            );
        }
        pattern.low_mode = 1;
        assert_eq!(
            pattern
                .plaintext_fragment_limit(MieruTransport::Tcp, usize::MAX)
                .unwrap(),
            32_764
        );
        assert!(
            pattern
                .plaintext_fragment_limit(MieruTransport::Udp, 95)
                .is_err()
        );
        pattern.middle = 255;
        pattern.end = 255;
        let mut random = FixedRandom {
            fraction: 0.999,
            ..Default::default()
        };
        let prepared = pattern
            .prepare_with(frame(), 4, MieruTransport::Udp, 128, &mut random)
            .unwrap();
        let encoding = prepared.encoding();
        assert!(
            PACKET_OVERHEAD
                + encoding.body.encoded_len(4).unwrap()
                + encoding.padding.prefix.len()
                + encoding.padding.suffix.len()
                <= 128
        );
    }

    #[test]
    fn control_fragment_ranges_and_final_delay_follow_the_physical_write() {
        let pattern = EffectivePattern::compile(Some(TCP), host(), "vole").unwrap();
        let mut chunks = pattern.control_chunks(100);
        chunks.max_sleep_ms = 100;
        let mut random = FixedRandom {
            draws: (0..10).flat_map(|_| [0, 7]).collect(),
            ..Default::default()
        };
        let mut end = 0;
        let mut count = 0;
        while let Some(chunk) = chunks.next_with(&mut random) {
            assert_eq!(chunk.range.start, end);
            assert_eq!(chunk.delay_after, Duration::from_millis(7));
            end = chunk.range.end;
            count += 1;
        }
        assert_eq!((end, count), (100, 10));
        let default = EffectivePattern::compile(None, host(), "vole").unwrap();
        let chunks: Vec<_> = default.control_chunks(100).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].range, 0..100);
        assert_eq!(chunks[0].delay_after, Duration::ZERO);
    }
}
