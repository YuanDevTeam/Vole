//! Content decoding into caller-owned bounded buffers. No recompression or
//! hidden buffering adapters are used; successful rewrites emit identity.
use super::{Budget, BudgetedBytes, Bypass, Encoding, MAX_BODY};
use brotli::{Allocator, SliceWrapper, SliceWrapperMut};
use flate2::{Decompress, FlushDecompress, Status};
use std::{
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const CODEC: usize = 256 * 1024;
const CHUNK: usize = 8192;

pub(super) fn decode(
    input: &[u8],
    encoding: Encoding,
    budget: &Budget,
) -> Result<Option<BudgetedBytes>, Bypass> {
    if encoding == Encoding::Identity {
        return Ok(None);
    }
    if encoding == Encoding::Unsupported {
        return Err(Bypass::Encoding);
    }
    let _workspace = budget.reserve(CODEC).ok_or(Bypass::Budget)?;
    let mut output = BudgetedBytes::new(budget, MAX_BODY).ok_or(Bypass::Budget)?;
    match encoding {
        Encoding::Gzip => gzip(input, &mut output)?,
        Encoding::Deflate => {
            let consumed = inflate(input, true, &mut output)?;
            if consumed != input.len() {
                return Err(Bypass::Transform);
            }
        }
        Encoding::Brotli => brotli(input, &mut output)?,
        _ => return Err(Bypass::Encoding),
    }
    Ok(Some(output))
}

fn inflate(input: &[u8], zlib: bool, output: &mut BudgetedBytes) -> Result<usize, Bypass> {
    // The locked flate2 rust_backend uses miniz_oxide's fixed InflateState.
    // CODEC covers it, this stack chunk, and decoder bookkeeping before new().
    let mut decoder = Decompress::new(zlib);
    let mut buffer = [0u8; CHUNK];
    loop {
        let start_in = decoder.total_in();
        let start_out = decoder.total_out();
        let status = decoder
            .decompress(
                &input[start_in as usize..],
                &mut buffer,
                FlushDecompress::None,
            )
            .map_err(|_| Bypass::Transform)?;
        let produced = (decoder.total_out() - start_out) as usize;
        output
            .extend(&buffer[..produced])
            .map_err(|_| Bypass::Size)?;
        if status == Status::StreamEnd {
            return Ok(decoder.total_in() as usize);
        }
        if start_in == decoder.total_in() && produced == 0 {
            return Err(Bypass::Transform);
        }
    }
}

fn gzip(mut input: &[u8], output: &mut BudgetedBytes) -> Result<(), Bypass> {
    if input.is_empty() {
        return Err(Bypass::Transform);
    }
    while !input.is_empty() {
        if input.len() < 10 || input[..3] != [0x1f, 0x8b, 8] || input[3] & 0xe0 != 0 {
            return Err(Bypass::Transform);
        }
        let flags = input[3];
        let mut at = 10usize;
        if flags & 4 != 0 {
            let extra = input.get(at..at + 2).ok_or(Bypass::Transform)?;
            at += 2 + u16::from_le_bytes([extra[0], extra[1]]) as usize;
            if at > input.len() {
                return Err(Bypass::Transform);
            }
        }
        for flag in [8, 16] {
            if flags & flag != 0 {
                at += input
                    .get(at..)
                    .ok_or(Bypass::Transform)?
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(Bypass::Transform)?
                    + 1;
            }
        }
        if flags & 2 != 0 {
            let crc = input.get(at..at + 2).ok_or(Bypass::Transform)?;
            if u16::from_le_bytes([crc[0], crc[1]]) != crc32fast::hash(&input[..at]) as u16 {
                return Err(Bypass::Transform);
            }
            at += 2;
        }
        let before = output.as_ref().len();
        let consumed = inflate(input.get(at..).ok_or(Bypass::Transform)?, false, output)?;
        at = at.checked_add(consumed).ok_or(Bypass::Transform)?;
        let trailer = input.get(at..at + 8).ok_or(Bypass::Transform)?;
        let crc = u32::from_le_bytes(trailer[..4].try_into().expect("four bytes"));
        let size = u32::from_le_bytes(trailer[4..].try_into().expect("four bytes"));
        let member = &output.as_ref()[before..];
        if crc != crc32fast::hash(member) || size != member.len() as u32 {
            return Err(Bypass::Transform);
        }
        input = &input[at + 8..];
    }
    Ok(())
}

struct Pool {
    used: AtomicUsize,
    failed: AtomicBool,
}
impl Pool {
    fn reserve(&self, bytes: usize) -> bool {
        let success = self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|used| *used <= CODEC)
            })
            .is_ok();
        if !success {
            self.failed.store(true, Ordering::Release);
        }
        success
    }
}
struct Alloc<T> {
    pool: Arc<Pool>,
    marker: PhantomData<T>,
}
impl<T> Alloc<T> {
    fn new(pool: &Arc<Pool>) -> Self {
        Self {
            pool: pool.clone(),
            marker: PhantomData,
        }
    }
}
struct Cell<T> {
    values: Vec<T>,
    pool: Option<Arc<Pool>>,
    charged: usize,
}
impl<T> Default for Cell<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            pool: None,
            charged: 0,
        }
    }
}
impl<T> SliceWrapper<T> for Cell<T> {
    fn slice(&self) -> &[T] {
        &self.values
    }
}
impl<T> SliceWrapperMut<T> for Cell<T> {
    fn slice_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}
impl<T> Drop for Cell<T> {
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            pool.used.fetch_sub(self.charged, Ordering::AcqRel);
        }
    }
}
impl<T: Default> Allocator<T> for Alloc<T> {
    type AllocatedMemory = Cell<T>;
    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        if len == 0 {
            return Cell::default();
        }
        let Some(bytes) = len
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Cell<T>>()))
        else {
            self.pool.failed.store(true, Ordering::Release);
            return Cell::default();
        };
        if !self.pool.reserve(bytes) {
            return Cell::default();
        }
        let mut result = Cell {
            values: Vec::new(),
            pool: Some(self.pool.clone()),
            charged: bytes,
        };
        if result.values.try_reserve_exact(len).is_err() || result.values.capacity() > len {
            self.pool.failed.store(true, Ordering::Release);
            return Cell::default();
        }
        result.values.resize_with(len, T::default);
        result
    }
    fn free_cell(&mut self, value: Self::AllocatedMemory) {
        drop(value);
    }
}

fn brotli(input: &[u8], output: &mut BudgetedBytes) -> Result<(), Bypass> {
    type State = brotli::BrotliState<Alloc<u8>, Alloc<u32>, Alloc<brotli::HuffmanCode>>;
    let pool = Arc::new(Pool {
        used: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
    });
    if !pool.reserve(std::mem::size_of::<State>() + CHUNK + std::mem::size_of::<Pool>() + 64) {
        return Err(Bypass::Budget);
    }
    let mut state = State::new_strict(Alloc::new(&pool), Alloc::new(&pool), Alloc::new(&pool));
    // This constructor allocation precedes the upstream decoder's error path.
    // Our allocator returns either the entire cell or an empty failure cell.
    if state.context_map_table.slice().is_empty() {
        return Err(Bypass::Budget);
    }
    let mut at = 0;
    let mut total = 0;
    let mut buffer = [0u8; CHUNK];
    loop {
        let before = at;
        let mut available_in = input.len() - at;
        let mut available_out = buffer.len();
        let mut produced = 0;
        let result = brotli::BrotliDecompressStream(
            &mut available_in,
            &mut at,
            input,
            &mut available_out,
            &mut produced,
            &mut buffer,
            &mut total,
            &mut state,
        );
        output
            .extend(&buffer[..produced])
            .map_err(|_| Bypass::Size)?;
        match result {
            brotli::BrotliResult::ResultSuccess if at == input.len() => return Ok(()),
            brotli::BrotliResult::NeedsMoreOutput if produced != 0 => {}
            brotli::BrotliResult::NeedsMoreInput if at < input.len() && at != before => {}
            _ if pool.failed.load(Ordering::Acquire) => return Err(Bypass::Budget),
            _ => return Err(Bypass::Transform),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn codecs_decode_and_reject_truncation_or_invalid_trailers() {
        let budget = Budget::default();
        let input = b"bounded UTF-8 body";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(input).unwrap();
        let mut gzip = gzip.finish().unwrap();
        assert_eq!(
            decode(&gzip, Encoding::Gzip, &budget)
                .unwrap()
                .unwrap()
                .as_ref(),
            input
        );
        gzip.pop();
        assert!(decode(&gzip, Encoding::Gzip, &budget).is_err());
        let mut deflate =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        deflate.write_all(input).unwrap();
        assert_eq!(
            decode(&deflate.finish().unwrap(), Encoding::Deflate, &budget)
                .unwrap()
                .unwrap()
                .as_ref(),
            input
        );
        let mut encoded = Vec::new();
        brotli::BrotliCompress(
            &mut input.as_slice(),
            &mut encoded,
            &brotli::enc::BrotliEncoderParams::default(),
        )
        .unwrap();
        assert_eq!(
            decode(&encoded, Encoding::Brotli, &budget)
                .unwrap()
                .unwrap()
                .as_ref(),
            input
        );
        assert_eq!(
            decode(b"\x0b\x05\x80old=1 old=2\x03", Encoding::Brotli, &budget)
                .unwrap()
                .unwrap()
                .as_ref(),
            b"old=1 old=2"
        );
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn compressed_expansion_and_allocator_failure_are_bounded() {
        let budget = Budget::default();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&vec![b'a'; MAX_BODY + 1]).unwrap();
        assert!(matches!(
            decode(&gzip.finish().unwrap(), Encoding::Gzip, &budget),
            Err(Bypass::Size)
        ));
        let pool = Arc::new(Pool {
            used: AtomicUsize::new(CODEC),
            failed: AtomicBool::new(false),
        });
        assert!(Alloc::<u32>::new(&pool).alloc_cell(1).slice().is_empty());
        assert!(pool.failed.load(Ordering::Acquire));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn upstream_brotli_allocation_failure_is_a_decoder_error() {
        let input = b"allocator failure must preserve the raw compressed response";
        let mut encoded = Vec::new();
        brotli::BrotliCompress(
            &mut input.as_slice(),
            &mut encoded,
            &brotli::enc::BrotliEncoderParams::default(),
        )
        .unwrap();
        let pool = Arc::new(Pool {
            used: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
        });
        let mut state = brotli::BrotliState::new_strict(
            Alloc::<u8>::new(&pool),
            Alloc::<u32>::new(&pool),
            Alloc::<brotli::HuffmanCode>::new(&pool),
        );
        assert!(!state.context_map_table.slice().is_empty());
        pool.used.store(CODEC, Ordering::Release);
        let mut available_in = encoded.len();
        let mut input_offset = 0;
        let mut available_out = 1024;
        let mut output_offset = 0;
        let mut total = 0;
        let result = brotli::BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            &encoded,
            &mut available_out,
            &mut output_offset,
            &mut [0; 1024],
            &mut total,
            &mut state,
        );
        assert!(matches!(result, brotli::BrotliResult::ResultFailure));
        assert!(pool.failed.load(Ordering::Acquire));
    }
}
