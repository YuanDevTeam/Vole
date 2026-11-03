//! Independent admission parser for the public 7z header format.
//! Inspects the same opened source used by the official archive decoder.
use std::{
    io::{self, Read, Seek, SeekFrom},
    time::{Duration, Instant},
};

const HEADER_BYTES: u64 = 128 * 1024;
const HEADER_PACKED: u64 = 16 * 1024 * 1024;
const DECODER_BYTES: u64 = 96 * 1024 * 1024;
const METADATA_AMPLIFICATION: u64 = 1024;
const MAX_CODERS: usize = 8;
const SIGNATURE: &[u8; 6] = b"7z\xbc\xaf\x27\x1c";

#[derive(Debug, Clone, Copy)]
pub struct Admission {
    pub file_len: u64,
    pub metadata_bytes: u64,
}

/// One opened handle for inspection and decode. Cooperative cancellation is
/// checked inside decoder reads, never by discarding a blocking JoinHandle.
pub struct CheckedSource<'a, R> {
    inner: R,
    length: u64,
    read_bytes: u64,
    operations: u32,
    deadline: Instant,
    cancelled: &'a dyn Fn() -> bool,
}
impl<'a, R: Read + Seek> CheckedSource<'a, R> {
    pub fn new(mut inner: R, cancelled: &'a dyn Fn() -> bool) -> io::Result<Self> {
        let length = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;
        Ok(Self {
            inner,
            length,
            read_bytes: 0,
            operations: 0,
            deadline: Instant::now() + Duration::from_secs(30),
            cancelled,
        })
    }
    pub(super) fn check(&mut self) -> io::Result<()> {
        // Interrupted is deliberately avoided: Read::read_exact retries it.
        if (self.cancelled)() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        if Instant::now() >= self.deadline || self.operations >= 65536 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.operations += 1;
        Ok(())
    }
}
impl<R: Read + Seek> Read for CheckedSource<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining = (256 * 1024 * 1024u64)
            .checked_sub(self.read_bytes)
            .ok_or_else(invalid)?;
        if remaining == 0 {
            return Err(invalid());
        }
        let length = bytes.len().min(8192).min(remaining as usize);
        let read = self.inner.read(&mut bytes[..length])?;
        self.read_bytes = add(self.read_bytes, read as u64)?;
        Ok(read)
    }
}
impl<R: Read + Seek> Seek for CheckedSource<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.check()?;
        let absolute = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
            SeekFrom::Current(offset) => {
                i128::from(self.inner.stream_position()?) + i128::from(offset)
            }
        };
        if absolute < 0 || absolute > i128::from(self.length) {
            return Err(invalid());
        }
        self.inner.seek(SeekFrom::Start(absolute as u64))
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "rule bundle failed admission")
}

fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b).ok_or_else(invalid)
}

/// Validate signature, both CRCs and any encoded-header decoder before
/// permitting the official library to instantiate its header decoder.
pub fn inspect(reader: &mut (impl Read + Seek)) -> io::Result<Admission> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    let mut signature = [0u8; 32];
    reader.read_exact(&mut signature)?;
    if &signature[..6] != SIGNATURE || signature[6] != 0 {
        return Err(invalid());
    }
    let number = |offset| u64::from_le_bytes(signature[offset..offset + 8].try_into().unwrap());
    let crc = u32::from_le_bytes(signature[8..12].try_into().unwrap());
    if crc32fast::hash(&signature[12..]) != crc {
        return Err(invalid());
    }
    let offset = add(32, number(12))?;
    let size = number(20);
    if size == 0 || size > HEADER_BYTES || add(offset, size)? > file_len {
        return Err(invalid());
    }
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; size as usize];
    reader.read_exact(&mut bytes)?;
    if crc32fast::hash(&bytes) != u32::from_le_bytes(signature[28..32].try_into().unwrap()) {
        return Err(invalid());
    }
    let mut input = Input(&bytes);
    let metadata_bytes = match input.byte()? {
        1 => add(8 * 1024 * 1024, size * METADATA_AMPLIFICATION)?,
        23 => encoded_header(&mut input, file_len)?,
        _ => return Err(invalid()),
    };
    if metadata_bytes > DECODER_BYTES {
        return Err(invalid());
    }
    reader.seek(SeekFrom::Start(0))?;
    Ok(Admission {
        file_len,
        metadata_bytes,
    })
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn bytes(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let (part, remainder) = self.0.split_at_checked(n).ok_or_else(invalid)?;
        self.0 = remainder;
        Ok(part)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    fn expect(&mut self, value: u8) -> io::Result<()> {
        if self.byte()? == value {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    // 7z integers carry low bytes after a prefix byte, not LEB128.
    fn integer(&mut self) -> io::Result<u64> {
        let prefix = self.byte()?;
        let mut value = 0;
        for count in 0..8 {
            let mask = 0x80u8 >> count;
            if prefix & mask == 0 {
                value |= u64::from(prefix & (mask - 1)) << (count * 8);
                return Ok(value);
            }
            value |= u64::from(self.byte()?) << (count * 8);
        }
        Ok(value)
    }
    fn count(&mut self, maximum: usize) -> io::Result<usize> {
        usize::try_from(self.integer()?)
            .ok()
            .filter(|n| *n <= maximum)
            .ok_or_else(invalid)
    }
    fn crc(&mut self, count: usize) -> io::Result<usize> {
        let all = self.byte()?;
        let present = if all == 0 {
            self.bytes(count.div_ceil(8))?
                .iter()
                .enumerate()
                .map(|(index, byte)| {
                    let remaining = count.saturating_sub(index * 8).min(8);
                    (byte & (0xff << (8 - remaining))).count_ones() as usize
                })
                .sum()
        } else if all == 1 {
            count
        } else {
            return Err(invalid());
        };
        self.bytes(present * 4)?;
        Ok(present)
    }
}

fn encoded_header(input: &mut Input<'_>, file_len: u64) -> io::Result<u64> {
    input.expect(6)?; // PackInfo
    let offset = add(32, input.integer()?)?;
    // Metadata headers only require a single packed stream. Additional
    // archived codecs/forms can later be audited without expanding admission.
    if input.count(1)? != 1 {
        return Err(invalid());
    }
    input.expect(9)?;
    let packed = input.integer()?;
    if packed > HEADER_PACKED || add(offset, packed)? > file_len {
        return Err(invalid());
    }
    let mut tag = input.byte()?;
    if tag == 10 {
        input.crc(1)?;
        tag = input.byte()?;
    }
    if tag != 0 {
        return Err(invalid());
    }
    input.expect(7)?; // UnpackInfo
    input.expect(11)?; // Folder
    if input.count(1)? != 1 {
        return Err(invalid());
    }
    input.expect(0)?; // no external folder metadata
    let coders = input.count(MAX_CODERS)?;
    if coders == 0 {
        return Err(invalid());
    }
    let mut memory = 8 * 1024 * 1024;
    for _ in 0..coders {
        let descriptor = input.byte()?;
        let id_length = usize::from(descriptor & 15);
        if id_length == 0 || descriptor & 0xc0 != 0 {
            return Err(invalid());
        }
        let method = input.bytes(id_length)?;
        if descriptor & 16 != 0 && (input.integer()? != 1 || input.integer()? != 1) {
            return Err(invalid());
        }
        let properties = if descriptor & 32 != 0 {
            let length = input.count(16)?;
            input.bytes(length)?
        } else {
            &[]
        };
        memory = add(memory, codec_memory(method, properties)?)?;
    }
    let mut inputs = 0u16;
    let mut outputs = 0u16;
    for _ in 1..coders {
        let source = input.count(coders - 1)?;
        let destination = input.count(coders - 1)?;
        let source = 1u16 << source;
        let destination = 1u16 << destination;
        if inputs & source != 0 || outputs & destination != 0 {
            return Err(invalid());
        }
        inputs |= source;
        outputs |= destination;
    }
    input.expect(12)?; // CodersUnpackSize
    let mut unpacked = 0;
    for _ in 0..coders {
        let size = input.integer()?;
        if size > HEADER_BYTES {
            return Err(invalid());
        }
        unpacked = unpacked.max(size);
        memory = add(memory, size)?;
    }
    memory = add(memory, unpacked * METADATA_AMPLIFICATION)?;
    if memory > DECODER_BYTES {
        return Err(invalid());
    }
    let mut tag = input.byte()?;
    let has_folder_crc = if tag == 10 {
        let present = input.crc(1)?;
        tag = input.byte()?;
        present != 0
    } else {
        false
    };
    if tag != 0 {
        return Err(invalid());
    }
    // With one folder and one substream the CRC can reside in UnpackInfo.
    let tag = input.byte()?;
    if tag == 8 {
        let mut tag = input.byte()?;
        if tag == 13 {
            if input.count(1)? != 1 {
                return Err(invalid());
            }
            tag = input.byte()?;
        }
        if tag == 10 {
            input.crc(usize::from(!has_folder_crc))?;
            tag = input.byte()?;
        }
        if tag != 0 {
            return Err(invalid());
        }
        input.expect(0)?;
    } else if tag != 0 {
        return Err(invalid());
    }
    if !input.0.is_empty() {
        return Err(invalid());
    }
    Ok(memory)
}

fn codec_memory(method: &[u8], props: &[u8]) -> io::Result<u64> {
    // These constants describe publicly specified codec identifiers/properties.
    match method {
        [0] if props.is_empty() => Ok(64 * 1024), // COPY
        [0x21] if props.len() == 1 && props[0] <= 40 => {
            let property = props[0];
            let dictionary = if property == 40 {
                u32::MAX as u64
            } else {
                (2u64 | u64::from(property & 1)) << (property / 2 + 11)
            };
            add(dictionary, 2 * 1024 * 1024)
        }
        [3, 1, 1] if props.len() == 5 && props[0] < 225 => {
            let lc = u32::from(props[0] % 9);
            let lp = u32::from(props[0] / 9 % 5);
            let dictionary =
                u64::from(u32::from_le_bytes(props[1..].try_into().unwrap())).max(4096);
            add(
                add(dictionary, (0x300u64 << (lc + lp)) * 2)?,
                2 * 1024 * 1024,
            )
        }
        [3, 3, 1, 3] | [3, 3, 5, 1] | [3, 3, 7, 1] if props.is_empty() || props.len() == 4 => {
            Ok(64 * 1024)
        } // BCJ filters
        [3] if props.len() == 1 => Ok(64 * 1024), // Delta
        _ => Err(invalid()),
    }
}

/// Validate the selected solid block before member decoder construction.
pub fn inspect_block(
    archive: &sevenz_rust2::Archive,
    index: usize,
    admission: Admission,
    retained_bytes: u64,
) -> io::Result<()> {
    let block = archive.blocks.get(index).ok_or_else(invalid)?;
    if block.coders.is_empty() || block.coders.len() > MAX_CODERS || archive.files.len() > 4096 {
        return Err(invalid());
    }
    let mut memory = add(admission.metadata_bytes, retained_bytes)?;
    let mut visited = 0u16;
    for (coder_index, _) in block.ordered_coder_iter() {
        let bit = 1u16 << coder_index;
        if visited & bit != 0 {
            return Err(invalid());
        }
        visited |= bit;
    }
    if visited.count_ones() as usize != block.coders.len() {
        return Err(invalid());
    }
    for (index, coder) in block.coders.iter().enumerate() {
        memory = add(
            memory,
            codec_memory(coder.encoder_method_id(), coder.properties())?,
        )?;
        if block.get_unpack_size_at_index(index) > 256 * 1024 * 1024 {
            return Err(invalid());
        }
    }
    if memory > DECODER_BYTES {
        return Err(invalid());
    }
    let first = *archive
        .stream_map
        .block_first_pack_stream_index()
        .get(index)
        .ok_or_else(invalid)?;
    let after = archive
        .stream_map
        .block_first_pack_stream_index()
        .get(index + 1)
        .copied()
        .unwrap_or(archive.pack_sizes().len());
    if after.checked_sub(first) != Some(1) {
        return Err(invalid());
    }
    // Only one packed input and an acyclic chain of audited codecs proceed.
    // The library additionally rejects non-1:1 coder descriptors before decode.
    let packed = *archive.pack_sizes().get(first).ok_or_else(invalid)?;
    if packed > 128 * 1024 * 1024 {
        return Err(invalid());
    }
    let relative = archive.pack_sizes()[..first]
        .iter()
        .try_fold(archive.pack_pos(), |sum, n| add(sum, *n))?;
    if add(add(32, relative)?, packed)? > admission.file_len {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_encoded_header_dictionary_fails_before_a_decoder_exists() {
        // Public 7z encoded-header shape, no library decoder constructed here.
        let wire = [
            6, 0, 1, 9, 1, 0, 7, 11, 1, 0, 1, 0x21, 0x21, 1, 40, 12, 1, 0, 0,
        ];
        assert!(encoded_header(&mut Input(&wire), 33).is_err());
        let mut safe = wire;
        safe[14] = 0;
        assert!(encoded_header(&mut Input(&safe), 33).is_ok());
    }
}
