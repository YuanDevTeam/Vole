//! Bounded wire-format filtering for a single protobuf message.
use super::{Budget, BudgetedBytes, Bypass};
use crate::http_processing::config::invalid;
use serde::Deserialize;
use std::{collections::BTreeMap, io};

const MAX_FIELD: u32 = (1 << 29) - 1;
const MAX_PATHS: usize = 32;
const MAX_DEPTH: usize = 8;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MediaType {
    #[serde(rename = "application/protobuf")]
    Protobuf,
    #[serde(rename = "application/x-protobuf")]
    XProtobuf,
    #[serde(rename = "application/octet-stream")]
    OctetStream,
}

impl MediaType {
    pub(super) fn parse(media: &str, field: &str) -> Option<Self> {
        let media = match media {
            "application/protobuf" => Self::Protobuf,
            "application/x-protobuf" => Self::XProtobuf,
            "application/octet-stream" => Self::OctetStream,
            _ => return None,
        };
        let mut quoted = false;
        let mut bytes = field.bytes();
        while let Some(byte) = bytes.next() {
            match byte {
                b'"' => quoted = !quoted,
                b'\\' if quoted => {
                    bytes.next()?;
                }
                b',' if !quoted => return None,
                _ => {}
            }
        }
        (!quoted).then_some(media)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct ProtobufRemoveSpec {
    paths: Vec<Vec<u32>>,
    #[serde(default = "default_media_types")]
    media_types: Vec<MediaType>,
}

fn default_media_types() -> Vec<MediaType> {
    vec![MediaType::Protobuf, MediaType::XProtobuf]
}

type Fields = BTreeMap<u32, Path>;

enum Path {
    Remove,
    Descend(Fields),
}

pub(crate) struct ProtobufRemove {
    fields: Fields,
    media_types: u8,
}

impl ProtobufRemove {
    pub(crate) fn compile(spec: ProtobufRemoveSpec) -> io::Result<(Self, usize)> {
        if spec.paths.is_empty()
            || spec.paths.len() > MAX_PATHS
            || spec.media_types.is_empty()
            || spec.media_types.len() > 3
        {
            return Err(invalid());
        }
        let mut cost = spec.media_types.len();
        let mut media_types = 0;
        for media in spec.media_types {
            if media_types & media.bit() != 0 {
                return Err(invalid());
            }
            media_types |= media.bit();
        }
        let mut fields = Fields::new();
        for path in spec.paths {
            if path.len() > MAX_DEPTH {
                return Err(invalid());
            }
            cost += path.len() * size_of::<u32>();
            insert(&mut fields, &path)?;
        }
        Ok((
            Self {
                fields,
                media_types,
            },
            cost,
        ))
    }

    pub(super) fn matches(&self, media: Option<MediaType>) -> bool {
        media.is_some_and(|media| self.media_types & media.bit() != 0)
    }

    pub(super) fn apply(
        &self,
        input: &[u8],
        budget: &Budget,
    ) -> Result<Option<BudgetedBytes>, Bypass> {
        let length = rewrite(input, &self.fields, None)?;
        if length == input.len() {
            return Ok(None);
        }
        let mut output = BudgetedBytes::new(budget, length).ok_or(Bypass::Budget)?;
        rewrite(input, &self.fields, Some(&mut output))?;
        Ok(Some(output))
    }
}

fn insert(fields: &mut Fields, path: &[u32]) -> io::Result<()> {
    let (&field, suffix) = path.split_first().ok_or_else(invalid)?;
    if !(1..=MAX_FIELD).contains(&field) {
        return Err(invalid());
    }
    match (fields.entry(field), suffix.is_empty()) {
        (std::collections::btree_map::Entry::Vacant(entry), true) => {
            entry.insert(Path::Remove);
            Ok(())
        }
        (entry, false) => match entry.or_insert_with(|| Path::Descend(Fields::new())) {
            Path::Descend(fields) => insert(fields, suffix),
            Path::Remove => Err(invalid()),
        },
        _ => Err(invalid()),
    }
}

fn varint(input: &mut &[u8]) -> Result<u64, Bypass> {
    let mut value = 0;
    for shift in (0..=63).step_by(7) {
        let (&byte, remaining) = input.split_first().ok_or(Bypass::Transform)?;
        *input = remaining;
        if shift == 63 && byte > 1 {
            return Err(Bypass::Transform);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err(Bypass::Transform)
}

fn take<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8], Bypass> {
    let (value, remaining) = input.split_at_checked(size).ok_or(Bypass::Transform)?;
    *input = remaining;
    Ok(value)
}

fn encode_length(mut length: usize, output: &mut [u8; 3]) -> &[u8] {
    let mut written = 0;
    loop {
        let byte = length as u8 & 0x7f;
        length >>= 7;
        output[written] = if length == 0 { byte } else { byte | 0x80 };
        written += 1;
        if length == 0 {
            return &output[..written];
        }
    }
}

fn write(output: &mut BudgetedBytes, bytes: &[u8]) -> Result<(), Bypass> {
    output.extend(bytes).map_err(|_| Bypass::Size)
}

// Sizing never allocates. When emitting, size a changed child before writing
// its prefix. A byte can be rescanned at most once per configured depth.
fn rewrite(
    mut input: &[u8],
    fields: &Fields,
    mut output: Option<&mut BudgetedBytes>,
) -> Result<usize, Bypass> {
    let mut length = 0;
    while !input.is_empty() {
        let start = input;
        let tag = u32::try_from(varint(&mut input)?).map_err(|_| Bypass::Transform)?;
        let field = tag >> 3;
        if field == 0 {
            return Err(Bypass::Transform);
        }
        let tag_bytes = &start[..start.len() - input.len()];
        let payload = match tag & 7 {
            0 => {
                varint(&mut input)?;
                None
            }
            1 => {
                take(&mut input, 8)?;
                None
            }
            2 => {
                let size = usize::try_from(varint(&mut input)?).map_err(|_| Bypass::Transform)?;
                Some(take(&mut input, size)?)
            }
            5 => {
                take(&mut input, 4)?;
                None
            }
            _ => return Err(Bypass::Transform),
        };
        match fields.get(&field) {
            Some(Path::Remove) => continue,
            Some(Path::Descend(children)) => {
                let payload = payload.ok_or(Bypass::Transform)?;
                let child_length = rewrite(payload, children, None)?;
                if child_length != payload.len() {
                    // A child is bounded by the 256 KiB entity limit.
                    let mut encoded = [0; 3];
                    let prefix = encode_length(child_length, &mut encoded);
                    length += tag_bytes.len() + prefix.len() + child_length;
                    if let Some(output) = output.as_deref_mut() {
                        write(output, tag_bytes)?;
                        write(output, prefix)?;
                        rewrite(payload, children, Some(output))?;
                    }
                    continue;
                }
            }
            None => {}
        }
        let unchanged = &start[..start.len() - input.len()];
        length += unchanged.len();
        if let Some(output) = output.as_deref_mut() {
            write(output, unchanged)?;
        }
    }
    Ok(length)
}
