//! Verified country MMDBs, with selective compact indexes for Meta records.

use std::{fmt, io::Read, net::IpAddr, path::Path};

use maxminddb::{MaxMindDbError, Metadata, Reader, WithinOptions};
use serde::{
    Deserialize,
    de::{self, SeqAccess, Visitor},
};

use super::{
    AllocationLedger, Cidr4, Cidr6, Code, GeoDataError, GeoDataKind, IpCategory, compact_v4,
    compact_v6, compact_vec, ensure_vec_capacity, open_asset_path, selector_code,
};

const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
const METADATA_HEADROOM: usize = 512;
const EMPTY_DESCRIPTION: &str = "description - Expected: non-empty map Actual: {}";

#[derive(Debug, Clone, Copy)]
enum Format {
    MaxMind,
    Sing,
    Meta,
}

impl Format {
    fn parse(value: &str) -> Self {
        match value {
            "sing-geoip" => Self::Sing,
            "Meta-geoip0" => Self::Meta,
            _ => Self::MaxMind,
        }
    }
}

pub(super) struct CountryDb {
    storage: Storage,
    selectors: Vec<String>,
    capacity: usize,
}

enum Storage {
    Reader {
        reader: Reader<Vec<u8>>,
        format: Format,
    },
    Meta {
        categories: Vec<IpCategory>,
        ipv6: bool,
    },
}

impl CountryDb {
    pub(super) fn load(path: &Path, selectors: &[String]) -> Result<Self, GeoDataError> {
        CountryCandidate::load(path)?.into_database(selectors)
    }

    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(super) fn available(&self, selector: &str) -> bool {
        self.selectors
            .binary_search_by(|value| {
                value
                    .bytes()
                    .cmp(selector.bytes().map(|byte| byte.to_ascii_lowercase()))
            })
            .is_ok()
    }

    pub(super) fn matches(&self, selector: &str, address: IpAddr) -> bool {
        if !self.available(selector) {
            return false;
        }
        let code = selector_code(selector);
        let (reader, format) = match &self.storage {
            Storage::Reader { reader, format } => (reader, format),
            Storage::Meta { categories, ipv6 } => {
                // Reader rejects IPv6 queries against IPv4-only databases,
                // including inverse selectors. This is not a no-record result.
                if !ipv6 && address.is_ipv6() {
                    return false;
                }
                let matched = categories
                    .binary_search_by(|category| category.code.cmp_str(code))
                    .ok()
                    .is_some_and(|at| categories[at].matches(address));
                return matched != selector.starts_with('!');
            }
        };
        let Ok(record) = reader.lookup(address) else {
            return false;
        };
        let matched = match format {
            Format::MaxMind => {
                match record.decode_path::<&str>(&maxminddb::path!["country", "iso_code"]) {
                    Ok(value) => value.is_some_and(|value| value.eq_ignore_ascii_case(code)),
                    Err(_) => return false,
                }
            }
            Format::Sing => match record.decode::<&str>() {
                Ok(value) => value.is_some_and(|value| canonical_code_matches(value, code)),
                Err(_) => return false,
            },
            Format::Meta => match record.decode::<BorrowedCodes<'_>>() {
                Ok(Some(BorrowedCodes::One(value))) => canonical_code_matches(value, code),
                Ok(Some(BorrowedCodes::Many(values))) => values
                    .iter()
                    .any(|value| canonical_code_matches(value, code)),
                Ok(None) => false,
                Err(_) => return false,
            },
        };
        matched != selector.starts_with('!')
    }
}

// Only string references are materialized for Meta's multi-code records. No
// country strings, full MaxMind maps or per-address cache survive the lookup.
enum BorrowedCodes<'a> {
    One(&'a str),
    Many(Vec<&'a str>),
}

impl<'de> Deserialize<'de> for BorrowedCodes<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CodesVisitor;
        impl<'de> Visitor<'de> for CodesVisitor {
            type Value = BorrowedCodes<'de>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a country code or an array of country codes")
            }
            fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
                Ok(BorrowedCodes::One(value))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<&'de str>()? {
                    values
                        .try_reserve(1)
                        .map_err(|_| de::Error::custom("country code allocation failed"))?;
                    values.push(value);
                }
                Ok(BorrowedCodes::Many(values))
            }
        }
        deserializer.deserialize_any(CodesVisitor)
    }
}

/// Full index/data verification borrows the candidate bytes while the old
/// reader remains usable. Ownership transfers after old readers are drained.
pub(super) struct CountryCandidate {
    bytes: Vec<u8>,
    format: Format,
}

impl CountryCandidate {
    pub(super) fn load(path: &Path) -> Result<Self, GeoDataError> {
        let (mut file, len) = open_asset_path(path)?;
        let len = usize::try_from(len)
            .map_err(|_| GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        let capacity = len
            .checked_add(METADATA_HEADROOM)
            .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| GeoDataError::AllocationFailed { bytes: capacity })?;
        bytes.resize(len, 0);
        file.read_exact(&mut bytes)
            .map_err(|source| GeoDataError::Io {
                path: path.into(),
                source,
            })?;
        verify_country_mmdb(&mut bytes)?;
        let format = {
            let reader = Reader::from_source(bytes.as_slice())
                .map_err(|_| invalid("invalid country MMDB"))?;
            Format::parse(&reader.metadata().database_type)
        };
        Ok(Self { bytes, format })
    }

    pub(super) fn into_database(self, selectors: &[String]) -> Result<CountryDb, GeoDataError> {
        let mut stored = Vec::new();
        stored
            .try_reserve_exact(selectors.len())
            .map_err(|_| GeoDataError::AllocationFailed {
                bytes: selectors
                    .len()
                    .saturating_mul(std::mem::size_of::<String>()),
            })?;
        for selector in selectors {
            let mut value = String::new();
            value.try_reserve_exact(selector.len()).map_err(|_| {
                GeoDataError::AllocationFailed {
                    bytes: selector.len(),
                }
            })?;
            value.push_str(selector);
            stored.push(value);
        }
        stored.sort_unstable();
        let selector_capacity = stored
            .iter()
            .fold(
                stored.capacity().checked_mul(std::mem::size_of::<String>()),
                |total, value| total.and_then(|total| total.checked_add(value.capacity())),
            )
            .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        let projected = if matches!(self.format, Format::Meta) {
            match project_meta(&self.bytes, &stored) {
                Ok(projected) => projected,
                Err(GeoDataError::AllocationFailed { .. }) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let (storage, capacity) = match projected {
            Some((categories, capacity, ipv6)) => {
                // Drop the verified file after projection; it is not retained
                // alongside the selected immutable CIDRs.
                (Storage::Meta { categories, ipv6 }, capacity)
            }
            None => {
                let capacity = self.bytes.capacity();
                let reader =
                    Reader::from_source(self.bytes).map_err(|_| invalid("invalid country MMDB"))?;
                (
                    Storage::Reader {
                        reader,
                        format: self.format,
                    },
                    capacity,
                )
            }
        };
        let capacity = capacity
            .checked_add(selector_capacity)
            .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        Ok(CountryDb {
            storage,
            selectors: stored,
            capacity,
        })
    }
}

/// A representation choice, never a resource admission limit. Invalid Meta
/// record types retain Reader's per-address error behavior, and a projection
/// that is not smaller than the file retains the original reader as well.
fn project_meta(
    bytes: &[u8],
    selectors: &[String],
) -> Result<Option<(Vec<IpCategory>, usize, bool)>, GeoDataError> {
    let reader = Reader::from_source(bytes).map_err(|_| invalid("invalid country MMDB"))?;
    let ipv6 = reader.metadata().ip_version == 6;
    let mut ledger = AllocationLedger::default();
    let mut categories: Vec<IpCategory> = Vec::new();
    for selector in selectors {
        let code = Code::parse(GeoDataKind::GeoIp, selector_code(selector).as_bytes())?;
        ensure_vec_capacity(&mut categories, 1, &mut ledger)?;
        categories.push(IpCategory {
            code,
            v4: Vec::new(),
            v6: Vec::new(),
            selectors: Vec::new(),
        });
    }
    categories.sort_unstable_by_key(|category| category.code);
    categories.dedup_by_key(|category| category.code);
    compact_vec(&mut categories, &mut ledger)?;
    if ledger.used >= bytes.len() {
        return Ok(None);
    }
    let Ok(networks) = reader.networks(WithinOptions::default().include_aliased_networks()) else {
        return Ok(None);
    };
    for (visited, record) in networks.enumerate() {
        // Aliases can revisit the same verified subtree. If projection work
        // ceases to be proportional to this file, keep its compact MMDB tree.
        if visited >= bytes.len() {
            return Ok(None);
        }
        let Ok(record) = record else { return Ok(None) };
        let Ok(Some(codes)) = record.decode::<BorrowedCodes<'_>>() else {
            return Ok(None);
        };
        let Ok(network) = record.network() else {
            return Ok(None);
        };
        let codes: &[&str] = match &codes {
            BorrowedCodes::One(code) => std::slice::from_ref(code),
            BorrowedCodes::Many(codes) => codes,
        };
        for code in codes {
            // Stored Meta strings are case-sensitive. Only selectors are
            // canonicalized; an uppercase record must not gain a new match.
            let Ok(at) = categories.binary_search_by(|category| category.code.as_str().cmp(code))
            else {
                continue;
            };
            let category = &mut categories[at];
            match network.network() {
                IpAddr::V4(address) => {
                    ensure_vec_capacity(&mut category.v4, 1, &mut ledger)?;
                    category.v4.push(Cidr4 {
                        network: address.octets(),
                        prefix: network.prefix(),
                    });
                    if ipv6 {
                        // The iterator formats the ::/96 IPv4 subtree as V4.
                        // Literal IPv6 lookups in that subtree still match it.
                        ensure_vec_capacity(&mut category.v6, 1, &mut ledger)?;
                        category.v6.push(Cidr6 {
                            network: u128::from(u32::from(address)).to_be_bytes(),
                            prefix: network.prefix() + 96,
                        });
                    }
                }
                IpAddr::V6(address) => {
                    ensure_vec_capacity(&mut category.v6, 1, &mut ledger)?;
                    category.v6.push(Cidr6 {
                        network: address.octets(),
                        prefix: network.prefix(),
                    });
                    if address.is_unspecified() && network.prefix() <= 96 {
                        // A data leaf above the IPv4 subtree answers every V4
                        // lookup, while remaining a V6 CIDR for V6 lookups.
                        ensure_vec_capacity(&mut category.v4, 1, &mut ledger)?;
                        category.v4.push(Cidr4 {
                            network: [0; 4],
                            prefix: 0,
                        });
                    }
                }
            }
        }
        if ledger.used >= bytes.len() {
            compact_projection(&mut categories, &mut ledger)?;
            if ledger.used >= bytes.len() {
                return Ok(None);
            }
        }
    }
    compact_projection(&mut categories, &mut ledger)?;
    compact_vec(&mut categories, &mut ledger)?;
    Ok((ledger.used < bytes.len()).then_some((categories, ledger.used, ipv6)))
}

fn compact_projection(
    categories: &mut [IpCategory],
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    for category in categories {
        compact_v4(&mut category.v4);
        compact_v6(&mut category.v6);
        compact_vec(&mut category.v4, ledger)?;
        compact_vec(&mut category.v6, ledger)?;
    }
    Ok(())
}

/// Some official sing/Meta databases have a valid empty description map.
/// maxminddb 0.32 verifies the complete original metadata graph before rejecting
/// that optional information. Validate its unchanged tree/data with a temporary
/// nonempty description, then restore the original metadata and byte identity.
pub(super) fn verify_country_mmdb(bytes: &mut Vec<u8>) -> Result<(), GeoDataError> {
    let replacement = {
        let reader =
            Reader::from_source(bytes.as_slice()).map_err(|_| invalid("invalid country MMDB"))?;
        match reader.verify() {
            Ok(()) => return Ok(()),
            Err(MaxMindDbError::InvalidDatabase {
                message,
                offset: None,
            }) if message == EMPTY_DESCRIPTION
                && reader.metadata().description.is_empty()
                && matches!(
                    reader.metadata().database_type.as_str(),
                    "sing-geoip" | "Meta-geoip0"
                ) =>
            {
                validation_metadata(reader.metadata())?
            }
            Err(_) => return Err(invalid("invalid country MMDB index or data")),
        }
    };
    // Use the same marker location as Reader. Moving it or adding another one
    // would enlarge the data section and could admit an originally bad pointer.
    let start = bytes
        .windows(METADATA_MARKER.len())
        .rposition(|part| part == METADATA_MARKER)
        .and_then(|index| index.checked_add(METADATA_MARKER.len()))
        .ok_or_else(|| invalid("invalid country MMDB metadata boundary"))?;
    let original = &bytes[start..];
    let mut saved = Vec::new();
    saved
        .try_reserve_exact(original.len())
        .map_err(|_| GeoDataError::AllocationFailed {
            bytes: original.len(),
        })?;
    saved.extend_from_slice(original);
    let required = start
        .checked_add(replacement.len())
        .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
    if required > bytes.capacity() {
        bytes
            .try_reserve_exact(required - bytes.len())
            .map_err(|_| GeoDataError::AllocationFailed { bytes: required })?;
    }
    let view = MetadataView::new(bytes, start, saved, &replacement);
    let result = Reader::from_source(view.bytes.as_slice())
        .and_then(|reader| reader.verify())
        .map_err(|_| invalid("invalid country MMDB index or data"));
    drop(view);
    result
}

struct MetadataView<'a> {
    bytes: &'a mut Vec<u8>,
    start: usize,
    original: Vec<u8>,
}

impl<'a> MetadataView<'a> {
    fn new(bytes: &'a mut Vec<u8>, start: usize, original: Vec<u8>, replacement: &[u8]) -> Self {
        bytes.truncate(start);
        bytes.extend_from_slice(replacement);
        Self {
            bytes,
            start,
            original,
        }
    }
}

impl Drop for MetadataView<'_> {
    fn drop(&mut self) {
        self.bytes.truncate(self.start);
        // Original capacity was retained, so restoration cannot reallocate.
        self.bytes.extend_from_slice(&self.original);
    }
}

// Encode only the nine public, already validated Metadata fields in MMDB 2.0
// wire format. No tree/data bytes or original unknown metadata are re-encoded;
// the latter's entire graph passed verification before the narrow exception.
fn validation_metadata(metadata: &Metadata) -> Result<Vec<u8>, GeoDataError> {
    let base = METADATA_HEADROOM
        .checked_add(metadata.database_type.len())
        .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
    let capacity = metadata
        .languages
        .iter()
        .try_fold(base, |total, language| {
            total.checked_add(language.len())?.checked_add(8)
        })
        .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| GeoDataError::AllocationFailed { bytes: capacity })?;
    mmdb_header(&mut out, 7, 9)?;
    for (name, kind, value) in [
        (
            "binary_format_major_version",
            5,
            u64::from(metadata.binary_format_major_version),
        ),
        (
            "binary_format_minor_version",
            5,
            u64::from(metadata.binary_format_minor_version),
        ),
        ("build_epoch", 9, metadata.build_epoch),
        ("ip_version", 5, u64::from(metadata.ip_version)),
        ("node_count", 6, u64::from(metadata.node_count)),
        ("record_size", 5, u64::from(metadata.record_size)),
    ] {
        mmdb_string(&mut out, name)?;
        let width = 8 - value.leading_zeros() as usize / 8;
        mmdb_header(&mut out, kind, width)?;
        out.extend_from_slice(&value.to_be_bytes()[8 - width..]);
    }
    mmdb_string(&mut out, "database_type")?;
    mmdb_string(&mut out, &metadata.database_type)?;
    mmdb_string(&mut out, "description")?;
    mmdb_header(&mut out, 7, 1)?;
    mmdb_string(&mut out, "en")?;
    mmdb_string(&mut out, "Vole validation")?;
    mmdb_string(&mut out, "languages")?;
    mmdb_header(&mut out, 11, metadata.languages.len())?;
    for language in &metadata.languages {
        mmdb_string(&mut out, language)?;
    }
    Ok(out)
}

fn mmdb_string(out: &mut Vec<u8>, value: &str) -> Result<(), GeoDataError> {
    mmdb_header(out, 2, value.len())?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn mmdb_header(out: &mut Vec<u8>, kind: u8, size: usize) -> Result<(), GeoDataError> {
    let (prefix, width, extra) = match size {
        0..=28 => (size as u8, 0, 0),
        29..=284 => (29, 1, size - 29),
        285..=65_820 => (30, 2, size - 285),
        65_821..=16_843_036 => (31, 3, size - 65_821),
        _ => return Err(invalid("country MMDB metadata value cannot be represented")),
    };
    out.push(if kind < 8 { kind << 5 } else { 0 } | prefix);
    if kind >= 8 {
        out.push(kind - 7);
    }
    let extra = (extra as u32).to_be_bytes();
    out.extend_from_slice(&extra[4 - width..]);
    Ok(())
}

fn invalid(detail: &str) -> GeoDataError {
    GeoDataError::InvalidCountry(detail.into())
}

fn canonical_code_matches(value: &str, selector: &str) -> bool {
    value
        .bytes()
        .eq(selector.bytes().map(|byte| byte.to_ascii_lowercase()))
}
