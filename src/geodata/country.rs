//! One country MMDB, queried in place without expanding its network tree.

use std::{fmt, io::Read, net::IpAddr, path::Path};

use maxminddb::Reader;
use serde::{
    Deserialize,
    de::{self, SeqAccess, Visitor},
};

use super::{GeoDataError, open_asset_path, selector_code};

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
    reader: Reader<Vec<u8>>,
    format: Format,
    selectors: Vec<String>,
    capacity: usize,
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
        let Ok(record) = self.reader.lookup(address) else {
            return false;
        };
        let code = selector_code(selector);
        let matched = match self.format {
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
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| GeoDataError::AllocationFailed { bytes: len })?;
        bytes.resize(len, 0);
        file.read_exact(&mut bytes)
            .map_err(|source| GeoDataError::Io {
                path: path.into(),
                source,
            })?;
        let format = {
            let reader = Reader::from_source(bytes.as_slice())
                .map_err(|_| invalid("invalid country MMDB"))?;
            reader
                .verify()
                .map_err(|_| invalid("invalid country MMDB index or data"))?;
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
        let capacity = stored
            .iter()
            .fold(
                stored
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())
                    .and_then(|count| self.bytes.capacity().checked_add(count)),
                |total, value| total.and_then(|total| total.checked_add(value.capacity())),
            )
            .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        let reader =
            Reader::from_source(self.bytes).map_err(|_| invalid("invalid country MMDB"))?;
        Ok(CountryDb {
            reader,
            format: self.format,
            selectors: stored,
            capacity,
        })
    }
}

fn invalid(detail: &str) -> GeoDataError {
    GeoDataError::InvalidCountry(detail.into())
}

fn canonical_code_matches(value: &str, selector: &str) -> bool {
    value
        .bytes()
        .eq(selector.bytes().map(|byte| byte.to_ascii_lowercase()))
}
