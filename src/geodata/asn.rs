//! One owned MMDB, with direct index lookups and no address cache.

use std::{io::Read, net::IpAddr, path::Path};

use maxminddb::Reader;

use super::{GeoDataError, GeoDataKind, open_asset};

#[derive(Debug, Clone, Copy)]
enum Format {
    Numeric,
    IpInfo,
}

impl Format {
    fn parse(value: &str) -> Result<Self, GeoDataError> {
        match value {
            "GeoLite2-ASN" | "DBIP-ASN-Lite (compat=GeoLite2-ASN)" => Ok(Self::Numeric),
            "ipinfo generic_asn_free.mmdb" => Ok(Self::IpInfo),
            _ => invalid("unsupported ASN database type"),
        }
    }
}

pub(super) struct AsnDb {
    reader: Reader<Vec<u8>>,
    format: Format,
    capacity: usize,
}

impl AsnDb {
    pub(super) fn load(dir: &Path) -> Result<Self, GeoDataError> {
        AsnCandidate::load(dir)?.into_database()
    }

    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(super) fn matches(&self, payload: &str, address: IpAddr) -> bool {
        let Ok(record) = self.reader.lookup(address) else {
            return false;
        };
        match self.format {
            Format::Numeric => {
                let number = if !record.has_data() {
                    0
                } else {
                    match record.decode_path::<u32>(&maxminddb::path!["autonomous_system_number"]) {
                        Ok(Some(value)) => value,
                        // Malformed/missing fields are not a legitimate absent network.
                        _ => return false,
                    }
                };
                canonical_number_matches(payload, number)
            }
            Format::IpInfo => record
                .decode_path::<&str>(&maxminddb::path!["asn"])
                .ok()
                .flatten()
                .and_then(|value| value.strip_prefix("AS"))
                .is_some_and(|value| value == payload),
        }
    }
}

/// Verified candidate storage. Verification borrows this buffer while the
/// old database remains available; ownership transfers only after retirement.
pub(super) struct AsnCandidate {
    bytes: Vec<u8>,
    format: Format,
}
impl AsnCandidate {
    pub(super) fn load(dir: &Path) -> Result<Self, GeoDataError> {
        let (mut file, len) = open_asset(dir, GeoDataKind::Asn)?;
        let len = usize::try_from(len)
            .map_err(|_| GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| GeoDataError::AllocationFailed { bytes: len })?;
        bytes.resize(len, 0);
        file.read_exact(&mut bytes)
            .map_err(|source| super::io_error(GeoDataKind::Asn, source))?;
        let format = {
            let reader =
                Reader::from_source(bytes.as_slice()).map_err(|_| error("invalid ASN MMDB"))?;
            let format = Format::parse(&reader.metadata().database_type)?;
            reader
                .verify()
                .map_err(|_| error("invalid ASN MMDB index or data"))?;
            format
        };
        Ok(Self { bytes, format })
    }

    pub(super) fn into_database(self) -> Result<AsnDb, GeoDataError> {
        let capacity = self.bytes.capacity();
        // Moves the already verified bytes without a second full buffer or
        // another graph verification. Only reader metadata is reconstructed.
        let reader = Reader::from_source(self.bytes).map_err(|_| error("invalid ASN MMDB"))?;
        Ok(AsnDb {
            reader,
            format: self.format,
            capacity,
        })
    }
}

fn canonical_number_matches(payload: &str, number: u32) -> bool {
    !payload.is_empty()
        && payload.len() <= 10
        && payload.bytes().all(|byte| byte.is_ascii_digit())
        && (payload.len() == 1 || !payload.starts_with('0'))
        && payload.parse::<u32>().ok() == Some(number)
}

fn error(detail: &str) -> GeoDataError {
    GeoDataError::InvalidAsn(detail.to_owned())
}
fn invalid<T>(detail: &str) -> Result<T, GeoDataError> {
    Err(error(detail))
}
