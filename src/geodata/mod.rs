//! Selective Xray GeoData loading with compact, shared category matchers.
//!
//! The loader deliberately scans protobuf wire framing itself. It indexes only
//! category ranges during the first pass and decodes records only for codes
//! referenced by the prepared rule set. No generated protobuf object graph or
//! memory mapping is used.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    mem,
    net::IpAddr,
    path::{Path, PathBuf},
    str,
};

use regex::bytes::{Regex, RegexBuilder};
use thiserror::Error;

use crate::{
    VoleError,
    config::{DnsNameserverPolicy, RuleKind, RuleSpec},
    routing::GeoMatcher,
};

mod manager;
mod selectors;
pub(crate) mod service;

pub(crate) use selectors::normalize_selector;
use selectors::{fold_attribute, selector_attributes, selector_code};

pub(crate) use manager::GeoDataRegistrationLease;
pub use manager::{
    DynamicGeoData, GeoDataLoadReport, GeoDataManager, GeoDataManagerError, GeoDataRegistration,
    GeoDataReloadReport, GeoDataResourceReport, GeoDataStatus, GeoResourceState, GeoUpdateSession,
};

pub const GEOSITE_FILE_NAME: &str = "geosite.dat";
pub const GEOIP_FILE_NAME: &str = "geoip.dat";

const MAX_CODE_BYTES: usize = 64;

/// The two supported Xray GeoData assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoDataKind {
    GeoSite,
    GeoIp,
}

impl GeoDataKind {
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::GeoSite => GEOSITE_FILE_NAME,
            Self::GeoIp => GEOIP_FILE_NAME,
        }
    }
}

impl std::fmt::Display for GeoDataKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::GeoSite => "GeoSite",
            Self::GeoIp => "GeoIP",
        })
    }
}

#[derive(Debug, Error)]
pub enum GeoDataError {
    #[error("failed to access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("GeoData asset is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("invalid {kind} category code `{code}`")]
    InvalidCode { kind: GeoDataKind, code: String },
    #[error("duplicate {kind} category code `{code}`")]
    DuplicateCode { kind: GeoDataKind, code: String },
    #[error("referenced {kind} category `{code}` is missing")]
    MissingCode { kind: GeoDataKind, code: String },
    #[error("malformed {kind} protobuf: {detail}")]
    Malformed { kind: GeoDataKind, detail: String },
    #[error("invalid GeoSite record in `{code}`: {detail}")]
    InvalidDomain { code: String, detail: String },
    #[error("invalid GeoSite Regex in `{code}`: {detail}")]
    InvalidRegex { code: String, detail: String },
    #[error("invalid GeoIP CIDR in `{code}`: {detail}")]
    InvalidCidr { code: String, detail: String },
    #[error("GeoData resource `{resource}` is {actual}; limit is {maximum}")]
    ResourceLimit {
        resource: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("GeoData allocation failed while reserving {bytes} bytes")]
    AllocationFailed { bytes: usize },
}

impl From<GeoDataError> for VoleError {
    fn from(error: GeoDataError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

/// Diagnostic capacity accounting, never a memory admission policy.
///
/// Includes Vole-owned matcher/index vectors and arenas, with old/new buffer
/// overlap during growth. Compiled regex programs and search caches are opaque
/// third-party allocations and are not counted, nor are allocator overhead or
/// the process peak; those require independent measurements.
#[derive(Debug, Default)]
struct AllocationLedger {
    used: usize,
    peak: usize,
}

impl AllocationLedger {
    fn reserve(&mut self, bytes: usize) -> Result<(), GeoDataError> {
        let requested = self
            .used
            .checked_add(bytes)
            .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
        self.used = requested;
        self.peak = self.peak.max(requested);
        Ok(())
    }

    fn release(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.used);
        self.used = self.used.saturating_sub(bytes);
    }
}

/// Prepared matchers for all GeoData codes referenced by one instance.
pub struct GeoData {
    sites: Vec<SiteCategory>,
    ips: Vec<IpCategory>,
    allocation_capacity: usize,
    peak_allocation_capacity: usize,
    // Fields drop in declaration order: signal only after matcher storage is
    // destroyed, not merely when the Arc strong count reaches zero.
    release: Option<manager::SnapshotRelease>,
}

impl std::fmt::Debug for GeoData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeoData")
            .field("site_categories", &self.sites.len())
            .field("ip_categories", &self.ips.len())
            .field("allocation_capacity", &self.allocation_capacity)
            .field("peak_allocation_capacity", &self.peak_allocation_capacity)
            .finish()
    }
}

impl Default for GeoData {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl GeoData {
    pub const EMPTY: Self = Self {
        sites: Vec::new(),
        ips: Vec::new(),
        allocation_capacity: 0,
        peak_allocation_capacity: 0,
        release: None,
    };

    /// Loads only categories referenced by `rules` from the two fixed sibling
    /// assets in `config_dir`.
    pub fn load(config_dir: &Path, rules: &[RuleSpec]) -> Result<Self, GeoDataError> {
        Self::load_with_dns_policies(config_dir, rules, &[])
    }

    /// Loads categories referenced by both business routing rules and DNS
    /// nameserver policies. Selectors with the same base code share the value
    /// arena and expressions; identical intersections share compact indexes.
    pub fn load_with_dns_policies(
        config_dir: &Path,
        rules: &[RuleSpec],
        dns_policies: &[DnsNameserverPolicy],
    ) -> Result<Self, GeoDataError> {
        let requested = RequestedCodes::collect(rules, dns_policies)?;
        if requested.total() == 0 {
            return Ok(Self::EMPTY);
        }

        let mut ledger = AllocationLedger::default();
        let mut sites = Vec::new();
        let mut ips = Vec::new();
        ensure_vec_capacity(&mut sites, requested.sites.values.len(), &mut ledger)?;
        ensure_vec_capacity(&mut ips, requested.ips.values.len(), &mut ledger)?;

        if !requested.ips.values.is_empty() {
            load_ip_file(config_dir, &requested.ips, &mut ips, &mut ledger)?;
        }
        if !requested.sites.values.is_empty() {
            load_site_file(config_dir, &requested.sites, &mut sites, &mut ledger)?;
        }
        Ok(Self::from_loaded(sites, ips, ledger.used, ledger.peak))
    }

    fn from_loaded(
        mut sites: Vec<SiteCategory>,
        mut ips: Vec<IpCategory>,
        allocation_capacity: usize,
        peak_allocation_capacity: usize,
    ) -> Self {
        // Sort categories, never routing rules. Both standalone loading and
        // manager reloads share this allocation-free indexing step.
        sites.sort_unstable_by_key(|category| category.code);
        ips.sort_unstable_by_key(|category| category.code);
        let release = (!sites.is_empty() || !ips.is_empty()).then(manager::SnapshotRelease::new);
        Self {
            sites,
            ips,
            allocation_capacity,
            peak_allocation_capacity,
            release,
        }
    }

    /// Accounted retained matcher capacity, not allocator or process memory.
    #[must_use]
    pub const fn allocation_capacity(&self) -> usize {
        self.allocation_capacity
    }

    /// Peak of accounted capacities, excluding compiled regexes/search caches and
    /// configuration requirements. Neither an admission quota nor a bound on
    /// actual loading or process memory.
    #[must_use]
    pub const fn peak_allocation_capacity(&self) -> usize {
        self.peak_allocation_capacity
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty() && self.ips.is_empty()
    }

    #[must_use]
    pub fn geosite_available(&self, code: &str) -> bool {
        self.site_category(code).is_some()
    }

    #[must_use]
    pub fn geoip_available(&self, code: &str) -> bool {
        self.ip_category(code).is_some()
    }

    fn site_category(&self, code: &str) -> Option<&SiteCategory> {
        self.sites
            .binary_search_by(|category| category.code.cmp_str(selector_code(code)))
            .ok()
            .map(|index| &self.sites[index])
            .filter(|category| category.has_selector(code))
    }

    fn ip_category(&self, code: &str) -> Option<&IpCategory> {
        self.ips
            .binary_search_by(|category| category.code.cmp_str(selector_code(code)))
            .ok()
            .map(|index| &self.ips[index])
            .filter(|category| category.has_selector(code))
    }
}

impl GeoMatcher for GeoData {
    fn geosite_available(&self, code: &str) -> bool {
        GeoData::geosite_available(self, code)
    }

    fn geoip_available(&self, code: &str) -> bool {
        GeoData::geoip_available(self, code)
    }

    fn matches_geosite(&self, code: &str, domain: &str) -> bool {
        self.site_category(code)
            .is_some_and(|category| !domain.is_empty() && category.matches_selector(code, domain))
    }

    fn matches_geoip(&self, code: &str, address: IpAddr) -> bool {
        self.ip_category(code)
            .is_some_and(|category| category.matches(address) != code.starts_with('!'))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Code {
    bytes: [u8; MAX_CODE_BYTES],
    len: u8,
}

impl Code {
    const EMPTY: Self = Self {
        bytes: [0; MAX_CODE_BYTES],
        len: 0,
    };

    fn parse(kind: GeoDataKind, raw: &[u8]) -> Result<Self, GeoDataError> {
        if raw.is_empty()
            || raw.len() > MAX_CODE_BYTES
            || !raw[0].is_ascii_alphanumeric()
            || !raw.iter().skip(1).all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'+' | b'!' | b'-')
            })
        {
            return Err(GeoDataError::InvalidCode {
                kind,
                code: String::from_utf8_lossy(raw).into_owned(),
            });
        }
        let mut code = Self::EMPTY;
        code.len = u8::try_from(raw.len()).expect("code length is bounded to 64");
        code.bytes[..raw.len()].copy_from_slice(raw);
        code.bytes[..raw.len()].make_ascii_lowercase();
        Ok(code)
    }

    fn as_str(&self) -> &str {
        // Code::parse admits ASCII only.
        str::from_utf8(&self.bytes[..usize::from(self.len)]).expect("validated ASCII GeoData code")
    }

    fn cmp_str(&self, other: &str) -> std::cmp::Ordering {
        self.as_str()
            .bytes()
            .cmp(other.bytes().map(|byte| byte.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodeSet {
    values: Vec<Code>,
    selectors: Vec<String>,
}

impl CodeSet {
    const EMPTY: Self = Self {
        values: Vec::new(),
        selectors: Vec::new(),
    };

    fn insert(&mut self, kind: GeoDataKind, raw: &str) -> Result<(), GeoDataError> {
        let selector = normalize_selector(kind, raw)?;
        if self.selectors.contains(&selector) {
            return Ok(());
        }
        self.selectors
            .try_reserve(1)
            .map_err(|_| GeoDataError::AllocationFailed {
                bytes: mem::size_of::<String>(),
            })?;
        let code = Code::parse(kind, selector_code(&selector).as_bytes())?;
        self.selectors.push(selector);
        if self.values.contains(&code) {
            return Ok(());
        }
        self.values
            .try_reserve(1)
            .map_err(|_| GeoDataError::AllocationFailed {
                bytes: self
                    .values
                    .len()
                    .saturating_add(1)
                    .saturating_mul(mem::size_of::<Code>()),
            })?;
        self.values.push(code);
        Ok(())
    }
}

#[derive(Debug)]
struct RequestedCodes {
    sites: CodeSet,
    ips: CodeSet,
}

impl RequestedCodes {
    fn collect(
        rules: &[RuleSpec],
        dns_policies: &[DnsNameserverPolicy],
    ) -> Result<Self, GeoDataError> {
        let mut requested = Self {
            sites: CodeSet::EMPTY,
            ips: CodeSet::EMPTY,
        };
        let mut pending: Vec<_> = rules.iter().collect();
        while let Some(rule) = pending.pop() {
            match &rule.kind {
                RuleKind::And(children) | RuleKind::Or(children) => pending.extend(children),
                RuleKind::RuleSet {
                    content: Some(content),
                    ..
                } => pending.extend(&content.classical),
                RuleKind::Not(child) => pending.push(child),
                RuleKind::GeoSite(code) => requested.sites.insert(GeoDataKind::GeoSite, code)?,
                RuleKind::GeoIp(code) => requested.ips.insert(GeoDataKind::GeoIp, code)?,
                _ => (),
            }
        }
        for policy in dns_policies {
            if let crate::config::DnsPolicySelector::RuleSets { sets, .. } = &policy.selector {
                let rules = sets
                    .iter()
                    .flat_map(|set| set.classical.iter().cloned())
                    .collect::<Vec<_>>();
                let nested = Self::collect(&rules, &[])?;
                for code in nested.sites.selectors {
                    requested.sites.insert(GeoDataKind::GeoSite, &code)?;
                }
                for code in nested.ips.selectors {
                    requested.ips.insert(GeoDataKind::GeoIp, &code)?;
                }
            }
            for code in policy.geosite_codes() {
                requested.sites.insert(GeoDataKind::GeoSite, code)?;
            }
        }
        Ok(requested)
    }

    const fn total(&self) -> usize {
        self.sites.selectors.len() + self.ips.selectors.len()
    }
}

/// Normalized GeoData categories referenced by one Vole configuration.
///
/// Collection validates base code/selector syntax and canonicalizes attribute
/// intersections and case, without a reference-count quota. Asset
/// availability and contents are deliberately handled later by
/// [`GeoDataManager`], where one unavailable resource can become dormant
/// without disabling the other kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoRequirements {
    sites: CodeSet,
    ips: CodeSet,
}

impl GeoRequirements {
    pub(crate) fn for_config(config: &crate::config::Config) -> Result<Self, GeoDataError> {
        let mut policies: Vec<_> = config
            .dns
            .nameserver_policies
            .iter()
            .chain(&config.dns.proxy_policies)
            .map(|policy| DnsNameserverPolicy {
                selector: policy.selector.clone(),
                nameservers: Box::new([]),
            })
            .collect();
        if config.dns.enable && config.dns.fake_ip.enabled {
            policies.extend(config.dns.fake_ip.filter.iter().cloned().map(|selector| {
                DnsNameserverPolicy {
                    selector,
                    nameservers: Box::new([]),
                }
            }));
        }
        let mut result = Self::collect(&config.rules, &policies)?;
        if config.dns.enable && config.dns.fake_ip.enabled {
            result.extend(&Self::collect(&config.dns.fake_ip.rules, &[])?)?;
        }
        Ok(result)
    }

    pub(crate) fn extend(&mut self, other: &Self) -> Result<(), GeoDataError> {
        for selector in &other.sites.selectors {
            self.sites.insert(GeoDataKind::GeoSite, selector)?;
        }
        for selector in &other.ips.selectors {
            self.ips.insert(GeoDataKind::GeoIp, selector)?;
        }
        Ok(())
    }

    /// Collects all GeoSite and GeoIP selectors used by business rules and DNS
    /// nameserver policies. Each underlying category is decoded only once.
    pub fn collect(
        rules: &[RuleSpec],
        dns_policies: &[DnsNameserverPolicy],
    ) -> Result<Self, GeoDataError> {
        let requested = RequestedCodes::collect(rules, dns_policies)?;
        Ok(Self {
            sites: requested.sites,
            ips: requested.ips,
        })
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sites.values.is_empty() && self.ips.values.is_empty()
    }

    #[must_use]
    pub const fn requires(&self, kind: GeoDataKind) -> bool {
        match kind {
            GeoDataKind::GeoSite => !self.sites.values.is_empty(),
            GeoDataKind::GeoIp => !self.ips.values.is_empty(),
        }
    }

    #[must_use]
    pub const fn total_codes(&self) -> usize {
        self.sites.selectors.len() + self.ips.selectors.len()
    }

    /// Returns canonical selector keys, which may include inversion/attributes.
    pub fn codes(&self, kind: GeoDataKind) -> impl Iterator<Item = &str> {
        let set = match kind {
            GeoDataKind::GeoSite => &self.sites,
            GeoDataKind::GeoIp => &self.ips,
        };
        set.selectors.iter().map(String::as_str)
    }

    fn code_set(&self, kind: GeoDataKind) -> &CodeSet {
        match kind {
            GeoDataKind::GeoSite => &self.sites,
            GeoDataKind::GeoIp => &self.ips,
        }
    }
}

struct KindLoad<T> {
    values: Vec<T>,
    used: usize,
    peak: usize,
}

fn load_sites_for_requirements(
    asset_dir: &Path,
    requested: &CodeSet,
    used: usize,
    peak: usize,
) -> Result<KindLoad<SiteCategory>, GeoDataError> {
    let mut ledger = AllocationLedger { used, peak };
    let mut values = Vec::new();
    ensure_vec_capacity(&mut values, requested.values.len(), &mut ledger)?;
    load_site_file(asset_dir, requested, &mut values, &mut ledger)?;
    Ok(KindLoad {
        values,
        used: ledger.used,
        peak: ledger.peak,
    })
}

fn load_ips_for_requirements(
    asset_dir: &Path,
    requested: &CodeSet,
    used: usize,
    peak: usize,
) -> Result<KindLoad<IpCategory>, GeoDataError> {
    let mut ledger = AllocationLedger { used, peak };
    let mut values = Vec::new();
    ensure_vec_capacity(&mut values, requested.values.len(), &mut ledger)?;
    load_ip_file(asset_dir, requested, &mut values, &mut ledger)?;
    Ok(KindLoad {
        values,
        used: ledger.used,
        peak: ledger.peak,
    })
}

fn validate_asset_structure(asset_dir: &Path, kind: GeoDataKind) -> Result<(), GeoDataError> {
    let (mut file, len) = open_asset(asset_dir, kind)?;
    let mut ledger = AllocationLedger::default();
    let _ = index_selected(&mut file, len, kind, &CodeSet::EMPTY, &mut ledger)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    code: Code,
    offset: u64,
    len: u64,
    record_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct SelectedRange {
    code: Code,
    offset: u64,
    len: u64,
    record_count: usize,
}

fn load_site_file(
    config_dir: &Path,
    requested: &CodeSet,
    output: &mut Vec<SiteCategory>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoSite;
    let (mut file, len) = open_asset(config_dir, kind)?;
    let mut selected = index_selected(&mut file, len, kind, requested, ledger)?;
    selected.sort_unstable_by_key(|range| range.code);
    for range in &selected {
        let selectors = requested
            .selectors
            .iter()
            .filter(|selector| range.code.cmp_str(selector_code(selector)).is_eq());
        let category = parse_site_category(&mut file, *range, ledger, selectors)?;
        output.push(category);
    }
    release_vec(&selected, ledger);
    Ok(())
}

fn load_ip_file(
    config_dir: &Path,
    requested: &CodeSet,
    output: &mut Vec<IpCategory>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    load_selected_file(
        GeoDataKind::GeoIp,
        config_dir,
        requested,
        output,
        ledger,
        parse_ip_category,
    )?;
    for category in output.iter_mut() {
        for selector in requested
            .selectors
            .iter()
            .filter(|selector| category.code.cmp_str(selector_code(selector)).is_eq())
        {
            ensure_vec_capacity(&mut category.selectors, 1, ledger)?;
            ledger.reserve(selector.len())?;
            category.selectors.push(selector.clone());
        }
    }
    Ok(())
}

fn load_selected_file<T>(
    kind: GeoDataKind,
    config_dir: &Path,
    requested: &CodeSet,
    output: &mut Vec<T>,
    ledger: &mut AllocationLedger,
    parse_category: fn(&mut File, SelectedRange, &mut AllocationLedger) -> Result<T, GeoDataError>,
) -> Result<(), GeoDataError> {
    let (mut file, len) = open_asset(config_dir, kind)?;
    let mut selected = index_selected(&mut file, len, kind, requested, ledger)?;
    selected.sort_unstable_by_key(|range| range.code);
    for range in &selected {
        output.push(parse_category(&mut file, *range, ledger)?);
    }
    release_vec(&selected, ledger);
    Ok(())
}

fn open_asset(config_dir: &Path, kind: GeoDataKind) -> Result<(File, u64), GeoDataError> {
    let path = config_dir.join(kind.file_name());
    let symlink_metadata = fs::symlink_metadata(&path).map_err(|source| GeoDataError::Io {
        path: path.clone(),
        source,
    })?;
    if !symlink_metadata.file_type().is_file() {
        return Err(GeoDataError::NotRegularFile(path));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(|source| GeoDataError::Io {
        path: path.clone(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| GeoDataError::Io {
        path: path.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(GeoDataError::NotRegularFile(path));
    }
    Ok((file, metadata.len()))
}

fn index_selected(
    file: &mut File,
    file_len: u64,
    kind: GeoDataKind,
    requested: &CodeSet,
    ledger: &mut AllocationLedger,
) -> Result<Vec<SelectedRange>, GeoDataError> {
    seek(file, 0, kind)?;
    let mut index = Vec::<IndexEntry>::new();
    while position(file, kind)? < file_len {
        let (field, wire) = read_key(file, file_len, kind)?;
        if field != 1 || wire != 2 {
            return malformed(
                kind,
                "top-level message accepts only repeated field 1 entries",
            );
        }
        let entry_len = read_length(file, file_len, kind)?;
        let offset = position(file, kind)?;
        let end = checked_end(offset, entry_len, file_len, kind)?;
        let (code, record_count) = scan_category_header(file, end, kind)?;
        ensure_vec_capacity(&mut index, 1, ledger)?;
        index.push(IndexEntry {
            code,
            offset,
            len: entry_len,
            record_count,
        });
        seek(file, end, kind)?;
    }

    index.sort_unstable_by_key(|entry| entry.code);
    for pair in index.windows(2) {
        if pair[0].code == pair[1].code {
            let error = GeoDataError::DuplicateCode {
                kind,
                code: pair[0].code.as_str().to_owned(),
            };
            release_vec(&index, ledger);
            return Err(error);
        }
    }

    let mut selected = Vec::new();
    ensure_vec_capacity(&mut selected, requested.values.len(), ledger)?;
    for code in &requested.values {
        let entry = index
            .binary_search_by_key(code, |entry| entry.code)
            .ok()
            .map(|at| index[at])
            .ok_or_else(|| GeoDataError::MissingCode {
                kind,
                code: code.as_str().to_owned(),
            });
        match entry {
            Ok(entry) => {
                selected.push(SelectedRange {
                    code: entry.code,
                    offset: entry.offset,
                    len: entry.len,
                    record_count: entry.record_count,
                });
            }
            Err(error) => {
                release_vec(&index, ledger);
                release_vec(&selected, ledger);
                return Err(error);
            }
        }
    }
    release_vec(&index, ledger);
    Ok(selected)
}

fn scan_category_header(
    file: &mut File,
    end: u64,
    kind: GeoDataKind,
) -> Result<(Code, usize), GeoDataError> {
    let mut code = None;
    let mut record_count = 0_usize;
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match (field, kind) {
            (1, _) => {
                require_wire(kind, wire, 2, "category code")?;
                if code.is_some() {
                    return malformed(kind, "category contains code more than once");
                }
                let len = read_length(file, end, kind)?;
                if len > MAX_CODE_BYTES as u64 {
                    return Err(GeoDataError::InvalidCode {
                        kind,
                        code: "<more than 64 bytes>".to_owned(),
                    });
                }
                let mut raw = [0_u8; MAX_CODE_BYTES];
                read_exact(file, &mut raw[..len as usize], end, kind)?;
                code = Some(Code::parse(kind, &raw[..len as usize])?);
            }
            (2, _) => {
                require_wire(kind, wire, 2, "category record")?;
                skip_field_payload(file, wire, end, kind)?;
                record_count =
                    record_count
                        .checked_add(1)
                        .ok_or_else(|| GeoDataError::Malformed {
                            kind,
                            detail: "category record count does not fit usize".to_owned(),
                        })?;
            }
            (3, GeoDataKind::GeoIp) => {
                require_wire(kind, wire, 0, "reverse_match")?;
                // Mihomo GeoIP selectors get inversion from `!code`, not the
                // legacy DAT flag, which its CIDR matcher does not inspect.
                let _ = read_varint(file, end, kind)?;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    let code = code.ok_or_else(|| GeoDataError::Malformed {
        kind,
        detail: "category is missing code field 1".to_owned(),
    })?;
    Ok((code, record_count))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SitePatternKind {
    Substr,
    Domain,
    Full,
}

#[derive(Debug, Clone, Copy)]
struct SitePattern {
    kind: SitePatternKind,
    start: u32,
    len: u32,
}

impl SitePattern {
    fn value<'a>(&self, values: &'a [u8]) -> &'a [u8] {
        let start = self.start as usize;
        &values[start..start + self.len as usize]
    }
}

struct SiteCategory {
    code: Code,
    patterns: Vec<SitePattern>,
    values: Vec<u8>,
    regexes: Vec<Regex>,
    selectors: Vec<String>,
    filters: Vec<SiteFilter>,
}

/// A filtered matcher owns only compact indexes. The category's values and
/// compiled expressions are shared by all filters and positive/negative aliases.
struct SiteFilter {
    attributes: String,
    all_records: bool,
    patterns: Vec<SitePattern>,
    regex_indices: Vec<usize>,
}

impl SiteCategory {
    fn has_selector(&self, selector: &str) -> bool {
        self.selectors
            .iter()
            .any(|requested| requested.eq_ignore_ascii_case(selector))
    }

    fn contains(&self, patterns: &[SitePattern], kind: SitePatternKind, value: &[u8]) -> bool {
        patterns
            .binary_search_by(|pattern| {
                pattern
                    .kind
                    .cmp(&kind)
                    .then_with(|| pattern.value(&self.values).cmp(value))
            })
            .is_ok()
    }

    fn matches_selector(&self, selector: &str, domain: &str) -> bool {
        let attributes = selector_attributes(selector);
        let filter = self
            .filters
            .iter()
            .find(|filter| filter.attributes.eq_ignore_ascii_case(attributes));
        let matched = if attributes.is_empty() {
            self.matches(domain, &self.patterns, None)
        } else if let Some(filter) = filter {
            if filter.all_records {
                self.matches(domain, &self.patterns, None)
            } else {
                self.matches(domain, &filter.patterns, Some(&filter.regex_indices))
            }
        } else {
            return false;
        };
        matched != selector.starts_with('!')
    }

    fn matches(
        &self,
        domain: &str,
        patterns: &[SitePattern],
        regex_indices: Option<&[usize]>,
    ) -> bool {
        // The loader validates/normalizes each value once. Reuse the compact
        // ranges as a sorted index; a miss must not scan all Domain/Full records
        // for every UDP packet. Category membership is a union, not rule order.
        let bytes = domain.as_bytes();
        if self.contains(patterns, SitePatternKind::Full, bytes) {
            return true;
        }
        let mut suffix = bytes;
        loop {
            if self.contains(patterns, SitePatternKind::Domain, suffix) {
                return true;
            }
            let Some(dot) = suffix.iter().position(|byte| *byte == b'.') else {
                break;
            };
            suffix = &suffix[dot + 1..];
        }
        for pattern in patterns
            .iter()
            .take_while(|pattern| pattern.kind == SitePatternKind::Substr)
        {
            let value = pattern.value(&self.values);
            if bytes.windows(value.len()).any(|window| window == value) {
                return true;
            }
        }
        // The regex library owns its compiled representation and search cache;
        // matching is not guaranteed to be allocation-free on first use.
        let matches_regex = |regex: &Regex| regex.is_match(domain.as_bytes());
        match regex_indices {
            Some(indices) => indices
                .iter()
                .any(|&index| matches_regex(&self.regexes[index])),
            None => self.regexes.iter().any(matches_regex),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ValueRange {
    start: u32,
    len: u32,
}

fn parse_site_category<'a>(
    file: &mut File,
    range: SelectedRange,
    ledger: &mut AllocationLedger,
    requested: impl Iterator<Item = &'a String>,
) -> Result<SiteCategory, GeoDataError> {
    let kind = GeoDataKind::GeoSite;
    let end = checked_end(range.offset, range.len, u64::MAX, kind)?;
    seek(file, range.offset, kind)?;
    let mut patterns = Vec::new();
    let mut values = Vec::new();
    let mut regex_bytes = Vec::new();
    let mut regex_ranges = Vec::new();
    let mut scratch = Vec::new();
    let mut seen_code = false;
    let mut remaining_records = range.record_count;
    let mut selectors = Vec::new();
    let mut filters: Vec<SiteFilter> = Vec::new();
    for selector in requested {
        ensure_vec_capacity(&mut selectors, 1, ledger)?;
        ledger.reserve(selector.len())?;
        selectors.push(selector.clone());
        let attributes = selector_attributes(selector);
        if !attributes.is_empty() && !filters.iter().any(|filter| filter.attributes == attributes) {
            ensure_vec_capacity(&mut filters, 1, ledger)?;
            ledger.reserve(attributes.len())?;
            filters.push(SiteFilter {
                attributes: attributes.to_owned(),
                all_records: false,
                patterns: Vec::new(),
                regex_indices: Vec::new(),
            });
        }
    }
    let unfiltered = selectors
        .iter()
        .any(|selector| selector_attributes(selector).is_empty());
    if filters.len() == 1 && !unfiltered {
        // The union equals this one intersection. Its positive and negative
        // aliases need no second literal or expression index at all.
        filters[0].all_records = true;
    }
    // One reusable membership bitmap per category, not attribute objects
    // retained for every record. Different selector intersections share values.
    let mut attribute_keys = Vec::<String>::new();
    for filter in &filters {
        for attribute in filter.attributes.split('@') {
            if !attribute_keys.iter().any(|key| key == attribute) {
                ensure_vec_capacity(&mut attribute_keys, 1, ledger)?;
                ledger.reserve(attribute.len())?;
                attribute_keys.push(attribute.to_owned());
            }
        }
    }
    let mut present = Vec::new();
    ensure_vec_capacity(&mut present, attribute_keys.len(), ledger)?;
    present.resize(attribute_keys.len(), false);
    let mut filter_matches = Vec::new();
    ensure_vec_capacity(&mut filter_matches, filters.len(), ledger)?;
    filter_matches.resize(filters.len(), false);

    let result = (|| {
        while position(file, kind)? < end {
            let (field, wire) = read_key(file, end, kind)?;
            match field {
                1 => {
                    require_wire(kind, wire, 2, "GeoSite code")?;
                    if seen_code {
                        return malformed(kind, "GeoSite contains code more than once");
                    }
                    let code = read_code(file, end, kind)?;
                    if code != range.code {
                        return malformed(kind, "GeoSite code changed between scan passes");
                    }
                    seen_code = true;
                }
                2 => {
                    require_wire(kind, wire, 2, "Domain")?;
                    remaining_records = remaining_records.checked_sub(1).ok_or_else(|| {
                        GeoDataError::Malformed {
                            kind,
                            detail: "GeoSite record count changed between scan passes".to_owned(),
                        }
                    })?;
                    let len = read_length(file, end, kind)?;
                    let start = position(file, kind)?;
                    let record_end = checked_end(start, len, end, kind)?;
                    if !filters.is_empty() {
                        present.fill(false);
                        scan_domain_attributes(
                            file,
                            record_end,
                            &attribute_keys,
                            &mut present,
                            &mut scratch,
                            ledger,
                        )?;
                        for (filter, matched) in filters.iter().zip(&mut filter_matches) {
                            *matched = filter.attributes.split('@').all(|attribute| {
                                let at = attribute_keys
                                    .iter()
                                    .position(|key| key == attribute)
                                    .expect("collected selector attribute");
                                present[at]
                            });
                        }
                        seek(file, start, kind)?;
                    }
                    if unfiltered || filter_matches.iter().any(|matched| *matched) {
                        let pattern_start = patterns.len();
                        let regex_start = regex_ranges.len();
                        parse_domain_record(
                            file,
                            record_end,
                            range.code,
                            &mut patterns,
                            &mut values,
                            &mut regex_bytes,
                            &mut regex_ranges,
                            &mut scratch,
                            ledger,
                        )?;
                        for (filter, matched) in filters.iter_mut().zip(&filter_matches) {
                            if !matched || filter.all_records {
                                continue;
                            }
                            if let Some(pattern) = patterns.get(pattern_start) {
                                ensure_vec_capacity(&mut filter.patterns, 1, ledger)?;
                                filter.patterns.push(*pattern);
                            }
                            if regex_ranges.len() > regex_start {
                                ensure_vec_capacity(&mut filter.regex_indices, 1, ledger)?;
                                filter.regex_indices.push(regex_start);
                            }
                        }
                    }
                    seek(file, record_end, kind)?;
                }
                _ => skip_field_payload(file, wire, end, kind)?,
            }
        }
        if !seen_code {
            return malformed(kind, "GeoSite is missing code");
        }
        if remaining_records != 0 {
            return malformed(kind, "GeoSite record count changed between scan passes");
        }
        compile_regex_set(range.code, &regex_bytes, &regex_ranges, ledger)
    })();

    release_vec(&scratch, ledger);
    release_vec(&regex_ranges, ledger);
    release_vec(&regex_bytes, ledger);
    for attribute in &attribute_keys {
        ledger.release(attribute.capacity());
    }
    release_vec(&attribute_keys, ledger);
    release_vec(&present, ledger);
    release_vec(&filter_matches, ledger);
    match result {
        Ok(regexes) => {
            // In-place sort does not duplicate the arena or retain a second
            // index. Keep every record, including overlapping types/duplicates.
            patterns.sort_unstable_by(|left, right| {
                left.kind
                    .cmp(&right.kind)
                    .then_with(|| left.value(&values).cmp(right.value(&values)))
            });
            for filter in &mut filters {
                filter.patterns.sort_unstable_by(|left, right| {
                    left.kind
                        .cmp(&right.kind)
                        .then_with(|| left.value(&values).cmp(right.value(&values)))
                });
            }
            Ok(SiteCategory {
                code: range.code,
                patterns,
                values,
                regexes,
                selectors,
                filters,
            })
        }
        Err(error) => {
            release_vec(&patterns, ledger);
            release_vec(&values, ledger);
            for selector in &selectors {
                ledger.release(selector.capacity());
            }
            release_vec(&selectors, ledger);
            for filter in &filters {
                ledger.release(filter.attributes.capacity());
                release_vec(&filter.patterns, ledger);
                release_vec(&filter.regex_indices, ledger);
            }
            release_vec(&filters, ledger);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_domain_record(
    file: &mut File,
    end: u64,
    code: Code,
    patterns: &mut Vec<SitePattern>,
    values: &mut Vec<u8>,
    regex_bytes: &mut Vec<u8>,
    regex_ranges: &mut Vec<ValueRange>,
    scratch: &mut Vec<u8>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoSite;
    let mut domain_type = 0_u64;
    let mut seen_type = false;
    let mut value_range = None;
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match field {
            1 => {
                require_wire(kind, wire, 0, "Domain.type")?;
                if seen_type {
                    return invalid_domain(code, "Domain.type occurs more than once");
                }
                domain_type = read_varint(file, end, kind)?;
                seen_type = true;
            }
            2 => {
                require_wire(kind, wire, 2, "Domain.value")?;
                if value_range.is_some() {
                    return invalid_domain(code, "Domain.value occurs more than once");
                }
                let len = read_length(file, end, kind)?;
                let start = position(file, kind)?;
                let value_end = checked_end(start, len, end, kind)?;
                value_range = Some((start, len));
                seek(file, value_end, kind)?;
            }
            3 => {
                require_wire(kind, wire, 2, "Domain.attribute")?;
                let len = read_length(file, end, kind)?;
                let start = position(file, kind)?;
                let attribute_end = checked_end(start, len, end, kind)?;
                validate_attribute(file, attribute_end, kind)?;
                seek(file, attribute_end, kind)?;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    let (value_offset, value_len) =
        value_range.ok_or_else(|| invalid_domain_error(code, "Domain.value is missing"))?;
    let value_len = usize::try_from(value_len)
        .map_err(|_| invalid_domain_error(code, "Domain.value length does not fit usize"))?;
    read_scratch(file, value_offset, value_len, scratch, ledger, kind)?;
    let raw = str::from_utf8(scratch)
        .map_err(|_| invalid_domain_error(code, "Domain.value is not UTF-8"))?;

    match domain_type {
        0 => {
            if raw.is_empty() || !raw.is_ascii() {
                return invalid_domain(code, "Substr value must be non-empty ASCII");
            }
            scratch.make_ascii_lowercase();
            append_site_value(SitePatternKind::Substr, scratch, patterns, values, ledger)?;
        }
        1 => {
            validate_regex_source(&code, raw)?;
            let start = u32::try_from(regex_bytes.len())
                .map_err(|_| invalid_domain_error(code, "Regex source offset overflow"))?;
            ensure_vec_capacity(regex_bytes, scratch.len(), ledger)?;
            regex_bytes.extend_from_slice(scratch);
            ensure_vec_capacity(regex_ranges, 1, ledger)?;
            regex_ranges.push(ValueRange {
                start,
                len: u32::try_from(scratch.len())
                    .map_err(|_| invalid_domain_error(code, "Regex source length overflow"))?,
            });
        }
        2 | 3 => {
            // These are static literal match values, not DNS lookup targets.
            // Keep opaque ASCII (including non-hostname labels) without STD3
            // validation or per-record allocation. Preserve valid IDN support,
            // but an IDNA failure must not discard a record or its category.
            let raw = raw.strip_suffix('.').unwrap_or(raw);
            if raw.is_empty() {
                return invalid_domain(code, "Domain/Full value must be non-empty");
            }
            let normalized = (!raw.is_ascii()).then(|| {
                idna::domain_to_ascii(raw)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| raw.to_lowercase())
            });
            let temporary_capacity = normalized.as_ref().map_or(0, String::capacity);
            let value = if let Some(normalized) = normalized.as_deref() {
                normalized.as_bytes()
            } else {
                scratch.truncate(raw.len());
                scratch.make_ascii_lowercase();
                scratch.as_slice()
            };
            ledger.reserve(temporary_capacity)?;
            let result = append_site_value(
                if domain_type == 2 {
                    SitePatternKind::Domain
                } else {
                    SitePatternKind::Full
                },
                value,
                patterns,
                values,
                ledger,
            );
            ledger.release(temporary_capacity);
            result?;
        }
        other => {
            return invalid_domain(code, &format!("unsupported Domain.type {other}"));
        }
    }
    Ok(())
}

fn validate_regex_source(code: &Code, pattern: &str) -> Result<(), GeoDataError> {
    if !pattern.is_ascii() {
        return Err(GeoDataError::InvalidRegex {
            code: code.as_str().to_owned(),
            detail: "the Vole Regex subset only accepts ASCII source".to_owned(),
        });
    }
    if has_unsupported_inline_regex_flag(pattern.as_bytes()) {
        return Err(GeoDataError::InvalidRegex {
            code: code.as_str().to_owned(),
            detail: "inline `u`, `x`, and `R` flags are outside the supported Go/Rust subset"
                .to_owned(),
        });
    }
    Ok(())
}

/// Finds Rust-only inline flags without interpreting escaped text or character
/// classes. Go and Rust share `i`, `m`, `s`, and `U`; the remaining syntax is
/// still validated by the regex library during compilation.
fn has_unsupported_inline_regex_flag(pattern: &[u8]) -> bool {
    let mut escaped = false;
    let mut in_class = false;
    let mut index = 0;
    while index < pattern.len() {
        let byte = pattern[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            index += 1;
            continue;
        }
        match byte {
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class && pattern.get(index + 1) == Some(&b'?') => {
                let mut flag_index = index + 2;
                while let Some(&flag) = pattern.get(flag_index) {
                    match flag {
                        b'u' | b'x' | b'R' => return true,
                        b'i' | b'm' | b's' | b'U' | b'-' => flag_index += 1,
                        b':' | b')' => break,
                        _ => break,
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    false
}

fn scan_domain_attributes(
    file: &mut File,
    end: u64,
    requested: &[String],
    present: &mut [bool],
    scratch: &mut Vec<u8>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoSite;
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        if field != 3 {
            skip_field_payload(file, wire, end, kind)?;
            continue;
        }
        require_wire(kind, wire, 2, "Domain.attribute")?;
        let len = read_length(file, end, kind)?;
        let start = position(file, kind)?;
        let attribute_end = checked_end(start, len, end, kind)?;
        let mut key_range = None;
        while position(file, kind)? < attribute_end {
            let (field, wire) = read_key(file, attribute_end, kind)?;
            match field {
                1 => {
                    require_wire(kind, wire, 2, "Attribute.key")?;
                    let len = read_length(file, attribute_end, kind)?;
                    let start = position(file, kind)?;
                    validate_utf8_bytes(file, len, attribute_end, kind)?;
                    // Protobuf singular string fields use the last occurrence.
                    key_range = Some((start, len));
                }
                2 | 3 => {
                    require_wire(kind, wire, 0, "Attribute value")?;
                    let _ = read_varint(file, attribute_end, kind)?;
                }
                _ => skip_field_payload(file, wire, attribute_end, kind)?,
            }
        }
        if let Some((offset, len)) = key_range {
            let len = usize::try_from(len)
                .map_err(|_| malformed_error(kind, "attribute key length does not fit usize"))?;
            read_scratch(file, offset, len, scratch, ledger, kind)?;
            let key = str::from_utf8(scratch).expect("validated attribute UTF-8");
            if key.is_ascii() {
                for (wanted, present) in requested.iter().zip(present.iter_mut()) {
                    *present |= wanted.eq_ignore_ascii_case(key);
                }
            } else {
                let key = fold_attribute(key);
                ledger.reserve(key.capacity())?;
                for (wanted, present) in requested.iter().zip(present.iter_mut()) {
                    *present |= *wanted == key;
                }
                ledger.release(key.capacity());
            }
        }
        seek(file, attribute_end, kind)?;
    }
    Ok(())
}

fn validate_attribute(file: &mut File, end: u64, kind: GeoDataKind) -> Result<(), GeoDataError> {
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match field {
            1 => {
                require_wire(kind, wire, 2, "Attribute.key")?;
                let len = read_length(file, end, kind)?;
                validate_utf8_bytes(file, len, end, kind)?;
            }
            2 | 3 => {
                require_wire(kind, wire, 0, "Attribute value")?;
                let _ = read_varint(file, end, kind)?;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    Ok(())
}

fn validate_utf8_bytes(
    file: &mut File,
    len: u64,
    end: u64,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    let start = position(file, kind)?;
    let _ = checked_end(start, len, end, kind)?;
    let mut remaining = len;
    let mut buffer = [0_u8; 256];
    let mut continuation = 0_u8;
    let mut first_min = 0x80_u8;
    let mut first_max = 0xbf_u8;
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("UTF-8 chunk length is bounded to 256");
        file.read_exact(&mut buffer[..take])
            .map_err(|source| io_error(kind, source))?;
        remaining -= take as u64;
        for &byte in &buffer[..take] {
            if continuation != 0 {
                if byte < first_min || byte > first_max {
                    return malformed(kind, "protobuf string field is not valid UTF-8");
                }
                continuation -= 1;
                first_min = 0x80;
                first_max = 0xbf;
                continue;
            }
            match byte {
                0x00..=0x7f => {}
                0xc2..=0xdf => continuation = 1,
                0xe0 => {
                    continuation = 2;
                    first_min = 0xa0;
                }
                0xe1..=0xec | 0xee..=0xef => continuation = 2,
                0xed => {
                    continuation = 2;
                    first_max = 0x9f;
                }
                0xf0 => {
                    continuation = 3;
                    first_min = 0x90;
                }
                0xf1..=0xf3 => continuation = 3,
                0xf4 => {
                    continuation = 3;
                    first_max = 0x8f;
                }
                _ => return malformed(kind, "protobuf string field is not valid UTF-8"),
            }
        }
    }
    if continuation != 0 {
        return malformed(kind, "protobuf string field ends inside a UTF-8 sequence");
    }
    Ok(())
}

fn append_site_value(
    kind: SitePatternKind,
    value: &[u8],
    patterns: &mut Vec<SitePattern>,
    values: &mut Vec<u8>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let start = u32::try_from(values.len()).map_err(|_| GeoDataError::ResourceLimit {
        resource: "GeoSite compact value offset",
        actual: values.len(),
        maximum: u32::MAX as usize,
    })?;
    ensure_vec_capacity(values, value.len(), ledger)?;
    values.extend_from_slice(value);
    ensure_vec_capacity(patterns, 1, ledger)?;
    patterns.push(SitePattern {
        kind,
        start,
        len: u32::try_from(value.len()).map_err(|_| GeoDataError::ResourceLimit {
            resource: "GeoSite compact value length",
            actual: value.len(),
            maximum: u32::MAX as usize,
        })?,
    });
    Ok(())
}

fn compile_regex_set(
    code: Code,
    bytes: &[u8],
    ranges: &[ValueRange],
    ledger: &mut AllocationLedger,
) -> Result<Vec<Regex>, GeoDataError> {
    let mut regexes = Vec::new();
    ensure_vec_capacity(&mut regexes, ranges.len(), ledger)?;

    // Use the library's normal byte-regex interface and default compiler/cache
    // protections. Vole adds no expression count, source or memory quota, and
    // does not request eager complete-DFA construction. Programs/search caches
    // are opaque to the ledger; only this owned vector is accounted.
    for range in ranges {
        let start = range.start as usize;
        let end = start + range.len as usize;
        let pattern = str::from_utf8(&bytes[start..end]).expect("validated Regex UTF-8");
        // Routing names are ASCII; keep byte-mode matching semantics while
        // retaining the library defaults for compilation and lazy caches.
        let result = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .map_err(|error| GeoDataError::InvalidRegex {
                code: code.as_str().to_owned(),
                // Syntax diagnostics contain the original expression. Do not
                // expose asset values through prepare/update errors or logs.
                detail: match error {
                    regex::Error::Syntax(_) => "invalid regex syntax",
                    regex::Error::CompiledTooBig(_) => {
                        "compiled regex exceeds the library default size limit"
                    }
                    _ => "regex compilation failed",
                }
                .to_owned(),
            });
        match result {
            Ok(regex) => regexes.push(regex),
            Err(error) => {
                release_vec(&regexes, ledger);
                return Err(error);
            }
        }
    }
    Ok(regexes)
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct Cidr4 {
    network: [u8; 4],
    prefix: u8,
}

impl Cidr4 {
    fn numeric(self) -> u32 {
        u32::from_be_bytes(self.network)
    }

    fn contains(self, address: u32) -> bool {
        mask_v4(address, self.prefix) == self.numeric()
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct Cidr6 {
    network: [u8; 16],
    prefix: u8,
}

impl Cidr6 {
    fn numeric(self) -> u128 {
        u128::from_be_bytes(self.network)
    }

    fn contains(self, address: u128) -> bool {
        mask_v6(address, self.prefix) == self.numeric()
    }
}

struct IpCategory {
    code: Code,
    v4: Vec<Cidr4>,
    v6: Vec<Cidr6>,
    selectors: Vec<String>,
}

impl IpCategory {
    fn has_selector(&self, selector: &str) -> bool {
        self.selectors
            .iter()
            .any(|requested| requested.eq_ignore_ascii_case(selector))
    }

    fn matches(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => {
                let address = u32::from(address);
                let at = self.v4.partition_point(|cidr| cidr.numeric() <= address);
                at != 0 && self.v4[at - 1].contains(address)
            }
            IpAddr::V6(address) => {
                let address = u128::from(address);
                let at = self.v6.partition_point(|cidr| cidr.numeric() <= address);
                at != 0 && self.v6[at - 1].contains(address)
            }
        }
    }
}

fn parse_ip_category(
    file: &mut File,
    range: SelectedRange,
    ledger: &mut AllocationLedger,
) -> Result<IpCategory, GeoDataError> {
    let kind = GeoDataKind::GeoIp;
    let end = checked_end(range.offset, range.len, u64::MAX, kind)?;
    seek(file, range.offset, kind)?;
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut seen_code = false;
    let mut remaining_records = range.record_count;
    let result = (|| {
        while position(file, kind)? < end {
            let (field, wire) = read_key(file, end, kind)?;
            match field {
                1 => {
                    require_wire(kind, wire, 2, "GeoIP code")?;
                    if seen_code {
                        return malformed(kind, "GeoIP contains code more than once");
                    }
                    let code = read_code(file, end, kind)?;
                    if code != range.code {
                        return malformed(kind, "GeoIP code changed between scan passes");
                    }
                    seen_code = true;
                }
                2 => {
                    require_wire(kind, wire, 2, "CIDR")?;
                    remaining_records = remaining_records.checked_sub(1).ok_or_else(|| {
                        malformed_error(kind, "GeoIP record count changed between scan passes")
                    })?;
                    let len = read_length(file, end, kind)?;
                    let start = position(file, kind)?;
                    let record_end = checked_end(start, len, end, kind)?;
                    parse_cidr_record(file, record_end, range.code, &mut v4, &mut v6, ledger)?;
                    seek(file, record_end, kind)?;
                }
                3 => {
                    require_wire(kind, wire, 0, "GeoIP.reverse_match")?;
                    let _ = read_varint(file, end, kind)?;
                }
                _ => skip_field_payload(file, wire, end, kind)?,
            }
        }
        if !seen_code {
            return malformed(kind, "GeoIP is missing code");
        }
        if remaining_records != 0 {
            return malformed(kind, "GeoIP record count changed between scan passes");
        }
        compact_v4(&mut v4);
        compact_v6(&mut v6);
        Ok(())
    })();
    match result {
        Ok(()) => Ok(IpCategory {
            code: range.code,
            v4,
            v6,
            selectors: Vec::new(),
        }),
        Err(error) => {
            release_vec(&v4, ledger);
            release_vec(&v6, ledger);
            Err(error)
        }
    }
}

fn parse_cidr_record(
    file: &mut File,
    end: u64,
    code: Code,
    v4: &mut Vec<Cidr4>,
    v6: &mut Vec<Cidr6>,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let kind = GeoDataKind::GeoIp;
    let mut ip = [0_u8; 16];
    let mut ip_len = None;
    let mut prefix = 0_u64;
    let mut seen_prefix = false;
    while position(file, kind)? < end {
        let (field, wire) = read_key(file, end, kind)?;
        match field {
            1 => {
                require_wire(kind, wire, 2, "CIDR.ip")?;
                if ip_len.is_some() {
                    return invalid_cidr(code, "CIDR.ip occurs more than once");
                }
                let len = read_length(file, end, kind)?;
                if len != 4 && len != 16 {
                    return invalid_cidr(code, "CIDR.ip must contain 4 or 16 bytes");
                }
                read_exact(file, &mut ip[..len as usize], end, kind)?;
                ip_len = Some(len as usize);
            }
            2 => {
                require_wire(kind, wire, 0, "CIDR.prefix")?;
                if seen_prefix {
                    return invalid_cidr(code, "CIDR.prefix occurs more than once");
                }
                prefix = read_varint(file, end, kind)?;
                seen_prefix = true;
            }
            _ => skip_field_payload(file, wire, end, kind)?,
        }
    }
    match ip_len {
        Some(4) if prefix <= 32 => {
            let numeric = mask_v4(
                u32::from_be_bytes(ip[..4].try_into().expect("four-byte slice")),
                prefix as u8,
            );
            ensure_vec_capacity(v4, 1, ledger)?;
            v4.push(Cidr4 {
                network: numeric.to_be_bytes(),
                prefix: prefix as u8,
            });
        }
        Some(16) if prefix <= 128 => {
            let numeric = mask_v6(u128::from_be_bytes(ip), prefix as u8);
            ensure_vec_capacity(v6, 1, ledger)?;
            v6.push(Cidr6 {
                network: numeric.to_be_bytes(),
                prefix: prefix as u8,
            });
        }
        Some(4 | 16) => return invalid_cidr(code, "CIDR.prefix exceeds address width"),
        _ => return invalid_cidr(code, "CIDR.ip is missing"),
    }
    Ok(())
}

fn compact_v4(values: &mut Vec<Cidr4>) {
    values.sort_unstable_by(|left, right| {
        left.numeric()
            .cmp(&right.numeric())
            .then(left.prefix.cmp(&right.prefix))
    });
    let mut write = 0_usize;
    for read in 0..values.len() {
        let value = values[read];
        if write != 0 && values[write - 1].contains(value.numeric()) {
            continue;
        }
        values[write] = value;
        write += 1;
        while write >= 2 && sibling_v4(values[write - 2], values[write - 1]) {
            let parent = Cidr4 {
                network: values[write - 2].network,
                prefix: values[write - 2].prefix - 1,
            };
            values[write - 2] = parent;
            write -= 1;
        }
    }
    values.truncate(write);
}

fn compact_v6(values: &mut Vec<Cidr6>) {
    values.sort_unstable_by(|left, right| {
        left.numeric()
            .cmp(&right.numeric())
            .then(left.prefix.cmp(&right.prefix))
    });
    let mut write = 0_usize;
    for read in 0..values.len() {
        let value = values[read];
        if write != 0 && values[write - 1].contains(value.numeric()) {
            continue;
        }
        values[write] = value;
        write += 1;
        while write >= 2 && sibling_v6(values[write - 2], values[write - 1]) {
            let parent = Cidr6 {
                network: values[write - 2].network,
                prefix: values[write - 2].prefix - 1,
            };
            values[write - 2] = parent;
            write -= 1;
        }
    }
    values.truncate(write);
}

fn sibling_v4(left: Cidr4, right: Cidr4) -> bool {
    if left.prefix == 0 || left.prefix != right.prefix {
        return false;
    }
    let parent_prefix = left.prefix - 1;
    let parent = mask_v4(left.numeric(), parent_prefix);
    left.numeric() == parent && right.numeric() == parent | (1_u32 << (32 - u32::from(left.prefix)))
}

fn sibling_v6(left: Cidr6, right: Cidr6) -> bool {
    if left.prefix == 0 || left.prefix != right.prefix {
        return false;
    }
    let parent_prefix = left.prefix - 1;
    let parent = mask_v6(left.numeric(), parent_prefix);
    left.numeric() == parent
        && right.numeric() == parent | (1_u128 << (128 - u32::from(left.prefix)))
}

fn mask_v4(address: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        address & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn mask_v6(address: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        address & (u128::MAX << (128 - u32::from(prefix)))
    }
}

fn read_code(file: &mut File, end: u64, kind: GeoDataKind) -> Result<Code, GeoDataError> {
    let len = read_length(file, end, kind)?;
    if len > MAX_CODE_BYTES as u64 {
        return Err(GeoDataError::InvalidCode {
            kind,
            code: "<more than 64 bytes>".to_owned(),
        });
    }
    let mut raw = [0_u8; MAX_CODE_BYTES];
    read_exact(file, &mut raw[..len as usize], end, kind)?;
    Code::parse(kind, &raw[..len as usize])
}

fn read_scratch(
    file: &mut File,
    offset: u64,
    len: usize,
    scratch: &mut Vec<u8>,
    ledger: &mut AllocationLedger,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    ensure_vec_capacity(scratch, len.saturating_sub(scratch.len()), ledger)?;
    scratch.resize(len, 0);
    seek(file, offset, kind)?;
    let end = offset
        .checked_add(len as u64)
        .ok_or_else(|| malformed_error(kind, "value range overflows u64"))?;
    read_exact(file, scratch, end, kind)
}

fn ensure_vec_capacity<T>(
    values: &mut Vec<T>,
    additional: usize,
    ledger: &mut AllocationLedger,
) -> Result<(), GeoDataError> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
    if required <= values.capacity() || mem::size_of::<T>() == 0 {
        return Ok(());
    }
    let desired = required.checked_next_power_of_two().unwrap_or(required);
    let old_capacity = values.capacity();
    // An allocator can move the buffer. Charge the entire new capacity while
    // the old allocation is still live, not only the retained-size delta.
    let requested_bytes = desired
        .checked_mul(mem::size_of::<T>())
        .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
    ledger.reserve(requested_bytes)?;
    let reserve_additional = desired - values.len();
    if values.try_reserve_exact(reserve_additional).is_err() {
        ledger.release(requested_bytes);
        return Err(GeoDataError::AllocationFailed {
            bytes: requested_bytes,
        });
    }
    let actual_elements = values.capacity();
    match actual_elements.cmp(&desired) {
        std::cmp::Ordering::Greater => {
            let extra = (actual_elements - desired)
                .checked_mul(mem::size_of::<T>())
                .ok_or(GeoDataError::AllocationFailed { bytes: usize::MAX })?;
            ledger.reserve(extra)?;
        }
        std::cmp::Ordering::Less => {
            ledger.release((desired - actual_elements) * mem::size_of::<T>());
        }
        std::cmp::Ordering::Equal => {}
    }
    ledger.release(old_capacity * mem::size_of::<T>());
    Ok(())
}

fn release_vec<T>(values: &Vec<T>, ledger: &mut AllocationLedger) {
    ledger.release(values.capacity().saturating_mul(mem::size_of::<T>()));
}

fn read_key(file: &mut File, end: u64, kind: GeoDataKind) -> Result<(u32, u8), GeoDataError> {
    let key = read_varint(file, end, kind)?;
    let field = key >> 3;
    let wire = (key & 7) as u8;
    if field == 0 || field > u64::from(u32::MAX) {
        return malformed(kind, "invalid protobuf field number");
    }
    Ok((field as u32, wire))
}

fn read_varint(file: &mut File, end: u64, kind: GeoDataKind) -> Result<u64, GeoDataError> {
    let mut value = 0_u64;
    for index in 0..10_u32 {
        if position(file, kind)? >= end {
            return malformed(kind, "truncated protobuf varint");
        }
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte)
            .map_err(|source| io_error(kind, source))?;
        if index == 9 && byte[0] > 1 {
            return malformed(kind, "protobuf varint overflows u64");
        }
        value |= u64::from(byte[0] & 0x7f) << (index * 7);
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    malformed(kind, "protobuf varint exceeds ten bytes")
}

fn read_length(file: &mut File, end: u64, kind: GeoDataKind) -> Result<u64, GeoDataError> {
    let len = read_varint(file, end, kind)?;
    let start = position(file, kind)?;
    let _ = checked_end(start, len, end, kind)?;
    Ok(len)
}

fn skip_field_payload(
    file: &mut File,
    wire: u8,
    end: u64,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    match wire {
        0 => {
            let _ = read_varint(file, end, kind)?;
            Ok(())
        }
        1 => skip_bytes(file, 8, end, kind),
        2 => {
            let len = read_length(file, end, kind)?;
            skip_bytes(file, len, end, kind)
        }
        5 => skip_bytes(file, 4, end, kind),
        _ => malformed(kind, "unsupported protobuf wire type"),
    }
}

fn skip_bytes(file: &mut File, len: u64, end: u64, kind: GeoDataKind) -> Result<(), GeoDataError> {
    let start = position(file, kind)?;
    let target = checked_end(start, len, end, kind)?;
    seek(file, target, kind)
}

fn read_exact(
    file: &mut File,
    output: &mut [u8],
    end: u64,
    kind: GeoDataKind,
) -> Result<(), GeoDataError> {
    let start = position(file, kind)?;
    let len = u64::try_from(output.len())
        .map_err(|_| malformed_error(kind, "read length does not fit u64"))?;
    let _ = checked_end(start, len, end, kind)?;
    file.read_exact(output)
        .map_err(|source| io_error(kind, source))
}

fn checked_end(
    start: u64,
    len: u64,
    outer_end: u64,
    kind: GeoDataKind,
) -> Result<u64, GeoDataError> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| malformed_error(kind, "length-delimited field overflows u64"))?;
    if end > outer_end {
        return malformed(kind, "length-delimited field exceeds enclosing message");
    }
    Ok(end)
}

fn position(file: &mut File, kind: GeoDataKind) -> Result<u64, GeoDataError> {
    file.stream_position()
        .map_err(|source| io_error(kind, source))
}

fn seek(file: &mut File, position: u64, kind: GeoDataKind) -> Result<(), GeoDataError> {
    file.seek(SeekFrom::Start(position))
        .map(|_| ())
        .map_err(|source| io_error(kind, source))
}

fn require_wire(
    kind: GeoDataKind,
    actual: u8,
    expected: u8,
    field: &'static str,
) -> Result<(), GeoDataError> {
    if actual != expected {
        return malformed(
            kind,
            &format!("{field} uses wire type {actual}, expected {expected}"),
        );
    }
    Ok(())
}

fn io_error(kind: GeoDataKind, source: std::io::Error) -> GeoDataError {
    GeoDataError::Io {
        path: PathBuf::from(kind.file_name()),
        source,
    }
}

fn malformed<T>(kind: GeoDataKind, detail: &str) -> Result<T, GeoDataError> {
    Err(malformed_error(kind, detail))
}

fn malformed_error(kind: GeoDataKind, detail: &str) -> GeoDataError {
    GeoDataError::Malformed {
        kind,
        detail: detail.to_owned(),
    }
}

fn invalid_domain<T>(code: Code, detail: &str) -> Result<T, GeoDataError> {
    Err(invalid_domain_error(code, detail))
}

fn invalid_domain_error(code: Code, detail: &str) -> GeoDataError {
    GeoDataError::InvalidDomain {
        code: code.as_str().to_owned(),
        detail: detail.to_owned(),
    }
}

fn invalid_cidr<T>(code: Code, detail: &str) -> Result<T, GeoDataError> {
    Err(GeoDataError::InvalidCidr {
        code: code.as_str().to_owned(),
        detail: detail.to_owned(),
    })
}

#[cfg(test)]
mod tests;
