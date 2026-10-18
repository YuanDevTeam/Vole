use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::{
    GeoData, GeoDataKind, GeoRequirements, load_ips_for_requirements, load_sites_for_requirements,
    validate_asset_structure,
};
use crate::routing::GeoMatcher;

const STATE_FILE: &str = "state.json";
const UPDATE_LOCK_FILE: &str = "update.lock";
const STATE_VERSION: u8 = 1;
const MAX_STATE_ERROR_BYTES: usize = 4_096;
const MAX_ETAG_BYTES: usize = 1_024;
const MAX_SOURCE_URL_BYTES: usize = 4_096;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
struct SnapshotReleaseState {
    released: Mutex<bool>,
    changed: Condvar,
}

impl SnapshotReleaseState {
    fn wait(&self, cancellation: &CancellationToken) -> Result<(), GeoDataManagerError> {
        let deadline = Instant::now() + crate::resource::http::DEFAULT_DOWNLOAD_TIMEOUT;
        let mut released = lock(&self.released);
        while !*released {
            check_cancellation(cancellation)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(GeoDataManagerError::Validation(
                    "GeoData readers did not release the retired snapshot in time".to_owned(),
                ));
            }
            (released, _) = self
                .changed
                .wait_timeout(released, remaining.min(Duration::from_millis(25)))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        check_cancellation(cancellation)
    }
}

/// Last GeoData field; dropping it proves all matcher storage was destroyed.
pub(super) struct SnapshotRelease(Arc<SnapshotReleaseState>);

impl SnapshotRelease {
    pub(super) fn new() -> Self {
        Self(Arc::new(SnapshotReleaseState::default()))
    }
}

impl Drop for SnapshotRelease {
    fn drop(&mut self) {
        *lock(&self.0.released) = true;
        self.0.changed.notify_all();
    }
}

/// Lock-free routing matcher whose immutable snapshot can be replaced without
/// stopping readers or the owning Vole instance.
pub struct DynamicGeoData {
    current: ArcSwap<GeoData>,
}

impl DynamicGeoData {
    #[must_use]
    pub fn new(snapshot: Arc<GeoData>) -> Self {
        Self {
            current: ArcSwap::from(snapshot),
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::new(Arc::new(GeoData::EMPTY))
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<GeoData> {
        self.current.load_full()
    }

    pub fn activate(&self, snapshot: Arc<GeoData>) {
        self.current.store(snapshot);
    }
}

impl Default for DynamicGeoData {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for DynamicGeoData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicGeoData")
            .field("snapshot", &self.current.load())
            .finish()
    }
}

impl GeoMatcher for DynamicGeoData {
    fn asn_available(&self) -> bool {
        self.current.load().asn_available()
    }
    fn matches_asn(&self, payload: &str, address: IpAddr) -> bool {
        self.current.load().matches_asn(payload, address)
    }
    fn routing_snapshot(&self) -> Option<Arc<dyn GeoMatcher>> {
        Some(self.current.load_full())
    }

    fn geosite_available(&self, code: &str) -> bool {
        self.current.load().geosite_available(code)
    }

    fn geoip_available(&self, code: &str) -> bool {
        self.current.load().geoip_available(code)
    }

    fn matches_geosite(&self, code: &str, domain: &str) -> bool {
        self.current.load().matches_geosite(code, domain)
    }

    fn matches_geosite_bounded(
        &self,
        code: &str,
        domain: &str,
        decision: &crate::config::RuleDecision,
    ) -> Result<bool, crate::config::MatchFailure> {
        self.current
            .load()
            .matches_geosite_bounded(code, domain, decision)
    }

    fn matches_geoip(&self, code: &str, address: IpAddr) -> bool {
        self.current.load().matches_geoip(code, address)
    }
}

/// Result for one independently degradable GeoData resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataResourceReport {
    pub required: bool,
    pub available: bool,
    pub error: Option<String>,
}

impl GeoDataResourceReport {
    const fn not_required() -> Self {
        Self {
            required: false,
            available: false,
            error: None,
        }
    }

    const fn available() -> Self {
        Self {
            required: true,
            available: true,
            error: None,
        }
    }

    fn degraded(error: impl ToString) -> Self {
        Self {
            required: true,
            available: false,
            error: Some(bounded_error(error.to_string())),
        }
    }
}

/// Degraded-or-ready result produced while building one immutable matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataLoadReport {
    pub geosite: GeoDataResourceReport,
    pub geoip: GeoDataResourceReport,
    pub asn: GeoDataResourceReport,
    pub allocation_capacity: usize,
    pub peak_allocation_capacity: usize,
}

impl GeoDataLoadReport {
    #[must_use]
    pub const fn resource(&self, kind: GeoDataKind) -> &GeoDataResourceReport {
        match kind {
            GeoDataKind::GeoSite => &self.geosite,
            GeoDataKind::GeoIp => &self.geoip,
            GeoDataKind::Asn => &self.asn,
        }
    }
}

/// Durable update state for one resource. `required` is process-local and is
/// overlaid from the manager's active registration; the other fields are read
/// from the cross-process state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoResourceState {
    pub required: bool,
    pub available: bool,
    pub updating: bool,
    pub last_success: Option<u64>,
    pub next_check: Option<u64>,
    pub last_error: Option<String>,
    pub etag: Option<String>,
    pub hash: Option<String>,
    pub(crate) source_url: Option<String>,
    pub(crate) source_identity: Option<String>,
    pub(crate) asset_identity: Option<String>,
}

/// Current resource-manager view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataStatus {
    pub geosite: GeoResourceState,
    pub geoip: GeoResourceState,
    pub asn: GeoResourceState,
}

impl GeoDataStatus {
    #[must_use]
    pub const fn resource(&self, kind: GeoDataKind) -> &GeoResourceState {
        match kind {
            GeoDataKind::GeoSite => &self.geosite,
            GeoDataKind::GeoIp => &self.geoip,
            GeoDataKind::Asn => &self.asn,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataReloadReport {
    pub active_registration: bool,
    pub geosite_required: bool,
    pub geosite_available: bool,
    pub geoip_required: bool,
    pub geoip_available: bool,
    pub asn_required: bool,
    pub asn_available: bool,
}

#[derive(Debug, Error)]
pub enum GeoDataManagerError {
    #[error("GeoData operation was cancelled")]
    Cancelled,
    #[error("GeoData manager I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("another process is already updating GeoData")]
    UpdateBusy,
    #[error("GeoData manager already has an active registration")]
    RegistrationActive,
    #[error("GeoData updater reported {reported} bytes but staged file contains {actual} bytes")]
    SizeMismatch { reported: u64, actual: u64 },
    #[error("GeoData update ETag exceeds {MAX_ETAG_BYTES} bytes")]
    EtagTooLarge,
    #[error("GeoData {kind} source URL exceeds {MAX_SOURCE_URL_BYTES} bytes")]
    SourceUrlTooLarge { kind: GeoDataKind },
    #[error("GeoData update validation failed: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistentResourceState {
    available: bool,
    updating: bool,
    last_success: Option<u64>,
    next_check: Option<u64>,
    last_error: Option<String>,
    etag: Option<String>,
    hash: Option<String>,
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    source_identity: Option<String>,
    #[serde(default)]
    asset_identity: Option<String>,
}

impl PersistentResourceState {
    fn with_required(&self, required: bool, degraded: Option<&str>) -> GeoResourceState {
        GeoResourceState {
            required,
            available: if required {
                degraded.is_none()
            } else {
                self.available
            },
            updating: self.updating,
            last_success: self.last_success,
            next_check: self.next_check,
            last_error: degraded
                .map(ToOwned::to_owned)
                .or_else(|| self.last_error.clone()),
            etag: self.etag.clone(),
            hash: self.hash.clone(),
            source_url: self
                .source_url
                .as_deref()
                .and_then(crate::resource::http::source_origin),
            source_identity: self.source_identity.clone().or_else(|| {
                self.source_url
                    .as_deref()
                    .filter(|raw| {
                        url::Url::parse(raw).ok().is_some_and(|url| {
                            url.username().is_empty() && url.password().is_none()
                        })
                    })
                    .map(crate::resource::http::source_identity)
            }),
            asset_identity: self.asset_identity.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistentState {
    #[serde(default = "state_version")]
    version: u8,
    #[serde(default)]
    geosite: PersistentResourceState,
    #[serde(default)]
    geoip: PersistentResourceState,
    #[serde(default)]
    asn: PersistentResourceState,
}

impl PersistentState {
    fn resource_mut(&mut self, kind: GeoDataKind) -> &mut PersistentResourceState {
        match kind {
            GeoDataKind::GeoSite => &mut self.geosite,
            GeoDataKind::GeoIp => &mut self.geoip,
            GeoDataKind::Asn => &mut self.asn,
        }
    }
}

const fn state_version() -> u8 {
    STATE_VERSION
}

#[derive(Debug)]
struct RegistrationEntry {
    lease: Arc<()>,
    requirements: GeoRequirements,
    assets: AssetPaths,
    matcher: Arc<DynamicGeoData>,
    report: GeoDataLoadReport,
    retired: Option<Arc<SnapshotReleaseState>>,
    reload_pending: bool,
}

impl RegistrationEntry {
    fn unload(&mut self) {
        self.reload_pending = true;
        let old = self.matcher.current.swap(Arc::new(GeoData::EMPTY));
        if let Some(release) = &old.release {
            self.retired = Some(release.0.clone());
        }
        drop(old);
        self.report = GeoDataLoadReport {
            geosite: dormant_report(&self.requirements, GeoDataKind::GeoSite),
            geoip: dormant_report(&self.requirements, GeoDataKind::GeoIp),
            asn: dormant_report(&self.requirements, GeoDataKind::Asn),
            allocation_capacity: 0,
            peak_allocation_capacity: 0,
        };
    }

    /// MMDB candidates are fully verified while old data is still usable.
    /// Retain one rollback reference until all other snapshot readers finish.
    fn unload_verified_database(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<(), GeoDataManagerError> {
        self.drain(cancellation)?;
        let mut old = self.matcher.current.swap(Arc::new(GeoData::EMPTY));
        let deadline = Instant::now() + crate::resource::http::DEFAULT_DOWNLOAD_TIMEOUT;
        loop {
            if let Err(error) = check_cancellation(cancellation) {
                self.matcher.activate(old);
                return Err(error);
            }
            // try_unwrap atomically obtains exclusive ownership, so a Weak
            // upgrade cannot retain the old payload after this succeeds.
            match Arc::try_unwrap(old) {
                Ok(snapshot) => {
                    // Payload fields drop before SnapshotRelease.
                    drop(snapshot);
                    break;
                }
                Err(snapshot) => old = snapshot,
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.matcher.activate(old);
                return Err(GeoDataManagerError::Validation(
                    "GeoData readers did not release the retired snapshot in time".to_owned(),
                ));
            }
            std::thread::sleep(remaining.min(Duration::from_millis(25)));
        }
        self.unload();
        Ok(())
    }

    fn drain(&mut self, cancellation: &CancellationToken) -> Result<(), GeoDataManagerError> {
        if let Some(retired) = &self.retired {
            retired.wait(cancellation)?;
            self.retired = None;
        }
        check_cancellation(cancellation)
    }

    fn publish(&mut self, snapshot: Arc<GeoData>, report: GeoDataLoadReport) {
        self.matcher.activate(snapshot);
        self.report = report;
        self.reload_pending = false;
    }
}

/// Fixed paths for one registration. MMDB discovery never changes the store
/// used by GeoSite/ASN, state, locks, or provider data-directory derivation.
#[derive(Debug, Clone)]
struct AssetPaths {
    store_dir: PathBuf,
    geoip: PathBuf,
    mmdb: bool,
    discovery_error: Option<String>,
}

impl AssetPaths {
    fn dat(store_dir: &Path) -> Self {
        Self {
            store_dir: store_dir.into(),
            geoip: store_dir.join(super::GEOIP_FILE_NAME),
            mmdb: false,
            discovery_error: None,
        }
    }

    fn for_registration(store_dir: &Path, geodata_mode: bool) -> Self {
        Self::discover(store_dir, geodata_mode).unwrap_or_else(|error| Self {
            store_dir: store_dir.into(),
            geoip: store_dir.parent().unwrap_or(store_dir).join("geoip.metadb"),
            mmdb: true,
            discovery_error: Some(bounded_error(error.to_string())),
        })
    }

    fn discover(store_dir: &Path, geodata_mode: bool) -> Result<Self, GeoDataManagerError> {
        if geodata_mode {
            return Ok(Self::dat(store_dir));
        }
        let root = store_dir.parent().unwrap_or(store_dir);
        let mut selected = None;
        for entry in fs::read_dir(root).map_err(|source| io_at(root, source))? {
            let entry = entry.map_err(|source| io_at(root, source))?;
            let name = entry.file_name();
            let Some(text) = name.to_str() else { continue };
            if !["Country.mmdb", "geoip.db", "geoip.metadb"]
                .iter()
                .any(|expected| text.eq_ignore_ascii_case(expected))
                || entry
                    .file_type()
                    .map_err(|source| io_at(&entry.path(), source))?
                    .is_dir()
            {
                continue;
            }
            if selected.as_ref().is_none_or(|old| &name < old) {
                selected = Some(name);
            }
        }
        Ok(Self {
            store_dir: store_dir.into(),
            geoip: root.join(selected.unwrap_or_else(|| "geoip.metadb".into())),
            mmdb: true,
            discovery_error: None,
        })
    }

    fn path(&self, kind: GeoDataKind) -> PathBuf {
        if kind == GeoDataKind::GeoIp {
            self.geoip.clone()
        } else {
            self.store_dir.join(kind.file_name())
        }
    }

    fn identity(&self, kind: GeoDataKind) -> String {
        if kind == GeoDataKind::GeoIp {
            format!(
                "{}:{}",
                if self.mmdb { "mmdb" } else { "dat" },
                self.geoip.file_name().unwrap().to_string_lossy()
            )
        } else {
            kind.file_name().into()
        }
    }

    fn staged(&self, directory: &Path) -> Self {
        Self {
            store_dir: directory.into(),
            geoip: directory.join(self.geoip.file_name().unwrap()),
            mmdb: self.mmdb,
            discovery_error: self.discovery_error.clone(),
        }
    }
}

enum VerifiedCandidate {
    Asn(super::asn::AsnCandidate),
    Country(super::country::CountryCandidate),
}

#[derive(Default)]
struct UpdateSource {
    url: Option<String>,
    etag: Option<String>,
}

fn dormant_report(requirements: &GeoRequirements, kind: GeoDataKind) -> GeoDataResourceReport {
    if requirements.requires(kind) {
        GeoDataResourceReport::degraded("GeoData matcher is unavailable while reloading")
    } else {
        GeoDataResourceReport::not_required()
    }
}

fn check_cancellation(cancellation: &CancellationToken) -> Result<(), GeoDataManagerError> {
    if cancellation.is_cancelled() {
        Err(GeoDataManagerError::Cancelled)
    } else {
        Ok(())
    }
}

/// Core-owned GeoData store and hot-reload registry.
///
/// `asset_dir` is the fixed stable writable GeoData directory selected by the
/// runtime-wide data-directory layer.
#[derive(Debug)]
pub struct GeoDataManager {
    store_dir: PathBuf,
    update_interval: AtomicU64,
    state: Mutex<PersistentState>,
    registration: Mutex<Option<RegistrationEntry>>,
}

impl GeoDataManager {
    pub fn open(
        asset_dir: impl AsRef<Path>,
        update_interval: Duration,
    ) -> Result<Arc<Self>, GeoDataManagerError> {
        let asset_dir = asset_dir.as_ref();
        create_private_directory(asset_dir)?;
        // AppContainer can use its ApplicationData path through normal file
        // APIs, but Windows denies canonicalizing that same package path.
        #[cfg(windows)]
        let store_dir = asset_dir.to_path_buf();
        #[cfg(not(windows))]
        let store_dir = fs::canonicalize(asset_dir).map_err(|source| io_at(asset_dir, source))?;
        let state = read_initial_state(&store_dir)?;
        let manager = Arc::new(Self {
            store_dir,
            update_interval: AtomicU64::new(update_interval.as_secs()),
            state: Mutex::new(state),
            registration: Mutex::new(None),
        });
        manager.recover_interrupted_state()?;
        Ok(manager)
    }

    #[must_use]
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// Registers the active configuration's requirements and immediately
    /// provides its matcher. A manager accepts exactly one live registration;
    /// callers must drop it before registering the next configuration.
    ///
    /// Missing, damaged, or incomplete resource files produce a dormant kind
    /// in the report rather than a registration failure.
    pub fn register(
        self: &Arc<Self>,
        requirements: GeoRequirements,
    ) -> Result<GeoDataRegistration, GeoDataManagerError> {
        self.register_with_interval(
            requirements,
            Duration::from_secs(self.update_interval.load(Ordering::Relaxed)),
        )
    }

    pub(crate) fn register_with_interval(
        self: &Arc<Self>,
        requirements: GeoRequirements,
        interval: Duration,
    ) -> Result<GeoDataRegistration, GeoDataManagerError> {
        let mut registration = lock(&self.registration);
        if registration.is_some() {
            return Err(GeoDataManagerError::RegistrationActive);
        }
        self.update_interval
            .store(interval.as_secs(), Ordering::Relaxed);
        let assets = AssetPaths::for_registration(&self.store_dir, requirements.geodata_mode);
        let (snapshot, report) = load_snapshot(&assets, &requirements);
        let matcher = Arc::new(DynamicGeoData::new(snapshot));
        let lease = Arc::new(());
        *registration = Some(RegistrationEntry {
            lease: lease.clone(),
            requirements,
            assets,
            matcher: matcher.clone(),
            report: report.clone(),
            retired: None,
            reload_pending: false,
        });
        Ok(GeoDataRegistration {
            lease,
            matcher,
            initial_report: report,
            manager: Arc::downgrade(self),
        })
    }

    /// Unloads the active matchers before loading current resource files.
    /// New decisions skip unavailable Geo rules; other rules remain active.
    /// GeoSite and GeoIP recover independently, just as on initial registration.
    pub fn reload(&self) -> GeoDataReloadReport {
        if let Err(error) = self.reload_with_cancellation(&CancellationToken::new()) {
            tracing::warn!(%error, "GeoData reload left its matchers unavailable");
        }
        reload_report(lock(&self.registration).as_ref())
    }

    pub(crate) fn reload_with_cancellation(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<GeoDataReloadReport, GeoDataManagerError> {
        // Serialize management operations through publication so a reload
        // started before an update cannot later publish an older snapshot.
        // Routing readers use ArcSwap and never acquire this lock.
        let mut registration = lock(&self.registration);
        if let Some(entry) = registration.as_mut() {
            // The disk generation may already be cached. Keep a retry signal
            // even when cancellation prevents unloading the current matcher.
            entry.reload_pending = true;
            check_cancellation(cancellation)?;
            if entry.assets.discovery_error.is_some() {
                entry.assets =
                    AssetPaths::for_registration(&self.store_dir, entry.requirements.geodata_mode);
            }
            entry.unload();
            entry.drain(cancellation)?;
            let (snapshot, report) = load_snapshot(&entry.assets, &entry.requirements);
            check_cancellation(cancellation)?;
            entry.publish(snapshot, report);
        }
        Ok(reload_report(registration.as_ref()))
    }

    pub(crate) fn replace_requirements(
        &self,
        lease: &GeoDataRegistrationLease,
        requirements: GeoRequirements,
        cancellation: &CancellationToken,
    ) -> Result<(), GeoDataManagerError> {
        let mut registration = lock(&self.registration);
        let entry = registration
            .as_mut()
            .filter(|entry| lease.matches(entry))
            .ok_or(GeoDataManagerError::RegistrationActive)?;
        if entry.requirements == requirements {
            return Ok(());
        }
        check_cancellation(cancellation)?;
        entry.unload();
        entry.drain(cancellation)?;
        if entry.requirements.geodata_mode != requirements.geodata_mode {
            entry.assets = AssetPaths::for_registration(&self.store_dir, requirements.geodata_mode);
        }
        entry.requirements = requirements;
        let (snapshot, report) = load_snapshot(&entry.assets, &entry.requirements);
        check_cancellation(cancellation)?;
        entry.publish(snapshot, report);
        Ok(())
    }

    fn refresh_durable_state(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<PersistentState, GeoDataManagerError> {
        check_cancellation(cancellation)?;
        let mut disk = read_state(&self.store_dir)?;
        if disk.geosite.updating || disk.geoip.updating || disk.asn.updating {
            self.recover_interrupted_state()?;
            disk = read_state(&self.store_dir)?;
        }
        self.observe_durable_state(&disk, cancellation)?;
        Ok(disk)
    }

    fn observe_durable_state(
        &self,
        disk: &PersistentState,
        cancellation: &CancellationToken,
    ) -> Result<(), GeoDataManagerError> {
        let generation_changed = {
            let mut cached = lock(&self.state);
            let changed = asset_generation_changed(&cached, disk);
            *cached = disk.clone();
            changed
        };
        let reload_pending = lock(&self.registration)
            .as_ref()
            .is_some_and(|entry| entry.reload_pending);
        if generation_changed || reload_pending {
            self.reload_with_cancellation(cancellation)?;
        }
        Ok(())
    }

    pub fn status(&self) -> Result<GeoDataStatus, GeoDataManagerError> {
        let disk = self.refresh_durable_state(&CancellationToken::new())?;
        Ok(status_for_entry(&disk, lock(&self.registration).as_ref()))
    }

    /// Returns the durable scheduling state for the active registration.
    /// `None` means the supplied lease is stale or already dropped.
    pub(super) fn status_for_active_registration(
        &self,
        lease: &GeoDataRegistrationLease,
        cancellation: &CancellationToken,
    ) -> Result<Option<GeoDataStatus>, GeoDataManagerError> {
        let disk = self.refresh_durable_state(cancellation)?;
        let registration = lock(&self.registration);
        Ok(registration
            .as_ref()
            .filter(|entry| lease.matches(entry))
            .map(|entry| scoped_status(&disk, &entry.report)))
    }

    /// Returns required resources whose durable next-check time has elapsed.
    pub fn due_resources(&self, now: SystemTime) -> Result<Vec<GeoDataKind>, GeoDataManagerError> {
        let now = unix_seconds(now);
        let status = self.status()?;
        Ok(GeoDataKind::ALL
            .into_iter()
            .filter(|kind| {
                let resource = status.resource(*kind);
                resource.required
                    && !resource.updating
                    && (!resource.available
                        || resource
                            .next_check
                            .is_none_or(|next_check| next_check <= now))
            })
            .collect())
    }

    /// Returns resources due for the active configuration and its source URLs.
    /// A source change is immediately due regardless of the previous source's
    /// durable next-check time.
    #[cfg(test)]
    pub(crate) fn due_resources_for_active_registration<const N: usize>(
        &self,
        lease: &GeoDataRegistrationLease,
        sources: [(GeoDataKind, &str); N],
        now: SystemTime,
    ) -> Result<Vec<GeoDataKind>, GeoDataManagerError> {
        self.due_resources_for_active_registration_with_cancellation(
            lease,
            sources,
            now,
            &CancellationToken::new(),
        )
    }

    pub(crate) fn due_resources_for_active_registration_with_cancellation<const N: usize>(
        &self,
        lease: &GeoDataRegistrationLease,
        sources: [(GeoDataKind, &str); N],
        now: SystemTime,
        cancellation: &CancellationToken,
    ) -> Result<Vec<GeoDataKind>, GeoDataManagerError> {
        let now = unix_seconds(now);
        let Some(status) = self.status_for_active_registration(lease, cancellation)? else {
            return Ok(Vec::new());
        };
        let registration = lock(&self.registration);
        let Some(entry) = registration.as_ref().filter(|entry| lease.matches(entry)) else {
            return Ok(Vec::new());
        };
        Ok(sources
            .into_iter()
            .filter_map(|(kind, source_url)| {
                resource_due(
                    status.resource(kind),
                    source_url,
                    &entry.assets.identity(kind),
                    now,
                    self.update_interval.load(Ordering::Relaxed),
                )
                .then_some(kind)
            })
            .collect())
    }

    /// Starts one cross-process serialized streaming update. The returned
    /// session owns a unique, still-absent temporary path. The downloader must
    /// create that path with `create_new`, stream and `sync_all` it before
    /// calling `commit`.
    pub fn begin_update(
        self: &Arc<Self>,
        kind: GeoDataKind,
    ) -> Result<GeoUpdateSession, GeoDataManagerError> {
        let lock_file = self.acquire_update_lock()?;
        let state = read_state(&self.store_dir)?;
        let assets = lock(&self.registration).as_ref().map_or_else(
            || AssetPaths::dat(&self.store_dir),
            |entry| entry.assets.clone(),
        );
        self.start_update_session(
            kind,
            UpdateSource::default(),
            None,
            lock_file,
            state,
            assets,
        )
    }

    /// Begins a source-bound update only if the active registration is still
    /// due after acquiring the cross-process update lock. The second due check
    /// lets a later process observe the winner's durable state instead of
    /// downloading the same resource again.
    #[cfg(test)]
    pub(crate) fn begin_update_for_active_registration(
        self: &Arc<Self>,
        lease: &GeoDataRegistrationLease,
        kind: GeoDataKind,
        source_url: &str,
        now: SystemTime,
    ) -> Result<Option<GeoUpdateSession>, GeoDataManagerError> {
        self.begin_update_for_active_registration_with_cancellation(
            lease,
            kind,
            source_url,
            now,
            &CancellationToken::new(),
        )
    }

    pub(crate) fn begin_update_for_active_registration_with_cancellation(
        self: &Arc<Self>,
        lease: &GeoDataRegistrationLease,
        kind: GeoDataKind,
        source_url: &str,
        now: SystemTime,
        cancellation: &CancellationToken,
    ) -> Result<Option<GeoUpdateSession>, GeoDataManagerError> {
        check_cancellation(cancellation)?;
        if source_url.len() > MAX_SOURCE_URL_BYTES {
            return Err(GeoDataManagerError::SourceUrlTooLarge { kind });
        }
        let lock_file = self.acquire_update_lock()?;
        let state = read_state(&self.store_dir)?;
        self.observe_durable_state(&state, cancellation)?;
        let selected = {
            let registration = lock(&self.registration);
            registration
                .as_ref()
                .filter(|entry| lease.matches(entry))
                .map(|entry| (scoped_status(&state, &entry.report), entry.assets.clone()))
        };
        let Some((status, assets)) = selected else {
            return Ok(None);
        };
        if !resource_due(
            status.resource(kind),
            source_url,
            &assets.identity(kind),
            unix_seconds(now),
            self.update_interval.load(Ordering::Relaxed),
        ) {
            return Ok(None);
        }
        let resource = status.resource(kind);
        let request_etag = (resource.source_identity.as_deref()
            == Some(crate::resource::http::source_identity(source_url).as_str())
            && resource.asset_identity.as_deref() == Some(assets.identity(kind).as_str())
            && resource.available
            && resource
                .hash
                .as_deref()
                .is_some_and(|expected| asset_matches_hash(&assets.path(kind), expected)))
        .then(|| resource.etag.clone())
        .flatten();
        self.start_update_session(
            kind,
            UpdateSource {
                url: Some(source_url.to_owned()),
                etag: request_etag,
            },
            Some(lease.clone()),
            lock_file,
            state,
            assets,
        )
        .map(Some)
    }

    fn acquire_update_lock(&self) -> Result<File, GeoDataManagerError> {
        let lock_path = self.store_dir.join(UPDATE_LOCK_FILE);
        let lock_file = open_lock_file(&lock_path)?;
        match lock_file.try_lock() {
            Ok(()) => Ok(lock_file),
            Err(TryLockError::WouldBlock) => Err(GeoDataManagerError::UpdateBusy),
            Err(TryLockError::Error(source)) => Err(io_at(&lock_path, source)),
        }
    }

    fn start_update_session(
        self: &Arc<Self>,
        kind: GeoDataKind,
        source: UpdateSource,
        validation_lease: Option<GeoDataRegistrationLease>,
        lock_file: File,
        mut state: PersistentState,
        mut assets: AssetPaths,
    ) -> Result<GeoUpdateSession, GeoDataManagerError> {
        if kind == GeoDataKind::GeoIp && assets.discovery_error.is_some() {
            assets = AssetPaths::discover(&self.store_dir, !assets.mmdb)?;
            if let Some(entry) = lock(&self.registration).as_mut()
                && entry.assets.discovery_error.is_some()
                && entry.assets.mmdb == assets.mmdb
                && validation_lease
                    .as_ref()
                    .is_none_or(|lease| lease.matches(entry))
            {
                entry.assets = assets.clone();
            }
        }
        let staging_dir = assets.path(kind).parent().unwrap().join(format!(
            ".update-{}-{}",
            std::process::id(),
            next_nonzero_id(&NEXT_TEMP_ID)
        ));
        create_private_directory_new(&staging_dir)?;
        let staging_path = assets.staged(&staging_dir).path(kind);

        state.resource_mut(kind).updating = true;
        persist_state(&self.store_dir, &state)?;
        *lock(&self.state) = state;

        Ok(GeoUpdateSession {
            manager: self.clone(),
            kind,
            assets,
            lock_file,
            staging_dir,
            staging_path,
            source_url: source.url,
            request_etag: source.etag,
            validation_lease,
            completed: false,
        })
    }

    fn recover_interrupted_state(&self) -> Result<(), GeoDataManagerError> {
        let lock_path = self.store_dir.join(UPDATE_LOCK_FILE);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| io_at(&lock_path, source))?;
        if lock_file.try_lock().is_err() {
            return Ok(());
        }
        let mut state = read_state(&self.store_dir)?;
        let mut changed = false;
        for kind in GeoDataKind::ALL {
            let resource = state.resource_mut(kind);
            if resource.updating {
                resource.updating = false;
                resource.last_error = Some("previous GeoData update was interrupted".to_owned());
                changed = true;
            }
        }
        if changed {
            persist_state(&self.store_dir, &state)?;
            *lock(&self.state) = state;
        }
        let _ = lock_file.unlock();
        Ok(())
    }

    fn stage_candidate(
        &self,
        kind: GeoDataKind,
        candidate_dir: &Path,
        assets: &AssetPaths,
    ) -> Result<Option<VerifiedCandidate>, GeoDataManagerError> {
        let verified = if kind == GeoDataKind::Asn {
            Some(VerifiedCandidate::Asn(
                super::asn::AsnCandidate::load(candidate_dir)
                    .map_err(|error| GeoDataManagerError::Validation(error.to_string()))?,
            ))
        } else if kind == GeoDataKind::GeoIp && assets.mmdb {
            Some(VerifiedCandidate::Country(
                super::country::CountryCandidate::load(&assets.staged(candidate_dir).geoip)
                    .map_err(|error| GeoDataManagerError::Validation(error.to_string()))?,
            ))
        } else {
            None
        };
        if verified.is_none() {
            validate_asset_structure(candidate_dir, kind)
                .map_err(|error| GeoDataManagerError::Validation(error.to_string()))?;
        }

        for other in GeoDataKind::ALL.into_iter().filter(|other| *other != kind) {
            let other_source = assets.path(other);
            let other_candidate = assets.staged(candidate_dir).path(other);
            if other_source.is_file() && fs::hard_link(&other_source, &other_candidate).is_err() {
                fs::copy(&other_source, &other_candidate)
                    .map_err(|source| io_at(&other_candidate, source))?;
            }
        }

        Ok(verified)
    }

    fn finish_success(
        &self,
        kind: GeoDataKind,
        source_url: Option<String>,
        etag: Option<String>,
        hash: String,
        asset_identity: String,
    ) -> Result<(), GeoDataManagerError> {
        let now = unix_seconds(SystemTime::now());
        let interval = self.update_interval.load(Ordering::Relaxed);
        let mut state = read_state(&self.store_dir)?;
        let resource = state.resource_mut(kind);
        resource.available = true;
        resource.updating = false;
        resource.last_success = Some(now);
        resource.next_check = Some(now.saturating_add(interval));
        resource.last_error = None;
        resource.etag = etag;
        resource.hash = Some(hash);
        resource.source_identity = source_url
            .as_deref()
            .map(crate::resource::http::source_identity);
        resource.source_url = source_url
            .as_deref()
            .and_then(crate::resource::http::source_origin);
        resource.asset_identity = Some(asset_identity);
        persist_state(&self.store_dir, &state)?;
        *lock(&self.state) = state;
        Ok(())
    }

    fn finish_not_modified(
        &self,
        kind: GeoDataKind,
        source_url: Option<String>,
        etag: Option<String>,
        asset_identity: String,
    ) -> Result<(), GeoDataManagerError> {
        let now = unix_seconds(SystemTime::now());
        let mut state = read_state(&self.store_dir)?;
        let resource = state.resource_mut(kind);
        resource.updating = false;
        resource.last_success = Some(now);
        resource.next_check =
            Some(now.saturating_add(self.update_interval.load(Ordering::Relaxed)));
        resource.last_error = None;
        if etag.is_some() {
            resource.etag = etag;
        }
        resource.source_identity = source_url
            .as_deref()
            .map(crate::resource::http::source_identity);
        resource.source_url = source_url
            .as_deref()
            .and_then(crate::resource::http::source_origin);
        resource.asset_identity = Some(asset_identity);
        persist_state(&self.store_dir, &state)?;
        *lock(&self.state) = state;
        Ok(())
    }

    fn finish_failure(&self, kind: GeoDataKind, error: &str) {
        let Ok(mut state) = read_state(&self.store_dir) else {
            return;
        };
        let resource = state.resource_mut(kind);
        resource.updating = false;
        resource.last_error = Some(bounded_error(error.to_owned()));
        let _ = persist_state(&self.store_dir, &state);
        *lock(&self.state) = state;
    }

    fn unregister(&self, lease: &Arc<()>) {
        let mut registration = lock(&self.registration);
        if registration
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(&entry.lease, lease))
        {
            *registration = None;
        }
    }
}

/// Type-safe identity used by the updater for the one active registration.
///
/// Holding this lease does not keep the manager slot active after the owning
/// `GeoDataRegistration` is dropped.
#[derive(Clone)]
pub(crate) struct GeoDataRegistrationLease {
    lease: Arc<()>,
}

impl GeoDataRegistrationLease {
    fn matches(&self, entry: &RegistrationEntry) -> bool {
        Arc::ptr_eq(&self.lease, &entry.lease)
    }
}

impl std::fmt::Debug for GeoDataRegistrationLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeoDataRegistrationLease")
            .finish_non_exhaustive()
    }
}

/// RAII registration for the active configuration. Dropping it clears the
/// manager slot; cloned matcher Arcs remain valid.
pub struct GeoDataRegistration {
    lease: Arc<()>,
    matcher: Arc<DynamicGeoData>,
    initial_report: GeoDataLoadReport,
    manager: Weak<GeoDataManager>,
}

impl GeoDataRegistration {
    #[must_use]
    pub(crate) fn updater_lease(&self) -> GeoDataRegistrationLease {
        GeoDataRegistrationLease {
            lease: self.lease.clone(),
        }
    }

    #[must_use]
    pub fn matcher(&self) -> Arc<DynamicGeoData> {
        self.matcher.clone()
    }

    #[must_use]
    pub const fn initial_report(&self) -> &GeoDataLoadReport {
        &self.initial_report
    }
}

impl std::fmt::Debug for GeoDataRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeoDataRegistration")
            .field("initial_report", &self.initial_report)
            .finish_non_exhaustive()
    }
}

impl Drop for GeoDataRegistration {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            manager.unregister(&self.lease);
        }
    }
}

/// Candidate transaction held under the cross-process update lock.
pub struct GeoUpdateSession {
    manager: Arc<GeoDataManager>,
    kind: GeoDataKind,
    assets: AssetPaths,
    lock_file: File,
    staging_dir: PathBuf,
    staging_path: PathBuf,
    source_url: Option<String>,
    request_etag: Option<String>,
    validation_lease: Option<GeoDataRegistrationLease>,
    completed: bool,
}

impl GeoUpdateSession {
    #[must_use]
    pub const fn kind(&self) -> GeoDataKind {
        self.kind
    }

    #[must_use]
    pub fn temporary_path(&self) -> &Path {
        &self.staging_path
    }

    #[must_use]
    pub(crate) fn request_etag(&self) -> Option<&str> {
        self.request_etag.as_deref()
    }

    pub fn commit(
        self,
        etag: Option<String>,
        sha256: [u8; 32],
        size: u64,
    ) -> Result<GeoDataReloadReport, GeoDataManagerError> {
        self.commit_with_cancellation(etag, sha256, size, &CancellationToken::new())
    }

    pub(crate) fn commit_with_cancellation(
        mut self,
        etag: Option<String>,
        sha256: [u8; 32],
        size: u64,
        cancellation: &CancellationToken,
    ) -> Result<GeoDataReloadReport, GeoDataManagerError> {
        if etag
            .as_ref()
            .is_some_and(|value| value.len() > MAX_ETAG_BYTES)
        {
            return self.finish_error(GeoDataManagerError::EtagTooLarge);
        }
        let result = self.commit_inner(etag, sha256, size, cancellation);
        match result {
            Ok(report) => {
                self.completed = true;
                let _ = fs::remove_dir_all(&self.staging_dir);
                let _ = self.lock_file.unlock();
                Ok(report)
            }
            Err(error) => self.finish_error(error),
        }
    }

    /// Completes an HTTP 304-style check without replacing the current file.
    pub fn not_modified(self, etag: Option<String>) -> Result<(), GeoDataManagerError> {
        self.not_modified_with_cancellation(etag, &CancellationToken::new())
    }

    pub(crate) fn not_modified_with_cancellation(
        mut self,
        etag: Option<String>,
        cancellation: &CancellationToken,
    ) -> Result<(), GeoDataManagerError> {
        if etag
            .as_ref()
            .is_some_and(|value| value.len() > MAX_ETAG_BYTES)
        {
            return self.finish_error(GeoDataManagerError::EtagTooLarge);
        }
        let result = self.not_modified_inner(etag, cancellation);
        if let Err(error) = result {
            return self.finish_error(error);
        }
        self.completed = true;
        let _ = fs::remove_dir_all(&self.staging_dir);
        let _ = self.lock_file.unlock();
        Ok(())
    }

    fn not_modified_inner(
        &self,
        etag: Option<String>,
        cancellation: &CancellationToken,
    ) -> Result<(), GeoDataManagerError> {
        check_cancellation(cancellation)?;
        let mut registration = lock(&self.manager.registration);
        self.validate_active_lease(registration.as_ref())?;
        let candidate = if let Some(entry) = registration.as_mut()
            && GeoDataKind::ALL.into_iter().any(|kind| {
                let report = entry.report.resource(kind);
                report.required && !report.available
            }) {
            entry.unload();
            entry.drain(cancellation)?;
            Some(load_snapshot(&entry.assets, &entry.requirements))
        } else {
            None
        };
        check_cancellation(cancellation)?;
        self.manager.finish_not_modified(
            self.kind,
            self.source_url.clone(),
            etag,
            self.assets.identity(self.kind),
        )?;
        check_cancellation(cancellation)?;
        if let Some(entry) = registration.as_mut()
            && let Some((snapshot, report)) = candidate
        {
            entry.publish(snapshot, report);
        }
        Ok(())
    }

    pub fn fail(mut self, message: impl Into<String>) -> Result<(), GeoDataManagerError> {
        let message = bounded_error(message.into());
        self.manager.finish_failure(self.kind, &message);
        self.completed = true;
        let cleanup = fs::remove_dir_all(&self.staging_dir);
        let _ = self.lock_file.unlock();
        cleanup.map_err(|source| io_at(&self.staging_dir, source))
    }

    fn commit_inner(
        &mut self,
        etag: Option<String>,
        sha256: [u8; 32],
        reported_size: u64,
        cancellation: &CancellationToken,
    ) -> Result<GeoDataReloadReport, GeoDataManagerError> {
        check_cancellation(cancellation)?;
        let metadata = fs::symlink_metadata(&self.staging_path)
            .map_err(|source| io_at(&self.staging_path, source))?;
        if !metadata.file_type().is_file() {
            return Err(GeoDataManagerError::Validation(
                "GeoData updater did not create a regular candidate file".to_owned(),
            ));
        }
        let actual_size = metadata.len();
        if actual_size != reported_size {
            return Err(GeoDataManagerError::SizeMismatch {
                reported: reported_size,
                actual: actual_size,
            });
        }

        // Keep the validated registration and candidate stable until both the
        // durable commit and publication finish. No routing read takes this lock.
        let mut registration = lock(&self.manager.registration);
        self.validate_active_lease(registration.as_ref())?;
        // Framing checks and disk staging do not allocate matchers. Keep the
        // old rules until this boundary, then release every old reader before
        // constructing the new generation.
        let candidate = self
            .manager
            .stage_candidate(self.kind, &self.staging_dir, &self.assets)?;
        if let Some(candidate) = candidate {
            return self.commit_verified_candidate(
                &mut registration,
                candidate,
                etag,
                sha256,
                cancellation,
            );
        }
        let candidate = if let Some(entry) = registration.as_mut()
            && entry.requirements.requires(self.kind)
        {
            entry.unload();
            entry.drain(cancellation)?;
            let (snapshot, report) =
                load_snapshot(&self.assets.staged(&self.staging_dir), &entry.requirements);
            check_cancellation(cancellation)?;
            let target = report.resource(self.kind);
            if !target.available {
                let error = target
                    .error
                    .clone()
                    .unwrap_or_else(|| format!("{} candidate is unavailable", self.kind));
                // Reuse initial-load degradation: only the failed kind is
                // missing. Keep the previous disk asset for a future retry.
                entry.publish(snapshot, report);
                return Err(GeoDataManagerError::Validation(error));
            }
            Some((snapshot, report))
        } else {
            None
        };
        check_cancellation(cancellation)?;
        let destination = self.assets.path(self.kind);
        fs::rename(&self.staging_path, &destination)
            .map_err(|source| io_at(&destination, source))?;
        sync_directory(destination.parent().unwrap())?;

        self.manager.finish_success(
            self.kind,
            self.source_url.clone(),
            etag,
            hex_digest(&sha256),
            self.assets.identity(self.kind),
        )?;
        check_cancellation(cancellation)?;
        if let Some(entry) = registration.as_mut()
            && let Some((snapshot, report)) = candidate
        {
            entry.publish(snapshot, report);
        }
        Ok(reload_report(registration.as_ref()))
    }

    /// MMDB validation, persistence and recovery are separate from DAT's
    /// existing degraded-reload contract. A failed candidate never becomes
    /// the replacement for a usable MMDB generation.
    fn commit_verified_candidate(
        &self,
        registration: &mut Option<RegistrationEntry>,
        candidate: VerifiedCandidate,
        etag: Option<String>,
        sha256: [u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<GeoDataReloadReport, GeoDataManagerError> {
        let destination = self.assets.path(self.kind);
        let previous_path = self.staging_dir.join("previous.mmdb");
        let previous = read_state(&self.manager.store_dir)?;
        let had_file = destination.is_file();
        if had_file && fs::hard_link(&destination, &previous_path).is_err() {
            fs::copy(&destination, &previous_path)
                .map_err(|source| io_at(&previous_path, source))?;
        }
        let mut retired = false;
        let mut file_published = false;
        let result = (|| {
            check_cancellation(cancellation)?;
            let loaded = if let Some(entry) = registration.as_mut()
                && entry.requirements.requires(self.kind)
            {
                entry.unload_verified_database(cancellation)?;
                retired = true;
                let (snapshot, report) = load_snapshot_with_candidate(
                    &self.assets.staged(&self.staging_dir),
                    &entry.requirements,
                    Some(candidate),
                );
                if !report.resource(self.kind).available {
                    return Err(GeoDataManagerError::Validation(
                        report
                            .resource(self.kind)
                            .error
                            .clone()
                            .unwrap_or_else(|| "MMDB candidate unavailable".into()),
                    ));
                }
                Some((snapshot, report))
            } else {
                None
            };
            check_cancellation(cancellation)?;
            fs::rename(&self.staging_path, &destination)
                .map_err(|source| io_at(&destination, source))?;
            file_published = true;
            sync_directory(destination.parent().unwrap())?;
            self.manager.finish_success(
                self.kind,
                self.source_url.clone(),
                etag,
                hex_digest(&sha256),
                self.assets.identity(self.kind),
            )?;
            check_cancellation(cancellation)?;
            if let Some(entry) = registration.as_mut()
                && let Some((snapshot, report)) = loaded
            {
                entry.publish(snapshot, report);
            }
            Ok(reload_report(registration.as_ref()))
        })();
        if let Err(original) = result {
            // The candidate snapshot/buffer has left the closure and dropped
            // before recovery reads the previous file into owned storage.
            let mut disk_restored = !file_published;
            let rollback = if file_published {
                (|| {
                    if had_file {
                        fs::rename(&previous_path, &destination)
                            .map_err(|source| io_at(&destination, source))?;
                    } else {
                        fs::remove_file(&destination)
                            .map_err(|source| io_at(&destination, source))?;
                    }
                    disk_restored = true;
                    sync_directory(destination.parent().unwrap())?;
                    persist_state(&self.manager.store_dir, &previous)?;
                    *lock(&self.manager.state) = previous;
                    Ok::<(), GeoDataManagerError>(())
                })()
            } else {
                Ok(())
            };
            if retired && let Some(entry) = registration.as_mut() {
                if disk_restored {
                    let (snapshot, report) = load_snapshot(&entry.assets, &entry.requirements);
                    entry.publish(snapshot, report);
                } else {
                    // An actual disk/state rollback error is exceptional. Do
                    // not present uncertain on-disk ASN contents as the old generation.
                    let mut requirements = entry.requirements.clone();
                    match self.kind {
                        GeoDataKind::Asn => requirements.asn = false,
                        GeoDataKind::GeoIp => requirements.ips = super::CodeSet::EMPTY,
                        GeoDataKind::GeoSite => unreachable!(),
                    }
                    let (snapshot, mut report) = load_snapshot(&entry.assets, &requirements);
                    let unavailable =
                        GeoDataResourceReport::degraded("MMDB disk state could not be restored");
                    match self.kind {
                        GeoDataKind::Asn => report.asn = unavailable,
                        GeoDataKind::GeoIp => report.geoip = unavailable,
                        GeoDataKind::GeoSite => unreachable!(),
                    }
                    entry.publish(snapshot, report);
                }
            }
            if let Err(rollback) = rollback {
                return Err(GeoDataManagerError::Validation(bounded_error(format!(
                    "MMDB update failed: {original}; previous disk state could not be restored: {rollback}"
                ))));
            }
            return Err(original);
        }
        result
    }

    fn validate_active_lease(
        &self,
        registration: Option<&RegistrationEntry>,
    ) -> Result<(), GeoDataManagerError> {
        if registration.is_some_and(|entry| {
            entry.assets.mmdb != self.assets.mmdb || entry.assets.geoip != self.assets.geoip
        }) {
            return Err(GeoDataManagerError::Validation(
                "GeoData update asset selection is no longer active".into(),
            ));
        }
        if let Some(lease) = &self.validation_lease {
            let entry = registration
                .filter(|entry| lease.matches(entry))
                .ok_or_else(|| {
                    GeoDataManagerError::Validation(
                        "GeoData update registration is no longer active".to_owned(),
                    )
                })?;
            if !entry.requirements.requires(self.kind) {
                return Err(GeoDataManagerError::Validation(format!(
                    "GeoData active registration does not require {}",
                    self.kind
                )));
            }
        }
        Ok(())
    }

    fn finish_error<T>(mut self, error: GeoDataManagerError) -> Result<T, GeoDataManagerError> {
        self.manager.finish_failure(self.kind, &error.to_string());
        self.completed = true;
        let _ = fs::remove_dir_all(&self.staging_dir);
        let _ = self.lock_file.unlock();
        Err(error)
    }
}

impl std::fmt::Debug for GeoUpdateSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeoUpdateSession")
            .field("kind", &self.kind)
            .field("staging_path", &self.staging_path)
            .finish_non_exhaustive()
    }
}

impl Drop for GeoUpdateSession {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.manager
            .finish_failure(self.kind, "GeoData update was cancelled");
        let _ = fs::remove_dir_all(&self.staging_dir);
        let _ = self.lock_file.unlock();
    }
}

fn load_snapshot(
    assets: &AssetPaths,
    requirements: &GeoRequirements,
) -> (Arc<GeoData>, GeoDataLoadReport) {
    load_snapshot_with_candidate(assets, requirements, None)
}

fn load_snapshot_with_candidate(
    assets: &AssetPaths,
    requirements: &GeoRequirements,
    candidate: Option<VerifiedCandidate>,
) -> (Arc<GeoData>, GeoDataLoadReport) {
    let mut sites = Vec::new();
    let mut ips = Vec::new();
    let mut used: usize = 0;
    let mut peak: usize = 0;
    let mut site_report = GeoDataResourceReport::not_required();
    let mut ip_report = GeoDataResourceReport::not_required();
    let mut asn_report = GeoDataResourceReport::not_required();
    let mut asn = None;
    let mut country = None;
    let (country_candidate, asn_candidate) = match candidate {
        Some(VerifiedCandidate::Country(value)) => (Some(value), None),
        Some(VerifiedCandidate::Asn(value)) => (None, Some(value)),
        None => (None, None),
    };

    if requirements.requires(GeoDataKind::GeoIp)
        && let Some(error) = &assets.discovery_error
    {
        ip_report = GeoDataResourceReport::degraded(error);
    } else if requirements.requires(GeoDataKind::GeoIp) && assets.mmdb {
        match country_candidate.map_or_else(
            || super::country::CountryDb::load(&assets.geoip, &requirements.ips.selectors),
            |candidate| candidate.into_database(&requirements.ips.selectors),
        ) {
            Ok(database) => {
                if let Some(total) = used.checked_add(database.capacity()) {
                    used = total;
                    peak = peak.max(used);
                    country = Some(database);
                    ip_report = GeoDataResourceReport::available();
                } else {
                    ip_report =
                        GeoDataResourceReport::degraded("country allocation capacity overflow");
                }
            }
            Err(error) => ip_report = GeoDataResourceReport::degraded(error),
        }
    } else if requirements.requires(GeoDataKind::GeoIp) {
        match load_ips_for_requirements(
            &assets.store_dir,
            requirements.code_set(GeoDataKind::GeoIp),
            used,
            peak,
        ) {
            Ok(loaded) => {
                ips = loaded.values;
                used = loaded.used;
                peak = loaded.peak;
                ip_report = GeoDataResourceReport::available();
            }
            // A failed kind does not disable independent GeoSite routing.
            Err(error) => ip_report = GeoDataResourceReport::degraded(error),
        }
    }
    if requirements.requires(GeoDataKind::GeoSite) {
        match load_sites_for_requirements(
            &assets.store_dir,
            requirements.code_set(GeoDataKind::GeoSite),
            used,
            peak,
        ) {
            Ok(loaded) => {
                sites = loaded.values;
                used = loaded.used;
                peak = loaded.peak;
                site_report = GeoDataResourceReport::available();
            }
            Err(error) => site_report = GeoDataResourceReport::degraded(error),
        }
    }

    if requirements.requires(GeoDataKind::Asn) {
        match asn_candidate.map_or_else(
            || super::asn::AsnDb::load(&assets.store_dir),
            super::asn::AsnCandidate::into_database,
        ) {
            Ok(database) => {
                if let Some(total) = used.checked_add(database.capacity()) {
                    used = total;
                    peak = peak.max(used);
                    asn = Some(database);
                    asn_report = GeoDataResourceReport::available();
                } else {
                    asn_report =
                        GeoDataResourceReport::degraded("ASN allocation capacity overflow");
                }
            }
            Err(error) => asn_report = GeoDataResourceReport::degraded(error),
        }
    }
    let snapshot = Arc::new(GeoData::from_loaded(sites, ips, country, asn, used, peak));
    (
        snapshot,
        GeoDataLoadReport {
            geosite: site_report,
            geoip: ip_report,
            asn: asn_report,
            allocation_capacity: used,
            peak_allocation_capacity: peak,
        },
    )
}

fn reload_report(registration: Option<&RegistrationEntry>) -> GeoDataReloadReport {
    let geosite = registration.map(|entry| &entry.report.geosite);
    let geoip = registration.map(|entry| &entry.report.geoip);
    let asn = registration.map(|entry| &entry.report.asn);
    GeoDataReloadReport {
        active_registration: registration.is_some(),
        geosite_required: geosite.is_some_and(|report| report.required),
        geosite_available: geosite.is_some_and(|report| report.required && report.available),
        geoip_required: geoip.is_some_and(|report| report.required),
        geoip_available: geoip.is_some_and(|report| report.required && report.available),
        asn_required: asn.is_some_and(|report| report.required),
        asn_available: asn.is_some_and(|report| report.required && report.available),
    }
}

fn scoped_status(disk: &PersistentState, report: &GeoDataLoadReport) -> GeoDataStatus {
    let site_error = report_error(&report.geosite);
    let ip_error = report_error(&report.geoip);
    GeoDataStatus {
        geosite: disk
            .geosite
            .with_required(report.geosite.required, site_error),
        geoip: disk.geoip.with_required(report.geoip.required, ip_error),
        asn: disk
            .asn
            .with_required(report.asn.required, report_error(&report.asn)),
    }
}

fn status_for_entry(
    disk: &PersistentState,
    registration: Option<&RegistrationEntry>,
) -> GeoDataStatus {
    registration.map_or_else(
        || GeoDataStatus {
            geosite: disk.geosite.with_required(false, None),
            geoip: disk.geoip.with_required(false, None),
            asn: disk.asn.with_required(false, None),
        },
        |entry| scoped_status(disk, &entry.report),
    )
}

fn report_error(report: &GeoDataResourceReport) -> Option<&str> {
    (report.required && !report.available)
        .then_some(report.error.as_deref())
        .flatten()
}

fn resource_due(
    resource: &GeoResourceState,
    source_url: &str,
    asset_identity: &str,
    now: u64,
    interval: u64,
) -> bool {
    resource.required
        && !resource.updating
        && (!resource.available
            || resource.source_identity.as_deref()
                != Some(crate::resource::http::source_identity(source_url).as_str())
            || resource.asset_identity.as_deref() != Some(asset_identity)
            || resource
                .last_success
                .is_none_or(|last| last.saturating_add(interval) <= now))
}

fn asset_matches_hash(path: &Path, expected: &str) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8 * 1_024];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => return false,
        };
        digest.update(&buffer[..read]);
    }
    hex_digest(&digest.finalize().into()) == expected
}

fn open_lock_file(path: &Path) -> Result<File, GeoDataManagerError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| io_at(path, source))
}

fn create_private_directory(path: &Path) -> Result<(), GeoDataManagerError> {
    fs::create_dir_all(path).map_err(|source| io_at(path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_at(path, source))?;
    }
    Ok(())
}

fn create_private_directory_new(path: &Path) -> Result<(), GeoDataManagerError> {
    fs::create_dir(path).map_err(|source| io_at(path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_at(path, source))?;
    }
    Ok(())
}

fn read_state(store_dir: &Path) -> Result<PersistentState, GeoDataManagerError> {
    let path = store_dir.join(STATE_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PersistentState {
                version: STATE_VERSION,
                ..PersistentState::default()
            });
        }
        Err(source) => return Err(io_at(&path, source)),
    };
    let state: PersistentState = serde_json::from_slice(&bytes).map_err(|error| {
        GeoDataManagerError::Validation(format!("invalid GeoData state file: {error}"))
    })?;
    if state.version != STATE_VERSION {
        return Err(GeoDataManagerError::Validation(format!(
            "unsupported GeoData state version {}; expected {STATE_VERSION}",
            state.version
        )));
    }
    Ok(state)
}

fn read_initial_state(store_dir: &Path) -> Result<PersistentState, GeoDataManagerError> {
    match read_state(store_dir) {
        Ok(state) => Ok(state),
        Err(GeoDataManagerError::Validation(error)) => {
            // GeoData metadata is advisory for scheduling. A damaged state
            // file must not prevent the business core from initializing.
            let lock_path = store_dir.join(UPDATE_LOCK_FILE);
            let lock_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(|source| io_at(&lock_path, source))?;
            match lock_file.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => {
                    tracing::warn!(
                        error = %error,
                        "ignoring invalid GeoData state while another process owns the update lock"
                    );
                    return Ok(PersistentState {
                        version: STATE_VERSION,
                        ..PersistentState::default()
                    });
                }
                Err(TryLockError::Error(source)) => return Err(io_at(&lock_path, source)),
            }

            // Re-read under the lock in case another process repaired the
            // atomic state file before this process acquired ownership.
            let recovered = match read_state(store_dir) {
                Ok(state) => Ok(state),
                Err(GeoDataManagerError::Validation(current_error)) => {
                    tracing::warn!(
                        error = current_error,
                        "resetting invalid GeoData scheduling state"
                    );
                    let state = PersistentState {
                        version: STATE_VERSION,
                        ..PersistentState::default()
                    };
                    persist_state(store_dir, &state)?;
                    Ok(state)
                }
                Err(other) => Err(other),
            };
            let _ = lock_file.unlock();
            recovered
        }
        Err(error) => Err(error),
    }
}

fn persist_state(store_dir: &Path, state: &PersistentState) -> Result<(), GeoDataManagerError> {
    let bytes = serde_json::to_vec(state).map_err(|error| {
        GeoDataManagerError::Validation(format!("failed to serialize GeoData state: {error}"))
    })?;
    let temporary = store_dir.join(format!(
        ".state-{}-{}.tmp",
        std::process::id(),
        next_nonzero_id(&NEXT_TEMP_ID)
    ));
    let destination = store_dir.join(STATE_FILE);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| io_at(&temporary, source))?;
        file.write_all(&bytes)
            .map_err(|source| io_at(&temporary, source))?;
        file.sync_all()
            .map_err(|source| io_at(&temporary, source))?;
        drop(file);
        fs::rename(&temporary, &destination).map_err(|source| io_at(&destination, source))?;
        sync_directory(store_dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), GeoDataManagerError> {
    // ponytail: Windows has no portable directory fsync; staged files are
    // flushed before atomic rename. Use a write-through Win32 rename only if
    // crash testing proves this metadata durability insufficient.
    Ok(())
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), GeoDataManagerError> {
    let directory = File::open(path).map_err(|source| io_at(path, source))?;
    directory.sync_all().map_err(|source| io_at(path, source))
}

fn next_nonzero_id(counter: &AtomicU64) -> u64 {
    loop {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn asset_generation_changed(previous: &PersistentState, current: &PersistentState) -> bool {
    previous.geosite.hash != current.geosite.hash
        || previous.geosite.last_success != current.geosite.last_success
        || previous.geoip.asset_identity != current.geoip.asset_identity
        || previous.geoip.hash != current.geoip.hash
        || previous.geoip.last_success != current.geoip.last_success
        || previous.asn.hash != current.asn.hash
        || previous.asn.last_success != current.asn.last_success
}

fn hex_digest(value: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(64);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn bounded_error(mut message: String) -> String {
    if message.len() <= MAX_STATE_ERROR_BYTES {
        return message;
    }
    let mut boundary = MAX_STATE_ERROR_BYTES;
    while boundary != 0 && !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message
}

fn io_at(path: &Path, source: io::Error) -> GeoDataManagerError {
    GeoDataManagerError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tempfile::tempdir;

    use super::super::GeoDataError;
    use super::*;
    use crate::config::{DnsNameserverPolicy, RuleAction, RuleKind, RuleSpec};

    #[test]
    fn source_identity_is_private_and_changes_invalidate_update_scheduling() {
        let first = "https://user:first@asset.example/data?token=private";
        let second = "https://user:second@asset.example/data?token=private";
        let resource = PersistentResourceState {
            available: true,
            last_success: Some(10),
            source_url: crate::resource::http::source_origin(first),
            source_identity: Some(crate::resource::http::source_identity(first)),
            asset_identity: Some("same-asset".into()),
            ..Default::default()
        };
        let stored = serde_json::to_string(&resource).unwrap();
        assert!(!stored.contains("user"));
        assert!(!stored.contains("first"));
        assert!(!stored.contains("private"));
        let view = resource.with_required(true, None);
        assert_eq!(view.source_url.as_deref(), Some("https://asset.example"));
        assert!(!resource_due(&view, first, "same-asset", 11, 3600));
        assert!(resource_due(&view, second, "same-asset", 11, 3600));
        let legacy = PersistentResourceState {
            source_url: Some("https://asset.example/data".into()),
            source_identity: None,
            ..resource.clone()
        }
        .with_required(true, None);
        assert!(!resource_due(
            &legacy,
            "https://asset.example/data",
            "same-asset",
            11,
            3600
        ));
        let legacy_auth = PersistentResourceState {
            source_url: Some(first.into()),
            source_identity: None,
            ..resource
        }
        .with_required(true, None);
        assert!(resource_due(&legacy_auth, first, "same-asset", 11, 3600));
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut output = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                return output;
            }
        }
    }

    fn field_varint(field: u32, value: u64) -> Vec<u8> {
        let mut output = varint(u64::from(field) << 3);
        output.extend(varint(value));
        output
    }

    fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
        let mut output = varint((u64::from(field) << 3) | 2);
        output.extend(varint(value.len() as u64));
        output.extend(value);
        output
    }

    fn site_file(code: &str, suffix: &str) -> Vec<u8> {
        let mut domain = field_varint(1, 2);
        domain.extend(field_bytes(2, suffix.as_bytes()));
        let mut site = field_bytes(1, code.as_bytes());
        site.extend(field_bytes(2, &domain));
        field_bytes(1, &site)
    }

    fn ip_file(code: &str, address: [u8; 4], prefix: u64) -> Vec<u8> {
        let mut cidr = field_bytes(1, &address);
        cidr.extend(field_varint(2, prefix));
        let mut geoip = field_bytes(1, code.as_bytes());
        geoip.extend(field_bytes(2, &cidr));
        field_bytes(1, &geoip)
    }

    fn rule(kind: RuleKind) -> RuleSpec {
        RuleSpec {
            kind,
            action: RuleAction::Route(crate::config::RouteTargetId::Proxy(
                crate::config::ProxyId::new(0).unwrap(),
            )),
            no_resolve: false,
        }
    }

    #[test]
    fn asn_update_verifies_before_retiring_and_preserves_healthy_siblings() {
        let dir = tempdir().unwrap();
        let fixture = super::super::asn_tests::FIXTURE;
        let asn_path = dir.path().join(super::super::ASN_FILE_NAME);
        fs::write(&asn_path, fixture).unwrap();
        fs::write(
            dir.path().join(super::super::GEOSITE_FILE_NAME),
            site_file("cn", "example.test"),
        )
        .unwrap();
        fs::write(
            dir.path().join(super::super::GEOIP_FILE_NAME),
            ip_file("cn", [10, 0, 0, 0], 8),
        )
        .unwrap();
        let manager = GeoDataManager::open(dir.path(), Duration::from_secs(3600)).unwrap();
        let registration = manager
            .register(requirements(&[
                rule(RuleKind::IpAsn("15169".into())),
                rule(RuleKind::GeoSite("cn".into())),
                rule(RuleKind::GeoIp("cn".into())),
            ]))
            .unwrap();
        let matcher = registration.matcher();
        let before = matcher.snapshot();
        assert!(registration.initial_report().asn.available);
        for malformed in [b"broken".to_vec(), {
            let mut bytes = fixture.to_vec();
            bytes[..6].fill(255);
            bytes
        }] {
            let update = manager.begin_update(GeoDataKind::Asn).unwrap();
            fs::write(update.temporary_path(), &malformed).unwrap();
            assert!(
                update
                    .commit(
                        None,
                        Sha256::digest(&malformed).into(),
                        malformed.len() as u64
                    )
                    .is_err()
            );
            assert!(Arc::ptr_eq(&before, &matcher.snapshot()));
            assert_eq!(fs::read(&asn_path).unwrap(), fixture);
            assert!(matcher.matches_asn("15169", "1.0.0.1".parse().unwrap()));
            assert!(manager.status().unwrap().asn.last_error.is_some());
        }
        let released = before.release.as_ref().unwrap().0.clone();
        drop(before);
        let update = manager.begin_update(GeoDataKind::Asn).unwrap();
        fs::write(update.temporary_path(), fixture).unwrap();
        let report = update
            .commit(
                Some("asn-v1".into()),
                Sha256::digest(fixture).into(),
                fixture.len() as u64,
            )
            .unwrap();
        assert!(*lock(&released.released));
        assert!(report.asn_available && report.geosite_available && report.geoip_available);
        assert!(matcher.matches_geosite("cn", "www.example.test"));
        assert!(matcher.matches_geoip("cn", "10.0.0.1".parse().unwrap()));
        let status = manager.status().unwrap();
        assert_eq!(status.asn.etag.as_deref(), Some("asn-v1"));
        assert!(status.asn.hash.is_some() && status.asn.last_success.is_some());
        let current = matcher.snapshot();
        manager
            .begin_update(GeoDataKind::Asn)
            .unwrap()
            .not_modified(Some("asn-v1".into()))
            .unwrap();
        assert!(Arc::ptr_eq(&current, &matcher.snapshot()));
        let lease = registration.updater_lease();
        assert_eq!(
            manager
                .due_resources_for_active_registration(
                    &lease,
                    [(GeoDataKind::Asn, "https://assets.example.test/ASN.mmdb")],
                    SystemTime::now()
                )
                .unwrap(),
            [GeoDataKind::Asn]
        );
    }

    #[test]
    fn asn_state_io_failure_restores_old_file_and_matcher() {
        let dir = tempdir().unwrap();
        let fixture = super::super::asn_tests::FIXTURE;
        let asn_path = dir.path().join(super::super::ASN_FILE_NAME);
        fs::write(&asn_path, fixture).unwrap();
        let manager = GeoDataManager::open(dir.path(), Duration::from_secs(3600)).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::IpAsn("15169".into()))]))
            .unwrap();
        let matcher = registration.matcher();
        let old = matcher.snapshot();
        let update = manager.begin_update(GeoDataKind::Asn).unwrap();
        fs::write(update.temporary_path(), fixture).unwrap();
        let worker = std::thread::spawn(move || {
            update.commit(None, Sha256::digest(fixture).into(), fixture.len() as u64)
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while matcher.asn_available() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!matcher.asn_available());
        // The commit has verified the candidate and is waiting for this old
        // reader. Turn only the state destination into an actual I/O error.
        let state_path = dir.path().join(STATE_FILE);
        fs::remove_file(&state_path).unwrap();
        fs::create_dir(&state_path).unwrap();
        drop(old);
        assert!(worker.join().unwrap().is_err());
        assert_eq!(fs::read(&asn_path).unwrap(), fixture);
        assert!(matcher.matches_asn("15169", "1.0.0.1".parse().unwrap()));
        fs::remove_dir(&state_path).unwrap();
        assert!(manager.status().unwrap().asn.available);
    }

    #[test]
    fn asn_retirement_cancellation_restores_previous_snapshot() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(super::super::ASN_FILE_NAME),
            super::super::asn_tests::FIXTURE,
        )
        .unwrap();
        let manager = GeoDataManager::open(dir.path(), Duration::from_secs(3600)).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::IpAsn("15169".into()))]))
            .unwrap();
        let matcher = registration.matcher();
        let old = matcher.snapshot();
        let cancellation = CancellationToken::new();
        let worker_token = cancellation.clone();
        let worker_manager = manager.clone();
        let worker = std::thread::spawn(move || {
            let mut registration = lock(&worker_manager.registration);
            registration
                .as_mut()
                .unwrap()
                .unload_verified_database(&worker_token)
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while matcher.asn_available() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!matcher.asn_available());
        cancellation.cancel();
        assert!(matches!(
            worker.join().unwrap(),
            Err(GeoDataManagerError::Cancelled)
        ));
        assert!(Arc::ptr_eq(&old, &matcher.snapshot()));
        assert!(matcher.matches_asn("15169", "1.0.0.1".parse().unwrap()));
        assert!(manager.status().unwrap().asn.available);
    }

    fn requirements(rules: &[RuleSpec]) -> GeoRequirements {
        GeoRequirements::collect(rules, &[])
            .unwrap()
            .with_geodata_mode(true)
    }

    fn stage_candidate(session: &GeoUpdateSession, contents: &[u8]) -> ([u8; 32], u64) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(session.temporary_path())
            .unwrap();
        file.write_all(contents).unwrap();
        file.sync_all().unwrap();
        let hash = Sha256::digest(contents).into();
        (hash, contents.len() as u64)
    }

    #[test]
    fn requirements_validate_and_deduplicate_across_dns_and_rules() {
        let policy = DnsNameserverPolicy {
            selector: crate::config::DnsPolicySelector::GeoSite(
                vec!["CN".to_owned(), "private".to_owned()].into_boxed_slice(),
            ),
            nameservers: Vec::new().into_boxed_slice(),
        };
        let requirements = GeoRequirements::collect(
            &[
                rule(RuleKind::GeoSite("cn".to_owned())),
                rule(RuleKind::GeoIp("PRIVATE".to_owned())),
            ],
            &[policy],
        )
        .unwrap();
        assert_eq!(requirements.total_codes(), 3);
        assert_eq!(
            requirements.codes(GeoDataKind::GeoSite).collect::<Vec<_>>(),
            ["cn", "private"]
        );
        assert_eq!(
            requirements.codes(GeoDataKind::GeoIp).collect::<Vec<_>>(),
            ["private"]
        );

        let invalid = GeoRequirements::collect(&[rule(RuleKind::GeoSite(" bad".to_owned()))], &[])
            .unwrap_err();
        assert!(matches!(invalid, GeoDataError::InvalidCode { .. }));
    }

    #[test]
    fn resources_degrade_independently_and_missing_code_is_dormant() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        fs::write(
            manager.store_dir().join(super::super::GEOSITE_FILE_NAME),
            site_file("cn", "example.cn"),
        )
        .unwrap();
        let registration = manager
            .register(requirements(&[
                rule(RuleKind::GeoSite("cn".to_owned())),
                rule(RuleKind::GeoIp("private".to_owned())),
            ]))
            .unwrap();
        assert!(registration.initial_report().geosite.available);
        assert!(!registration.initial_report().geoip.available);
        assert!(
            registration
                .matcher()
                .matches_geosite("cn", "www.example.cn")
        );
        assert!(
            !registration
                .matcher()
                .matches_geoip("private", Ipv4Addr::new(10, 0, 0, 1).into())
        );

        fs::write(
            manager.store_dir().join(super::super::GEOIP_FILE_NAME),
            ip_file("other", [10, 0, 0, 0], 8),
        )
        .unwrap();
        let report = manager.reload();
        assert!(report.geosite_available);
        assert!(!report.geoip_available);
        let status = manager.status().unwrap();
        assert!(status.geoip.last_error.unwrap().contains("missing"));
    }

    #[test]
    fn dynamic_snapshot_activates_without_replacing_matcher() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let path = manager.store_dir().join(super::super::GEOSITE_FILE_NAME);
        fs::write(&path, site_file("cn", "old.example")).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let matcher = registration.matcher();
        assert!(matcher.matches_geosite("cn", "www.old.example"));
        assert!(!matcher.matches_geosite("cn", "www.new.example"));

        fs::write(&path, site_file("cn", "new.example")).unwrap();
        manager.reload();
        assert!(!matcher.matches_geosite("cn", "www.old.example"));
        assert!(matcher.matches_geosite("cn", "www.new.example"));
    }

    #[test]
    fn reload_skips_geo_rules_until_the_old_reader_releases_its_snapshot() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let path = root.path().join(super::super::GEOSITE_FILE_NAME);
        fs::write(&path, site_file("cn", "old.example")).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let matcher = registration.matcher();
        let old = matcher.snapshot();
        fs::write(path, site_file("cn", "new.example")).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || send.send(manager.reload()).unwrap());

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while matcher.geosite_available("cn") && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!matcher.geosite_available("cn"));
        assert!(old.matches_geosite("cn", "www.old.example"));
        assert!(receive.try_recv().is_err());
        let rules = crate::routing::RuleSet::compile(vec![
            rule(RuleKind::GeoSite("cn".to_owned())),
            RuleSpec {
                kind: RuleKind::DomainSuffix("example".to_owned()),
                action: RuleAction::Direct,
                no_resolve: false,
            },
            rule(RuleKind::Match),
        ])
        .unwrap();
        let destination = crate::session::Destination::domain("www.old.example", 443).unwrap();
        let context =
            crate::routing::RoutingContext::new(crate::config::Network::Tcp, &destination).unwrap();
        assert!(matches!(
            rules.evaluate_with_geo(&context, matcher.as_ref()),
            crate::routing::RuleEvaluation::Matched(crate::routing::RuleMatch {
                action: RuleAction::Direct,
                ..
            })
        ));
        drop(old);
        assert!(
            receive
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .geosite_available
        );
        worker.join().unwrap();
        assert!(matcher.matches_geosite("cn", "www.new.example"));
    }

    #[test]
    fn status_recovers_external_generation_cancelled_before_unload() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(super::super::GEOSITE_FILE_NAME),
            site_file("cn", "old.example"),
        )
        .unwrap();
        let updater = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let consumer = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let registration = consumer
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let matcher = registration.matcher();
        let lease = registration.updater_lease();
        let update = updater.begin_update(GeoDataKind::GeoSite).unwrap();
        let candidate = site_file("cn", "new.example");
        let (hash, size) = stage_candidate(&update, &candidate);
        update.commit(None, hash, size).unwrap();
        let published_hash = updater.status().unwrap().geosite.hash.unwrap();

        // Delay reload at its management lock, then cancel only after the
        // production scheduler has observed the external disk generation.
        let gate = lock(&consumer.registration);
        let cancellation = CancellationToken::new();
        let worker_manager = consumer.clone();
        let worker_token = cancellation.clone();
        let worker = std::thread::spawn(move || {
            worker_manager.due_resources_for_active_registration_with_cancellation(
                &lease,
                [
                    (
                        GeoDataKind::GeoSite,
                        "https://rules.example.test/geosite.dat",
                    ),
                    (GeoDataKind::GeoIp, "https://rules.example.test/geoip.dat"),
                ],
                SystemTime::now(),
                &worker_token,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let observed = loop {
            if lock(&consumer.state).geosite.hash.as_deref() == Some(published_hash.as_str()) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::yield_now();
        };
        cancellation.cancel();
        drop(gate);
        let result = worker.join().unwrap();
        assert!(observed, "scheduler must observe the external generation");
        assert!(matches!(result, Err(GeoDataManagerError::Cancelled)));
        assert!(matcher.matches_geosite("cn", "www.old.example"));
        assert!(!matcher.matches_geosite("cn", "www.new.example"));

        // No second update or new registration: public status must retry the
        // same generation and make its rules available through the matcher.
        assert!(consumer.status().unwrap().geosite.available);
        assert!(matcher.matches_geosite("cn", "www.new.example"));
        assert!(!matcher.matches_geosite("cn", "www.old.example"));
    }

    #[test]
    fn status_recovers_a_cancelled_reload_without_a_new_disk_generation() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let path = root.path().join(super::super::GEOSITE_FILE_NAME);
        fs::write(&path, site_file("cn", "old.example")).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let matcher = registration.matcher();
        let old = matcher.snapshot();
        fs::write(path, site_file("cn", "new.example")).unwrap();
        let cancellation = CancellationToken::new();
        let worker_manager = manager.clone();
        let worker_token = cancellation.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(worker_manager.reload_with_cancellation(&worker_token))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while matcher.geosite_available("cn") && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!matcher.geosite_available("cn"));
        cancellation.cancel();
        assert!(matches!(
            receive.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(GeoDataManagerError::Cancelled)
        ));
        worker.join().unwrap();
        drop(old);
        assert!(manager.status().unwrap().geosite.available);
        assert!(matcher.matches_geosite("cn", "www.new.example"));
    }

    #[test]
    fn preexisting_asset_is_available_and_due_when_state_is_missing() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        fs::write(
            manager.store_dir().join(super::super::GEOSITE_FILE_NAME),
            site_file("cn", "example.cn"),
        )
        .unwrap();
        let _registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();

        let status = manager.status().unwrap();
        assert!(status.geosite.required);
        assert!(status.geosite.available);
        assert_eq!(status.geosite.last_success, None);
        assert_eq!(status.geosite.next_check, None);
        assert_eq!(
            manager.due_resources(SystemTime::now()).unwrap(),
            [GeoDataKind::GeoSite]
        );
    }

    #[test]
    fn invalid_scheduling_state_does_not_block_manager_initialization() {
        let root = tempdir().unwrap();
        fs::write(root.path().join(STATE_FILE), b"{not-json").unwrap();

        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let status = manager.status().unwrap();
        assert!(!status.geosite.available);
        assert!(!status.geoip.available);
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(STATE_FILE)).unwrap()).unwrap();
        assert_eq!(persisted["version"], STATE_VERSION);
    }

    #[test]
    fn status_recovers_an_interrupted_cross_process_update() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let mut state = read_state(root.path()).unwrap();
        state.geosite.updating = true;
        persist_state(root.path(), &state).unwrap();

        let status = manager.status().unwrap();
        assert!(!status.geosite.updating);
        assert!(
            status
                .geosite
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("interrupted"))
        );
    }

    #[test]
    fn update_is_cross_process_locked_validated_and_atomically_committed() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let peer = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let registration = manager
            .register_with_interval(
                requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]),
                Duration::from_secs(6 * 3600),
            )
            .unwrap();
        let matcher = registration.matcher();

        let update = manager.begin_update(GeoDataKind::GeoSite).unwrap();
        assert!(manager.status().unwrap().geosite.updating);
        assert!(matches!(
            peer.begin_update(GeoDataKind::GeoIp),
            Err(GeoDataManagerError::UpdateBusy)
        ));
        let candidate = site_file("cn", "updated.example");
        let (hash, size) = stage_candidate(&update, &candidate);
        let reload = update
            .commit(Some("\"v1\"".to_owned()), hash, size)
            .unwrap();
        assert!(reload.active_registration);
        assert!(reload.geosite_available);
        assert!(matcher.matches_geosite("cn", "www.updated.example"));

        let status = manager.status().unwrap();
        assert!(status.geosite.available);
        assert!(!status.geosite.updating);
        assert_eq!(status.geosite.etag.as_deref(), Some("\"v1\""));
        assert_eq!(status.geosite.hash.as_deref().map(str::len), Some(64));
        assert!(status.geosite.last_success.is_some());
        assert_eq!(
            status.geosite.next_check.unwrap() - status.geosite.last_success.unwrap(),
            6 * 3600
        );
        assert!(manager.due_resources(SystemTime::now()).unwrap().is_empty());
        let peer_status = peer.status().unwrap();
        assert!(peer_status.geosite.available);
        assert_eq!(peer_status.geosite.etag.as_deref(), Some("\"v1\""));
    }

    #[test]
    fn update_drains_existing_readers_before_rebuilding_both_kinds() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join(super::super::GEOSITE_FILE_NAME),
            site_file("cn", "old.example"),
        )
        .unwrap();
        fs::write(
            root.path().join(super::super::GEOIP_FILE_NAME),
            ip_file("private", [10, 0, 0, 0], 8),
        )
        .unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let registration = manager
            .register(requirements(&[
                rule(RuleKind::GeoSite("cn".to_owned())),
                rule(RuleKind::GeoIp("private".to_owned())),
            ]))
            .unwrap();
        let matcher = registration.matcher();
        let old_snapshot = matcher.snapshot();
        let old_weak = Arc::downgrade(&old_snapshot);

        let update = manager.begin_update(GeoDataKind::GeoSite).unwrap();
        let (hash, size) = stage_candidate(&update, &site_file("cn", "new.example"));
        let (send, receive) = std::sync::mpsc::channel();
        let worker =
            std::thread::spawn(move || send.send(update.commit(None, hash, size)).unwrap());
        let deadline = Instant::now() + Duration::from_secs(1);
        while matcher.geosite_available("cn") && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!matcher.geosite_available("cn"));
        let address = Ipv4Addr::new(10, 0, 0, 1).into();
        assert!(!matcher.geoip_available("private"));
        assert!(receive.try_recv().is_err());
        assert!(old_snapshot.matches_geosite("cn", "www.old.example"));
        assert!(!old_snapshot.matches_geosite("cn", "www.new.example"));
        assert!(old_snapshot.matches_geoip("private", address));
        drop(old_snapshot);
        let report = receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(old_weak.upgrade().is_none());
        assert!(report.geosite_available && report.geoip_available);
        assert!(matcher.matches_geosite("cn", "www.new.example"));
        assert!(!matcher.matches_geosite("cn", "www.old.example"));
        assert!(matcher.matches_geoip("private", address));
    }

    #[test]
    fn cancelled_update_drain_never_publishes_and_304_recovers_local_assets() {
        let root = tempdir().unwrap();
        let path = root.path().join(super::super::GEOSITE_FILE_NAME);
        let original = site_file("cn", "old.example");
        fs::write(&path, &original).unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let matcher = registration.matcher();
        let old = matcher.snapshot();
        let update = manager.begin_update(GeoDataKind::GeoSite).unwrap();
        let (hash, size) = stage_candidate(&update, &site_file("cn", "new.example"));
        let cancellation = CancellationToken::new();
        let worker_token = cancellation.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(update.commit_with_cancellation(None, hash, size, &worker_token))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while matcher.geosite_available("cn") && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(!matcher.geosite_available("cn"));
        cancellation.cancel();
        assert!(matches!(
            receive.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(GeoDataManagerError::Cancelled)
        ));
        worker.join().unwrap();
        drop(old);
        assert!(!matcher.geosite_available("cn"));
        assert_eq!(fs::read(path).unwrap(), original);

        // A 304 can recover a valid local asset even if a previous load was
        // interrupted; it must not merely advance next_check while empty.
        manager
            .begin_update(GeoDataKind::GeoSite)
            .unwrap()
            .not_modified(None)
            .unwrap();
        assert!(matcher.matches_geosite("cn", "www.old.example"));
        assert!(!matcher.matches_geosite("cn", "www.new.example"));
    }

    #[test]
    fn same_source_peer_skips_download_after_the_cross_process_winner_commits() {
        let root = tempdir().unwrap();
        let first = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let second = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let first_registration = first
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let second_registration = second
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let first_lease = first_registration.updater_lease();
        let second_lease = second_registration.updater_lease();
        let source = "https://rules.example.test/geosite.dat";
        let geoip_source = "https://rules.example.test/geoip.dat";
        let now = SystemTime::now();

        let update = first
            .begin_update_for_active_registration(&first_lease, GeoDataKind::GeoSite, source, now)
            .unwrap()
            .expect("the first manager owns the due update");
        assert!(matches!(
            second.begin_update_for_active_registration(
                &second_lease,
                GeoDataKind::GeoSite,
                source,
                now,
            ),
            Err(GeoDataManagerError::UpdateBusy)
        ));

        let candidate = site_file("cn", "winner.example");
        let (hash, size) = stage_candidate(&update, &candidate);
        update
            .commit(Some("\"winner\"".to_owned()), hash, size)
            .unwrap();

        assert!(
            second
                .begin_update_for_active_registration(
                    &second_lease,
                    GeoDataKind::GeoSite,
                    source,
                    now,
                )
                .unwrap()
                .is_none(),
            "the peer must observe the durable next-check state instead of downloading again"
        );
        assert!(
            second_registration
                .matcher()
                .matches_geosite("cn", "www.winner.example")
        );
        assert!(
            second
                .due_resources_for_active_registration(
                    &second_lease,
                    [
                        (GeoDataKind::GeoSite, source),
                        (GeoDataKind::GeoIp, geoip_source),
                    ],
                    now,
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn not_modified_preserves_asset_metadata_and_advances_next_check() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let _registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();

        let update = manager.begin_update(GeoDataKind::GeoSite).unwrap();
        assert!(!update.temporary_path().exists());
        let candidate = site_file("cn", "example.cn");
        let (hash, size) = stage_candidate(&update, &candidate);
        update
            .commit(Some("\"v1\"".to_owned()), hash, size)
            .unwrap();
        let before = manager.status().unwrap().geosite;

        let check = manager.begin_update(GeoDataKind::GeoSite).unwrap();
        assert!(!check.temporary_path().exists());
        check.not_modified(None).unwrap();
        let after = manager.status().unwrap().geosite;

        assert!(after.available);
        assert!(!after.updating);
        assert_eq!(after.last_success, before.last_success);
        assert_eq!(after.etag, before.etag);
        assert_eq!(after.hash, before.hash);
        assert!(after.next_check > Some(unix_seconds(SystemTime::now())));
    }

    #[test]
    fn status_hot_reloads_an_update_committed_by_another_manager() {
        let root = tempdir().unwrap();
        let updater = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let consumer = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let registration = consumer
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        let matcher = registration.matcher();
        assert!(!matcher.geosite_available("cn"));

        let update = updater.begin_update(GeoDataKind::GeoSite).unwrap();
        let candidate = site_file("cn", "example.cn");
        let (hash, size) = stage_candidate(&update, &candidate);
        update.commit(None, hash, size).unwrap();

        assert!(consumer.status().unwrap().geosite.available);
        assert!(matcher.geosite_available("cn"));
        assert!(matcher.matches_geosite("cn", "www.example.cn"));
    }

    #[test]
    fn external_update_skips_missing_code_until_a_compatible_asset_arrives() {
        let root = tempdir().unwrap();
        let mut initial = site_file("a", "a.example");
        initial.extend(site_file("b", "old-b.example"));
        fs::write(root.path().join(super::super::GEOSITE_FILE_NAME), initial).unwrap();

        let updater = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let _updater_registration = updater
            .register(requirements(&[rule(RuleKind::GeoSite("a".to_owned()))]))
            .unwrap();
        let consumer = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let consumer_registration = consumer
            .register(requirements(&[rule(RuleKind::GeoSite("b".to_owned()))]))
            .unwrap();
        let matcher = consumer_registration.matcher();
        assert!(matcher.matches_geosite("b", "www.old-b.example"));

        let update = updater.begin_update(GeoDataKind::GeoSite).unwrap();
        let only_a = site_file("a", "new-a.example");
        let (hash, size) = stage_candidate(&update, &only_a);
        update.commit(None, hash, size).unwrap();

        let status = consumer.status().unwrap();
        assert!(!status.geosite.available);
        assert!(!matcher.geosite_available("b"));
        assert!(!matcher.matches_geosite("b", "www.old-b.example"));

        let update = updater.begin_update(GeoDataKind::GeoSite).unwrap();
        let mut compatible = site_file("a", "newer-a.example");
        compatible.extend(site_file("b", "new-b.example"));
        let (hash, size) = stage_candidate(&update, &compatible);
        update.commit(None, hash, size).unwrap();

        let status = consumer.status().unwrap();
        assert!(status.geosite.available);
        assert!(!matcher.matches_geosite("b", "www.old-b.example"));
        assert!(matcher.matches_geosite("b", "www.new-b.example"));
    }

    #[test]
    fn invalid_candidate_preserves_old_resource_and_records_error() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let path = manager.store_dir().join(super::super::GEOSITE_FILE_NAME);
        fs::write(&path, site_file("cn", "old.example")).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();

        let update = manager.begin_update(GeoDataKind::GeoSite).unwrap();
        let (hash, size) = stage_candidate(&update, b"not protobuf");
        assert!(matches!(
            update.commit(None, hash, size),
            Err(GeoDataManagerError::Validation(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), site_file("cn", "old.example"));
        assert!(
            registration
                .matcher()
                .matches_geosite("cn", "www.old.example")
        );
        let status = manager.status().unwrap();
        assert!(!status.geosite.updating);
        assert!(status.geosite.last_error.is_some());
    }

    #[test]
    fn manager_rejects_a_second_registration_until_the_active_one_is_dropped() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoIp("private".to_owned()))]))
            .unwrap();
        assert!(manager.status().unwrap().geoip.required);
        assert!(matches!(
            manager.register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))])),
            Err(GeoDataManagerError::RegistrationActive)
        ));

        drop(registration);
        assert!(!manager.status().unwrap().geoip.required);
        let replacement = manager
            .register(requirements(&[rule(RuleKind::GeoSite("cn".to_owned()))]))
            .unwrap();
        assert!(manager.status().unwrap().geosite.required);
        drop(replacement);
    }

    #[test]
    fn due_and_etag_are_bound_to_the_active_registration_and_source() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let source_a = "https://a.example.test/geosite.dat";
        let source_b = "https://b.example.test/geosite.dat";
        let geoip_source = "https://a.example.test/geoip.dat";
        let now = SystemTime::now();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("a".to_owned()))]))
            .unwrap();
        let lease = registration.updater_lease();

        let update = manager
            .begin_update_for_active_registration(&lease, GeoDataKind::GeoSite, source_a, now)
            .unwrap()
            .expect("first source check is due");
        assert_eq!(update.request_etag(), None);
        let candidate = site_file("a", "a.example");
        let (hash, size) = stage_candidate(&update, &candidate);
        update
            .commit(Some("\"source-a\"".to_owned()), hash, size)
            .unwrap();

        assert!(registration.initial_report().geosite.required);
        assert!(
            manager
                .due_resources_for_active_registration(
                    &lease,
                    [
                        (GeoDataKind::GeoSite, source_a),
                        (GeoDataKind::GeoIp, geoip_source),
                    ],
                    now,
                )
                .unwrap()
                .is_empty(),
            "the current source is not due again before its interval"
        );
        assert_eq!(
            manager
                .due_resources_for_active_registration(
                    &lease,
                    [
                        (GeoDataKind::GeoSite, source_b),
                        (GeoDataKind::GeoIp, geoip_source),
                    ],
                    now,
                )
                .unwrap(),
            [GeoDataKind::GeoSite],
            "a source change is immediately due"
        );

        let future = now + Duration::from_secs(7_200);
        let same_source = manager
            .begin_update_for_active_registration(&lease, GeoDataKind::GeoSite, source_a, future)
            .unwrap()
            .expect("same source is due after its interval");
        assert_eq!(same_source.request_etag(), Some("\"source-a\""));
        same_source.fail("test cleanup").unwrap();

        let asset_path = manager.store_dir().join(super::super::GEOSITE_FILE_NAME);
        fs::remove_file(&asset_path).unwrap();
        let missing_asset = manager
            .begin_update_for_active_registration(&lease, GeoDataKind::GeoSite, source_a, future)
            .unwrap()
            .expect("missing asset remains due");
        assert_eq!(
            missing_asset.request_etag(),
            None,
            "a missing asset must not receive a 304 through a stale ETag"
        );
        missing_asset.fail("test cleanup").unwrap();

        fs::write(&asset_path, b"damaged").unwrap();
        let damaged_asset = manager
            .begin_update_for_active_registration(&lease, GeoDataKind::GeoSite, source_a, future)
            .unwrap()
            .expect("damaged asset remains due");
        assert_eq!(
            damaged_asset.request_etag(),
            None,
            "a damaged asset must not receive a 304 through a stale ETag"
        );
        damaged_asset.fail("test cleanup").unwrap();

        let changed_source = manager
            .begin_update_for_active_registration(&lease, GeoDataKind::GeoSite, source_b, now)
            .unwrap()
            .expect("changed source remains immediately due");
        assert_eq!(
            changed_source.request_etag(),
            None,
            "an ETag from a different source must never be reused"
        );
        changed_source.fail("test cleanup").unwrap();
    }

    #[test]
    fn source_bound_commit_validates_the_active_registration() {
        let root = tempdir().unwrap();
        let initial = site_file("a", "old-a.example");
        fs::write(root.path().join(super::super::GEOSITE_FILE_NAME), initial).unwrap();
        fs::write(
            root.path().join(super::super::GEOIP_FILE_NAME),
            ip_file("private", [10, 0, 0, 0], 8),
        )
        .unwrap();

        let manager = GeoDataManager::open(root.path(), Duration::from_secs(3_600)).unwrap();
        let registration = manager
            .register(requirements(&[
                rule(RuleKind::GeoSite("a".to_owned())),
                rule(RuleKind::GeoIp("private".to_owned())),
            ]))
            .unwrap();
        let lease = registration.updater_lease();
        let matcher = registration.matcher();
        assert!(matcher.matches_geosite("a", "www.old-a.example"));

        let update = manager
            .begin_update_for_active_registration(
                &lease,
                GeoDataKind::GeoSite,
                "https://a.example.test/geosite.dat",
                SystemTime::now(),
            )
            .unwrap()
            .expect("owner source is initially due");
        let only_a = site_file("a", "new-a.example");
        let (hash, size) = stage_candidate(&update, &only_a);
        update.commit(None, hash, size).unwrap();

        assert!(!matcher.matches_geosite("a", "www.old-a.example"));
        assert!(matcher.matches_geosite("a", "www.new-a.example"));

        let incompatible = manager
            .begin_update_for_active_registration(
                &lease,
                GeoDataKind::GeoSite,
                "https://b.example.test/geosite.dat",
                SystemTime::now(),
            )
            .unwrap()
            .expect("a source change is immediately due");
        let only_b = site_file("b", "new-b.example");
        let (hash, size) = stage_candidate(&incompatible, &only_b);
        assert!(matches!(
            incompatible.commit(None, hash, size),
            Err(GeoDataManagerError::Validation(_))
        ));
        assert!(!matcher.geosite_available("a"));
        assert!(matcher.matches_geoip("private", Ipv4Addr::new(10, 0, 0, 1).into()));
        assert_eq!(
            fs::read(root.path().join(super::super::GEOSITE_FILE_NAME)).unwrap(),
            only_a
        );
        assert!(
            manager
                .due_resources_for_active_registration(
                    &lease,
                    [
                        (GeoDataKind::GeoSite, "https://a.example.test/geosite.dat"),
                        (GeoDataKind::GeoIp, "https://a.example.test/geoip.dat")
                    ],
                    SystemTime::now(),
                )
                .unwrap()
                .contains(&GeoDataKind::GeoSite)
        );
    }

    #[test]
    fn stale_update_lease_cannot_replace_the_new_registration_or_asset() {
        let root = tempdir().unwrap();
        let mut initial = site_file("a", "old-a.example");
        initial.extend(site_file("b", "old-b.example"));
        let path = root.path().join(super::super::GEOSITE_FILE_NAME);
        fs::write(&path, &initial).unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let registration = manager
            .register(requirements(&[rule(RuleKind::GeoSite("a".to_owned()))]))
            .unwrap();
        let update = manager
            .begin_update_for_active_registration(
                &registration.updater_lease(),
                GeoDataKind::GeoSite,
                "https://assets.example.test/geosite.dat",
                SystemTime::now(),
            )
            .unwrap()
            .unwrap();
        let (hash, size) = stage_candidate(&update, &site_file("a", "new-a.example"));
        drop(registration);
        let replacement = manager
            .register(requirements(&[rule(RuleKind::GeoSite("b".to_owned()))]))
            .unwrap();

        assert!(matches!(
            update.commit(None, hash, size),
            Err(GeoDataManagerError::Validation(_))
        ));
        assert!(
            replacement
                .matcher()
                .matches_geosite("b", "www.old-b.example")
        );
        assert_eq!(fs::read(path).unwrap(), initial);
        assert!(manager.status().unwrap().geosite.required);
    }

    #[test]
    fn empty_registration_stays_inside_zero_allocation_snapshot() {
        let root = tempdir().unwrap();
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let registration = manager
            .register(GeoRequirements::collect(&[], &[]).unwrap())
            .unwrap();
        assert_eq!(registration.initial_report().allocation_capacity, 0);
        assert_eq!(registration.initial_report().peak_allocation_capacity, 0);
    }
}
