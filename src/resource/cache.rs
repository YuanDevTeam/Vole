//! Provider files and candidate updates. Publication belongs to the runtime graph owner.
use super::http::{self, DownloadOutcome, DownloadRequest, HttpOptions};
use super::subscription::SubscriptionInfo;
use crate::{
    config::providers::{
        ProviderContent, ProviderContents, ProviderSpec, ProviderTemplate, ProviderType,
    },
    dispatch::Dispatcher,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);
const MAX_PARSE_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Metadata {
    url: String,
    etag: Option<String>,
    hash: String,
    checked: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subscription_info: Option<SubscriptionInfo>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProviderState {
    pub name: String,
    pub vehicle_type: &'static str,
    pub rule: bool,
    pub available: bool,
    pub downloaded: bool,
    pub updating: bool,
    pub updated_at: Option<u64>,
    pub error: Option<&'static str>,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_info: Option<SubscriptionInfo>,
}
pub(crate) struct ResourceEntry {
    pub key: String,
    pub spec: ProviderSpec,
    pub state: ProviderState,
    path: Option<PathBuf>,
    metadata: Metadata,
    pub next: tokio::time::Instant,
    modified: Option<SystemTime>,
    failures: u32,
}
pub(crate) struct ProviderCache {
    pub template: Arc<ProviderTemplate>,
    pub entries: Vec<ResourceEntry>,
    pub contents: ProviderContents,
}
pub(crate) struct Candidate {
    pub content: ProviderContent,
    temporary: Option<PathBuf>,
    metadata: Metadata,
}
impl Drop for Candidate {
    fn drop(&mut self) {
        if let Some(path) = &self.temporary {
            let _ = fs::remove_file(path);
        }
    }
}
impl ProviderCache {
    pub fn open(root: &Path, template: Arc<ProviderTemplate>) -> io::Result<Self> {
        Self::open_with_cancel(root, template, None)
    }
    pub fn open_with_cancel(
        root: &Path,
        template: Arc<ProviderTemplate>,
        cancellation: Option<&CancellationToken>,
    ) -> io::Result<Self> {
        let mut entries = Vec::new();
        let mut contents = ProviderContents::new();
        for (rule, (name, spec)) in template
            .proxies
            .iter()
            .map(|item| (false, item))
            .chain(template.rules.iter().map(|item| (true, item)))
        {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let key = ProviderTemplate::key(rule, name);
            let mut entry = ResourceEntry {
                key: key.clone(),
                spec: spec.clone(),
                state: ProviderState {
                    name: name.clone(),
                    rule,
                    vehicle_type: match spec.kind {
                        ProviderType::Http => "HTTP",
                        ProviderType::File => "File",
                        ProviderType::Inline => "Inline",
                    },
                    available: spec.kind == ProviderType::Inline || !spec.payload.is_empty(),
                    downloaded: false,
                    updating: false,
                    updated_at: None,
                    error: None,
                    count: spec.payload.len(),
                    subscription_info: None,
                },
                path: None,
                metadata: Metadata::default(),
                next: tokio::time::Instant::now(),
                modified: None,
                failures: 0,
            };
            if spec.kind != ProviderType::Inline {
                let fallback = format!(
                    "{}/{}",
                    if rule { "rules" } else { "proxies" },
                    hex(&Sha256::digest(spec.url.as_bytes()))
                );
                let path = resource_path(
                    root,
                    if spec.path.is_empty() {
                        &fallback
                    } else {
                        &spec.path
                    },
                    spec.kind == ProviderType::Http,
                )?;
                let metadata = fs::read(metadata_path(&path))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Metadata>(&bytes).ok())
                    .unwrap_or_default();
                let control = super::age_provider::DecodeControl::new(
                    cancellation,
                    std::time::Instant::now() + http::DEFAULT_DOWNLOAD_TIMEOUT,
                );
                if let Ok(bytes) = read_bounded(&path, spec.size_limit, &control) {
                    match template.parse_content_with_control(spec, &bytes, &control) {
                        Ok(content) => {
                            entry.state.available = true;
                            entry.state.downloaded = spec.kind == ProviderType::Http;
                            entry.state.count = content_len(&content);
                            entry.state.updated_at = fs::metadata(&path)
                                .ok()
                                .and_then(|m| m.modified().ok())
                                .map(unix_time);
                            entry.modified =
                                fs::metadata(&path).ok().and_then(|m| m.modified().ok());
                            if metadata.url == spec.url
                                && metadata.hash == hex(&Sha256::digest(&bytes))
                            {
                                entry.metadata = metadata;
                                if !rule && spec.kind == ProviderType::Http {
                                    entry.state.subscription_info =
                                        entry.metadata.subscription_info;
                                } else {
                                    entry.metadata.subscription_info = None;
                                }
                            }
                            contents.insert(key, content);
                            if spec.kind == ProviderType::Http {
                                entry.next = next_update(
                                    spec.interval,
                                    entry
                                        .metadata
                                        .checked
                                        .max(entry.state.updated_at.unwrap_or(0)),
                                );
                            }
                        }
                        Err(_) => entry.state.error = Some("invalid cached content"),
                    }
                }
                entry.path = Some(path);
            }
            entries.push(entry);
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(Self {
            template,
            entries,
            contents,
        })
    }
    pub fn next_due(&self) -> Option<usize> {
        self.next_refresh()
            .filter(|(_, deadline)| *deadline <= tokio::time::Instant::now())
            .map(|(index, _)| index)
    }
    pub fn next_refresh(&self) -> Option<(usize, tokio::time::Instant)> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.spec.kind != ProviderType::Inline
                    && !(entry.spec.kind == ProviderType::Http
                        && entry.spec.interval == 0
                        && entry.state.downloaded)
            })
            .min_by_key(|(_, entry)| entry.next)
            .map(|(index, entry)| (index, entry.next))
    }
    pub async fn fetch(
        &mut self,
        index: usize,
        dispatcher: Arc<dyn Dispatcher>,
        user_agent: String,
        etag_support: bool,
        security: crate::security::SecurityContext,
        cancellation: CancellationToken,
    ) -> io::Result<Option<Candidate>> {
        let deadline = std::time::Instant::now() + http::DEFAULT_DOWNLOAD_TIMEOUT;
        let entry = &mut self.entries[index];
        if cancellation.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if entry.spec.kind == ProviderType::Inline {
            return Ok(None);
        }
        let path = entry.path.as_ref().expect("file resource path").clone();
        entry.state.updating = true;
        let operation = async {
            if entry.spec.kind == ProviderType::File {
                let modified = fs::metadata(&path)?.modified()?;
                if Some(modified) == entry.modified && entry.state.available {
                    return Ok(None);
                }
                let spec = entry.spec.clone();
                let template = self.template.clone();
                let path = path.clone();
                let parse_cancellation = cancellation.clone();
                let content = tokio::task::spawn_blocking(move || {
                    let control = super::age_provider::DecodeControl::new(
                        Some(&parse_cancellation),
                        deadline,
                    );
                    let bytes = read_bounded(&path, spec.size_limit, &control)?;
                    template
                        .parse_content_with_control(&spec, &bytes, &control)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid provider content")
                        })
                })
                .await
                .map_err(io::Error::other)??;
                return Ok(Some(Candidate {
                    content,
                    temporary: None,
                    metadata: Metadata::default(),
                }));
            }
            let temporary = temporary_path(&path);
            let outcome = http::download(DownloadRequest {
                security,
                dispatcher,
                url: entry.spec.url.clone(),
                etag: etag_support.then(|| entry.metadata.etag.clone()).flatten(),
                temporary_path: temporary.clone(),
                timeout: deadline.saturating_duration_since(std::time::Instant::now()),
                cancellation: cancellation.clone(),
                options: HttpOptions {
                    user_agent,
                    headers: entry.spec.headers(),
                    size_limit: (entry.spec.size_limit > 0).then_some(entry.spec.size_limit),
                    allow_http: true,
                    allow_ip: true,
                },
            })
            .await
            .map_err(|_| io::Error::other("provider download failed"))?;
            match outcome {
                DownloadOutcome::NotModified { subscription_info } => {
                    if cancellation.is_cancelled() {
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                    let mut metadata = entry.metadata.clone();
                    metadata.checked = unix_time(SystemTime::now());
                    if !entry.state.rule {
                        metadata.subscription_info =
                            subscription_info.or(metadata.subscription_info);
                    } else {
                        metadata.subscription_info = None;
                    }
                    write_metadata(&path, &metadata)?;
                    entry.state.subscription_info = metadata.subscription_info;
                    entry.metadata = metadata;
                    Ok(None)
                }
                DownloadOutcome::Downloaded {
                    etag,
                    sha256,
                    subscription_info,
                    ..
                } => {
                    let mut cleanup = TemporaryFile(Some(temporary.clone()));
                    let spec = entry.spec.clone();
                    let template = self.template.clone();
                    let input = temporary.clone();
                    let parse_cancellation = cancellation.clone();
                    let parsed = tokio::task::spawn_blocking(move || {
                        let control = super::age_provider::DecodeControl::new(
                            Some(&parse_cancellation),
                            deadline,
                        );
                        let bytes = read_bounded(&input, spec.size_limit, &control)?;
                        template
                            .parse_content_with_control(&spec, &bytes, &control)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid provider content",
                                )
                            })
                    })
                    .await
                    .map_err(io::Error::other)?;
                    match parsed {
                        Ok(content) => {
                            cleanup.0 = None;
                            Ok(Some(Candidate {
                                content,
                                temporary: Some(temporary),
                                metadata: Metadata {
                                    url: entry.spec.url.clone(),
                                    etag,
                                    hash: sha256.iter().map(|byte| format!("{byte:02x}")).collect(),
                                    checked: unix_time(SystemTime::now()),
                                    subscription_info: if entry.state.rule {
                                        None
                                    } else {
                                        subscription_info.or(entry.metadata.subscription_info)
                                    },
                                },
                            }))
                        }
                        Err(error) => {
                            let _ = fs::remove_file(temporary);
                            Err(error)
                        }
                    }
                }
            }
        }
        .await;
        entry.state.updating = false;
        if cancellation.is_cancelled() {
            drop(operation);
            return Err(io::ErrorKind::Interrupted.into());
        }
        if operation.is_err() {
            Self::failed_entry(entry, "resource fetch or parse failed");
        } else if matches!(operation, Ok(None)) {
            Self::schedule(entry);
            entry.state.error = None;
        }
        operation
    }
    pub fn reject(&mut self, index: usize) {
        Self::failed_entry(&mut self.entries[index], "candidate graph rejected");
    }
    pub fn commit(
        &mut self,
        index: usize,
        mut candidate: Candidate,
        cancellation: &CancellationToken,
    ) -> io::Result<()> {
        if cancellation.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let entry = &mut self.entries[index];
        if let Some(temporary) = &candidate.temporary {
            let path = entry.path.as_ref().expect("cache path");
            commit_download(path, temporary, &candidate.metadata)?;
            candidate.temporary = None;
            entry.metadata = candidate.metadata.clone();
            entry.state.downloaded = true;
            entry.state.subscription_info = entry.metadata.subscription_info;
        }
        entry.modified = entry
            .path
            .as_ref()
            .and_then(|path| fs::metadata(path).ok())
            .and_then(|m| m.modified().ok());
        entry.state.available = true;
        entry.state.updated_at = Some(unix_time(SystemTime::now()));
        entry.state.error = None;
        entry.state.count = content_len(&candidate.content);
        self.contents
            .insert(entry.key.clone(), candidate.content.clone());
        Self::schedule(entry);
        Ok(())
    }
    fn failed_entry(entry: &mut ResourceEntry, error: &'static str) {
        entry.state.error = Some(error);
        entry.failures = entry.failures.saturating_add(1);
        entry.next = tokio::time::Instant::now()
            + Duration::from_secs(
                (10u64.saturating_mul(1u64.checked_shl(entry.failures.min(8) - 1).unwrap_or(256)))
                    .min(3600),
            );
    }
    fn schedule(entry: &mut ResourceEntry) {
        entry.failures = 0;
        let seconds = if entry.spec.kind == ProviderType::File {
            1
        } else if entry.spec.interval == 0 {
            365 * 24 * 3600
        } else {
            entry.spec.interval.min(i64::MAX as u64 / 1_000_000_000)
        };
        entry.next = tokio::time::Instant::now() + Duration::from_secs(seconds);
    }
}
fn content_len(content: &ProviderContent) -> usize {
    match content {
        ProviderContent::Proxies(values) => values.len(),
        ProviderContent::Rules(set) => set.len(),
    }
}
fn next_update(interval: u64, checked: u64) -> tokio::time::Instant {
    let seconds = if interval == 0 {
        365 * 24 * 3600
    } else {
        checked
            .saturating_add(interval)
            .saturating_sub(unix_time(SystemTime::now()))
            .min(i64::MAX as u64 / 1_000_000_000)
    };
    tokio::time::Instant::now() + Duration::from_secs(seconds)
}
fn unix_time(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn read_bounded(
    path: &Path,
    limit: u64,
    control: &super::age_provider::DecodeControl<'_>,
) -> io::Result<Vec<u8>> {
    let limit = if limit == 0 {
        MAX_PARSE_BYTES
    } else {
        limit.min(MAX_PARSE_BYTES)
    };
    control
        .check()
        .map_err(|_| io::Error::other("provider read stopped"))?;
    let mut file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("provider path must be a regular file"));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        control
            .check()
            .map_err(|_| io::Error::other("provider read stopped"))?;
        let available = (limit + 1 - bytes.len() as u64).min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..available])?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > limit {
            return Err(io::Error::other("provider exceeds parser byte limit"));
        }
        let required = bytes.len() + count;
        if required > bytes.capacity() {
            let capacity = bytes
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(limit as usize);
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(|_| io::Error::other("provider input allocation failed"))?;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    control
        .check()
        .map_err(|_| io::Error::other("provider read stopped"))?;
    Ok(bytes)
}
fn metadata_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".metadata.json");
    PathBuf::from(name)
}
fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(name)
}
fn write_metadata(path: &Path, metadata: &Metadata) -> io::Result<()> {
    let staged = stage_metadata(path, metadata)?;
    fs::rename(staged.0.as_ref().unwrap(), metadata_path(path))
}

fn stage_metadata(path: &Path, metadata: &Metadata) -> io::Result<TemporaryFile> {
    let staged = TemporaryFile(Some(temporary_path(&metadata_path(path))));
    fs::write(
        staged.0.as_ref().unwrap(),
        serde_json::to_vec(metadata).map_err(io::Error::other)?,
    )?;
    Ok(staged)
}

fn commit_download(path: &Path, temporary: &Path, metadata: &Metadata) -> io::Result<()> {
    let staged = stage_metadata(path, metadata)?;
    let mut previous = TemporaryFile(None);
    match fs::metadata(path) {
        Ok(file) if file.is_file() => {
            let backup = temporary_path(path);
            fs::rename(path, &backup)?;
            previous.0 = Some(backup);
        }
        Ok(_) => return Err(io::Error::other("provider cache must be a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut installed = false;
    let result = fs::rename(temporary, path).and_then(|()| {
        installed = true;
        fs::rename(staged.0.as_ref().unwrap(), metadata_path(path))
    });
    if let Err(error) = result {
        // Keep the old body and sidecar paired if either publication fails.
        // A rollback failure retains its backup for recovery instead of deleting it.
        if let Some(backup) = previous.0.take() {
            fs::rename(backup, path)
                .map_err(|_| io::Error::other("provider cache rollback failed"))?;
        } else if installed {
            fs::remove_file(path)?;
        }
        return Err(error);
    }
    Ok(())
}
pub(crate) fn resource_path(root: &Path, path: &str, create: bool) -> io::Result<PathBuf> {
    let root = fs::canonicalize(root)?;
    let requested = Path::new(path);
    let target = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    if !target.starts_with(&root)
        || target
            .strip_prefix(&root)
            .unwrap()
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "provider path escapes dataDir",
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::other("provider path requires parent"))?;
    let mut ancestor = parent;
    while !ancestor.exists() {
        ancestor = ancestor
            .parent()
            .ok_or_else(|| io::Error::other("invalid provider path"))?;
    }
    if !fs::canonicalize(ancestor)?.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "provider path escapes dataDir",
        ));
    }
    if create {
        fs::create_dir_all(parent)?;
    }
    if target.exists() && !fs::canonicalize(&target)?.starts_with(&root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "provider path escapes dataDir",
        ));
    }
    Ok(target)
}

impl std::fmt::Debug for ProviderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderCache")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct TemporaryFile(Option<PathBuf>);
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
