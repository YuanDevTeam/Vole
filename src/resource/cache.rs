//! Provider files and candidate updates. Publication belongs to the runtime graph owner.
use super::http::{self, DownloadOutcome, DownloadRequest, HttpOptions};
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
        let mut entries = Vec::new();
        let mut contents = ProviderContents::new();
        for (rule, (name, spec)) in template
            .proxies
            .iter()
            .map(|item| (false, item))
            .chain(template.rules.iter().map(|item| (true, item)))
        {
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
                if let Ok(bytes) = read_bounded(&path, spec.size_limit) {
                    match template.parse_content(spec, &bytes) {
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
        Ok(Self {
            template,
            entries,
            contents,
        })
    }
    pub fn next_due(&self) -> Option<usize> {
        self.entries.iter().position(|entry| {
            entry.spec.kind != ProviderType::Inline
                && !(entry.spec.kind == ProviderType::Http
                    && entry.spec.interval == 0
                    && entry.state.downloaded)
                && entry.next <= tokio::time::Instant::now()
        })
    }
    pub async fn fetch(
        &mut self,
        index: usize,
        dispatcher: Arc<dyn Dispatcher>,
        user_agent: String,
        etag_support: bool,
        cancellation: CancellationToken,
    ) -> io::Result<Option<Candidate>> {
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
                let content = tokio::task::spawn_blocking(move || {
                    let bytes = read_bounded(&path, spec.size_limit)?;
                    template.parse_content(&spec, &bytes).map_err(|_| {
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
                dispatcher,
                url: entry.spec.url.clone(),
                etag: etag_support.then(|| entry.metadata.etag.clone()).flatten(),
                temporary_path: temporary.clone(),
                timeout: http::DEFAULT_DOWNLOAD_TIMEOUT,
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
                DownloadOutcome::NotModified => {
                    entry.metadata.checked = unix_time(SystemTime::now());
                    write_metadata(&path, &entry.metadata)?;
                    Ok(None)
                }
                DownloadOutcome::Downloaded { etag, sha256, .. } => {
                    let mut cleanup = TemporaryFile(Some(temporary.clone()));
                    let spec = entry.spec.clone();
                    let template = self.template.clone();
                    let input = temporary.clone();
                    let parsed = tokio::task::spawn_blocking(move || {
                        let bytes = read_bounded(&input, spec.size_limit)?;
                        template.parse_content(&spec, &bytes).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid provider content")
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
            write_metadata(path, &candidate.metadata)?;
            fs::rename(temporary, path)?;
            candidate.temporary = None;
            entry.metadata = candidate.metadata.clone();
            entry.state.downloaded = true;
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
        entry.next = if entry.spec.kind == ProviderType::File {
            tokio::time::Instant::now() + Duration::from_secs(1)
        } else {
            next_update(entry.spec.interval, unix_time(SystemTime::now()))
        };
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
fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let limit = if limit == 0 {
        MAX_PARSE_BYTES
    } else {
        limit.min(MAX_PARSE_BYTES)
    };
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("provider path must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("provider exceeds parser byte limit"));
    }
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
    let path = metadata_path(path);
    let temporary = temporary_path(&path);
    let result = (|| {
        fs::write(
            &temporary,
            serde_json::to_vec(metadata).map_err(io::Error::other)?,
        )?;
        fs::rename(&temporary, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
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
