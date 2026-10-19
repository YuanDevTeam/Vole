//! One-shot preparation and immutable publication of complete HTTP candidates.
#[path = "providers_cache.rs"]
mod cache;
use super::{Payload, ProviderSpec};
use crate::{
    dispatch::Dispatcher,
    http_processing::config::{Document, PolicyCandidate, invalid},
    security::SecurityContext,
};
use cache::{CacheEntry, PendingWrite, load_cache, prepare_download, publish};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub(crate) struct SourceContext {
    pub(crate) base_dir: Option<PathBuf>,
    pub(crate) data_dir: Option<PathBuf>,
    pub(crate) config_path: Option<PathBuf>,
}

pub(crate) struct DownloadContext {
    pub(crate) dispatcher: Arc<dyn Dispatcher>,
    pub(crate) security: SecurityContext,
}

impl SourceContext {
    pub(crate) fn identity(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        for path in [&self.base_dir, &self.data_dir] {
            if let Some(path) = path {
                let bytes = path.as_os_str().as_encoded_bytes();
                hash.update([1]);
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            } else {
                hash.update([0]);
            }
        }
        hash.finalize().into()
    }
}

struct Prepared {
    document: [u8; 32],
    context: [u8; 32],
    candidate: Arc<PolicyCandidate>,
}

#[derive(Default)]
pub(crate) struct Store {
    entries: BTreeMap<String, CacheEntry>,
    prepared: Option<Prepared>,
    retry_after: Option<Instant>,
    notification: Arc<tokio::sync::Notify>,
}

impl Store {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn notification(&self) -> Arc<tokio::sync::Notify> {
        self.notification.clone()
    }

    /// Restore actual content from a protected snapshot without touching its
    /// former sources or claiming that a disk validator has been checked.
    pub(crate) fn adopt(
        &mut self,
        candidate: Arc<PolicyCandidate>,
        context: &SourceContext,
    ) -> io::Result<()> {
        if candidate
            .source_identity
            .is_some_and(|identity| identity != context.identity())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP snapshot source context does not match",
            ));
        }
        let document = &candidate.document;
        let paths = resolve_paths(document, context, false)?;
        let mut entries = BTreeMap::new();
        for name in document.active_provider_names() {
            let spec = &document.providers[name];
            if matches!(spec, ProviderSpec::Http { .. }) {
                let payload = candidate.payloads.get(name).cloned().ok_or_else(invalid)?;
                entries.insert(
                    name.to_owned(),
                    CacheEntry::adopt(spec.source_identity()?, paths[name].clone(), payload),
                );
            }
        }
        self.entries = entries;
        self.prepared = Some(Prepared {
            document: document.identity(),
            context: context.identity(),
            candidate,
        });
        self.retry_after = None;
        self.notification.notify_one();
        Ok(())
    }

    /// No disk or network I/O; only return the exact already prepared document
    /// under the same host-provided path context.
    pub(crate) fn prepared(
        &self,
        document: &Arc<Document>,
        context: &SourceContext,
    ) -> io::Result<Option<Arc<PolicyCandidate>>> {
        Ok(self
            .prepared
            .as_ref()
            .filter(|ready| {
                ready.document == document.identity() && ready.context == context.identity()
            })
            .map(|ready| ready.candidate.clone()))
    }

    pub(crate) async fn prepare(
        &mut self,
        document: Arc<Document>,
        context: &SourceContext,
        network: Option<&DownloadContext>,
        cancellation: &CancellationToken,
        force_refresh: bool,
    ) -> io::Result<Arc<PolicyCandidate>> {
        check_cancel(cancellation)?;
        let paths = resolve_paths(&document, context, true)?;
        if force_refresh {
            self.retry_after = Some(Instant::now() + Duration::from_secs(60));
        }
        let mut contents = BTreeMap::new();
        let mut entries = BTreeMap::new();
        let mut writes: Vec<PendingWrite> = Vec::new();
        let mut input_bytes = document.input_bytes;
        for name in document.active_provider_names() {
            check_cancel(cancellation)?;
            match &document.providers[name] {
                ProviderSpec::Inline { .. } => (),
                ProviderSpec::File { .. } => {
                    let input = cache::read_bounded(
                        &paths[name],
                        crate::http_processing::MAX_ADDENDUM.saturating_sub(input_bytes),
                    )?;
                    contents.insert(name.to_owned(), Arc::new(Payload::parse(&input)?));
                }
                spec @ ProviderSpec::Http { .. } => {
                    let path = &paths[name];
                    let source = spec.source_identity()?;
                    let memory = self
                        .entries
                        .get(name)
                        .filter(|entry| entry.source == source && entry.path == *path)
                        .cloned();
                    let cached = if force_refresh || memory.is_none() {
                        load_cache(path, &source)?
                    } else {
                        memory
                    };
                    let (entry, write) = if !force_refresh && cached.is_some() {
                        (cached.expect("checked cached resource"), None)
                    } else {
                        let network = network.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotConnected,
                                "HTTP rewrite resource requires a download context",
                            )
                        })?;
                        prepare_download(
                            spec,
                            path,
                            &source,
                            cached.as_ref(),
                            network,
                            cancellation,
                            crate::http_processing::MAX_ADDENDUM.saturating_sub(input_bytes),
                        )
                        .await?
                    };
                    contents.insert(name.to_owned(), entry.payload.clone());
                    entries.insert(name.to_owned(), entry);
                    if let Some(write) = write {
                        writes.push(write);
                    }
                }
            }
            if let Some(payload) = contents.get(name) {
                input_bytes = input_bytes
                    .checked_add(payload.input_bytes())
                    .ok_or_else(invalid)?;
                if input_bytes > crate::http_processing::MAX_ADDENDUM {
                    return Err(invalid());
                }
            }
        }
        check_cancel(cancellation)?;
        let candidate = document.compile(&contents)?.bind_source(context.identity());
        check_cancel(cancellation)?;
        // No file, metadata, in-memory entry or pending policy is published
        // before the entire candidate has compiled within aggregate limits.
        publish(&mut writes, cancellation)?;
        self.entries = entries;
        self.prepared = Some(Prepared {
            document: document.identity(),
            context: context.identity(),
            candidate: candidate.clone(),
        });
        self.retry_after = None;
        self.notification.notify_one();
        Ok(candidate)
    }

    /// Only HTTP sources have automatic refresh. File sources are deliberately
    /// not watched. A failed automatic refresh backs off without a busy loop.
    pub(crate) fn next_due(&self) -> Option<Duration> {
        let prepared = self.prepared.as_ref()?;
        let now = unix_time();
        let due = prepared
            .candidate
            .document
            .active_provider_names()
            .filter_map(|name| {
                let ProviderSpec::Http { interval, .. } =
                    prepared.candidate.document.providers[name]
                else {
                    return None;
                };
                if interval == 0 {
                    return None;
                }
                let checked = self.entries.get(name)?.checked;
                Some(Duration::from_secs(
                    checked.saturating_add(interval).saturating_sub(now),
                ))
            })
            .min()?;
        Some(self.retry_after.map_or(due, |retry| {
            due.max(retry.saturating_duration_since(Instant::now()))
        }))
    }

    /// A periodic pass refreshes only due HTTP sources. It must not silently
    /// reread file sources or refresh sources whose interval is zero.
    pub(crate) async fn refresh_due(
        &mut self,
        network: &DownloadContext,
        cancellation: &CancellationToken,
    ) -> io::Result<Option<Arc<PolicyCandidate>>> {
        check_cancel(cancellation)?;
        if self.next_due().is_none_or(|delay| !delay.is_zero()) {
            return Ok(None);
        }
        let prepared = self.prepared.as_ref().ok_or_else(invalid)?;
        let document = prepared.candidate.document.clone();
        let context = prepared.context;
        let mut contents = prepared.candidate.payloads.clone();
        let mut entries = self.entries.clone();
        let mut writes = Vec::new();
        let now = unix_time();
        self.retry_after = Some(Instant::now() + Duration::from_secs(60));
        for name in document.active_provider_names() {
            let spec = &document.providers[name];
            let ProviderSpec::Http { interval, .. } = spec else {
                continue;
            };
            let previous = entries.get(name).ok_or_else(invalid)?;
            if *interval == 0 || previous.checked.saturating_add(*interval) > now {
                continue;
            }
            let other_bytes = contents
                .iter()
                .filter(|(key, _)| key.as_str() != name)
                .try_fold(document.input_bytes, |total, (_, payload)| {
                    total.checked_add(payload.input_bytes()).ok_or_else(invalid)
                })?;
            let remaining = crate::http_processing::MAX_ADDENDUM
                .checked_sub(other_bytes)
                .ok_or_else(invalid)?;
            let cached = load_cache(&previous.path, &previous.source)?;
            let (entry, write) = prepare_download(
                spec,
                &previous.path,
                &previous.source,
                cached.as_ref(),
                network,
                cancellation,
                remaining,
            )
            .await?;
            contents.insert(name.to_owned(), entry.payload.clone());
            entries.insert(name.to_owned(), entry);
            if let Some(write) = write {
                writes.push(write);
            }
        }
        let candidate = document.compile(&contents)?.bind_source(context);
        check_cancel(cancellation)?;
        publish(&mut writes, cancellation)?;
        self.entries = entries;
        self.prepared = Some(Prepared {
            document: document.identity(),
            context,
            candidate: candidate.clone(),
        });
        self.retry_after = None;
        self.notification.notify_one();
        Ok(Some(candidate))
    }
}

pub(super) fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(super) fn check_cancel(cancellation: &CancellationToken) -> io::Result<()> {
    if cancellation.is_cancelled() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    Ok(())
}

fn resolve_paths(
    document: &Document,
    context: &SourceContext,
    canonical: bool,
) -> io::Result<BTreeMap<String, PathBuf>> {
    let active: BTreeSet<_> = document.active_provider_names().collect();
    let mut files = BTreeSet::new();
    if let Some(path) = &context.config_path {
        let path = normalize(path)?;
        files.insert(if canonical {
            std::fs::canonicalize(&path).unwrap_or(path)
        } else {
            path
        });
    }
    let mut paths = BTreeMap::new();
    let mut caches = Vec::new();
    for (name, spec) in &document.providers {
        let required = active.contains(name.as_str());
        match spec {
            ProviderSpec::Inline { .. } => (),
            ProviderSpec::File { path } => {
                if let Some(path) = resolve(path, context.base_dir.as_deref(), required)? {
                    files.insert(if canonical && required {
                        std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone())
                    } else {
                        path.clone()
                    });
                    paths.insert(name.clone(), path);
                }
            }
            ProviderSpec::Http { path, .. } => {
                let generated;
                let path = if let Some(path) = path {
                    path.as_str()
                } else {
                    generated = format!(
                        "http-rewrite/{}.yaml",
                        spec.source_identity()?
                            .trim_start_matches("request-sha256:")
                    );
                    generated.as_str()
                };
                if let Some(path) = resolve(path, context.data_dir.as_deref(), required)? {
                    let path = if canonical && required {
                        canonical_target(&path)?
                    } else {
                        path
                    };
                    caches.push(path.clone());
                    paths.insert(name.clone(), path);
                }
            }
        }
    }
    for path in caches {
        if !files.insert(path.clone()) || !files.insert(cache::metadata_path(&path)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP rewrite resource paths overlap",
            ));
        }
    }
    Ok(paths)
}

fn resolve(raw: &str, base: Option<&Path>, required: bool) -> io::Result<Option<PathBuf>> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return normalize(path).map(Some);
    }
    if let Some(base) = base {
        return normalize(&base.join(path)).map(Some);
    }
    if required {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative HTTP resource requires an explicit source directory",
        ))
    } else {
        Ok(None)
    }
}

fn normalize(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => (),
            Component::ParentDir => {
                if !result.pop() {
                    return Err(invalid());
                }
            }
            component => result.push(component.as_os_str()),
        }
    }
    Ok(result)
}

// Resolve existing parent aliases before comparing writable caches against
// source files. No payload is opened, including for disabled declarations.
fn canonical_target(path: &Path) -> io::Result<PathBuf> {
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(ancestor) {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(ancestor.file_name().ok_or_else(invalid)?.to_os_string());
                ancestor = ancestor.parent().ok_or_else(invalid)?;
            }
            Err(_) => return Err(io::Error::other("HTTP rewrite cache path is unavailable")),
        }
    }
}

#[cfg(test)]
#[path = "providers_store_tests.rs"]
mod tests;
