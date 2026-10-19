//! Source-bound caches, private staging and rollback across a complete update.
use super::{DownloadContext, check_cancel, unix_time};
use crate::{
    http_processing::{
        config::{MAX_ADDENDUM, invalid},
        providers::{Payload, ProviderSpec},
    },
    resource::http::{self, DownloadOutcome, DownloadRequest},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio_util::sync::CancellationToken;

static NEXT_STAGE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(super) struct CacheEntry {
    pub(super) source: String,
    pub(super) path: PathBuf,
    pub(super) payload: Arc<Payload>,
    pub(super) checked: u64,
    metadata: Metadata,
}
impl CacheEntry {
    pub(super) fn adopt(source: String, path: PathBuf, payload: Arc<Payload>) -> Self {
        let checked = unix_time();
        Self {
            source: source.clone(),
            path,
            payload,
            checked,
            metadata: Metadata {
                source,
                hash: [0; 32],
                etag: None,
                checked,
            },
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    source: String,
    hash: [u8; 32],
    etag: Option<String>,
    checked: u64,
}

pub(super) fn metadata_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".http-meta");
    PathBuf::from(name)
}

pub(super) fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| io::Error::other("HTTP rewrite resource cannot be opened"))?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(invalid());
    }
    let mut input = Vec::new();
    input
        .try_reserve_exact(metadata.len() as usize)
        .map_err(|_| invalid())?;
    file.take(limit as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| io::Error::other("HTTP rewrite resource cannot be read"))?;
    if input.len() > limit {
        return Err(invalid());
    }
    Ok(input)
}

fn regular_cache(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

pub(super) fn load_cache(path: &Path, source: &str) -> io::Result<Option<CacheEntry>> {
    if !regular_cache(path) || !regular_cache(&metadata_path(path)) {
        return Ok(None);
    }
    let loaded = (|| -> io::Result<_> {
        let metadata: Metadata = serde_json::from_slice(&read_bounded(&metadata_path(path), 4096)?)
            .map_err(|_| invalid())?;
        if metadata.source != source {
            return Ok(None);
        }
        let input = read_bounded(path, MAX_ADDENDUM)?;
        let hash: [u8; 32] = Sha256::digest(&input).into();
        if hash != metadata.hash {
            return Ok(None);
        }
        let payload = Arc::new(Payload::parse(&input)?);
        Ok(Some(CacheEntry {
            source: source.into(),
            path: path.into(),
            payload,
            checked: metadata.checked,
            metadata,
        }))
    })();
    // An invalid disk cache is unavailable, never an implicit empty payload.
    Ok(loaded.unwrap_or(None))
}

struct StageDirectory(Option<PathBuf>);
impl StageDirectory {
    fn new(parent: &Path) -> io::Result<Self> {
        fs::create_dir_all(parent)
            .map_err(|_| io::Error::other("HTTP rewrite cache directory cannot be created"))?;
        for _ in 0..8 {
            let id = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".http-rewrite-{}-{id}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(Some(path))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => {
                    return Err(io::Error::other(
                        "HTTP rewrite staging directory cannot be created",
                    ));
                }
            }
        }
        Err(io::Error::other(
            "HTTP rewrite staging directory is unavailable",
        ))
    }
    fn path(&self) -> &Path {
        self.0.as_deref().expect("live staging directory")
    }
}
impl Drop for StageDirectory {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

struct Replacement {
    temporary: PathBuf,
    target: PathBuf,
    backup: Option<PathBuf>,
    installed: bool,
}
pub(super) struct PendingWrite {
    directory: StageDirectory,
    replacements: Vec<Replacement>,
}

pub(super) async fn prepare_download(
    spec: &ProviderSpec,
    path: &Path,
    source: &str,
    previous: Option<&CacheEntry>,
    network: &DownloadContext,
    cancellation: &CancellationToken,
    remaining: usize,
) -> io::Result<(CacheEntry, Option<PendingWrite>)> {
    check_cancel(cancellation)?;
    let ProviderSpec::Http { url, .. } = spec else {
        return Err(invalid());
    };
    let directory = StageDirectory::new(path.parent().ok_or_else(invalid)?)?;
    let temporary = directory.path().join("payload");
    let mut options = spec.options()?;
    options.size_limit = Some(remaining as u64);
    let outcome = http::download(DownloadRequest {
        security: network.security.clone(),
        dispatcher: network.dispatcher.clone(),
        url: url.clone(),
        etag: previous.and_then(|entry| entry.metadata.etag.clone()),
        temporary_path: temporary.clone(),
        timeout: http::DEFAULT_DOWNLOAD_TIMEOUT,
        cancellation: cancellation.clone(),
        options,
    })
    .await
    .map_err(|_| io::Error::other("HTTP rewrite resource download failed"))?;
    check_cancel(cancellation)?;
    let mut replacements = Vec::new();
    let (payload, metadata) = match outcome {
        DownloadOutcome::NotModified { .. } => {
            let previous = previous.ok_or_else(invalid)?;
            let mut metadata = previous.metadata.clone();
            metadata.checked = unix_time();
            (previous.payload.clone(), metadata)
        }
        DownloadOutcome::Downloaded { etag, sha256, .. } => {
            let input = read_bounded(&temporary, remaining)?;
            let hash: [u8; 32] = Sha256::digest(&input).into();
            if sha256 != hash {
                return Err(invalid());
            }
            let payload = Arc::new(Payload::parse(&input)?);
            private_permissions(&temporary)?;
            replacements.push(Replacement {
                temporary,
                target: path.into(),
                backup: None,
                installed: false,
            });
            (
                payload,
                Metadata {
                    source: source.into(),
                    hash,
                    etag,
                    checked: unix_time(),
                },
            )
        }
    };
    let temporary = directory.path().join("metadata");
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| io::Error::other("HTTP rewrite metadata cannot be staged"))?;
    file.write_all(&serde_json::to_vec(&metadata).map_err(|_| invalid())?)
        .map_err(|_| io::Error::other("HTTP rewrite metadata cannot be written"))?;
    file.sync_all()
        .map_err(|_| io::Error::other("HTTP rewrite metadata cannot be flushed"))?;
    drop(file);
    replacements.push(Replacement {
        temporary,
        target: metadata_path(path),
        backup: None,
        installed: false,
    });
    let entry = CacheEntry {
        source: source.into(),
        path: path.into(),
        payload,
        checked: metadata.checked,
        metadata,
    };
    Ok((
        entry,
        Some(PendingWrite {
            directory,
            replacements,
        }),
    ))
}

fn private_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| io::Error::other("HTTP rewrite cache permissions cannot be set"))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(super) fn publish(
    writes: &mut [PendingWrite],
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let result = (|| -> io::Result<()> {
        for write in writes.iter_mut() {
            for (index, replacement) in write.replacements.iter_mut().enumerate() {
                check_cancel(cancellation)?;
                match fs::symlink_metadata(&replacement.target) {
                    Ok(metadata) => {
                        if !metadata.is_file() || metadata.file_type().is_symlink() {
                            return Err(invalid());
                        }
                        let backup = write.directory.path().join(format!("backup-{index}"));
                        fs::rename(&replacement.target, &backup).map_err(|_| {
                            io::Error::other("HTTP rewrite cache cannot be staged for replacement")
                        })?;
                        replacement.backup = Some(backup);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                    Err(_) => {
                        return Err(io::Error::other("HTTP rewrite cache target is unavailable"));
                    }
                }
                fs::rename(&replacement.temporary, &replacement.target)
                    .map_err(|_| io::Error::other("HTTP rewrite cache cannot be published"))?;
                replacement.installed = true;
            }
        }
        check_cancel(cancellation)
    })();
    if let Err(error) = result {
        let mut rollback_failed = false;
        for write in writes.iter_mut().rev() {
            for replacement in write.replacements.iter_mut().rev() {
                if replacement.installed && fs::remove_file(&replacement.target).is_err() {
                    rollback_failed = true;
                }
                if let Some(backup) = &replacement.backup
                    && fs::rename(backup, &replacement.target).is_err()
                {
                    rollback_failed = true;
                }
            }
            if rollback_failed {
                write.directory.0 = None;
            }
        }
        return if rollback_failed {
            Err(io::Error::other(
                "HTTP rewrite cache publication failed; preserved recovery files",
            ))
        } else {
            Err(error)
        };
    }
    Ok(())
}
