use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::windows::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use windows::{
    Win32::Foundation::E_FAIL,
    core::{Error, Result},
};

use super::managed_processes::SessionBackend;
use crate::config::MAX_CONFIG_BYTES;

pub(crate) const SESSION_DIRECTORY: &str = "vole/windows/sessions";
const SESSION_TOKEN_PREFIX: &str = "vole-session-v2:";
const SESSION_REVISION: u32 = 2;
const MAX_SESSION_SNAPSHOT_BYTES: u64 = 1024 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
static STAGING_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SessionReference {
    digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SessionSnapshot {
    revision: u32,
    config_yaml: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_config_yaml: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_session_backend"
    )]
    session_backend: Option<SessionBackend>,
}

fn deserialize_session_backend<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SessionBackend>, D::Error>
where
    D: Deserializer<'de>,
{
    SessionBackend::deserialize(deserializer).map(Some)
}

impl SessionReference {
    pub(crate) fn parse(token: &str) -> Result<Self> {
        let digest = token
            .strip_prefix(SESSION_TOKEN_PREFIX)
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| Error::new(E_FAIL, "invalid Windows session snapshot token"))?;
        Ok(Self {
            digest: digest.to_owned(),
        })
    }

    pub(crate) fn publish(
        local_folder: &Path,
        install_root: &Path,
        config_yaml: String,
        session_backend: Option<SessionBackend>,
        http_config_yaml: Option<String>,
    ) -> Result<Self> {
        validate_config_yaml(&config_yaml)?;
        validate_http_config_yaml(http_config_yaml.as_deref())?;
        if let Some(backend) = &session_backend {
            backend.validate(install_root).map_err(windows_error)?;
        }
        let snapshot = SessionSnapshot {
            revision: SESSION_REVISION,
            config_yaml,
            session_backend,
            http_config_yaml,
        };
        let bytes = snapshot.to_canonical_json()?;
        let reference = Self {
            digest: snapshot_digest(&bytes),
        };
        let sessions = session_directory(local_folder, true)?;
        let target = sessions.join(reference.file_name());
        if target.exists() {
            reference.read(local_folder, install_root)?;
            return Ok(reference);
        }

        let staging = sessions.join(format!(
            "staging-{}-{}",
            std::process::id(),
            STAGING_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .map_err(windows_error)?;
            file.write_all(&bytes).map_err(windows_error)?;
            file.sync_all().map_err(windows_error)?;
            drop(file);
            match fs::rename(&staging, &target) {
                Ok(()) => Ok(()),
                Err(_) if target.exists() => reference.read(local_folder, install_root).map(|_| ()),
                Err(error) => Err(windows_error(error)),
            }
        })();
        _ = fs::remove_file(staging);
        result?;
        reference.read(local_folder, install_root)?;
        Ok(reference)
    }

    pub(crate) fn token(&self) -> String {
        format!("{SESSION_TOKEN_PREFIX}{}", self.digest)
    }

    pub(crate) fn file_name(&self) -> String {
        format!("{}.json", self.digest)
    }

    pub(crate) fn read(&self, local_folder: &Path, install_root: &Path) -> Result<SessionSnapshot> {
        let path = session_directory(local_folder, false)?.join(self.file_name());
        let metadata = fs::symlink_metadata(&path).map_err(windows_error)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() == 0
            || metadata.len() > MAX_SESSION_SNAPSHOT_BYTES
        {
            return Err(invalid_snapshot());
        }
        let bytes = fs::read(path).map_err(windows_error)?;
        if snapshot_digest(&bytes) != self.digest {
            return Err(Error::new(
                E_FAIL,
                "Windows session snapshot digest mismatch",
            ));
        }
        let snapshot: SessionSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| invalid_snapshot())?;
        snapshot.validate(install_root)?;
        if snapshot.to_canonical_json()? != bytes {
            return Err(invalid_snapshot());
        }
        Ok(snapshot)
    }

    pub(crate) fn prune(
        &self,
        local_folder: &Path,
        previous: Option<&SessionReference>,
    ) -> Result<()> {
        let sessions = session_directory(local_folder, false)?;
        let retained = [Some(self.file_name()), previous.map(Self::file_name)];
        for entry in fs::read_dir(sessions).map_err(windows_error)? {
            let entry = entry.map_err(windows_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if retained.iter().flatten().any(|retained| retained == &name) {
                continue;
            }
            if name.starts_with("staging-") || is_session_file_name(&name) {
                _ = fs::remove_file(entry.path());
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for SessionSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSnapshot")
            .field("revision", &self.revision)
            .field("config_bytes", &self.config_yaml.len())
            .field("http_config_present", &self.http_config_yaml.is_some())
            .field("backend_present", &self.session_backend.is_some())
            .finish_non_exhaustive()
    }
}
impl SessionSnapshot {
    pub(crate) fn http_config_yaml(&self) -> Option<&str> {
        self.http_config_yaml.as_deref()
    }
    pub(crate) fn config_yaml(&self) -> &str {
        &self.config_yaml
    }

    pub(crate) fn session_backend(&self) -> Option<&SessionBackend> {
        self.session_backend.as_ref()
    }

    fn validate(&self, install_root: &Path) -> Result<()> {
        if self.revision != SESSION_REVISION {
            return Err(invalid_snapshot());
        }
        validate_config_yaml(&self.config_yaml)?;
        validate_http_config_yaml(self.http_config_yaml.as_deref())?;
        if let Some(backend) = &self.session_backend {
            backend.validate(install_root).map_err(windows_error)?;
        }
        Ok(())
    }

    fn to_canonical_json(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| invalid_snapshot())?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_SESSION_SNAPSHOT_BYTES {
            return Err(invalid_snapshot());
        }
        Ok(bytes)
    }
}

fn validate_http_config_yaml(input: Option<&str>) -> Result<()> {
    if input.is_some_and(|input| input.len() > crate::http_processing::MAX_ADDENDUM) {
        return Err(invalid_snapshot());
    }
    Ok(())
}
fn validate_config_yaml(config_yaml: &str) -> Result<()> {
    if config_yaml.is_empty() || config_yaml.len() > MAX_CONFIG_BYTES {
        return Err(Error::new(
            E_FAIL,
            "invalid Windows Vole configuration size",
        ));
    }
    Ok(())
}

fn session_directory(local_folder: &Path, create: bool) -> Result<PathBuf> {
    let sessions = local_folder.join(SESSION_DIRECTORY);
    if create {
        fs::create_dir_all(&sessions).map_err(windows_error)?;
    }
    for path in [
        local_folder.join("vole"),
        local_folder.join("vole/windows"),
        sessions.clone(),
    ] {
        reject_reparse_point(&path)?;
    }
    Ok(sessions)
}

fn reject_reparse_point(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(windows_error)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::new(
            E_FAIL,
            "invalid Windows session snapshot directory",
        ));
    }
    Ok(())
}

fn is_session_file_name(name: &str) -> bool {
    name.len() == 69
        && name.ends_with(".json")
        && name[..64]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn snapshot_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn invalid_snapshot() -> Error {
    Error::new(E_FAIL, "invalid Windows session snapshot")
}

fn windows_error(error: impl std::fmt::Display) -> Error {
    Error::new(E_FAIL, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        fs::write(root.path().join("bin/proxy.exe"), b"fixture").unwrap();
        root
    }

    fn backend(arguments: &[&str]) -> SessionBackend {
        serde_json::from_value(serde_json::json!({
            "processes": [{
                "executableRelativePath": "bin\\proxy.exe",
                "arguments": arguments,
            }]
        }))
        .unwrap()
    }

    #[test]
    fn token_accepts_only_the_canonical_session_digest() {
        let digest = "0123456789abcdef".repeat(4);
        let reference = SessionReference::parse(&format!("vole-session-v2:{digest}")).unwrap();
        assert_eq!(reference.file_name(), format!("{digest}.json"));

        for token in [
            digest.clone(),
            format!("vole-v1:{digest}"),
            format!("vole-session-v3:{digest}"),
            format!("vole-session-v2:{}", digest.to_uppercase()),
            "vole-session-v2:../session.json".to_owned(),
            "vole-session-v2:00".to_owned(),
        ] {
            assert!(SessionReference::parse(&token).is_err(), "accepted {token}");
        }
    }

    #[test]
    fn publication_covers_process_order_and_arguments() {
        let local = tempfile::tempdir().unwrap();
        let install = install_root();
        let first = SessionReference::publish(
            local.path(),
            install.path(),
            "tun:\n  enable: true\n".to_owned(),
            Some(backend(&["run", "one"])),
            None,
        )
        .unwrap();
        let same = SessionReference::publish(
            local.path(),
            install.path(),
            "tun:\n  enable: true\n".to_owned(),
            Some(backend(&["run", "one"])),
            None,
        )
        .unwrap();
        let changed = SessionReference::publish(
            local.path(),
            install.path(),
            "tun:\n  enable: true\n".to_owned(),
            Some(backend(&["run", "two"])),
            None,
        )
        .unwrap();

        assert_eq!(first, same);
        assert_ne!(first, changed);
        assert_eq!(
            first
                .read(local.path(), install.path())
                .unwrap()
                .config_yaml(),
            "tun:\n  enable: true\n"
        );
    }

    #[test]
    fn read_rejects_tampering_and_noncanonical_json() {
        let local = tempfile::tempdir().unwrap();
        let install = install_root();
        let reference = SessionReference::publish(
            local.path(),
            install.path(),
            "tun:\n  enable: true\n".to_owned(),
            None,
            None,
        )
        .unwrap();
        fs::write(
            local
                .path()
                .join(SESSION_DIRECTORY)
                .join(reference.file_name()),
            b"changed",
        )
        .unwrap();
        assert!(reference.read(local.path(), install.path()).is_err());
    }

    #[test]
    fn snapshot_rejects_an_explicit_null_backend() {
        assert!(
            serde_json::from_value::<SessionSnapshot>(serde_json::json!({
                "revision": 2,
                "configYaml": "tun:\n  enable: true\n",
                "sessionBackend": null
            }))
            .is_err()
        );
    }

    #[test]
    fn cleanup_retains_current_and_previous_sessions() {
        let local = tempfile::tempdir().unwrap();
        let install = install_root();
        let publish = |yaml: &str| {
            SessionReference::publish(local.path(), install.path(), yaml.to_owned(), None, None)
                .unwrap()
        };
        let first = publish("first");
        let second = publish("second");
        let third = publish("third");
        fs::write(
            local.path().join(SESSION_DIRECTORY).join("staging-old"),
            b"x",
        )
        .unwrap();

        third.prune(local.path(), Some(&second)).unwrap();
        let sessions = local.path().join(SESSION_DIRECTORY);
        assert!(!sessions.join(first.file_name()).exists());
        assert!(sessions.join(second.file_name()).exists());
        assert!(sessions.join(third.file_name()).exists());
        assert!(!sessions.join("staging-old").exists());
    }

    #[test]
    fn snapshot_identity_and_readback_include_the_http_addendum() {
        let local = tempfile::tempdir().unwrap();
        let install = install_root();
        let main = "tun: {enable: true}".to_owned();
        let initial =
            SessionReference::publish(local.path(), install.path(), main.clone(), None, None)
                .unwrap();
        let http = "rewrite: [{pattern: '.', action: reject}]".to_owned();
        let updated =
            SessionReference::publish(local.path(), install.path(), main, None, Some(http.clone()))
                .unwrap();
        assert_ne!(initial, updated);
        let snapshot = updated.read(local.path(), install.path()).unwrap();
        assert_eq!(snapshot.http_config_yaml(), Some(http.as_str()));
        assert!(!format!("{snapshot:?}").contains("pattern"));
    }
}
