use std::{
    fs::{self, OpenOptions},
    io::{self, Read as _, Write as _},
    os::windows::ffi::{OsStrExt as _, OsStringExt as _},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
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
use crate::http_processing::{
    config::{MAX_SNAPSHOT, PolicyCandidate},
    private_context::CaMaterial,
};

pub(crate) const SESSION_DIRECTORY: &str = "vole/windows/sessions";
const SESSION_TOKEN_PREFIX: &str = "vole-session-v2:";
const SESSION_REVISION: u32 = 2;
const MAX_BASE_DIR_CODE_UNITS: usize = 32_768;
// Backend validation limits paths to 8 KiB and arguments to 128 KiB in total.
// Their worst-case JSON escaping, process fields and separators fit in 1 MiB.
const MAX_BACKEND_SNAPSHOT_BYTES: usize = 1024 * 1024;
// JSON strings expand by at most six bytes per UTF-8 source byte; each u16
// path element uses at most five digits and a separator. The final 1 KiB
// covers field names, revision, the public digest and container punctuation.
// This is only a read ceiling: publication allocates the exact encoded size.
const MAX_SESSION_SNAPSHOT_BYTES: usize = (MAX_CONFIG_BYTES + MAX_SNAPSHOT) * 6
    + MAX_BASE_DIR_CODE_UNITS * 6
    + MAX_BACKEND_SNAPSHOT_BYTES
    + 1024;
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::http_processing::config::nonnull"
    )]
    http: Option<HttpSessionSnapshot>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_session_backend"
    )]
    session_backend: Option<SessionBackend>,
}

/// A transient publication input. The ordinary snapshot receives only the
/// public certificate identity; the CA is sealed into a separate sidecar.
pub(crate) struct HttpSessionInput<'a> {
    pub(crate) rules: String,
    pub(crate) base_dir: Option<PathBuf>,
    pub(crate) ca: Option<&'a CaMaterial>,
    pub(crate) package_family: &'a str,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HttpSessionSnapshot {
    rules: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::http_processing::config::nonnull"
    )]
    base_dir: Option<Vec<u16>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::http_processing::config::nonnull"
    )]
    ca_identity: Option<[u8; 32]>,
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
        http: Option<HttpSessionInput<'_>>,
    ) -> Result<Self> {
        validate_config_yaml(&config_yaml)?;
        let public_http = http
            .as_ref()
            .map(|input| -> Result<HttpSessionSnapshot> {
                let base_dir = input
                    .base_dir
                    .as_ref()
                    .map(|path| path.as_os_str().encode_wide().collect());
                Ok(HttpSessionSnapshot {
                    rules: input.rules.clone(),
                    base_dir,
                    ca_identity: input
                        .ca
                        .map(CaMaterial::identity)
                        .transpose()
                        .map_err(|_| invalid_snapshot())?,
                })
            })
            .transpose()?;
        validate_http_snapshot(public_http.as_ref())?;
        if let Some(backend) = &session_backend {
            backend.validate(install_root).map_err(windows_error)?;
        }
        let snapshot = SessionSnapshot {
            revision: SESSION_REVISION,
            config_yaml,
            session_backend,
            http: public_http,
        };
        let bytes = snapshot.to_canonical_json()?;
        let reference = Self {
            digest: snapshot_digest(&bytes),
        };
        let sessions = session_directory(local_folder, true)?;
        let private_created = if let Some(input) = &http
            && let Some(ca) = input.ca
        {
            reference.publish_http_ca(local_folder, input.package_family, ca)?
        } else {
            false
        };
        let target = sessions.join(reference.file_name());
        if target.exists() {
            if let Err(error) = reference.read(local_folder, install_root) {
                if private_created {
                    _ = fs::remove_file(sessions.join(reference.private_file_name()));
                }
                return Err(error);
            }
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
        let result = result.and_then(|()| reference.read(local_folder, install_root).map(|_| ()));
        if let Err(error) = result {
            if private_created && reference.read(local_folder, install_root).is_err() {
                _ = fs::remove_file(sessions.join(reference.private_file_name()));
            }
            return Err(error);
        }
        Ok(reference)
    }

    pub(crate) fn token(&self) -> String {
        format!("{SESSION_TOKEN_PREFIX}{}", self.digest)
    }

    pub(crate) fn file_name(&self) -> String {
        format!("{}.json", self.digest)
    }

    fn private_file_name(&self) -> String {
        format!("{}.http-ca.dpapi", self.digest)
    }

    fn publish_http_ca(
        &self,
        local_folder: &Path,
        package_family: &str,
        ca: &CaMaterial,
    ) -> Result<bool> {
        let identity = ca.identity().map_err(|_| invalid_snapshot())?;
        let sessions = session_directory(local_folder, true)?;
        let target = sessions.join(self.private_file_name());
        if target.exists() {
            self.read_http_ca_file(local_folder, package_family, identity)?;
            return Ok(false);
        }
        let protected = super::http_ca::seal(ca, package_family, &self.token())?;
        let staging = sessions.join(format!(
            "staging-{}-{}-ca",
            std::process::id(),
            STAGING_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .map_err(windows_error)?;
            file.write_all(&protected).map_err(windows_error)?;
            file.sync_all().map_err(windows_error)?;
            drop(file);
            match fs::rename(&staging, &target) {
                Ok(()) => Ok(true),
                Err(_) if target.exists() => self
                    .read_http_ca_file(local_folder, package_family, identity)
                    .map(|_| false),
                Err(error) => Err(windows_error(error)),
            }
        })();
        _ = fs::remove_file(staging);
        result
    }

    fn read_http_ca_file(
        &self,
        local_folder: &Path,
        package_family: &str,
        identity: [u8; 32],
    ) -> Result<CaMaterial> {
        let path = session_directory(local_folder, false)?.join(self.private_file_name());
        let bytes = read_regular_file(&path, super::http_ca::MAX_PROTECTED_CA_BYTES as u64)?;
        super::http_ca::open(&bytes, package_family, &self.token(), identity)
    }

    pub(crate) fn read_http_ca(
        &self,
        local_folder: &Path,
        package_family: &str,
        snapshot: &SessionSnapshot,
    ) -> Result<Option<CaMaterial>> {
        if snapshot_digest(&snapshot.to_canonical_json()?) != self.digest {
            return Err(invalid_snapshot());
        }
        snapshot
            .http
            .as_ref()
            .and_then(|http| http.ca_identity)
            .map(|identity| self.read_http_ca_file(local_folder, package_family, identity))
            .transpose()
    }

    pub(crate) fn read(&self, local_folder: &Path, install_root: &Path) -> Result<SessionSnapshot> {
        let path = session_directory(local_folder, false)?.join(self.file_name());
        let bytes = read_regular_file(&path, MAX_SESSION_SNAPSHOT_BYTES as u64)?;
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
        let retained = [
            Some(self.file_name()),
            Some(self.private_file_name()),
            previous.map(Self::file_name),
            previous.map(Self::private_file_name),
        ];
        for entry in fs::read_dir(sessions).map_err(windows_error)? {
            let entry = entry.map_err(windows_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if retained.iter().flatten().any(|retained| retained == &name) {
                continue;
            }
            if name.starts_with("staging-")
                || is_session_file_name(&name)
                || is_private_file_name(&name)
            {
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
            .field("http_config_present", &self.http.is_some())
            .field("backend_present", &self.session_backend.is_some())
            .finish_non_exhaustive()
    }
}
impl SessionSnapshot {
    pub(crate) fn http_snapshot(&self) -> Option<&str> {
        self.http.as_ref().map(|http| http.rules.as_str())
    }

    pub(crate) fn http_base_dir(&self) -> Option<PathBuf> {
        self.http
            .as_ref()
            .and_then(|http| http.base_dir.as_deref())
            .map(|wide| std::ffi::OsString::from_wide(wide).into())
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
        validate_http_snapshot(self.http.as_ref())?;
        if let Some(backend) = &self.session_backend {
            backend.validate(install_root).map_err(windows_error)?;
        }
        Ok(())
    }

    fn to_canonical_json(&self) -> Result<Vec<u8>> {
        validate_config_yaml(&self.config_yaml)?;
        if let Some(http) = &self.http
            && (http.rules.len() > MAX_SNAPSHOT
                || http
                    .base_dir
                    .as_ref()
                    .is_some_and(|path| path.len() > MAX_BASE_DIR_CODE_UNITS))
        {
            return Err(invalid_snapshot());
        }
        if let Some(backend) = &self.session_backend {
            serialized_size(backend, MAX_BACKEND_SNAPSHOT_BYTES)?;
        }
        let size = serialized_size(self, MAX_SESSION_SNAPSHOT_BYTES)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| invalid_snapshot())?;
        serde_json::to_writer(&mut bytes, self).map_err(|_| invalid_snapshot())?;
        debug_assert_eq!(bytes.len(), size);
        Ok(bytes)
    }
}

fn serialized_size(value: &impl Serialize, maximum: usize) -> Result<usize> {
    struct Counter {
        size: usize,
        maximum: usize,
    }
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.size = self
                .size
                .checked_add(bytes.len())
                .filter(|size| *size <= self.maximum)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "session snapshot exceeds limit",
                    )
                })?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { size: 0, maximum };
    serde_json::to_writer(&mut counter, value).map_err(|_| invalid_snapshot())?;
    Ok(counter.size)
}

fn validate_http_snapshot(input: Option<&HttpSessionSnapshot>) -> Result<()> {
    if let Some(input) = input {
        if input.rules.len() > MAX_SNAPSHOT {
            return Err(invalid_snapshot());
        }
        PolicyCandidate::import_snapshot(&input.rules).map_err(|_| invalid_snapshot())?;
        if let Some(wide) = &input.base_dir {
            let path = PathBuf::from(std::ffi::OsString::from_wide(wide));
            if wide.is_empty()
                || wide.len() > MAX_BASE_DIR_CODE_UNITS
                || wide.contains(&0)
                || !path.is_absolute()
            {
                return Err(invalid_snapshot());
            }
        }
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

fn is_private_file_name(name: &str) -> bool {
    name.strip_suffix(".http-ca.dpapi").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn read_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    // Inspect the opened object, not a path that could be replaced between a
    // metadata lookup and the read. Never follow a final reparse point.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(windows_error)?;
    let metadata = file.metadata().map_err(windows_error)?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(invalid_snapshot());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(windows_error)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid_snapshot());
    }
    Ok(bytes)
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

    #[test]
    fn snapshot_json_budget_counts_actual_escaping_before_allocation() {
        let value = "\\\n\"\u{0000}é";
        let expected = serde_json::to_vec(value).unwrap();
        assert_eq!(
            serialized_size(&value, expected.len()).unwrap(),
            expected.len()
        );
        assert!(serialized_size(&value, expected.len() - 1).is_err());
        let snapshot = SessionSnapshot {
            revision: SESSION_REVISION,
            config_yaml: "x".repeat(MAX_CONFIG_BYTES + 1),
            http: None,
            session_backend: None,
        };
        assert!(snapshot.to_canonical_json().is_err());
    }

    #[test]
    fn snapshot_preserves_valid_http_content_expanded_beyond_one_mibibyte() {
        let input = format!(
            "rewrite:\n  enabled: true\n  rules:\n    - &rule {{url: '.', action: response-body-set, value: '{}'}}\n    - *rule\n    - *rule\n    - *rule\n    - *rule\n",
            "x".repeat(256 * 1024)
        );
        assert!(input.len() < crate::http_processing::MAX_ADDENDUM);
        let document = crate::http_processing::config::Document::parse(&input).unwrap();
        let rules = document
            .compile(&Default::default())
            .unwrap()
            .export_snapshot()
            .unwrap();
        assert!(rules.len() > 1024 * 1024);
        let snapshot = SessionSnapshot {
            revision: SESSION_REVISION,
            config_yaml: "tun: {enable: true}".into(),
            http: Some(HttpSessionSnapshot {
                rules,
                base_dir: None,
                ca_identity: None,
            }),
            session_backend: None,
        };
        snapshot.validate(Path::new(".")).unwrap();
        let encoded = snapshot.to_canonical_json().unwrap();
        assert!(encoded.len() > 1024 * 1024);
        let restored: SessionSnapshot = serde_json::from_slice(&encoded).unwrap();
        restored.validate(Path::new(".")).unwrap();
        assert_eq!(restored.to_canonical_json().unwrap(), encoded);
    }

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
        let document = crate::http_processing::config::Document::parse(
            "rewrite: {enabled: true, rules: [{url: '.', action: reject}]}",
        )
        .unwrap();
        let http = document
            .compile(&Default::default())
            .unwrap()
            .export_snapshot()
            .unwrap();
        let updated = SessionReference::publish(
            local.path(),
            install.path(),
            main,
            None,
            Some(HttpSessionInput {
                rules: http.clone(),
                base_dir: None,
                ca: None,
                package_family: "ExamplePackage",
            }),
        )
        .unwrap();
        assert_ne!(initial, updated);
        let snapshot = updated.read(local.path(), install.path()).unwrap();
        assert_eq!(snapshot.http_snapshot(), Some(http.as_str()));
        assert!(!format!("{snapshot:?}").contains("action"));
    }

    #[test]
    fn private_ca_stays_outside_snapshot_and_cannot_cross_session_tokens() {
        let local = tempfile::tempdir().unwrap();
        let install = install_root();
        let ca = crate::http_processing::private_context::test_material();
        let document = crate::http_processing::config::Document::parse(
            "mitm: {enabled: true, domains: [{pattern: example.com}]}",
        )
        .unwrap();
        let rules = document
            .compile(&Default::default())
            .unwrap()
            .export_snapshot()
            .unwrap();
        let publish = |main: &str| {
            SessionReference::publish(
                local.path(),
                install.path(),
                main.to_owned(),
                None,
                Some(HttpSessionInput {
                    rules: rules.clone(),
                    base_dir: None,
                    ca: Some(&ca),
                    package_family: "ExamplePackage",
                }),
            )
            .unwrap()
        };
        let first = publish("rules: [MATCH,DIRECT]");
        assert_eq!(first, publish("rules: [MATCH,DIRECT]"));
        let second = publish("rules: [MATCH,REJECT]");
        assert_ne!(first, second);
        let snapshot = first.read(local.path(), install.path()).unwrap();
        let restored = first
            .read_http_ca(local.path(), "ExamplePackage", &snapshot)
            .unwrap()
            .unwrap();
        assert_eq!(restored.identity().unwrap(), ca.identity().unwrap());
        let encoded = snapshot.to_canonical_json().unwrap();
        let encoded = std::str::from_utf8(&encoded).unwrap();
        assert!(!encoded.contains("PRIVATE KEY"));
        assert!(!encoded.contains("privateKey"));
        assert!(!encoded.contains("BEGIN CERTIFICATE"));
        let sessions = local.path().join(SESSION_DIRECTORY);
        fs::copy(
            sessions.join(first.private_file_name()),
            sessions.join(second.private_file_name()),
        )
        .unwrap();
        let snapshot = second.read(local.path(), install.path()).unwrap();
        assert!(
            second
                .read_http_ca(local.path(), "ExamplePackage", &snapshot)
                .is_err()
        );
    }
}
