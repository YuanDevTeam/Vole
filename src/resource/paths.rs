//! Session-owned provider authorization. It grants no general filesystem access.
#[cfg(any(feature = "invoke", test))]
use std::{env, ffi::OsString};
use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, PartialEq, Eq)]
struct SafeRoot {
    requested: PathBuf,
    canonical: PathBuf,
}
#[derive(Clone, PartialEq, Eq)]
struct ReservedPath {
    path: PathBuf,
    private: bool,
}
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct ProviderPaths {
    roots: Arc<[SafeRoot]>,
    reserved: Arc<[ReservedPath]>,
}
impl std::fmt::Debug for ProviderPaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderPaths")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Access {
    FileRead,
    CacheRead,
    CacheWrite,
}
impl ProviderPaths {
    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn from_os_value(value: Option<OsString>, cwd: &Path) -> io::Result<Self> {
        let Some(value) = value.filter(|value| !value.is_empty()) else {
            return Ok(Self::default());
        };
        if value.as_encoded_bytes().len() > 64 * 1024 {
            return Err(denied());
        }
        let mut roots = Vec::new();
        for root in env::split_paths(&value).filter(|root| !root.as_os_str().is_empty()) {
            if roots.len() == 64 {
                return Err(denied());
            }
            let requested = if root.is_absolute() {
                root
            } else {
                cwd.join(root)
            };
            let canonical = fs::canonicalize(&requested)?;
            if !fs::metadata(&canonical)?.is_dir() {
                return Err(denied());
            }
            if !roots
                .iter()
                .any(|root: &SafeRoot| root.canonical == canonical)
            {
                roots.push(SafeRoot {
                    requested,
                    canonical,
                });
            }
        }
        Ok(Self {
            roots: roots.into(),
            reserved: Arc::default(),
        })
    }
    #[cfg(feature = "invoke")]
    pub(crate) fn authorization_only(&self) -> Self {
        Self {
            roots: self.roots.clone(),
            reserved: Arc::default(),
        }
    }
    #[cfg(any(feature = "invoke", test))]
    pub(crate) fn reserve_inputs(&mut self, paths: impl IntoIterator<Item = (PathBuf, bool)>) {
        self.reserved = paths
            .into_iter()
            .map(|(path, private)| ReservedPath { path, private })
            .collect::<Vec<_>>()
            .into();
    }
    pub(crate) fn resolve(
        &self,
        data_dir: &Path,
        requested: &Path,
        access: Access,
    ) -> io::Result<PathBuf> {
        let default = fs::canonicalize(data_dir)?;
        let target = if requested.is_absolute() {
            requested.to_owned()
        } else {
            default.join(requested)
        };
        let (root, target) = if target.starts_with(&default) {
            (default.clone(), target)
        } else {
            self.roots
                .iter()
                .find_map(|root| {
                    target
                        .strip_prefix(&root.requested)
                        .or_else(|_| target.strip_prefix(&root.canonical))
                        .ok()
                        .map(|relative| (root.canonical.clone(), root.canonical.join(relative)))
                })
                .ok_or_else(denied)?
        };
        let relative = target.strip_prefix(&root).map_err(|_| denied())?;
        if relative
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(denied());
        }
        let parent = target.parent().ok_or_else(denied)?;
        let mut ancestor = parent;
        while !ancestor.exists() {
            ancestor = ancestor.parent().ok_or_else(denied)?;
        }
        if !fs::canonicalize(ancestor)?.starts_with(&root) {
            return Err(denied());
        }
        if !self.reserved.is_empty() {
            let actual = canonical_target(&target)?;
            for reserved in self
                .reserved
                .iter()
                .filter(|reserved| reserved.private || matches!(access, Access::CacheWrite))
            {
                if reserved.path == target
                    || canonical_target(&reserved.path).is_ok_and(|path| path == actual)
                {
                    return Err(denied());
                }
            }
        }
        if matches!(access, Access::CacheWrite) {
            fs::create_dir_all(parent)?;
            if !fs::canonicalize(parent)?.starts_with(&root) {
                return Err(denied());
            }
        }
        match fs::symlink_metadata(&target) {
            Ok(_) if !fs::canonicalize(&target)?.starts_with(&root) => return Err(denied()),
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        Ok(target)
    }
}
fn canonical_target(path: &Path) -> io::Result<PathBuf> {
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(ancestor) {
            Ok(mut canonical) => {
                for name in missing.iter().rev() {
                    canonical.push(name);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(ancestor.file_name().ok_or_else(denied)?.to_os_string());
                ancestor = ancestor.parent().ok_or_else(denied)?;
            }
            Err(error) => return Err(error),
        }
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "provider path escapes authorized roots",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_roots_separate_reads_and_http_cache_writes() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let shared = root.path().join("shared");
        let outside = root.path().join("outside");
        for directory in [&data, &shared, &outside] {
            fs::create_dir(directory).unwrap();
        }
        let paths =
            ProviderPaths::from_os_value(Some(env::join_paths([&shared]).unwrap()), root.path())
                .unwrap();
        let file = shared.join("source.yaml");
        fs::write(&file, b"payload: []").unwrap();
        assert_eq!(
            paths.resolve(&data, &file, Access::FileRead).unwrap(),
            fs::canonicalize(&file).unwrap()
        );
        assert!(
            ProviderPaths::default()
                .resolve(&data, &file, Access::FileRead)
                .is_err()
        );
        let cache = shared.join("cache/resource.yaml");
        paths.resolve(&data, &cache, Access::CacheRead).unwrap();
        assert!(!cache.parent().unwrap().exists());
        paths.resolve(&data, &cache, Access::CacheWrite).unwrap();
        assert!(cache.parent().unwrap().is_dir());
        assert!(
            paths
                .resolve(&data, &outside.join("resource"), Access::CacheWrite)
                .is_err()
        );
        assert!(!outside.join("resource").exists());
        let main = shared.join("main.yaml");
        let private = shared.join("private.json");
        fs::write(&main, b"rules: []").unwrap();
        fs::write(&private, b"private-fixture").unwrap();
        let mut guarded = paths.clone();
        guarded.reserve_inputs([(main.clone(), false), (private.clone(), true)]);
        assert!(guarded.resolve(&data, &main, Access::FileRead).is_ok());
        assert!(guarded.resolve(&data, &main, Access::CacheWrite).is_err());
        assert!(guarded.resolve(&data, &private, Access::FileRead).is_err());
        assert!(
            guarded
                .resolve(&data, &private, Access::CacheWrite)
                .is_err()
        );
        assert!(
            paths
                .resolve(
                    &data,
                    &shared.join("../outside/resource"),
                    Access::CacheWrite
                )
                .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn provider_roots_preserve_aliases_and_reject_symlink_escapes() {
        #[cfg(target_os = "linux")]
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        #[cfg(target_os = "linux")]
        let shared = root.path().join(OsString::from_vec(vec![b's', 255]));
        #[cfg(not(target_os = "linux"))]
        let shared = root.path().join("shared-目录");
        let outside = root.path().join("outside");
        for directory in [&data, &shared, &outside] {
            fs::create_dir(directory).unwrap();
        }
        let paths =
            ProviderPaths::from_os_value(Some(env::join_paths([&shared]).unwrap()), root.path())
                .unwrap();
        let file = shared.join("source.yaml");
        fs::write(&file, b"payload: []").unwrap();
        assert_eq!(
            paths.resolve(&data, &file, Access::FileRead).unwrap(),
            fs::canonicalize(&file).unwrap()
        );
        symlink(&outside, shared.join("escape")).unwrap();
        assert!(
            paths
                .resolve(&data, &shared.join("escape/cache.yaml"), Access::CacheWrite)
                .is_err()
        );
        let external = outside.join("source.yaml");
        fs::write(&external, b"private-fixture").unwrap();
        symlink(&external, shared.join("escaped-file.yaml")).unwrap();
        assert!(
            paths
                .resolve(&data, &shared.join("escaped-file.yaml"), Access::FileRead)
                .is_err()
        );
        let alias = root.path().join("authorized-alias");
        symlink(&shared, &alias).unwrap();
        let alias_paths =
            ProviderPaths::from_os_value(Some(env::join_paths([&alias]).unwrap()), root.path())
                .unwrap();
        assert_eq!(
            alias_paths
                .resolve(&data, &alias.join("source.yaml"), Access::FileRead)
                .unwrap(),
            fs::canonicalize(&file).unwrap()
        );
    }
}
