//! Runtime-owned selection cache. The source YAML is never rewritten.
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Mutex,
};
#[derive(Debug)]
pub(crate) struct SelectionStore {
    path: Option<PathBuf>,
    values: Mutex<BTreeMap<String, String>>,
}
impl SelectionStore {
    pub fn open(root: &Path, enabled: bool) -> Self {
        let path = enabled.then(|| root.join("selected.json"));
        let values = path
            .as_ref()
            .and_then(|path| {
                let file = fs::File::open(path).ok()?;
                let mut bytes = Vec::new();
                file.take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .ok()?;
                if bytes.len() > 8 * 1024 * 1024 {
                    return None;
                }
                serde_json::from_slice(&bytes).ok()
            })
            .unwrap_or_default();
        Self {
            path,
            values: Mutex::new(values),
        }
    }
    pub fn restore(&self, groups: &crate::routing::ProxyGroups) {
        for (name, member) in self.values.lock().unwrap().iter() {
            let _ = groups.select(name, member);
        }
    }
    pub fn save(&self, name: &str, member: &str) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut values = self.values.lock().unwrap();
        values.insert(name.into(), member.into());
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        let result = (|| {
            fs::write(
                &temporary,
                serde_json::to_vec(&*values).map_err(io::Error::other)?,
            )?;
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}
