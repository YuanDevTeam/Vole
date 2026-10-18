use std::{fs::OpenOptions, io::Read, path::Path};

use serde_yaml_ng::{Mapping, Value};

use super::MAX_CONFIG_BYTES;
use crate::{Result, VoleError};

/// Resolve identities before normalization, keeping file I/O out of TLS clients.
/// One resource generation has a shared, bounded file-content budget.
pub(super) struct IdentityFiles<'a> {
    directory: Option<&'a Path>,
    remaining: usize,
}

impl<'a> IdentityFiles<'a> {
    pub(super) fn new(directory: Option<&'a Path>) -> Self {
        Self {
            directory,
            remaining: MAX_CONFIG_BYTES,
        }
    }

    pub(super) fn inline_node(&mut self, node: &mut Value) -> Result<()> {
        let Some(map) = node.as_mapping_mut() else {
            return Ok(()); // The strict node parser reports the invalid shape.
        };
        if map.get("type").and_then(Value::as_str) == Some("ss")
            && matches!(
                map.get("plugin").and_then(Value::as_str),
                Some("shadow-tls" | "v2ray-plugin" | "gost-plugin")
            )
        {
            if let Some(options) = map.get_mut("plugin-opts").and_then(Value::as_mapping_mut) {
                self.inline_pair(options)?;
            }
            return Ok(());
        }
        if !matches!(
            map.get("type").and_then(Value::as_str),
            Some(
                "http"
                    | "socks5"
                    | "anytls"
                    | "trojan"
                    | "vmess"
                    | "vless"
                    | "hysteria2"
                    | "tuic"
                    | "trusttunnel"
            )
        ) {
            return Ok(());
        }
        self.inline_pair(map)?;
        if let Some(download) = map
            .get_mut("xhttp-opts")
            .and_then(Value::as_mapping_mut)
            .and_then(|xhttp| xhttp.get_mut("download-settings"))
            .and_then(Value::as_mapping_mut)
        {
            self.inline_pair(download)?;
        }
        Ok(())
    }

    fn inline_pair(&mut self, map: &mut Mapping) -> Result<()> {
        let (Some(certificate), Some(private_key)) = (
            map.get("certificate").and_then(Value::as_str),
            map.get("private-key").and_then(Value::as_str),
        ) else {
            return Ok(()); // Pair presence and types remain strict-schema checks.
        };
        if certificate.is_empty() || private_key.is_empty() {
            return Ok(());
        }
        if crate::security::TlsClientIdentity::from_pem(certificate, private_key).is_ok() {
            return Ok(());
        }
        let certificate = self.read(certificate)?;
        let private_key = self.read(private_key)?;
        crate::security::TlsClientIdentity::from_pem(&certificate, &private_key)
            .map_err(|_| invalid_identity())?;
        map.insert("certificate".into(), certificate.into());
        map.insert("private-key".into(), private_key.into());
        Ok(())
    }

    fn read(&mut self, value: &str) -> Result<String> {
        let path = Path::new(value);
        let path = self
            .directory
            .filter(|_| path.is_relative())
            .map_or_else(|| path.to_path_buf(), |directory| directory.join(path));
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|_| invalid_identity())?;
        if !file.metadata().map_err(|_| invalid_identity())?.is_file() {
            return Err(invalid_identity());
        }
        let mut content = String::new();
        file.take(self.remaining as u64 + 1)
            .read_to_string(&mut content)
            .map_err(|_| invalid_identity())?;
        if content.len() > self.remaining {
            return Err(invalid_identity());
        }
        self.remaining -= content.len();
        Ok(content)
    }
}

fn invalid_identity() -> VoleError {
    VoleError::InvalidConfig("invalid TLS client identity file".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_budget_is_shared_and_rejects_non_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("first"), "ab").unwrap();
        std::fs::write(directory.path().join("second"), "cd").unwrap();
        let mut files = IdentityFiles::new(Some(directory.path()));
        files.remaining = 3;
        assert_eq!(files.read("first").unwrap(), "ab");
        assert!(files.read("second").is_err());
        assert!(files.read(".").is_err());
    }
}
