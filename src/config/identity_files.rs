use std::{
    fs::{Metadata, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use serde_yaml_ng::{Mapping, Value};

use super::MAX_CONFIG_BYTES;
use crate::{Result, VoleError};

/// Resolve identities before normalization, keeping file I/O out of TLS clients.
/// One resource generation has a shared, bounded file-content budget.
pub(super) struct IdentityFiles<'a> {
    directory: Option<&'a Path>,
    remaining: usize,
    origins: Vec<NodeOrigins>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct IdentityFileOrigin {
    certificate: PathBuf,
    private_key: PathBuf,
    pub(crate) initial: PairStamp,
}

impl std::fmt::Debug for IdentityFileOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityFileOrigin").finish_non_exhaustive()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct PairStamp(FileStamp, FileStamp);

impl PairStamp {
    pub(crate) fn bytes(&self) -> usize {
        (self.0.len as usize).saturating_add(self.1.len as usize)
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileStamp {
    fn new(metadata: &Metadata) -> Result<Self> {
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
            return Err(invalid_identity());
        }
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }
}

impl IdentityFileOrigin {
    pub(crate) fn stamp(&self) -> Result<PairStamp> {
        Ok(PairStamp(
            FileStamp::new(&std::fs::metadata(&self.certificate).map_err(|_| invalid_identity())?)?,
            FileStamp::new(&std::fs::metadata(&self.private_key).map_err(|_| invalid_identity())?)?,
        ))
    }

    pub(crate) fn read(&self, remaining: &mut usize) -> Result<(String, String, PairStamp)> {
        // Open both members before reading either, and check both open handles
        // and their current paths. A replacement cannot publish a torn pair.
        let open = |path: &Path| {
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK);
            }
            options.open(path).map_err(|_| invalid_identity())
        };
        let mut certificate = open(&self.certificate)?;
        let mut private_key = open(&self.private_key)?;
        let before = PairStamp(
            FileStamp::new(&certificate.metadata().map_err(|_| invalid_identity())?)?,
            FileStamp::new(&private_key.metadata().map_err(|_| invalid_identity())?)?,
        );
        let mut read = |file: &mut std::fs::File| -> Result<String> {
            let mut content = String::new();
            file.take(*remaining as u64 + 1)
                .read_to_string(&mut content)
                .map_err(|_| invalid_identity())?;
            if content.len() > *remaining {
                return Err(invalid_identity());
            }
            *remaining -= content.len();
            Ok(content)
        };
        let certificate_pem = read(&mut certificate)?;
        let private_key_pem = read(&mut private_key)?;
        let after = PairStamp(
            FileStamp::new(&certificate.metadata().map_err(|_| invalid_identity())?)?,
            FileStamp::new(&private_key.metadata().map_err(|_| invalid_identity())?)?,
        );
        if before != after || self.stamp()? != after {
            return Err(invalid_identity());
        }
        Ok((certificate_pem, private_key_pem, after))
    }

    pub(crate) fn same_files(&self, other: &Self) -> bool {
        self.certificate == other.certificate && self.private_key == other.private_key
    }
}

#[derive(Default)]
struct NodeOrigins {
    primary: Option<Arc<IdentityFileOrigin>>,
    realm: Option<Arc<IdentityFileOrigin>>,
    download: Option<Arc<IdentityFileOrigin>>,
    download_inherits: bool,
}

impl<'a> IdentityFiles<'a> {
    pub(super) fn new(directory: Option<&'a Path>) -> Self {
        Self {
            directory,
            remaining: MAX_CONFIG_BYTES,
            origins: Vec::new(),
        }
    }

    pub(super) fn inline_node(&mut self, node: &mut Value) -> Result<()> {
        self.origins.push(NodeOrigins::default());
        let index = self.origins.len() - 1;
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
                self.origins[index].primary = self.inline_pair(options)?;
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
        self.origins[index].primary = self.inline_pair(map)?;
        if map.get("type").and_then(Value::as_str) == Some("hysteria2")
            && let Some(realm) = map.get_mut("realm-opts").and_then(Value::as_mapping_mut)
            && realm.get("enable").and_then(Value::as_bool) == Some(true)
        {
            self.origins[index].realm = self.inline_pair(realm)?;
        }
        if let Some(download) = map
            .get_mut("xhttp-opts")
            .and_then(Value::as_mapping_mut)
            .and_then(|xhttp| xhttp.get_mut("download-settings"))
            .and_then(Value::as_mapping_mut)
        {
            self.origins[index].download_inherits =
                !download.contains_key("certificate") && !download.contains_key("private-key");
            self.origins[index].download = self.inline_pair(download)?;
        }
        Ok(())
    }

    fn inline_pair(&mut self, map: &mut Mapping) -> Result<Option<Arc<IdentityFileOrigin>>> {
        let (Some(certificate), Some(private_key)) = (
            map.get("certificate").and_then(Value::as_str),
            map.get("private-key").and_then(Value::as_str),
        ) else {
            return Ok(None); // Pair presence and types remain strict-schema checks.
        };
        if certificate.is_empty() || private_key.is_empty() {
            return Ok(None);
        }
        if crate::security::TlsClientIdentity::from_pem(certificate, private_key).is_ok() {
            return Ok(None);
        }
        let resolve = |value: &str| -> Result<PathBuf> {
            let path = Path::new(value);
            let path = self
                .directory
                .filter(|_| path.is_relative())
                .map_or_else(|| path.to_path_buf(), |directory| directory.join(path));
            if path.is_absolute() {
                Ok(path)
            } else {
                Ok(std::env::current_dir()
                    .map_err(|_| invalid_identity())?
                    .join(path))
            }
        };
        let mut origin = IdentityFileOrigin {
            certificate: resolve(certificate)?,
            private_key: resolve(private_key)?,
            initial: PairStamp::default(),
        };
        let (certificate, private_key, stamp) = origin.read(&mut self.remaining)?;
        origin.initial = stamp;
        crate::security::TlsClientIdentity::from_pem(&certificate, &private_key)
            .map_err(|_| invalid_identity())?;
        map.insert("certificate".into(), certificate.into());
        map.insert("private-key".into(), private_key.into());
        Ok(Some(Arc::new(origin)))
    }

    pub(super) fn attach(self, proxies: &mut [super::ProxyConfig]) {
        use super::{ProxyProtocol as P, SecurityConfig as S, ShadowsocksPlugin as Plugin};
        fn security(config: &mut S) -> &mut Option<super::TlsIdentityPem> {
            match config {
                S::Tls(tls) => &mut tls.identity,
                S::ShadowTls(tls) => &mut tls.identity,
                S::Jls(jls) => &mut jls.tls.identity,
                // Neither mode can contain an mTLS identity.
                S::None | S::Reality(_) => unreachable!("identity source without standard TLS"),
            }
        }
        fn bind(
            identity: &mut Option<super::TlsIdentityPem>,
            origin: Option<Arc<IdentityFileOrigin>>,
        ) {
            if let (Some(identity), Some(origin)) = (identity, origin) {
                identity.origin = Some(origin);
            }
        }
        for (proxy, origins) in proxies.iter_mut().zip(self.origins) {
            let primary = origins.primary;
            if let P::Vless(vless) = &mut proxy.protocol {
                if primary.is_some() {
                    bind(security(&mut vless.security), primary.clone());
                }
                if let super::VlessTransport::Xhttp(xhttp) = &mut vless.transport
                    && let Some(download) = &mut xhttp.download
                {
                    let origin = if origins.download_inherits {
                        primary
                    } else {
                        origins.download
                    };
                    if origin.is_some() {
                        bind(security(&mut download.security), origin);
                    }
                }
                continue;
            }
            if let P::Hysteria2(hy2) = &mut proxy.protocol {
                bind(&mut hy2.tls.identity, primary);
                if let Some(tls) = hy2.realm.as_mut().and_then(|realm| realm.tls.as_mut()) {
                    bind(&mut tls.identity, origins.realm);
                }
                continue;
            }
            if primary.is_none() {
                continue;
            }
            match &mut proxy.protocol {
                P::Http(node) => {
                    if let Some(tls) = &mut node.tls {
                        bind(&mut tls.identity, primary);
                    }
                }
                P::Socks5(node) => {
                    if let Some(tls) = &mut node.tls {
                        bind(&mut tls.identity, primary);
                    }
                }
                P::TrustTunnel(node) => bind(&mut node.tls.identity, primary),
                P::Tuic(node) => bind(&mut node.tls.identity, primary),
                P::Vmess(node) => bind(security(&mut node.security), primary),
                P::Trojan(node) => bind(security(&mut node.security), primary),
                P::AnyTls(node) => bind(security(&mut node.security), primary),
                P::Shadowsocks(node) => match &mut node.plugin {
                    Some(Plugin::ShadowTls(tls)) => bind(&mut tls.identity, primary),
                    Some(Plugin::WebSocket { tls: Some(tls), .. }) => {
                        bind(&mut tls.identity, primary)
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    #[cfg(test)]
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

    #[test]
    fn file_pair_metadata_and_reads_share_the_input_budget() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate");
        let private_key = directory.path().join("private-key");
        std::fs::write(&certificate, "ab").unwrap();
        std::fs::write(&private_key, "cd").unwrap();
        let origin = IdentityFileOrigin {
            certificate: certificate.clone(),
            private_key,
            initial: PairStamp::default(),
        };
        let mut remaining = 3;
        assert!(origin.read(&mut remaining).is_err());
        let mut remaining = 4;
        let (cert, key, stamp) = origin.read(&mut remaining).unwrap();
        assert_eq!((cert.as_str(), key.as_str(), remaining), ("ab", "cd", 0));
        assert!(stamp == origin.stamp().unwrap());
        assert_eq!(stamp.bytes(), 4);
        // A sparse oversized file is rejected by metadata, before allocating
        // or reading its content into an identity candidate.
        OpenOptions::new()
            .write(true)
            .open(certificate)
            .unwrap()
            .set_len(MAX_CONFIG_BYTES as u64 + 1)
            .unwrap();
        assert!(origin.stamp().is_err());
        let mut remaining = MAX_CONFIG_BYTES;
        assert!(origin.read(&mut remaining).is_err());
        assert_eq!(remaining, MAX_CONFIG_BYTES);
    }
}

#[cfg(all(test, feature = "outbound-hysteria2"))]
mod realm_tests {
    use super::*;
    #[test]
    fn realm_identity_files_use_the_same_generation_budget_and_directory() {
        use base64::Engine as _;
        let identity = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
        let pem = |label: &str, bytes: &[u8]| {
            format!(
                "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            )
        };
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("client.crt"),
            pem("CERTIFICATE", identity.cert.der()),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("client.key"),
            pem("PRIVATE KEY", &identity.signing_key.serialize_der()),
        )
        .unwrap();
        let input = serde_json::json!({"proxies":[{"type":"hysteria2","name":"edge","server":"peer.invalid","port":443,"password":"synthetic","realm-opts":{"enable":true,"server-url":"https://control.invalid","realm-id":"synthetic-zone","stun-servers":["192.0.2.1"],"certificate":"client.crt","private-key":"client.key"}}]});
        let bytes = serde_json::to_vec(&input).unwrap();
        let config =
            super::super::Config::parse_yaml_with_directory(&bytes, Some(directory.path()))
                .unwrap();
        let super::super::ProxyProtocol::Hysteria2(node) = &config.proxies[0].protocol else {
            panic!("HY2")
        };
        assert!(
            node.realm
                .as_ref()
                .unwrap()
                .tls
                .as_ref()
                .unwrap()
                .identity
                .is_some()
        );
        let mut source: Value = serde_yaml_ng::from_slice(&bytes).unwrap();
        let mut files = IdentityFiles::new(Some(directory.path()));
        files.remaining = 1;
        assert!(files.inline_node(&mut source["proxies"][0]).is_err());
    }
}
