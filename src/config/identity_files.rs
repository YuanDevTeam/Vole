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

#[cfg(all(
    test,
    feature = "inbound-http",
    any(
        feature = "outbound-http",
        feature = "outbound-socks5",
        feature = "outbound-vmess",
        feature = "outbound-trojan",
        feature = "outbound-anytls",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "outbound-vless"
    )
))]
mod http_reuse_security_memory_tests {
    use super::{IdentityFileOrigin, PairStamp};
    #[cfg(feature = "outbound-vmess")]
    use crate::outbound::vmess::VmessOutbound;
    use crate::{
        config::{StaticEchConfig, TlsIdentityPem},
        security::SecurityContext,
    };
    #[cfg(any(
        feature = "outbound-http",
        feature = "outbound-socks5",
        feature = "outbound-vmess",
        feature = "outbound-trojan",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic"
    ))]
    use crate::{
        dialer::Dialer,
        outbound::{OutboundConnector, UpstreamPath},
    };
    use std::{path::PathBuf, sync::Arc};

    fn identity() -> TlsIdentityPem {
        use base64::Engine as _;
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["client.memory.invalid".into()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params.self_signed(&key).unwrap();
        let pem = |label: &str, bytes: &[u8]| {
            format!(
                "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            )
        };
        TlsIdentityPem {
            certificate: pem("CERTIFICATE", certificate.der()),
            private_key: pem("PRIVATE KEY", &key.serialize_der()),
            origin: None,
        }
    }

    fn marked_file_identity(mut identity: TlsIdentityPem) -> TlsIdentityPem {
        // A marker only: the supplied PEM is already valid. No test invokes
        // IdentityFiles, stamp/read, refresh, a worker or any filesystem API.
        identity.origin = Some(Arc::new(IdentityFileOrigin {
            certificate: PathBuf::from("/__vole_memory_identity__/certificate.pem"),
            private_key: PathBuf::from("/__vole_memory_identity__/private-key.pem"),
            initial: PairStamp::default(),
        }));
        identity
    }

    #[cfg(any(
        feature = "outbound-http",
        feature = "outbound-socks5",
        feature = "outbound-vmess",
        feature = "outbound-trojan",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic"
    ))]
    fn path() -> UpstreamPath {
        UpstreamPath::LazyDirect {
            dialer: Dialer::default(),
        }
    }

    #[cfg(feature = "outbound-tuic")]
    #[test]
    fn tuic_real_tls_constructor_reuses_inline_but_rejects_file_identity() {
        let parsed = crate::config::Config::parse_yaml(
            b"proxies: [{name: memory, type: tuic, server: 192.0.2.10, port: 443, uuid: 00000000-0000-0000-0000-000000000007, password: synthetic, sni: tuic.memory.invalid}]",
        ).unwrap();
        let crate::config::ProxyProtocol::Tuic(config) = &parsed.proxies[0].protocol else {
            panic!("TUIC memory configuration")
        };
        let identity = identity();
        for mode in [
            crate::config::TuicUdpMode::Native,
            crate::config::TuicUdpMode::Quic,
        ] {
            for uot in [false, true] {
                let mut config = config.clone();
                config.udp_mode = mode;
                config.udp_over_stream = uot;
                let security = SecurityContext::new();
                for inline in [None, Some(identity.clone())] {
                    config.tls.identity = inline;
                    let node = crate::outbound::tuic::TuicOutbound::with_shared_security(
                        &config,
                        path(),
                        &security,
                        8192,
                    )
                    .unwrap();
                    assert!(node.permits_http_tcp_reuse());
                    node.begin_shutdown();
                    assert!(!node.permits_http_tcp_reuse());
                }
                assert!(!security.identities.has_sources());
                config.tls.identity = Some(marked_file_identity(identity.clone()));
                let file = crate::outbound::tuic::TuicOutbound::with_shared_security(
                    &config,
                    path(),
                    &security,
                    8192,
                )
                .unwrap();
                assert!(security.identities.has_sources());
                assert!(!file.permits_http_tcp_reuse());
            }
        }
    }

    #[cfg(feature = "outbound-http")]
    fn http(
        identity: Option<TlsIdentityPem>,
        ech: Option<StaticEchConfig>,
        security: &SecurityContext,
    ) -> crate::outbound::http::HttpOutbound {
        let config = crate::config::HttpOutboundConfig {
            address: "192.0.2.10".into(),
            port: 8443,
            tls: Some(crate::config::TlsConfig {
                server_name: "proxy.memory.invalid".into(),
                alpn: vec![b"http/1.1".to_vec()],
                tls13_only: false,
                required_alpn: None,
                certificate: Default::default(),
                identity,
                ech,
                client_fingerprint: None,
            }),
            auth: None,
            headers: Default::default(),
        };
        crate::outbound::http::HttpOutbound::with_shared_security(
            &config,
            path(),
            security,
            0,
            8192,
        )
        .unwrap()
    }

    #[cfg(feature = "outbound-socks5")]
    fn socks(
        server: &str,
        identity: Option<TlsIdentityPem>,
        ech: Option<StaticEchConfig>,
        security: &SecurityContext,
    ) -> std::io::Result<crate::outbound::Socks5Outbound> {
        let config = crate::config::Socks5OutboundConfig {
            address: server.into(),
            port: 8443,
            username: None,
            password: None,
            tls: Some(crate::config::TlsClientPolicy {
                identity,
                ech,
                ..Default::default()
            }),
        };
        crate::outbound::Socks5Outbound::with_shared_security(
            &config,
            path(),
            Some(security),
            0,
            8192,
        )
    }

    #[cfg(feature = "outbound-http")]
    #[test]
    fn http_inline_identity_reuses_but_file_origin_does_not() {
        let identity = identity();
        let security = SecurityContext::new();
        let inline = http(Some(identity.clone()), None, &security);
        assert!(inline.permits_http_tcp_reuse());
        assert!(!security.identities.has_sources());
        let file = http(Some(marked_file_identity(identity)), None, &security);
        assert!(!file.permits_http_tcp_reuse());
        assert!(security.identities.has_sources());
    }

    #[cfg(feature = "outbound-socks5")]
    #[test]
    fn socks5_inline_identity_reuses_but_file_origin_does_not() {
        let identity = identity();
        let security = SecurityContext::new();
        let inline = socks("192.0.2.10", Some(identity.clone()), None, &security).unwrap();
        assert!(OutboundConnector::permits_http_tcp_reuse(&inline));
        assert!(!security.identities.has_sources());
        let file = socks(
            "192.0.2.10",
            Some(marked_file_identity(identity)),
            None,
            &security,
        )
        .unwrap();
        assert!(!OutboundConnector::permits_http_tcp_reuse(&file));
        assert!(security.identities.has_sources());
    }

    #[cfg(feature = "ech")]
    fn dynamic_ech() -> StaticEchConfig {
        let raw: super::super::ech::RawEch =
            serde_yaml_ng::from_str("enable: true\nquery-server-name: ech.memory.invalid\n")
                .unwrap();
        let ech = raw.normalize(false).unwrap().unwrap();
        assert!(ech.is_dynamic());
        ech
    }

    #[cfg(feature = "ech")]
    fn static_ech() -> StaticEchConfig {
        // A public X25519 key and bounded ECHConfigList. No private
        // ECH key, server, ClientHello or network operation is needed here.
        let name = b"public.memory.invalid";
        let key = [9_u8; 32];
        let mut content = vec![7];
        content.extend_from_slice(&0x0020_u16.to_be_bytes());
        content.extend_from_slice(&(key.len() as u16).to_be_bytes());
        content.extend_from_slice(&key);
        content.extend_from_slice(&4_u16.to_be_bytes());
        content.extend_from_slice(&1_u16.to_be_bytes());
        content.extend_from_slice(&1_u16.to_be_bytes());
        content.extend_from_slice(&[0, name.len() as u8]);
        content.extend_from_slice(name);
        content.extend_from_slice(&[0, 0]);
        let mut list = ((content.len() + 4) as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&0xfe0d_u16.to_be_bytes());
        list.extend_from_slice(&(content.len() as u16).to_be_bytes());
        list.extend_from_slice(&content);
        let ech = StaticEchConfig::from_config_list_for_backend(&list, false).unwrap();
        assert!(!ech.is_dynamic());
        ech
    }

    #[cfg(all(feature = "outbound-http", feature = "ech"))]
    #[test]
    fn http_static_ech_reuses_but_dynamic_ech_does_not() {
        let security = SecurityContext::new();
        let fixed = http(None, Some(static_ech()), &security);
        assert!(fixed.permits_http_tcp_reuse());
        let dynamic = http(None, Some(dynamic_ech()), &security);
        assert!(!dynamic.permits_http_tcp_reuse());
        assert!(!security.identities.has_sources());
    }

    #[cfg(all(feature = "outbound-socks5", feature = "ech"))]
    #[test]
    fn socks5_ech_cannot_bypass_literal_endpoint_and_dns_name_requirements() {
        let security = SecurityContext::new();
        for ech in [static_ech(), dynamic_ech()] {
            // SOCKS TLS deliberately authenticates its configured address.
            // ECH requires DNS SNI, whereas the reuse proof requires literal
            // proxy addressing. The actual constructor rejects this pair.
            let result = socks("192.0.2.10", None, Some(ech.clone()), &security);
            assert!(
                matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::InvalidInput)
            );
            // A supported DNS-named ECH constructor remains keyless; it must
            // not manufacture a literal endpoint or perform DNS to qualify.
            let named = socks("proxy.memory.invalid", None, Some(ech), &security).unwrap();
            assert!(!OutboundConnector::permits_http_tcp_reuse(&named));
        }
    }

    #[cfg(feature = "outbound-hysteria2")]
    fn hysteria2(
        identity: Option<TlsIdentityPem>,
        ech: Option<StaticEchConfig>,
        security: &SecurityContext,
    ) -> crate::outbound::hysteria2::Hysteria2Outbound {
        let parsed = crate::config::Config::parse_yaml(
            br#"proxies:
  - name: memory-hysteria2
    type: hysteria2
    server: 192.0.2.10
    port: 8443
    password: memory-only-password
    sni: proxy.memory.invalid
"#,
        )
        .unwrap();
        let crate::config::ProxyProtocol::Hysteria2(config) = &parsed.proxies[0].protocol else {
            panic!("expected normalized Hysteria2 configuration");
        };
        let mut config = config.as_ref().clone();
        config.tls.identity = identity;
        config.tls.ech = ech;
        crate::outbound::hysteria2::Hysteria2Outbound::with_shared_security(
            &config,
            path(),
            security,
            0,
            8192,
        )
        .unwrap()
    }

    #[cfg(feature = "outbound-hysteria2")]
    #[test]
    fn hysteria2_inline_identity_qualifies_but_file_storage_does_not() {
        let identity = identity();
        let security = SecurityContext::new();
        let inline = hysteria2(Some(identity.clone()), None, &security);
        assert!(inline.permits_http_tcp_reuse());
        assert!(!security.identities.has_sources());
        let file = hysteria2(Some(marked_file_identity(identity)), None, &security);
        assert!(!file.permits_http_tcp_reuse());
        assert!(security.identities.has_sources());
    }

    #[cfg(all(feature = "outbound-hysteria2", feature = "ech"))]
    #[test]
    fn hysteria2_static_ech_qualifies_but_dynamic_ech_does_not() {
        let security = SecurityContext::new();
        let fixed = hysteria2(None, Some(static_ech()), &security);
        assert!(fixed.permits_http_tcp_reuse());
        let dynamic = hysteria2(None, Some(dynamic_ech()), &security);
        assert!(!dynamic.permits_http_tcp_reuse());
        assert!(!security.identities.has_sources());
    }

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    fn stream_tls(
        network: &str,
        identity: Option<TlsIdentityPem>,
        ech: Option<StaticEchConfig>,
    ) -> crate::config::SecurityConfig {
        let alpn = match network {
            "ws" => vec![b"http/1.1".to_vec()],
            "grpc" => vec![b"h2".to_vec()],
            _ => Vec::new(),
        };
        crate::config::SecurityConfig::Tls(crate::config::TlsConfig {
            server_name: "proxy.memory.invalid".into(),
            required_alpn: alpn.first().cloned(),
            alpn,
            tls13_only: ech.is_some(),
            certificate: Default::default(),
            identity,
            ech,
            client_fingerprint: None,
        })
    }

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    fn stream_proxies(
        network: &str,
        security: crate::config::SecurityConfig,
        upstream: UpstreamPath,
    ) -> Vec<(&'static str, Box<dyn OutboundConnector>)> {
        vec![
            #[cfg(feature = "outbound-vmess")]
            (
                "vmess",
                Box::new(
                    crate::outbound::vmess::VmessOutbound::new_with_path(
                        &crate::config::VmessOutboundConfig {
                            address: "192.0.2.10".into(),
                            port: 8443,
                            id: uuid::Uuid::from_u128(7),
                            cipher: crate::config::VmessCipher::Aes128Gcm,
                            global_padding: false,
                            authenticated_length: false,
                            packet_encoding: crate::config::VmessPacketEncoding::Raw,
                            server_name: security.server_name().into(),
                            security: security.clone(),
                            transport: match network {
                                "tcp" => crate::config::VmessTransport::Tcp,
                                "ws" => crate::config::VmessTransport::WebSocket {
                                    uri: "wss://proxy.memory.invalid/path".into(),
                                    headers: Default::default(),
                                    max_early_data: 0,
                                    early_data_header_name: "Sec-WebSocket-Protocol".into(),
                                    handshake: Default::default(),
                                },
                                "grpc" => crate::config::VmessTransport::Grpc {
                                    uri: "https://proxy.memory.invalid/GunService/Tun".into(),
                                    options: Default::default(),
                                },
                                _ => panic!("unsupported memory transport"),
                            },
                        },
                        upstream.clone(),
                    )
                    .unwrap(),
                ) as Box<dyn OutboundConnector>,
            ),
            #[cfg(feature = "outbound-trojan")]
            (
                "trojan",
                Box::new(
                    crate::outbound::trojan::TrojanOutbound::new_with_path(
                        &crate::config::TrojanOutboundConfig {
                            address: "192.0.2.10".into(),
                            port: 8443,
                            password: "memory-password".into(),
                            server_name: security.server_name().into(),
                            security: security.clone(),
                            transport: match network {
                                "tcp" => crate::config::TrojanTransport::Tcp,
                                "ws" => crate::config::TrojanTransport::WebSocket {
                                    uri: "wss://proxy.memory.invalid/path".into(),
                                    headers: Default::default(),
                                    max_early_data: 0,
                                    early_data_header_name: "Sec-WebSocket-Protocol".into(),
                                    handshake: Default::default(),
                                },
                                "grpc" => crate::config::TrojanTransport::Grpc {
                                    uri: "https://proxy.memory.invalid/GunService/Tun".into(),
                                    options: Default::default(),
                                },
                                _ => panic!("unsupported memory transport"),
                            },
                        },
                        upstream.clone(),
                    )
                    .unwrap(),
                ) as Box<dyn OutboundConnector>,
            ),
        ]
    }

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    #[test]
    fn stream_proxy_static_transports_reuse_and_owner_stop_revokes_admission() {
        for network in ["tcp", "ws", "grpc"] {
            for (name, node) in stream_proxies(network, stream_tls(network, None, None), path()) {
                assert!(node.permits_http_tcp_reuse(), "{name}/{network}");
                node.begin_shutdown();
                assert!(!node.permits_http_tcp_reuse(), "{name}/{network}");
            }
        }
    }

    #[cfg(feature = "outbound-vmess")]
    #[test]
    fn vmess_plain_tcp_keeps_static_http_proof() {
        let mut config = crate::config::Config::parse_yaml(
            b"proxies: [{name: memory, type: vmess, server: 192.0.2.10, port: 8443, uuid: 00000000-0000-0000-0000-000000000007, cipher: aes-128-gcm}]\nrules: ['MATCH,memory']\n",
        )
        .unwrap();
        let crate::config::ProxyProtocol::Vmess(node) = config.proxies.remove(0).protocol else {
            panic!("memory VMess configuration")
        };
        let outbound = crate::outbound::vmess::VmessOutbound::new_with_path(&node, path()).unwrap();
        assert!(outbound.permits_http_tcp_reuse());
        outbound.begin_shutdown();
        assert!(!outbound.permits_http_tcp_reuse());
    }

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    #[test]
    fn stream_proxy_inline_identity_qualifies_but_file_source_does_not() {
        let identity = identity();
        for network in ["tcp", "ws", "grpc"] {
            for (name, node) in stream_proxies(
                network,
                stream_tls(network, Some(identity.clone()), None),
                path(),
            ) {
                assert!(node.permits_http_tcp_reuse(), "{name}/{network}");
            }
            for (name, node) in stream_proxies(
                network,
                stream_tls(network, Some(marked_file_identity(identity.clone())), None),
                path(),
            ) {
                assert!(!node.permits_http_tcp_reuse(), "{name}/{network}");
            }
        }
    }

    #[cfg(all(
        feature = "ech",
        any(feature = "outbound-vmess", feature = "outbound-trojan")
    ))]
    #[test]
    fn stream_proxy_static_ech_qualifies_but_dynamic_ech_does_not() {
        for network in ["tcp", "ws", "grpc"] {
            for (name, node) in stream_proxies(
                network,
                stream_tls(network, None, Some(static_ech())),
                path(),
            ) {
                assert!(node.permits_http_tcp_reuse(), "{name}/{network}");
            }
            for (name, node) in stream_proxies(
                network,
                stream_tls(network, None, Some(dynamic_ech())),
                path(),
            ) {
                assert!(!node.permits_http_tcp_reuse(), "{name}/{network}");
            }
        }
    }

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    #[test]
    fn stream_proxy_upstream_group_remains_keyless_and_dialer_stop_propagates() {
        let selection = Arc::new(crate::routing::GroupSelection::new(0));
        let group = UpstreamPath::Group {
            server: crate::session::Destination::Ip("192.0.2.10:8443".parse().unwrap()),
            group: Arc::new(crate::outbound::SelectUpstream::new(
                selection.clone(),
                vec![crate::outbound::SelectUpstreamMember::Direct],
            )),
            endpoint: None,
            dialer: Dialer::default(),
        };
        for (name, node) in stream_proxies("tcp", stream_tls("tcp", None, None), group) {
            assert!(!node.permits_http_tcp_reuse(), "{name}");
        }
        let dialer = Dialer::default();
        let nodes = stream_proxies(
            "tcp",
            stream_tls("tcp", None, None),
            UpstreamPath::LazyDirect {
                dialer: dialer.clone(),
            },
        );
        assert!(nodes.iter().all(|(_, node)| node.permits_http_tcp_reuse()));
        dialer.begin_shutdown();
        assert!(nodes.iter().all(|(_, node)| !node.permits_http_tcp_reuse()));
    }

    #[cfg(any(
        feature = "outbound-anytls",
        feature = "outbound-vmess",
        feature = "outbound-trojan",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "outbound-vless"
    ))]
    fn constructed_tls(
        identity: Option<TlsIdentityPem>,
        ech: Option<StaticEchConfig>,
        profile: Option<crate::config::ClientFingerprint>,
    ) -> crate::security::StandardTlsClient {
        let context = SecurityContext::new();
        let identity = identity.as_ref().map(|identity| {
            crate::security::TlsClientIdentity::from_config(identity, &context).unwrap()
        });
        crate::security::StandardTlsClient::with_options(
            &context,
            "proxy.memory.invalid",
            crate::security::TlsClientOptions {
                identity,
                ech,
                client_fingerprint: profile,
                ..Default::default()
            },
            0,
            8192,
        )
        .unwrap()
    }

    #[cfg(any(
        feature = "outbound-anytls",
        feature = "outbound-vmess",
        feature = "outbound-trojan",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "outbound-vless"
    ))]
    #[test]
    fn constructed_tls_inline_identity_qualifies_but_file_storage_does_not() {
        let identity = identity();
        let profiles = [
            None,
            #[cfg(feature = "tls-fingerprint")]
            Some(crate::config::ClientFingerprint::Chrome155),
        ];
        for profile in profiles {
            let inline = constructed_tls(Some(identity.clone()), None, profile);
            assert!(inline.permits_static_http_reuse());
            let file = constructed_tls(Some(marked_file_identity(identity.clone())), None, profile);
            assert!(!file.permits_static_http_reuse());
        }
    }

    #[cfg(all(
        feature = "ech",
        any(
            feature = "outbound-anytls",
            feature = "outbound-vmess",
            feature = "outbound-trojan",
            feature = "outbound-hysteria2",
            feature = "outbound-tuic",
            feature = "outbound-vless"
        )
    ))]
    #[test]
    fn constructed_tls_static_ech_qualifies_but_dynamic_wrapper_does_not() {
        let fixed = constructed_tls(None, Some(static_ech()), None);
        assert!(fixed.permits_static_http_reuse());
        let dynamic = constructed_tls(None, Some(dynamic_ech()), None);
        assert!(!dynamic.permits_static_http_reuse());
    }

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    struct OpaqueStreamDependency;

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    #[async_trait::async_trait]
    impl OutboundConnector for OpaqueStreamDependency {
        async fn connect_stream(
            &self,
            _: crate::session::StreamSession,
            _: &crate::outbound::EstablishContext,
        ) -> std::result::Result<crate::outbound::ConnectedStream, crate::dispatch::DispatchError>
        {
            panic!("a structural query must not open opaque IO")
        }
        async fn open_datagram(
            &self,
            _: crate::outbound::DatagramRequest,
            _: &crate::outbound::EstablishContext,
        ) -> std::result::Result<
            Box<dyn crate::dispatch::DatagramTransport>,
            crate::dispatch::DispatchError,
        > {
            panic!("a structural query must not open opaque datagrams")
        }
    }

    #[cfg(any(feature = "outbound-vmess", feature = "outbound-trojan"))]
    #[test]
    fn stream_proxy_opaque_dependency_never_gains_reuse_permission() {
        for (name, node) in stream_proxies(
            "tcp",
            stream_tls("tcp", None, None),
            UpstreamPath::proxy(Arc::new(OpaqueStreamDependency)),
        ) {
            assert!(!node.permits_http_tcp_reuse(), "{name}");
        }
    }

    #[cfg(feature = "outbound-vmess")]
    fn vmess_h2_config(tls: bool) -> crate::config::VmessOutboundConfig {
        let security = if tls {
            ", tls: true, servername: proxy.memory.invalid"
        } else {
            ""
        };
        let yaml = format!(
            "proxies: [{{name: memory, type: vmess, server: 192.0.2.10, port: 8443, uuid: 00000000-0000-0000-0000-000000000007, cipher: aes-128-gcm, network: h2, h2-opts: {{host: [proxy.memory.invalid], path: /memory}}{security}}}]\nrules: ['MATCH,memory']\n"
        );
        let mut config = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
        let crate::config::ProxyProtocol::Vmess(node) = config.proxies.remove(0).protocol else {
            panic!("memory VMess H2 configuration")
        };
        node
    }

    #[cfg(feature = "outbound-vmess")]
    #[test]
    fn vmess_h2_single_uri_plain_and_static_tls_reuse_until_owner_stop() {
        for tls in [false, true] {
            let config = vmess_h2_config(tls);
            let crate::config::VmessTransport::H2 { uris } = &config.transport else {
                panic!("memory VMess H2 transport")
            };
            assert_eq!(
                uris,
                &[format!(
                    "{}://proxy.memory.invalid/memory",
                    if tls { "https" } else { "http" }
                )]
            );
            let node = VmessOutbound::new_with_path(&config, path()).unwrap();
            assert!(node.permits_http_tcp_reuse(), "tls={tls}");
            node.begin_shutdown();
            assert!(!node.permits_http_tcp_reuse(), "tls={tls}");
        }
    }

    #[cfg(feature = "outbound-vmess")]
    #[test]
    fn vmess_h2_multiple_uris_keep_single_use_http() {
        for tls in [false, true] {
            let mut config = vmess_h2_config(tls);
            let crate::config::VmessTransport::H2 { uris } = &mut config.transport else {
                panic!("memory VMess H2 transport")
            };
            uris.push(uris[0].replace("proxy.memory.invalid", "alternate.memory.invalid"));
            let node = VmessOutbound::new_with_path(&config, path()).unwrap();
            assert!(!node.permits_http_tcp_reuse(), "tls={tls}");
        }
    }

    #[cfg(feature = "outbound-vmess")]
    #[test]
    fn vmess_h2_inline_identity_qualifies_but_file_source_does_not() {
        let mut config = vmess_h2_config(true);
        let crate::config::SecurityConfig::Tls(tls) = &mut config.security else {
            panic!("memory VMess H2 TLS")
        };
        tls.identity = Some(identity());
        let inline = VmessOutbound::new_with_path(&config, path()).unwrap();
        assert!(inline.permits_http_tcp_reuse());
        let crate::config::SecurityConfig::Tls(tls) = &mut config.security else {
            unreachable!()
        };
        tls.identity = Some(marked_file_identity(tls.identity.take().unwrap()));
        let file = VmessOutbound::new_with_path(&config, path()).unwrap();
        assert!(!file.permits_http_tcp_reuse());
    }

    #[cfg(all(feature = "outbound-vmess", feature = "ech"))]
    #[test]
    fn vmess_h2_static_ech_qualifies_but_dynamic_ech_does_not() {
        let mut config = vmess_h2_config(true);
        let crate::config::SecurityConfig::Tls(tls) = &mut config.security else {
            panic!("memory VMess H2 TLS")
        };
        tls.tls13_only = true;
        tls.ech = Some(static_ech());
        let fixed = VmessOutbound::new_with_path(&config, path()).unwrap();
        assert!(fixed.permits_http_tcp_reuse());
        let crate::config::SecurityConfig::Tls(tls) = &mut config.security else {
            unreachable!()
        };
        tls.ech = Some(dynamic_ech());
        let dynamic = VmessOutbound::new_with_path(&config, path()).unwrap();
        assert!(!dynamic.permits_http_tcp_reuse());
    }

    #[cfg(feature = "outbound-vmess")]
    #[test]
    fn vmess_h2_keeps_upstream_and_dialer_restrictions() {
        let config = vmess_h2_config(false);
        let group = UpstreamPath::Group {
            server: crate::session::Destination::Ip("192.0.2.10:8443".parse().unwrap()),
            group: Arc::new(crate::outbound::SelectUpstream::new(
                Arc::new(crate::routing::GroupSelection::new(0)),
                vec![crate::outbound::SelectUpstreamMember::Direct],
            )),
            endpoint: None,
            dialer: Dialer::default(),
        };
        let egress = crate::config::EgressOptions {
            interface: Some("memory-interface".into()),
            ..Default::default()
        };
        for upstream in [
            group,
            UpstreamPath::proxy(Arc::new(OpaqueStreamDependency)),
            UpstreamPath::LazyDirect {
                dialer: Dialer::default().with_ip_version(crate::config::IpVersion::Ipv4),
            },
            UpstreamPath::LazyDirect {
                dialer: Dialer::default().with_source_ip("192.0.2.20".parse().unwrap()),
            },
            UpstreamPath::LazyDirect {
                dialer: Dialer::default().with_egress(&egress),
            },
        ] {
            let node = VmessOutbound::new_with_path(&config, upstream).unwrap();
            assert!(!node.permits_http_tcp_reuse());
        }
        let dialer = Dialer::default();
        let node = VmessOutbound::new_with_path(
            &config,
            UpstreamPath::LazyDirect {
                dialer: dialer.clone(),
            },
        )
        .unwrap();
        assert!(node.permits_http_tcp_reuse());
        dialer.begin_shutdown();
        assert!(!node.permits_http_tcp_reuse());
        let mut domain = config;
        domain.address = "proxy.memory.invalid".into();
        let node = VmessOutbound::new_with_path(&domain, path()).unwrap();
        assert!(!node.permits_http_tcp_reuse());
    }

    #[cfg(feature = "outbound-vmess")]
    #[test]
    fn vmess_tls_http_camouflage_remains_outside_the_proof_scope() {
        let mut config = crate::config::Config::parse_yaml(
            b"proxies: [{name: memory, type: vmess, server: 192.0.2.10, port: 8443, uuid: 00000000-0000-0000-0000-000000000007, cipher: aes-128-gcm, network: http, tls: true}]\nrules: ['MATCH,memory']\n",
        )
        .unwrap();
        let crate::config::ProxyProtocol::Vmess(config) = config.proxies.remove(0).protocol else {
            panic!("memory VMess HTTP camouflage configuration")
        };
        assert!(
            matches!(&config.security, crate::config::SecurityConfig::Tls(_)),
            "the HTTP camouflage negative control must normalize to real TLS"
        );
        let node = VmessOutbound::new_with_path(&config, path()).unwrap();
        assert!(!node.permits_http_tcp_reuse());
    }
}
