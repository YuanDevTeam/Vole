use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

use super::{invalid, validate_host, validate_port};
use crate::Result;
use serde::Deserialize;

/// Fixed strict-v3 cover policy, independent of the SS payload credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct ShadowTlsConfig {
    pub server_name: String,
    pub password: String,
    pub alpn: Vec<Vec<u8>>,
    pub required_alpn: Option<Vec<u8>>,
    pub identity: Option<super::TlsIdentityPem>,
    pub certificate: super::TlsCertificatePolicy,
    pub client_fingerprint: Option<super::ClientFingerprint>,
}

impl std::fmt::Debug for ShadowTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowTlsConfig")
            .field("client_fingerprint", &self.client_fingerprint)
            .field("certificate", &self.certificate)
            .finish_non_exhaustive()
    }
}

impl ShadowTlsConfig {
    pub(super) fn tls_config(&self) -> super::TlsConfig {
        super::TlsConfig {
            server_name: self.server_name.clone(),
            client_fingerprint: self.client_fingerprint,
            alpn: self.alpn.clone(),
            required_alpn: self.required_alpn.clone(),
            tls13_only: true,
            ech: None,
            certificate: self.certificate.clone(),
            identity: self.identity.clone(),
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        super::validate_tls13_fingerprint(self.client_fingerprint)?;
        if !cfg!(feature = "shadow-tls-v3") {
            return invalid("ShadowTLS v3 is not compiled in");
        }
        validate_host(&self.server_name, "ShadowTLS host")?;
        if let Some(name) = &self.certificate.verification_name {
            validate_host(name, "ShadowTLS verification name")?;
        }
        if !(1..=65_535).contains(&self.password.len()) {
            return invalid("ShadowTLS password must contain 1..65535 UTF-8 bytes");
        }
        if self
            .alpn
            .iter()
            .any(|value| !(1..=255).contains(&value.len()))
            || self.alpn.iter().map(|value| value.len() + 1).sum::<usize>() > 65_533
        {
            return invalid("invalid ShadowTLS ALPN list");
        }
        if self
            .required_alpn
            .as_ref()
            .is_some_and(|required| !self.alpn.contains(required))
        {
            return invalid("ShadowTLS ALPN does not include the selected transport");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawShadowTls {
    version: u8,
    host: String,
    password: String,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    certificate: Option<String>,
    #[serde(
        rename = "private-key",
        default,
        deserialize_with = "super::deserialize_present_option"
    )]
    private_key: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    name_cert_verify: Option<String>,
}

impl std::fmt::Debug for RawShadowTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawShadowTls").finish_non_exhaustive()
    }
}

pub(super) fn plugin(
    name: Option<String>,
    options: Option<RawShadowTls>,
    fingerprint: Option<String>,
) -> Result<Option<ShadowTlsConfig>> {
    let (name, raw) = match (name.filter(|name| !name.is_empty()), options) {
        (None, None) if fingerprint.is_none() => return Ok(None),
        (Some(name), Some(raw)) => (name, raw),
        _ => return invalid("ShadowTLS plugin and plugin-opts must be provided together"),
    };
    if name != "shadow-tls" || raw.version != 3 {
        return invalid("only explicit ShadowTLS v3 is supported");
    }
    let config = ShadowTlsConfig {
        server_name: raw.host,
        password: raw.password,
        identity: super::normalize_client_identity(raw.certificate, raw.private_key)?,
        required_alpn: None,
        alpn: raw
            .alpn
            .unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()])
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        certificate: super::TlsCertificatePolicy {
            verification_name: super::normalize_verification_name(raw.name_cert_verify)?,
            skip_cert_verify: raw.skip_cert_verify,
            fingerprint: super::normalize_certificate_fingerprint(raw.fingerprint.as_deref())
                .map_err(|_| {
                    crate::VoleError::InvalidConfig("invalid ShadowTLS certificate pin".into())
                })?,
        },
        client_fingerprint: super::parse_client_fingerprint(fingerprint.as_deref())?,
    };
    config.validate()?;
    Ok(Some(config))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl ShadowsocksCipher {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    pub const fn key_len(self) -> usize {
        if matches!(self, Self::Aes128Gcm) {
            16
        } else {
            32
        }
    }

    pub const fn supports_eih(self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::Aes256Gcm)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ShadowsocksOutboundConfig {
    pub address: String,
    pub port: u16,
    pub cipher: ShadowsocksCipher,
    pub password: String,
    pub plugin: Option<super::ShadowsocksPlugin>,
    pub udp_over_tcp: bool,
}

impl std::fmt::Debug for ShadowsocksOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksOutboundConfig")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl ShadowsocksOutboundConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_host(&self.address, "Shadowsocks server")?;
        validate_port(self.port, "Shadowsocks")?;
        if let Some(plugin) = &self.plugin {
            plugin.validate()?;
        }
        if !self.cipher.supports_eih() && self.password.contains(':') {
            return invalid("Shadowsocks identity chains require an AES 2022 cipher");
        }
        const ENGINE: GeneralPurpose = GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
        for key in self.password.split(':') {
            if key.is_empty() || key.len() > 44 {
                return invalid("Shadowsocks password contains an invalid PSK");
            }
            if !matches!(ENGINE.decode(key), Ok(decoded) if decoded.len() == self.cipher.key_len())
            {
                return invalid(
                    "Shadowsocks PSK must be valid Base64 with the cipher's key length",
                );
            }
        }
        Ok(())
    }
}

pub(super) fn normalize(
    address: String,
    port: u16,
    cipher: String,
    password: String,
) -> Result<ShadowsocksOutboundConfig> {
    let cipher = match cipher.as_str() {
        "2022-blake3-aes-128-gcm" => ShadowsocksCipher::Aes128Gcm,
        "2022-blake3-aes-256-gcm" => ShadowsocksCipher::Aes256Gcm,
        "2022-blake3-chacha20-poly1305" => ShadowsocksCipher::Chacha20Poly1305,
        _ => return invalid("Shadowsocks cipher must be one of the three supported 2022 methods"),
    };
    let config = ShadowsocksOutboundConfig {
        address,
        port,
        cipher,
        password,
        plugin: None,
        udp_over_tcp: false,
    };
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ProxyProtocol};
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn ss_schema_validates_three_methods_and_preserves_eih_order() {
        for cipher in [
            ShadowsocksCipher::Aes128Gcm,
            ShadowsocksCipher::Aes256Gcm,
            ShadowsocksCipher::Chacha20Poly1305,
        ] {
            let key = STANDARD.encode(vec![7; cipher.key_len()]);
            for password in [key.clone(), key.trim_end_matches('=').to_owned()] {
                let yaml = format!(
                    "mixed-port: 1080\nproxies: [{{name: ss, type: ss, server: fixture.invalid, port: 443, cipher: {}, password: '{password}', udp: true}}]\nrules: ['MATCH,ss']",
                    cipher.as_str()
                );
                let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
                let ProxyProtocol::Shadowsocks(ss) = &config.proxies[0].protocol else {
                    panic!("wrong protocol")
                };
                assert_eq!(ss.password, password);
                assert!(!format!("{ss:?}").contains(&password));
                assert!(!format!("{ss:?}").contains("fixture.invalid"));
                for field in [
                    "plugin: obfs",
                    "tls: true",
                    "sni: fixture.invalid",
                    "username: secret",
                    "alpn: [h2]",
                ] {
                    let invalid = yaml.replace("udp: true", &format!("udp: true, {field}"));
                    assert!(Config::parse_yaml(invalid.as_bytes()).is_err());
                }
            }
            let chain = format!("{}:{key}", STANDARD.encode(vec![9; cipher.key_len()]));
            let result = normalize(
                "fixture.invalid".into(),
                443,
                cipher.as_str().into(),
                chain.clone(),
            );
            assert_eq!(result.is_ok(), cipher.supports_eih());
            if let Ok(config) = result {
                assert_eq!(config.password, chain);
            }
            for bad in [
                String::new(),
                ":".into(),
                format!("{key}:"),
                format!(" {key}"),
                STANDARD.encode([1; 17]),
                "PRIVATE-BAD-KEY".into(),
            ] {
                let error = normalize(
                    "fixture.invalid".into(),
                    443,
                    cipher.as_str().into(),
                    bad.clone(),
                )
                .unwrap_err();
                assert!(!error.to_string().contains("PRIVATE-BAD-KEY"));
            }
        }
        for cipher in [
            "aes-128-gcm",
            "none",
            "2022-blake3-chacha12-poly1305",
            "2022-blake3-chacha8-poly1305",
            "2022-blake3-chacha20-ietf-poly1305",
        ] {
            assert!(
                normalize(
                    "fixture.invalid".into(),
                    443,
                    cipher.into(),
                    STANDARD.encode([7; 32])
                )
                .is_err()
            );
        }
    }

    #[test]
    fn ss_chacha8_is_rejected_by_runtime_and_measurement_config() {
        let node = format!(
            "{{name: ss, type: ss, server: fixture.invalid, port: 443, cipher: 2022-blake3-chacha8-poly1305, password: '{}' }}",
            STANDARD.encode([7; 32])
        );
        let runtime = format!("mixed-port: 1080\nproxies: [{node}]\nrules: ['MATCH,ss']");
        assert!(Config::parse_yaml(runtime.as_bytes()).is_err());
        #[cfg(feature = "invoke")]
        assert!(
            crate::config::MeasureConfig::parse_yaml(format!("proxies: [{node}]").as_bytes())
                .is_err()
        );
    }
}
