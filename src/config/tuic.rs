use serde::Deserialize;
use uuid::Uuid;

use super::{
    ProxyProtocol, TlsCertificatePolicy, TlsConfig, invalid, validate_host, validate_port,
};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuicCongestion {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TuicUdpMode {
    #[default]
    Native,
    Quic,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TuicOutboundConfig {
    pub address: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub tls: TlsConfig,
    pub congestion: TuicCongestion,
    pub udp_mode: TuicUdpMode,
}

impl std::fmt::Debug for TuicOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicOutboundConfig")
            .field("congestion", &self.congestion)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawTuic {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    udp: bool,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    dialer_proxy: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    sni: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    name_cert_verify: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    certificate: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    private_key: Option<String>,
    #[serde(default)]
    congestion_controller: TuicCongestion,
    #[serde(default)]
    udp_relay_mode: TuicUdpMode,
}

impl std::fmt::Debug for RawTuic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTuic").finish_non_exhaustive()
    }
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<RawTuic, D::Error> {
    RawTuic::deserialize(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid TUIC configuration fields"))
}

impl RawTuic {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-tuic") {
            return invalid("TUIC outbound support is disabled at build time");
        }
        let uuid = super::parse_standard_uuid(&self.uuid).map_err(|_| {
            crate::VoleError::InvalidConfig("TUIC requires a standard hyphenated UUID".into())
        })?;
        let config = TuicOutboundConfig {
            address: self.server.clone(),
            port: self.port,
            uuid,
            password: self.password,
            congestion: self.congestion_controller,
            udp_mode: self.udp_relay_mode,
            tls: TlsConfig {
                server_name: self
                    .sni
                    .filter(|name| !name.is_empty())
                    .unwrap_or(self.server),
                alpn: self
                    .alpn
                    .unwrap_or_else(|| vec!["h3".into()])
                    .into_iter()
                    .map(String::into_bytes)
                    .collect(),
                tls13_only: true,
                required_alpn: None,
                identity: super::normalize_client_identity(self.certificate, self.private_key)?,
                ech: None,
                client_fingerprint: None,
                certificate: TlsCertificatePolicy {
                    skip_cert_verify: self.skip_cert_verify,
                    verification_name: super::normalize_verification_name(self.name_cert_verify)?,
                    fingerprint: super::normalize_certificate_fingerprint(
                        self.fingerprint.as_deref(),
                    )?,
                },
            },
        };
        config.validate()?;
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::Tuic(config),
        ))
    }
}

impl TuicOutboundConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_host(&self.address, "TUIC server")?;
        validate_port(self.port, "TUIC")?;
        validate_host(&self.tls.server_name, "TUIC sni")?;
        if let Some(name) = &self.tls.certificate.verification_name {
            validate_host(name, "TUIC verification name")?;
        }
        if self.password.len() > 65_535 {
            return invalid("TUIC password exceeds 65535 UTF-8 bytes");
        }
        if self.tls.alpn.is_empty()
            || self.tls.alpn.iter().any(|p| p.is_empty() || p.len() > 255)
            || self.tls.alpn.iter().map(|p| p.len() + 1).sum::<usize>() > 65_533
        {
            return invalid("invalid TUIC ALPN list");
        }
        if !self.tls.tls13_only
            || self.tls.ech.is_some()
            || self.tls.client_fingerprint.is_some()
            || self.tls.required_alpn.is_some()
        {
            return invalid("TUIC requires standard QUIC TLS 1.3");
        }
        if let Some(identity) = &self.tls.identity {
            crate::security::TlsClientIdentity::from_pem(
                &identity.certificate,
                &identity.private_key,
            )
            .map_err(|_| {
                crate::VoleError::InvalidConfig("invalid TUIC TLS client identity".into())
            })?;
        }
        Ok(())
    }
}
