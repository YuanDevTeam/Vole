use serde::Deserialize;

use super::{
    ProxyProtocol, TlsCertificatePolicy, TlsConfig, TlsIdentityPem, deserialize_present_option,
    invalid, normalize_verification_name, validate_host, validate_port,
};
use crate::Result;

#[derive(Clone, PartialEq, Eq)]
pub struct Hysteria2OutboundConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub tls: TlsConfig,
    pub up: u64,
    pub down: u64,
    pub udp_mtu: u16,
    pub obfs_password: Option<String>,
    pub hopping: Option<Hysteria2Hopping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2Hopping {
    pub ports: Vec<u16>,
    pub min_seconds: u32,
    pub max_seconds: u32,
}

impl std::fmt::Debug for Hysteria2OutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2OutboundConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHysteria2 {
    name: String,
    server: String,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    port: Option<u16>,
    #[serde(default)]
    password: String,
    #[serde(default)]
    udp: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sni: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(
        rename = "name-cert-verify",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    name_cert_verify: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(
        rename = "certificate",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    certificate: Option<String>,
    #[serde(
        rename = "private-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    private_key: Option<String>,
    #[serde(
        rename = "dialer-proxy",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    dialer_proxy: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    up: Option<NumberOrText>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    down: Option<NumberOrText>,
    #[serde(rename = "udp-mtu", default)]
    udp_mtu: u16,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    obfs: Option<String>,
    #[serde(
        rename = "obfs-password",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    obfs_password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    ports: Option<String>,
    #[serde(
        rename = "hop-interval",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    hop_interval: Option<NumberOrText>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NumberOrText {
    Number(u64),
    Text(String),
}

impl std::fmt::Debug for RawHysteria2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawHysteria2").finish_non_exhaustive()
    }
}

impl RawHysteria2 {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-hysteria2") {
            return invalid("Hysteria2 outbound support is disabled at build time");
        }
        validate_host(&self.server, "Hysteria2 server")?;
        if let Some(port) = self.port {
            validate_port(port, "Hysteria2")?;
        }
        let hopping = self
            .ports
            .map(|ports| {
                let ports = parse_ports(&ports)?;
                let (min_seconds, max_seconds) = parse_interval(self.hop_interval.as_ref())?;
                Ok::<_, crate::VoleError>(Hysteria2Hopping {
                    ports,
                    min_seconds,
                    max_seconds,
                })
            })
            .transpose()?;
        if hopping.is_none() && self.hop_interval.is_some() {
            return invalid("Hysteria2 hop-interval requires ports");
        }
        let port = match &hopping {
            Some(hopping) => hopping.ports[0],
            None => self.port.ok_or_else(|| {
                crate::VoleError::InvalidConfig("Hysteria2 requires port or ports".into())
            })?,
        };
        // The complete auth header section is bounded to 16 KiB. Validate the
        // raw value, without trimming credentials or printing them on failure.
        if self.password.len() > 8192
            || http::HeaderValue::from_bytes(self.password.as_bytes()).is_err()
        {
            return invalid("invalid or over-limit Hysteria2 authentication header");
        }
        let obfs_password = match (self.obfs.as_deref(), self.obfs_password) {
            (None, None) => None,
            (Some("salamander"), Some(password)) if !password.is_empty() => Some(password),
            _ => return invalid("Hysteria2 Salamander requires obfs and a nonempty obfs-password"),
        };
        let server_name = self.sni.unwrap_or_else(|| self.server.clone());
        validate_host(&server_name, "Hysteria2 sni")?;
        let mut alpn = self.alpn.unwrap_or_default();
        if alpn.is_empty() {
            alpn.push("h3".into());
        }
        if alpn.iter().any(|item| item.is_empty() || item.len() > 255)
            || alpn.iter().map(|item| item.len() + 1).sum::<usize>() > 65533
        {
            return invalid("invalid Hysteria2 ALPN list");
        }
        let identity = match (self.certificate, self.private_key) {
            (None, None) => None,
            (Some(certificate), Some(private_key)) => {
                #[cfg(feature = "outbound-hysteria2")]
                crate::security::TlsClientIdentity::from_pem(&certificate, &private_key).map_err(
                    |_| crate::VoleError::InvalidConfig("invalid Hysteria2 client identity".into()),
                )?;
                Some(TlsIdentityPem {
                    certificate,
                    private_key,
                })
            }
            _ => return invalid("Hysteria2 certificate and private-key must be paired"),
        };
        let fingerprint = self
            .fingerprint
            .map(|pin| {
                super::vless::parse_pin(&pin).map_err(|_| {
                    crate::VoleError::InvalidConfig(
                        "invalid Hysteria2 certificate fingerprint".into(),
                    )
                })
            })
            .transpose()?;
        let udp_mtu = if self.udp_mtu == 0 {
            1197
        } else {
            self.udp_mtu
        };
        if udp_mtu < 64 {
            return invalid("Hysteria2 udp-mtu must be 0 or 64..65535");
        }
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::Hysteria2(Hysteria2OutboundConfig {
                address: self.server,
                port,
                password: self.password,
                tls: TlsConfig {
                    ech: None,
                    client_fingerprint: None,
                    server_name,
                    alpn: alpn.into_iter().map(String::into_bytes).collect(),
                    tls13_only: true,
                    required_alpn: None,
                    certificate: TlsCertificatePolicy {
                        skip_cert_verify: self.skip_cert_verify,
                        fingerprint,
                        verification_name: normalize_verification_name(self.name_cert_verify)?,
                    },
                    identity,
                },
                up: parse_rate(self.up)?,
                down: parse_rate(self.down)?,
                udp_mtu,
                obfs_password,
                hopping,
            }),
        ))
    }
}

fn parse_rate(raw: Option<NumberOrText>) -> Result<u64> {
    let text = match raw {
        None => return Ok(0),
        Some(NumberOrText::Number(value)) => format!("{value}"),
        Some(NumberOrText::Text(value)) => value.trim().to_owned(),
    };
    let end = text.bytes().take_while(u8::is_ascii_digit).count();
    let value = text[..end]
        .parse::<u64>()
        .map_err(|_| crate::VoleError::InvalidConfig("invalid Hysteria2 bandwidth".into()))?;
    let unit = text[end..].trim();
    let (factor, divisor) = match unit {
        "" | "Mbps" => (1_000_000_u64, 8),
        "bps" => (1, 8),
        "Kbps" => (1000, 8),
        "Gbps" => (1_000_000_000, 8),
        "Tbps" => (1_000_000_000_000, 8),
        "Bps" => (1, 1),
        "KBps" => (1000, 1),
        "MBps" => (1_000_000, 1),
        "GBps" => (1_000_000_000, 1),
        "TBps" => (1_000_000_000_000, 1),
        _ => return invalid("invalid Hysteria2 bandwidth unit"),
    };
    value
        .checked_mul(factor)
        .map(|bytes| bytes / divisor)
        .ok_or_else(|| crate::VoleError::InvalidConfig("Hysteria2 bandwidth overflows".into()))
}

fn decimal(value: &str) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return invalid("invalid Hysteria2 integer range");
    }
    value
        .parse()
        .map_err(|_| crate::VoleError::InvalidConfig("Hysteria2 integer range overflows".into()))
}

fn parse_ports(value: &str) -> Result<Vec<u16>> {
    let mut ports = std::collections::BTreeSet::new();
    for item in value.split(',') {
        let item = item.trim();
        let (start, end) = item.split_once('-').unwrap_or((item, item));
        let (start, end) = (decimal(start)?, decimal(end)?);
        if start == 0 || start > end || end > 65535 {
            return invalid("invalid Hysteria2 ports");
        }
        ports.extend((start..=end).map(|port| port as u16));
    }
    Ok(ports.into_iter().collect())
}

fn parse_interval(value: Option<&NumberOrText>) -> Result<(u32, u32)> {
    let text = match value {
        None => return Ok((30, 30)),
        Some(NumberOrText::Number(value)) => value.to_string(),
        Some(NumberOrText::Text(value)) => value.clone(),
    };
    let (start, end) = text.split_once('-').unwrap_or((&text, &text));
    let (start, end) = (decimal(start)?, decimal(end)?);
    if start < 5 || start > end {
        return invalid("Hysteria2 hop-interval requires 5 <= min <= max <= 4294967295 seconds");
    }
    Ok((start, end))
}
