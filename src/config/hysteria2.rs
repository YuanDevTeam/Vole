use serde::Deserialize;

use super::{
    ProxyProtocol, TlsCertificatePolicy, TlsConfig, deserialize_present_option, invalid,
    normalize_certificate_fingerprint, normalize_client_identity, normalize_verification_name,
    validate_host, validate_port,
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
    pub gecko: Option<Hysteria2Gecko>,
    pub realm: Option<super::Hysteria2Realm>,
    pub hopping: Option<Hysteria2Hopping>,
    pub stream_window: super::QuicReceiveWindow,
    pub connection_window: super::QuicReceiveWindow,
    pub handshake_timeout: std::time::Duration,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Hysteria2Gecko {
    pub password: String,
    pub min_packet_size: u16,
    pub max_packet_size: u16,
}
impl std::fmt::Debug for Hysteria2Gecko {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Gecko")
            .field("min_packet_size", &self.min_packet_size)
            .field("max_packet_size", &self.max_packet_size)
            .finish_non_exhaustive()
    }
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
        rename = "ech-opts",
        default,
        deserialize_with = "super::ech::deserialize"
    )]
    ech_opts: Option<super::ech::RawEch>,
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
    #[serde(rename = "obfs-min-packet-size", default)]
    obfs_min_packet_size: i64,
    #[serde(rename = "obfs-max-packet-size", default)]
    obfs_max_packet_size: i64,
    #[serde(
        rename = "realm-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    realm: Option<super::hysteria2_realm::RawRealm>,
    #[serde(rename = "initial-stream-receive-window", default)]
    initial_stream_receive_window: u64,
    #[serde(rename = "max-stream-receive-window", default)]
    max_stream_receive_window: u64,
    #[serde(rename = "initial-connection-receive-window", default)]
    initial_connection_receive_window: u64,
    #[serde(rename = "max-connection-receive-window", default)]
    max_connection_receive_window: u64,
    #[serde(rename = "handshake-timeout", default)]
    handshake_timeout: i64,
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
            .filter(|ports| !ports.is_empty())
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
        let realm = self.realm.map(|raw| raw.normalize()).transpose()?.flatten();
        if realm.is_some() && hopping.is_some() {
            return invalid("Hysteria2 Realm and ports are mutually exclusive");
        }
        let (obfs_password, gecko) = match (
            self.obfs.as_deref().filter(|value| !value.is_empty()),
            self.obfs_password,
        ) {
            (None, None) if self.obfs_min_packet_size == 0 && self.obfs_max_packet_size == 0 => {
                (None, None)
            }
            (Some("salamander"), Some(password))
                if !password.is_empty()
                    && self.obfs_min_packet_size == 0
                    && self.obfs_max_packet_size == 0 =>
            {
                (Some(password), None)
            }
            (Some("gecko"), Some(password)) if !password.is_empty() => {
                let min = if self.obfs_min_packet_size == 0 {
                    512
                } else {
                    self.obfs_min_packet_size
                };
                let max = if self.obfs_max_packet_size == 0 {
                    1200
                } else {
                    self.obfs_max_packet_size
                };
                if min <= 0 || min > max || max > 2048 {
                    return invalid("invalid Hysteria2 Gecko packet size range");
                }
                (
                    None,
                    Some(Hysteria2Gecko {
                        password,
                        min_packet_size: min as u16,
                        max_packet_size: max as u16,
                    }),
                )
            }
            _ => return invalid("invalid Hysteria2 obfuscation options"),
        };
        let server_name = self
            .sni
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| self.server.clone());
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
        let ech = self
            .ech_opts
            .map(|raw| raw.normalize(false))
            .transpose()?
            .flatten();
        if ech.is_some() && server_name.parse::<std::net::IpAddr>().is_ok() {
            return invalid("Hysteria2 ECH requires DNS sni");
        }
        let identity = normalize_client_identity(self.certificate, self.private_key)?;
        let fingerprint = normalize_certificate_fingerprint(self.fingerprint.as_deref())?;
        let udp_mtu = if self.udp_mtu == 0 {
            crate::limits::HY2_QUIC_PAYLOAD as u16
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
                    ech,
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
                gecko,
                realm,
                hopping,
                stream_window: super::QuicReceiveWindow::normalize(
                    self.initial_stream_receive_window,
                    self.max_stream_receive_window,
                    super::QuicReceiveWindow {
                        initial: 64 * 1024,
                        maximum: 64 * 1024,
                    },
                )?,
                connection_window: super::QuicReceiveWindow::normalize(
                    self.initial_connection_receive_window,
                    self.max_connection_receive_window,
                    super::QuicReceiveWindow {
                        initial: 4 * 1024 * 1024,
                        maximum: 4 * 1024 * 1024,
                    },
                )?,
                handshake_timeout: std::time::Duration::from_secs(
                    self.handshake_timeout.max(0) as u64
                ),
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

#[cfg(all(test, feature = "outbound-hysteria2"))]
mod p08_tests {
    use super::*;
    fn parse(extra: serde_json::Value) -> Result<Hysteria2OutboundConfig> {
        let mut raw = serde_json::json!({"name":"edge","server":"peer.invalid","port":443});
        raw.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let raw: RawHysteria2 = serde_json::from_value(raw).unwrap();
        let (_, _, _, ProxyProtocol::Hysteria2(config)) = raw.normalize()? else {
            panic!("HY2")
        };
        Ok(config)
    }
    #[test]
    fn gecko_options_consume_actual_min_max_and_realm_excludes_hopping() {
        let gecko=parse(serde_json::json!({"obfs":"gecko","obfs-password":"private","obfs-min-packet-size":600,"obfs-max-packet-size":1400})).unwrap().gecko.unwrap();
        assert_eq!((gecko.min_packet_size, gecko.max_packet_size), (600, 1400));
        assert!(!format!("{gecko:?}").contains("private"));
        for fields in [
            serde_json::json!({"obfs":"gecko","obfs-password":"private","obfs-min-packet-size":1401,"obfs-max-packet-size":1400}),
            serde_json::json!({"obfs":"salamander","obfs-password":"private","obfs-max-packet-size":1200}),
            serde_json::json!({"ports":"443,8443","realm-opts":{"enable":true,"server-url":"https://control.example","realm-id":"zone","stun-servers":["192.0.2.1"]}}),
        ] {
            assert!(parse(fields).is_err());
        }
    }
}
