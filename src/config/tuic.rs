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
    pub ip: Option<String>,
    pub heartbeat_interval: std::time::Duration,
    pub stream_window: super::QuicReceiveWindow,
    pub connection_window: super::QuicReceiveWindow,
    pub max_open_streams: usize,
    pub max_udp_relay_packet_size: u16,
    pub max_datagram_frame_size: u16,
    pub disable_mtu_discovery: bool,
    pub udp_over_stream: bool,
    pub disable_sni: bool,
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
    // Accepted for compatibility; Mihomo always advertises UDP for this protocol.
    #[serde(rename = "udp", default)]
    _udp: bool,
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
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    ip: Option<String>,
    #[serde(default)]
    heartbeat_interval: i64,
    #[serde(default)]
    recv_window_conn: u64,
    #[serde(default)]
    recv_window: u64,
    #[serde(default)]
    max_open_streams: i64,
    #[serde(default)]
    max_udp_relay_packet_size: i64,
    #[serde(default)]
    max_datagram_frame_size: i64,
    #[serde(default)]
    disable_mtu_discovery: bool,
    #[serde(default)]
    disable_sni: bool,
    #[serde(default)]
    udp_over_stream: bool,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    udp_over_stream_version: Option<u8>,
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
        let open_streams = if self.max_open_streams == 0 {
            100
        } else {
            self.max_open_streams
        };
        let client_threshold = if open_streams == 100 {
            90
        } else {
            open_streams.max(1)
        };
        let max_open_streams = client_threshold.saturating_sub(1) as usize;
        // The fixed reference computes TUIC v5's overhead with an IPv6 address (29 bytes).
        let relay = if self.max_udp_relay_packet_size == 0 {
            1252
        } else {
            self.max_udp_relay_packet_size
        };
        let frame = if self.max_datagram_frame_size == 0 {
            relay.checked_add(29).ok_or_else(|| {
                crate::VoleError::InvalidConfig("TUIC datagram limit overflows".into())
            })?
        } else {
            self.max_datagram_frame_size
        }
        .min(1400);
        if frame < 0 {
            return invalid("TUIC DATAGRAM frame limit cannot be negative");
        }
        if self
            .udp_over_stream_version
            .is_some_and(|version| version != 2)
        {
            return invalid("TUIC UDP-over-stream only supports version 2");
        }
        let config = TuicOutboundConfig {
            address: self.server.clone(),
            port: self.port,
            uuid,
            password: self.password,
            congestion: self.congestion_controller,
            udp_mode: self.udp_relay_mode,
            ip: self.ip.filter(|value| !value.is_empty()),
            heartbeat_interval: std::time::Duration::from_millis(if self.heartbeat_interval <= 0 {
                10000
            } else {
                self.heartbeat_interval as u64
            }),
            stream_window: super::QuicReceiveWindow::normalize(
                self.recv_window_conn,
                self.recv_window_conn,
                super::QuicReceiveWindow {
                    initial: 15 * 1024 * 1024 / 10,
                    maximum: 15 * 1024 * 1024,
                },
            )?,
            connection_window: super::QuicReceiveWindow::normalize(
                self.recv_window,
                self.recv_window,
                super::QuicReceiveWindow {
                    initial: 2 * 1024 * 1024,
                    maximum: 64 * 1024 * 1024,
                },
            )?,
            max_open_streams,
            max_udp_relay_packet_size: frame.saturating_sub(29).max(0) as u16,
            max_datagram_frame_size: frame as u16,
            disable_mtu_discovery: self.disable_mtu_discovery,
            disable_sni: self.disable_sni,
            udp_over_stream: self.udp_over_stream,
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
            true,
            ProxyProtocol::Tuic(config),
        ))
    }
}

impl TuicOutboundConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_host(&self.address, "TUIC server")?;
        validate_port(self.port, "TUIC")?;
        if let Some(ip) = &self.ip {
            validate_host(ip, "TUIC ip")?;
        }
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
