//! Mieru's Mihomo fields; credentials and protocol settings never enter Debug.
use super::{ProxyProtocol, deserialize_present_option, invalid, validate_host};
use crate::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MieruTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MieruMultiplexing {
    Off,
    Low,
    Middle,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MieruHandshake {
    Standard,
    NoWait,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MieruOutboundConfig {
    pub address: String,
    /// Inclusive physical carrier port range; a single port has equal ends.
    pub port: u16,
    pub port_end: u16,
    pub username: String,
    pub password: String,
    pub transport: MieruTransport,
    pub udp: bool,
    pub multiplexing: MieruMultiplexing,
    pub handshake_mode: MieruHandshake,
    pub traffic_pattern: Option<String>,
}

impl std::fmt::Debug for MieruOutboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MieruOutboundConfig")
            .field("transport", &self.transport)
            .field("udp", &self.udp)
            .field("multiplexing", &self.multiplexing)
            .field("handshake_mode", &self.handshake_mode)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawMieru {
    name: String,
    server: String,
    #[serde(default)]
    port: i64,
    #[serde(default)]
    port_range: String,
    transport: String,
    username: String,
    password: String,
    #[serde(default)]
    udp: bool,
    #[serde(default)]
    multiplexing: String,
    #[serde(default)]
    handshake_mode: String,
    #[serde(default)]
    traffic_pattern: String,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    dialer_proxy: Option<String>,
}

impl std::fmt::Debug for RawMieru {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("RawMieru").finish_non_exhaustive()
    }
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<RawMieru, D::Error> {
    RawMieru::deserialize(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid Mieru configuration fields"))
}

impl RawMieru {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-mieru") {
            return invalid("Mieru outbound support is disabled at build time");
        }
        validate_host(&self.server, "Mieru server")?;
        let (port, port_end) = match (self.port, self.port_range.is_empty()) {
            (0, true) => return invalid("Mieru requires port or port-range"),
            (0, false) => parse_port_range(&self.port_range)?,
            (port, true) if (1..=65_535).contains(&port) => (port as u16, port as u16),
            (_, true) => return invalid("invalid Mieru port"),
            (_, false) => return invalid("Mieru port and port-range are mutually exclusive"),
        };
        if self.username.is_empty()
            || self.password.is_empty()
            || self.username.len() > 64
            || self.password.len() > 64
        {
            return invalid("Mieru credentials require 1 to 64 UTF-8 bytes each");
        }
        let transport = match self.transport.as_str() {
            "TCP" => MieruTransport::Tcp,
            "UDP" => MieruTransport::Udp,
            _ => return invalid("Mieru transport must be TCP or UDP"),
        };
        let multiplexing = match self.multiplexing.as_str() {
            "" | "MULTIPLEXING_DEFAULT" | "MULTIPLEXING_LOW" => MieruMultiplexing::Low,
            "MULTIPLEXING_OFF" => MieruMultiplexing::Off,
            "MULTIPLEXING_MIDDLE" => MieruMultiplexing::Middle,
            "MULTIPLEXING_HIGH" => MieruMultiplexing::High,
            _ => return invalid("invalid Mieru multiplexing level"),
        };
        let handshake_mode = match self.handshake_mode.as_str() {
            "" | "HANDSHAKE_DEFAULT" | "HANDSHAKE_STANDARD" => MieruHandshake::Standard,
            "HANDSHAKE_NO_WAIT" => MieruHandshake::NoWait,
            _ => return invalid("invalid Mieru handshake mode"),
        };
        if !self.traffic_pattern.is_empty() {
            return invalid("Mieru traffic-pattern is not implemented");
        }
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::Mieru(MieruOutboundConfig {
                address: self.server,
                port,
                port_end,
                username: self.username,
                password: self.password,
                transport,
                udp: self.udp,
                multiplexing,
                handshake_mode,
                traffic_pattern: None,
            }),
        ))
    }
}

fn parse_port_range(value: &str) -> Result<(u16, u16)> {
    // The SDK's Store validates the whole range, after Mihomo's initial
    // Sscanf check. Preserve that effective consumer rather than its precheck.
    let parsed = value.split_once('-').and_then(|(start, end)| {
        if start.is_empty()
            || end.is_empty()
            || !start.bytes().all(|byte| byte.is_ascii_digit())
            || !end.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let start: u16 = start.parse().ok()?;
        let end: u16 = end.parse().ok()?;
        (start != 0 && start <= end).then_some((start, end))
    });
    match parsed {
        Some(ports) => Ok(ports),
        None => invalid("invalid Mieru port-range"),
    }
}

#[cfg(all(test, feature = "outbound-mieru"))]
mod tests {
    use super::*;
    use crate::config::Config;

    fn parse(transport: &str, fields: &str) -> MieruOutboundConfig {
        let yaml = format!(
            "proxies:\n  - name: edge\n    type: mieru\n    server: edge.invalid\n    username: ' user '\n    password: ' password '\n    transport: {transport}\n{fields}"
        );
        let config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let ProxyProtocol::Mieru(node) = &config.proxies[0].protocol else {
            panic!("expected Mieru")
        };
        node.clone()
    }

    #[test]
    fn defaults_preserve_credentials_and_tcp_carrier_udp_business() {
        let node = parse("TCP", "    port: 443\n    udp: true\n");
        assert_eq!((node.port, node.port_end), (443, 443));
        assert_eq!(node.transport, MieruTransport::Tcp);
        assert!(node.udp);
        assert_eq!(node.multiplexing, MieruMultiplexing::Low);
        assert_eq!(node.handshake_mode, MieruHandshake::Standard);
        assert_eq!(node.username, " user ");
        assert_eq!(node.password, " password ");
        let debug = format!("{node:?}");
        assert!(!debug.contains("password") && !debug.contains(" user "));
    }

    #[test]
    fn range_equal_endpoints_and_explicit_default_enums_are_valid() {
        let node = parse(
            "TCP",
            "    port-range: 443-443\n    multiplexing: MULTIPLEXING_DEFAULT\n    handshake-mode: HANDSHAKE_DEFAULT\n",
        );
        assert_eq!((node.port, node.port_end), (443, 443));
        assert_eq!(node.multiplexing, MieruMultiplexing::Low);
        assert_eq!(node.handshake_mode, MieruHandshake::Standard);
    }

    #[test]
    fn port_range_and_no_wait_keep_their_effective_settings() {
        let node = parse(
            "TCP",
            "    port: 0\n    port-range: 4000-4002\n    multiplexing: MULTIPLEXING_OFF\n    handshake-mode: HANDSHAKE_NO_WAIT\n",
        );
        assert_eq!((node.port, node.port_end), (4000, 4002));
        assert_eq!(node.multiplexing, MieruMultiplexing::Off);
        assert_eq!(node.handshake_mode, MieruHandshake::NoWait);
    }

    #[test]
    fn udp_carrier_does_not_enable_udp_business_by_itself() {
        let node = parse("UDP", "    port-range: 4000-4002\n");
        assert_eq!(node.transport, MieruTransport::Udp);
        assert!(!node.udp);
        assert_eq!((node.port, node.port_end), (4000, 4002));
    }
}
