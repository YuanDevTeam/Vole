use std::{fmt, net::SocketAddr, sync::Arc};

use bytes::Bytes;

const DEFAULT_TUN_MTU: usize = 1_500;
const IPV6_UDP_OVERHEAD: usize = 48;
const TUN_XUDP_MAX_RESPONSE_PAYLOAD_SIZE: u16 = (DEFAULT_TUN_MTU - IPV6_UDP_OVERHEAD) as u16;
const INTERNAL_DNS_XUDP_MAX_RESPONSE_PAYLOAD_SIZE: u16 = 4_096;
const XUDP_MAX_RESPONSE_PAYLOAD_SIZE: u16 = u16::MAX;
// IPv4's UDP wire ceiling is the conservative cross-family limit. Reserve
// the largest SOCKS5 response header even when a particular reply is shorter.
pub(crate) const SOCKS5_UDP_PACKET_LIMIT: usize = 65_507;
const SOCKS5_UDP_PAYLOAD_LIMIT: u16 = (SOCKS5_UDP_PACKET_LIMIT - 262) as u16;

/// A remote endpoint without forcing an inbound to resolve domain names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Destination {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl Destination {
    pub fn domain(host: impl Into<String>, port: u16) -> std::io::Result<Self> {
        let host = host.into();
        if host.is_empty()
            || host.len() > 255
            || port == 0
            || host.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid domain destination",
            ));
        }
        Ok(Self::Domain { host, port })
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    #[must_use]
    pub fn authority(&self) -> String {
        match self {
            Self::Ip(address) => address.to_string(),
            Self::Domain { host, port } => format!("{host}:{port}"),
        }
    }

    /// Parses HTTP authority-form. A port is mandatory.
    pub fn from_authority(authority: &str) -> std::io::Result<Self> {
        if authority.is_empty() || authority.len() > 512 || authority.contains(['/', '@', '#', '?'])
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid authority",
            ));
        }

        if let Ok(address) = authority.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "destination port is zero",
                ));
            }
            return Ok(Self::Ip(address));
        }

        let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "authority has no port")
        })?;
        if host.contains(':') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IPv6 literals must use brackets",
            ));
        }
        let port = port.parse::<u16>().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid authority port")
        })?;
        Self::domain(host, port)
    }
}

impl From<SocketAddr> for Destination {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.authority())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundKind {
    Tun,
    Http,
    Socks5,
    /// Core-originated DNS traffic sent through the raw proxy dispatcher.
    /// This context must never be passed back through the routing dispatcher.
    InternalDns,
    /// Core-owned GeoData HTTPS traffic routed by the current mode and rules.
    InternalGeoData,
    /// Core-owned latency probe sent through a node-only default proxy graph.
    /// This context never enters the public inbound or routing pipeline.
    InternalMeasure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSession {
    pub inbound: InboundKind,
    pub source: SocketAddr,
    pub destination: Destination,
    /// Canonical domain extracted from intercepted client payload.
    ///
    /// This is routing-only metadata. Outbounds must continue to use
    /// `destination`, which preserves the original TUN IP target.
    pub sniffed_domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramSession {
    pub inbound: InboundKind,
    pub source: SocketAddr,
    max_response_payload_size: u16,
}

impl DatagramSession {
    /// Builds a UDP association with an inbound-specific XUDP response limit.
    ///
    /// The generic TUN default uses the conservative IPv6 UDP payload budget
    /// for a 1500-byte MTU. TUN runtimes with a lower effective MTU use
    /// [`Self::for_tun`]. Internal DNS is capped at the DNS wire-message ceiling,
    /// while SOCKS5 reserves its maximum header within the real UDP wire limit.
    #[must_use]
    pub const fn new(inbound: InboundKind, source: SocketAddr) -> Self {
        let max_response_payload_size = match inbound {
            InboundKind::Tun => TUN_XUDP_MAX_RESPONSE_PAYLOAD_SIZE,
            InboundKind::InternalDns => INTERNAL_DNS_XUDP_MAX_RESPONSE_PAYLOAD_SIZE,
            InboundKind::InternalGeoData => XUDP_MAX_RESPONSE_PAYLOAD_SIZE,
            InboundKind::InternalMeasure => XUDP_MAX_RESPONSE_PAYLOAD_SIZE,
            InboundKind::Http => XUDP_MAX_RESPONSE_PAYLOAD_SIZE,
            InboundKind::Socks5 => SOCKS5_UDP_PAYLOAD_LIMIT,
        };
        Self {
            inbound,
            source,
            max_response_payload_size,
        }
    }

    /// Builds a TUN UDP association whose response budget follows its effective MTU.
    #[must_use]
    pub(crate) const fn for_tun(source: SocketAddr, mtu: usize) -> Self {
        let payload_size = mtu.saturating_sub(IPV6_UDP_OVERHEAD);
        Self {
            inbound: InboundKind::Tun,
            source,
            max_response_payload_size: if payload_size > u16::MAX as usize {
                u16::MAX
            } else {
                payload_size as u16
            },
        }
    }

    #[must_use]
    #[cfg_attr(not(feature = "outbound-vless"), allow(dead_code))]
    pub(crate) const fn max_response_payload_size(&self) -> u16 {
        self.max_response_payload_size
    }
}

/// One datagram crossing the dispatcher boundary.
///
/// On send, `remote` is the destination. On receive, it is the remote source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub remote: Destination,
    pub payload: Bytes,
    /// Canonical domain extracted from intercepted client payload.
    ///
    /// This is routing-only metadata. The routing dispatcher consumes and
    /// clears it before forwarding the datagram, so outbounds continue to use
    /// `remote`, which preserves the original TUN IP target.
    pub sniffed_domain: Option<Arc<str>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_requires_a_port_and_bracketed_ipv6() {
        assert_eq!(
            Destination::from_authority("example.com:443").unwrap(),
            Destination::Domain {
                host: "example.com".to_owned(),
                port: 443,
            }
        );
        assert!(Destination::from_authority("example.com").is_err());
        assert!(Destination::from_authority("2001:db8::1:443").is_err());
        assert!(matches!(
            Destination::from_authority("[::1]:443").unwrap(),
            Destination::Ip(_)
        ));
    }

    #[test]
    fn datagram_response_limit_is_selected_by_inbound() {
        let source = "127.0.0.1:10000".parse().unwrap();
        assert_eq!(
            DatagramSession::new(InboundKind::Tun, source).max_response_payload_size(),
            TUN_XUDP_MAX_RESPONSE_PAYLOAD_SIZE
        );
        assert_eq!(
            DatagramSession::for_tun(source, 1_400).max_response_payload_size(),
            1_352
        );
        assert_eq!(
            DatagramSession::new(InboundKind::Http, source).max_response_payload_size(),
            XUDP_MAX_RESPONSE_PAYLOAD_SIZE
        );
        assert_eq!(
            DatagramSession::new(InboundKind::Socks5, source).max_response_payload_size(),
            65_245
        );
        assert_eq!(
            DatagramSession::new(InboundKind::InternalMeasure, source).max_response_payload_size(),
            XUDP_MAX_RESPONSE_PAYLOAD_SIZE
        );
        assert_eq!(
            DatagramSession::new(InboundKind::InternalDns, source).max_response_payload_size(),
            INTERNAL_DNS_XUDP_MAX_RESPONSE_PAYLOAD_SIZE
        );
        assert_eq!(
            DatagramSession::new(InboundKind::InternalGeoData, source).max_response_payload_size(),
            XUDP_MAX_RESPONSE_PAYLOAD_SIZE
        );
    }
}
