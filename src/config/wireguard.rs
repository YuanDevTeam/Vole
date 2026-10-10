use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, de::Visitor};
use zeroize::Zeroizing;

use super::{
    DnsNameserver, DnsRoute, IpCidr, ProxyProtocol, invalid, validate_host, validate_port,
};
use crate::Result;

#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for WireGuardKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WireGuardKey { .. }")
    }
}
impl WireGuardKey {
    fn parse(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        let bytes = Zeroizing::new(STANDARD.decode(value.as_bytes()).map_err(|_| {
            crate::VoleError::InvalidConfig("WireGuard requires a 32-byte base64 key".into())
        })?);
        let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            crate::VoleError::InvalidConfig("WireGuard requires a 32-byte base64 key".into())
        })?;
        Ok(Self(Zeroizing::new(bytes)))
    }
    #[cfg(feature = "outbound-wireguard")]
    pub(crate) fn bytes(&self) -> [u8; 32] {
        *self.0
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardPeerConfig {
    pub address: String,
    pub port: u16,
    pub public_key: WireGuardKey,
    pub pre_shared_key: Option<WireGuardKey>,
    pub reserved: [u8; 3],
    pub allowed_ips: Vec<IpCidr>,
}
impl std::fmt::Debug for WireGuardPeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardPeerConfig")
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardOutboundConfig {
    /// Representative first endpoint for the existing graph/measurement visitor.
    pub address: String,
    pub port: u16,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub private_key: WireGuardKey,
    pub mtu: u16,
    pub persistent_keepalive: u16,
    pub peers: Vec<WireGuardPeerConfig>,
    pub routes: Vec<(IpCidr, usize)>,
    /// Active node resolver; absent when the switch is false or DNS list empty.
    pub dns: Vec<DnsNameserver>,
    pub refresh_server_ip_interval: i64,
}
impl std::fmt::Debug for WireGuardOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardOutboundConfig")
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawPeer {
    server: String,
    port: u16,
    public_key: String,
    #[serde(default)]
    pre_shared_key: String,
    #[serde(default, deserialize_with = "deserialize_reserved")]
    reserved: Vec<u8>,
    #[serde(default)]
    allowed_ips: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawWireGuard {
    name: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    ipv6: String,
    private_key: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    pre_shared_key: String,
    #[serde(default, deserialize_with = "deserialize_reserved")]
    reserved: Vec<u8>,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    peers: Vec<RawPeer>,
    #[serde(default)]
    mtu: u16,
    #[serde(default)]
    persistent_keepalive: u16,
    #[serde(default)]
    remote_dns_resolve: bool,
    #[serde(default)]
    dns: Vec<String>,
    #[serde(default)]
    refresh_server_ip_interval: i64,
    #[serde(default)]
    udp: bool,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    dialer_proxy: Option<String>,
}
impl std::fmt::Debug for RawWireGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawWireGuard").finish_non_exhaustive()
    }
}
pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<RawWireGuard, D::Error> {
    RawWireGuard::deserialize(d)
        .map_err(|_| serde::de::Error::custom("invalid WireGuard configuration fields"))
}

fn deserialize_reserved<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct Reserved;

    impl<'de> Visitor<'de> for Reserved {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("three bytes as a byte array or standard Base64")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Vec<u8>, E> {
            let error = || E::custom("WireGuard reserved requires three bytes");
            let mut encoded = [0; 4];
            let mut length = 0;
            // Go's standard Base64 decoder ignores CR and LF.
            for byte in value.bytes().filter(|byte| !matches!(*byte, b'\r' | b'\n')) {
                if length == encoded.len() {
                    return Err(error());
                }
                encoded[length] = byte;
                length += 1;
            }
            if length == 0 {
                return Ok(Vec::new());
            }
            let mut decoded = [0; 3];
            if STANDARD
                .decode_slice(&encoded[..length], &mut decoded)
                .map_err(|_| error())?
                != decoded.len()
            {
                return Err(error());
            }
            Ok(decoded.to_vec())
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::with_capacity(3);
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == 3 {
                    return Err(serde::de::Error::custom(
                        "WireGuard reserved requires three bytes",
                    ));
                }
                bytes.push(byte);
            }
            if !bytes.is_empty() && bytes.len() != 3 {
                return Err(serde::de::Error::custom(
                    "WireGuard reserved requires three bytes",
                ));
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_any(Reserved)
}

fn reserved(value: Vec<u8>, default: [u8; 3]) -> Result<[u8; 3]> {
    if value.is_empty() {
        Ok(default)
    } else {
        value.try_into().map_err(|_| {
            crate::VoleError::InvalidConfig("WireGuard reserved requires three bytes".into())
        })
    }
}
fn supported_node_dns(nameserver: &DnsNameserver) -> bool {
    matches!(
        nameserver.address,
        super::DnsAddress::Ip(_) | super::DnsAddress::Domain(_)
    ) && matches!(
        nameserver.transport,
        super::DnsTransport::Udp
            | super::DnsTransport::Tcp
            | super::DnsTransport::Tls
            | super::DnsTransport::Http
            | super::DnsTransport::Https
            | super::DnsTransport::Quic
            | super::DnsTransport::Rcode(_)
    )
}

impl RawPeer {
    fn normalize(self, default: [u8; 3]) -> Result<WireGuardPeerConfig> {
        validate_host(&self.server, "WireGuard server")?;
        validate_port(self.port, "WireGuard")?;
        if self.allowed_ips.is_empty() {
            return invalid("WireGuard peer requires allowed-ips");
        }
        let ips = self
            .allowed_ips
            .iter()
            .map(|v| {
                super::parse_ip_cidr(
                    v,
                    v.split_once('/')
                        .and_then(|(ip, _)| ip.parse::<IpAddr>().ok())
                        .is_some_and(|ip| ip.is_ipv6()),
                )
                .map_err(|_| {
                    crate::VoleError::InvalidConfig("invalid WireGuard allowed prefix".into())
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(WireGuardPeerConfig {
            address: self.server,
            port: self.port,
            public_key: WireGuardKey::parse(self.public_key)?,
            pre_shared_key: (!self.pre_shared_key.is_empty())
                .then(|| WireGuardKey::parse(self.pre_shared_key))
                .transpose()?,
            reserved: reserved(self.reserved, default)?,
            allowed_ips: ips,
        })
    }
}
impl RawWireGuard {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-wireguard") {
            return invalid("WireGuard support is disabled at build time");
        }
        let mut ipv4 = None;
        let mut ipv6 = None;
        for value in [&self.ip, &self.ipv6].into_iter().filter(|s| !s.is_empty()) {
            let (address, prefix) = value
                .split_once('/')
                .map_or((value.as_str(), None), |(a, p)| (a, Some(p)));
            let ip = address.parse::<IpAddr>().map_err(|_| {
                crate::VoleError::InvalidConfig("invalid WireGuard local address".into())
            })?;
            if let Some(prefix) = prefix {
                let p = prefix.parse::<u8>().map_err(|_| {
                    crate::VoleError::InvalidConfig("invalid WireGuard local prefix".into())
                })?;
                if p > if ip.is_ipv4() { 32 } else { 128 } {
                    return invalid("invalid WireGuard local prefix");
                }
            }
            match ip {
                IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(ip),
                IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(ip),
                _ => return invalid("WireGuard requires at most one local address per family"),
            }
        }
        let global = reserved(self.reserved, [0; 3])?;
        let mut peers = Vec::<WireGuardPeerConfig>::new();
        let mut routes = Vec::new();
        if self.peers.is_empty() {
            // Fixed reference ignores top-level allowed-ips in single-peer mode.
            let _ = self.allowed_ips;
            let mut allowed_ips = Vec::new();
            if ipv4.is_some() {
                allowed_ips.push("0.0.0.0/0".into());
            }
            if ipv6.is_some() {
                allowed_ips.push("::/0".into());
            }
            peers.push(
                RawPeer {
                    server: self.server,
                    port: self.port,
                    public_key: self.public_key,
                    pre_shared_key: self.pre_shared_key,
                    reserved: Vec::new(),
                    allowed_ips,
                }
                .normalize(global)?,
            );
            routes.extend(peers[0].allowed_ips.iter().map(|cidr| (*cidr, 0)));
        } else {
            for raw in self.peers {
                let peer = raw.normalize(global)?;
                // WireGuard's device identifies peers by key. Repeated declarations
                // update that peer rather than inventing a second crypto identity.
                if let Some(index) = peers
                    .iter()
                    .position(|old| old.public_key == peer.public_key)
                {
                    routes.extend(peer.allowed_ips.iter().map(|cidr| (*cidr, index)));
                    let old = &mut peers[index];
                    old.address = peer.address;
                    old.port = peer.port;
                    old.reserved = peer.reserved;
                    if peer.pre_shared_key.is_some() {
                        old.pre_shared_key = peer.pre_shared_key;
                    }
                    old.allowed_ips.extend(peer.allowed_ips);
                } else {
                    routes.extend(peer.allowed_ips.iter().map(|cidr| (*cidr, peers.len())));
                    peers.push(peer);
                }
            }
        }
        let dns = if self.remote_dns_resolve && !self.dns.is_empty() {
            self.dns
                .iter()
                .map(|v| {
                    // The reference replaces every parsed DNS route with this
                    // WireGuard adapter; a named fragment cannot select an
                    // external group or bypass the node's raw-IP data plane.
                    let endpoint = v.split_once('#').map_or(v.as_str(), |(v, _)| v);
                    let nameserver = super::parse_dns_nameserver(
                        endpoint,
                        &super::RouteTargetsByName::new(),
                        DnsRoute::Direct,
                    )?;
                    if !supported_node_dns(&nameserver) {
                        return invalid(
                            "WireGuard node DNS requires an explicit network or RCODE upstream",
                        );
                    }
                    Ok(nameserver)
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let config = WireGuardOutboundConfig {
            address: peers[0].address.clone(),
            port: peers[0].port,
            ipv4,
            ipv6,
            private_key: WireGuardKey::parse(self.private_key)?,
            mtu: if self.mtu == 0 { 1408 } else { self.mtu },
            persistent_keepalive: self.persistent_keepalive,
            peers,
            routes,
            dns,
            refresh_server_ip_interval: self.refresh_server_ip_interval,
        };
        config.validate()?;
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::WireGuard(config),
        ))
    }
}
impl WireGuardOutboundConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.peers.is_empty() {
            return invalid("WireGuard requires a peer");
        }
        if self
            .dns
            .iter()
            .any(|nameserver| !supported_node_dns(nameserver))
        {
            return invalid("WireGuard node DNS requires an explicit network or RCODE upstream");
        }
        for peer in &self.peers {
            validate_host(&peer.address, "WireGuard server")?;
            validate_port(peer.port, "WireGuard")?;
            if peer.allowed_ips.is_empty() {
                return invalid("WireGuard peer requires allowed-ips");
            }
        }
        if self.routes.iter().any(|(prefix, index)| {
            *index >= self.peers.len()
                || prefix.prefix_len > if prefix.network.is_ipv4() { 32 } else { 128 }
        }) {
            return invalid("invalid WireGuard peer route");
        }
        if self.ipv4.is_none() && self.ipv6.is_none() {
            return invalid("WireGuard requires a local address");
        }
        if self
            .ipv4
            .is_some_and(|ip| ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
            || self
                .ipv6
                .is_some_and(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return invalid("WireGuard requires unicast local addresses");
        }
        if !(1280..=65503).contains(&self.mtu) {
            return invalid("WireGuard MTU must be between 1280 and 65503");
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "outbound-wireguard"))]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::config::Config;

    fn document(global: Value, peer: Option<Value>) -> Vec<u8> {
        let mut node = json!({
            "name": "wg", "type": "wireguard", "server": "192.0.2.1", "port": 51820,
            "ip": "10.0.0.2", "private-key": STANDARD.encode([1; 32]),
            "public-key": STANDARD.encode([2; 32]), "reserved": global
        });
        if let Some(reserved) = peer {
            node["peers"] = json!([{
                "server": "192.0.2.1", "port": 51820, "public-key": STANDARD.encode([2; 32]),
                "allowed-ips": ["0.0.0.0/0"], "reserved": reserved
            }]);
        }
        serde_json::to_vec(&json!({"mixed-port": 1080, "proxies": [node]})).unwrap()
    }

    #[test]
    fn reserved_base64_and_bytes_match_and_empty_peer_inherits() {
        for peer in [None, Some(json!([])), Some(json!([0, 1, 255]))] {
            let base64_peer = peer.as_ref().map(|value| {
                if value.as_array().unwrap().is_empty() {
                    json!("")
                } else {
                    json!("AAH/")
                }
            });
            let bytes = Config::parse_yaml(&document(json!([83, 128, 39]), peer)).unwrap();
            let encoded = Config::parse_yaml(&document(json!("U4An"), base64_peer)).unwrap();
            assert_eq!(bytes.proxies[0].protocol, encoded.proxies[0].protocol);
        }
        let inherited = Config::parse_yaml(&document(json!("U4An"), Some(json!("")))).unwrap();
        let ProxyProtocol::WireGuard(config) = &inherited.proxies[0].protocol else {
            panic!("expected WireGuard");
        };
        assert_eq!(config.peers[0].reserved, [83, 128, 39]);
        let zeros = Config::parse_yaml(&document(json!("U4An"), Some(json!("AAAA")))).unwrap();
        let ProxyProtocol::WireGuard(config) = &zeros.proxies[0].protocol else {
            panic!("expected WireGuard");
        };
        assert_eq!(config.peers[0].reserved, [0; 3]);
        let default = Config::parse_yaml(&document(json!(""), None)).unwrap();
        let bytes = Config::parse_yaml(&document(json!([]), None)).unwrap();
        assert_eq!(default.proxies[0].protocol, bytes.proxies[0].protocol);
        assert!(Config::parse_yaml(&document(json!("U4\r\nAn"), None)).is_ok());
    }

    #[test]
    fn reserved_rejects_invalid_base64_lengths_and_byte_values_at_both_levels() {
        for value in [
            json!("AA=="),
            json!("AAE="),
            json!("AAECAw=="),
            json!("%%%"),
            json!("____"),
            json!([1]),
            json!([1, 2, 3, 4]),
            json!([0, 1, 256]),
            json!([-1, 1, 2]),
            json!([0, 1, 2.0]),
            json!(null),
            json!(true),
            json!(42),
        ] {
            assert!(Config::parse_yaml(&document(value.clone(), None)).is_err());
            assert!(Config::parse_yaml(&document(json!([0, 0, 0]), Some(value))).is_err());
        }
    }
}
