use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
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
    #[serde(default)]
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
    #[serde(default)]
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
