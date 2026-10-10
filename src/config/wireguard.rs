use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{ProxyProtocol, invalid, validate_host, validate_port};
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
pub struct WireGuardOutboundConfig {
    pub address: String,
    pub port: u16,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub private_key: WireGuardKey,
    pub public_key: WireGuardKey,
    pub pre_shared_key: Option<WireGuardKey>,
    pub mtu: u16,
    pub persistent_keepalive: u16,
    /// Mihomo ignores this top-level option without `peers`.
    pub allowed_ips: Vec<String>,
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
pub(super) struct RawWireGuard {
    name: String,
    server: String,
    port: u16,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    ipv6: String,
    private_key: String,
    public_key: String,
    #[serde(default)]
    pre_shared_key: String,
    #[serde(default)]
    mtu: u16,
    #[serde(default)]
    persistent_keepalive: u16,
    #[serde(default)]
    allowed_ips: Vec<String>,
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
                let prefix = prefix.parse::<u8>().map_err(|_| {
                    crate::VoleError::InvalidConfig("invalid WireGuard local prefix".into())
                })?;
                if prefix > if ip.is_ipv4() { 32 } else { 128 } {
                    return invalid("invalid WireGuard local prefix");
                }
            }
            match ip {
                IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(ip),
                IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(ip),
                _ => return invalid("WireGuard requires at most one local address per family"),
            }
        }
        let config = WireGuardOutboundConfig {
            address: self.server,
            port: self.port,
            ipv4,
            ipv6,
            private_key: WireGuardKey::parse(self.private_key)?,
            public_key: WireGuardKey::parse(self.public_key)?,
            pre_shared_key: (!self.pre_shared_key.is_empty())
                .then(|| WireGuardKey::parse(self.pre_shared_key))
                .transpose()?,
            mtu: if self.mtu == 0 { 1408 } else { self.mtu },
            persistent_keepalive: self.persistent_keepalive,
            allowed_ips: self.allowed_ips,
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
        validate_host(&self.address, "WireGuard server")?;
        validate_port(self.port, "WireGuard")?;
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
