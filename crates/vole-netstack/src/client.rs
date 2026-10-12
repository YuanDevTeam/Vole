use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use crate::{ClientAddresses, ConfigError};

/// Largest ordinary IPv6 packet, including its fixed header. Jumbograms are
/// outside the raw client codec; this limit is independent of the TX MTU.
pub const MAX_RECEIVE_PACKET_SIZE: usize = 40 + 65_535;

/// A local address and its actual prefix length, retaining the address's host
/// bits. Field names in a proxy configuration do not determine its family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
}

/// One internal client profile. It adds no system address or route settings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientConfig {
    pub prefixes: [Option<ClientPrefix>; 2],
    /// Zero preserves the legacy behavior of using the configured TX MTU.
    pub receive_packet_limit: usize,
    /// Enables correlated packet-layer ICMP PMTU feedback in active mode only.
    pub path_mtu_discovery: bool,
}

impl From<ClientAddresses> for ClientConfig {
    fn from(addresses: ClientAddresses) -> Self {
        Self {
            prefixes: [
                addresses.ipv4.map(|address| ClientPrefix {
                    address: address.into(),
                    prefix_len: 32,
                }),
                addresses.ipv6.map(|address| ClientPrefix {
                    address: address.into(),
                    prefix_len: 128,
                }),
            ],
            receive_packet_limit: 0,
            path_mtu_discovery: false,
        }
    }
}

impl ClientConfig {
    /// Normalizes mapped addresses and duplicate source candidates, then
    /// checks the active family's MTU and the separate receive allocation bound.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for invalid or non-unicast prefixes,
    /// subnet broadcasts, missing local addresses, or invalid packet bounds.
    pub fn validate(mut self, mtu: usize) -> Result<Self, ConfigError> {
        let mut normalized = [None; 2];
        for (slot, prefix) in self.prefixes.into_iter().enumerate() {
            let Some(mut prefix) = prefix else { continue };
            if let IpAddr::V6(address) = prefix.address
                && let Some(address) = address.to_ipv4_mapped()
            {
                prefix.address = address.into();
                prefix.prefix_len = prefix
                    .prefix_len
                    .checked_sub(96)
                    .ok_or(ConfigError::ClientPrefix)?;
            }
            let maximum = if prefix.address.is_ipv4() { 32 } else { 128 };
            if prefix.prefix_len > maximum {
                return Err(ConfigError::ClientPrefix);
            }
            match prefix.address {
                IpAddr::V4(address) => {
                    if address.is_unspecified() || address.is_multicast() {
                        return Err(ConfigError::ClientAddress("IPv4"));
                    }
                    if address.is_broadcast() || subnet_broadcast(prefix, false) == Some(address) {
                        return Err(ConfigError::ClientBroadcast);
                    }
                }
                IpAddr::V6(address) => {
                    if address.is_unspecified() || address.is_multicast() {
                        return Err(ConfigError::ClientAddress("IPv6"));
                    }
                }
            }
            normalized[slot] = Some(prefix);
        }
        if normalized.iter().all(Option::is_none) {
            return Err(ConfigError::NoClientAddress);
        }

        // An address supplied under one prefix can be another supplied
        // prefix's subnet broadcast. Check before merging duplicate sources.
        for prefix in normalized.into_iter().flatten() {
            if let Some(broadcast) = subnet_broadcast(prefix, true)
                && normalized
                    .iter()
                    .flatten()
                    .any(|source| source.address == IpAddr::V4(broadcast))
            {
                return Err(ConfigError::ClientBroadcast);
            }
        }

        self.prefixes = [None; 2];
        let mut count = 0;
        for prefix in normalized.into_iter().flatten() {
            if let Some(existing) = self.prefixes[..count]
                .iter_mut()
                .flatten()
                .find(|existing| existing.address == prefix.address)
            {
                existing.prefix_len = existing.prefix_len.max(prefix.prefix_len);
            } else {
                self.prefixes[count] = Some(prefix);
                count += 1;
            }
        }
        let minimum = if self.has_ipv6() { 1_280 } else { 68 };
        if !(minimum..=65_535).contains(&mtu) {
            return Err(ConfigError::ClientMtu {
                value: mtu,
                minimum,
            });
        }
        if self.receive_packet_limit == 0 {
            self.receive_packet_limit = mtu;
        }
        if !(1..=MAX_RECEIVE_PACKET_SIZE).contains(&self.receive_packet_limit) {
            return Err(ConfigError::ReceivePacketLimit(self.receive_packet_limit));
        }
        Ok(self)
    }

    /// Iterates the at most two canonical source candidates in stable order.
    pub fn prefixes(&self) -> impl Iterator<Item = ClientPrefix> + '_ {
        self.prefixes.iter().copied().flatten()
    }

    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.prefixes().any(|prefix| prefix.address.is_ipv6())
    }

    #[must_use]
    pub fn contains_address(&self, address: IpAddr) -> bool {
        let address = unmap(address);
        self.prefixes().any(|prefix| prefix.address == address)
    }

    /// Selects an actual local source with the applicable RFC 6724 rules.
    /// Configured addresses are stable and non-deprecated on a single output
    /// interface, so those rules are ties. Complete ties retain input order.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for an invalid destination or unavailable family.
    pub fn source_for(&self, destination: IpAddr) -> io::Result<IpAddr> {
        let destination = unmap(destination);
        if destination.is_unspecified()
            || destination.is_multicast()
            || matches!(destination, IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid client peer",
            ));
        }
        if destination.is_loopback() && !self.contains_address(destination) {
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "client loopback peer is not a local address",
            ));
        }
        let mut selected = None;
        for candidate in self
            .prefixes()
            .filter(|prefix| prefix.address.is_ipv4() == destination.is_ipv4())
        {
            if selected.is_none_or(|current| prefer_source(candidate, current, destination)) {
                selected = Some(candidate);
            }
        }
        selected.map(|prefix| prefix.address).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "active client source family is unavailable",
            )
        })
    }
}

fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn subnet_broadcast(prefix: ClientPrefix, skip_loopback: bool) -> Option<Ipv4Addr> {
    let IpAddr::V4(address) = prefix.address else {
        return None;
    };
    if prefix.prefix_len >= 31 || (skip_loopback && address.is_loopback()) {
        return None;
    }
    let host_mask = u32::try_from((1_u64 << (32 - prefix.prefix_len)) - 1).ok()?;
    Some(Ipv4Addr::from(u32::from(address) | host_mask))
}

fn prefer_source(candidate: ClientPrefix, current: ClientPrefix, destination: IpAddr) -> bool {
    if candidate.address == destination || current.address == destination {
        return candidate.address == destination;
    }
    let candidate_scope = scope(candidate.address);
    let current_scope = scope(current.address);
    let destination_scope = scope(destination);
    if candidate_scope != current_scope {
        let candidate_appropriate = candidate_scope >= destination_scope;
        let current_appropriate = current_scope >= destination_scope;
        if candidate_appropriate != current_appropriate {
            return candidate_appropriate;
        }
        return if candidate_appropriate {
            candidate_scope < current_scope
        } else {
            candidate_scope > current_scope
        };
    }
    let matching_label = |source| label(source) == label(destination);
    if matching_label(candidate.address) != matching_label(current.address) {
        return matching_label(candidate.address);
    }
    common_prefix(candidate, destination) > common_prefix(current, destination)
}

fn scope(address: IpAddr) -> u8 {
    if address.is_loopback() {
        return 2;
    }
    match address {
        IpAddr::V4(ip) if ip.is_link_local() => 2,
        IpAddr::V6(ip) => {
            let bytes = ip.octets();
            if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
                2
            } else if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0xc0 {
                5
            } else {
                14
            }
        }
        IpAddr::V4(_) => 14,
    }
}

fn label(address: IpAddr) -> u8 {
    let IpAddr::V6(ip) = address else { return 4 };
    if ip.is_loopback() {
        return 0;
    }
    let bytes = ip.octets();
    if bytes[..2] == [0x20, 0x02] {
        2
    } else if bytes[..4] == [0x20, 0x01, 0, 0] {
        5
    } else if bytes[0] & 0xfe == 0xfc {
        13
    } else if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0xc0 {
        11
    } else if bytes[..2] == [0x3f, 0xfe] {
        12
    } else if bytes[..12] == [0; 12] {
        3
    } else {
        1
    }
}

fn common_prefix(source: ClientPrefix, destination: IpAddr) -> u8 {
    let differing = match (source.address, destination) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) ^ u32::from(b)).leading_zeros(),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a) ^ u128::from(b)).leading_zeros(),
        _ => return 0,
    };
    u8::try_from(differing)
        .unwrap_or(128)
        .min(source.prefix_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(address: &str, prefix_len: u8) -> ClientPrefix {
        ClientPrefix {
            address: address.parse().unwrap(),
            prefix_len,
        }
    }

    #[test]
    fn source_selection_keeps_two_same_family_candidates_and_prefix_bounds() {
        let config = ClientConfig {
            prefixes: [
                Some(prefix("2001:db8:1::2", 48)),
                Some(prefix("2001:db8:2::2", 48)),
            ],
            ..Default::default()
        }
        .validate(1280)
        .unwrap();
        assert_eq!(
            config.source_for("2001:db8:1::9".parse().unwrap()).unwrap(),
            "2001:db8:1::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            config.source_for("2001:db8:2::9".parse().unwrap()).unwrap(),
            "2001:db8:2::2".parse::<IpAddr>().unwrap()
        );
        // Equal configured /32 matches tie even though the second address is
        // closer beyond those bits; the first candidate must stay selected.
        let config = ClientConfig {
            prefixes: [
                Some(prefix("2001:db8:1::2", 32)),
                Some(prefix("2001:db8:2::2", 32)),
            ],
            ..config
        }
        .validate(1280)
        .unwrap();
        assert_eq!(
            config.source_for("2001:db8:2::9".parse().unwrap()).unwrap(),
            "2001:db8:1::2".parse::<IpAddr>().unwrap()
        );
        let config = ClientConfig {
            prefixes: [Some(prefix("fe80::2", 64)), Some(prefix("2001:db8::2", 64))],
            ..config
        }
        .validate(1280)
        .unwrap();
        assert_eq!(
            config.source_for("fe80::9".parse().unwrap()).unwrap(),
            "fe80::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            config.source_for("2001:db8::9".parse().unwrap()).unwrap(),
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn mapped_duplicates_and_broadcasts_follow_actual_prefixes() {
        for prefixes in [
            [
                Some(prefix("::ffff:10.23.0.2", 120)),
                Some(prefix("10.23.0.2", 32)),
            ],
            [
                Some(prefix("10.23.0.2", 32)),
                Some(prefix("::ffff:10.23.0.2", 120)),
            ],
        ] {
            let config = ClientConfig {
                prefixes,
                ..Default::default()
            }
            .validate(68)
            .unwrap();
            assert_eq!(
                config.prefixes().collect::<Vec<_>>(),
                vec![ClientPrefix {
                    address: "10.23.0.2".parse().unwrap(),
                    prefix_len: 32
                }]
            );
            assert!(!config.has_ipv6());
        }
        for prefixes in [
            [Some(prefix("10.23.0.255", 24)), None],
            [
                Some(prefix("10.23.0.2", 24)),
                Some(prefix("10.23.0.255", 32)),
            ],
        ] {
            assert_eq!(
                ClientConfig {
                    prefixes,
                    ..Default::default()
                }
                .validate(68),
                Err(ConfigError::ClientBroadcast)
            );
        }
        ClientConfig {
            prefixes: [Some(prefix("10.23.0.255", 31)), None],
            ..Default::default()
        }
        .validate(68)
        .unwrap();
    }

    #[test]
    fn active_family_mtu_and_receive_budget_leave_passive_bounds_intact() {
        let ipv4 = ClientConfig {
            prefixes: [Some(prefix("10.23.0.2", 24)), None],
            receive_packet_limit: MAX_RECEIVE_PACKET_SIZE,
            path_mtu_discovery: true,
        };
        let ipv4 = ipv4.validate(68).unwrap();
        assert_eq!(ipv4.receive_packet_limit, MAX_RECEIVE_PACKET_SIZE);
        let config = crate::NetStackConfig {
            mtu: 68,
            ..Default::default()
        };
        config.validate_client(&ipv4).unwrap();
        assert_eq!(config.validate(), Err(ConfigError::Mtu(68)));
        let ipv6 = ClientConfig {
            prefixes: [Some(prefix("fd23::2", 64)), None],
            ..ipv4
        };
        assert!(matches!(
            ipv6.validate(1279),
            Err(ConfigError::ClientMtu { minimum: 1280, .. })
        ));
        ipv6.validate(1280).unwrap();
        let legacy = ClientConfig::from(ClientAddresses {
            ipv4: Some(Ipv4Addr::new(10, 23, 0, 2)),
            ipv6: None,
        })
        .validate(1500)
        .unwrap();
        assert_eq!(legacy.receive_packet_limit, 1500);
        assert!(!legacy.path_mtu_discovery);
    }
}
