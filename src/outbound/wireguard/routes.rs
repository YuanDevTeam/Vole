//! Immutable longest-prefix ownership, shared by send and authenticated receive.
use crate::config::WireGuardOutboundConfig;
use std::{collections::HashMap, net::IpAddr};
pub(super) struct Routes {
    v4: HashMap<(u32, u8), usize>,
    v6: HashMap<(u128, u8), usize>,
}
impl Routes {
    pub fn new(config: &WireGuardOutboundConfig) -> Self {
        let mut routes = Self {
            v4: HashMap::new(),
            v6: HashMap::new(),
        };
        for (cidr, index) in &config.routes {
            match cidr.network {
                IpAddr::V4(ip) => {
                    let network = if cidr.prefix_len == 0 {
                        0
                    } else {
                        u32::from(ip) & (u32::MAX << (32 - cidr.prefix_len))
                    };
                    routes.v4.insert((network, cidr.prefix_len), *index);
                }
                IpAddr::V6(ip) => {
                    let network = if cidr.prefix_len == 0 {
                        0
                    } else {
                        u128::from(ip) & (u128::MAX << (128 - cidr.prefix_len))
                    };
                    routes.v6.insert((network, cidr.prefix_len), *index);
                }
            }
        }
        routes
    }
    pub fn select(&self, ip: IpAddr) -> Option<usize> {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                if self.v4.is_empty() {
                    return None;
                }
                if self.v4.len() == 1 {
                    let (&(network, prefix), &owner) = self.v4.iter().next()?;
                    let masked = if prefix == 0 {
                        0
                    } else {
                        ip & (u32::MAX << (32 - prefix))
                    };
                    return (masked == network).then_some(owner);
                }
                (0..=32).rev().find_map(|prefix| {
                    self.v4
                        .get(&(
                            if prefix == 0 {
                                0
                            } else {
                                ip & (u32::MAX << (32 - prefix))
                            },
                            prefix,
                        ))
                        .copied()
                })
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                if self.v6.is_empty() {
                    return None;
                }
                if self.v6.len() == 1 {
                    let (&(network, prefix), &owner) = self.v6.iter().next()?;
                    let masked = if prefix == 0 {
                        0
                    } else {
                        ip & (u128::MAX << (128 - prefix))
                    };
                    return (masked == network).then_some(owner);
                }
                (0..=128).rev().find_map(|prefix| {
                    self.v6
                        .get(&(
                            if prefix == 0 {
                                0
                            } else {
                                ip & (u128::MAX << (128 - prefix))
                            },
                            prefix,
                        ))
                        .copied()
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[(&str, u8, usize)]) -> Routes {
        let mut config = crate::outbound::wireguard::tests::config();
        let peer = config.peers[0].clone();
        let owners = entries.iter().map(|entry| entry.2).max().unwrap_or(0) + 1;
        config.peers.resize(owners, peer);
        config.routes = entries
            .iter()
            .map(|&(network, prefix_len, owner)| {
                (
                    crate::config::IpCidr {
                        network: network.parse().unwrap(),
                        prefix_len,
                    },
                    owner,
                )
            })
            .collect();
        config.validate().unwrap();
        Routes::new(&config)
    }

    #[test]
    fn wireguard_single_ipv4_route_keeps_prefix_and_host_boundaries() {
        let narrow = table(&[("192.0.2.129", 24, 2)]);
        for ip in ["192.0.2.0", "192.0.2.255"] {
            assert_eq!(narrow.select(ip.parse().unwrap()), Some(2));
        }
        assert_eq!(narrow.select("192.0.3.0".parse().unwrap()), None);
        assert_eq!(narrow.select("2001:db8::1".parse().unwrap()), None);

        let default = table(&[("0.0.0.0", 0, 1)]);
        for ip in ["0.0.0.0", "255.255.255.255"] {
            assert_eq!(default.select(ip.parse().unwrap()), Some(1));
        }
        let host = table(&[("203.0.113.9", 32, 0)]);
        assert_eq!(host.select("203.0.113.9".parse().unwrap()), Some(0));
        for ip in ["203.0.113.8", "203.0.113.10"] {
            assert_eq!(host.select(ip.parse().unwrap()), None);
        }
    }

    #[test]
    fn wireguard_single_ipv6_route_keeps_prefix_and_host_boundaries() {
        let narrow = table(&[("2001:db8:1:2::99", 64, 2)]);
        for ip in ["2001:db8:1:2::", "2001:db8:1:2:ffff:ffff:ffff:ffff"] {
            assert_eq!(narrow.select(ip.parse().unwrap()), Some(2));
        }
        assert_eq!(narrow.select("2001:db8:1:3::".parse().unwrap()), None);
        assert_eq!(narrow.select("192.0.2.1".parse().unwrap()), None);

        let default = table(&[("::", 0, 1)]);
        for ip in ["::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"] {
            assert_eq!(default.select(ip.parse().unwrap()), Some(1));
        }
        let host = table(&[("2001:db8::9", 128, 0)]);
        assert_eq!(host.select("2001:db8::9".parse().unwrap()), Some(0));
        for ip in ["2001:db8::8", "2001:db8::10"] {
            assert_eq!(host.select(ip.parse().unwrap()), None);
        }
    }

    #[test]
    fn wireguard_route_tables_preserve_lpm_and_last_prefix_owner() {
        let routes = table(&[
            ("0.0.0.0", 0, 0),
            ("192.0.0.0", 16, 1),
            ("192.0.2.1", 24, 1),
            ("192.0.2.129", 24, 2),
            ("::", 0, 0),
            ("2001:db8::", 32, 1),
            ("2001:db8:1:2::", 64, 1),
            ("2001:db8:1:2::99", 64, 2),
        ]);
        for (ip, owner) in [
            ("192.0.2.255", 2),
            ("192.0.3.1", 1),
            ("198.51.100.1", 0),
            ("2001:db8:1:2::1", 2),
            ("2001:db8:1:3::1", 1),
            ("2001:db9::1", 0),
        ] {
            assert_eq!(routes.select(ip.parse().unwrap()), Some(owner));
        }

        let repeated = table(&[
            ("192.0.2.1", 24, 1),
            ("192.0.2.129", 24, 2),
            ("2001:db8:1:2::", 64, 1),
            ("2001:db8:1:2::99", 64, 2),
        ]);
        assert_eq!(repeated.v4.len(), 1);
        assert_eq!(repeated.v6.len(), 1);
        assert_eq!(repeated.select("192.0.2.1".parse().unwrap()), Some(2));
        assert_eq!(repeated.select("2001:db8:1:2::1".parse().unwrap()), Some(2));
    }

    #[test]
    fn wireguard_empty_family_tables_never_cross_route() {
        let empty = table(&[]);
        assert_eq!(empty.select("192.0.2.1".parse().unwrap()), None);
        assert_eq!(empty.select("2001:db8::1".parse().unwrap()), None);
        let v4_only = table(&[("0.0.0.0", 0, 0)]);
        assert_eq!(v4_only.select("2001:db8::1".parse().unwrap()), None);
        let v6_only = table(&[("::", 0, 0)]);
        assert_eq!(v6_only.select("192.0.2.1".parse().unwrap()), None);
    }
}
