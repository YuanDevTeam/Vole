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
