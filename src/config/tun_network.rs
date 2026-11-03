//! TUN network inputs shared with host adapters; Linux owns native application.
use super::{IpCidr, PortRange, Result, UidRange, invalid, parse_ip_cidr};
use serde::Deserialize;
use std::net::{IpAddr, Ipv6Addr};

pub(crate) const MAX_NETWORK_ITEMS: usize = 256;
pub const DEFAULT_TUN_TABLE: u32 = 2022;
pub const DEFAULT_TUN_RULE: u32 = 9000;

/// Network settings do not grant permission to reconfigure a borrowed device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunNetworkConfig {
    pub inet6_address: Vec<TunAddress6>,
    pub route_address: Vec<IpCidr>,
    pub route_exclude_address: Vec<IpCidr>,
    pub table_index: u32,
    pub rule_index: u32,
    pub strict_route: bool,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<UidRange>,
    pub exclude_uid: Vec<UidRange>,
    pub exclude_src_port: Vec<PortRange>,
    pub exclude_dst_port: Vec<PortRange>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunAddress6 {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
}
impl Default for TunNetworkConfig {
    fn default() -> Self {
        Self {
            inet6_address: vec![TunAddress6 {
                address: "fdfe:dcba:9876::1".parse().expect("static IPv6"),
                prefix_len: 126,
            }],
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
            table_index: DEFAULT_TUN_TABLE,
            rule_index: DEFAULT_TUN_RULE,
            strict_route: false,
            include_interface: Vec::new(),
            exclude_interface: Vec::new(),
            include_uid: Vec::new(),
            exclude_uid: Vec::new(),
            exclude_src_port: Vec::new(),
            exclude_dst_port: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct RawTunNetworkConfig {
    pub inet6_address: Option<Vec<String>>,
    pub route_address: Vec<String>,
    pub route_exclude_address: Vec<String>,
    pub table_index: u32,
    pub rule_index: u32,
    pub strict_route: bool,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<u32>,
    pub include_uid_range: Vec<String>,
    pub exclude_uid: Vec<u32>,
    pub exclude_uid_range: Vec<String>,
    pub exclude_src_port: Vec<u16>,
    pub exclude_src_port_range: Vec<String>,
    pub exclude_dst_port: Vec<u16>,
    pub exclude_dst_port_range: Vec<String>,
}
impl RawTunNetworkConfig {
    pub(super) fn normalize(self) -> Result<TunNetworkConfig> {
        let count = self.inet6_address.as_ref().map_or(0, Vec::len)
            + self.route_address.len()
            + self.route_exclude_address.len()
            + self.include_interface.len()
            + self.exclude_interface.len()
            + self.include_uid.len()
            + self.include_uid_range.len()
            + self.exclude_uid.len()
            + self.exclude_uid_range.len()
            + self.exclude_src_port.len()
            + self.exclude_src_port_range.len()
            + self.exclude_dst_port.len()
            + self.exclude_dst_port_range.len();
        if count > MAX_NETWORK_ITEMS {
            return invalid("TUN network configuration exceeds its route-object budget");
        }
        let table_index = if self.table_index == 0 {
            DEFAULT_TUN_TABLE
        } else {
            self.table_index
        };
        let rule_index = if self.rule_index == 0 {
            DEFAULT_TUN_RULE
        } else {
            self.rule_index
        };
        if matches!(table_index, 253..=255)
            || rule_index.checked_add(8).is_none()
            || (rule_index..=rule_index + 8).any(|priority| matches!(priority, 0 | 32766 | 32767))
        {
            return invalid("TUN routing indices overlap reserved system objects");
        }
        let inet6_address = self.inet6_address.map_or_else(
            || Ok(TunNetworkConfig::default().inet6_address),
            |values| {
                values
                    .iter()
                    .map(|value| {
                        let (ip, prefix) = value.split_once('/').ok_or_else(|| {
                            super::VoleError::InvalidConfig(
                                "tun.inet6-address requires IPv6 prefixes".into(),
                            )
                        })?;
                        let address: Ipv6Addr = ip.parse().map_err(|_| {
                            super::VoleError::InvalidConfig(
                                "tun.inet6-address requires IPv6 prefixes".into(),
                            )
                        })?;
                        let prefix_len: u8 = prefix.parse().map_err(|_| {
                            super::VoleError::InvalidConfig(
                                "invalid tun.inet6-address prefix".into(),
                            )
                        })?;
                        if prefix_len > 128
                            || address.is_unspecified()
                            || address.is_multicast()
                            || address.is_loopback()
                        {
                            return invalid("tun.inet6-address requires unicast IPv6 prefixes");
                        }
                        Ok(TunAddress6 {
                            address,
                            prefix_len,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            },
        )?;
        let routes = |values: Vec<String>| {
            values
                .iter()
                .map(|value| {
                    let ipv6 = value
                        .split_once('/')
                        .is_some_and(|(ip, _)| ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()));
                    parse_ip_cidr(value, ipv6).map_err(|_| {
                        super::VoleError::InvalidConfig("TUN routes require IPv4/IPv6 CIDRs".into())
                    })
                })
                .collect::<Result<Vec<_>>>()
        };
        Ok(TunNetworkConfig {
            inet6_address,
            route_address: routes(self.route_address)?,
            route_exclude_address: routes(self.route_exclude_address)?,
            table_index,
            rule_index,
            strict_route: self.strict_route,
            include_interface: interface_names(self.include_interface)?,
            exclude_interface: interface_names(self.exclude_interface)?,
            include_uid: uid_ranges(self.include_uid, self.include_uid_range)?,
            exclude_uid: uid_ranges(self.exclude_uid, self.exclude_uid_range)?,
            exclude_src_port: port_ranges(self.exclude_src_port, self.exclude_src_port_range)?,
            exclude_dst_port: port_ranges(self.exclude_dst_port, self.exclude_dst_port_range)?,
        })
    }
}
fn interface_names(mut names: Vec<String>) -> Result<Vec<String>> {
    // Linux IFNAMSIZ includes NUL. Retain names rather than ifindices: an
    // absent interface is a dormant RPDB selector and can appear later.
    if names.iter().any(|name| {
        name.is_empty()
            || name.len() >= 16
            || matches!(name.as_str(), "." | "..")
            || name
                .bytes()
                .any(|byte| byte == 0 || byte == b'/' || byte == b':' || byte.is_ascii_whitespace())
    }) {
        return invalid("TUN input interfaces require valid Linux interface names");
    }
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

fn number(text: &str) -> Option<u32> {
    if text.is_empty() || text.trim() != text || text.starts_with('-') {
        return None;
    }
    let (radix, digits) =
        if let Some(value) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (16, value)
        } else if let Some(value) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
            (8, value)
        } else if let Some(value) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
            (2, value)
        } else if text.starts_with('0') && text.len() > 1 {
            (8, &text[1..])
        } else {
            (10, text)
        };
    u32::from_str_radix(digits, radix).ok()
}
fn range(text: &str, maximum: u32) -> Result<(u32, u32)> {
    let pair = text
        .split_once(':')
        .and_then(|(first, last)| Some((number(first)?, number(last)?)));
    match pair {
        Some((first, last)) if first <= last && last <= maximum => Ok((first, last)),
        _ => invalid("TUN ranges require ordered start:end values"),
    }
}
fn uid_ranges(values: Vec<u32>, ranges: Vec<String>) -> Result<Vec<UidRange>> {
    let mut result: Vec<_> = values
        .into_iter()
        .map(|id| UidRange { start: id, end: id })
        .collect();
    for text in ranges {
        let (start, end) = range(&text, u32::MAX)?;
        result.push(UidRange { start, end });
    }
    Ok(result)
}
fn port_ranges(values: Vec<u16>, ranges: Vec<String>) -> Result<Vec<PortRange>> {
    let mut result: Vec<_> = values
        .into_iter()
        .map(|port| PortRange {
            start: port,
            end: port,
        })
        .collect();
    for text in ranges {
        let (start, end) = range(&text, u32::from(u16::MAX))?;
        result.push(PortRange {
            start: start as u16,
            end: end as u16,
        });
    }
    Ok(super::merge_port_ranges(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tun_network_fields_keep_host_addresses_and_real_mihomo_range_syntax() {
        let value = super::super::Config::parse_yaml(
            br#"
ipv6: true
tun:
  inet6-address: ["fd23::17/64"]
  route-address: ["203.0.113.17/24", "2001:db8:5::7/48"]
  route-exclude-address: ["203.0.113.64/26"]
  iproute2-table-index: 2500
  iproute2-rule-index: 8500
  strict-route: true
  include-uid: [1001]
  include-uid-range: ["0x1000:0x1003"]
  exclude-uid-range: ["1002:1003"]
  exclude-src-port: [12345]
  exclude-dst-port-range: ["0x35:0x36"]
rules: ["MATCH,DIRECT"]
"#,
        )
        .unwrap()
        .tun
        .network;
        assert_eq!(
            value.inet6_address[0].address,
            "fd23::17".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            value.route_address[0].network,
            "203.0.113.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!((value.table_index, value.rule_index), (2500, 8500));
        assert_eq!(
            value.include_uid[1],
            UidRange {
                start: 4096,
                end: 4099
            }
        );
        assert_eq!(
            value.exclude_dst_port,
            vec![PortRange { start: 53, end: 54 }]
        );
        assert!(value.strict_route);
    }
    #[test]
    fn tun_network_rejects_unbounded_or_reserved_objects_before_acquisition() {
        for network in [
            "iproute2-table-index: 254",
            "iproute2-rule-index: 32765",
            "iproute2-rule-index: 4294967295",
            "include-uid-range: ['1002:1001']",
            "exclude-dst-port-range: ['0:65536']",
            "inet6-address: ['192.0.2.1/24']",
        ] {
            let yaml = format!("tun: {{{network}}}\nrules: ['MATCH,DIRECT']\n");
            assert!(super::super::Config::parse_yaml(yaml.as_bytes()).is_err());
        }
        assert!(
            RawTunNetworkConfig {
                route_address: vec!["0.0.0.0/0".into(); MAX_NETWORK_ITEMS + 1],
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        let empty = RawTunNetworkConfig {
            inet6_address: Some(Vec::new()),
            ..Default::default()
        }
        .normalize()
        .unwrap();
        assert!(empty.inet6_address.is_empty());
    }
    #[test]
    fn tun_input_interfaces_are_bounded_names_without_interface_discovery() {
        let config = super::super::Config::parse_yaml(
            br#"tun: {include-interface: [lo, absent-veth, lo], exclude-interface: [other-veth]}
rules: ['MATCH,DIRECT']"#,
        )
        .unwrap();
        assert_eq!(config.tun.network.include_interface, ["absent-veth", "lo"]);
        for name in [
            "",
            ".",
            "..",
            "with/slash",
            "bad:name",
            "bad name",
            "1234567890123456",
            "bad\0name",
        ] {
            assert!(interface_names(vec![name.into()]).is_err());
        }
        assert!(
            RawTunNetworkConfig {
                include_interface: vec!["lo".into(); MAX_NETWORK_ITEMS + 1],
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        assert!(super::super::Config::parse_yaml(b"tun: {iproute2-rule-index: 32760}").is_err());
    }
}
