//! Pure route/rule plan. No sockets, interfaces or process state are inspected.
use crate::config::{IpCidr, PortRange, TunConfig, UidRange};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub(super) const MAX_ROUTES: usize = 4096;
pub(super) const RULE_SPAN: u32 = 4;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Route {
    pub ipv6: bool,
    pub index: u32,
    pub table: u32,
    pub destination: IpCidr,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selector {
    Local,
    Uid(UidRange),
    SourcePort(PortRange),
    DestinationPort(PortRange),
    Any,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Table(u32),
    MainNonDefault,
    Goto(u32),
    Unreachable,
    Nop,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rule {
    pub ipv6: bool,
    pub priority: u32,
    pub selector: Selector,
    pub action: Action,
}
pub(super) struct Plan {
    pub routes: Vec<IpCidr>,
    pub rules: Vec<Rule>,
    pub ipv6: bool,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TUN route plan exceeds its bounded system-object budget",
    )
}
impl Plan {
    pub(super) fn new(config: &TunConfig, ipv6: bool) -> io::Result<Self> {
        let options = &config.network;
        let ipv6 = ipv6 && !options.inet6_address.is_empty();
        let mut routes = Vec::new();
        for family in [false, true].into_iter().take(if ipv6 { 2 } else { 1 }) {
            let mut include: Vec<_> = options
                .route_address
                .iter()
                .filter(|p| p.network.is_ipv6() == family)
                .copied()
                .collect();
            if include.is_empty() {
                include.push(IpCidr {
                    network: if family {
                        Ipv6Addr::UNSPECIFIED.into()
                    } else {
                        Ipv4Addr::UNSPECIFIED.into()
                    },
                    prefix_len: 0,
                });
            }
            let exclude: Vec<_> = options
                .route_exclude_address
                .iter()
                .filter(|p| p.network.is_ipv6() == family)
                .copied()
                .collect();
            let selected = route_ranges(include, exclude)?;
            if routes.len() + selected.len() > MAX_ROUTES {
                return Err(invalid());
            }
            routes.extend(selected);
        }
        let excluded = excluded_uids(&options.include_uid, &options.exclude_uid);
        let mut rules = Vec::new();
        let base = options.rule_index;
        for family in [false, true] {
            let available = !family || ipv6;
            if !available && !options.strict_route {
                continue;
            }
            let mut push = |offset, selector, action| {
                rules.push(Rule {
                    ipv6: family,
                    priority: base + offset,
                    selector,
                    action,
                })
            };
            for &range in &options.exclude_src_port {
                push(
                    0,
                    Selector::SourcePort(range),
                    Action::Goto(base + RULE_SPAN),
                );
            }
            for &range in &options.exclude_dst_port {
                push(
                    0,
                    Selector::DestinationPort(range),
                    Action::Goto(base + RULE_SPAN),
                );
            }
            for &range in &excluded {
                push(0, Selector::Uid(range), Action::Goto(base + RULE_SPAN));
            }
            if available {
                // LAN routes stay usable; DNS is first offered to the configured
                // capture table, as in the reference's non-53 main-table rule.
                push(
                    1,
                    Selector::DestinationPort(PortRange { start: 53, end: 53 }),
                    Action::Table(options.table_index),
                );
                push(2, Selector::Local, Action::MainNonDefault);
                push(3, Selector::Local, Action::Table(options.table_index));
            } else {
                // This rejects the uncaptured family for local application
                // traffic, but never the core's protected physical sockets.
                push(1, Selector::Local, Action::Unreachable);
            }
            push(RULE_SPAN, Selector::Any, Action::Nop);
        }
        Ok(Self {
            routes,
            rules,
            ipv6,
        })
    }
}
fn key(prefix: IpCidr) -> (bool, u8, u128) {
    (
        prefix.network.is_ipv6(),
        prefix.prefix_len,
        match prefix.network {
            IpAddr::V4(ip) => u128::from(u32::from(ip)),
            IpAddr::V6(ip) => u128::from(ip),
        },
    )
}
fn canonical(mut prefixes: Vec<IpCidr>) -> Vec<IpCidr> {
    prefixes.sort_unstable_by_key(|prefix| key(*prefix));
    let mut output: Vec<IpCidr> = Vec::new();
    for prefix in prefixes {
        if !output.iter().any(|old| old.contains(prefix.network)) {
            output.push(prefix);
        }
    }
    output
}
fn split(prefix: IpCidr) -> (IpCidr, IpCidr) {
    let length = prefix.prefix_len + 1;
    let second = match prefix.network {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) | (1u32 << (32 - length)))),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) | (1u128 << (128 - length)))),
    };
    (
        IpCidr {
            network: prefix.network,
            prefix_len: length,
        },
        IpCidr {
            network: second,
            prefix_len: length,
        },
    )
}
fn route_ranges(include: Vec<IpCidr>, exclude: Vec<IpCidr>) -> io::Result<Vec<IpCidr>> {
    let mut result = canonical(include);
    for excluded in canonical(exclude) {
        let mut next = Vec::new();
        for mut prefix in result {
            if excluded.contains(prefix.network) && excluded.prefix_len <= prefix.prefix_len {
                continue;
            }
            if !prefix.contains(excluded.network)
                || prefix.network.is_ipv6() != excluded.network.is_ipv6()
            {
                next.push(prefix);
                continue;
            }
            while prefix.prefix_len < excluded.prefix_len {
                let (left, right) = split(prefix);
                let (keep, descend) = if left.contains(excluded.network) {
                    (right, left)
                } else {
                    (left, right)
                };
                if next.len() >= MAX_ROUTES {
                    return Err(invalid());
                }
                next.push(keep);
                prefix = descend;
            }
        }
        if next.len() > MAX_ROUTES {
            return Err(invalid());
        }
        result = next;
    }
    Ok(result)
}
fn merge(mut ranges: Vec<UidRange>) -> Vec<UidRange> {
    ranges.sort_unstable_by_key(|r| (r.start, r.end));
    let mut output: Vec<UidRange> = Vec::new();
    for range in ranges {
        if let Some(last) = output.last_mut()
            && u64::from(range.start) <= u64::from(last.end) + 1
        {
            last.end = last.end.max(range.end);
        } else {
            output.push(range);
        }
    }
    output
}
fn excluded_uids(include: &[UidRange], exclude: &[UidRange]) -> Vec<UidRange> {
    let mut output = exclude.to_vec();
    if !include.is_empty() {
        let mut next = 0u64;
        for range in merge(include.to_vec()) {
            if next < u64::from(range.start) {
                output.push(UidRange {
                    start: next as u32,
                    end: range.start - 1,
                });
            }
            next = next.max(u64::from(range.end) + 1);
        }
        // uid_t(-1) is not a real Linux UID; reference uses MAX-1 too.
        if next < u64::from(u32::MAX) {
            output.push(UidRange {
                start: next as u32,
                end: u32::MAX - 1,
            });
        }
    }
    merge(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cidr(value: &str) -> IpCidr {
        let (ip, bits) = value.split_once('/').unwrap();
        IpCidr {
            network: ip.parse().unwrap(),
            prefix_len: bits.parse().unwrap(),
        }
    }
    #[test]
    fn native_tun_plan_cidr_exclusions_override_more_specific_capture_routes() {
        let output = route_ranges(
            vec![
                cidr("10.0.0.0/8"),
                cidr("10.0.1.0/24"),
                cidr("2001:db8::/32"),
            ],
            vec![cidr("10.0.0.0/16"), cidr("2001:db8:1::/48")],
        )
        .unwrap();
        for (ip, expected) in [
            ("10.0.1.4", false),
            ("10.1.1.4", true),
            ("11.1.1.4", false),
            ("2001:db8:1::4", false),
            ("2001:db8:2::4", true),
        ] {
            assert_eq!(
                output.iter().any(|r| r.contains(ip.parse().unwrap())),
                expected
            );
        }
        assert!(output.len() < 128);
        assert!(
            route_ranges(vec![cidr("0.0.0.0/0")], vec![cidr("0.0.0.0/0")])
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn native_tun_plan_uid_port_and_strict_family_match_only_local_apps() {
        let mut config = TunConfig::default();
        config.network.include_uid = vec![UidRange {
            start: 1001,
            end: 1003,
        }];
        config.network.exclude_uid = vec![UidRange {
            start: 1002,
            end: 1002,
        }];
        config.network.exclude_src_port = vec![PortRange {
            start: 20000,
            end: 20001,
        }];
        config.network.strict_route = true;
        let plan = Plan::new(&config, false).unwrap();
        assert!(
            plan.rules.iter().any(|r| r.ipv6
                && r.action == Action::Unreachable
                && r.selector == Selector::Local)
        );
        for uid in [0, 1000, 1001, 1002, 1003, 1004] {
            let excluded=plan.rules.iter().any(|r|!r.ipv6 && matches!(r.selector,Selector::Uid(range) if (range.start..=range.end).contains(&uid)));
            assert_eq!(excluded, ![1001, 1003].contains(&uid));
        }
        assert!(plan.rules.iter().any(|r| matches!(
            r.selector,
            Selector::SourcePort(PortRange {
                start: 20000,
                end: 20001
            })
        )));
        config.network.inet6_address.clear();
        assert!(!Plan::new(&config, true).unwrap().ipv6);
    }
}
