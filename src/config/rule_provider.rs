//! Immutable provider rule data. MRSv1 is decoded as an interoperable file format.
use super::{
    providers::{RuleBehavior, RuleFormat},
    *,
};
use crate::{
    dns::policy::DomainIndex,
    routing::{GeoMatcher, RoutingContext},
};
use serde::Deserialize;
use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

const MAX_RESOURCE_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCollection {
    behavior: RuleBehavior,
    domains: Arc<DomainIndex>,
    ranges: Vec<(IpAddr, IpAddr)>,
    pub(crate) classical: Vec<RuleSpec>,
    count: usize,
}
impl RuleCollection {
    pub fn behavior(&self) -> RuleBehavior {
        self.behavior
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub(crate) fn uses_ip(&self) -> bool {
        self.behavior == RuleBehavior::Ipcidr
            || self
                .classical
                .iter()
                .any(crate::routing::uses_destination_ip)
    }
    pub(crate) fn uses_domain(&self) -> bool {
        self.behavior != RuleBehavior::Ipcidr
    }
    pub fn parse(bytes: &[u8], behavior: RuleBehavior, format: RuleFormat) -> Result<Self> {
        if bytes.len() > MAX_RESOURCE_BYTES {
            return invalid("rule provider exceeds parser byte limit");
        }
        if format == RuleFormat::Mrs {
            return parse_mrs(bytes, behavior);
        }
        let values = match format {
            RuleFormat::Yaml => {
                #[derive(Deserialize)]
                struct Payload {
                    payload: Vec<String>,
                }
                let payload: Payload = serde_yaml_ng::from_value(yaml::parse(bytes)?)
                    .map_err(|_| VoleError::InvalidConfig("invalid rule provider YAML".into()))?;
                payload.payload
            }
            RuleFormat::Text => std::str::from_utf8(bytes)
                .map_err(|_| VoleError::InvalidConfig("rule provider text requires UTF-8".into()))?
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .map(str::to_owned)
                .collect(),
            RuleFormat::Mrs => unreachable!(),
        };
        Self::from_payload(values, behavior)
    }
    pub fn from_payload(values: Vec<String>, behavior: RuleBehavior) -> Result<Self> {
        let mut data = Self {
            behavior,
            domains: Arc::new(DomainIndex::new()),
            ranges: Vec::new(),
            classical: Vec::new(),
            count: values.len(),
        };
        for value in values {
            match behavior {
                RuleBehavior::Domain => {
                    let selector = normalize_dns_policy_selector(&value)?;
                    let DnsPolicySelector::Domains(patterns) = selector else {
                        return invalid("domain provider requires domain patterns");
                    };
                    if value.contains('/') || patterns.len() != 1 {
                        return invalid("invalid rule provider domain");
                    }
                    Arc::get_mut(&mut data.domains)
                        .unwrap()
                        .insert(&patterns[0], 0);
                }
                RuleBehavior::Ipcidr => {
                    let cidr = parse_ip_cidr(&value, value.contains(':'))?;
                    let (start, width) = match cidr.network {
                        IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32u8),
                        IpAddr::V6(ip) => (u128::from(ip), 128u8),
                    };
                    let host_bits = width - cidr.prefix_len;
                    let mask = if host_bits == 128 {
                        u128::MAX
                    } else {
                        (1u128 << host_bits) - 1
                    };
                    let a = start & !mask;
                    let b = a | mask;
                    data.ranges.push(if width == 32 {
                        (
                            Ipv4Addr::from(a as u32).into(),
                            Ipv4Addr::from(b as u32).into(),
                        )
                    } else {
                        (Ipv6Addr::from(a).into(), Ipv6Addr::from(b).into())
                    });
                }
                RuleBehavior::Classical => {
                    let kind = value
                        .split(',')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_uppercase();
                    if ["MATCH", "RULE-SET", "SUB-RULE"].contains(&kind.as_str()) {
                        return invalid("unsupported classical provider rule");
                    }
                    data.classical.push(rules::parse_predicate(&value)?);
                }
            }
        }
        // Reuse normal compilation to validate classical matcher semantics.
        crate::routing::RuleSet::compile(data.classical.clone())
            .map_err(|_| VoleError::InvalidConfig("invalid classical provider rules".into()))?;
        data.merge_ranges();
        Ok(data)
    }
    fn merge_ranges(&mut self) {
        self.ranges.sort_unstable();
        let mut merged: Vec<(IpAddr, IpAddr)> = Vec::new();
        for (start, end) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && start.is_ipv4() == last.0.is_ipv4()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        self.ranges = merged;
    }
    pub(crate) fn matches(
        &self,
        context: &RoutingContext,
        geo: &dyn GeoMatcher,
        no_resolve: bool,
    ) -> std::result::Result<bool, ()> {
        match self.behavior {
            RuleBehavior::Domain => Ok(context
                .domain()
                .is_some_and(|name| self.domains.find(0, name).is_some())),
            RuleBehavior::Ipcidr => {
                let Some(ip) = context.effective_ip() else {
                    return if !no_resolve && context.should_request_ip_resolution() {
                        Err(())
                    } else {
                        Ok(false)
                    };
                };
                let index = self.ranges.partition_point(|(start, _)| *start <= ip);
                Ok(index > 0
                    && self.ranges[index - 1].0.is_ipv4() == ip.is_ipv4()
                    && ip <= self.ranges[index - 1].1)
            }
            RuleBehavior::Classical => {
                let mut context = context.clone();
                if no_resolve {
                    context.disable_ip_resolution();
                }
                for rule in &self.classical {
                    if crate::routing::matches_rule(rule, &context, geo)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
    pub(crate) fn matches_ip(&self, address: std::net::IpAddr, geo: &dyn GeoMatcher) -> bool {
        let destination = crate::session::Destination::Ip(std::net::SocketAddr::new(address, 1));
        let context = RoutingContext::new(Network::Tcp, &destination).expect("literal address");
        if self.behavior == RuleBehavior::Classical {
            self.classical.iter().any(|rule| {
                matches!(rule.kind, RuleKind::IpCidr(_) | RuleKind::GeoIp(_))
                    && crate::routing::matches_rule(rule, &context, geo).unwrap_or(false)
            })
        } else {
            self.matches(&context, geo, true).unwrap_or(false)
        }
    }
    pub(crate) fn matches_domain(&self, domain: &str, geo: &dyn GeoMatcher) -> bool {
        let Ok(destination) = crate::session::Destination::domain(domain, 53) else {
            return false;
        };
        let Ok(context) = RoutingContext::new(Network::Tcp, &destination) else {
            return false;
        };
        // DNS policy uses domain predicates only, never port/IP/source criteria.
        if self.behavior == RuleBehavior::Classical {
            self.classical.iter().any(|rule| {
                matches!(
                    rule.kind,
                    RuleKind::Domain(_)
                        | RuleKind::DomainSuffix(_)
                        | RuleKind::DomainKeyword(_)
                        | RuleKind::DomainWildcard(_)
                        | RuleKind::DomainRegex(_)
                        | RuleKind::GeoSite(_)
                ) && crate::routing::matches_rule(rule, &context, geo).unwrap_or(false)
            })
        } else {
            self.matches(&context, geo, true).unwrap_or(false)
        }
    }
}

fn corrupt() -> VoleError {
    VoleError::InvalidConfig("invalid MRSv1 rule provider".into())
}
fn read<const N: usize>(reader: &mut Cursor<Vec<u8>>) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes).map_err(|_| corrupt())?;
    Ok(bytes)
}
fn length(reader: &mut Cursor<Vec<u8>>, unit: usize) -> Result<usize> {
    let n = usize::try_from(i64::from_be_bytes(read(reader)?)).map_err(|_| corrupt())?;
    let remaining = reader
        .get_ref()
        .len()
        .saturating_sub(reader.position() as usize);
    if n > remaining / unit {
        return Err(corrupt());
    }
    Ok(n)
}
fn words(reader: &mut Cursor<Vec<u8>>) -> Result<Vec<u64>> {
    let n = length(reader, 8)?;
    (0..n)
        .map(|_| read(reader).map(u64::from_be_bytes))
        .collect()
}
fn parse_mrs(bytes: &[u8], behavior: RuleBehavior) -> Result<RuleCollection> {
    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|_| corrupt())?;
    let mut decoded = Vec::new();
    decoder
        .take((MAX_RESOURCE_BYTES + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|_| corrupt())?;
    if decoded.len() > MAX_RESOURCE_BYTES {
        return Err(corrupt());
    }
    let mut input = Cursor::new(decoded);
    if read::<4>(&mut input)? != *b"MRS\x01" {
        return Err(corrupt());
    }
    let expected = match behavior {
        RuleBehavior::Domain => 0,
        RuleBehavior::Ipcidr => 1,
        RuleBehavior::Classical => return Err(corrupt()),
    };
    if read::<1>(&mut input)?[0] != expected {
        return Err(corrupt());
    }
    let count = usize::try_from(i64::from_be_bytes(read(&mut input)?)).map_err(|_| corrupt())?;
    let extra = length(&mut input, 1)?;
    input.set_position(input.position() + extra as u64);
    if read::<1>(&mut input)? != [1] {
        return Err(corrupt());
    }
    let mut data = RuleCollection::from_payload(Vec::new(), behavior)?;
    data.count = count;
    if behavior == RuleBehavior::Ipcidr {
        let n = length(&mut input, 32)?;
        for _ in 0..n {
            let convert = |bytes| {
                let ip = Ipv6Addr::from(bytes);
                ip.to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(ip))
            };
            let start = convert(read::<16>(&mut input)?);
            let end = convert(read::<16>(&mut input)?);
            if start.is_ipv4() != end.is_ipv4() || start > end {
                return Err(corrupt());
            }
            data.ranges.push((start, end));
        }
        data.merge_ranges();
    } else {
        let leaves = words(&mut input)?;
        let bitmap = words(&mut input)?;
        let n = length(&mut input, 1)?;
        let mut labels = vec![0; n];
        input.read_exact(&mut labels).map_err(|_| corrupt())?;
        let bit = |bits: &[u64], i: usize| {
            bits.get(i / 64)
                .is_some_and(|w| w & (1u64 << (i % 64)) != 0)
        };
        let nodes = n.checked_add(1).ok_or_else(corrupt)?;
        if leaves.len().saturating_mul(64) < nodes {
            return Err(corrupt());
        }
        // LOUDS stores every node's outgoing labels, followed by a one bit.
        let mut edges = Vec::with_capacity(nodes);
        let (mut position, mut label) = (0usize, 0usize);
        for _ in 0..nodes {
            let start = label;
            while position < bitmap.len() * 64 && !bit(&bitmap, position) {
                position += 1;
                label += 1;
                if label > n {
                    return Err(corrupt());
                }
            }
            if position >= bitmap.len() * 64 {
                return Err(corrupt());
            }
            position += 1;
            edges.push(start..label);
        }
        if label != n {
            return Err(corrupt());
        }
        let mut stack = vec![(0usize, Vec::<u8>::new())];
        while let Some((node, key)) = stack.pop() {
            if key.len() > 253 {
                return Err(corrupt());
            }
            if bit(&leaves, node) {
                let key = std::str::from_utf8(&key)
                    .map_err(|_| corrupt())?
                    .trim_end_matches('+');
                let domain: String = key.chars().rev().collect();
                Arc::get_mut(&mut data.domains).unwrap().insert(&domain, 0);
            }
            for edge in edges[node].clone().rev() {
                let child = edge + 1;
                if child <= node || child >= nodes {
                    return Err(corrupt());
                }
                let mut next = key.clone();
                next.push(labels[edge]);
                stack.push((child, next));
            }
        }
    }
    if input.position() != input.get_ref().len() as u64 {
        return Err(corrupt());
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mrs_domain_and_ip_ranges_match_yaml_and_text() {
        fn header(behavior: u8) -> Vec<u8> {
            let mut bytes = b"MRS\x01".to_vec();
            bytes.push(behavior);
            bytes.extend(1i64.to_be_bytes());
            bytes.extend(0i64.to_be_bytes());
            bytes.push(1);
            bytes
        }
        let mut bytes = header(0);
        let labels = b"tset.cba";
        bytes.extend(1i64.to_be_bytes());
        bytes.extend((1u64 << labels.len()).to_be_bytes());
        bytes.extend(1i64.to_be_bytes());
        let bitmap =
            (0..labels.len()).fold(1u64 << (labels.len() * 2), |b, i| b | (1 << (i * 2 + 1)));
        bytes.extend(bitmap.to_be_bytes());
        bytes.extend((labels.len() as i64).to_be_bytes());
        bytes.extend(labels);
        let compressed = zstd::encode_all(bytes.as_slice(), 1).unwrap();
        let mrs =
            RuleCollection::parse(&compressed, RuleBehavior::Domain, RuleFormat::Mrs).unwrap();
        let yaml = RuleCollection::parse(
            b"payload: [abc.test]",
            RuleBehavior::Domain,
            RuleFormat::Yaml,
        )
        .unwrap();
        for domain in ["abc.test", "no.test", "www.abc.test"] {
            assert_eq!(
                mrs.matches_domain(domain, &crate::routing::EmptyGeoMatcher),
                yaml.matches_domain(domain, &crate::routing::EmptyGeoMatcher)
            );
        }
        let mut bytes = header(1);
        bytes.extend(1i64.to_be_bytes());
        for ip in [Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 255, 255, 255)] {
            bytes.extend(ip.to_ipv6_mapped().octets());
        }
        let compressed = zstd::encode_all(bytes.as_slice(), 1).unwrap();
        let mrs =
            RuleCollection::parse(&compressed, RuleBehavior::Ipcidr, RuleFormat::Mrs).unwrap();
        let text = RuleCollection::parse(
            b"# private\n10.0.0.0/8\n",
            RuleBehavior::Ipcidr,
            RuleFormat::Text,
        )
        .unwrap();
        assert_eq!(mrs.ranges, text.ranges);
        assert!(RuleCollection::parse(&compressed, RuleBehavior::Domain, RuleFormat::Mrs).is_err());
    }
}
