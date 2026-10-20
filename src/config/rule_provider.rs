//! Immutable provider rule data. MRSv1 is decoded as an interoperable file format.
use super::{
    providers::{RuleBehavior, RuleFormat},
    *,
};
use crate::routing::{GeoMatcher, RoutingContext};
mod domain_set;
use domain_set::DomainSet;
use serde::Deserialize;
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

const MAX_RESOURCE_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCollection {
    behavior: RuleBehavior,
    domains: Arc<DomainSet>,
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
            domains: Arc::new(DomainSet::default()),
            ranges: Vec::new(),
            classical: Vec::new(),
            count: values.len(),
        };
        let mut domains = Vec::new();
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
                    domains.extend(patterns.into_vec());
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
        data.domains = Arc::new(DomainSet::from_patterns(domains)?);
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
        source: bool,
    ) -> std::result::Result<bool, crate::routing::PredicateFailure> {
        match self.behavior {
            RuleBehavior::Domain => Ok(context
                .domain()
                .is_some_and(|name| self.domains.contains(name))),
            RuleBehavior::Ipcidr => {
                let ip = if source {
                    context.source_ip()
                } else {
                    context.effective_ip()
                };
                let Some(ip) = ip else {
                    return if !source && !no_resolve && context.should_request_ip_resolution() {
                        Err(crate::routing::PredicateFailure::NeedsIpResolution)
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
                if source {
                    context.swap_source_destination();
                }
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
    pub(crate) fn matches_ip(
        &self,
        address: std::net::IpAddr,
        geo: &dyn GeoMatcher,
        decision: &super::RuleDecision,
    ) -> std::result::Result<bool, super::MatchFailure> {
        decision.visit()?;
        let destination = crate::session::Destination::Ip(std::net::SocketAddr::new(address, 1));
        let context = RoutingContext::selector(&destination)
            .expect("literal address")
            .with_decision(decision);
        self.matches_selector(&context, geo)
    }
    pub(crate) fn matches_domain(
        &self,
        domain: &str,
        geo: &dyn GeoMatcher,
        decision: &super::RuleDecision,
    ) -> std::result::Result<bool, super::MatchFailure> {
        decision.visit()?;
        let Ok(destination) = crate::session::Destination::domain(domain, 53) else {
            return Ok(false);
        };
        let Ok(context) = RoutingContext::selector(&destination) else {
            return Ok(false);
        };
        let context = context.with_decision(decision);
        self.matches_selector(&context, geo)
    }
    fn matches_selector(
        &self,
        context: &RoutingContext,
        geo: &dyn GeoMatcher,
    ) -> std::result::Result<bool, super::MatchFailure> {
        use crate::routing::PredicateFailure;
        if self.behavior == RuleBehavior::Classical {
            for rule in &self.classical {
                match crate::routing::matches_rule(rule, context, geo) {
                    Ok(true) => return Ok(true),
                    Ok(false)
                    | Err(
                        PredicateFailure::NeedsIpResolution | PredicateFailure::NeedsProcessLookup,
                    ) => {}
                    Err(PredicateFailure::Evaluation(failure)) => return Err(failure),
                }
            }
            Ok(false)
        } else {
            match self.matches(context, geo, true, false) {
                Ok(matched) => Ok(matched),
                Err(PredicateFailure::NeedsIpResolution | PredicateFailure::NeedsProcessLookup) => {
                    Ok(false)
                }
                Err(PredicateFailure::Evaluation(failure)) => Err(failure),
            }
        }
    }
}

fn corrupt() -> VoleError {
    VoleError::InvalidConfig("invalid MRSv1 rule provider".into())
}
struct MrsReader<R> {
    input: R,
    remaining: usize,
}
impl<R: Read> MrsReader<R> {
    fn read<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() > self.remaining {
            return Err(corrupt());
        }
        self.input.read_exact(bytes).map_err(|_| corrupt())?;
        self.remaining -= bytes.len();
        Ok(())
    }
    fn length(&mut self, unit: usize) -> Result<usize> {
        let n = usize::try_from(i64::from_be_bytes(self.read()?)).map_err(|_| corrupt())?;
        if n > self.remaining / unit {
            return Err(corrupt());
        }
        Ok(n)
    }
    fn words(&mut self) -> Result<Vec<u64>> {
        let count = self.length(8)?;
        let mut words = Vec::new();
        self.chunks(count * 8, |bytes| {
            words.extend(
                bytes
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .copied()
                    .map(u64::from_be_bytes),
            );
        })?;
        Ok(words)
    }
    fn bytes(&mut self, count: usize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.chunks(count, |block| bytes.extend_from_slice(block))?;
        Ok(bytes)
    }
    // Length declarations are untrusted. Grow output only after each complete
    // block is available, so a short truncated stream cannot reserve its whole
    // declared array before EOF is discovered. The block size is divisible by
    // eight for the word-array decoder.
    fn chunks(&mut self, mut bytes: usize, mut consume: impl FnMut(&[u8])) -> Result<()> {
        if bytes > self.remaining {
            return Err(corrupt());
        }
        let mut block = [0_u8; 8192];
        while bytes != 0 {
            let len = bytes.min(block.len());
            self.read_exact(&mut block[..len])?;
            consume(&block[..len]);
            bytes -= len;
        }
        Ok(())
    }
    fn skip(&mut self, mut bytes: usize) -> Result<()> {
        let mut block = [0_u8; 8192];
        while bytes != 0 {
            let len = bytes.min(block.len());
            self.read_exact(&mut block[..len])?;
            bytes -= len;
        }
        Ok(())
    }
    fn finish(mut self) -> Result<()> {
        if self.input.read(&mut [0]).map_err(|_| corrupt())? != 0 {
            return Err(corrupt());
        }
        Ok(())
    }
}
fn parse_mrs(bytes: &[u8], behavior: RuleBehavior) -> Result<RuleCollection> {
    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|_| corrupt())?;
    let mut input = MrsReader {
        input: decoder,
        remaining: MAX_RESOURCE_BYTES,
    };
    if input.read::<4>()? != *b"MRS\x01" {
        return Err(corrupt());
    }
    let expected = match behavior {
        RuleBehavior::Domain => 0,
        RuleBehavior::Ipcidr => 1,
        RuleBehavior::Classical => return Err(corrupt()),
    };
    if input.read::<1>()?[0] != expected {
        return Err(corrupt());
    }
    let count = usize::try_from(i64::from_be_bytes(input.read()?)).map_err(|_| corrupt())?;
    let extra = input.length(1)?;
    input.skip(extra)?;
    if input.read::<1>()? != [1] {
        return Err(corrupt());
    }
    let mut data = RuleCollection::from_payload(Vec::new(), behavior)?;
    data.count = count;
    if behavior == RuleBehavior::Ipcidr {
        let n = input.length(32)?;
        for _ in 0..n {
            let convert = |bytes| {
                let ip = Ipv6Addr::from(bytes);
                ip.to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(ip))
            };
            let start = convert(input.read::<16>()?);
            let end = convert(input.read::<16>()?);
            if start.is_ipv4() != end.is_ipv4() || start > end {
                return Err(corrupt());
            }
            data.ranges.push((start, end));
        }
        data.merge_ranges();
    } else {
        let leaves = input.words()?;
        let bitmap = input.words()?;
        let n = input.length(1)?;
        let labels = input.bytes(n)?;
        data.domains = Arc::new(DomainSet::from_mrs(leaves, bitmap, labels)?);
    }
    input.finish()?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_provider_keeps_normalization_input_count_and_generation_snapshots() {
        let first = Arc::new(
            RuleCollection::from_payload(
                vec![
                    "API.Example.COM".into(),
                    ".example.com".into(),
                    "API.EXAMPLE.COM".into(),
                    "é.test".into(),
                ],
                RuleBehavior::Domain,
            )
            .unwrap(),
        );
        let existing = Arc::clone(&first);
        let next = Arc::new(
            RuleCollection::from_payload(vec!["next.test".into()], RuleBehavior::Domain).unwrap(),
        );
        assert_eq!(first.len(), 4);
        let matches = |set: &RuleCollection, domain| {
            set.matches_domain(
                domain,
                &crate::routing::EmptyGeoMatcher,
                &Default::default(),
            )
            .unwrap()
        };
        assert!(matches(&existing, "api.example.com"));
        assert!(matches(&existing, "www.example.com"));
        assert!(!matches(&existing, "example.com"));
        // Preserve current selector normalization: Unicode patterns are lower
        // cased, while query destinations are independently normalized to IDNA.
        assert!(!matches(&existing, "é.test"));
        assert!(!matches(&existing, "xn--9ca.test"));
        assert!(!matches(&existing, "next.test"));
        assert!(matches(&next, "next.test"));
        for invalid in ["foo/bar", "one.test,two.test", "foo*bar.test", "geosite:cn"] {
            assert!(
                RuleCollection::from_payload(vec![invalid.into()], RuleBehavior::Domain).is_err()
            );
        }
    }

    #[test]
    fn mrs_stream_reader_keeps_cumulative_limit_and_rejects_trailing_or_truncated_data() {
        let mut reader = MrsReader {
            input: &b"abcdefgh"[..],
            remaining: 7,
        };
        assert_eq!(reader.read::<4>().unwrap(), *b"abcd");
        assert!(reader.read::<4>().is_err());
        reader.skip(3).unwrap();
        assert!(reader.finish().is_err());
        let mut reader = MrsReader {
            input: &b"abc"[..],
            remaining: 3,
        };
        assert_eq!(reader.read::<3>().unwrap(), *b"abc");
        reader.finish().unwrap();

        let mut bytes = b"MRS\x01".to_vec();
        bytes.push(0);
        bytes.extend(97_i64.to_be_bytes());
        bytes.extend(0_i64.to_be_bytes());
        bytes.push(1);
        // A single exact 'a' domain. Header count remains the writer's input
        // count, which need not equal the number of unique stored terminals.
        bytes.extend(1_i64.to_be_bytes());
        bytes.extend(2_u64.to_be_bytes());
        bytes.extend(1_i64.to_be_bytes());
        bytes.extend(6_u64.to_be_bytes());
        bytes.extend(1_i64.to_be_bytes());
        bytes.push(b'a');
        let compressed = zstd::encode_all(bytes.as_slice(), 1).unwrap();
        let set =
            RuleCollection::parse(&compressed, RuleBehavior::Domain, RuleFormat::Mrs).unwrap();
        assert_eq!(set.len(), 97);
        for cut in [0, 4, 13, bytes.len() - 1] {
            let truncated = zstd::encode_all(&bytes[..cut], 1).unwrap();
            assert!(
                RuleCollection::parse(&truncated, RuleBehavior::Domain, RuleFormat::Mrs).is_err()
            );
        }
        bytes.push(0);
        let trailing = zstd::encode_all(bytes.as_slice(), 1).unwrap();
        assert!(RuleCollection::parse(&trailing, RuleBehavior::Domain, RuleFormat::Mrs).is_err());
    }

    #[test]
    fn mrs_truncated_large_arrays_only_retain_successfully_read_blocks() {
        let actual = vec![0_u8; 8200];
        let mut reader = MrsReader {
            input: actual.as_slice(),
            remaining: MAX_RESOURCE_BYTES,
        };
        let mut retained = Vec::new();
        assert!(
            reader
                .chunks(MAX_RESOURCE_BYTES - 8, |block| {
                    retained.extend_from_slice(block)
                })
                .is_err()
        );
        assert_eq!(retained.len(), 8192);
        assert!(retained.capacity() <= actual.len());
        assert_eq!(reader.remaining, MAX_RESOURCE_BYTES - retained.len());

        let mut header = b"MRS\x01".to_vec();
        header.push(0);
        header.extend(1_i64.to_be_bytes());
        header.extend(0_i64.to_be_bytes());
        header.push(1);
        let mut missing_words = header.clone();
        missing_words.extend(((MAX_RESOURCE_BYTES / 8 - 16) as i64).to_be_bytes());
        let compressed = zstd::encode_all(missing_words.as_slice(), 1).unwrap();
        assert!(RuleCollection::parse(&compressed, RuleBehavior::Domain, RuleFormat::Mrs).is_err());
        // Valid one-word arrays followed by a large label declaration and EOF.
        for word in [2_u64, 6_u64] {
            header.extend(1_i64.to_be_bytes());
            header.extend(word.to_be_bytes());
        }
        header.extend(((MAX_RESOURCE_BYTES - 128) as i64).to_be_bytes());
        let compressed = zstd::encode_all(header.as_slice(), 1).unwrap();
        assert!(RuleCollection::parse(&compressed, RuleBehavior::Domain, RuleFormat::Mrs).is_err());
    }

    #[test]
    fn classical_selectors_keep_complete_logical_domain_and_ip_predicates() {
        let geo = crate::routing::EmptyGeoMatcher;
        for (payload, matched, unmatched) in [
            (
                "AND,((DOMAIN-SUFFIX,example),(DOMAIN-KEYWORD,api))",
                "api.example",
                "www.example",
            ),
            (
                "OR,((DOMAIN,api.example),(AND,((DOMAIN-SUFFIX,example),(NOT,((DOMAIN,skip.example))))))",
                "www.example",
                "skip.example",
            ),
            ("NOT,((DOMAIN,skip.example))", "api.example", "skip.example"),
        ] {
            let set = RuleCollection::from_payload(vec![payload.into()], RuleBehavior::Classical)
                .unwrap();
            assert_eq!(
                set.matches_domain(matched, &geo, &Default::default()),
                Ok(true)
            );
            assert_eq!(
                set.matches_domain(unmatched, &geo, &Default::default()),
                Ok(false)
            );
        }
        for (payload, matched, unmatched) in [
            (
                "AND,((IP-CIDR,192.0.2.0/24),(NOT,((IP-CIDR,192.0.2.7/32))))",
                "192.0.2.1",
                "192.0.2.7",
            ),
            (
                "OR,((IP-CIDR,192.0.2.0/24),(IP-SUFFIX,198.51.100.1/8))",
                "198.51.100.1",
                "198.51.100.2",
            ),
            ("NOT,((IP-CIDR,192.0.2.0/24))", "198.51.100.1", "192.0.2.1"),
            (
                "AND,((IP-CIDR6,2001:db8::/32),(NOT,((IP-SUFFIX,::7/8))))",
                "2001:db8::1",
                "2001:db8::7",
            ),
            (
                "OR,((IP-CIDR6,2001:db8::/32),(IP-SUFFIX,::1/8))",
                "2001:db9::1",
                "2001:db9::2",
            ),
            (
                "NOT,((IP-CIDR6,2001:db8::/32))",
                "2001:db9::1",
                "2001:db8::1",
            ),
        ] {
            let set = RuleCollection::from_payload(vec![payload.into()], RuleBehavior::Classical)
                .unwrap();
            assert_eq!(
                set.matches_ip(matched.parse().unwrap(), &geo, &Default::default()),
                Ok(true)
            );
            assert_eq!(
                set.matches_ip(unmatched.parse().unwrap(), &geo, &Default::default()),
                Ok(false)
            );
        }
        // Reference selectors evaluate the complete expression using their
        // zero metadata; a missing source predicate is false and NOT is true.
        for payload in [
            "AND,((DOMAIN,api.example),(NETWORK,TCP))",
            "OR,((DOMAIN,api.example),(DST-PORT,53))",
            "NOT,((SRC-IP-CIDR,192.0.2.0/24))",
        ] {
            let set = RuleCollection::from_payload(vec![payload.into()], RuleBehavior::Classical)
                .unwrap();
            assert_eq!(
                set.matches_domain("api.example", &geo, &Default::default()),
                Ok(true)
            );
        }
        for payload in [
            "AND,((IP-CIDR,192.0.2.0/24),(NETWORK,TCP))",
            "OR,((IP-CIDR,192.0.2.0/24),(DOMAIN,api.example))",
            "NOT,((SRC-IP-CIDR,198.51.100.0/24))",
        ] {
            let set = RuleCollection::from_payload(vec![payload.into()], RuleBehavior::Classical)
                .unwrap();
            assert_eq!(
                set.matches_ip("192.0.2.1".parse().unwrap(), &geo, &Default::default()),
                Ok(true)
            );
        }
    }

    #[test]
    fn classical_selector_uses_zero_metadata_without_business_ingress_or_resolution() {
        let geo = crate::routing::EmptyGeoMatcher;
        for (payload, expected) in [
            ("AND,((DOMAIN,api.example),(DST-PORT,0))", true),
            ("AND,((DOMAIN,api.example),(DST-PORT,53))", false),
            ("AND,((DOMAIN,api.example),(NETWORK,TCP))", true),
            ("AND,((DOMAIN,api.example),(NETWORK,UDP))", false),
            ("AND,((DOMAIN,api.example),(IN-TYPE,HTTP))", true),
            ("AND,((DOMAIN,api.example),(IN-TYPE,INNER))", false),
            ("AND,((DOMAIN,api.example),(IN-NAME,DEFAULT-MIXED))", false),
            ("AND,((DOMAIN,api.example),(IN-NAME,DEFAULT-TUN))", false),
            ("AND,((DOMAIN,api.example),(IN-PORT,0))", true),
            ("NOT,((IP-CIDR,192.0.2.0/24))", true),
            ("NOT,((PROCESS-NAME,synthetic))", true),
        ] {
            let set = RuleCollection::from_payload(vec![payload.into()], RuleBehavior::Classical)
                .unwrap();
            assert_eq!(
                set.matches_domain("api.example", &geo, &Default::default()),
                Ok(expected),
                "{payload}"
            );
        }
        for (payload, expected) in [
            ("AND,((IP-CIDR,192.0.2.0/24),(DST-PORT,0))", true),
            ("AND,((IP-CIDR,192.0.2.0/24),(DST-PORT,1))", false),
            ("AND,((IP-CIDR,192.0.2.0/24),(SRC-PORT,0))", true),
            ("AND,((IP-CIDR,192.0.2.0/24),(IN-TYPE,HTTP))", true),
        ] {
            let set = RuleCollection::from_payload(vec![payload.into()], RuleBehavior::Classical)
                .unwrap();
            assert_eq!(
                set.matches_ip("192.0.2.1".parse().unwrap(), &geo, &Default::default()),
                Ok(expected),
                "{payload}"
            );
        }
    }

    #[test]
    fn ingress_source_rule_set_swaps_address_ports_but_keeps_host_and_identity() {
        use crate::session::{InboundKind, InboundMetadata};
        let destination = crate::session::Destination::domain("host.example", 443).unwrap();
        let mut context = RoutingContext::new(Network::Tcp, &destination).unwrap();
        context.set_source("192.0.2.1:1234".parse().unwrap());
        context.set_inbound(
            InboundKind::Https,
            &InboundMetadata {
                local_port: 1080,
                user: Some("Alice".into()),
                ..Default::default()
            },
        );
        let before = context.clone();
        let geo = crate::routing::EmptyGeoMatcher;
        let classical = RuleCollection::from_payload(vec![
            "AND,((IP-CIDR,192.0.2.0/24),(DST-PORT,1234),(SRC-PORT,443),(DOMAIN,host.example),(IN-TYPE,HTTPS),(IN-PORT,1080),(IN-USER,Alice))".into()
        ], RuleBehavior::Classical).unwrap();
        assert_eq!(classical.matches(&context, &geo, true, true), Ok(true));
        assert_eq!(classical.matches(&context, &geo, true, false), Ok(false));
        // Source port remains available while the domain target has no resolved IP.
        let source_ip = RuleCollection::from_payload(
            vec!["SRC-IP-CIDR,203.0.113.0/24".into()],
            RuleBehavior::Classical,
        )
        .unwrap();
        assert_eq!(source_ip.matches(&context, &geo, true, true), Ok(false));
        context.pin_ip("203.0.113.1".parse().unwrap());
        assert_eq!(source_ip.matches(&context, &geo, true, true), Ok(true));
        context = before.clone();
        for (behavior, payload) in [
            (RuleBehavior::Domain, "host.example"),
            (RuleBehavior::Ipcidr, "192.0.2.0/24"),
        ] {
            let set = RuleCollection::from_payload(vec![payload.into()], behavior).unwrap();
            assert_eq!(set.matches(&context, &geo, true, true), Ok(true));
        }
        assert_eq!(context, before);
    }

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
                mrs.matches_domain(
                    domain,
                    &crate::routing::EmptyGeoMatcher,
                    &Default::default()
                ),
                yaml.matches_domain(
                    domain,
                    &crate::routing::EmptyGeoMatcher,
                    &Default::default()
                )
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
