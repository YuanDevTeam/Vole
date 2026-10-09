//! Allocation-free runtime matching for Vole routing rules.
//!
//! Rule parsing and structural validation belong to [`crate::config`]. This
//! module performs a second, deliberately small compilation step: textual
//! match values are normalized once and the resulting ordered rule set can be
//! evaluated without allocating for each rule.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use crate::{
    config::{IpCidr, Network, RuleAction, RuleKind, RuleSpec},
    session::Destination,
};

mod dispatcher;
mod proxy_group;

pub(crate) use dispatcher::RouteTargetDispatchers;
pub use dispatcher::{ProxyDispatchers, RoutingDispatcher};
pub(crate) use proxy_group::{
    ProxyGroupError, ProxyGroupState, ProxyGroups, ResolvedProxyGroupLeaf,
};

/// Defensive runtime ceiling, independent from the configuration parser.
pub const MAX_ROUTING_RULES: usize = crate::config::MAX_RULES;
/// Total owned bytes used by textual values in one rule set.
pub const MAX_RULE_TEXT_BYTES: usize = crate::config::MAX_RULES_TOTAL_BYTES;

/// A prepared routing context. Domain normalization happens only while this
/// value is built; matching the context does not allocate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingContext {
    network: Network,
    destination_port: u16,
    source: Option<SocketAddr>,
    normalized_domain: Option<Box<str>>,
    destination_ip: Option<IpAddr>,
    pinned_ip: Option<IpAddr>,
    ip_resolution_unavailable: bool,
}

impl RoutingContext {
    /// Builds a context from the original destination without a redir-host
    /// domain hint.
    pub fn new(network: Network, destination: &Destination) -> Result<Self, DomainNameError> {
        Self::with_domain_hint(network, destination, None)
    }

    /// Builds a context and, for an IP destination, optionally attaches a
    /// redir-host domain hint. A domain destination always takes precedence
    /// over the hint.
    pub fn with_domain_hint(
        network: Network,
        destination: &Destination,
        domain_hint: Option<&str>,
    ) -> Result<Self, DomainNameError> {
        let (normalized_domain, destination_ip) = match destination {
            Destination::Domain { host, .. } => {
                (Some(normalize_domain_name(host)?.into_boxed_str()), None)
            }
            Destination::Ip(address) => (
                domain_hint
                    // redir-host is only a best-effort annotation for an
                    // already valid literal destination. DNS wire names are
                    // slightly broader than host names (for example they may
                    // contain `_`), so an unusable hint must not turn the
                    // literal IP itself into an unreachable destination.
                    .and_then(|hint| normalize_domain_name(hint).ok())
                    .map(String::into_boxed_str),
                Some(address.ip()),
            ),
        };

        Ok(Self {
            network,
            destination_port: destination.port(),
            source: None,
            normalized_domain,
            destination_ip,
            pinned_ip: None,
            ip_resolution_unavailable: false,
        })
    }

    pub(crate) fn disable_ip_resolution(&mut self) {
        self.ip_resolution_unavailable = true;
    }

    pub fn set_source(&mut self, source: SocketAddr) {
        self.source = Some(source);
    }

    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    #[must_use]
    pub const fn destination_port(&self) -> u16 {
        self.destination_port
    }

    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.normalized_domain.as_deref()
    }

    /// Returns an IP selected by runtime DNS, or the literal destination IP.
    #[must_use]
    pub fn effective_ip(&self) -> Option<IpAddr> {
        self.pinned_ip.or(self.destination_ip)
    }

    #[must_use]
    pub const fn pinned_ip(&self) -> Option<IpAddr> {
        self.pinned_ip
    }

    /// Pins the address chosen by a lazy DNS decision. The caller must keep
    /// this context with the selected TCP session or UDP datagram.
    pub fn pin_ip(&mut self, address: IpAddr) {
        self.pinned_ip = Some(address);
        self.ip_resolution_unavailable = false;
    }

    /// Marks lazy runtime DNS unavailable or exhausted for this decision. IP
    /// rules then fall through instead of repeatedly requesting resolution.
    pub fn mark_ip_resolution_unavailable(&mut self) {
        self.ip_resolution_unavailable = true;
    }

    #[must_use]
    pub(crate) fn should_request_ip_resolution(&self) -> bool {
        self.destination_ip.is_none() && self.pinned_ip.is_none() && !self.ip_resolution_unavailable
    }
}

/// Normalization failure for a domain destination or redir-host hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainNameError {
    Empty,
    InvalidIdna,
}

impl fmt::Display for DomainNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "domain name is empty",
            Self::InvalidIdna => "domain name is not a valid UTS #46/STD3 DNS name",
        })
    }
}

impl std::error::Error for DomainNameError {}

/// Applies UTS #46 non-transitional processing with STD3 and DNS length checks,
/// then stores the canonical lower-case ASCII A-label form without one final
/// root dot.
///
/// Xray-compatible GeoData also contains a small number of already-ASCII DNS
/// labels whose `xn--` prefix is not valid Punycode. DNS transports still treat
/// those labels as opaque ASCII, so a syntactically valid ASCII DNS name is
/// accepted as a compatibility fallback instead of making the whole GeoData
/// category unusable.
pub(crate) fn normalize_domain_name(value: &str) -> Result<String, DomainNameError> {
    if value.is_empty() {
        return Err(DomainNameError::Empty);
    }

    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() {
        return Err(DomainNameError::Empty);
    }
    let mut ascii = match idna::domain_to_ascii_strict(value) {
        Ok(ascii) => ascii,
        Err(_) if valid_opaque_ascii_dns_name(value) => value.to_owned(),
        Err(_) => return Err(DomainNameError::InvalidIdna),
    };
    ascii.make_ascii_lowercase();
    Ok(ascii)
}

fn valid_opaque_ascii_dns_name(value: &str) -> bool {
    value.is_ascii()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// GeoData lookup boundary. The empty implementation deliberately never
/// matches, allowing the base rule engine to ship before the bounded GeoData
/// loader without treating absent data as an error or wildcard.
pub trait GeoMatcher: Send + Sync {
    /// Captures one immutable view for a whole routing decision. Changed
    /// contents require a new view, never interior mutation of the snapshot.
    /// Unknown or mutable providers may return None. Established TUN IP UDP
    /// flows pin their action independently of later matcher updates.
    fn routing_snapshot(&self) -> Option<Arc<dyn GeoMatcher>> {
        None
    }

    /// Whether a prepared GeoSite category is currently available.
    ///
    /// The default preserves existing complete matchers. Dynamic or empty
    /// matchers override this so a dormant GeoData rule has no side effects.
    fn geosite_available(&self, _code: &str) -> bool {
        true
    }

    /// Whether a prepared GeoIP category is currently available.
    ///
    /// Callers must check this before requesting lazy DNS for a GEOIP rule.
    fn geoip_available(&self, _code: &str) -> bool {
        true
    }

    fn matches_geosite(&self, code: &str, domain: &str) -> bool;
    fn matches_geoip(&self, code: &str, address: IpAddr) -> bool;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyGeoMatcher;

impl GeoMatcher for EmptyGeoMatcher {
    fn geosite_available(&self, _code: &str) -> bool {
        false
    }

    fn geoip_available(&self, _code: &str) -> bool {
        false
    }

    fn matches_geosite(&self, _code: &str, _domain: &str) -> bool {
        false
    }

    fn matches_geoip(&self, _code: &str, _address: IpAddr) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub action: RuleAction,
    pub rule_index: usize,
}

/// Evaluation may pause before an IP rule so that the caller can perform at
/// most one lazy runtime-DNS lookup, pin an address, and evaluate again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleEvaluation {
    Matched(RuleMatch),
    NeedsIpResolution { rule_index: usize },
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSetError {
    TooManyRules {
        count: usize,
        maximum: usize,
    },
    TooMuchText {
        bytes: usize,
        maximum: usize,
    },
    InvalidDomain {
        rule_index: usize,
        source: DomainNameError,
    },
    InvalidKeyword {
        rule_index: usize,
    },
    InvalidGeoCode {
        rule_index: usize,
    },
    InvalidCidr {
        rule_index: usize,
    },
    InvalidPortRange {
        rule_index: usize,
    },
}

impl fmt::Display for RuleSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRules { count, maximum } => {
                write!(formatter, "routing rule count {count} exceeds {maximum}")
            }
            Self::TooMuchText { bytes, maximum } => {
                write!(
                    formatter,
                    "routing rule text size {bytes} exceeds {maximum}"
                )
            }
            Self::InvalidDomain { rule_index, source } => {
                write!(
                    formatter,
                    "routing rule {rule_index} has an invalid domain: {source}"
                )
            }
            Self::InvalidKeyword { rule_index } => {
                write!(
                    formatter,
                    "routing rule {rule_index} has an invalid keyword"
                )
            }
            Self::InvalidGeoCode { rule_index } => {
                write!(
                    formatter,
                    "routing rule {rule_index} has an invalid GeoData code"
                )
            }
            Self::InvalidCidr { rule_index } => {
                write!(formatter, "routing rule {rule_index} has an invalid CIDR")
            }
            Self::InvalidPortRange { rule_index } => {
                write!(
                    formatter,
                    "routing rule {rule_index} has an invalid destination port"
                )
            }
        }
    }
}

impl std::error::Error for RuleSetError {}

/// An immutable ordered rule set.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Box<[RuleSpec]>,
    uses_domain_routing: bool,
}

impl RuleSet {
    /// Validates and normalizes the ordered rules. This is the only rule-set
    /// construction path that allocates.
    pub fn compile(mut rules: Vec<RuleSpec>) -> Result<Self, RuleSetError> {
        if rules.len() > MAX_ROUTING_RULES {
            return Err(RuleSetError::TooManyRules {
                count: rules.len(),
                maximum: MAX_ROUTING_RULES,
            });
        }
        let mut text_bytes = 0;
        let mut uses_domain_routing = false;
        for (index, rule) in rules.iter_mut().enumerate() {
            normalize_rule(rule, index, 0, &mut text_bytes, &mut uses_domain_routing)?;
        }

        Ok(Self {
            rules: rules.into_boxed_slice(),
            uses_domain_routing,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether an IP-based TUN flow can benefit from a sniffed or DNS-derived
    /// domain routing hint.
    #[must_use]
    pub const fn uses_domain_routing(&self) -> bool {
        self.uses_domain_routing
    }

    /// Exposes one immutable compiled rule so the asynchronous router can
    /// select and pin the first matching A/AAAA result after
    /// [`RuleEvaluation::NeedsIpResolution`].
    #[must_use]
    pub fn rule(&self, index: usize) -> Option<&RuleSpec> {
        self.rules.get(index)
    }

    /// Evaluates with no loaded GeoData. GEOSITE and GEOIP never match.
    #[must_use]
    pub fn evaluate(&self, context: &RoutingContext) -> RuleEvaluation {
        self.evaluate_with_geo(context, &EmptyGeoMatcher)
    }

    /// Evaluates from top to bottom and stops at the first match. Rule traversal
    /// does not allocate; GeoSite regexes may allocate internal search caches.
    #[must_use]
    pub fn evaluate_with_geo(
        &self,
        context: &RoutingContext,
        geo_matcher: &dyn GeoMatcher,
    ) -> RuleEvaluation {
        for (index, rule) in self.rules.iter().enumerate() {
            let matched = match matches_rule(rule, context, geo_matcher) {
                Ok(matched) => matched,
                Err(()) => return RuleEvaluation::NeedsIpResolution { rule_index: index },
            };

            if matched {
                return RuleEvaluation::Matched(RuleMatch {
                    action: rule.action,
                    rule_index: index,
                });
            }
        }
        RuleEvaluation::Matched(RuleMatch {
            action: RuleAction::Direct,
            rule_index: self.rules.len(),
        })
    }

    /// Continues evaluation at the IP rule which requested a bounded
    /// runtime-DNS result. Rules before `resolution_rule_index` have already
    /// failed and are not revisited. This matches Mihomo's `no-resolve`
    /// semantics: the flag prevents a rule from initiating DNS, while later
    /// `no-resolve` rules may still consume an address resolved by an earlier
    /// rule.
    ///
    /// For each IP-based rule, A addresses are considered in response order
    /// before AAAA addresses. The first address matching the first matching
    /// rule is pinned in `context`.
    ///
    /// This differs deliberately from pinning the first DNS result and then
    /// restarting normal evaluation: doing that would make address order take
    /// precedence over rule order when different addresses match different
    /// IP rules.
    #[must_use]
    pub fn evaluate_with_resolved_ips(
        &self,
        context: &mut RoutingContext,
        geo_matcher: &dyn GeoMatcher,
        resolution_rule_index: usize,
        addresses: &[IpAddr],
    ) -> RuleEvaluation {
        for (index, rule) in self.rules.iter().enumerate().skip(resolution_rule_index) {
            let mut selected_address = None;
            let matched = if context.effective_ip().is_none()
                && uses_destination_ip(rule)
                && !addresses.is_empty()
            {
                selected_address = preferred_addresses(addresses).find(|address| {
                    let mut candidate = context.clone();
                    candidate.pin_ip(*address);
                    matches_rule(rule, &candidate, geo_matcher).unwrap_or(false)
                });
                selected_address.is_some()
            } else {
                let mut candidate = context.clone();
                candidate.mark_ip_resolution_unavailable();
                matches_rule(rule, &candidate, geo_matcher).unwrap_or(false)
            };

            if matched {
                if let Some(address) = selected_address {
                    context.pin_ip(address);
                }
                return RuleEvaluation::Matched(RuleMatch {
                    action: rule.action,
                    rule_index: index,
                });
            }
        }
        RuleEvaluation::Matched(RuleMatch {
            action: RuleAction::Direct,
            rule_index: self.rules.len(),
        })
    }
}

fn normalize_rule(
    rule: &mut RuleSpec,
    index: usize,
    depth: usize,
    bytes: &mut usize,
    domain: &mut bool,
) -> Result<(), RuleSetError> {
    if depth > 32 {
        return Err(RuleSetError::TooManyRules {
            count: depth,
            maximum: 32,
        });
    }
    match &mut rule.kind {
        RuleKind::RuleSet { content, .. } => {
            *domain |= content.as_ref().is_some_and(|set| set.uses_domain());
        }
        RuleKind::Domain(value) | RuleKind::DomainSuffix(value) => {
            *value =
                normalize_domain_name(value).map_err(|source| RuleSetError::InvalidDomain {
                    rule_index: index,
                    source,
                })?;
            *bytes = checked_text_bytes(*bytes, value.len())?;
            *domain = true;
        }
        RuleKind::DomainKeyword(value) | RuleKind::DomainWildcard(value) => {
            if value.is_empty() {
                return Err(RuleSetError::InvalidKeyword { rule_index: index });
            }
            value.make_ascii_lowercase();
            *bytes = checked_text_bytes(*bytes, value.len())?;
            *domain = true;
        }
        RuleKind::DomainRegex(value) => {
            *bytes = checked_text_bytes(*bytes, value.as_str().len())?;
            *domain = true;
        }
        RuleKind::GeoSite(value) => {
            *value =
                crate::geodata::normalize_selector(crate::geodata::GeoDataKind::GeoSite, value)
                    .map_err(|_| RuleSetError::InvalidGeoCode { rule_index: index })?;
            *bytes = checked_text_bytes(*bytes, value.len())?;
            *domain = true;
        }
        RuleKind::GeoIp(value) => {
            *value = crate::geodata::normalize_selector(crate::geodata::GeoDataKind::GeoIp, value)
                .map_err(|_| RuleSetError::InvalidGeoCode { rule_index: index })?;
            *bytes = checked_text_bytes(*bytes, value.len())?;
        }
        RuleKind::IpCidr(cidr) | RuleKind::SrcIpCidr(cidr) => {
            if !valid_cidr(cidr) {
                return Err(RuleSetError::InvalidCidr { rule_index: index });
            }
        }
        RuleKind::DstPorts(ranges) | RuleKind::SrcPorts(ranges) => {
            if ranges.is_empty() || ranges.iter().any(|range| range.start > range.end) {
                return Err(RuleSetError::InvalidPortRange { rule_index: index });
            }
        }
        RuleKind::And(children) | RuleKind::Or(children) => {
            for child in children {
                normalize_rule(child, index, depth + 1, bytes, domain)?;
            }
        }
        RuleKind::Not(child) => normalize_rule(child, index, depth + 1, bytes, domain)?,
        RuleKind::Network(_) | RuleKind::Match => {}
    }
    Ok(())
}

pub(crate) fn uses_destination_ip(rule: &RuleSpec) -> bool {
    match &rule.kind {
        RuleKind::RuleSet { content, .. } => content.as_ref().is_some_and(|set| set.uses_ip()),
        RuleKind::IpCidr(_) | RuleKind::GeoIp(_) => true,
        RuleKind::And(children) | RuleKind::Or(children) => {
            children.iter().any(uses_destination_ip)
        }
        RuleKind::Not(child) => uses_destination_ip(child),
        _ => false,
    }
}

// Err means this exact traversal requires one lazy DNS resolution. Short
// circuiting keeps later IP predicates from triggering unnecessary queries.
pub(crate) fn matches_rule(
    rule: &RuleSpec,
    context: &RoutingContext,
    geo: &dyn GeoMatcher,
) -> Result<bool, ()> {
    let port_matches = |ranges: &[crate::config::PortRange], port| {
        ranges
            .iter()
            .any(|range| range.start <= port && port <= range.end)
    };
    Ok(match &rule.kind {
        RuleKind::RuleSet { content, .. } => match content {
            Some(set) => set.matches(context, geo, rule.no_resolve)?,
            None => false,
        },
        RuleKind::Domain(value) => context.domain() == Some(value.as_str()),
        RuleKind::DomainSuffix(value) => context
            .domain()
            .is_some_and(|domain| domain_suffix_matches(domain, value)),
        RuleKind::DomainKeyword(value) => context
            .domain()
            .is_some_and(|domain| domain.contains(value)),
        RuleKind::DomainWildcard(value) => context
            .domain()
            .is_some_and(|domain| wildcard_matches(value, domain)),
        RuleKind::DomainRegex(value) => context
            .domain()
            .is_some_and(|domain| value.is_match(domain)),
        RuleKind::GeoSite(code) => {
            geo.geosite_available(code)
                && context
                    .domain()
                    .is_some_and(|domain| geo.matches_geosite(code, domain))
        }
        RuleKind::GeoIp(code) => {
            if !geo.geoip_available(code) {
                false
            } else if let Some(address) = context.effective_ip() {
                geo.matches_geoip(code, address)
            } else if !rule.no_resolve && context.should_request_ip_resolution() {
                return Err(());
            } else {
                false
            }
        }
        RuleKind::IpCidr(cidr) => {
            if let Some(address) = context.effective_ip() {
                cidr_contains(cidr, address)
            } else if !rule.no_resolve && context.should_request_ip_resolution() {
                return Err(());
            } else {
                false
            }
        }
        RuleKind::SrcIpCidr(cidr) => context
            .source
            .is_some_and(|source| cidr_contains(cidr, source.ip())),
        RuleKind::SrcPorts(ranges) => context
            .source
            .is_some_and(|source| port_matches(ranges, source.port())),
        RuleKind::DstPorts(ranges) => port_matches(ranges, context.destination_port),
        RuleKind::Network(network) => *network == context.network,
        RuleKind::And(children) => {
            for child in children {
                if !matches_rule(child, context, geo)? {
                    return Ok(false);
                }
            }
            true
        }
        RuleKind::Or(children) => {
            for child in children {
                if matches_rule(child, context, geo)? {
                    return Ok(true);
                }
            }
            false
        }
        RuleKind::Not(child) => !matches_rule(child, context, geo)?,
        RuleKind::Match => true,
    })
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let (pattern, value) = (pattern.as_bytes(), value.as_bytes());
    let (mut p, mut v) = (0, 0);
    let mut retry = None;
    while v < value.len() {
        match pattern.get(p) {
            Some(b'*') => {
                retry = Some((p + 1, v));
                p += 1;
            }
            Some(byte) if *byte == b'?' || *byte == value[v] => {
                p += 1;
                v += 1;
            }
            _ => match retry {
                Some((after_star, consumed)) => {
                    v = consumed + 1;
                    p = after_star;
                    retry = Some((p, v));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

fn preferred_addresses(addresses: &[IpAddr]) -> impl Iterator<Item = IpAddr> + '_ {
    addresses
        .iter()
        .copied()
        .filter(IpAddr::is_ipv4)
        .chain(addresses.iter().copied().filter(IpAddr::is_ipv6))
}

fn checked_text_bytes(current: usize, additional: usize) -> Result<usize, RuleSetError> {
    let bytes = current
        .checked_add(additional)
        .ok_or(RuleSetError::TooMuchText {
            bytes: usize::MAX,
            maximum: MAX_RULE_TEXT_BYTES,
        })?;
    if bytes > MAX_RULE_TEXT_BYTES {
        return Err(RuleSetError::TooMuchText {
            bytes,
            maximum: MAX_RULE_TEXT_BYTES,
        });
    }
    Ok(bytes)
}

fn valid_cidr(cidr: &IpCidr) -> bool {
    match cidr.network {
        IpAddr::V4(_) => cidr.prefix_len <= 32,
        IpAddr::V6(_) => cidr.prefix_len <= 128,
    }
}

fn cidr_contains(cidr: &IpCidr, address: IpAddr) -> bool {
    match (cidr.network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let prefix = cidr.prefix_len;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let prefix = cidr.prefix_len;
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn domain_suffix_matches(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::config::PortRange;

    use super::*;

    fn spec(kind: RuleKind, action: RuleAction) -> RuleSpec {
        RuleSpec {
            kind,
            action,
            no_resolve: false,
        }
    }

    fn proxy_action(index: usize) -> RuleAction {
        RuleAction::Route(crate::config::RouteTargetId::Proxy(
            crate::config::ProxyId::new(index).unwrap(),
        ))
    }

    fn domain_context(network: Network, host: &str, port: u16) -> RoutingContext {
        let destination = Destination::domain(host, port).unwrap();
        RoutingContext::new(network, &destination).unwrap()
    }

    fn action(evaluation: RuleEvaluation) -> RuleAction {
        match evaluation {
            RuleEvaluation::Matched(rule_match) => rule_match.action,
            other => panic!("expected match, got {other:?}"),
        }
    }

    #[test]
    fn geodata_selectors_are_canonicalized_at_the_routing_boundary() {
        let rules = RuleSet::compile(vec![
            spec(
                RuleKind::GeoSite("!GOOGLE@CN@ADS@cn".to_owned()),
                RuleAction::Direct,
            ),
            spec(RuleKind::GeoIp("!CN".to_owned()), RuleAction::Reject),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();
        assert_eq!(
            rules.rules[0].kind,
            RuleKind::GeoSite("!google@ads@cn".to_owned())
        );
        assert_eq!(rules.rules[1].kind, RuleKind::GeoIp("!cn".to_owned()));
        assert!(
            RuleSet::compile(vec![
                spec(RuleKind::GeoIp("cn@ads".to_owned()), RuleAction::Direct),
                spec(RuleKind::Match, proxy_action(0)),
            ])
            .is_err()
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let rules = RuleSet::compile(vec![
            spec(
                RuleKind::Domain("api.example.com".to_owned()),
                RuleAction::Direct,
            ),
            spec(
                RuleKind::DomainSuffix("example.com".to_owned()),
                RuleAction::Reject,
            ),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();

        let result = rules.evaluate(&domain_context(Network::Tcp, "API.Example.Com.", 443));
        assert_eq!(action(result), RuleAction::Direct);
    }

    #[test]
    fn domain_suffix_requires_a_label_boundary() {
        let rules = RuleSet::compile(vec![
            spec(
                RuleKind::DomainSuffix("example.com".to_owned()),
                RuleAction::Direct,
            ),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();

        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "example.com", 443))),
            RuleAction::Direct
        );
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "a.example.com", 443))),
            RuleAction::Direct
        );
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "badexample.com", 443))),
            proxy_action(0)
        );
    }

    #[test]
    fn cidr_matches_only_the_same_address_family() {
        let rules = RuleSet::compile(vec![
            spec(
                RuleKind::IpCidr(IpCidr {
                    network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                }),
                RuleAction::Direct,
            ),
            spec(
                RuleKind::IpCidr(IpCidr {
                    network: IpAddr::V6("fc00::".parse::<Ipv6Addr>().unwrap()),
                    prefix_len: 7,
                }),
                RuleAction::Reject,
            ),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();

        let v4 = Destination::Ip(SocketAddr::from(([10, 23, 4, 5], 443)));
        let v6 = Destination::Ip(SocketAddr::new("fd00::1".parse().unwrap(), 443));
        let public = Destination::Ip(SocketAddr::from(([203, 0, 113, 1], 443)));
        assert_eq!(
            action(rules.evaluate(&RoutingContext::new(Network::Tcp, &v4).unwrap())),
            RuleAction::Direct
        );
        assert_eq!(
            action(rules.evaluate(&RoutingContext::new(Network::Tcp, &v6).unwrap())),
            RuleAction::Reject
        );
        assert_eq!(
            action(rules.evaluate(&RoutingContext::new(Network::Tcp, &public).unwrap())),
            proxy_action(0)
        );
    }

    #[test]
    fn destination_port_supports_sets_and_ranges() {
        let rules = RuleSet::compile(vec![
            spec(
                RuleKind::DstPorts(vec![
                    PortRange { start: 25, end: 25 },
                    PortRange {
                        start: 440,
                        end: 445,
                    },
                ]),
                RuleAction::Reject,
            ),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();

        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "mail.example", 25))),
            RuleAction::Reject
        );
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "files.example", 443))),
            RuleAction::Reject
        );
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "web.example", 80))),
            proxy_action(0)
        );
    }

    #[test]
    fn network_rule_distinguishes_tcp_and_udp() {
        let rules = RuleSet::compile(vec![
            spec(RuleKind::Network(Network::Udp), RuleAction::Reject),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();

        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Udp, "example.com", 53))),
            RuleAction::Reject
        );
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "example.com", 53))),
            proxy_action(0)
        );
    }

    #[test]
    fn final_match_supplies_the_default_action() {
        let rules = RuleSet::compile(vec![spec(RuleKind::Match, RuleAction::Direct)]).unwrap();
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "example.com", 443))),
            RuleAction::Direct
        );
        let rules = RuleSet::compile(vec![spec(
            RuleKind::Domain("example.com".to_owned()),
            RuleAction::Reject,
        )])
        .unwrap();
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "other.example", 443))),
            RuleAction::Direct
        );
        assert_eq!(
            action(RuleSet::compile(vec![]).unwrap().evaluate(&domain_context(
                Network::Tcp,
                "other.example",
                443
            ))),
            RuleAction::Direct
        );
    }

    #[test]
    fn domain_routing_flag_is_compiled_once_from_relevant_rule_kinds() {
        for kind in [
            RuleKind::Domain("example.com".to_owned()),
            RuleKind::DomainSuffix("example.com".to_owned()),
            RuleKind::DomainKeyword("example".to_owned()),
            RuleKind::GeoSite("private".to_owned()),
        ] {
            let rules = RuleSet::compile(vec![
                spec(kind, RuleAction::Direct),
                spec(RuleKind::Match, RuleAction::Reject),
            ])
            .unwrap();
            assert!(rules.uses_domain_routing());
        }

        let rules = RuleSet::compile(vec![
            spec(RuleKind::GeoIp("private".to_owned()), RuleAction::Direct),
            spec(
                RuleKind::IpCidr(IpCidr {
                    network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                }),
                RuleAction::Direct,
            ),
            spec(
                RuleKind::DstPorts(vec![PortRange {
                    start: 443,
                    end: 443,
                }]),
                RuleAction::Direct,
            ),
            spec(RuleKind::Network(Network::Tcp), RuleAction::Direct),
            spec(RuleKind::Match, RuleAction::Reject),
        ])
        .unwrap();
        assert!(!rules.uses_domain_routing());
    }

    #[test]
    fn unresolved_ip_rule_pauses_once_unless_no_resolve() {
        let mut resolvable = spec(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }),
            RuleAction::Direct,
        );
        let rules = RuleSet::compile(vec![
            resolvable.clone(),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();
        let mut context = domain_context(Network::Tcp, "example.com", 443);
        assert_eq!(
            rules.evaluate(&context),
            RuleEvaluation::NeedsIpResolution { rule_index: 0 }
        );
        context.mark_ip_resolution_unavailable();
        assert_eq!(action(rules.evaluate(&context)), proxy_action(0));

        resolvable.no_resolve = true;
        let rules =
            RuleSet::compile(vec![resolvable, spec(RuleKind::Match, proxy_action(0))]).unwrap();
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "example.com", 443))),
            proxy_action(0)
        );
    }

    #[test]
    fn resolved_ip_is_visible_to_later_no_resolve_rule() {
        let mut later_no_resolve = spec(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }),
            RuleAction::Reject,
        );
        later_no_resolve.no_resolve = true;
        let rules = RuleSet::compile(vec![
            spec(
                RuleKind::IpCidr(IpCidr {
                    network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    prefix_len: 24,
                }),
                RuleAction::Direct,
            ),
            later_no_resolve,
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();
        let mut context = domain_context(Network::Tcp, "example.com", 443);
        let RuleEvaluation::NeedsIpResolution { rule_index } = rules.evaluate(&context) else {
            panic!("first resolvable IP rule must request runtime DNS");
        };
        let resolved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

        assert_eq!(
            rules.evaluate_with_resolved_ips(
                &mut context,
                &EmptyGeoMatcher,
                rule_index,
                &[resolved],
            ),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Reject,
                rule_index: 1,
            })
        );
        assert_eq!(context.pinned_ip(), Some(resolved));
    }

    #[test]
    fn resolved_ip_does_not_revisit_earlier_no_resolve_rule() {
        let mut earlier_no_resolve = spec(
            RuleKind::IpCidr(IpCidr {
                network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }),
            RuleAction::Reject,
        );
        earlier_no_resolve.no_resolve = true;
        let rules = RuleSet::compile(vec![
            earlier_no_resolve,
            spec(
                RuleKind::IpCidr(IpCidr {
                    network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    prefix_len: 24,
                }),
                RuleAction::Direct,
            ),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();
        let mut context = domain_context(Network::Tcp, "example.com", 443);
        let RuleEvaluation::NeedsIpResolution { rule_index } = rules.evaluate(&context) else {
            panic!("later resolvable IP rule must request runtime DNS");
        };

        assert_eq!(rule_index, 1);
        assert_eq!(
            rules.evaluate_with_resolved_ips(
                &mut context,
                &EmptyGeoMatcher,
                rule_index,
                &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))],
            ),
            RuleEvaluation::Matched(RuleMatch {
                action: proxy_action(0),
                rule_index: 2,
            })
        );
        assert_eq!(context.pinned_ip(), None);
    }

    #[test]
    fn absent_geodata_never_matches() {
        let rules = RuleSet::compile(vec![
            spec(RuleKind::GeoSite("CN".to_owned()), RuleAction::Direct),
            spec(RuleKind::Match, proxy_action(0)),
        ])
        .unwrap();
        assert_eq!(
            action(rules.evaluate(&domain_context(Network::Tcp, "example.cn", 443))),
            proxy_action(0)
        );
    }

    #[test]
    fn unavailable_geoip_does_not_request_lazy_dns() {
        let proxy = crate::config::ProxyId::new(0).unwrap();
        let rules = RuleSet::compile(vec![
            spec(RuleKind::GeoIp("cn".to_owned()), RuleAction::Direct),
            spec(
                RuleKind::Match,
                RuleAction::Route(crate::config::RouteTargetId::Proxy(proxy)),
            ),
        ])
        .unwrap();
        let context = domain_context(Network::Tcp, "example.com", 443);
        assert_eq!(
            rules.evaluate_with_geo(&context, &EmptyGeoMatcher),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Route(crate::config::RouteTargetId::Proxy(proxy)),
                rule_index: 1,
            })
        );
    }

    #[test]
    fn unicode_domain_is_normalized_to_an_ascii_a_label() {
        let destination = Destination::domain("例子.中国", 443).unwrap();
        assert_eq!(
            RoutingContext::new(Network::Tcp, &destination)
                .unwrap()
                .domain(),
            Some("xn--fsqu00a.xn--fiqs8s")
        );
    }

    #[test]
    fn opaque_ascii_dns_name_is_accepted_for_xray_geodata_compatibility() {
        let destination = Destination::domain("XN--WCVS22D1M.HK", 443).unwrap();
        assert_eq!(
            RoutingContext::new(Network::Tcp, &destination)
                .unwrap()
                .domain(),
            Some("xn--wcvs22d1m.hk")
        );
    }

    #[test]
    fn invalid_idna_domain_is_rejected() {
        let destination = Destination::domain("-invalid.example", 443).unwrap();
        assert_eq!(
            RoutingContext::new(Network::Tcp, &destination),
            Err(DomainNameError::InvalidIdna)
        );
    }

    #[test]
    fn invalid_redir_host_hint_does_not_reject_a_literal_ip() {
        let destination = Destination::Ip("192.0.2.7:443".parse().unwrap());
        let context =
            RoutingContext::with_domain_hint(Network::Tcp, &destination, Some("_service.example"))
                .unwrap();

        assert_eq!(context.domain(), None);
        assert_eq!(context.effective_ip(), Some("192.0.2.7".parse().unwrap()));
    }
}
