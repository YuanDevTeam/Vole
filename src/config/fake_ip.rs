use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FakeIpFilterMode {
    #[default]
    Blacklist,
    Whitelist,
    Rule,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub range: Option<FakeIpRange>,
    pub range6: Option<FakeIpRange>,
    pub ttl: u32,
    pub mode: FakeIpFilterMode,
    pub filter: Vec<DnsPolicySelector>,
    pub rules: Vec<RuleSpec>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeIpRange {
    pub cidr: IpCidr,
    pub interface_address: IpAddr,
}
impl FakeIpRange {
    pub fn parse(value: &str, ipv6: bool) -> Result<Option<Self>> {
        if value.is_empty() {
            return Ok(None);
        }
        let cidr = parse_ip_cidr(value, ipv6)?;
        if cidr.prefix_len > if ipv6 { 125 } else { 29 } {
            return invalid("fake-IP range must leave at least three allocatable addresses");
        }
        let interface_address = value
            .split('/')
            .next()
            .unwrap()
            .parse()
            .map_err(|_| VoleError::InvalidConfig("invalid fake-IP prefix".into()))?;
        Ok(Some(Self {
            cidr,
            interface_address,
        }))
    }
    pub(crate) fn bounds(self) -> (u128, u128) {
        let (base, width) = match self.cidr.network {
            IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32),
            IpAddr::V6(ip) => (u128::from(ip), 128),
        };
        let host_bits = width - self.cidr.prefix_len;
        let mask = if host_bits == 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        (base, base | mask)
    }
    pub(crate) fn address(self, value: u128) -> IpAddr {
        if self.cidr.network.is_ipv4() {
            Ipv4Addr::from(value as u32).into()
        } else {
            Ipv6Addr::from(value).into()
        }
    }
}
pub(super) fn default_fake_range() -> String {
    "198.18.0.1/16".into()
}
pub(super) fn default_fake_ttl() -> i64 {
    1
}
pub(super) fn default_fake_filter() -> Vec<String> {
    [
        "dns.msftnsci.com",
        "www.msftnsci.com",
        "www.msftconnecttest.com",
    ]
    .map(str::to_owned)
    .to_vec()
}
impl RawDnsConfig {
    pub(super) fn fake_ip(&self) -> Result<FakeIpConfig> {
        let enabled = match self.enhanced_mode.as_str() {
            "redir-host" => false,
            "fake-ip" => true,
            _ => return invalid("dns.enhanced-mode must be redir-host or fake-ip"),
        };
        let range = FakeIpRange::parse(&self.fake_ip_range, false)?;
        let range6 = FakeIpRange::parse(&self.fake_ip_range6, true)?;
        if enabled && range.is_none() && range6.is_none() {
            return invalid("fake-ip requires at least one range");
        }
        let mut filter = Vec::new();
        let mut rules = Vec::new();
        if self.fake_ip_filter_mode == FakeIpFilterMode::Rule {
            for value in &self.fake_ip_filter {
                let (predicate, action) = value.rsplit_once(',').ok_or_else(|| {
                    VoleError::InvalidConfig("fake-IP rule requires an action".into())
                })?;
                let action = match action.trim().to_ascii_lowercase().as_str() {
                    "real-ip" => "DIRECT",
                    "fake-ip" => "REJECT",
                    _ => return invalid("fake-IP rule action must be real-ip or fake-ip"),
                };
                let rule =
                    parse_rule(&format!("{predicate},{action}"), &RouteTargetsByName::new())?;
                if !matches!(
                    rule.kind,
                    RuleKind::Domain(_)
                        | RuleKind::DomainSuffix(_)
                        | RuleKind::DomainKeyword(_)
                        | RuleKind::DomainWildcard(_)
                        | RuleKind::DomainRegex(_)
                        | RuleKind::GeoSite(_)
                        | RuleKind::RuleSet { .. }
                        | RuleKind::Match
                ) {
                    return invalid("fake-IP filter rules must match domains");
                }
                rules.push(rule);
            }
        } else {
            for value in &self.fake_ip_filter {
                filter.push(normalize_dns_policy_selector(value)?);
            }
        }
        Ok(FakeIpConfig {
            enabled,
            range,
            range6,
            ttl: self.fake_ip_ttl.clamp(0, u32::MAX.into()) as u32,
            mode: self.fake_ip_filter_mode,
            filter,
            rules,
        })
    }
}
