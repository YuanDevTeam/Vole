use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsFallbackConfig {
    pub nameservers: Vec<DnsNameserver>,
    pub geoip: Option<String>,
    pub ipcidr: Vec<IpCidr>,
    pub domains: Vec<DnsPolicySelector>,
    pub lazy: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawFallbackFilter {
    geoip: bool,
    geoip_code: String,
    ipcidr: Vec<String>,
    domain: Vec<String>,
    geosite: Vec<String>,
}
impl Default for RawFallbackFilter {
    fn default() -> Self {
        Self {
            geoip: true,
            geoip_code: "CN".into(),
            ipcidr: Vec::new(),
            domain: Vec::new(),
            geosite: Vec::new(),
        }
    }
}
impl RawFallbackFilter {
    pub(super) fn normalize(
        self,
        nameservers: Vec<DnsNameserver>,
        lazy: bool,
    ) -> Result<DnsFallbackConfig> {
        let mut domains = Vec::new();
        for pattern in self.domain {
            let selector = normalize_dns_policy_selector(&pattern)?;
            if !matches!(selector, DnsPolicySelector::Domains(_)) {
                return invalid("fallback-filter.domain requires domain patterns");
            }
            domains.push(selector);
        }
        for code in self.geosite {
            domains.push(DnsPolicySelector::GeoSite(
                vec![normalize_geo_code(&code, "fallback-filter.geosite")?].into_boxed_slice(),
            ));
        }
        Ok(DnsFallbackConfig {
            nameservers,
            geoip: self
                .geoip
                .then(|| normalize_geo_code(&self.geoip_code, "fallback-filter.geoip-code"))
                .transpose()?,
            ipcidr: self
                .ipcidr
                .iter()
                .map(|cidr| parse_ip_cidr(cidr, cidr.contains(':')))
                .collect::<Result<_>>()?,
            domains,
            lazy,
        })
    }
}
