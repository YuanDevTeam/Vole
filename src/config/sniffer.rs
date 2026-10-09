use super::*;

pub(super) fn addresses(values: Vec<String>) -> Result<Vec<RuleSpec>> {
    let mut rules = Vec::new();
    for value in values {
        let lower = value.to_ascii_lowercase();
        if let Some(codes) = lower.strip_prefix("geoip:") {
            for code in codes.split(',') {
                rules.push(parse_rule(
                    &format!("GEOIP,{code},DIRECT,no-resolve"),
                    &RouteTargetsByName::new(),
                )?);
            }
        } else if lower.starts_with("rule-set:") {
            for name in value[9..].split(',') {
                rules.push(parse_rule(
                    &format!("RULE-SET,{name},DIRECT,no-resolve"),
                    &RouteTargetsByName::new(),
                )?);
            }
        } else {
            let cidr = parse_ip_cidr(&value, value.contains(':'))?;
            rules.push(RuleSpec {
                kind: RuleKind::IpCidr(cidr),
                action: RuleAction::Direct,
                no_resolve: true,
            });
        }
    }
    Ok(rules)
}
pub(super) fn domains(values: Vec<String>) -> Result<Vec<DnsPolicySelector>> {
    values
        .iter()
        .map(|pattern| normalize_dns_policy_selector(pattern))
        .collect()
}
