use regex::{Regex, RegexBuilder};

use super::*;

/// Compile once; equality continues to describe the configuration pattern.
#[derive(Debug, Clone)]
pub struct DomainRegex(Regex);

impl PartialEq for DomainRegex {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}
impl Eq for DomainRegex {}

impl DomainRegex {
    pub fn new(pattern: &str) -> Result<Self> {
        RegexBuilder::new(pattern).case_insensitive(true).size_limit(MAX_CONFIG_BYTES)
            .build().map(Self).map_err(|_| VoleError::InvalidConfig(
                "DOMAIN-REGEX requires a valid supported regular expression; lookaround and backreferences are not supported".into()
            ))
    }
    pub fn is_match(&self, domain: &str) -> bool {
        self.0.is_match(domain)
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

pub(super) fn parse_rule(input: &str, targets: &RouteTargetsByName) -> Result<RuleSpec> {
    parse(input, Some(targets), 0)
}

fn parse(input: &str, targets: Option<&RouteTargetsByName>, depth: usize) -> Result<RuleSpec> {
    if depth > 32 {
        return invalid("logical rules exceed 32 nesting levels");
    }
    let (kind, rest) = input
        .split_once(',')
        .ok_or_else(|| VoleError::InvalidConfig("rule requires a type and payload".into()))?;
    let kind = trim_ascii_whitespace(kind).to_ascii_uppercase();
    if kind == "MATCH" {
        let targets = targets.ok_or_else(|| {
            VoleError::InvalidConfig("MATCH is not supported inside logical rules".into())
        })?;
        return Ok(RuleSpec {
            kind: RuleKind::Match,
            action: parse_rule_action(
                trim_ascii_whitespace(rest.split(',').next().unwrap_or_default()),
                targets,
            )?,
            no_resolve: false,
        });
    }
    let (payload, action, no_resolve) =
        if matches!(kind.as_str(), "AND" | "OR" | "NOT" | "DOMAIN-REGEX") {
            match targets {
                Some(targets) => {
                    let (payload, action) = rest
                        .rsplit_once(',')
                        .ok_or_else(|| VoleError::InvalidConfig("rule requires a target".into()))?;
                    (
                        trim_ascii_whitespace(payload),
                        parse_rule_action(trim_ascii_whitespace(action), targets)?,
                        false,
                    )
                }
                None => (trim_ascii_whitespace(rest), RuleAction::Direct, false),
            }
        } else {
            let mut fields = rest.split(',').map(trim_ascii_whitespace);
            let payload = fields.next().unwrap_or_default();
            let action = match targets {
                Some(targets) => parse_rule_action(fields.next().unwrap_or_default(), targets)?,
                None => RuleAction::Direct,
            };
            let mut no_resolve = false;
            for option in fields {
                if option == "no-resolve"
                    && matches!(
                        kind.as_str(),
                        "GEOIP" | "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR"
                    )
                {
                    no_resolve = true;
                } else {
                    return invalid("unsupported rule parameter");
                }
            }
            (payload, action, no_resolve)
        };
    let rule_kind = match kind.as_str() {
        "DOMAIN" => RuleKind::Domain(normalize_rule_domain(payload, "DOMAIN")?),
        "DOMAIN-SUFFIX" => RuleKind::DomainSuffix(normalize_rule_domain(payload, "DOMAIN-SUFFIX")?),
        "DOMAIN-KEYWORD" => RuleKind::DomainKeyword(normalize_rule_keyword(payload)?),
        "DOMAIN-WILDCARD" => RuleKind::DomainWildcard(payload.to_lowercase()),
        "DOMAIN-REGEX" => RuleKind::DomainRegex(DomainRegex::new(payload)?),
        "GEOSITE" => RuleKind::GeoSite(normalize_geo_code(payload, "GEOSITE")?),
        "GEOIP" => RuleKind::GeoIp(normalize_geo_code(payload, "GEOIP")?),
        "IP-CIDR" => RuleKind::IpCidr(parse_ip_cidr(payload, false)?),
        "IP-CIDR6" => RuleKind::IpCidr(parse_ip_cidr(payload, true)?),
        "SRC-IP-CIDR" => RuleKind::SrcIpCidr(parse_ip_cidr(payload, payload.contains(':'))?),
        "DST-PORT" => RuleKind::DstPorts(parse_port_ranges(payload)?),
        "SRC-PORT" => RuleKind::SrcPorts(parse_port_ranges(payload)?),
        "NETWORK" => RuleKind::Network(parse_network(payload)?),
        "AND" | "OR" | "NOT" => {
            let children = logical_children(payload)?
                .into_iter()
                .map(|child| parse(child, None, depth + 1))
                .collect::<Result<Vec<_>>>()?;
            match kind.as_str() {
                "AND" => RuleKind::And(children),
                "OR" => RuleKind::Or(children),
                _ if children.len() == 1 => {
                    RuleKind::Not(Box::new(children.into_iter().next().unwrap()))
                }
                _ => return invalid("NOT requires exactly one rule"),
            }
        }
        _ => return invalid(format!("unsupported rule type `{kind}`")),
    };
    Ok(RuleSpec {
        kind: rule_kind,
        action,
        no_resolve,
    })
}

fn logical_children(payload: &str) -> Result<Vec<&str>> {
    let inner = payload
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| {
            VoleError::InvalidConfig("logical rule payload requires parentheses".into())
        })?;
    let mut children = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0;
    for (index, byte) in inner.bytes().enumerate() {
        match byte {
            b'(' => {
                if depth == 0 {
                    start = index + 1;
                }
                depth += 1;
            }
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| VoleError::InvalidConfig("unbalanced logical rule".into()))?;
                if depth == 0 {
                    children.push(&inner[start..index]);
                }
            }
            b',' | b' ' | b'\t' | b'\r' | b'\n' if depth == 0 => {}
            _ if depth == 0 => return invalid("logical rule children require parentheses"),
            _ => {}
        }
    }
    if depth != 0 {
        return invalid("unbalanced logical rule");
    }
    Ok(children)
}
