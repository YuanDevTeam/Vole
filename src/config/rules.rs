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

pub(super) fn parse_program_rule(
    input: &str,
    targets: &RouteTargetsByName,
    sub_rules: &HashMap<String, SubRuleId>,
) -> Result<RuleSpec> {
    let (kind, rest) = input
        .split_once(',')
        .ok_or_else(|| VoleError::InvalidConfig("rule requires a type and payload".into()))?;
    if trim_ascii_whitespace(kind).eq_ignore_ascii_case("SUB-RULE") {
        let (condition, name) = rest.rsplit_once(',').ok_or_else(|| {
            VoleError::InvalidConfig("SUB-RULE requires a condition and named program".into())
        })?;
        let condition = trim_ascii_whitespace(condition)
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
            .ok_or_else(|| {
                VoleError::InvalidConfig("SUB-RULE condition requires parentheses".into())
            })?;
        let target = sub_rules
            .get(trim_ascii_whitespace(name))
            .copied()
            .ok_or_else(|| {
                VoleError::InvalidConfig("SUB-RULE references an unknown program".into())
            })?;
        return Ok(RuleSpec {
            kind: RuleKind::SubRule {
                predicate: Box::new(parse_predicate(condition)?),
                target,
            },
            action: RuleAction::Direct,
            no_resolve: false,
        });
    }
    let logical = matches!(
        trim_ascii_whitespace(kind).to_ascii_uppercase().as_str(),
        "AND" | "OR" | "NOT" | "DOMAIN-REGEX"
    );
    let target_range = if logical {
        input.rfind(',').map(|start| start + 1..input.len())
    } else {
        let start = input.find(',').unwrap() + 1;
        if trim_ascii_whitespace(kind).eq_ignore_ascii_case("MATCH") {
            Some(start..input.len())
        } else {
            input[start..].find(',').map(|offset| {
                let start = start + offset + 1;
                let end = input[start..]
                    .find(',')
                    .map_or(input.len(), |offset| start + offset);
                start..end
            })
        }
    };
    if let Some(range) = target_range {
        let control = match trim_ascii_whitespace(&input[range.clone()]) {
            "PASS" => Some(RuleControl::Pass),
            "PASS-RULE" => Some(RuleControl::PassRule),
            _ => None,
        };
        if let Some(control) = control {
            let mut terminal = input.to_owned();
            terminal.replace_range(range, "DIRECT");
            let predicate = parse(&terminal, Some(targets), 0)?;
            return Ok(RuleSpec {
                kind: RuleKind::Flow {
                    predicate: Box::new(predicate),
                    control,
                },
                action: RuleAction::Direct,
                no_resolve: false,
            });
        }
    }
    parse(input, Some(targets), 0)
}

pub(crate) fn validate_subrule_calls(
    main: &[RuleSpec],
    sub_rules: &[NamedRuleProgram],
) -> Result<()> {
    fn visit(
        id: usize,
        depth: usize,
        sub_rules: &[NamedRuleProgram],
        states: &mut [u8],
        lengths: &mut [usize],
    ) -> Result<usize> {
        if depth > 32 {
            return invalid("sub-rules exceed 32 call levels");
        }
        let Some(program) = sub_rules.get(id) else {
            return invalid("SUB-RULE references an unknown program");
        };
        if states[id] == 1 {
            return invalid("sub-rules contain a reference cycle");
        }
        if states[id] == 2 {
            return Ok(lengths[id]);
        }
        states[id] = 1;
        let mut length = 1;
        for rule in &program.rules {
            if let RuleKind::SubRule { target, .. } = &rule.kind {
                length =
                    length.max(1 + visit(target.index(), depth + 1, sub_rules, states, lengths)?);
            }
        }
        if length > 32 {
            return invalid("sub-rules exceed 32 call levels");
        }
        states[id] = 2;
        lengths[id] = length;
        Ok(length)
    }
    fn pure(rule: &RuleSpec, depth: usize) -> Result<()> {
        if depth > 32 {
            return invalid("logical rules exceed 32 nesting levels");
        }
        match &rule.kind {
            RuleKind::Flow { .. } | RuleKind::SubRule { .. } => {
                invalid("flow controls are not predicates")
            }
            RuleKind::And(children) | RuleKind::Or(children) => {
                for child in children {
                    pure(child, depth + 1)?;
                }
                Ok(())
            }
            RuleKind::Not(child) => pure(child, depth + 1),
            _ => Ok(()),
        }
    }
    let mut names = std::collections::HashSet::new();
    for program in sub_rules {
        if program.name.is_empty() || !names.insert(&program.name) {
            return invalid("sub-rules require unique nonempty names");
        }
    }
    for rule in main
        .iter()
        .chain(sub_rules.iter().flat_map(|program| &program.rules))
    {
        match &rule.kind {
            RuleKind::Flow { predicate, .. } | RuleKind::SubRule { predicate, .. } => {
                pure(predicate, 0)?
            }
            _ => pure(rule, 0)?,
        }
    }
    let mut states = vec![0; sub_rules.len()];
    let mut lengths = vec![0; sub_rules.len()];
    for id in 0..sub_rules.len() {
        visit(id, 1, sub_rules, &mut states, &mut lengths)?;
    }
    for rule in main {
        if let RuleKind::SubRule { target, .. } = &rule.kind {
            visit(target.index(), 1, sub_rules, &mut states, &mut lengths)?;
        }
    }
    Ok(())
}

pub(super) fn parse_predicate(input: &str) -> Result<RuleSpec> {
    parse(input, None, 0)
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
                        "RULE-SET" | "GEOIP" | "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR"
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
        "RULE-SET" => RuleKind::RuleSet {
            name: payload.to_owned(),
            content: None,
        },
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
