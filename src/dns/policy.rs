use std::collections::HashMap;

use crate::{
    config::{DnsNameserverPolicy, DnsPolicySelector},
    routing::GeoMatcher,
};

/// Adjacent domain entries form one specificity-ordered lookup. GeoSite
/// entries separate those lookups and retain their configured ordering.
#[derive(Debug, Default)]
pub(super) struct NameserverPolicies(Vec<PolicyStep>);

#[derive(Debug)]
enum PolicyStep {
    Domains(DomainIndex),
    GeoSite(usize),
    RuleSet(usize),
}

impl NameserverPolicies {
    pub(super) fn new(policies: &[DnsNameserverPolicy]) -> Self {
        let mut steps = Vec::new();
        for (index, policy) in policies.iter().enumerate() {
            match &policy.selector {
                DnsPolicySelector::RuleSets { .. } => steps.push(PolicyStep::RuleSet(index)),
                DnsPolicySelector::GeoSite(_) => steps.push(PolicyStep::GeoSite(index)),
                DnsPolicySelector::Domains(patterns) => {
                    if !matches!(steps.last(), Some(PolicyStep::Domains(_))) {
                        steps.push(PolicyStep::Domains(DomainIndex::new()));
                    }
                    let Some(PolicyStep::Domains(domains)) = steps.last_mut() else {
                        unreachable!();
                    };
                    for pattern in patterns {
                        domains.insert(pattern, index);
                    }
                }
            }
        }
        Self(steps)
    }

    pub(super) fn select(
        &self,
        name: &str,
        policies: &[DnsNameserverPolicy],
        geo: &dyn GeoMatcher,
        decision: &crate::config::RuleDecision,
    ) -> Result<Option<usize>, crate::config::MatchFailure> {
        decision.visit()?;
        for step in &self.0 {
            match step {
                PolicyStep::Domains(domains) => {
                    if let Some(index) = domains.find(0, name) {
                        return Ok(Some(index));
                    }
                }
                PolicyStep::RuleSet(index) => {
                    let DnsPolicySelector::RuleSets { sets, .. } = &policies[*index].selector
                    else {
                        unreachable!()
                    };
                    for set in sets {
                        if set.matches_domain(name, geo, decision)? {
                            return Ok(Some(*index));
                        }
                    }
                }
                PolicyStep::GeoSite(index) => {
                    for code in policies[*index].geosite_codes() {
                        if geo.matches_geosite_bounded(code, name, decision)? {
                            return Ok(Some(*index));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DomainNode {
    labels: HashMap<String, usize>,
    wildcard: Option<usize>,
    exact: Option<usize>,
    suffix: Option<usize>,
}

/// A flat arena keeps construction and destruction independent of pattern
/// depth; lookup depth is bounded by the validated DNS question.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DomainIndex(Vec<DomainNode>);

impl DomainIndex {
    pub(crate) fn new() -> Self {
        Self(vec![DomainNode::default()])
    }

    pub(crate) fn insert(&mut self, pattern: &str, policy: usize) {
        let (domain, exact, suffix) = if let Some(domain) = pattern.strip_prefix("+.") {
            (domain, true, true)
        } else if let Some(domain) = pattern.strip_prefix('.') {
            (domain, false, true)
        } else {
            (pattern, true, false)
        };
        let mut current = 0;
        for label in domain.rsplit('.') {
            let child = if label == "*" {
                self.0[current].wildcard
            } else {
                self.0[current].labels.get(label).copied()
            };
            current = child.unwrap_or_else(|| {
                let next = self.0.len();
                self.0.push(DomainNode::default());
                if label == "*" {
                    self.0[current].wildcard = Some(next);
                } else {
                    self.0[current].labels.insert(label.to_owned(), next);
                }
                next
            });
        }
        if exact {
            self.0[current].exact = Some(policy);
        }
        if suffix {
            self.0[current].suffix = Some(policy);
        }
    }

    pub(crate) fn find(&self, current: usize, name: &str) -> Option<usize> {
        let node = &self.0[current];
        if name.is_empty() {
            return node.exact;
        }
        let (rest, label) = name.rsplit_once('.').unwrap_or(("", name));
        node.labels
            .get(label)
            .and_then(|child| self.find(*child, rest))
            .or_else(|| node.wildcard.and_then(|child| self.find(child, rest)))
            .or(node.suffix)
    }
}
