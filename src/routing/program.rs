//! Immutable programs and bounded resumable rule traversal.
use std::net::IpAddr;

use super::{
    GeoMatcher, RoutingContext, RuleEvaluation, RuleMatch, RuleSet, matches_rule,
    preferred_addresses, uses_destination_ip,
};
use crate::config::{NamedRuleProgram, RuleAction, RuleControl, RuleKind, RuleSpec};

#[derive(Debug)]
pub(super) struct CompiledProgram {
    pub main: Box<[RuleSpec]>,
    pub sub_rules: Box<[NamedRuleProgram]>,
    pub uses_domain_routing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Frame {
    program: usize,
    index: usize,
    address: Option<IpAddr>,
}

/// Pauses only the current predicate; completed controls and groups are not replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleCursor {
    frames: [Frame; 33],
    depth: usize,
}

impl RuleCursor {
    fn new(index: usize) -> Self {
        let frame = Frame {
            program: 0,
            index: 0,
            address: None,
        };
        let mut frames = [frame; 33];
        frames[0].index = index;
        Self { frames, depth: 0 }
    }
    pub(crate) fn root_index(&self) -> usize {
        self.frames[0].index
    }
}

// The fixed cursor is inline; ordinary decisions do not allocate a call stack.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProgramEvaluation {
    Matched(RuleMatch),
    NeedsIpResolution(RuleCursor),
    Failed(crate::config::MatchFailure),
}

impl ProgramEvaluation {
    pub(crate) fn into_public(self) -> RuleEvaluation {
        match self {
            Self::Failed(failure) => RuleEvaluation::Failed(failure),
            Self::Matched(matched) => RuleEvaluation::Matched(matched),
            Self::NeedsIpResolution(cursor) => RuleEvaluation::NeedsIpResolution {
                rule_index: cursor.root_index(),
            },
        }
    }
}

pub(crate) enum RuleTargetEffect {
    Accept,
    Skip,
    Control(RuleControl),
}

impl RuleSet {
    pub(crate) fn evaluate_program(
        &self,
        context: &mut RoutingContext,
        geo: &dyn GeoMatcher,
        cursor: Option<RuleCursor>,
        addresses: Option<&[IpAddr]>,
        mut effect: impl FnMut(RuleAction, &RoutingContext) -> RuleTargetEffect,
    ) -> ProgramEvaluation {
        let mut cursor = cursor.unwrap_or_else(|| RuleCursor::new(0));
        loop {
            if let Err(failure) = context.decision().check() {
                return ProgramEvaluation::Failed(failure);
            }
            let frame = cursor.frames[cursor.depth];
            let rules = if frame.program == 0 {
                &self.graph.main[..]
            } else {
                &self.graph.sub_rules[frame.program - 1].rules[..]
            };
            let Some(rule) = rules.get(frame.index) else {
                if cursor.depth == 0 {
                    return ProgramEvaluation::Matched(RuleMatch {
                        action: RuleAction::Direct,
                        rule_index: self.len(),
                    });
                }
                cursor.depth -= 1;
                cursor.frames[cursor.depth].index += 1;
                continue;
            };
            let predicate = match &rule.kind {
                RuleKind::Flow { predicate, .. } | RuleKind::SubRule { predicate, .. } => predicate,
                _ => rule,
            };
            let mut candidate = context.clone();
            if let Some(address) = frame.address {
                candidate.pin_ip(address);
            }
            let matched = if candidate.effective_ip().is_none()
                && uses_destination_ip(predicate)
                && let Some(addresses) = addresses
                && !addresses.is_empty()
            {
                let mut found = None;
                for address in preferred_addresses(addresses) {
                    candidate.pin_ip(address);
                    match matches_rule(predicate, &candidate, geo) {
                        Ok(true) => {
                            found = Some(address);
                            break;
                        }
                        Ok(false) | Err(super::PredicateFailure::NeedsIpResolution) => {}
                        Err(super::PredicateFailure::Evaluation(failure)) => {
                            return ProgramEvaluation::Failed(failure);
                        }
                    }
                }
                if let Some(address) = found {
                    candidate.pin_ip(address);
                    true
                } else {
                    false
                }
            } else {
                if addresses.is_some() {
                    candidate.mark_ip_resolution_unavailable();
                }
                match matches_rule(predicate, &candidate, geo) {
                    Ok(matched) => matched,
                    Err(super::PredicateFailure::NeedsIpResolution) => {
                        return ProgramEvaluation::NeedsIpResolution(cursor);
                    }
                    Err(super::PredicateFailure::Evaluation(failure)) => {
                        return ProgramEvaluation::Failed(failure);
                    }
                }
            };
            if !matched {
                cursor.frames[cursor.depth].index += 1;
                continue;
            }
            let effect = match &rule.kind {
                RuleKind::Flow { control, .. } => RuleTargetEffect::Control(*control),
                RuleKind::SubRule { target, .. } => {
                    cursor.depth += 1;
                    cursor.frames[cursor.depth] = Frame {
                        program: target.index() + 1,
                        index: 0,
                        address: candidate.pinned_ip(),
                    };
                    continue;
                }
                _ => effect(rule.action, &candidate),
            };
            match effect {
                RuleTargetEffect::Control(RuleControl::Pass) => {
                    cursor.depth = 0;
                    cursor.frames[0].index += 1;
                }
                RuleTargetEffect::Control(RuleControl::PassRule) if cursor.depth == 0 => {
                    return ProgramEvaluation::Matched(RuleMatch {
                        action: RuleAction::Reject,
                        rule_index: cursor.root_index(),
                    });
                }
                RuleTargetEffect::Skip | RuleTargetEffect::Control(RuleControl::PassRule) => {
                    cursor.frames[cursor.depth].index += 1
                }
                RuleTargetEffect::Accept => {
                    if let Some(address) = candidate.pinned_ip() {
                        context.pin_ip(address);
                    }
                    return ProgramEvaluation::Matched(RuleMatch {
                        action: rule.action,
                        rule_index: cursor.root_index(),
                    });
                }
            }
        }
    }

    pub(super) fn flat_resolved(
        &self,
        context: &mut RoutingContext,
        geo: &dyn GeoMatcher,
        index: usize,
        addresses: &[IpAddr],
        effect: impl FnMut(RuleAction, &RoutingContext) -> RuleTargetEffect,
    ) -> RuleEvaluation {
        self.evaluate_program(
            context,
            geo,
            Some(RuleCursor::new(index)),
            Some(addresses),
            effect,
        )
        .into_public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, Network, RuntimeRuleProgram},
        routing::EmptyGeoMatcher,
        session::Destination,
    };

    fn compile(yaml: &str) -> RuleSet {
        let mut config =
            Config::parse_yaml(format!("mixed-port: 1080\n{yaml}").as_bytes()).unwrap();
        RuleSet::compile_config(&mut config).unwrap()
    }
    fn context() -> RoutingContext {
        RoutingContext::new(
            Network::Tcp,
            &Destination::domain("example.com", 443).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn subrule_nested_calls_and_flow_controls_preserve_root_position() {
        for (inner, outer_tail, expected, index) in [
            ("['DOMAIN,example.com,REJECT']", "", RuleAction::Reject, 0),
            ("[]", ", 'MATCH,REJECT'", RuleAction::Reject, 0),
            ("['MATCH,PASS']", ", 'MATCH,REJECT'", RuleAction::Direct, 1),
            (
                "['MATCH,PASS-RULE','MATCH,REJECT']",
                "",
                RuleAction::Reject,
                0,
            ),
        ] {
            let rules = compile(&format!(
                "rules: ['SUB-RULE,(NETWORK,TCP),outer', 'MATCH,DIRECT']\nsub-rules:\n  outer: ['SUB-RULE,(DOMAIN,example.com),inner'{outer_tail}]\n  inner: {inner}\n"
            ));
            assert_eq!(
                rules.evaluate(&context()),
                RuleEvaluation::Matched(RuleMatch {
                    action: expected,
                    rule_index: index
                })
            );
            assert!(std::sync::Arc::ptr_eq(&rules.graph, &rules.clone().graph));
        }
        assert_eq!(
            compile("rules: ['MATCH,PASS-RULE']\n").evaluate(&context()),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Reject,
                rule_index: 0
            })
        );
    }

    #[test]
    fn subrule_graph_validation_covers_references_and_combined_budget() {
        for yaml in [
            "rules: ['SUB-RULE,(NETWORK,TCP),missing']\n",
            "sub-rules: {a: ['SUB-RULE,(NETWORK,TCP),b'], b: ['SUB-RULE,(NETWORK,TCP),a']}\n",
        ] {
            assert!(Config::parse_yaml(format!("mixed-port: 1080\n{yaml}").as_bytes()).is_err());
        }
        for depth in [32, 33] {
            let definitions = (0..depth)
                .map(|index| {
                    let rule = if index + 1 == depth {
                        "MATCH,DIRECT".to_owned()
                    } else {
                        format!("SUB-RULE,(NETWORK,TCP),p{}", index + 1)
                    };
                    format!("  p{index}: ['{rule}']\n")
                })
                .collect::<String>();
            let parsed = Config::parse_yaml(format!("mixed-port: 1080\nrules: ['SUB-RULE,(NETWORK,TCP),p0']\nsub-rules:\n{definitions}").as_bytes());
            assert_eq!(parsed.is_ok(), depth == 32);
            if let Ok(mut config) = parsed {
                assert_eq!(
                    RuleSet::compile_config(&mut config)
                        .unwrap()
                        .evaluate(&context()),
                    RuleEvaluation::Matched(RuleMatch {
                        action: RuleAction::Direct,
                        rule_index: 0
                    })
                );
            }
        }
        let rules = compile("rules: ['MATCH,DIRECT']\nsub-rules: {one: ['MATCH,DIRECT']}\n");
        let program = RuntimeRuleProgram {
            main: vec![rules.graph.main[0].clone(); crate::config::MAX_RULES],
            sub_rules: rules.graph.sub_rules.to_vec(),
        };
        assert!(matches!(
            RuleSet::compile(program),
            Err(super::super::RuleSetError::TooManyRules { .. })
        ));
    }

    #[test]
    fn subrule_dns_cursor_does_not_replay_controls_or_mix_candidate_ips() {
        let rules = compile(
            "rules: ['SUB-RULE,(NETWORK,TCP),child', 'MATCH,REJECT']\nsub-rules: {child: ['NETWORK,TCP,DIRECT', 'IP-CIDR,192.0.2.0/24,DIRECT']}\n",
        );
        let mut context = context();
        let mut controls = 0;
        let cursor =
            match rules.evaluate_program(&mut context, &EmptyGeoMatcher, None, None, |_, _| {
                controls += 1;
                RuleTargetEffect::Control(RuleControl::PassRule)
            }) {
                ProgramEvaluation::NeedsIpResolution(cursor) => cursor,
                _ => panic!("expected a child DNS pause"),
            };
        let addresses = ["192.0.2.7".parse().unwrap()];
        let result = rules.evaluate_program(
            &mut context,
            &EmptyGeoMatcher,
            Some(cursor),
            Some(&addresses),
            |_, _| RuleTargetEffect::Accept,
        );
        assert_eq!(controls, 1);
        assert_eq!(
            result.into_public(),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                rule_index: 0
            })
        );
        assert_eq!(context.pinned_ip(), Some(addresses[0]));
        let rules = compile(
            "rules: ['SUB-RULE,(IP-CIDR,192.0.2.0/24),child', 'MATCH,REJECT']\nsub-rules: {child: ['IP-CIDR,198.51.100.0/24,DIRECT']}\n",
        );
        let mut context = self::context();
        let result = rules.evaluate_program(
            &mut context,
            &EmptyGeoMatcher,
            None,
            Some(&[addresses[0], "198.51.100.7".parse().unwrap()]),
            |_, _| RuleTargetEffect::Accept,
        );
        assert_eq!(
            result.into_public(),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Reject,
                rule_index: 1
            })
        );
        assert_eq!(context.pinned_ip(), None);
    }
    #[test]
    fn suffix_rules_use_source_low_bits_and_resume_with_shared_provider_budget() {
        let rules = compile(
            "rules: ['SUB-RULE,(NETWORK,TCP),child', 'MATCH,REJECT']\nsub-rules: {child: ['AND,((SRC-IP-SUFFIX,192.0.2.19/5),(IP-SUFFIX,198.51.100.7/9)),DIRECT']}\n",
        );
        let mut context = self::context();
        context.set_source("203.0.113.51:9000".parse().unwrap());
        let cursor =
            match rules.evaluate_program(&mut context, &EmptyGeoMatcher, None, None, |_, _| {
                RuleTargetEffect::Accept
            }) {
                ProgramEvaluation::NeedsIpResolution(cursor) => cursor,
                _ => panic!("destination suffix must request lazy DNS"),
            };
        let addresses = [
            "203.0.113.8".parse().unwrap(),
            "203.0.112.7".parse().unwrap(),
        ];
        assert!(matches!(
            rules.evaluate_program(
                &mut context,
                &EmptyGeoMatcher,
                Some(cursor),
                Some(&addresses),
                |_, _| RuleTargetEffect::Accept
            ),
            ProgramEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                ..
            })
        ));
        assert_eq!(context.pinned_ip(), Some(addresses[1]));

        // A classical provider spends most of the decision's complex quota before DNS.
        let payload = vec!["DOMAIN-REGEX,(?=never)never"; 31];
        let payload = serde_json::to_string(&payload).unwrap();
        let rules = compile(&format!(
            "rule-providers: {{patterns: {{type: inline, behavior: classical, payload: {payload}}}}}\nrules: ['RULE-SET,patterns,REJECT', 'IP-SUFFIX,192.0.2.19/5,REJECT', 'DOMAIN-REGEX,(?=never)never,REJECT', 'MATCH,DIRECT']\n"
        ));
        let mut context = self::context();
        assert!(matches!(
            rules.evaluate(&context),
            RuleEvaluation::NeedsIpResolution { rule_index: 1 }
        ));
        assert_eq!(
            rules.evaluate_with_resolved_ips(
                &mut context,
                &EmptyGeoMatcher,
                1,
                &["203.0.113.20".parse().unwrap()]
            ),
            RuleEvaluation::Failed(crate::config::MatchFailure::Budget)
        );
        assert_eq!(
            rules.evaluate(&context),
            RuleEvaluation::Failed(crate::config::MatchFailure::Budget)
        );
    }
}
