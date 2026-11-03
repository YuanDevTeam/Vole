//! Immutable programs and bounded resumable rule traversal.
use std::{net::IpAddr, sync::Arc};

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
    pub disabled: Arc<super::rule_disable::RuleDisable>,
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
    disabled: super::rule_disable::Snapshot,
    rematch: Option<Box<super::rematch::RematchCursor>>,
}

impl RuleCursor {
    fn new(index: usize, disabled: super::rule_disable::Snapshot) -> Self {
        let frame = Frame {
            program: 0,
            index: 0,
            address: None,
        };
        let mut frames = [frame; 33];
        frames[0].index = index;
        Self {
            frames,
            depth: 0,
            disabled,
            rematch: None,
        }
    }
    pub(crate) fn root_index(&self) -> usize {
        if self.frames[0].program == 0 {
            self.frames[0].index
        } else {
            self.rematch
                .as_ref()
                .map_or(usize::MAX, |state| state.unlisted_index)
        }
    }
}

// The fixed cursor is inline; ordinary decisions do not allocate a call stack.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProgramEvaluation {
    Matched(RuleMatch),
    NeedsIpResolution(RuleCursor),
    NeedsProcessLookup(RuleCursor),
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
            Self::NeedsProcessLookup(cursor) => RuleEvaluation::NeedsProcessLookup {
                rule_index: cursor.root_index(),
            },
        }
    }
}

pub(crate) enum RuleTargetEffect {
    Accept,
    Skip,
    Control(RuleControl),
    Rematch(Arc<super::rematch::RematchTarget>),
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
        let mut cursor =
            cursor.unwrap_or_else(|| RuleCursor::new(0, self.graph.disabled.snapshot()));
        loop {
            if let Err(failure) = context.decision().check() {
                return ProgramEvaluation::Failed(failure);
            }
            let frame = cursor.frames[cursor.depth];
            if frame.program == 0 && cursor.disabled.contains(frame.index) {
                cursor.frames[0].index += 1;
                continue;
            }
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
                        Err(super::PredicateFailure::NeedsProcessLookup) => {
                            return ProgramEvaluation::NeedsProcessLookup(cursor);
                        }
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
                    Err(super::PredicateFailure::NeedsProcessLookup) => {
                        return ProgramEvaluation::NeedsProcessLookup(cursor);
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
                RuleTargetEffect::Rematch(target) => {
                    let state = cursor.rematch.get_or_insert_with(|| {
                        Box::new(super::rematch::RematchCursor::new(self.len()))
                    });
                    if let Err(failure) = state.enter(&target.name, context.decision()) {
                        return ProgramEvaluation::Failed(failure);
                    }
                    // Retain addresses, source, identity, budget and deadline from
                    // the predicate that actually selected this control.
                    *context = candidate;
                    if let Some(name) = &target.config.target_rematch_name {
                        context.rematch_name = (!name.is_empty()).then(|| name.clone());
                    }
                    let program = if let Some(name) = &target.config.target_sub_rule {
                        match self.rematch_program(name, context.decision()) {
                            Ok(program) => program,
                            Err(failure) => return ProgramEvaluation::Failed(failure),
                        }
                    } else {
                        cursor.frames[0].program
                    };
                    cursor.depth = 0;
                    cursor.frames[0] = Frame {
                        program,
                        index: 0,
                        address: None,
                    };
                    // Keep the original D07 switch snapshot across every restart.
                }
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

    fn rematch_program(
        &self,
        name: &str,
        decision: &crate::config::RuleDecision,
    ) -> Result<usize, crate::config::MatchFailure> {
        if !name.is_empty() {
            for (index, program) in self.graph.sub_rules.iter().enumerate() {
                decision.visit()?;
                if program.name == name {
                    return Ok(index + 1);
                }
            }
        }
        Ok(0)
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
            Some(RuleCursor::new(index, self.graph.disabled.snapshot())),
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

    fn rematch_fixture(yaml: &str) -> (RuleSet, super::super::RematchTargets) {
        let mut config = Config::parse_yaml(yaml.as_bytes()).unwrap();
        let targets = super::super::RematchTargets::new(&config.proxies);
        (RuleSet::compile_config(&mut config).unwrap(), targets)
    }

    fn rematch_effect(
        targets: &super::super::RematchTargets,
        action: RuleAction,
    ) -> RuleTargetEffect {
        if let RuleAction::Route(crate::config::RouteTargetId::Proxy(id)) = action
            && let Some(target) = targets.get(id)
        {
            return RuleTargetEffect::Rematch(target.clone());
        }
        RuleTargetEffect::Accept
    }

    #[test]
    fn rematch_sets_clears_and_preserves_metadata_and_selects_root_programs() {
        let cases = [
            // A selected child root has no row in GET /rules. Its hit must use
            // the existing sentinel, even when child index equals a main index.
            (
                r#"
proxies:
  - {name: mark, type: rematch, target-rematch-name: phase}
  - {name: clear, type: rematch, target-rematch-name: '', target-sub-rule: clean}
rules: ['REMATCH-NAME,phase,clear', 'MATCH,mark']
sub-rules:
  clean: ['NOT,((REMATCH-NAME,phase)),DIRECT', 'MATCH,REJECT']
"#,
                2,
                None,
            ),
            // Omitting the sub-rule preserves the selected root; omitting the
            // name on a subsequent control preserves the mark.
            (
                r#"
proxies:
  - {name: mark, type: rematch, target-rematch-name: phase, target-sub-rule: first}
  - {name: retag, type: rematch, target-rematch-name: done}
  - {name: jump, type: rematch, target-sub-rule: last}
rules: ['MATCH,mark']
sub-rules:
  first: ['REMATCH-NAME,phase,retag', 'REMATCH-NAME,done,jump', 'MATCH,REJECT']
  last: ['REMATCH-NAME,done,DIRECT', 'MATCH,REJECT']
"#,
                1,
                Some("done"),
            ),
            (
                r#"
proxies: [{name: jump, type: rematch, target-rematch-name: phase, target-sub-rule: missing}]
rules: ['REMATCH-NAME,phase,DIRECT', 'MATCH,jump']
"#,
                0,
                Some("phase"),
            ),
            (
                r#"
proxies: [{name: jump, type: rematch, target-rematch-name: phase, target-sub-rule: ''}]
rules: ['REMATCH-NAME,phase,DIRECT', 'MATCH,jump']
"#,
                0,
                Some("phase"),
            ),
            // Existing empty programs exhaust to DIRECT; they are not unknown.
            (
                r#"
proxies: [{name: jump, type: rematch, target-sub-rule: empty}]
rules: ['MATCH,jump', 'MATCH,REJECT']
sub-rules: {empty: []}
"#,
                2,
                None,
            ),
        ];
        for (yaml, expected_index, expected_name) in cases {
            let (rules, targets) = rematch_fixture(yaml);
            let mut context = context();
            assert!(matches!(
                rules.evaluate_program(&mut context, &EmptyGeoMatcher, None, None,
                    |action, _| rematch_effect(&targets, action)),
                ProgramEvaluation::Matched(RuleMatch { action: RuleAction::Direct, rule_index })
                    if rule_index == expected_index
            ));
            assert_eq!(context.rematch_name.as_deref(), expected_name);
        }
    }

    #[test]
    fn rematch_keeps_lazy_progress_and_the_original_rule_switch_snapshot() {
        let (rules, targets) = rematch_fixture(
            r#"
proxies: [{name: mark, type: rematch, target-rematch-name: done}]
rules:
  - REMATCH-NAME,done,DIRECT
  - AND,((PROCESS-NAME,app),(IP-CIDR,192.0.2.0/24)),mark
  - MATCH,REJECT
"#,
        );
        let mut context = context();
        context.enable_process_lookup(true);
        let cursor =
            match rules.evaluate_program(&mut context, &EmptyGeoMatcher, None, None, |action, _| {
                rematch_effect(&targets, action)
            }) {
                ProgramEvaluation::NeedsProcessLookup(cursor) => cursor,
                _ => panic!("process identity must be requested only at its predicate"),
            };
        assert!(cursor.rematch.is_none());
        context.set_process(crate::process::Identity {
            name: Some("app".into()),
            ..Default::default()
        });
        let cursor = match rules.evaluate_program(
            &mut context,
            &EmptyGeoMatcher,
            Some(cursor),
            None,
            |action, _| rematch_effect(&targets, action),
        ) {
            ProgramEvaluation::NeedsIpResolution(cursor) => cursor,
            _ => panic!("DNS continuation must retain completed process lookup"),
        };
        rules.disable_state().apply(&[(0, true)]).unwrap();
        let addresses = ["192.0.2.7".parse().unwrap()];
        assert!(matches!(
            rules.evaluate_program(
                &mut context,
                &EmptyGeoMatcher,
                Some(cursor),
                Some(&addresses),
                |action, _| rematch_effect(&targets, action)
            ),
            ProgramEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                rule_index: 0
            })
        ));
        assert_eq!(context.pinned_ip(), Some(addresses[0]));
        assert_eq!(
            context
                .process()
                .and_then(|identity| identity.name.as_deref()),
            Some("app")
        );
    }

    #[test]
    fn rematch_keeps_the_original_cancellation_and_deadline() {
        let (rules, targets) = rematch_fixture(
            r#"
proxies: [{name: mark, type: rematch, target-rematch-name: done}]
rules: ['REMATCH-NAME,done,DIRECT', 'MATCH,mark']
"#,
        );
        for cancel in [false, true] {
            let mut context = context();
            let token = tokio_util::sync::CancellationToken::new();
            context.decision().set_cancellation(token.clone());
            let result = rules.evaluate_program(
                &mut context,
                &EmptyGeoMatcher,
                None,
                None,
                |action, candidate| {
                    if cancel {
                        token.cancel();
                    } else {
                        candidate.decision().set_deadline(
                            std::time::Instant::now() - std::time::Duration::from_secs(1),
                        );
                    }
                    rematch_effect(&targets, action)
                },
            );
            let expected = if cancel {
                crate::config::MatchFailure::Cancelled
            } else {
                crate::config::MatchFailure::Budget
            };
            assert!(matches!(result, ProgramEvaluation::Failed(failure) if failure == expected));
        }
    }

    #[test]
    fn rematch_repeated_node_fails_before_replaying_its_effect() {
        let (rules, targets) = rematch_fixture(
            r#"
proxies:
  - {name: first, type: rematch, target-rematch-name: a}
  - {name: second, type: rematch, target-rematch-name: b}
rules: ['REMATCH-NAME,b,first', 'REMATCH-NAME,a,second', 'MATCH,first']
"#,
        );
        let mut calls = 0;
        assert!(matches!(
            rules.evaluate_program(&mut context(), &EmptyGeoMatcher, None, None, |action, _| {
                calls += 1;
                rematch_effect(&targets, action)
            }),
            ProgramEvaluation::Failed(crate::config::MatchFailure::Budget)
        ));
        assert_eq!(calls, 3);
    }

    #[test]
    fn disabled_main_rules_skip_subprograms_and_keep_the_decision_snapshot() {
        let rules = compile(
            "rules: ['SUB-RULE,(NETWORK,TCP),child', 'MATCH,REJECT']\nsub-rules: {child: ['IP-CIDR,192.0.2.0/24,DIRECT']}\n",
        );
        let mut context = self::context();
        let cursor =
            match rules.evaluate_program(&mut context, &EmptyGeoMatcher, None, None, |_, _| {
                RuleTargetEffect::Accept
            }) {
                ProgramEvaluation::NeedsIpResolution(cursor) => cursor,
                _ => panic!("child IP predicate must pause"),
            };
        rules.disable_state().apply(&[(0, true)]).unwrap();
        assert!(matches!(
            rules.evaluate_program(
                &mut context,
                &EmptyGeoMatcher,
                Some(cursor),
                Some(&["192.0.2.7".parse().unwrap()]),
                |_, _| RuleTargetEffect::Accept
            ),
            ProgramEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                rule_index: 0
            })
        ));
        assert!(matches!(
            rules.evaluate(&self::context()),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Reject,
                rule_index: 1
            })
        ));
        let fresh = compile(
            "rules: ['SUB-RULE,(NETWORK,TCP),child', 'MATCH,REJECT']\nsub-rules: {child: ['IP-CIDR,192.0.2.0/24,DIRECT']}\n",
        );
        assert!(matches!(
            fresh.evaluate(&self::context()),
            RuleEvaluation::NeedsIpResolution { rule_index: 0 }
        ));
    }

    #[test]
    fn process_cursor_is_lazy_once_and_keeps_dns_and_subrule_progress() {
        let rules = compile(
            "rules: ['SUB-RULE,(NETWORK,TCP),child', 'MATCH,REJECT']\nsub-rules: {child: ['DOMAIN,never.invalid,DIRECT', 'AND,((PROCESS-NAME,APP),(IP-CIDR,192.0.2.0/24)),DIRECT']}\n",
        );
        let mut context = context();
        context.enable_process_lookup(true);
        let cursor =
            match rules.evaluate_program(&mut context, &EmptyGeoMatcher, None, None, |_, _| {
                RuleTargetEffect::Accept
            }) {
                ProgramEvaluation::NeedsProcessLookup(cursor) => cursor,
                _ => panic!("strict must pause at the actual identity predicate"),
            };
        context.set_process(crate::process::Identity {
            name: Some("app".into()),
            ..Default::default()
        });
        let cursor = match rules.evaluate_program(
            &mut context,
            &EmptyGeoMatcher,
            Some(cursor),
            None,
            |_, _| RuleTargetEffect::Accept,
        ) {
            ProgramEvaluation::NeedsIpResolution(cursor) => cursor,
            _ => panic!("identity continuation must preserve the child DNS position"),
        };
        let addresses = ["192.0.2.7".parse().unwrap()];
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
                rule_index: 0
            })
        ));
        assert_eq!(context.pinned_ip(), Some(addresses[0]));

        for yaml in [
            "rules: ['MATCH,DIRECT', 'PROCESS-NAME,app,REJECT']\n",
            "rules: ['AND,((DOMAIN,never.invalid),(PROCESS-NAME,app)),REJECT', 'MATCH,DIRECT']\n",
            "rules: ['MATCH,DIRECT']\n",
        ] {
            let mut context = self::context();
            context.enable_process_lookup(true);
            assert!(matches!(
                compile(yaml).evaluate_program(
                    &mut context,
                    &EmptyGeoMatcher,
                    None,
                    None,
                    |_, _| RuleTargetEffect::Accept
                ),
                ProgramEvaluation::Matched(RuleMatch {
                    action: RuleAction::Direct,
                    ..
                })
            ));
            assert!(context.process().is_none());
        }
        let mut context = self::context();
        let rules = compile("rules: ['PROCESS-NAME-REGEX,.*,REJECT', 'MATCH,DIRECT']\n");
        // off and inaccessible identity never match an empty-string regex.
        assert!(matches!(
            rules.evaluate(&context),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                ..
            })
        ));
        context.enable_process_lookup(true);
        context.set_process(Default::default());
        assert!(matches!(
            rules.evaluate(&context),
            RuleEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                ..
            })
        ));
    }

    #[test]
    fn classical_process_provider_resumes_without_selector_side_effects() {
        let rules = compile(
            "rule-providers: {identity: {type: inline, behavior: classical, payload: ['PROCESS-PATH-REGEX,^/路径/.*$']}}\nrules: ['RULE-SET,identity,DIRECT','MATCH,REJECT']\n",
        );
        let mut context = context();
        context.enable_process_lookup(true);
        let cursor =
            match rules.evaluate_program(&mut context, &EmptyGeoMatcher, None, None, |_, _| {
                RuleTargetEffect::Accept
            }) {
                ProgramEvaluation::NeedsProcessLookup(cursor) => cursor,
                _ => panic!("provider must pause"),
            };
        context.set_process(crate::process::Identity {
            path: Some("/路径/程序".into()),
            ..Default::default()
        });
        assert!(matches!(
            rules.evaluate_program(
                &mut context,
                &EmptyGeoMatcher,
                Some(cursor),
                None,
                |_, _| RuleTargetEffect::Accept
            ),
            ProgramEvaluation::Matched(RuleMatch {
                action: RuleAction::Direct,
                ..
            })
        ));
        let crate::config::RuleKind::RuleSet {
            content: Some(set), ..
        } = &rules.graph.main[0].kind
        else {
            panic!("bound provider")
        };
        assert!(
            !set.matches_domain("example.com", &EmptyGeoMatcher, &Default::default())
                .unwrap()
        );
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
