//! Real document/rule compiler controls without listeners or peers.
use super::*;
use crate::http_processing::rules::{
    MAX_PATTERN, MAX_RULE_TEXT, Matcher, Phase, RuleAction, SelectorCompiler, UrlAction,
};
use regex::Regex;
use serde_json::{Value, json};

const UP: &str = r"^https://example\.test/up/(?P<id>[0-9]+)$";
const DOWN: &str = r"^https://example\.test/down/(?P<id>[0-9]+)$";

fn document(value: Value) -> Arc<Document> {
    Document::parse(&serde_yaml_ng::to_string(&value).unwrap()).unwrap()
}

fn raw(value: Value) -> RawRule {
    serde_yaml_ng::from_str(&serde_yaml_ng::to_string(&value).unwrap()).unwrap()
}

fn selector(rule: &Rule) -> &Arc<Regex> {
    let Matcher::Regex(regex) = &rule.selector.matcher else {
        panic!("expected a native regex selector");
    };
    regex
}

fn target(rule: &Rule, input: &str) -> String {
    let Some(UrlAction::Forward(url)) =
        rule.evaluate_url(&url::Url::parse(input).unwrap()).unwrap()
    else {
        panic!("expected an actual URL replacement");
    };
    url.to_string()
}

fn source_inputs() -> Arc<Document> {
    let origins = ["https://example.test"];
    let first = json!({"targets": [
        {"origins": origins, "rules": [
            {"match": {"url-regex": UP}, "request": {"headers": [{"set": {"X-Proof": "one"}}]}}
        ]}
    ]});
    let second = json!({"targets": [
        {"origins": origins, "rules": [
            {"match": {"url-regex": DOWN}, "response": {"body": [{"replace": {"search": "a", "replacement": "b"}}]}},
            {"match": {"url-regex": UP}, "request": {"url": {"replace": "https://one.test/${id}"}}}
        ]},
        {"origins": origins, "rules": [
            {"match": {"url-regex": DOWN}, "request": {"url": {"replace": "https://two.test/$1"}}}
        ]}
    ]});
    Document::parse_documents(&[
        serde_yaml_ng::to_string(&first).unwrap(),
        serde_yaml_ng::to_string(&second).unwrap(),
    ])
    .unwrap()
}

#[test]
fn native_selectors_share_within_candidate_without_merging_sources_or_captures() {
    let candidate = source_inputs().compile().unwrap();
    assert_eq!(candidate.rules.len(), 4);
    assert!(Arc::ptr_eq(
        selector(&candidate.rules[0]),
        selector(&candidate.rules[2]),
    ));
    assert!(Arc::ptr_eq(
        selector(&candidate.rules[1]),
        selector(&candidate.rules[3]),
    ));
    assert!(!Arc::ptr_eq(
        selector(&candidate.rules[0]),
        selector(&candidate.rules[1]),
    ));
    assert!(matches!(
        &candidate.rules[0].action,
        RuleAction::Header {
            phase: Phase::Request,
            ..
        }
    ));
    assert!(matches!(
        &candidate.rules[1].action,
        RuleAction::Body {
            phase: Phase::Response,
            ..
        }
    ));
    for (index, (source, target, rule)) in [(0, 0, 0), (1, 0, 0), (1, 0, 1), (1, 1, 0)]
        .into_iter()
        .enumerate()
    {
        assert!(matches!(
            candidate.origin(index),
            Some(SourceLocation { source: s, target: t, index: i }) if (*s, *t, *i) == (source, target, rule)
        ));
    }
    assert_eq!(
        target(&candidate.rules[2], "https://example.test/up/17"),
        "https://one.test/17"
    );
    assert_eq!(
        target(&candidate.rules[3], "https://example.test/down/23"),
        "https://two.test/23"
    );
}

#[test]
fn native_selector_owners_are_generation_local_and_release_after_last_policy_owner() {
    let first = source_inputs().compile().unwrap();
    let second = source_inputs().compile().unwrap();
    assert_eq!(first.identity(), second.identity());
    assert!(!Arc::ptr_eq(
        selector(&first.rules[0]),
        selector(&second.rules[0]),
    ));
    let weak = Arc::downgrade(selector(&first.rules[0]));
    let policy = first.bind_settings(&Default::default(), None).unwrap();
    let last_owner = Arc::clone(&first);
    drop(first);
    assert!(weak.upgrade().is_some());
    drop(policy);
    assert!(weak.upgrade().is_some());
    drop(last_owner);
    assert!(weak.upgrade().is_none());
    assert!(second.rules[0].matches(&url::Url::parse("https://example.test/up/17").unwrap()));
}

#[test]
fn native_selector_sharing_preserves_limits_on_rule_count_and_text() {
    let reject = json!({"match": {"url-regex": "."}, "request": {"url": {"reject": true}}});
    let source = |count| {
        serde_yaml_ng::to_string(&json!({"targets": [
            {"origins": ["http://example.test"], "rules": vec![reject.clone(); count]}
        ]}))
        .unwrap()
    };
    let full = document(json!({"targets": [
        {"origins": ["http://example.test"], "rules": vec![reject.clone(); MAX_RULES]}
    ]}))
    .compile()
    .unwrap();
    assert_eq!(full.rules.len(), MAX_RULES);
    assert!(
        full.rules
            .iter()
            .all(|rule| Arc::ptr_eq(selector(rule), selector(&full.rules[0])))
    );
    assert!(
        Document::parse_documents(&[source(MAX_RULES), source(1)])
            .and_then(|document| document.compile())
            .is_err()
    );

    // The comment keeps the NFA small while charging exact raw pattern bytes.
    let pattern = format!("(?x)#{}", "a".repeat(MAX_PATTERN - 5));
    assert_eq!(pattern.len(), MAX_PATTERN);
    let mut selectors = SelectorCompiler::default();
    let mut text = 0;
    let mut first = None;
    for _ in 0..MAX_RULE_TEXT / MAX_PATTERN {
        let rule = Rule::compile_with_selectors(
            raw(json!({"url": pattern, "action": "reject"})),
            &mut text,
            &mut selectors,
        )
        .unwrap();
        if let Some(first) = &first {
            assert!(Arc::ptr_eq(selector(first), selector(&rule)));
        } else {
            first = Some(rule);
        }
    }
    assert_eq!(text, MAX_RULE_TEXT);
    assert!(
        Rule::compile_with_selectors(
            raw(json!({"url": pattern, "action": "reject"})),
            &mut text,
            &mut selectors,
        )
        .is_err()
    );
    assert_eq!(text, MAX_RULE_TEXT);
}
