//! Real document/rule compiler controls; no listeners, peers or user scripts.
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

fn payload(value: Value) -> Arc<Payload> {
    Arc::new(Payload::parse(serde_yaml_ng::to_string(&value).unwrap().as_bytes()).unwrap())
}

fn raw(value: Value) -> RawRule {
    serde_yaml_ng::from_str(&serde_yaml_ng::to_string(&value).unwrap()).unwrap()
}

fn selector(rule: &Rule) -> &Arc<Regex> {
    let Matcher::Regex(regex) = &rule.selector else {
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

fn source_inputs() -> (Arc<Document>, BTreeMap<String, Arc<Payload>>) {
    let document = document(json!({
        "rewrite-providers": {"inside": {"type": "file", "path": "rules.yaml"}},
        "rewrite": {
            "enabled": true,
            "rules": [
                {
                    "url": UP, "action": "request-header-set",
                    "header": "X-Proof", "value": "one"
                },
                {"rule-set": "inside"},
                {
                    "url": DOWN, "action": "replace",
                    "replacement": "https://two.test/$1"
                }
            ]
        }
    }));
    let payload = payload(json!({"payload": [
        {
            "url": DOWN, "action": "response-body-replace",
            "search": "a", "replacement": "b"
        },
        {
            "url": UP, "action": "replace",
            "replacement": "https://one.test/${id}"
        }
    ]}));
    (document, BTreeMap::from([("inside".to_owned(), payload)]))
}

#[test]
fn native_selectors_share_within_candidate_without_merging_origins_or_captures() {
    let (document, contents) = source_inputs();
    let candidate = document.compile(&contents).unwrap();
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
    assert!(matches!(
        candidate.origin(0),
        Some(SourceLocation::Local { index: 0 })
    ));
    assert!(matches!(
        candidate.origin(1),
        Some(SourceLocation::Provider { provider, index: 0 }) if provider == "inside"
    ));
    assert!(matches!(
        candidate.origin(2),
        Some(SourceLocation::Provider { provider, index: 1 }) if provider == "inside"
    ));
    assert!(matches!(
        candidate.origin(3),
        Some(SourceLocation::Local { index: 2 })
    ));
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
    let (document, contents) = source_inputs();
    let first = document.compile(&contents).unwrap();
    let second = document.compile(&contents).unwrap();
    assert_eq!(first.identity(), second.identity());
    assert!(!Arc::ptr_eq(
        selector(&first.rules[0]),
        selector(&second.rules[0]),
    ));
    let weak = Arc::downgrade(selector(&first.rules[0]));
    let policy = first.bind_ca(None).unwrap();
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
fn native_selector_sharing_keeps_rule_text_pattern_and_disabled_boundaries() {
    let reject = json!({"url": ".", "action": "reject"});
    let full = document(json!({"rewrite": {
        "enabled": true, "rules": vec![reject.clone(); MAX_RULES]
    }}))
    .compile(&BTreeMap::new())
    .unwrap();
    assert_eq!(full.rules.len(), MAX_RULES);
    assert!(
        full.rules
            .iter()
            .all(|rule| Arc::ptr_eq(selector(rule), selector(&full.rules[0])))
    );
    let expanded = |count| {
        let document = document(json!({
            "rewrite-providers": {"inside": {"type": "file", "path": "rules.yaml"}},
            "rewrite": {"rules": [reject.clone(), {"rule-set": "inside"}]}
        }));
        let contents = BTreeMap::from([(
            "inside".to_owned(),
            payload(json!({"payload": vec![reject.clone(); count]})),
        )]);
        document.compile(&contents)
    };
    assert_eq!(expanded(MAX_RULES - 1).unwrap().rules.len(), MAX_RULES);
    assert!(expanded(MAX_RULES).is_err());

    // The comment keeps the regex NFA tiny while charging exact raw pattern bytes.
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

    let mut selectors = SelectorCompiler::default();
    let mut text = 0;
    let enabled = Rule::compile_with_selectors(raw(reject), &mut text, &mut selectors).unwrap();
    let disabled = Rule::compile_with_selectors(
        raw(json!({"url": ".", "action": "reject", "enabled": false})),
        &mut text,
        &mut selectors,
    )
    .unwrap();
    assert!(Arc::ptr_eq(selector(&enabled), selector(&disabled)));
    assert_eq!(text, 2);
    assert!(!disabled.matches(&url::Url::parse("https://example.test/").unwrap()));
    for pattern in [
        "(".to_owned(),
        format!("(?x)#{}", "a".repeat(MAX_PATTERN - 4)),
    ] {
        assert!(
            Rule::compile_with_selectors(
                raw(json!({"url": pattern, "action": "reject", "enabled": false})),
                &mut text,
                &mut selectors,
            )
            .is_err()
        );
        assert_eq!(text, 2);
    }
    let disabled_reference = document(json!({
        "rewrite-providers": {"missing": {"type": "file", "path": "never-read.yaml"}},
        "rewrite": {"rules": [{"rule-set": "missing", "enabled": false}]}
    }));
    assert_eq!(disabled_reference.unresolved_count(), 0);
    assert!(
        disabled_reference
            .compile(&BTreeMap::new())
            .unwrap()
            .rules
            .is_empty()
    );
    assert!(
        Document::parse(
            &serde_yaml_ng::to_string(&json!({
                "rewrite": {"enabled": false, "rules": [
                    {"url": "(", "action": "reject", "enabled": false}
                ]}
            }))
            .unwrap()
        )
        .is_err()
    );
}
