use super::*;

fn compile(input: &str) -> io::Result<Rule> {
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(input).map_err(|_| invalid())?;
    let raw = serde_yaml_ng::from_value(value).map_err(|_| invalid())?;
    Rule::compile(raw, &mut 0)
}

fn target(rule: &Rule, input: &str) -> String {
    match rule
        .evaluate_url(&checked_url(input).unwrap())
        .unwrap()
        .unwrap()
    {
        UrlAction::Forward(url) | UrlAction::Redirect { url, .. } => url.to_string(),
        UrlAction::Reject => panic!("unexpected reject"),
    }
}

#[test]
fn flat_rules_keep_defaults_and_reject_action_parameter_confusion() {
    let rule = compile("{url: '/v1/', action: replace, replacement: '/v2/'}").unwrap();
    assert!(rule.enabled);
    assert_eq!(
        target(&rule, "https://api.example/v1/a/v1/b?q=1"),
        "https://api.example/v2/a/v1/b?q=1"
    );
    for input in [
        "{url: '.', action: reject, replacement: ''}",
        "{url: '.', action: reject, replacement-mode: match}",
        "{url: '.', action: reject, value: null}",
        "{url: '.', action: reject, enabled: null}",
        "{url: '.', action: replace}",
        "{url: '.', action: request-header-remove, header: Server, value: ''}",
        "{url: '.', action: response-body-set, value: '', search-mode: literal}",
        "{url: '.', action: request-header-set, header: Host, value: example.com}",
        "{url: '.', action: response-header-add, header: X-Test, value: \"a\\r\\nb\"}",
        "{url: '.', action: response-body-replace, search: '', replacement: x}",
        "{url: '.', action: reject, pattern: '.'}",
        "{url: '.', match: {type: regex, value: '.'}, action: reject}",
        "{url: 123, action: reject}",
        "{url: '.', action: response-body-set, value: true}",
    ] {
        assert!(compile(input).is_err(), "accepted invalid rule: {input}");
    }
    let disabled = compile("{url: '.', action: reject, enabled: false}").unwrap();
    assert!(
        disabled
            .evaluate_url(&checked_url("https://example.com/").unwrap())
            .unwrap()
            .is_none()
    );
    assert!(compile("{url: '(', action: reject, enabled: false}").is_err());
}

#[test]
fn prefix_normalization_preserves_suffix_and_only_removes_boundary_slash() {
    let rule = compile("{url: 'HTTPS://API.EXAMPLE:443/v1', match: prefix, action: replace, replacement: 'https://new.example/'}").unwrap();
    assert_eq!(
        target(&rule, "https://api.example/v1/item?q=1"),
        "https://new.example/item?q=1"
    );
    assert_eq!(
        target(&rule, "https://api.example/v10"),
        "https://new.example/0"
    );
    let rule = compile("{url: 'https://api.example/v1/', match: prefix, action: replace, replacement: 'https://new.example'}").unwrap();
    assert_eq!(
        target(&rule, "https://api.example/v1/item"),
        "https://new.example/item"
    );
    let query = compile("{url: 'https://api.example/v1', match: prefix, action: replace, replacement: 'https://new.example/?x=/'}").unwrap();
    assert_eq!(
        target(&query, "https://api.example/v1/item?q=1"),
        "https://new.example/?x=//item?q=1"
    );
    let whole = compile("{url: 'https://api.example/v1', match: prefix, action: redirect307, replacement-mode: url, replacement: 'https://new.example/'}").unwrap();
    assert_eq!(
        target(&whole, "https://api.example/v1/item?q=1"),
        "https://new.example/"
    );
    let literal = compile("{url: 'https://api.example/', match: exact, action: replace, replacement: 'https://new.example/$1'}").unwrap();
    assert_eq!(
        target(&literal, "https://api.example/"),
        "https://new.example/$1"
    );
}

#[test]
fn regex_templates_validate_captures_and_keep_unmatched_parts() {
    let rule = compile("{url: '/(?P<old>v1)/(x)?', action: replace, replacement: '/${old}/$2$$/'}")
        .unwrap();
    assert_eq!(
        target(&rule, "https://api.example/v1/item"),
        "https://api.example/v1/$/item"
    );
    let whole = compile("{url: '^https://api\\.example/(.*)$', action: replace, replacement-mode: url, replacement: 'https://new.example/$1'}").unwrap();
    assert_eq!(
        target(&whole, "https://api.example/a?q=1"),
        "https://new.example/a?q=1"
    );
    for template in ["$name", "$2", "${missing}", "${", "$", "$12", "${}"] {
        let input = format!("{{url: '(x)', action: replace, replacement: '{template}'}}");
        assert!(
            compile(&input).is_err(),
            "accepted invalid template {template}"
        );
    }
    let bounded = compile("{url: '^(.*)$', action: replace, replacement: '$1$1'}").unwrap();
    let input = checked_url(&format!("https://example.com/{}", "x".repeat(MAX_URL / 2))).unwrap();
    assert!(bounded.evaluate_url(&input).is_err());
    assert!(
        compile("{url: '.', action: replace, replacement-mode: url, replacement: 'file:///tmp/a'}")
            .is_err()
    );
}

#[test]
fn url_input_and_rule_targets_have_distinct_fragment_boundaries() {
    assert_eq!(
        offline_url(" HTTPS://EXAMPLE.COM:443/a/../b?q=%23#ignored ")
            .unwrap()
            .as_str(),
        "https://example.com/b?q=%23"
    );
    for raw in [
        "https://example.com/#fragment",
        "https://u:p@example.com/",
        "https://example.com:0/",
        "https://example.com/\\x",
        "https://example.com/ x",
    ] {
        assert!(checked_url(raw).is_err());
    }
}

#[test]
fn shared_search_distinguishes_literals_and_local_regex_captures() {
    let literal = Search::compile(
        "a".into(),
        "$1".into(),
        SearchMode::Literal,
        Occurrences::All,
    )
    .unwrap();
    assert_eq!(literal.apply("aba", 32).unwrap(), "$1b$1");
    let regex = Search::compile(
        "(?P<letter>a)(b)?".into(),
        "${letter}-$2-$$".into(),
        SearchMode::Regex,
        Occurrences::First,
    )
    .unwrap();
    assert_eq!(regex.apply("a ab", 32).unwrap(), "a--$ ab");
    assert!(Search::compile("x".into(), "$1".into(), SearchMode::Regex, Occurrences::All).is_err());
    let zero = Search::compile("".into(), "x".into(), SearchMode::Regex, Occurrences::All).unwrap();
    assert_eq!(zero.apply("ab", 5).unwrap(), "xaxbx");
    assert!(zero.apply("ab", 4).is_err());
}

#[test]
fn body_values_are_not_limited_to_url_size_and_json_patch_is_strict() {
    let value = "x".repeat(MAX_URL + 1);
    let input = format!("{{url: '.', action: response-body-set, value: '{value}'}}");
    assert!(compile(&input).is_ok());
    let rule = compile("{url: '.', action: response-body-json-patch, patch: [{op: add, path: /flags/0, value: null}, {op: test, path: /enabled, value: false}]}").unwrap();
    let RuleAction::Body {
        operation: BodyOperation::JsonPatch(patch),
        ..
    } = rule.action
    else {
        panic!()
    };
    assert!(matches!(
        &patch[0],
        PatchOperation::Add {
            value: serde_json::Value::Null,
            ..
        }
    ));
    for input in [
        "{url: '.', action: response-body-json-patch, patch: [{op: remove, path: /x, value: false}]}",
        "{url: '.', action: response-body-json-patch, patch: [{op: add, path: /x}]}",
        "{url: '.', action: response-body-json-patch, patch: [{op: move, from: /x, path: /bad~2}]}",
        "{url: '.', action: response-body-json-patch, patch: null}",
        "{url: '.', action: response-body-json-patch, patch: [{op: add, path: /x, value: .nan}]}",
    ] {
        assert!(compile(input).is_err(), "accepted invalid patch: {input}");
    }
}
