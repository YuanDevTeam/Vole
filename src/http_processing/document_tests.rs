use super::*;

#[cfg(feature = "inbound-http")]
const RULES: &str = r#"name: API rules
targets:
  - origins: [http://api.example.test:8080, https://api.example.test:8443]
    rules:
      - match: {method: GET, path-prefix: /v1/}
        request:
          url: {replace: http://final.example.test/changed}
      - match: {path-exact: /blocked}
        request:
          url: {reject: true}
"#;

#[cfg(feature = "inbound-http")]
fn forward(policy: &Policy, input: &str, method: &str) -> String {
    let Action::Forward(url) = policy.evaluate(Url::parse(input).unwrap(), method).unwrap() else {
        panic!("expected a forward action for {method} {input}");
    };
    url.to_string()
}

#[cfg(feature = "inbound-http")]
#[test]
fn rewrite_matches_method_path_scheme_and_exact_effective_port() {
    let policy = Policy::compile(RULES).unwrap();
    assert!(policy.plain_port(8080));
    assert!(!policy.plain_port(8443));
    assert!(!policy.plain_port(80));
    for input in [
        "http://api.example.test:8080/v1/items?q=1",
        "https://api.example.test:8443/v1/items",
    ] {
        assert_eq!(
            forward(&policy, input, "GET"),
            "http://final.example.test/changed"
        );
        assert_eq!(forward(&policy, input, "POST"), input);
    }
    for input in [
        "http://api.example.test/v1/items",
        "http://api.example.test:8443/v1/items",
        "https://api.example.test:8080/v1/items",
        "https://other.example.test:8443/v1/items",
        "https://api.example.test:8443/v10/items",
    ] {
        assert_eq!(forward(&policy, input, "GET"), input);
    }
    assert!(matches!(
        policy.evaluate(
            Url::parse("http://api.example.test:8080/blocked?x=1").unwrap(),
            "GET"
        ),
        Ok(Action::Reject)
    ));
    let disabled = Document::parse(RULES)
        .unwrap()
        .compile()
        .unwrap()
        .bind_settings(
            &HttpSettings {
                mitm_enabled: true,
                rewrite_enabled: false,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert!(!disabled.plain_port(8080));
    assert!(disabled.mitm().is_none());
    assert_eq!(
        forward(&disabled, "http://api.example.test:8080/v1/item", "GET"),
        "http://api.example.test:8080/v1/item"
    );

    let defaults = Policy::compile(
        "targets: [{origins: ['http://api.example.test'], rules: [{request: {url: {reject: true}}}]}]",
    ).unwrap();
    assert!(matches!(
        defaults.evaluate(
            Url::parse("http://api.example.test:80/items").unwrap(),
            "GET"
        ),
        Ok(Action::Reject)
    ));
}

#[cfg(feature = "inbound-http")]
#[test]
fn ordered_documents_keep_authorization_scoped_and_preserve_original_bytes() {
    let second = r#"# Community file
targets:
  - origins: [https://another.example.test:8443]
    rules:
      - request:
          url: {reject: true}
  - origins: [https://api.example.test:8443]
    rules:
      - match: {path-prefix: /v1/}
        request:
          url: {replace: https://second.example.test/}
"#;
    let sources = vec![RULES.to_owned(), second.to_owned()];
    let document = Document::parse_documents(&sources).unwrap();
    assert_eq!(document.raw_documents(), sources.as_slice());
    let policy = document.static_policy().unwrap();
    assert_eq!(
        forward(&policy, "https://api.example.test:8443/v1/item", "GET"),
        "http://final.example.test/changed"
    );
    assert_eq!(
        forward(&policy, "https://api.example.test:8443/elsewhere", "GET"),
        "https://api.example.test:8443/elsewhere"
    );
    assert!(matches!(
        policy.evaluate(
            Url::parse("https://another.example.test:8443/v1/item").unwrap(),
            "GET"
        ),
        Ok(Action::Reject)
    ));
    let reversed = Document::parse_documents(&[sources[1].clone(), sources[0].clone()])
        .unwrap()
        .static_policy()
        .unwrap();
    assert_eq!(
        forward(&reversed, "https://api.example.test:8443/v1/item", "GET"),
        "https://second.example.test/"
    );
}

#[cfg(feature = "inbound-http")]
#[test]
fn local_exclusions_cover_every_https_port_but_leave_http_active() {
    let first = RULES.replace("api.example.test", "child.example.test");
    let second = first.replace(":8443", ":443").replace(":8080", ":80");
    let root = first.replace("child.example.test", "example.test");
    let candidate = Document::parse_documents(&[first, second, root])
        .unwrap()
        .compile()
        .unwrap();
    assert!(!candidate.requires_ca(&Default::default()).unwrap());

    let material = crate::http_processing::private_context::test_material();
    let allowed = HttpSettings {
        mitm_enabled: true,
        ..Default::default()
    };
    let policy = candidate.bind_settings(&allowed, Some(&material)).unwrap();
    let mitm = policy.mitm().unwrap();
    assert!(mitm.permits("child.example.test", 8443));
    assert!(mitm.permits("child.example.test", 443));
    assert!(!mitm.permits("child.example.test", 8080));
    assert!(!mitm.permits("another.example.test", 443));
    let excluded = HttpSettings {
        exclude_domains: vec!["*.example.test".into()],
        ..allowed
    };
    let policy = candidate.bind_settings(&excluded, Some(&material)).unwrap();
    let mitm = policy.mitm().unwrap();
    assert!(!mitm.permits("child.example.test", 8443));
    assert!(!mitm.permits("child.example.test", 443));
    assert!(mitm.permits("example.test", 8443));
    assert_eq!(
        forward(&policy, "http://child.example.test:8080/v1/item", "GET"),
        "http://final.example.test/changed"
    );
}

#[cfg(feature = "inbound-http")]
#[test]
fn shared_rewrite_document_rejects_host_controls_and_invalid_selectors() {
    for invalid in [
        "null".to_owned(),
        "targets: null".to_owned(),
        "targets: []".to_owned(),
        format!("{RULES}\nmitm: {{enabled: true}}\n"),
        RULES.replace("https://api.example.test:8443", "https://*.com:8443"),
        RULES.replace("https://api.example.test:8443", "https://192.0.2.2:8443"),
        RULES.replace(
            "https://api.example.test:8443",
            "https://api.example.test:8443/v1",
        ),
        RULES.replace(
            "https://api.example.test:8443",
            "HTTP://API.EXAMPLE.TEST:8080",
        ),
        RULES.replace("method: GET", "method: null"),
        RULES.replace("method: GET", "url-regex: '.'"),
        RULES.replace("path-prefix: /v1/", "path-prefix: v1/"),
        RULES.replace("request:", "response:"),
        RULES.replace("    rules:", "    intercept-only: true\n    rules:"),
    ] {
        assert!(Document::parse(&invalid).is_err(), "accepted {invalid}");
    }
}

#[cfg(feature = "inbound-http")]
const P0_SOURCE: &str = r#"name: Scoped responses
description: Verify the P0 raw plugin syntax
parameters:
  mock:
    type: boolean
    default: true
  profile:
    type: string
    default: stable
    choices: [stable, beta]
  count:
    type: integer
    default: 3
targets:
  - origins: ['http://*.cdn.example.com:8080']
    rules:
      - id: reply
        match:
          method: POST
          path-exact: /test
          request-headers: [{name: x-mode, equals: mock}]
          parameters: {mock: true}
        request:
          respond:
            status: 200
            headers: [{name: content-type, value: application/json}]
            body: {base64: AAAAAAA=}
      - id: label
        match:
          method: GET
          request-headers: [{name: x-request, exists: true}]
        response:
          when:
            status: 200
            headers: [{name: content-type, regex: '^application/json'}]
          headers: [{set: {x-profile: {param: profile}}}]
          js:
            body: none
            source: 'function rewrite(input) { if (input.parameters.count > 0) { return {type: "pass"}; } return {type: "abort"}; }'
"#;

#[cfg(feature = "inbound-http")]
#[test]
fn p0_schema_filters_on_frozen_request_and_response_facts() {
    use crate::http_processing::{
        headers,
        rules::{HeaderView, Phase, RequestMatch, UrlAction},
    };
    let document = Document::parse(P0_SOURCE).unwrap();
    let compiled = document.compile().unwrap();
    let target = Url::parse("http://a.b.cdn.example.com:8080/test?query=1").unwrap();
    let original = document.request_conditions(HeaderView::Fields(&[
        ("X-MODE".into(), "wrong".into()),
        ("x-mode".into(), "mock".into()),
        ("x-request".into(), "".into()),
    ]));
    let post = RequestMatch::from((&target, "POST")).with_conditions(original, 0);
    let Some(UrlAction::Respond(reply)) = compiled.rules[0].evaluate_url(post).unwrap() else {
        panic!("expected compiled native response");
    };
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body.as_ref(), [0; 5]);
    assert!(
        compiled.rules[0]
            .evaluate_url((&target, "POST"))
            .unwrap()
            .is_none()
    );
    for url in [
        "http://cdn.example.com:8080/test",
        "http://a.cdn.example.com/test",
    ] {
        let url = Url::parse(url).unwrap();
        let selection = RequestMatch::from((&url, "POST")).with_conditions(original, 0);
        assert!(compiled.rules[0].evaluate_url(selection).unwrap().is_none());
    }

    let mut response_headers = http::HeaderMap::new();
    response_headers.insert(
        "content-type",
        http::HeaderValue::from_bytes(b"\xff").unwrap(),
    );
    assert_eq!(
        document.response_conditions(200, HeaderView::Map(&response_headers)),
        0
    );
    response_headers.append(
        "content-type",
        http::HeaderValue::from_static("application/json;charset=utf-8"),
    );
    assert_eq!(
        document.response_conditions(103, HeaderView::Map(&response_headers)),
        0
    );
    assert_eq!(
        document.response_conditions(404, HeaderView::Map(&response_headers)),
        0
    );
    let response = document.response_conditions(200, HeaderView::Map(&response_headers));
    let selected = RequestMatch::from((&target, "GET")).with_conditions(original, response);
    let mut current = vec![("content-type".into(), "text/plain".into())];
    assert_eq!(
        headers::apply(&compiled.rules, selected, Phase::Response, &mut current),
        headers::Outcome::Changed
    );
    assert_eq!(current[1], ("x-profile".into(), "stable".into()));
    assert!(compiled.scripts[0].matches(selected));
    assert_eq!(
        compiled.scripts[0].parameters["count"],
        ParameterValue::Integer(3)
    );
}

#[cfg(feature = "inbound-http")]
#[test]
fn p0_parameter_overrides_are_typed_and_keep_raw_identity_distinct() {
    let documents = [P0_SOURCE.to_owned()];
    let defaults = Document::parse_documents(&documents).unwrap();
    let overrides = BTreeMap::from([(
        0,
        BTreeMap::from([
            ("profile".into(), ParameterValue::String("beta".into())),
            ("mock".into(), ParameterValue::Boolean(false)),
        ]),
    )]);
    let resolved = Document::parse_overrides(&documents, &overrides).unwrap();
    assert_eq!(resolved.raw_documents(), defaults.raw_documents());
    assert_ne!(resolved.identity(), defaults.identity());
    let resolved = resolved.compile().unwrap();
    assert_eq!(resolved.rules.len(), 1);
    assert_eq!(
        resolved.scripts[0].parameters["profile"],
        ParameterValue::String("beta".into())
    );
    for (key, value) in [
        ("mock", ParameterValue::String("true".into())),
        ("count", ParameterValue::Integer(1 << 53)),
        ("profile", ParameterValue::String("unlisted".into())),
        ("unknown", ParameterValue::Boolean(true)),
    ] {
        let wrong = BTreeMap::from([(0, BTreeMap::from([(key.into(), value)]))]);
        assert!(Document::parse_overrides(&documents, &wrong).is_err());
    }
}

#[cfg(feature = "inbound-http")]
#[test]
fn p0_managed_documents_verify_digest_and_do_not_borrow_permissions() {
    let yaml = P0_SOURCE.replace("http://", "https://");
    let approved = PluginInput {
        id: "approved".into(),
        digest: super::document::sha256_hex(&yaml),
        yaml,
        parameters: Default::default(),
        permissions: PluginPermissions {
            https_origins: vec!["https://*.cdn.example.com:8080".into()],
            js: true,
            ..Default::default()
        },
    };
    let mut denied = PluginInput {
        id: "denied".into(),
        permissions: Default::default(),
        ..approved.clone()
    };
    let document = Document::parse_managed(&[denied.clone(), approved.clone()]).unwrap();
    let compiled = document.compile().unwrap();
    assert_eq!(compiled.rules.len(), 2);
    assert_eq!(compiled.scripts.len(), 1);
    assert_eq!(compiled.origin(0).unwrap().source, 1);
    let targets = serde_json::to_value(document.target_summary()).unwrap();
    assert_eq!(targets[0]["origins"][0]["wildcard"], true);
    assert_eq!(targets[0]["rules"][0]["request"]["respond"], true);
    assert_eq!(targets[1]["rules"][1]["path"], "targets[0].rules[1]");
    assert!(Document::parse_managed(&[approved.clone(), approved]).is_err());
    denied
        .permissions
        .https_origins
        .push("https://one.cdn.example.com:8080".into());
    assert!(Document::parse_managed(&[denied.clone()]).is_err());
    denied.permissions.https_origins.clear();
    denied.yaml.push('\n');
    assert!(Document::parse_managed(&[denied]).is_err());
}

#[cfg(feature = "inbound-http")]
#[test]
fn p0_unapproved_fixed_upstream_does_not_shadow_a_local_decision() {
    let yaml = r#"targets:
  - origins: ['http://api.example.com']
    rules:
      - request: {url: {replace: 'https://upstream.example.com/v1'}}
      - request: {respond: {status: 204}}
"#
    .to_owned();
    let mut input = PluginInput {
        id: "instance".into(),
        digest: super::document::sha256_hex(&yaml),
        yaml,
        parameters: Default::default(),
        permissions: Default::default(),
    };
    let original = Url::parse("http://api.example.com/path").unwrap();
    let document = Document::parse_managed(&[input.clone()]).unwrap();
    assert!(matches!(
        document
            .static_policy()
            .unwrap()
            .evaluate(original.clone(), "GET"),
        Ok(Action::Respond(_))
    ));
    for (js, intercept_only) in [(true, false), (false, true)] {
        let mut overbroad = input.clone();
        overbroad.permissions.js = js;
        overbroad.permissions.intercept_only = intercept_only;
        assert!(Document::parse_managed(&[overbroad]).is_err());
    }
    input
        .permissions
        .upstream_origins
        .push("https://upstream.example.com:443".into());
    let document = Document::parse_managed(&[input]).unwrap();
    assert!(
        matches!(document.static_policy().unwrap().evaluate(original, "GET"), Ok(Action::Forward(url)) if url.as_str() == "https://upstream.example.com/v1")
    );
}

#[cfg(feature = "inbound-http")]
#[test]
fn p0_preview_tracks_rule_content_and_fixed_client_redirects() {
    let input = r#"targets:
  - origins: ['http://api.example.com']
    rules:
      - id: send-to-cdn
        match: {url-regex: '^http://api.example.com/(.*)$'}
        request: {url: {redirect: {status: 302, to: 'https://cdn.example.com/$1'}}}
"#;
    let rule_summary = |input: &str| {
        let document = Document::parse(input).unwrap();
        serde_json::to_value(document.target_summary()).unwrap()[0]["rules"][0].clone()
    };
    let initial = rule_summary(input);
    let updated = rule_summary(&input.replace("status: 302", "status: 307"));
    let comment = rule_summary(&format!("# Updated description\n{input}"));
    assert_eq!(initial["redirectTo"], "https://cdn.example.com");
    assert_eq!(initial["digest"].as_str().unwrap().len(), 64);
    assert_ne!(initial["digest"], updated["digest"]);
    assert_eq!(initial["digest"], comment["digest"]);

    let local_replace = r#"targets:
  - origins: ['http://api.example.com']
    rules:
      - request: {url: {replace: 'http://api.example.com/v1'}}
"#;
    let document = Document::parse(local_replace).unwrap();
    let summary = serde_json::to_value(document.plugin_summary()).unwrap();
    assert_eq!(summary[0]["upstreamOrigins"], serde_json::json!([]));
}

#[cfg(feature = "inbound-http")]
#[test]
fn p0_retains_initial_utf8_bom_and_crlf_in_managed_plugin_identity() {
    let yaml = format!("\u{feff}{}", P0_SOURCE.replace('\n', "\r\n"));
    let mut input = PluginInput {
        id: "instance".into(),
        digest: super::document::sha256_hex(&yaml),
        yaml: yaml.clone(),
        parameters: Default::default(),
        permissions: Default::default(),
    };
    let document = Document::parse_managed(&[input.clone()]).unwrap();
    assert_eq!(document.raw_documents(), &[yaml]);
    assert_ne!(
        document.identity(),
        Document::parse(P0_SOURCE).unwrap().identity()
    );
    input.digest = super::document::sha256_hex(P0_SOURCE);
    assert!(Document::parse_managed(&[input]).is_err());
}

#[cfg(feature = "inbound-http")]
#[test]
fn p0_rejects_malformed_terminal_actions_and_conditions_even_if_disabled() {
    for invalid in [
        P0_SOURCE.replace(
            "status: 200\n            headers",
            "status: 204\n            headers",
        ),
        P0_SOURCE.replace(
            "status: 200\n            headers",
            "status: 206\n            headers",
        ),
        P0_SOURCE.replace("AAAAAAA=", "AAAAAAA"),
        P0_SOURCE.replace(
            "content-type, value: application/json",
            "content-length, value: '4'",
        ),
        P0_SOURCE.replace("equals: mock", "equals: mock, exists: true"),
        P0_SOURCE.replace("equals: mock", "equals: null"),
        P0_SOURCE.replace(
            "when:\n            status: 200",
            "when:\n            status: 103",
        ),
        P0_SOURCE.replace("id: label", "id: reply"),
        P0_SOURCE.replace("x-profile: {param: profile}", "location: {param: profile}"),
        P0_SOURCE.replace("x-profile: {param: profile}", "x-profile: {param: count}"),
        P0_SOURCE.replace(
            "        request:\n          respond:",
            "        request:\n          url: {reject: true}\n          respond:",
        ),
        P0_SOURCE.replace("default: true", "default: 'true'"),
    ] {
        assert_ne!(invalid, P0_SOURCE, "fixture mutation did not match");
        assert!(Document::parse(&invalid).is_err(), "accepted {invalid}");
    }
    let disabled = P0_SOURCE
        .replace("default: true", "default: false")
        .replace(
            "status: 200\n            headers",
            "status: 204\n            headers",
        );
    assert!(Document::parse(&disabled).is_err());
}

#[cfg(feature = "inbound-http")]
const SCRIPT: &str = r#"targets:
  - origins: [http://example.test]
    rules:
      - name: edit-body
        match: {method: POST, path-prefix: /api/}
        request:
          js:
            body: bytes
            source: 'function rewrite(input) { return {type: "pass"}; }'
"#;

#[cfg(feature = "inbound-http")]
#[test]
fn script_only_target_has_an_independent_local_switch() {
    use crate::http_processing::{rules::Phase, script_config::BodyMode};
    let document = Document::parse(SCRIPT).unwrap();
    let candidate = document.compile().unwrap();
    let policy = document.static_policy().unwrap();
    assert!(policy.rules().is_empty());
    assert!(policy.plain_port(80));
    let [script] = policy.scripts() else {
        panic!("expected exactly one compiled script");
    };
    assert_eq!(
        (script.phase, script.body),
        (Phase::Request, BodyMode::Bytes)
    );
    assert_eq!(script.name, "edit-body");
    let original = Url::parse("http://example.test/api/item").unwrap();
    assert!(script.matches((&original, "POST")));
    assert!(!script.matches((&original, "GET")));
    let disabled = candidate
        .bind_settings(
            &HttpSettings {
                js_enabled: false,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert!(disabled.scripts().is_empty());
    assert!(!disabled.plain_port(80));

    let tls_candidate = Document::parse(&SCRIPT.replace("http://", "https://"))
        .unwrap()
        .compile()
        .unwrap();
    let mitm_only_if_js_is_enabled = HttpSettings {
        mitm_enabled: true,
        ..Default::default()
    };
    assert!(
        tls_candidate
            .requires_ca(&mitm_only_if_js_is_enabled)
            .unwrap()
    );
    assert!(
        !tls_candidate
            .requires_ca(&HttpSettings {
                js_enabled: false,
                ..mitm_only_if_js_is_enabled
            })
            .unwrap()
    );
}

#[cfg(feature = "inbound-http")]
#[test]
fn inline_scripts_are_validated_and_change_candidate_identity() {
    let candidate = Document::parse(SCRIPT).unwrap().compile().unwrap();
    for changed in [
        SCRIPT.replace("body: bytes", "body: text"),
        SCRIPT.replace("method: POST", "method: GET"),
        SCRIPT.replace("type: \"pass\"", "type: \"abort\""),
    ] {
        let changed = Document::parse(&changed).unwrap().compile().unwrap();
        assert_ne!(candidate.identity(), changed.identity());
    }
    for invalid in [
        SCRIPT.replace("body: bytes", "body: null"),
        SCRIPT.replace("body: bytes", "body: automatic"),
        SCRIPT.replace("source:", "script-path:"),
        SCRIPT.replace("function rewrite(input)", "function rewrite("),
    ] {
        assert!(Document::parse(&invalid).is_err(), "accepted {invalid}");
    }
}

#[cfg(all(
    feature = "inbound-http",
    not(any(
        target_vendor = "apple",
        all(feature = "http-js-v8", any(target_os = "linux", windows))
    ))
))]
#[test]
fn unsupported_script_backend_is_reported_during_preparation() {
    let candidate = Document::parse(SCRIPT).unwrap().compile().unwrap();
    assert_eq!(
        candidate
            .bind_settings(&Default::default(), None)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
}

#[cfg(not(feature = "inbound-http"))]
#[test]
fn http_documents_without_adapter_are_reported_as_unsupported() {
    let input = "targets: [{origins: ['http://api.example.test'], rules: [{request: {url: {reject: true}}}]}]";
    assert_eq!(
        Document::parse(input).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
}
