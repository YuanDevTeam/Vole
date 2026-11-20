use super::*;
#[cfg(feature = "inbound-http")]
#[test]
fn http_document_is_static_strict_and_keeps_disabled_sources_unprepared() {
    let document = Document::parse("rewrite-providers: {missing: {type: file, path: missing.yaml}}\nrewrite: {enabled: true, rules: [{rule-set: missing}]}\n").unwrap();
    assert_eq!(document.unresolved_count(), 1);
    assert!(!document.static_policy().unwrap().is_prepared());
    for bad in [
        "null",
        "rewrite: []",
        "rewrite: {rules: null}",
        "http-ports: [80,80]",
        "mitm: {ports: [443,443]}",
        "mitm: {domains: null}",
        "rewrite-providers: {x: {type: inline, payload: null}}",
        "rewrite-providers: {x: {type: file, path: x, interval: 0}}",
        "rewrite: {rules: [{rule-set: unknown, enabled: false}]}",
    ] {
        assert!(Document::parse(bad).is_err(), "accepted {bad}");
    }
}
#[cfg(feature = "inbound-http")]
#[test]
fn inline_http_resources_expand_at_reference_position_and_roundtrip_actual_content() {
    let doc = Document::parse("rewrite-providers:\n  inside:\n    type: inline\n    payload: [{url: '/old/', action: replace, replacement: '/new/'}]\nrewrite:\n  enabled: true\n  rules:\n    - {rule-set: inside}\n    - {url: '.', action: reject}\n").unwrap();
    let candidate = doc.compile(&BTreeMap::new()).unwrap();
    let policy = candidate.bind_ca(None).unwrap();
    let Action::Forward(url) = policy
        .evaluate(checked_url("https://example.com/old/a").unwrap())
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(url.as_str(), "https://example.com/new/a");
    let restored = PolicyCandidate::import_snapshot(&candidate.export_snapshot().unwrap()).unwrap();
    assert_eq!(restored.identity(), candidate.identity());
    assert!(matches!(
        restored
            .bind_ca(None)
            .unwrap()
            .evaluate(checked_url("https://example.com/other").unwrap())
            .unwrap(),
        Action::Reject
    ));
}

#[cfg(not(feature = "inbound-http"))]
#[test]
fn http_documents_without_adapter_are_rejected_before_resource_preparation() {
    for input in [
        "{}",
        "rewrite: {enabled: true, rules: [{url: '.', action: reject}]}",
        "rewrite-providers: {missing: {type: file, path: missing.yaml}}\nrewrite: {rules: [{rule-set: missing}]}",
    ] {
        let error = Document::parse(input)
            .err()
            .expect("HTTP input was accepted");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
    // Even an internal DTO that bypasses parsing cannot become a runtime policy.
    let document: Document = serde_yaml_ng::from_str("{}").unwrap();
    let candidate = Arc::new(document).compile(&BTreeMap::new()).unwrap();
    assert_eq!(
        candidate.bind_ca(None).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
    assert!(Policy::compile_optional(None).unwrap().is_none());
    assert!(Policy::compile_optional(Some("")).unwrap().is_none());
}
#[test]
fn external_http_payload_is_mandatory_and_never_carries_local_authority() {
    for invalid in [
        "{}",
        "payload: null",
        "payload: []\nmitm: {enabled: true}",
        "payload: [{rule-set: nested}]",
    ] {
        assert!(Payload::parse(invalid.as_bytes()).is_err());
    }
    assert!(Payload::parse(b"payload: []").unwrap().rules().is_empty());
    let doc = Document::parse(
        "rewrite-providers: {x: {type: file, path: rules.yaml}}\nrewrite: {rules: [{rule-set: x}, {rule-set: x, enabled: false}]}",
    );
    assert!(doc.is_err());
}

#[cfg(feature = "inbound-http")]
fn inline_script_document(enabled: bool, body: &str, source: &str) -> String {
    format!(
        "http-scripts:\n  enabled: {enabled}\n  scripts:\n    - name: example\n      phase: request\n      url: 'https://example.test/api/'\n      match: prefix\n      body: {body}\n      source: {}\n",
        serde_json::to_string(source).unwrap()
    )
}

#[cfg(feature = "inbound-http")]
const PASS_SCRIPT: &str = "function rewrite(input) { return { type: 'pass' }; }";

#[cfg(feature = "inbound-http")]
#[test]
fn inline_scripts_have_independent_switch_and_static_compilation() {
    use crate::http_processing::{rules::Phase, script_config::BodyMode};
    let document = Document::parse(&inline_script_document(true, "bytes", PASS_SCRIPT)).unwrap();
    let policy = document.static_policy().unwrap();
    assert!(policy.rules().is_empty());
    assert_eq!(policy.scripts().len(), 1);
    assert!(policy.plain_port(80));
    assert!(!policy.plain_port(81));
    assert!(!policy.is_prepared());
    let script = &policy.scripts()[0];
    assert_eq!(script.name, "example");
    assert_eq!(script.phase, Phase::Request);
    assert_eq!(script.body, BodyMode::Bytes);
    assert!(script.matches(&Url::parse("https://example.test/api/item").unwrap()));
    assert!(!script.matches(&Url::parse("https://example.test/other").unwrap()));

    let disabled = Policy::compile(&inline_script_document(false, "none", PASS_SCRIPT)).unwrap();
    assert!(disabled.scripts().is_empty());
    assert_eq!(disabled.all_scripts().len(), 1);
    assert!(!disabled.plain_port(80));
    assert!(disabled.is_prepared());
}

#[cfg(feature = "inbound-http")]
#[test]
fn inline_script_schema_is_strict_even_when_disabled() {
    for invalid in [
        "http-scripts: null",
        "http-scripts: {enabled: null}",
        "http-scripts: {scripts: null}",
        "http-scripts: {scripts: [], provider: remote}",
    ] {
        assert!(Document::parse(invalid).is_err());
    }
    let valid = inline_script_document(false, "text", PASS_SCRIPT);
    for (field, invalid) in [
        ("name", serde_yaml_ng::Value::String(String::new())),
        ("phase", serde_yaml_ng::Value::String("cron".into())),
        ("body", serde_yaml_ng::Value::Null),
        ("match", serde_yaml_ng::Value::String("automatic".into())),
        (
            "source",
            serde_yaml_ng::Value::String("function rewrite(".into()),
        ),
        ("url", serde_yaml_ng::Value::String("[".into())),
        (
            "script-path",
            serde_yaml_ng::Value::String("remote.js".into()),
        ),
    ] {
        let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&valid).unwrap();
        value["http-scripts"]["scripts"][0][field] = invalid;
        assert!(
            Document::parse(&serde_yaml_ng::to_string(&value).unwrap()).is_err(),
            "accepted invalid script field {field}"
        );
    }
    assert!(
        Payload::parse(
            format!(
                "payload: []\n{}",
                inline_script_document(true, "none", PASS_SCRIPT)
            )
            .as_bytes()
        )
        .is_err()
    );
}

#[cfg(feature = "inbound-http")]
#[test]
fn inline_script_sources_are_hashed_and_frozen_in_actual_snapshots() {
    let original = Document::parse(&inline_script_document(true, "none", PASS_SCRIPT)).unwrap();
    let candidate = original.compile(&BTreeMap::new()).unwrap();
    let exported = candidate.export_snapshot().unwrap();
    let restored = PolicyCandidate::import_snapshot(&exported).unwrap();
    assert_eq!(candidate.identity(), restored.identity());
    assert_eq!(restored.scripts.len(), 1);
    let snapshot: serde_yaml_ng::Value = serde_yaml_ng::from_str(&exported).unwrap();
    assert_eq!(
        snapshot["document"]["http-scripts"]["scripts"][0]["source"].as_str(),
        Some(PASS_SCRIPT)
    );
    for other in [
        inline_script_document(false, "none", PASS_SCRIPT),
        inline_script_document(true, "text", PASS_SCRIPT),
        inline_script_document(true, "none", &format!("{PASS_SCRIPT}\n")),
        inline_script_document(true, "none", PASS_SCRIPT)
            .replace("phase: request", "phase: response"),
        inline_script_document(true, "none", PASS_SCRIPT).replace("match: prefix", "match: exact"),
        inline_script_document(true, "none", PASS_SCRIPT).replace("name: example", "name: other"),
    ] {
        let changed = Document::parse(&other).unwrap();
        assert_ne!(original.identity(), changed.identity());
        assert_eq!(restored.identity(), candidate.identity());
    }
}

#[cfg(all(feature = "inbound-http", not(target_vendor = "apple")))]
#[tokio::test]
async fn unsupported_script_backend_fails_preparation_before_external_resources() {
    use crate::http_processing::providers::{SourceContext, Store};
    let input = format!(
        "rewrite-providers: {{missing: {{type: file, path: missing.yaml}}}}\nrewrite: {{rules: [{{rule-set: missing}}]}}\n{}",
        inline_script_document(true, "none", PASS_SCRIPT)
    );
    let document = Document::parse(&input).unwrap();
    let error = Store::new()
        .prepare(
            document,
            &SourceContext::default(),
            None,
            &tokio_util::sync::CancellationToken::new(),
            false,
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    let candidate = Document::parse(&inline_script_document(true, "none", PASS_SCRIPT))
        .unwrap()
        .compile(&BTreeMap::new())
        .unwrap();
    assert_eq!(
        candidate.bind_ca(None).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
}
