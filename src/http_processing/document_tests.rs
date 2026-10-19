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
