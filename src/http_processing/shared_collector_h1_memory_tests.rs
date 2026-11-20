// The real shared H1 Cursor/collector; no sockets or background owners.
use super::*;

fn shared_h1_native_noop() -> Vec<crate::http_processing::rules::Rule> {
    let raw: crate::http_processing::rules::RawRule = serde_yaml_ng::from_str(
        "{url: '.', action: response-body-replace, search: a, replacement: a}",
    )
    .unwrap();
    vec![crate::http_processing::rules::Rule::compile(raw, &mut 0).unwrap()]
}

#[tokio::test]
async fn shared_h1_known_64k_keeps_next_request_and_final_slice_owner() {
    let url = Url::parse("https://shared-h1.invalid/body").unwrap();
    let native = shared_h1_native_noop();
    let payload = vec![b'a'; 65536];
    for script_body in [false, true] {
        let budget = body::Budget::default();
        let mut fields = vec![("Content-Length".into(), "65536".into())];
        let before = fields.clone();
        let meta = OriginalRequestMeta::new("GET", &fields);
        let wire = WireBodyMeta::new(
            &fields,
            &meta,
            Phase::Response,
            Some(200),
            Some(65536),
            false,
        );
        let selected = if script_body {
            &[][..]
        } else {
            native.as_slice()
        };
        let transaction =
            Transaction::begin_shared(&budget, selected, &url, Phase::Response, &wire, script_body)
                .unwrap();
        let mut wire_bytes = payload.clone();
        wire_bytes.extend_from_slice(b"NEXT");
        let mut reader = wire_bytes.as_slice();
        let (prepared, entity) = prepare_shared(
            &mut reader,
            Body::Length(65536),
            &HashSet::new(),
            Duration::from_secs(1),
            Some(transaction),
            &mut fields,
        )
        .await
        .unwrap();
        assert_eq!(wire_bytes.len() - reader.len(), 65536);
        assert_eq!(reader, b"NEXT");
        assert_eq!(fields, before);
        let entity = entity.expect("shared completed entity");
        assert_eq!(entity.wire().as_ref(), payload);
        let last = entity.wire().slice(65535..);
        drop(entity);
        let mut sent = Vec::new();
        prepared
            .transfer(
                &mut reader,
                &mut sent,
                Duration::from_secs(1),
                &HashSet::new(),
                false,
            )
            .await
            .unwrap();
        assert_eq!(sent, payload);
        assert_eq!(reader, b"NEXT");
        assert_eq!(last.as_ref(), b"a");
        assert_eq!(
            budget.used(),
            body::BudgetedBytes::allocation_cost(65536).unwrap()
        );
        drop(last);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn shared_h1_declared_64k_partial_eof_never_commits() {
    let budget = body::Budget::default();
    let url = Url::parse("https://shared-h1.invalid/body").unwrap();
    let mut fields = vec![
        ("Content-Length".into(), "65536".into()),
        ("X-Independent".into(), "kept".into()),
    ];
    let before = fields.clone();
    let meta = OriginalRequestMeta::new("GET", &fields);
    let wire = WireBodyMeta::new(
        &fields,
        &meta,
        Phase::Response,
        Some(200),
        Some(65536),
        false,
    );
    let transaction =
        Transaction::begin_shared(&budget, &[], &url, Phase::Response, &wire, true).unwrap();
    let bytes = vec![b'a'; 65535];
    let mut reader = bytes.as_slice();
    let error = prepare_shared(
        &mut reader,
        Body::Length(65536),
        &HashSet::new(),
        Duration::from_secs(1),
        Some(transaction),
        &mut fields,
    )
    .await
    .err()
    .expect("real cursor must observe the partial EOF");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert!(reader.is_empty());
    assert_eq!(fields, before);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn shared_h1_unknown_overflow_keeps_full_sentinel_trailers_and_next() {
    let budget = body::Budget::default();
    let url = Url::parse("https://shared-h1.invalid/body").unwrap();
    let meta = OriginalRequestMeta::new("GET", &vec![]);
    let wire = WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(200), None, false);
    let transaction =
        Transaction::begin_shared(&budget, &[], &url, Phase::Response, &wire, true).unwrap();
    let payload = vec![b'a'; body::MAX_BODY + 123];
    let mut wire_bytes = format!("{:x}\r\n", payload.len()).into_bytes();
    wire_bytes.extend_from_slice(&payload);
    wire_bytes.extend_from_slice(b"\r\n0\r\nX-End: kept\r\n\r\nNEXT");
    let mut reader = wire_bytes.as_slice();
    let mut fields = vec![("X-Independent".into(), "kept".into())];
    let before = fields.clone();
    let (prepared, entity) = prepare_shared(
        &mut reader,
        Body::Chunked,
        &HashSet::new(),
        Duration::from_secs(1),
        Some(transaction),
        &mut fields,
    )
    .await
    .unwrap();
    assert!(entity.is_none());
    let prefix = prepared.prefix.as_ref().expect("original overflow prefix");
    assert_eq!(prefix.as_ref().len(), body::MAX_BODY + 1);
    assert!(!prefix.is_mapped_for_test());
    assert_eq!(fields, before);
    assert_eq!(
        budget.used(),
        body::BudgetedBytes::allocation_cost(body::MAX_BODY + 1).unwrap()
    );
    let mut sent = Vec::new();
    prepared
        .transfer(
            &mut reader,
            &mut sent,
            Duration::from_secs(1),
            &HashSet::new(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(reader, b"NEXT");
    assert!(sent.ends_with(b"0\r\nX-End: kept\r\n\r\n"));
    let mut replay = sent.as_slice();
    let mut dechunked = Vec::new();
    framing::transfer_body(
        &mut replay,
        &mut dechunked,
        Body::Chunked,
        Duration::from_secs(1),
        &HashSet::new(),
        true,
    )
    .await
    .unwrap();
    assert_eq!(dechunked, payload);
    assert!(replay.is_empty());
    assert_eq!(budget.used(), 0);
}
