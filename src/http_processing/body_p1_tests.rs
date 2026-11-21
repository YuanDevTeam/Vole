use super::*;
use crate::http_processing::config::{Document, Policy};
use std::io::Write;

const JSON: &str =
    "- json-filter: {path: /items, remove-where: {path: /kind, in: [ad, 9007199254740993, null]}}";
const PROTOBUF: &str = "- protobuf-remove: {paths: [[7], [9, 18]]}";
const PROTOBUF_INPUT: &[u8] = &[
    0x3a, 2, 0xff, 0x00, 0x4a, 8, 0x90, 1, 1, 0x08, 0x96, 0x01, 0x08, 2,
];
const PROTOBUF_OUTPUT: &[u8] = &[0x4a, 5, 0x08, 0x96, 0x01, 0x08, 2];

fn plugin(body: &str) -> String {
    format!(
        "targets:\n  - origins: [http://p1.example.test]\n    rules:\n      - response:\n          body:\n{}\n",
        body.lines()
            .map(|line| format!("            {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn run(
    body: &str,
    input: &[u8],
    fields: &mut Fields,
    shared: bool,
    pressure: bool,
) -> (Vec<u8>, bool, Option<Bypass>) {
    let policy = Policy::compile(&plugin(body)).unwrap();
    let budget = policy.body_budget();
    let url = Url::parse("http://p1.example.test/").unwrap();
    let original = OriginalRequestMeta::new("GET", &vec![]);
    let wire = WireBodyMeta::new(
        fields,
        &original,
        Phase::Response,
        Some(200),
        Some(input.len() as u64),
        false,
    );
    let reservation = pressure.then(|| {
        budget
            .reserve(budget::WORKSPACE - BudgetedBytes::allocation_cost(input.len()).unwrap())
            .unwrap()
    });
    let mut transaction = if shared {
        // Metadata-only scripts use shared collection when native work exists.
        Transaction::begin_shared(budget, policy.rules(), &url, Phase::Response, &wire, false)
    } else {
        Transaction::begin(budget, policy.rules(), &url, Phase::Response, &wire)
    }
    .unwrap();
    transaction.push(input).unwrap();
    let result = if shared {
        let result = transaction.finish_shared(false, fields);
        (result.wire().to_vec(), result.changed(), result.bypass)
    } else {
        let mut result = transaction.finish(false);
        result.finalize_headers(fields);
        (result.body.as_ref().to_vec(), result.changed, result.bypass)
    };
    drop(reservation);
    assert_eq!(budget.used(), 0);
    result
}

#[test]
fn p1_body_schema_rejects_invalid_predicates_and_field_paths() {
    for invalid in [
        "- json-filter: {path: /items~2, remove-where: {path: /kind, equals: ad}}",
        "- json-filter: {path: /items, remove-where: {path: /kind, equals: [ad]}}",
        "- json-filter: {path: /items, remove-where: {path: /kind, equals: null, in: [ad]}}",
        "- json-filter: {path: /items, remove-where: {path: /kind, in: []}}",
        "- protobuf-remove: {paths: []}",
        "- protobuf-remove: {paths: [[]]}",
        "- protobuf-remove: {paths: [[0]]}",
        "- protobuf-remove: {paths: [[536870912]]}",
        "- protobuf-remove: {paths: [[1], [1, 2]]}",
        "- protobuf-remove: {paths: [[1, 2], [1]]}",
        "- protobuf-remove: {paths: [[1], [1]]}",
        "- protobuf-remove: {paths: [[1, 2, 3, 4, 5, 6, 7, 8, 9]]}",
        "- protobuf-remove: {paths: [[1]], media-types: []}",
        "- protobuf-remove: {paths: [[1]], media-types: [application/grpc]}",
    ] {
        assert!(Document::parse(&plugin(invalid)).is_err(), "{invalid}");
    }
    assert!(
        Document::parse(&plugin(
            "- json-filter: {path: '', remove-where: {path: '', equals: null}}"
        ))
        .is_ok()
    );
}

#[test]
fn p1_json_filter_preserves_numbers_and_untouched_compressed_representations() {
    let input = br#"{ "other":0.00001, "items":[{"kind":"ad"},{"kind":9007199254740993.0},{"kind":null},{"other":1e2},{"kind":"9007199254740993"},{"kind":9007199254740992.0}] }"#;
    for shared in [false, true] {
        let mut fields = vec![("content-type".into(), "application/json".into())];
        let (bytes, changed, bypass) = run(JSON, input, &mut fields, shared, false);
        assert!(changed);
        assert_eq!(bypass, None);
        assert_eq!(
            bytes,
            br#"{"other":0.00001,"items":[{"other":1e2},{"kind":"9007199254740993"},{"kind":9007199254740992.0}]}"#
        );

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(br#"{ "items": [{"untouched":1.0}] }"#)
            .unwrap();
        let compressed = gzip.finish().unwrap();
        fields.push(("content-encoding".into(), "gzip".into()));
        let preserved = fields.clone();
        assert_eq!(
            run(JSON, &compressed, &mut fields, shared, false),
            (compressed, false, None)
        );
        assert_eq!(fields, preserved);

        let old = br#"{"items":4}"#;
        assert_eq!(
            run(JSON, old, &mut vec![], shared, false),
            (old.to_vec(), false, Some(Bypass::Transform))
        );
    }
}

#[test]
fn p1_protobuf_preserves_wire_bytes_and_rewrites_only_changed_nested_lengths() {
    for size in [2058, 16394, 65548, 131084] {
        // An untouched fixed32 field follows two occurrences of field 9.
        // The second child shrinks from 130 to 2, shortening its length prefix.
        let mut input = PROTOBUF_INPUT.to_vec();
        input.extend_from_slice(&[0x4a, 0x82, 1, 0x90, 1, 1, 0x08, 1]);
        // Extend the deleted terminal with another complete length field.
        input.extend_from_slice(&[0x92, 1, 122]);
        input.resize(input.len() + 122, 0xff);
        input.extend_from_slice(&[0x2d, 1, 2, 3, 4]);
        // Add a large unknown length-delimited field with an overlong length
        // spelling. The untouched field remains byte-for-byte identical.
        let tail_size = size - input.len() - 5;
        let tail_start = input.len();
        input.push(0x22);
        input.extend_from_slice(&[
            (tail_size as u8 & 0x7f) | 0x80,
            ((tail_size >> 7) as u8 & 0x7f) | 0x80,
            ((tail_size >> 14) as u8 & 0x7f) | 0x80,
            0,
        ]);
        input.resize(size, 0xee);
        let mut expected = PROTOBUF_OUTPUT.to_vec();
        expected.extend_from_slice(&[0x4a, 2, 0x08, 1, 0x2d, 1, 2, 3, 4]);
        expected.extend_from_slice(&input[tail_start..]);
        for shared in [false, true] {
            let original = "Application/Protobuf; charset=binary";
            let mut fields = vec![("content-type".into(), original.into())];
            assert_eq!(
                run(PROTOBUF, &input, &mut fields, shared, false),
                (expected.clone(), true, None)
            );
            assert_eq!(fields[0].1, original);
        }
    }
}

#[test]
fn p1_protobuf_media_admission_and_later_failures_are_atomic() {
    let policy = Policy::compile(&plugin(PROTOBUF)).unwrap();
    let url = Url::parse("http://p1.example.test/").unwrap();
    let original = OriginalRequestMeta::new("GET", &vec![]);
    for value in [
        "application/octet-stream",
        "application/protobuf; charset=utf-8, text/plain",
        "text/plain",
    ] {
        let fields = vec![("content-type".into(), value.into())];
        let wire = WireBodyMeta::new(&fields, &original, Phase::Response, Some(200), None, false);
        assert!(matches!(
            Transaction::begin(
                policy.body_budget(),
                policy.rules(),
                &url,
                Phase::Response,
                &wire
            ),
            Err(Bypass::NoRules)
        ));
    }
    for shared in [false, true] {
        let media = "application/octet-stream";
        let mut fields = vec![("content-type".into(), media.into())];
        let allowed = "- protobuf-remove: {paths: [[7]], media-types: [application/octet-stream]}";
        let (bytes, changed, _) = run(allowed, PROTOBUF_INPUT, &mut fields, shared, false);
        assert!(changed);
        assert_eq!(bytes, PROTOBUF_INPUT[4..]);
        let invalid_path = format!(
            "{allowed}\n- protobuf-remove: {{paths: [[9, 1, 2]], media-types: [application/octet-stream]}}"
        );
        let original_fields = fields.clone();
        for (spec, pressure, reason) in [
            (allowed, true, Bypass::Budget),
            (invalid_path.as_str(), false, Bypass::Transform),
        ] {
            assert_eq!(
                run(spec, PROTOBUF_INPUT, &mut fields, shared, pressure),
                (PROTOBUF_INPUT.to_vec(), false, Some(reason))
            );
            assert_eq!(fields, original_fields);
        }
        for malformed in [&[0x3b, 0x3c][..], &[0x3a, 2, 0xff][..], &[0][..]] {
            assert_eq!(
                run(allowed, malformed, &mut fields, shared, false),
                (malformed.to_vec(), false, Some(Bypass::Transform))
            );
        }
    }
}
