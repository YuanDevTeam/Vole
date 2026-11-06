use super::*;
use crate::http_processing::body_budget::{Budget, BudgetedBytes};
use serde_json::json;
use tokio_util::sync::CancellationToken;

fn input(kind: &str) -> serde_json::Value {
    json!({"phase":"response","original":{"url":"https://example.com/","method":"GET"},
        "request":{"url":"https://example.com/","method":"GET","headers":[]},
        "response":{"status":200,"headers":[]},"body":{"kind":kind}})
}

#[tokio::test(flavor = "current_thread")]
async fn apple_ascii_export_reuses_prepaid_output_and_preserves_fallback_boundaries() {
    let code = validate_source(
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data}};}",
    )
    .unwrap();
    let limit = super::super::body_budget::MAX_BODY;
    let controls: String = (1u8..=127).map(char::from).collect();
    for body in [
        String::new(),
        "a".into(),
        controls.repeat(32),
        "a".repeat(64 * 1024),
        "a".repeat(limit - 1),
        "a".repeat(limit),
        format!("{}\0{}", "a".repeat(4096), "b".repeat(4096)),
        format!("{}é😀", "a".repeat(4096)),
    ] {
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, limit).unwrap();
        let output_cost = budget.used();
        let bridge_cost =
            super::super::body_budget::bridge_workspace_cost(body.len(), true).unwrap();
        let prepaid = budget.reserve(bridge_cost).unwrap();
        let occupied = budget
            .reserve(super::super::body_budget::WORKSPACE - budget.used())
            .unwrap();
        assert_eq!(
            evaluate_until(
                &code,
                &input("text"),
                Some(body.as_bytes()),
                &mut output,
                Some(&prepaid),
                &CancellationToken::new(),
                std::time::Instant::now() + std::time::Duration::from_millis(100),
            )
            .await
            .unwrap(),
            json!({"type":"modify","body":{"kind":"text"}})
        );
        assert_eq!(output.as_ref(), body.as_bytes());
        assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
        drop(occupied);
        assert_eq!(budget.used(), output_cost + bridge_cost);
        drop(output);
        assert_eq!(budget.used(), bridge_cost);
        drop(prepaid);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn bridge_api_direct_input_reserves_before_materialization_and_releases_on_error() {
    let pass = validate_source("function rewrite(input){return {type:'pass'};}").unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE - 64 * 1024)
        .unwrap();
    for kind in ["text", "bytes"] {
        let error = evaluate(
            &pass,
            &input(kind),
            Some(&vec![b'a'; 64 * 1024]),
            &mut output,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(output.as_ref().is_empty());
        assert_eq!(
            budget.used(),
            super::super::body_budget::WORKSPACE - 64 * 1024
        );
    }
    drop(occupied);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn bridge_api_none_response_reserves_its_view_before_copying() {
    let code = validate_source(
        "function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:'hello'}};}",
    )
    .unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE - 14)
        .unwrap();
    let error = evaluate(
        &code,
        &input("not-requested"),
        None,
        &mut output,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert!(output.as_ref().is_empty());
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE - 14);
    drop(occupied);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn bridge_api_none_empty_text_response_needs_no_body_workspace() {
    let code = validate_source(
        "function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:''}};}",
    )
    .unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE)
        .unwrap();
    assert_eq!(
        evaluate(
            &code,
            &input("not-requested"),
            None,
            &mut output,
            &CancellationToken::new(),
        )
        .await
        .unwrap(),
        json!({"type":"respond","status":200,"body":{"kind":"text"}})
    );
    assert!(output.as_ref().is_empty());
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    drop(occupied);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn bridge_api_metadata_only_pass_and_headers_need_no_body_workspace() {
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE)
        .unwrap();
    for source in [
        "function rewrite(input){return {type:'pass'};}",
        "function rewrite(input){return {type:'modify',headers:[{op:'set',name:'x-test',values:['yes']}]};}",
    ] {
        let code = validate_source(source).unwrap();
        assert!(
            evaluate(
                &code,
                &input("not-requested"),
                None,
                &mut output,
                &CancellationToken::new(),
            )
            .await
            .is_ok()
        );
        assert!(output.as_ref().is_empty());
        assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    }
    drop(occupied);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn bridge_api_text_output_can_grow_and_come_from_bytes_or_none() {
    let text = "a".repeat(64 * 1024);
    let code = validate_source(&format!(
        "function rewrite(input){{return {{type:'respond',status:200,body:{{kind:'text',data:{}}}}};}}",
        serde_json::to_string(&text).unwrap()
    ))
    .unwrap();
    for (kind, source) in [
        ("text", Some(&b"x"[..])),
        ("bytes", Some(&b"x"[..])),
        ("not-requested", None),
    ] {
        let budget = Budget::default();
        let mut output = BudgetedBytes::empty(&budget);
        assert_eq!(
            evaluate(
                &code,
                &input(kind),
                source,
                &mut output,
                &CancellationToken::new(),
            )
            .await
            .unwrap(),
            json!({"type":"respond","status":200,"body":{"kind":"text"}})
        );
        assert_eq!(output.as_ref(), text.as_bytes());
        assert_eq!(
            budget.used(),
            BudgetedBytes::allocation_cost(text.len()).unwrap()
        );
        drop(output);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn bridge_api_prepaid_workspace_is_validated_and_reused_without_double_reserving() {
    let code = validate_source(
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data}};}",
    )
    .unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, super::super::body_budget::MAX_BODY).unwrap();
    let required =
        super::super::body_budget::BridgePlan::new(1, true, code.maximum_output_bytes(1))
            .unwrap()
            .cost()
            .unwrap();
    let prepaid = budget.reserve(required).unwrap();
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE - budget.used())
        .unwrap();
    assert_eq!(
        evaluate_until(
            &code,
            &input("text"),
            Some(b"x"),
            &mut output,
            Some(&prepaid),
            &CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        )
        .await
        .unwrap(),
        json!({"type":"modify","body":{"kind":"text"}})
    );
    assert_eq!(output.as_ref(), b"x");
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    drop(occupied);
    drop(prepaid);
    drop(output);
    assert_eq!(budget.used(), 0);

    for foreign in [false, true] {
        let budget = Budget::default();
        let mut output = BudgetedBytes::empty(&budget);
        let other = Budget::default();
        let invalid = if foreign {
            other.reserve(required).unwrap()
        } else {
            budget.reserve(required - 1).unwrap()
        };
        assert_eq!(
            evaluate_until(
                &code,
                &input("text"),
                Some(b"x"),
                &mut output,
                Some(&invalid),
                &CancellationToken::new(),
                std::time::Instant::now() + std::time::Duration::from_millis(100),
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(output.as_ref().is_empty());
        drop(invalid);
        assert_eq!(budget.used(), 0);
        assert_eq!(other.used(), 0);
    }
}

#[tokio::test]
async fn bridge_api_input_escrow_is_released_after_real_execution_failure() {
    let fail = validate_source("function rewrite(input){while(true){}}").unwrap();
    let pass = validate_source("function rewrite(input){return {type:'pass'};}").unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    assert_eq!(
        evaluate(
            &fail,
            &input("text"),
            Some(b"x"),
            &mut output,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(budget.used(), 0);
    assert_eq!(
        evaluate(
            &pass,
            &input("not-requested"),
            None,
            &mut output,
            &CancellationToken::new(),
        )
        .await
        .unwrap(),
        json!({"type":"pass"})
    );
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn apple_executes_json_rewrite_and_exports_body_separately() {
    let code = validate_source(
        r#"function rewrite(input) {
        let document = JSON.parse(input.body.data);
        document.enabled = true;
        return {type:"modify",body:{kind:"text",data:JSON.stringify(document)}};
    }"#,
    )
    .unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, 0).unwrap();
    let result = evaluate(
        &code,
        &input("text"),
        Some(br#"{"enabled":false,"n":2}"#),
        &mut output,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(result, json!({"type":"modify","body":{"kind":"text"}}));
    let body: serde_json::Value = serde_json::from_slice(output.as_ref()).unwrap();
    assert_eq!(body, json!({"enabled":true,"n":2}));
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn apple_bytes_are_isolated_and_export_the_exact_view() {
    let code = validate_source(
        r#"function rewrite(input) {
        input.body.data[1] = 9;
        return {type:"modify",body:{kind:"bytes",data:input.body.data.subarray(1,3)}};
    }"#,
    )
    .unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, 0).unwrap();
    let source = [1, 2, 3, 4];
    let result = evaluate(
        &code,
        &input("bytes"),
        Some(&source),
        &mut output,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(result, json!({"type":"modify","body":{"kind":"bytes"}}));
    assert_eq!(source, [1, 2, 3, 4]);
    assert_eq!(output.as_ref(), [9, 3]);
}

#[tokio::test]
async fn apple_finite_loop_stops_before_the_next_evaluation() {
    let infinite = validate_source("function rewrite(input) { while (true) {} }").unwrap();
    let healthy = validate_source("function rewrite(input) { return {type:'pass'}; }").unwrap();
    let budget = Budget::default();
    let start = std::time::Instant::now();
    let mut output = BudgetedBytes::new(&budget, 0).unwrap();
    assert!(
        evaluate(
            &infinite,
            &input("not-requested"),
            None,
            &mut output,
            &CancellationToken::new()
        )
        .await
        .is_err()
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(
        evaluate(
            &healthy,
            &input("not-requested"),
            None,
            &mut output,
            &CancellationToken::new()
        )
        .await
        .unwrap(),
        json!({"type":"pass"})
    );
}

#[tokio::test]
async fn apple_rejects_undefined_before_json_can_erase_it() {
    // An uninitialized local is ordinary JavaScript undefined, even though
    // explicit globals and arbitrary dynamic calls are not in the subset.
    let code = validate_source(
        "function rewrite(input) { let method; return {type:'modify',method:method}; }",
    )
    .unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, 0).unwrap();
    assert!(
        evaluate(
            &code,
            &input("not-requested"),
            None,
            &mut output,
            &CancellationToken::new()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn apple_cancelled_or_expired_text_call_never_executes_or_keeps_output() {
    let code = validate_source("function rewrite(input) { return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','c')}}; }").unwrap();
    let body = vec![b'a'; 65536];
    let token = CancellationToken::new();
    token.cancel();
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, 0).unwrap();
    let error = evaluate(&code, &input("text"), Some(&body), &mut output, &token)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(output.as_ref().is_empty());
    let error = evaluate_until(
        &code,
        &input("text"),
        Some(&body),
        &mut output,
        None,
        &CancellationToken::new(),
        std::time::Instant::now() - std::time::Duration::from_millis(1),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(output.as_ref().is_empty());
}

async fn evaluate_text(
    source: &str,
    body: &[u8],
    metadata: serde_json::Value,
) -> io::Result<(serde_json::Value, Vec<u8>)> {
    let code = validate_source(source)?;
    evaluate_compiled_text(&code, body, metadata).await
}

async fn evaluate_compiled_text(
    code: &CompiledSource,
    body: &[u8],
    metadata: serde_json::Value,
) -> io::Result<(serde_json::Value, Vec<u8>)> {
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, 0).unwrap();
    let result = evaluate(
        code,
        &metadata,
        Some(body),
        &mut output,
        &CancellationToken::new(),
    )
    .await;
    let body = output.as_ref().to_vec();
    drop(output);
    assert_eq!(budget.used(), 0);
    result.map(|metadata| (metadata, body))
}

#[tokio::test]
async fn apple_text_input_preserves_utf16_length_and_embedded_data() {
    let code = validate_source(
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:JSON.stringify({text:input.body.data,units:input.body.data.length})}};}",
    )
    .unwrap();
    let ascii = (1u8..=127).map(char::from).collect::<String>();
    for body in [
        String::new(),
        "a".into(),
        ascii.repeat(32),
        "\0a\0".into(),
        format!("{}\0{}", "a".repeat(4096), "b".repeat(4096)),
        "中éa\u{301}".into(),
        "😀a中😀".into(),
        "a".repeat(64 * 1024),
    ] {
        let (metadata, output) = evaluate_compiled_text(&code, body.as_bytes(), input("text"))
            .await
            .unwrap();
        assert_eq!(metadata, json!({"type":"modify","body":{"kind":"text"}}));
        let actual: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            actual,
            json!({"text": body, "units": body.encode_utf16().count()}),
        );
    }
}

async fn replace_text(
    body: &str,
    search: &str,
    replacement: &str,
    all: bool,
) -> io::Result<Vec<u8>> {
    let source = format!(
        "function rewrite(input){{return {{type:'modify',body:{{kind:'text',data:input.body.data.{}({},{})}}}};}}",
        if all { "replaceAll" } else { "replace" },
        serde_json::to_string(search).unwrap(),
        serde_json::to_string(replacement).unwrap(),
    );
    let (metadata, body) = evaluate_text(&source, body.as_bytes(), input("text")).await?;
    assert_eq!(metadata, json!({"type":"modify","body":{"kind":"text"}}));
    Ok(body)
}

#[tokio::test]
async fn apple_ascii_replacement_preserves_controls_unicode_and_literal_searches() {
    for (body, search, replacement, first, all) in [
        ("aaa", "a", "c", "caa", "ccc"),
        ("abc", "x", "y", "abc", "abc"),
        ("", "a", "c", "", ""),
        ("aaa", "a", "a", "aaa", "aaa"),
        ("$a$$", "$", "c", "ca$$", "cacc"),
        ("\0a\0", "\0", "\x7f", "\x7fa\0", "\x7fa\x7f"),
        ("a\na", "a", "\0", "\0\na", "\0\n\0"),
        ("\t\r\n\t", "\t", "\r", "\r\r\n\t", "\r\r\n\r"),
        ("a\\a", "\\", "'", "a'a", "a'a"),
        ("a\"a\"", "\"", "\\", "a\\a\"", "a\\a\\"),
        (
            "😀a中aéa\u{301}",
            "a",
            "\x7f",
            "😀\x7f中aéa\u{301}",
            "😀\x7f中\x7fé\x7f\u{301}",
        ),
    ] {
        for (replace_all, expected) in [(false, first), (true, all)] {
            assert_eq!(
                replace_text(body, search, replacement, replace_all)
                    .await
                    .unwrap(),
                expected.as_bytes(),
                "body={body:?}, search={search:?}, replacement={replacement:?}, all={replace_all}",
            );
        }
    }
}

#[tokio::test]
async fn apple_ascii_replace_all_rewrites_dense_64k_js_and_mixed_bodies() {
    let mut original = vec![b'a'; 65536];
    original[..14].copy_from_slice(b"flow:00000000\n");
    let expected: Vec<_> = original
        .iter()
        .map(|b| if *b == b'a' { b'c' } else { *b })
        .collect();
    for mixed in [false, true] {
        let body: Vec<_> = original
            .iter()
            .map(|b| if mixed && *b == b'a' { b'b' } else { *b })
            .collect();
        let guard = if mixed {
            "let found=false; for(let i=0;i<input.response.headers.length;i++){if(input.response.headers[i].name==='x-benchmark-native' && input.response.headers[i].value==='1'){found=true;}} if(!found){return {type:'abort'};}"
        } else {
            ""
        };
        let source = format!(
            "function rewrite(input){{{guard} const data=input.body.data.replaceAll('{}','c');return {{type:'modify',headers:[{{op:'set',name:'X-Benchmark-JS',values:['1']}}],body:{{kind:'text',data:data}}}};}}",
            if mixed { 'b' } else { 'a' },
        );
        let mut metadata = input("text");
        if mixed {
            metadata["response"]["headers"] = json!([{"name":"x-benchmark-native","value":"1"}]);
        }
        let (metadata, actual) = evaluate_text(&source, &body, metadata).await.unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            metadata,
            json!({"type":"modify","headers":[{"op":"set","name":"X-Benchmark-JS","values":["1"]}],"body":{"kind":"text"}}),
        );
    }
}

#[tokio::test]
async fn apple_ascii_replacement_keeps_templates_and_non_ascii_byte_lengths() {
    for (body, search, replacement, first, all) in [
        ("aba", "a", "$", "$ba", "$b$"),
        ("aba", "a", "$$", "$ba", "$b$"),
        ("aba", "a", "$&", "aba", "aba"),
        ("aba", "a", "$`", "ba", "bab"),
        ("aba", "a", "$'", "baba", "bab"),
        ("aba", "a", "$1", "$1ba", "$1b$1"),
        ("bc", "", "a", "abc", "abaca"),
        ("aba", "a", "", "ba", "b"),
        ("abab", "ab", "c", "cab", "cc"),
        ("aaa", "a", "\u{80}", "\u{80}aa", "\u{80}\u{80}\u{80}"),
        ("éaé", "é", "a", "aaé", "aaa"),
        ("😀a😀", "😀", "a", "aa😀", "aaa"),
    ] {
        for (replace_all, expected) in [(false, first), (true, all)] {
            assert_eq!(
                replace_text(body, search, replacement, replace_all)
                    .await
                    .unwrap(),
                expected.as_bytes(),
                "body={body:?}, search={search:?}, replacement={replacement:?}, all={replace_all}",
            );
        }
    }
}

#[tokio::test]
async fn apple_ascii_replacement_keeps_utf8_body_limits_and_rejects_invalid_text() {
    const LIMIT: usize = 256 * 1024;
    let body = "a".repeat(LIMIT);
    assert_eq!(
        replace_text(&body, "a", "c", true).await.unwrap(),
        vec![b'c'; LIMIT],
    );
    let unicode = format!("{}aaaa", "😀".repeat(LIMIT / 4 - 1));
    let expected = format!("{}cccc", "😀".repeat(LIMIT / 4 - 1));
    assert_eq!(unicode.len(), LIMIT);
    assert_eq!(
        replace_text(&unicode, "a", "c", true).await.unwrap(),
        expected.as_bytes(),
    );
    for body in ["a".repeat(LIMIT + 1), "é".repeat(LIMIT / 2 + 1)] {
        let error = replace_text(&body, "a", "c", true).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    // One UTF-16 code unit need not be one UTF-8 byte; even four replacements
    // must retain the general expansion preflight at the UTF-8 byte boundary.
    for replacement in ["\u{80}", "😀"] {
        let error = replace_text(&unicode, "a", replacement, true)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    let source = "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','c')}};}";
    let error = evaluate_text(source, &[0xed, 0xa0, 0x80], input("text"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    // Existing value validation rejects a sliced surrogate before replacement.
    for slice in ["slice(0,1)", "slice(1,2)"] {
        let source = format!(
            "function rewrite(input){{const bad=input.body.data.{slice};return {{type:'modify',body:{{kind:'text',data:bad.replaceAll('a','c')}}}};}}"
        );
        let error = evaluate_text(&source, "😀".as_bytes(), input("text"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn apple_ascii_replacement_still_charges_no_match_allocation_work() {
    let body = vec![b'a'; 65536];
    for (calls, accepted) in [(3, true), (4, false)] {
        // The concat prefix consumes about 1.5MiB of allocation-work. Each
        // no-match replacement still costs 65536*2+32: three fit, four exceed
        // the unchanged 2MiB work limit without needing a long execution loop.
        let source = format!(
            "function rewrite(input){{let reserve=[0];for(let i=0;i<15;i++){{reserve=reserve.concat(reserve);}}let data=input.body.data;for(let i=0;i<{calls};i++){{data=data.replaceAll('x','c');}}return {{type:'pass'}};}}"
        );
        let result = evaluate_text(&source, &body, input("text")).await;
        if accepted {
            let (metadata, body) = result.unwrap();
            assert_eq!(metadata, json!({"type":"pass"}));
            assert!(body.is_empty());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }
}

async fn trusted_text_size(body: &str, quoted: bool, expression: &str) -> io::Result<usize> {
    // The user-language frontend deliberately cannot name trusted helpers.
    // Exercise this prelude seam directly; the replacement tests above still
    // cover the real frontend, bridge, budget and body-export call path.
    let code = CompiledSource {
        code: format!(
            "function rewrite(input){{return {{type:'modify',body:{{kind:'text',data:String(__voleTextSize({expression},{quoted}))}}}};}}"
        ).into(),
        ..Default::default()
    };
    let (_, output) = evaluate_compiled_text(&code, body.as_bytes(), input("text")).await?;
    Ok(std::str::from_utf8(&output).unwrap().parse().unwrap())
}

#[tokio::test]
async fn apple_large_ascii_text_size_preserves_raw_unicode_and_quoted_lengths() {
    for length in [4095, 4096, 4097, 256 * 1024] {
        let body = "a".repeat(length);
        assert_eq!(
            trusted_text_size(&body, false, "input.body.data")
                .await
                .unwrap(),
            body.len(),
        );
    }
    // Every ASCII code unit is one raw byte, including NUL, DEL and controls.
    let ascii: String = (0u8..=127).map(char::from).collect::<String>().repeat(32);
    assert_eq!(ascii.len(), 4096);
    for body in [
        ascii,
        format!("{}é", "a".repeat(4095)),
        format!("{}😀", "a".repeat(4095)),
    ] {
        assert_eq!(
            trusted_text_size(&body, false, "input.body.data")
                .await
                .unwrap(),
            body.len(),
        );
        assert_eq!(
            trusted_text_size(&body, true, "input.body.data")
                .await
                .unwrap(),
            serde_json::to_vec(&body).unwrap().len(),
        );
    }
}

#[tokio::test]
async fn apple_large_ascii_text_size_keeps_limits_and_surrogate_validation() {
    const LIMIT: usize = 256 * 1024;
    assert_eq!(
        trusted_text_size(&"a".repeat(LIMIT - 2), true, "input.body.data")
            .await
            .unwrap(),
        LIMIT,
    );
    for (body, quoted) in [
        ("a".repeat(LIMIT + 1), false),
        ("a".repeat(LIMIT - 1), true),
    ] {
        let error = trusted_text_size(&body, quoted, "input.body.data")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    let body = format!("{}😀", "a".repeat(4096));
    for expression in [
        "input.body.data.slice(0,-1)",
        "input.body.data.slice(0,4096)+input.body.data.slice(-1)",
    ] {
        for quoted in [false, true] {
            // Native slicing here leaves a high or low surrogate after the
            // ASCII prefix, bypassing the frontend's earlier value checks.
            let error = trusted_text_size(&body, quoted, expression)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_ascii_preserves_public_text_and_utf16_header() {
    let code = validate_source(
        r#"function rewrite(input) {
          return {type:"modify",
            headers:[{op:"set",name:"x-utf16-length",values:[String(input.body.data.length)]}],
            body:{kind:"text",data:input.body.data}};
        }"#,
    )
    .unwrap();
    let controls: String = (0u8..=127).map(char::from).collect::<String>().repeat(32);
    let bodies = vec![
        String::new(),
        "a".into(),
        "a".repeat(4095),
        "a".repeat(4096),
        "a".repeat(4097),
        "a".repeat(64 * 1024),
        "a".repeat(super::super::body_budget::MAX_BODY),
        controls,
        format!("é{}", "a".repeat(4096)),
        format!("{}é{}", "a".repeat(2048), "a".repeat(2048)),
        format!("{}é", "a".repeat(4096)),
        format!("{}😀\0\u{7f}", "a".repeat(4096)),
    ];
    for body in bodies {
        let (metadata, actual) = evaluate_compiled_text(&code, body.as_bytes(), input("text"))
            .await
            .unwrap();
        assert_eq!(actual.as_slice(), body.as_bytes());
        assert_eq!(
            metadata,
            json!({"type":"modify", "headers":[{"op":"set", "name":"x-utf16-length",
                "values":[body.encode_utf16().count().to_string()]}], "body":{"kind":"text"}}),
        );
    }
}

async fn metadata_only_with_ticks(
    code: &CompiledSource,
    budget: &Budget,
) -> (serde_json::Value, usize) {
    let mut output = BudgetedBytes::empty(budget);
    let result = evaluate(
        code,
        &input("not-requested"),
        None,
        &mut output,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    let ticks = apple::last_ticks_for_test().expect("completed current-thread evaluation");
    assert!(output.as_ref().is_empty());
    (result, ticks)
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_ascii_large_input_reuses_prepaid_view_with_full_workspace() {
    // Internal adapter seam only: public source cannot name this helper. The
    // explicit result header distinguishes an admitted native scan (`true`)
    // from `undefined` followed by an otherwise successful regex fallback.
    let code = CompiledSource {
        code: "function rewrite(input){return {type:'modify',headers:[{op:'set',name:'x-native-prepaid',values:[String(__voleIsASCII(input.body.data,input.body.data.length))]}],body:{kind:'text',data:input.body.data}};}".into(),
        ..Default::default()
    };
    let body = vec![b'a'; 4097];
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, super::super::body_budget::MAX_BODY).unwrap();
    let output_cost = BudgetedBytes::allocation_cost(super::super::body_budget::MAX_BODY).unwrap();
    let bridge_cost = super::super::body_budget::bridge_workspace_cost(body.len(), true).unwrap();
    let prepaid = budget.reserve(bridge_cost).unwrap();
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE - budget.used())
        .unwrap();
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    assert_eq!(
        evaluate_until(
            &code,
            &input("text"),
            Some(&body),
            &mut output,
            Some(&prepaid),
            &CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        )
        .await
        .unwrap(),
        json!({"type":"modify","headers":[{"op":"set","name":"x-native-prepaid","values":["true"]}],"body":{"kind":"text"}}),
    );
    assert_eq!(output.as_ref(), body.as_slice());
    // The helper's API view has already ended; neither helper nor export may
    // need an additional reservation while all remaining workspace is held.
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    drop(occupied);
    assert_eq!(budget.used(), output_cost + bridge_cost);
    drop(output);
    assert_eq!(budget.used(), bridge_cost);
    drop(prepaid);
    assert_eq!(budget.used(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_ascii_budget_fallback_preserves_metadata_and_fuel() {
    // Legal public source: no private helper reference. slice invokes the
    // existing trusted string validation on a 4096-unit ASCII receiver.
    let literal = serde_json::to_string(&"a".repeat(4096)).unwrap();
    let source = format!(
        "function rewrite(input){{const text={literal};return {{type:'modify',headers:[{{op:'set',name:'x-ascii',values:[text.slice(0,1)]}}]}};}}",
    );
    let code = validate_source(&source).unwrap();
    let budget = Budget::default();
    let (native, native_ticks) = metadata_only_with_ticks(&code, &budget).await;
    assert_eq!(budget.used(), 0);
    assert!(native_ticks > 0);
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE)
        .unwrap();
    let (fallback, fallback_ticks) = metadata_only_with_ticks(&code, &budget).await;
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    assert_eq!(native, fallback);
    assert_eq!(native_ticks, fallback_ticks);
    assert_eq!(
        native,
        json!({"type":"modify","headers":[{"op":"set","name":"x-ascii","values":["a"]}]})
    );
    drop(occupied);
    assert_eq!(budget.used(), 0);
}

async fn trusted_ascii_result(expression: &str, budget: &Budget) -> serde_json::Value {
    // Only this internal test bypasses the public AST frontend. Incorrect
    // lengths are defensive vectors, not an external pre-copy memory API.
    let code = CompiledSource {
        code: format!(
            "function rewrite(input){{return {{type:'modify',headers:[{{op:'set',name:'x-result',values:[String({expression})]}}]}};}}",
        ).into(),
        ..Default::default()
    };
    let before = budget.used();
    let (metadata, _) = metadata_only_with_ticks(&code, budget).await;
    assert_eq!(budget.used(), before);
    metadata
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_ascii_private_abi_returns_exact_results_and_releases_guards() {
    let budget = Budget::default();
    for (expression, expected) in [
        ("__voleIsASCII()", "undefined"),
        ("__voleIsASCII('a')", "undefined"),
        ("__voleIsASCII('a',1,2)", "undefined"),
        ("__voleIsASCII(1,1)", "undefined"),
        ("__voleIsASCII({},1)", "undefined"),
        ("__voleIsASCII('a','1')", "undefined"),
        ("__voleIsASCII('a',NaN)", "undefined"),
        ("__voleIsASCII('a',Infinity)", "undefined"),
        ("__voleIsASCII('a',-1)", "undefined"),
        ("__voleIsASCII('a',0.5)", "undefined"),
        ("__voleIsASCII('a',262145)", "undefined"),
        ("__voleIsASCII('a',0)", "undefined"),
        ("__voleIsASCII('a',2)", "undefined"),
        ("__voleIsASCII('',0)", "true"),
        ("__voleIsASCII('a',1)", "true"),
        (r#"__voleIsASCII("a\u0000\u007f",3)"#, "true"),
        (r#"__voleIsASCII("a\\u0000\u007f",3)"#, "undefined"),
        (r#"__voleIsASCII("a\\u0000\u007f",8)"#, "true"),
        (r#"__voleIsASCII("é",1)"#, "false"),
        (r#"__voleIsASCII("é",2)"#, "undefined"),
        (r#"__voleIsASCII("😀",2)"#, "false"),
        (r#"__voleIsASCII("\ud800",1)"#, "false"),
    ] {
        let metadata = trusted_ascii_result(expression, &budget).await;
        assert_eq!(
            metadata,
            json!({"type":"modify","headers":[{"op":"set","name":"x-result","values":[expected]}]}),
            "{expression}"
        );
        assert_eq!(budget.used(), 0);
    }
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE)
        .unwrap();
    assert_eq!(
        trusted_ascii_result("__voleIsASCII('a',1)", &budget).await,
        json!({"type":"modify","headers":[{"op":"set","name":"x-result","values":["undefined"]}]}),
    );
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    drop(occupied);
    assert_eq!(budget.used(), 0);
}

#[test]
fn native_ascii_helper_remains_private_to_trusted_prelude() {
    for source in [
        "function rewrite(input){return __voleIsASCII('a',1);}",
        "function rewrite(input){let __voleIsASCII=1;return {type:'pass'};}",
        "function rewrite(input){return input.__voleIsASCII;}",
        "function rewrite(input){return input['__voleIsASCII'];}",
        "function rewrite(input){return {__voleIsASCII:1};}",
    ] {
        assert!(validate_source(source).is_err(), "accepted {source}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_ascii_dynamic_reserved_properties_fail_at_runtime() {
    for source in [
        "function rewrite(input){const key='__vole'+'IsASCII';const value=input[key];return {type:'pass'};}",
        "function rewrite(input){const key='__vole'+'IsASCII';input[key]='x';return {type:'pass'};}",
    ] {
        // Dynamic key syntax is accepted statically; __voleKey rejects the
        // resulting reserved value before it can read or write a property.
        let code = validate_source(source).unwrap();
        let budget = Budget::default();
        let mut output = BudgetedBytes::empty(&budget);
        let error = evaluate(
            &code,
            &input("not-requested"),
            None,
            &mut output,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(output.as_ref().is_empty());
        assert_eq!(budget.used(), 0);
    }
}

struct ScopedThreadExit(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for ScopedThreadExit {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}
thread_local! {
    static SCOPED_THREAD_EXIT: std::cell::RefCell<Option<ScopedThreadExit>> = const { std::cell::RefCell::new(None) };
}
fn observe_scoped_exit(flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    SCOPED_THREAD_EXIT.with(|slot| {
        *slot.borrow_mut() = Some(ScopedThreadExit(flag));
    });
}

#[derive(Debug)]
struct ScopedDispatchProbe;
impl tracing::Subscriber for ScopedDispatchProbe {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_jsc_worker_joins_tls_and_preserves_dispatch_and_panic() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let exited = Arc::new(AtomicBool::new(false));
    let observed = exited.clone();
    let caller = std::thread::current().id();
    let mut borrowed = 0;
    let dispatch = tracing::Dispatch::new(ScopedDispatchProbe);
    let worker = tracing::dispatcher::with_default(&dispatch, || {
        tokio::task::block_in_place(|| {
            run_on_scoped_thread(|| {
                observe_scoped_exit(observed);
                assert!(tracing::dispatcher::get_default(|d| d
                    .downcast_ref::<ScopedDispatchProbe>()
                    .is_some()));
                borrowed = 7;
                Ok(std::thread::current().id())
            })
        })
    })
    .unwrap();
    assert_ne!(caller, worker);
    assert_eq!(borrowed, 7);
    // A TLS destructor runs on actual thread exit, after the job returns.
    assert!(exited.load(Ordering::Acquire));

    let exited = Arc::new(AtomicBool::new(false));
    let observed = exited.clone();
    let marker = Arc::new(());
    let expected = marker.clone();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::task::block_in_place(|| {
            run_on_scoped_thread::<()>(move || {
                observe_scoped_exit(observed);
                std::panic::panic_any(marker);
            })
        })
    }))
    .expect_err("worker panic must reach its caller");
    let marker = panic
        .downcast::<Arc<()>>()
        .unwrap_or_else(|_| panic!("panic payload changed"));
    assert!(Arc::ptr_eq(marker.as_ref(), &expected));
    assert!(exited.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_jsc_cancellation_joins_and_next_public_evaluation_is_healthy() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};
    let code = validate_source("function rewrite(input){while(true){}}").unwrap();
    let body = vec![b'a'; 4096];
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    let cancellation = CancellationToken::new();
    let controller_token = cancellation.clone();
    let worker_token = cancellation.clone();
    let exited = Arc::new(AtomicBool::new(false));
    let observed = exited.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let body_ref = body.as_slice();
    let (result, handshake) = tokio::task::block_in_place(|| {
        std::thread::scope(|scope| {
            let controller = scope.spawn(move || {
                let entered = ready_rx.recv_timeout(Duration::from_secs(5)).is_ok();
                controller_token.cancel();
                let released = resume_tx.send(()).is_ok();
                (entered, released)
            });
            let output_ref = &mut output;
            let result = run_on_scoped_thread(move || {
                observe_scoped_exit(observed);
                let fail_safe = worker_token.clone();
                // No assertions/panics in the extern-C callback. The bounded
                // timeout is only a failed-test watchdog, not an exit heuristic.
                apple::on_first_tick_for_test(move || {
                    let _ = ready_tx.send(());
                    if resume_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                        fail_safe.cancel();
                    }
                });
                apple::evaluate(
                    &code,
                    &input("text"),
                    Some(body_ref),
                    output_ref,
                    None,
                    &worker_token,
                    Instant::now() + Duration::from_millis(100),
                )
            });
            (
                result,
                controller.join().expect("cancellation controller panicked"),
            )
        })
    });
    assert_eq!(handshake, (true, true));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert!(exited.load(Ordering::Acquire));
    assert!(output.as_ref().is_empty());
    assert_eq!(budget.used(), 0);
    let healthy = validate_source(
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data}};}",
    )
    .unwrap();
    let result = evaluate(
        &healthy,
        &input("text"),
        Some(&body),
        &mut output,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(result, json!({"type":"modify","body":{"kind":"text"}}));
    assert_eq!(output.as_ref(), body);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn apple_native_literal_replace_preserves_generic_ascii_and_fallback_semantics() {
    // Dense controls, NUL, DEL and regexp metacharacters are ordinary ASCII
    // code units; no benchmark-specific character or payload is recognized.
    for (search, replacement) in [
        ('q', 'z'),
        ('\0', '\x7f'),
        ('\x7f', '\0'),
        ('$', '!'),
        ('\\', '"'),
        ('.', '\n'),
        ('\t', '\r'),
        ('q', 'q'),
    ] {
        let body: String = [search, search, 'x', search]
            .into_iter()
            .cycle()
            .take(4096)
            .collect();
        let expected: String = body
            .chars()
            .map(|c| if c == search { replacement } else { c })
            .collect();
        assert_eq!(
            replace_text(&body, &search.to_string(), &replacement.to_string(), true)
                .await
                .unwrap(),
            expected.as_bytes()
        );
    }
    // Each vector deliberately misses a native eligibility rule. Original
    // replaceAll still owns Unicode, templates, sparse/short and multi-unit.
    for (body, search, replacement, expected) in [
        ("q".repeat(4095), "q", "z", "z".repeat(4095)),
        (
            format!("{}q", "x".repeat(4095)),
            "q",
            "z",
            format!("{}z", "x".repeat(4095)),
        ),
        ("éq".repeat(2048), "q", "z", "éz".repeat(2048)),
        ("😀q".repeat(2048), "q", "z", "😀z".repeat(2048)),
        ("q".repeat(4096), "q", "$", "$".repeat(4096)),
        ("q".repeat(4096), "q", "$$", "$".repeat(4096)),
        ("q".repeat(4096), "q", "$&", "q".repeat(4096)),
        ("q".repeat(4096), "q", "$1", "$1".repeat(4096)),
        ("q".repeat(4096), "q", "", String::new()),
        ("qr".repeat(2048), "qr", "z", "z".repeat(2048)),
    ] {
        assert_eq!(
            replace_text(&body, search, replacement, true)
                .await
                .unwrap(),
            expected.as_bytes()
        );
    }
}

#[test]
fn native_literal_replace_helper_remains_private() {
    for source in [
        "function rewrite(input){return __voleReplaceASCIIAll('q',1,113,122);}",
        "function rewrite(input){let __voleReplaceASCIIAll=1;return {type:'pass'};}",
        "function rewrite(input){return input.__voleReplaceASCIIAll;}",
        "function rewrite(input){return input['__voleReplaceASCIIAll'];}",
        "function rewrite(input){return {__voleReplaceASCIIAll:1};}",
    ] {
        assert!(validate_source(source).is_err(), "accepted {source}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_literal_replace_private_abi_does_not_coerce_or_accept_invalid_numbers() {
    let literal = serde_json::to_string(&"q".repeat(4096)).unwrap();
    let budget = Budget::default();
    for expression in [
        "__voleReplaceASCIIAll()".to_owned(),
        format!("__voleReplaceASCIIAll({literal},4096,113)"),
        format!("__voleReplaceASCIIAll({literal},4096,113,122,0)"),
        "__voleReplaceASCIIAll({toString:function(){throw new Error('coerced')}},4096,113,122)"
            .to_owned(),
        format!("__voleReplaceASCIIAll({literal},'4096',113,122)"),
        format!("__voleReplaceASCIIAll({literal},NaN,113,122)"),
        format!("__voleReplaceASCIIAll({literal},Infinity,113,122)"),
        format!("__voleReplaceASCIIAll({literal},-1,113,122)"),
        format!("__voleReplaceASCIIAll({literal},4096.5,113,122)"),
        format!("__voleReplaceASCIIAll({literal},262145,113,122)"),
        format!("__voleReplaceASCIIAll({literal},4095,113,122)"),
        format!("__voleReplaceASCIIAll({literal},4097,113,122)"),
        format!("__voleReplaceASCIIAll({literal},4096,128,122)"),
        format!("__voleReplaceASCIIAll({literal},4096,113,128)"),
        format!("__voleReplaceASCIIAll({literal},4096,113,36)"),
        format!(
            "__voleReplaceASCIIAll({literal},4096,{{valueOf:function(){{throw new Error('coerced')}}}},122)"
        ),
        format!(
            "__voleReplaceASCIIAll({literal},4096,113,{{valueOf:function(){{throw new Error('coerced')}}}})"
        ),
    ] {
        // Bypass the frontend only to exercise the private defensive ABI.
        let code = CompiledSource { code: format!("function rewrite(input){{return {{type:'modify',headers:[{{op:'set',name:'x-native',values:[typeof ({expression})]}}]}};}}").into(), ..Default::default() };
        let (actual, _) = metadata_only_with_ticks(&code, &budget).await;
        assert_eq!(
            actual,
            json!({"type":"modify","headers":[{"op":"set","name":"x-native","values":["undefined"]}]}),
            "expression={expression}"
        );
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_literal_replace_retains_each_output_until_real_context_release() {
    use crate::http_processing::body_budget::{MAX_BODY, WORKSPACE, bridge_workspace_cost};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    const LENGTH: usize = 4096;
    let code = CompiledSource { code: "function rewrite(input){let flags='';for(let i=0;i<3;i++){const value=__voleReplaceASCIIAll(input.body.data,input.body.data.length,113,122);flags+=value===undefined?'0':'1';}return {type:'modify',headers:[{op:'set',name:'x-native',values:[flags]}]};}".into(), ..Default::default() };
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, MAX_BODY).unwrap();
    let prepaid = budget
        .reserve(bridge_workspace_cost(LENGTH, true).unwrap())
        .unwrap();
    let occupied = budget
        .reserve(WORKSPACE - budget.used() - 4 * LENGTH)
        .unwrap();
    let before = budget.used();
    let observed = Arc::new(AtomicBool::new(false));
    let after_release = observed.clone();
    let at_release = budget.clone();
    apple::on_context_release_for_test(move || {
        // Called immediately after JSGlobalContextRelease returns, while
        // ExecutionGuard still owns both successful 2O reservations.
        after_release.store(at_release.used() == WORKSPACE, Ordering::Release);
    });
    let actual = evaluate_until(
        &code,
        &input("text"),
        Some(&vec![b'q'; LENGTH]),
        &mut output,
        Some(&prepaid),
        &CancellationToken::new(),
        std::time::Instant::now() + std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!(
        actual,
        json!({"type":"modify","headers":[{"op":"set","name":"x-native","values":["110"]}]})
    );
    assert!(observed.load(Ordering::Acquire));
    assert_eq!(budget.used(), before);
    drop(occupied);
    drop(prepaid);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_literal_replace_budget_fallback_keeps_public_result_and_exact_fuel() {
    use crate::http_processing::body_budget::{MAX_BODY, WORKSPACE, bridge_workspace_cost};
    let code = validate_source("function rewrite(input){const text=input.body.data.replaceAll('q','z');return {type:'modify',headers:[{op:'set',name:'x-result',values:[text.slice(0,1)]}]};}").unwrap();
    let body = vec![b'q'; 4096];
    let mut observations = Vec::new();
    for fill in [false, true] {
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, MAX_BODY).unwrap();
        let prepaid = budget
            .reserve(bridge_workspace_cost(body.len(), true).unwrap())
            .unwrap();
        let occupied = fill.then(|| budget.reserve(WORKSPACE - budget.used()).unwrap());
        let before = budget.used();
        let actual = evaluate_until(
            &code,
            &input("text"),
            Some(&body),
            &mut output,
            Some(&prepaid),
            &CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        )
        .await
        .unwrap();
        let ticks = apple::last_ticks_for_test().unwrap();
        assert!(output.as_ref().is_empty());
        assert_eq!(budget.used(), before);
        observations.push((actual, ticks));
        drop(occupied);
        drop(prepaid);
        drop(output);
        assert_eq!(budget.used(), 0);
    }
    assert_eq!(observations[0], observations[1]);
    assert_eq!(
        observations[0].0,
        json!({"type":"modify","headers":[{"op":"set","name":"x-result","values":["z"]}]})
    );
    assert!(observations[0].1 > 0);
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_literal_replace_sparse_and_unicode_refund_retained_admission() {
    use crate::http_processing::body_budget::{MAX_BODY, WORKSPACE, bridge_workspace_cost};
    for body in [format!("{}q", "x".repeat(4095)), "éq".repeat(2048)] {
        let units = body.encode_utf16().count();
        let code = CompiledSource { code: "function rewrite(input){let flags='';for(let i=0;i<3;i++){flags+=typeof __voleReplaceASCIIAll(input.body.data,input.body.data.length,113,122);}return {type:'modify',headers:[{op:'set',name:'x-native',values:[flags]}]};}".into(), ..Default::default() };
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, MAX_BODY).unwrap();
        let prepaid = budget
            .reserve(bridge_workspace_cost(body.len(), true).unwrap())
            .unwrap();
        let occupied = budget
            .reserve(WORKSPACE - budget.used() - 2 * units)
            .unwrap();
        let expected = budget.used();
        let at_release = budget.clone();
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = observed.clone();
        apple::on_context_release_for_test(move || {
            result.store(
                at_release.used() == expected,
                std::sync::atomic::Ordering::Release,
            );
        });
        let actual = evaluate_until(
            &code,
            &input("text"),
            Some(body.as_bytes()),
            &mut output,
            Some(&prepaid),
            &CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(
            actual,
            json!({"type":"modify","headers":[{"op":"set","name":"x-native","values":["undefinedundefinedundefined"]}]})
        );
        assert!(observed.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(budget.used(), expected);
        drop(occupied);
        drop(prepaid);
        drop(output);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_native_literal_replace_large_input_needs_additional_temporary_payload() {
    use crate::http_processing::body_budget::{MAX_BODY, WORKSPACE, bridge_workspace_cost};
    let code = CompiledSource { code: "function rewrite(input){const value=__voleReplaceASCIIAll(input.body.data,input.body.data.length,113,122);return {type:'modify',headers:[{op:'set',name:'x-native',values:[typeof value]}]};}".into(), ..Default::default() };
    let body = vec![b'q'; MAX_BODY];
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    let prepaid = budget
        .reserve(bridge_workspace_cost(body.len(), true).unwrap())
        .unwrap();
    // Exactly 2O remains available: a broken implementation that reuses the
    // 3MAX slot for a 5I temporary peak could incorrectly return a string.
    let occupied = budget
        .reserve(WORKSPACE - budget.used() - 2 * MAX_BODY)
        .unwrap();
    let before = budget.used();
    let actual = evaluate_until(
        &code,
        &input("text"),
        Some(&body),
        &mut output,
        Some(&prepaid),
        &CancellationToken::new(),
        std::time::Instant::now() + std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!(
        actual,
        json!({"type":"modify","headers":[{"op":"set","name":"x-native","values":["undefined"]}]})
    );
    assert_eq!(budget.used(), before);
    drop(occupied);
    drop(prepaid);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn apple_native_literal_replace_keeps_dense_allocation_work_and_error_refund() {
    let body = vec![b'q'; 65536];
    for (calls, accepted) in [(3, true), (4, false)] {
        let source = format!(
            "function rewrite(input){{let reserve=[0];for(let i=0;i<15;i++){{reserve=reserve.concat(reserve);}}let data=input.body.data;for(let i=0;i<{calls};i++){{data=data.replaceAll('q','q');}}return {{type:'pass'}};}}"
        );
        assert_eq!(
            evaluate_text(&source, &body, input("text")).await.is_ok(),
            accepted
        );
    }
    let code = validate_source("function rewrite(input){const text=input.body.data.replaceAll('q','z');return {type:'modify',status:0,body:{kind:'text',data:text}};}").unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    assert!(
        evaluate(
            &code,
            &input("text"),
            Some(&body),
            &mut output,
            &CancellationToken::new()
        )
        .await
        .is_err()
    );
    assert_eq!(budget.used(), 0);
}

async fn ascii_utf8_input_observation(
    code: &CompiledSource,
    body: &str,
    force_utf16: bool,
    fill_workspace: bool,
) -> (Result<serde_json::Value, io::ErrorKind>, Vec<u8>, usize) {
    let _constructor = force_utf16.then(apple::force_utf16_input_for_test);
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, super::super::body_budget::MAX_BODY).unwrap();
    let prepaid = budget
        .reserve(super::super::body_budget::bridge_workspace_cost(body.len(), true).unwrap())
        .unwrap();
    let occupied = fill_workspace.then(|| {
        budget
            .reserve(super::super::body_budget::WORKSPACE - budget.used())
            .unwrap()
    });
    let admitted = budget.used();
    let metadata = evaluate_until(
        code,
        &input("text"),
        Some(body.as_bytes()),
        &mut output,
        Some(&prepaid),
        &CancellationToken::new(),
        std::time::Instant::now() + std::time::Duration::from_millis(100),
    )
    .await
    .map_err(|error| error.kind());
    let ticks = apple::last_ticks_for_test().unwrap();
    // API-view and literal-output guards must have ended with the real context.
    assert_eq!(budget.used(), admitted);
    let bytes = output.as_ref().to_vec();
    drop(occupied);
    drop(prepaid);
    drop(output);
    assert_eq!(budget.used(), 0);
    (metadata, bytes, ticks)
}

#[tokio::test(flavor = "current_thread")]
async fn apple_ascii_utf8_input_matches_utf16_data_methods_templates_and_fuel() {
    let controls: String = (1u8..=127).map(char::from).collect::<String>().repeat(32);
    let bodies = [
        String::new(),
        "q".into(),
        controls,
        "q".repeat(4095),
        "q".repeat(4096),
        "q".repeat(64 * 1024),
        "q".repeat(super::super::body_budget::MAX_BODY),
        "\0q\0".into(),
        format!("{}\0q", "q".repeat(4096)),
        format!("{}é😀q", "q".repeat(4096)),
    ];
    for replacement in ["z", "$&"] {
        let code = validate_source(&format!(
            "function rewrite(input){{const text=input.body.data;return {{type:'modify',headers:[{{op:'set',name:'x-units',values:[String(text.length)]}}],body:{{kind:'text',data:text.replaceAll('q',{})}}}};}}",
            serde_json::to_string(replacement).unwrap(),
        )).unwrap();
        for body in &bodies {
            let optimized = ascii_utf8_input_observation(&code, body, false, false).await;
            let original = ascii_utf8_input_observation(&code, body, true, false).await;
            assert_eq!(
                optimized,
                original,
                "constructor changed result or fuel for length {}",
                body.len()
            );
            if replacement == "$&" && body.len() == super::super::body_budget::MAX_BODY {
                // The original template scan consumes one tick per match.
                // Constructor selection must preserve its real fuel failure.
                assert_eq!(optimized.0, Err(io::ErrorKind::TimedOut));
                assert_eq!(optimized.2, 100_001);
                assert!(optimized.1.is_empty());
                continue;
            }
            let expected = if replacement == "$&" {
                body.clone()
            } else {
                body.replace('q', "z")
            };
            assert_eq!(optimized.1, expected.as_bytes());
            assert_eq!(
                optimized.0.as_ref().unwrap()["headers"][0]["values"][0],
                body.encode_utf16().count().to_string()
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_ascii_utf8_input_keeps_full_workspace_and_cancel_deadline_boundaries() {
    let code = validate_source(
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data}};}",
    )
    .unwrap();
    for body in [
        "q".repeat(64 * 1024),
        "q".repeat(super::super::body_budget::MAX_BODY),
        "q\0é😀".into(),
    ] {
        let optimized = ascii_utf8_input_observation(&code, &body, false, true).await;
        let original = ascii_utf8_input_observation(&code, &body, true, true).await;
        assert_eq!(optimized, original);
        assert!(optimized.0.is_ok());
        assert_eq!(optimized.1, body.as_bytes());
    }
    for force_utf16 in [false, true] {
        let _constructor = force_utf16.then(apple::force_utf16_input_for_test);
        let budget = Budget::default();
        let mut output = BudgetedBytes::empty(&budget);
        let body = vec![b'q'; 65536];
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let error = evaluate(&code, &input("text"), Some(&body), &mut output, &cancelled)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        let error = evaluate_until(
            &code,
            &input("text"),
            Some(&body),
            &mut output,
            None,
            &CancellationToken::new(),
            std::time::Instant::now() - std::time::Duration::from_millis(1),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(output.as_ref().is_empty());
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_bounded_bridge_matches_maximum_on_text_unicode_nul_bytes_none_and_max() {
    use crate::http_processing::body_budget::{BridgePlan, MAX_BODY, WORKSPACE};
    let identity =
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data}};}";
    let replace = "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('q','z')}};}";
    let literal =
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:'é😀\\u0000q'}};}";
    let cases = vec![
        (identity, "text", Some(vec![])),
        (identity, "text", Some(vec![b'q'; MAX_BODY])),
        (replace, "text", Some(vec![b'q'; 65536])),
        (replace, "text", Some("qé😀\0".repeat(4096).into_bytes())),
        (literal, "bytes", Some(vec![0xff; 32])),
        (literal, "not-requested", None),
    ];
    for (source, kind, bytes) in cases {
        let mut observations = Vec::new();
        for maximum in [false, true] {
            let mut code = validate_source(source).unwrap();
            if maximum {
                code.output_bound = OutputBound::Maximum;
            }
            let budget = Budget::default();
            let output_bound = code.maximum_output_bytes(bytes.as_ref().map_or(0, Vec::len));
            let mut output = if bytes.is_some() {
                BudgetedBytes::new(
                    &budget,
                    super::super::body_budget::output_capacity(output_bound).unwrap(),
                )
                .unwrap()
            } else {
                BudgetedBytes::empty(&budget)
            };
            let prepaid = bytes.as_ref().map(|bytes| {
                budget
                    .reserve(
                        BridgePlan::new(bytes.len(), kind == "text", output_bound)
                            .unwrap()
                            .cost()
                            .unwrap(),
                    )
                    .unwrap()
            });
            // Same old pre-candidate occupancy: do not fill the newly saved
            // bytes and accidentally manufacture a late export failure.
            let old_cost = bytes.as_ref().map_or(0, |bytes| {
                BudgetedBytes::allocation_cost(MAX_BODY).unwrap()
                    + super::super::body_budget::bridge_workspace_cost(bytes.len(), kind == "text")
                        .unwrap()
            });
            let occupied = if bytes.is_some() {
                Some(budget.reserve(WORKSPACE - old_cost).unwrap())
            } else {
                None
            };
            let before = budget.used();
            let result = apple::evaluate(
                &code,
                &input(kind),
                bytes.as_deref(),
                &mut output,
                prepaid.as_ref(),
                &CancellationToken::new(),
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .map_err(|e| e.kind());
            assert!(result.is_ok(), "{kind}, maximum={maximum}, {result:?}");
            if bytes.is_some() {
                assert_eq!(budget.used(), before);
            }
            assert!(output.as_ref().len() <= output_bound);
            observations.push((
                result,
                output.as_ref().to_vec(),
                apple::last_ticks_for_test(),
            ));
            drop(occupied);
            drop(prepaid);
            drop(output);
            assert_eq!(budget.used(), 0);
        }
        assert_eq!(
            observations[0], observations[1],
            "source={source},kind={kind}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_bounded_bridge_retained_slices_and_extra_live_through_actual_context_release() {
    use crate::http_processing::body_budget::{BridgePlan, WORKSPACE};
    use std::{cell::RefCell, rc::Rc};
    let length = 4096;
    // Trusted ABI-only vector forces four outputs past the small slot. The
    // production proof does not come from this raw initializer.
    let code=CompiledSource{code:"function rewrite(input){let flags='';for(let i=0;i<5;i++){const v=__voleReplaceASCIIAll(input.body.data,input.body.data.length,113,122);flags+=v===undefined?'0':'1';}return {type:'modify',headers:[{op:'set',name:'x-native',values:[flags]}],body:{kind:'text',data:input.body.data}};}".into(),output_bound:OutputBound::InputOrConstant{maximum_literal_bytes:0}};
    let plan = BridgePlan::new(length, true, length).unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, length).unwrap();
    let prepaid = budget.reserve(plan.cost().unwrap()).unwrap();
    let occupied = budget
        .reserve(WORKSPACE - budget.used() - 6 * length)
        .unwrap();
    let before = budget.used();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let copy = seen.clone();
    let at_event = budget.clone();
    apple::observe_bridge_for_test(move |event| {
        copy.borrow_mut()
            .push((event, at_event.used(), apple::bridge_view_for_test()))
    });
    let released = Rc::new(RefCell::new(None));
    let copy = released.clone();
    let at_release = budget.clone();
    apple::on_context_release_for_test(move || {
        *copy.borrow_mut() = Some((at_release.used(), apple::bridge_view_for_test()))
    });
    let result = apple::evaluate(
        &code,
        &input("text"),
        Some(&vec![b'q'; length]),
        &mut output,
        Some(&prepaid),
        &CancellationToken::new(),
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    apple::observe_bridge_for_test(|_| {});
    assert_eq!(result["headers"][0]["values"][0], "11110");
    let retained_capacity = plan.view_capacity - 3 * length;
    let extra_retained = 8 * length - retained_capacity;
    assert_eq!(
        *released.borrow(),
        Some((
            before + extra_retained,
            (plan.view_capacity, retained_capacity)
        ))
    );
    assert_eq!(budget.used(), before);
    assert_eq!(output.as_ref(), vec![b'q'; length]);
    let seen = seen.borrow();
    assert!(
        seen.iter()
            .any(|entry| entry.0 == apple::BridgeEvent::ExportCopyStart
                && entry.1 == before + extra_retained)
    );
    let starts: Vec<_> = seen
        .iter()
        .filter(|e| e.0 == apple::BridgeEvent::NativeCopyStart)
        .collect();
    let commits: Vec<_> = seen
        .iter()
        .filter(|e| e.0 == apple::BridgeEvent::NativeRetainedCommitted)
        .collect();
    let drops: Vec<_> = seen
        .iter()
        .filter(|e| e.0 == apple::BridgeEvent::NativeOwnersDropped)
        .collect();
    assert_eq!((starts.len(), commits.len(), drops.len()), (4, 4, 4));
    let sequence: Vec<_> = seen
        .iter()
        .filter_map(|entry| match entry.0 {
            apple::BridgeEvent::NativeInputOwnerDropped => Some(false),
            apple::BridgeEvent::NativeRetainedCommitted => Some(true),
            _ => None,
        })
        .collect();
    assert_eq!(
        sequence,
        vec![false, true, false, true, false, true, false, true]
    );
    for ((start, commit), dropped) in starts.iter().zip(commits).zip(drops) {
        let available = plan.view_capacity - start.2.1;
        let needed_extra = (7 * length + std::mem::size_of::<Vec<u16>>()).saturating_sub(available);
        assert!(start.1 >= before + needed_extra);
        assert!(commit.2.1 >= start.2.1);
        // Runs after native API refs and Vec dropped but before temporary guard.
        assert_eq!(dropped.1, commit.1);
    }
    drop(seen);
    drop(occupied);
    drop(prepaid);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn apple_bounded_bridge_export_reserves_before_copy_and_refunds_after_owner() {
    use crate::http_processing::body_budget::WORKSPACE;
    use std::{cell::RefCell, rc::Rc};
    let text = "é😀\0";
    let units = text.encode_utf16().count();
    let code=validate_source("function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:'é😀\\u0000'}};}").unwrap();
    for free in [3 * units - 1, 3 * units] {
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, text.len()).unwrap();
        let occupied = budget.reserve(WORKSPACE - budget.used() - free).unwrap();
        let before = budget.used();
        let events = Rc::new(RefCell::new(Vec::new()));
        let copy = events.clone();
        let ledger = budget.clone();
        apple::observe_bridge_for_test(move |event| copy.borrow_mut().push((event, ledger.used())));
        let result = apple::evaluate(
            &code,
            &input("not-requested"),
            None,
            &mut output,
            None,
            &CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        apple::observe_bridge_for_test(|_| {});
        if free < 3 * units {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::OutOfMemory);
            assert!(events.borrow().is_empty());
            assert!(output.as_ref().is_empty());
        } else {
            assert!(result.is_ok());
            assert_eq!(output.as_ref(), text.as_bytes());
            assert_eq!(
                &*events.borrow(),
                &[
                    (apple::BridgeEvent::ExportCopyStart, before + 3 * units),
                    (apple::BridgeEvent::ExportOwnerDropped, before + 3 * units)
                ]
            );
        }
        assert_eq!(budget.used(), before);
        drop(occupied);
        drop(output);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_bounded_bridge_max_constructor_uses_paid_utf16_and_empty_none_needs_no_view() {
    use crate::http_processing::body_budget::{BridgePlan, MAX_BODY, WORKSPACE};
    use std::{cell::RefCell, rc::Rc};
    let code = validate_source(
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data}};}",
    )
    .unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::new(&budget, MAX_BODY).unwrap();
    let plan = BridgePlan::new(MAX_BODY, true, MAX_BODY).unwrap();
    let prepaid = budget.reserve(plan.cost().unwrap()).unwrap();
    let held = budget.reserve(WORKSPACE - budget.used()).unwrap();
    let before = budget.used();
    let events = Rc::new(RefCell::new(Vec::new()));
    let copy = events.clone();
    apple::observe_bridge_for_test(move |event| copy.borrow_mut().push(event));
    apple::evaluate(
        &code,
        &input("text"),
        Some(&vec![b'q'; MAX_BODY]),
        &mut output,
        Some(&prepaid),
        &CancellationToken::new(),
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    apple::observe_bridge_for_test(|_| {});
    assert!(
        events
            .borrow()
            .contains(&apple::BridgeEvent::InputUtf16Start)
    );
    assert!(
        !events
            .borrow()
            .contains(&apple::BridgeEvent::InputUtf8Start)
    );
    assert_eq!(budget.used(), before);
    assert_eq!(output.as_ref().len(), MAX_BODY);
    drop(held);
    drop(prepaid);
    drop(output);
    assert_eq!(budget.used(), 0);
    let code = validate_source(
        "function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:''}};}",
    )
    .unwrap();
    let held = budget.reserve(WORKSPACE).unwrap();
    let mut output = BudgetedBytes::empty(&budget);
    apple::evaluate(
        &code,
        &input("not-requested"),
        None,
        &mut output,
        None,
        &CancellationToken::new(),
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(budget.used(), WORKSPACE);
    assert!(output.as_ref().is_empty());
    drop(held);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn apple_bounded_bridge_defensive_bounds_reject_before_copy_or_output_write() {
    use std::{cell::RefCell, rc::Rc};
    // Artificially shrink an otherwise valid proof to exercise native defense.
    // A two-byte UTF8 é has only one code unit and must fail before any write,
    // even though the paid O+1 output capacity happens to fit its bytes.
    for (source, expected_copies) in [
        (
            "function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:'zz'}};}",
            0,
        ),
        (
            "function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:'😀'}};}",
            0,
        ),
        (
            "function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:'é'}};}",
            1,
        ),
        (
            "function rewrite(input){return {type:'respond',status:200,body:{kind:'bytes',data:Uint8Array.from([1,2])}};}",
            0,
        ),
    ] {
        let mut code = validate_source(source).unwrap();
        code.output_bound = OutputBound::InputOrConstant {
            maximum_literal_bytes: 1,
        };
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, 2).unwrap();
        let before = budget.used();
        let events = Rc::new(RefCell::new(Vec::new()));
        let copy = events.clone();
        apple::observe_bridge_for_test(move |event| copy.borrow_mut().push(event));
        let result = apple::evaluate(
            &code,
            &input("not-requested"),
            None,
            &mut output,
            None,
            &CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        apple::observe_bridge_for_test(|_| {});
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|e| **e == apple::BridgeEvent::ExportCopyStart)
                .count(),
            expected_copies
        );
        assert!(output.as_ref().is_empty());
        assert_eq!(output.remaining(), 2);
        assert_eq!(budget.used(), before);
        drop(output);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_bounded_bridge_accounts_for_intermediate_strings_larger_than_input_and_bound() {
    use crate::http_processing::body_budget::{BridgePlan, WORKSPACE, output_capacity};
    use std::{cell::RefCell, rc::Rc};
    let body = "qxxx".repeat(16384);
    let length = body.len();
    let wide_length = 3 * length;
    for statement in [
        "const unused=wide.includes('z');",
        "const unused=wide.replaceAll('q','z');",
    ] {
        let source = format!(
            "function rewrite(input){{const wide=input.body.data+input.body.data+input.body.data;{statement}return {{type:'modify',body:{{kind:'text',data:input.body.data}}}};}}"
        );
        let code = validate_source(&source).unwrap();
        assert_eq!(code.maximum_output_bytes(length), length);
        let plan = BridgePlan::new(length, true, length).unwrap();
        let mut observations = Vec::new();
        for fill in [false, true] {
            let budget = Budget::default();
            let mut output = BudgetedBytes::new(&budget, output_capacity(length).unwrap()).unwrap();
            let prepaid = budget.reserve(plan.cost().unwrap()).unwrap();
            let occupied = fill.then(|| budget.reserve(WORKSPACE - budget.used()).unwrap());
            let before = budget.used();
            let events = Rc::new(RefCell::new(Vec::new()));
            let copy = events.clone();
            let ledger = budget.clone();
            apple::observe_bridge_for_test(move |event| {
                copy.borrow_mut().push((event, ledger.used()))
            });
            let result = apple::evaluate(
                &code,
                &input("text"),
                Some(body.as_bytes()),
                &mut output,
                Some(&prepaid),
                &CancellationToken::new(),
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .map_err(|e| e.kind());
            apple::observe_bridge_for_test(|_| {});
            assert!(result.is_ok(), "{statement} fill={fill} {result:?}");
            assert_eq!(output.as_ref(), body.as_bytes());
            assert_eq!(budget.used(), before);
            let events = events.borrow();
            if !fill {
                let (kind, extra) = if statement.contains("replaceAll") {
                    (
                        apple::BridgeEvent::NativeCopyStart,
                        7 * wide_length + std::mem::size_of::<Vec<u16>>() - plan.view_capacity,
                    )
                } else {
                    (
                        apple::BridgeEvent::AsciiCopyStart,
                        3 * wide_length - plan.view_capacity,
                    )
                };
                assert!(
                    events
                        .iter()
                        .any(|(event, used)| *event == kind && *used >= before + extra)
                );
            } else {
                assert!(events.iter().all(|(_, used)| *used == before));
                assert!(
                    !events
                        .iter()
                        .any(|(e, _)| *e == apple::BridgeEvent::NativeCopyStart)
                );
            }
            observations.push((result, apple::last_ticks_for_test()));
            drop(events);
            drop(occupied);
            drop(prepaid);
            drop(output);
            assert_eq!(budget.used(), 0);
        }
        assert_eq!(observations[0], observations[1], "{statement}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apple_bounded_bridge_continuous_native_fallback_preserves_prepaid_final_egress() {
    use crate::http_processing::body_budget::{BridgePlan, WORKSPACE, output_capacity};
    use std::{cell::RefCell, rc::Rc};
    let source = "function rewrite(input){const first=input.body.data.replaceAll('q','z');const second=first.replaceAll('z','y');const third=second.replaceAll('y','x');return {type:'modify',body:{kind:'text',data:third}};}";
    let code = validate_source(source).unwrap();
    let length = 4096;
    assert_eq!(code.maximum_output_bytes(length), length);
    let plan = BridgePlan::new(length, true, length).unwrap();
    let mut observations = Vec::new();
    for fill in [false, true] {
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, output_capacity(length).unwrap()).unwrap();
        let prepaid = budget.reserve(plan.cost().unwrap()).unwrap();
        let occupied = fill.then(|| budget.reserve(WORKSPACE - budget.used()).unwrap());
        let before = budget.used();
        let events = Rc::new(RefCell::new(Vec::new()));
        let copy = events.clone();
        let ledger = budget.clone();
        apple::observe_bridge_for_test(move |event| {
            copy.borrow_mut()
                .push((event, ledger.used(), apple::bridge_view_for_test()))
        });
        let result = apple::evaluate(
            &code,
            &input("text"),
            Some(&vec![b'q'; length]),
            &mut output,
            Some(&prepaid),
            &CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .map_err(|e| e.kind());
        apple::observe_bridge_for_test(|_| {});
        assert!(result.is_ok(), "fill={fill} {result:?}");
        assert_eq!(output.as_ref(), vec![b'x'; length]);
        let events = events.borrow();
        let starts = events
            .iter()
            .filter(|event| event.0 == apple::BridgeEvent::NativeCopyStart)
            .count();
        assert_eq!(starts, if fill { 1 } else { 3 });
        assert!(
            events
                .iter()
                .any(|event| event.0 == apple::BridgeEvent::ExportCopyStart
                    && event.2.0 - event.2.1 >= 3 * length)
        );
        if fill {
            assert!(events.iter().all(|event| event.1 == before));
        }
        observations.push((result, apple::last_ticks_for_test()));
        assert_eq!(budget.used(), before);
        drop(events);
        drop(occupied);
        drop(prepaid);
        drop(output);
        assert_eq!(budget.used(), 0);
    }
    assert_eq!(observations[0], observations[1]);
}
