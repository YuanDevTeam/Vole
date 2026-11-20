//! Memory/Apple semantic regressions. New integration changes are unexecuted.
//! Physical tvOS validation is owned by the explicit diagnostic suite.
use super::*;
use crate::http_processing::{
    body_budget::{BridgePlan, Budget, output_capacity},
    scripts::{apple, validate_source},
};
use serde_json::json;
use std::time::Duration;

const BODY_ONLY: &str = "function rewrite(input){const text=input.body.data.replaceAll('-', '_');return {type:'modify',body:{kind:'text',data:text}};}";

fn input_metadata() -> Value {
    json!({"body":{"kind":"text"}})
}
fn buffers(
    budget: &Budget,
    input: &[u8],
    bound: usize,
) -> (BudgetedBytes, BudgetedBytes, Reservation) {
    let input = BudgetedBytes::copy(budget, input).unwrap();
    let output = BudgetedBytes::new(budget, output_capacity(bound).unwrap()).unwrap();
    let bridge = budget
        .reserve(
            BridgePlan::new(input.as_ref().len(), true, bound)
                .unwrap()
                .cost()
                .unwrap(),
        )
        .unwrap();
    (input, output, bridge)
}

fn compare_jsc(source: &str, input: &[u8]) {
    let compiled = validate_source(source).unwrap();
    let bound = compiled.maximum_output_bytes(input.len());
    let budget = Budget::default();
    let (source_input, mut output, bridge) = buffers(&budget, input, bound);
    let jsc = apple::evaluate(
        &compiled,
        &input_metadata(),
        Some(source_input.as_ref()),
        &mut output,
        Some(&bridge),
        &CancellationToken::new(),
        Instant::now() + Duration::from_millis(100),
    );
    let jsc_ticks = apple::last_ticks_for_test().expect("actual JSC owner ended");
    let jsc_bytes = output.as_ref().to_vec();
    drop((source_input, output, bridge));
    assert_eq!(budget.used(), 0);

    let (source_input, mut output, bridge) = buffers(&budget, input, bound);
    let result = compile(source)
        .expect("closed AST subset")
        .try_execute(
            &input_metadata(),
            Some(source_input.borrowed_body()),
            &mut output,
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(100),
        )
        .expect("UTF-8 text pre-execution eligibility");
    match (jsc, result.result) {
        (Ok(jsc), Ok(native)) => {
            assert_eq!(native, jsc);
            assert_eq!(output.as_ref(), jsc_bytes);
        }
        (Err(jsc), Err(native)) => assert_eq!(native.kind(), jsc.kind()),
        other => panic!("backend result mismatch: {other:?}"),
    }
    assert_eq!(result.ticks, jsc_ticks, "controlled healthy/quota trace");
    assert_eq!(result.backend, "static-ascii-literal-prototype");
    drop((source_input, output, bridge));
    assert_eq!(budget.used(), 0);
}

#[test]
#[ignore = "unbuilt isolated prototype; actual Apple JSC differential required"]
fn static_literal_closed_ast_never_ignores_other_statements() {
    for source in [
        "function rewrite(input){while(true){}return {type:'modify',body:{kind:'text',data:input.body.data}};}",
        "function rewrite(input){const a=input.body.data; a='x';return {type:'modify',body:{kind:'text',data:a}};}",
        "function rewrite(input){const a=input.body.data; a[0]=1;return {type:'modify',body:{kind:'text',data:a}};}",
        "function rewrite(input){if(true){return {type:'modify',body:{kind:'text',data:input.body.data}};}return {type:'modify',body:{kind:'text',data:input.body.data}};}",
        "function rewrite(input){const h=[];h.push('x');return {type:'modify',headers:h,body:{kind:'text',data:input.body.data}};}",
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('', 'x')}};}",
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('-', '$')}};}",
        "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('é', '_')}};}",
        "function rewrite(input){return {type:'modify',type:'modify',body:{kind:'text',data:input.body.data}};}",
    ] {
        assert!(compile(source).is_none(), "must keep JSC: {source}");
    }
    // The complete generic guard is proved, never removed or assumed true.
    // Extra unknown statements still force the whole invocation to JSC.
    let mixed = "function rewrite(input){let found=false;for(let i=0;i<input.response.headers.length;i++){if(input.response.headers[i].name==='x-native'){found=true;}}if(!found){return {type:'abort'};}const t=input.body.data.replaceAll('-', '_');return {type:'modify',body:{kind:'text',data:t}};}";
    assert!(compile(mixed).is_some());
    for unsupported in [
        mixed.replace("let found=false;", "let found=false;while(false){}"),
        mixed.replace("found=true;", "found=false;"),
        mixed.replace("found=true;", "found=true;break;"),
    ] {
        assert!(compile(&unsupported).is_none());
    }
}

#[test]
#[ignore = "unbuilt isolated prototype; run after independent trace review"]
fn static_literal_ascii_body_only_has_the_known_trace() {
    let budget = Budget::default();
    let text = vec![b'-'; 65536];
    let (input, mut output, bridge) = buffers(&budget, &text, text.len());
    let attempt = compile(BODY_ONLY)
        .unwrap()
        .try_execute(
            &input_metadata(),
            Some(input.borrowed_body()),
            &mut output,
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap();
    assert_eq!(
        attempt.result.unwrap(),
        json!({"type":"modify","body":{"kind":"text"}})
    );
    assert_eq!(attempt.ticks, 25);
    assert_eq!(attempt.allocation_work, 131472);
    assert!(output.as_ref().iter().all(|b| *b == b'_'));
    drop((input, output, bridge));
    assert_eq!(budget.used(), 0);
}

#[test]
#[ignore = "unbuilt prototype; independently derived static-header trace"]
fn static_literal_ascii_header_has_the_known_trace() {
    let source = "function rewrite(input){const d=input.body.data.replaceAll('-', '_');return {type:'modify',headers:[{op:'set',name:'x-test',values:['x']}],body:{kind:'text',data:d}};}";
    let budget = Budget::default();
    let body = vec![b'-'; 65536];
    let (input, mut output, bridge) = buffers(&budget, &body, body.len());
    let attempt = compile(source)
        .unwrap()
        .try_execute(
            &input_metadata(),
            Some(input.borrowed_body()),
            &mut output,
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap();
    assert!(attempt.result.is_ok());
    assert_eq!(attempt.ticks, 44);
    assert_eq!(attempt.allocation_work, 131920);
    drop((input, output, bridge));
    assert_eq!(budget.used(), 0);
}

#[test]
#[ignore = "matched-plan budget refusal is skip/rollback, never JSC fallback"]
fn static_literal_matched_plan_budget_refusal_is_an_attempt_error() {
    let budget = Budget::default();
    let (input, mut output, bridge) = buffers(&budget, b"--", 2);
    let blocker = budget
        .reserve(crate::http_processing::body_budget::WORKSPACE - budget.used())
        .unwrap();
    let attempt = compile(BODY_ONLY)
        .unwrap()
        .try_execute(
            &input_metadata(),
            Some(input.borrowed_body()),
            &mut output,
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(100),
        )
        .expect("closed ASCII selection cannot fall back after budget refusal");
    assert_eq!(
        attempt.result.unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(attempt.ticks, 0);
    assert_eq!(attempt.allocation_work, 0);
    assert!(output.as_ref().is_empty());
    drop((blocker, input, output, bridge));
    assert_eq!(budget.used(), 0);
}

#[test]
#[ignore = "requires real Apple JSC with the production warmup; limits unchanged"]
fn static_literal_real_jsc_differential_ascii_shapes_aliases_and_headers() {
    for length in [0, 1, 255, 256, 4095, 4096, 65536, MAX_BODY] {
        let input = vec![b'-'; length];
        for (method, search, replacement) in [
            ("replace", "-", "_"),
            ("replaceAll", "-", "_"),
            ("replaceAll", "~", "~"),
            ("replaceAll", "\0", "\x7f"),
        ] {
            let a = serde_json::to_string(search).unwrap();
            let b = serde_json::to_string(replacement).unwrap();
            for name in ["text", "renamedLocal"] {
                let source = format!(
                    "function rewrite(input){{const {name}=input.body.data;const result={name}.{method}({a},{b});return {{headers:[{{op:'set',name:'X-Proof',values:['a\\t\\\"b']}},{{op:'add',name:'X-Proof',values:['']}},{{op:'remove',name:'X-Old'}}],body:{{data:result,kind:'text'}},type:'modify'}};}}"
                );
                compare_jsc(&source, &input);
            }
        }
    }
    compare_jsc(
        "function rewrite(input){const a='--\0-';const b=a.replace('-', '_');return {type:'modify',body:{kind:'text',data:b}};}",
        b"input",
    );
    compare_jsc(
        "function rewrite(input){const unused=input.body.data.replaceAll('-', '_');const original=input.body.data;return {body:{data:original,kind:'text'},type:'modify'};}",
        b"----",
    );
}

#[test]
#[ignore = "requires real JSC; no source-level dead-code removal is permitted"]
fn static_literal_unused_calls_preserve_cumulative_work_failure() {
    for calls in [14, 15, 16] {
        let declarations = (0..calls)
            .map(|i| format!("const unused{i}=input.body.data.replaceAll('-', '_');"))
            .collect::<String>();
        let source = format!(
            "function rewrite(input){{{declarations}return {{type:'modify',body:{{kind:'text',data:input.body.data}}}};}}"
        );
        compare_jsc(&source, &vec![b'-'; 65536]);
    }
}

#[test]
#[ignore = "pre-execution fallback and actual last-owner release draft"]
fn static_literal_invalid_utf8_or_unpaid_guards_fall_back_before_execution() {
    let plan = compile(BODY_ONLY).unwrap();
    for text in [b"\xff".as_slice(), b"\xc3", b"\xed\xa0\x80"] {
        let budget = Budget::default();
        let (input, mut output, bridge) = buffers(&budget, text, text.len());
        assert!(
            plan.try_execute(
                &input_metadata(),
                Some(input.borrowed_body()),
                &mut output,
                &CancellationToken::new(),
                Instant::now() + Duration::from_millis(100)
            )
            .is_none()
        );
        assert!(output.as_ref().is_empty());
        drop((input, output, bridge));
        assert_eq!(budget.used(), 0);
    }
    let budget = Budget::default();
    let (input, mut output, bridge) = buffers(&budget, b"--", 2);
    assert!(
        plan.try_execute(
            &input_metadata(),
            None,
            &mut output,
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(100)
        )
        .is_none()
    );
    let attempt = plan
        .try_execute(
            &input_metadata(),
            Some(input.borrowed_body()),
            &mut output,
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap();
    attempt.result.unwrap();
    drop((input, bridge));
    let bytes = output.into_bytes();
    let last = bytes.slice(..);
    drop(bytes);
    assert!(budget.used() > 0);
    drop(last);
    assert_eq!(budget.used(), 0);
}

#[test]
fn utf8_literal_plan_matches_actual_jsc_for_all_text_shapes_and_first_all_chains() {
    let boundary = format!("{}😀{}-", "a".repeat(255), "a".repeat(255));
    let long_unicode = format!("{}-", "中文😀e\u{301}".repeat(800));
    for input in [
        "中文--结尾\0$",
        "😀-😀--",
        "e\u{301}-é--",
        "\0-\0$",
        &boundary,
        &long_unicode,
    ] {
        for expression in [
            "input.body.data",
            "input.body.data.replace('-', '_')",
            "input.body.data.replaceAll('-', '_')",
            "input.body.data.replaceAll('-', '_').replace('_', '+')",
            "input.body.data.replace('-', '_').replaceAll('_', '+')",
        ] {
            let source = format!(
                "function rewrite(input){{const unused=input.body.data.replaceAll('a','b');return {{type:'modify',body:{{kind:'text',data:{expression}}}}};}}"
            );
            compare_jsc(&source, input.as_bytes());
        }
    }
}

#[test]
fn utf8_text_size_fuel_counts_scalar_starts_in_utf16_not_utf8_or_rounded_units() {
    let cancellation = CancellationToken::new();
    let work = Work {
        ticks: 0,
        allocated: 0,
        cancellation: &cancellation,
        deadline: Instant::now() + Duration::from_millis(100),
    };
    assert_eq!(utf8_text_ticks(&"é".repeat(256), &work).unwrap(), 1);
    let boundary = format!("{}😀{}", "a".repeat(255), "a".repeat(255));
    assert_eq!(boundary.encode_utf16().count(), 512);
    assert_eq!(utf8_text_ticks(&boundary, &work).unwrap(), 1);
    assert_eq!(utf8_text_ticks(&"a".repeat(4095), &work).unwrap(), 16);
    assert_eq!(utf8_text_ticks(&"a".repeat(4096), &work).unwrap(), 1);
    compare_jsc(BODY_ONLY, boundary.as_bytes());
}

fn guarded_plan_source(length: usize, early: &str, tail: &str) -> String {
    format!(
        "function rewrite(input){{if(!input.body||input.body.kind!=='text'||typeof input.body.data!=='string'||input.body.data.length!=={length}){{return {{type:'{early}'}};}}{tail}}}"
    )
}

// Mac exposes the real JSC tick count, but its numeric allocation-work probe
// is tvOS-only. Work below uses independent canaries and actual JSC quota
// outcomes; it must not be reported as a direct numeric JSC-work observation.
fn guarded_plan_compare(
    source: &str,
    input: &[u8],
    metadata: &Value,
) -> (Result<Value, io::ErrorKind>, Vec<u8>, usize, usize) {
    let compiled = validate_source(source).expect("accepted public JS subset");
    let budget = Budget::default();
    let (owned_input, mut output, bridge) =
        buffers(&budget, input, compiled.maximum_output_bytes(input.len()));
    let jsc = apple::evaluate(
        &compiled,
        metadata,
        Some(owned_input.as_ref()),
        &mut output,
        Some(&bridge),
        &CancellationToken::new(),
        Instant::now() + Duration::from_millis(100),
    )
    .map_err(|error| error.kind());
    let jsc_ticks = apple::last_ticks_for_test().expect("actual JSC context ended");
    let jsc_bytes = output.as_ref().to_vec();
    drop((owned_input, output, bridge));
    assert_eq!(budget.used(), 0);

    let plan = compile(source).expect("complete generic guard and immutable string versions");
    let owned_input = BudgetedBytes::copy(&budget, input).unwrap();
    let bound = plan.maximum_output_bytes(input.len()).unwrap();
    let mut output = BudgetedBytes::new(&budget, bound).unwrap();
    let attempt = plan
        .try_execute(
            metadata,
            Some(owned_input.borrowed_body()),
            &mut output,
            &CancellationToken::new(),
            Instant::now() + Duration::from_millis(100),
        )
        .expect("qualified text input selected before execution");
    let result = attempt.result.map_err(|error| error.kind());
    assert_eq!(result, jsc, "actual backend outcome");
    assert_eq!(attempt.ticks, jsc_ticks, "actual controlled tick trace");
    assert_eq!(output.as_ref(), jsc_bytes, "actual complete body output");
    let bytes = output.as_ref().to_vec();
    drop((owned_input, output));
    assert_eq!(budget.used(), 0, "all actual body owners released");
    (result, bytes, attempt.ticks, attempt.allocation_work)
}

#[test]
fn guarded_plan_generic_text_checks_use_utf16_and_versioned_let_bindings() {
    for (name, search, replacement, input, expected) in [
        ("payload", "-", "_", "😀-\0", "😀_\0"),
        ("renamedText", "x", "y", "x\0😀", "y\0😀"),
        ("emptyText", "-", "_", "", ""),
    ] {
        let tail = format!(
            "let {name}=input.body.data;{name}={name}.replaceAll('{search}','{replacement}');return {{type:'modify',body:{{kind:'text',data:{name}}}}};"
        );
        let source = guarded_plan_source(input.encode_utf16().count(), "abort", &tail);
        let (result, bytes, _, work) =
            guarded_plan_compare(&source, input.as_bytes(), &input_metadata());
        assert_eq!(
            result.unwrap(),
            json!({"type":"modify","body":{"kind":"text"}})
        );
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(
            work,
            input.len() * 2 + 400,
            "one replacement plus complete Finish"
        );
    }
    let input = "😀-\0";
    for early in ["pass", "abort"] {
        // Six UTF-8 bytes are four JS code units: this must take the early
        // branch, not silently use a UTF-8 length or execute the tail.
        let source = guarded_plan_source(
            input.len(),
            early,
            "let s=input.body.data;s=s.replaceAll('-','_');return {type:'modify',body:{kind:'text',data:s}};",
        );
        let (result, bytes, ticks, work) =
            guarded_plan_compare(&source, input.as_bytes(), &input_metadata());
        assert_eq!(result.unwrap(), json!({"type":early}));
        assert!(bytes.is_empty());
        assert_eq!(ticks, 23);
        assert_eq!(work, if early == "pass" { 142 } else { 144 });
    }
}

#[test]
fn guarded_plan_header_early_return_skips_the_body_guard_and_tail() {
    let input = "😀\0-".repeat(1024);
    for early in ["pass", "abort"] {
        let body = guarded_plan_source(
            1,
            "abort",
            "let changed=input.body.data;changed=changed.replaceAll('-','_');return {type:'modify',body:{kind:'text',data:changed}};",
        );
        let prefix = format!(
            "let present=false;for(let cursor=0;cursor<input.response.headers.length;cursor++){{if(input.response.headers[cursor].name==='x-generic-stage'&&input.response.headers[cursor].value==='ready'){{present=true;}}}}if(!present){{return {{type:'{early}'}};}}"
        );
        let source = body.replacen(
            "function rewrite(input){",
            &format!("function rewrite(input){{{prefix}"),
            1,
        );
        let metadata = json!({"body":{"kind":"text"},"response":{"headers":[{"name":"other","value":"ready"}]}});
        let (result, bytes, ticks, work) =
            guarded_plan_compare(&source, input.as_bytes(), &metadata);
        assert_eq!(result.unwrap(), json!({"type":early}));
        assert!(bytes.is_empty());
        assert_eq!(ticks, 34, "one failed name leaf; no body-guard Gets");
        assert_eq!(work, if early == "pass" { 158 } else { 160 });
        let matched = json!({"body":{"kind":"text"},"response":{"headers":[{"name":"x-generic-stage","value":"ready"}]}});
        let healthy = source.replacen(
            "input.body.data.length!==1",
            &format!("input.body.data.length!=={}", input.encode_utf16().count()),
            1,
        );
        let (result, bytes, _, work) = guarded_plan_compare(&healthy, input.as_bytes(), &matched);
        assert_eq!(
            result.unwrap(),
            json!({"type":"modify","body":{"kind":"text"}})
        );
        assert_eq!(bytes, input.replace('-', "_").as_bytes());
        assert_eq!(
            work,
            input.len() * 2 + 416,
            "matched header update and full tail"
        );
    }
}

#[test]
fn guarded_plan_old_aliases_and_unused_replacements_preserve_work() {
    let source = guarded_plan_source(
        4,
        "abort",
        "let current=input.body.data;const old=current;current=current.replaceAll('-','_');const unused=current.replaceAll('_','+');return {type:'modify',body:{kind:'text',data:old}};",
    );
    let (result, bytes, _, work) = guarded_plan_compare(&source, b"----", &input_metadata());
    assert!(result.is_ok());
    assert_eq!(
        bytes, b"----",
        "an old alias must retain its immutable version"
    );
    assert_eq!(
        work, 448,
        "both replacements execute even when the old value is returned"
    );

    let input = vec![b'-'; 65536];
    for calls in [15, 16] {
        let assignments = "current=current.replaceAll('-','_');".repeat(calls);
        let tail = format!(
            "let current=input.body.data;{assignments}return {{type:'modify',body:{{kind:'text',data:current}}}};"
        );
        let source = guarded_plan_source(input.len(), "abort", &tail);
        let (result, bytes, _, work) = guarded_plan_compare(&source, &input, &input_metadata());
        if calls == 15 {
            assert!(result.is_ok());
            assert_eq!(work, 1_966_928);
            assert!(bytes.iter().all(|byte| *byte == b'_'));
        } else {
            assert_eq!(result.unwrap_err(), io::ErrorKind::InvalidData);
            assert_eq!(
                work, 1_966_560,
                "failed sixteenth Charge must not commit its work"
            );
            assert!(
                bytes.is_empty(),
                "work failure must not publish a partial result"
            );
        }
    }
}

#[test]
fn guarded_plan_unknown_writes_and_calls_keep_the_complete_jsc_path() {
    for mutation in [
        "input.body.data='changed';",
        "if(input.phase==='request'){s=s.replaceAll('-','_');}",
        "s+='growing';",
        "s=s.replaceAll('-','$');",
        "s=s.replaceAll('','_');",
        "s=s.replaceAll('é','_');",
        "Math.abs(1);",
        "while(false){s=s.replaceAll('-','_');}",
        "{let s='shadow';s=s.replaceAll('-','_');}",
    ] {
        let tail = format!(
            "let s=input.body.data;{mutation}return {{type:'modify',body:{{kind:'text',data:s}}}};"
        );
        let source = guarded_plan_source(4, "abort", &tail);
        validate_source(&source).expect("negative Plan case must remain accepted JS");
        assert!(
            compile(&source).is_none(),
            "unknown complete effect selected Plan: {source}"
        );
    }
}

#[test]
fn guarded_plan_predicates_preserve_short_circuit_and_literal_order() {
    let tail = "const mapped=input.body.data.replaceAll('-','_');return {type:'modify',body:{kind:'text',data:mapped}};";
    for (predicate, early, ticks) in [
        (
            "input.body.kind==='text'||input.body.data.length!==999",
            true,
            11,
        ),
        (
            "typeof input.body.data==='string'&&input.body.data.length===4",
            true,
            17,
        ),
        (
            "!(input.body.kind!=='text')&&4===input.body.data.length",
            true,
            17,
        ),
        ("input.body&&input.body.kind==='text'", true, 13),
        (
            "input.body.kind==='bytes'&&input.body.data.length===4",
            false,
            29,
        ),
        ("input.body.data.length!==4.5", true, 13),
        ("'text'===input.body.kind", true, 11),
        ("input.body.kind!=='文'", true, 11),
    ] {
        let source =
            format!("function rewrite(input){{if({predicate}){{return {{type:'pass'}};}}{tail}}}");
        let (result, bytes, actual_ticks, work) =
            guarded_plan_compare(&source, "😀-\0".as_bytes(), &input_metadata());
        assert_eq!(actual_ticks, ticks, "independent guard trace: {predicate}");
        if early {
            assert_eq!(result.unwrap(), json!({"type":"pass"}));
            assert!(bytes.is_empty());
            assert_eq!(work, 142);
        } else {
            assert_eq!(
                result.unwrap(),
                json!({"type":"modify","body":{"kind":"text"}})
            );
            assert_eq!(bytes, "😀_\0".as_bytes());
            assert_eq!(work, 412);
        }
    }
}

#[test]
fn guarded_plan_standalone_rebindings_keep_immutable_aliases() {
    let source = "function rewrite(input){let value=input.body.data;const old=value;value=value.replaceAll('-','_');value=value.replaceAll('_','+');return {type:'modify',body:{kind:'text',data:old}};}";
    let (result, bytes, _, work) = guarded_plan_compare(source, b"----", &input_metadata());
    assert!(result.is_ok());
    assert_eq!(bytes, b"----");
    assert_eq!(work, 448);
}

#[test]
fn guarded_plan_input_classification_and_selected_failures_keep_owners() {
    let source = guarded_plan_source(
        4,
        "abort",
        "let text=input.body.data;text=text.replaceAll('-','_');return {type:'modify',body:{kind:'text',data:text}};",
    );
    let plan = compile(&source).unwrap();
    let budget = Budget::default();
    let input = BudgetedBytes::copy(&budget, "😀-\0".as_bytes()).unwrap();
    for metadata in [
        json!({}),
        json!({"body":null}),
        json!({"body":{"kind":"bytes"}}),
        json!({"body":{"kind":"not-requested"}}),
        json!({"body":{"kind":[]}}),
    ] {
        let mut output = BudgetedBytes::new(&budget, input.as_ref().len()).unwrap();
        assert!(!plan.accepts_input(&metadata, Some(input.borrowed_body())));
        assert!(
            plan.try_execute(
                &metadata,
                Some(input.borrowed_body()),
                &mut output,
                &CancellationToken::new(),
                Instant::now() + Duration::from_millis(100),
            )
            .is_none()
        );
        assert!(output.as_ref().is_empty());
    }
    for (cancel, expire, expected) in [
        (true, false, io::ErrorKind::Interrupted),
        (false, true, io::ErrorKind::TimedOut),
        (true, true, io::ErrorKind::Interrupted),
    ] {
        let cancellation = CancellationToken::new();
        if cancel {
            cancellation.cancel();
        }
        let deadline = if expire {
            Instant::now() - Duration::from_millis(1)
        } else {
            Instant::now() + Duration::from_millis(100)
        };
        let mut output = BudgetedBytes::new(&budget, input.as_ref().len()).unwrap();
        let attempt = plan
            .try_execute(
                &input_metadata(),
                Some(input.borrowed_body()),
                &mut output,
                &cancellation,
                deadline,
            )
            .expect("selected failure is an attempt, never JSC retry");
        assert_eq!(attempt.result.unwrap_err().kind(), expected);
        assert_eq!((attempt.ticks, attempt.allocation_work), (0, 0));
        assert!(output.as_ref().is_empty());
    }
    drop(input);
    assert_eq!(budget.used(), 0);

    // JSC overwrites this metadata slot with the same actual borrowed text.
    let metadata = json!({"body":{"kind":"text","data":[1,2,3]}});
    let (result, bytes, _, _) = guarded_plan_compare(&source, "😀-\0".as_bytes(), &metadata);
    assert!(result.is_ok());
    assert_eq!(bytes, "😀_\0".as_bytes());
}

#[test]
fn guarded_plan_combined_proof_cap_keeps_the_whole_source_on_jsc() {
    let predicate = ["input.body"; 40].join("||");
    // 40 body leaves + 39 logical nodes + 2 guard control nodes = 81.
    // The tail adds one input node and one immutable version per call:
    // 46 calls reach the combined 128-node cap; 47 exceed it by one.
    // Both sources have at most 126 lexical operator characters, below the
    // independent frontend limit of 128 that the former 60-call case hit.
    for (calls, expected) in [(46, true), (47, false)] {
        let assignments = "value=value.replaceAll('-','_');".repeat(calls);
        let tail = format!(
            "let value=input.body.data;{assignments}return {{type:'modify',body:{{kind:'text',data:value}}}};"
        );
        let tail_only = format!("function rewrite(input){{{tail}}}");
        let tail_plan = compile(&tail_only).expect("each immutable tail is independently provable");
        assert_eq!(tail_plan.nodes.len(), calls + 1);
        let source =
            format!("function rewrite(input){{if({predicate}){{return {{type:'pass'}};}}{tail}}}");
        validate_source(&source).expect("proof limit must not change source acceptance");
        let plan = compile(&source);
        assert_eq!(
            plan.is_some(),
            expected,
            "combined guard and immutable-value cap"
        );
        if let Some(plan) = plan {
            let guard_nodes = plan.body_guard.as_ref().unwrap().node_count();
            assert_eq!(guard_nodes, 81);
            assert_eq!(guard_nodes + plan.nodes.len(), MAX_NODES);
        }
    }
}
