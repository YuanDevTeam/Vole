//! Fixed, active tvOS diagnostic. No caller-supplied source, body or resources.
//! Requires Invoke's irreversible dedicated-process admission; never pressure.
use super::{CompiledSource, apple, static_literal_plan};
use crate::http_processing::{
    Policy,
    body::Entity,
    body_budget::{BridgePlan, Budget, BudgetedBytes, WORKSPACE, output_capacity},
    diagnostics,
    script_config::BodyMode,
    script_message::{self, Message, OriginalSnapshot, Outcome, RequestSnapshot, ScriptOutput},
};
use serde_json::{Value, json};
use std::{
    io,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

const INVOCATION_LIMIT: Duration = Duration::from_millis(100);
enum Input {
    Small(&'static [u8]),
    Repeat(u8, usize),
    Alphabet,
    None,
}
struct Case {
    id: &'static str,
    source: String,
    input: Input,
    kind: &'static str,
    selection: &'static str,
}
struct Observation {
    result: io::Result<Value>,
    ticks: Option<usize>,
    work: Option<usize>,
    backend: &'static str,
    trace: Value,
}
fn body(expression: &str) -> String {
    format!(
        "function rewrite(input){{return {{type:'modify',body:{{kind:'text',data:{expression}}}}};}}"
    )
}
fn cases() -> Vec<Case> {
    let replace = "input.body.data.replaceAll('-', '_')";
    let mut cases = vec![
        Case { id: "empty", source: body("input.body.data"), input: Input::Small(b""), kind: "text", selection: "plan" },
        Case { id: "renamed-local", source: "function rewrite(input){const renamedPayload=input.body.data;const independentlyNamed=renamedPayload.replaceAll('-', '_');return {type:'modify',body:{kind:'text',data:independentlyNamed}};}".into(), input: Input::Small(b"p-q--$\0"), kind: "text", selection: "plan" },
        Case { id: "first-only", source: body("input.body.data.replace('-', '_')"), input: Input::Small(b"---$\0"), kind: "text", selection: "plan" },
        Case { id: "nested-replace", source: body("input.body.data.replaceAll('-', '_').replace('_', '+')"), input: Input::Small(b"---x"), kind: "text", selection: "plan" },
        Case { id: "literal-nul-dollar", source: body(r"'Q\u0000$-'.replace('-', '_')"), input: Input::Small(b"ignored"), kind: "text", selection: "plan" },
        Case { id: "nul-search", source: body(r"input.body.data.replaceAll('\u0000', '!')"), input: Input::Small(b"a\0-\0$"), kind: "text", selection: "plan" },
        Case { id: "dollar-search", source: body("input.body.data.replaceAll('$', '#')"), input: Input::Small(b"$-$\0"), kind: "text", selection: "plan" },
        Case { id: "static-headers", source: r#"function rewrite(input){return {headers:[{op:'set',name:'X-Trace',values:['a\t\"b']},{op:'add',name:'X-Trace',values:['']},{op:'remove',name:'X-Old'}],body:{data:input.body.data.replaceAll('-', '_'),kind:'text'},type:'modify'};}"#.into(), input: Input::Small(b"--\0"), kind: "text", selection: "plan" },
        Case { id: "ascii-4095", source: body(replace), input: Input::Repeat(b'-', 4095), kind: "text", selection: "plan" },
        Case { id: "ascii-4096", source: body(replace), input: Input::Repeat(b'-', 4096), kind: "text", selection: "plan" },
        Case { id: "ascii-64k", source: body(replace), input: Input::Repeat(b'-', 65536), kind: "text", selection: "plan" },
        Case { id: "ascii-no-match-64k", source: body(replace), input: Input::Repeat(b'x', 65536), kind: "text", selection: "plan" },
        Case { id: "unicode-input", source: body(replace), input: Input::Small("é-😀\0$".as_bytes()), kind: "text", selection: "plan" },
        Case { id: "unicode-literal", source: body("input.body.data.replaceAll('é', 'e')"), input: Input::Small("é-é".as_bytes()), kind: "text", selection: "ast-fallback" },
        Case { id: "dollar-replacement", source: body("input.body.data.replaceAll('-', '$')"), input: Input::Small(b"x--"), kind: "text", selection: "ast-fallback" },
        Case { id: "template-match", source: body("input.body.data.replaceAll('-', '$&')"), input: Input::Small(b"x--"), kind: "text", selection: "ast-fallback" },
        Case { id: "empty-search", source: body("input.body.data.replaceAll('', 'x')"), input: Input::Small(b"q"), kind: "text", selection: "ast-fallback" },
        Case { id: "unknown-loop", source: "function rewrite(input){let found=false;for(let i=0;i<input.response.headers.length;i++){if(input.response.headers[i].name==='X-Unused'){found=true;}}if(!found){return {type:'abort'};}return {type:'modify',body:{kind:'text',data:input.body.data}};}".into(), input: Input::Small(b"loop-body"), kind: "text", selection: "input-fallback" },
        Case { id: "bytes-input", source: body("input.body.data"), input: Input::Small(b"abc\0"), kind: "bytes", selection: "input-fallback" },
        Case { id: "none-to-text", source: body("'constant'"), input: Input::None, kind: "none", selection: "input-fallback" },
    ];
    for (id, count) in [("unused-work-15", 15), ("unused-work-limit-16", 16)] {
        let declarations = (0..count)
            .map(|i| format!("const unused{i}=input.body.data.replaceAll('-', '_');"))
            .collect::<String>();
        cases.push(Case { id, source: format!("function rewrite(input){{{declarations}return {{type:'modify',body:{{kind:'text',data:input.body.data}}}};}}"), input: Input::Repeat(b'-', 65536), kind: "text", selection: "plan" });
    }
    cases
}
fn extra_semantic_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (id, length) in [
        ("identity-1", 1),
        ("identity-255", 255),
        ("identity-256", 256),
        ("identity-max", 262144),
    ] {
        cases.push(Case {
            id,
            source: body("input.body.data"),
            input: Input::Repeat(b'Q', length),
            kind: "text",
            selection: "plan",
        });
    }
    cases.push(Case {
        id: "identical-replacement",
        source: body("input.body.data.replaceAll('a', 'a')"),
        input: Input::Small(b"aa-a\0$"),
        kind: "text",
        selection: "plan",
    });
    cases.push(Case {
        id: "del-search-and-replacement",
        source: body(r"input.body.data.replaceAll('\u007f', '!').replace('!', '\u007f')"),
        input: Input::Small(b"a\x7fb\x7f"),
        kind: "text",
        selection: "plan",
    });
    // The value is 4097 ASCII code units. Header validation uses the unquoted
    // shortcut; metadata Measure must still run 17 quoted-string tick points.
    let mut long_value = "q".repeat(4094);
    long_value.push_str("\t\\\"");
    let long_value = serde_json::to_string(&long_value).unwrap();
    let allowed = serde_json::to_string("\t !~\"\\").unwrap();
    cases.push(Case {
        id: "quoted-long-header-order-and-values",
        source: format!(
            "function rewrite(input){{return {{body:{{data:input.body.data,kind:'text'}},headers:[{{values:[{long_value}],name:'X-Quoted',op:'set'}},{{name:'X-Order',values:['',{allowed}],op:'add'}},{{name:'X-Old',op:'remove'}}],type:'modify'}};}}"
        ),
        input: Input::Small(b"x\0"),
        kind: "text",
        selection: "plan",
    });
    cases.push(Case {
        id: "duplicate-body-key-ast-fallback",
        source: "function rewrite(input){return {type:'modify',body:{kind:'text',data:'discarded',data:input.body.data}};}".into(),
        input: Input::Small(b"last-key-wins"),
        kind: "text",
        selection: "ast-fallback",
    });
    cases.push(Case {
        id: "let-assignment-ast-fallback",
        source: "function rewrite(input){let named=input.body.data;named='changed';return {type:'modify',body:{kind:'text',data:named}};}".into(),
        input: Input::Small(b"original"),
        kind: "text",
        selection: "ast-fallback",
    });
    cases
}

fn materialization_cases() -> Vec<Case> {
    let input = b"aabbcc--za\0$";
    let mut cases = vec![
        Case { id:"writer-transitive", source:body("input.body.data.replaceAll('a','b').replaceAll('b','c')"), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-reversed", source:body("input.body.data.replaceAll('b','c').replaceAll('a','b')"), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-cycle", source:body("input.body.data.replaceAll('a','b').replaceAll('b','a')"), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-alias-branch", source:"function rewrite(input){const original=input.body.data;const unused=original.replaceAll('z','q');const chosen=original.replaceAll('a','b');const other=chosen.replaceAll('c','z');return {type:'modify',body:{kind:'text',data:chosen.replaceAll('b','c')}};}".into(), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-renamed-local", source:"function rewrite(input){const renamed=input.body.data;const independentlyNamed=renamed.replaceAll('a','b');return {body:{data:independentlyNamed.replaceAll('b','c'),kind:'text'},headers:[{values:['static'],op:'set',name:'X-Proof'}],type:'modify'};}".into(), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-literal-base", source:body(r"'a-\u0000aa$'.replaceAll('a','b').replaceAll('b','c')"), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-unused-first", source:"function rewrite(input){const ignored=input.body.data.replace('a','z');return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b').replaceAll('b','c')}};}".into(), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-first-ancestor", source:body("input.body.data.replace('a','b').replaceAll('b','c')"), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-all-first-all", source:body("input.body.data.replaceAll('a','b').replace('b','c').replaceAll('c','d')"), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-ascii-alphabet", source:body(r"input.body.data.replaceAll('\u0000','\u007f').replaceAll('\u007f','!')"), input:Input::Alphabet, kind:"text", selection:"plan" },
        Case { id:"writer-no-match", source:body("input.body.data.replaceAll('x','y').replaceAll('y','z')"), input:Input::Small(input), kind:"text", selection:"plan" },
        Case { id:"writer-equal-byte", source:body("input.body.data.replaceAll('a','a').replaceAll('b','b')"), input:Input::Small(input), kind:"text", selection:"plan" },
    ];
    for (id, length) in [
        ("writer-chunk-0", 0),
        ("writer-chunk-1", 1),
        ("writer-chunk-255", 255),
        ("writer-chunk-256", 256),
        ("writer-chunk-257", 257),
        ("writer-chunk-64k", 65536),
    ] {
        cases.push(Case {
            id,
            source: body("input.body.data.replaceAll('a','b').replaceAll('b','c')"),
            input: Input::Repeat(b'a', length),
            kind: "text",
            selection: "plan",
        });
    }
    for (id, count) in [
        ("writer-unused-literal-15", 15),
        ("writer-unused-literal-16", 16),
    ] {
        let declarations = (0..count)
            .map(|i| format!("const unused{i}=input.body.data.replaceAll('a','b');"))
            .collect::<String>();
        cases.push(Case { id, source:format!("function rewrite(input){{{declarations}return {{type:'modify',body:{{kind:'text',data:'constant\\u0000$'}}}};}}"), input:Input::Repeat(b'a',65536), kind:"text", selection:"plan" });
    }
    cases
}

fn single_step_cases() -> Vec<Case> {
    vec![
        Case {
            id: "single-empty",
            source: body("input.body.data.replaceAll('a','z')"),
            input: Input::Small(b""),
            kind: "text",
            selection: "plan",
        },
        Case {
            id: "single-ascii-nul-del",
            source: body(r"input.body.data.replaceAll('\u0000','\u007f')"),
            input: Input::Alphabet,
            kind: "text",
            selection: "plan",
        },
        Case {
            id: "single-cross-chunk-tail",
            source: body("input.body.data.replaceAll('a','z')"),
            input: Input::Repeat(b'a', 257),
            kind: "text",
            selection: "plan",
        },
        Case {
            id: "single-literal-source",
            source: body(r"'a\u0000-\u007fa'.replaceAll('a','z')"),
            input: Input::Small(b"ignored"),
            kind: "text",
            selection: "plan",
        },
    ]
}

struct GuardCase {
    case: Case,
    metadata: Value,
    canary: Option<(usize, usize, &'static str)>,
}
fn guarded_source(
    path: &str,
    flag: &str,
    index: &str,
    predicate: &str,
    early: &str,
    prefix: bool,
) -> String {
    let update = if prefix {
        format!("++{index}")
    } else {
        format!("{index}++")
    };
    format!(
        "function rewrite(input){{let {flag}=false;for(let {index}=0;{index}<input.{path}.headers.length;{update}){{if({predicate}){{{flag}=true;}}}}if(!{flag}){{return {{type:'{early}'}};}}const mappedBody=input.body.data.replaceAll('-', '_');return {{type:'modify',body:{{kind:'text',data:mappedBody}}}};}}"
    )
}
fn guard_metadata(path: &str, rows: Value) -> Value {
    let mut metadata = json!({"body":{"kind":"text"}});
    metadata[path] = json!({"headers":rows});
    metadata
}
fn guard_case(
    id: &'static str,
    source: String,
    metadata: Value,
    selection: &'static str,
    canary: Option<(usize, usize, &'static str)>,
) -> GuardCase {
    GuardCase {
        case: Case {
            id,
            source,
            input: Input::Small(b"--source"),
            kind: "text",
            selection,
        },
        metadata,
        canary,
    }
}
fn guard_cases() -> Vec<GuardCase> {
    let name = "input.response.headers[row].name === 'x-probe'";
    let value = "input.response.headers[row].value === 'ok'";
    let source = |predicate: &str, early: &str| {
        guarded_source("response", "seen", "row", predicate, early, false)
    };
    let rows = |value: Value| guard_metadata("response", value);
    let matched = rows(json!([{"name":"x-probe","value":"ok"}]));
    let other = rows(json!([{"name":"x-other","value":"no"}]));
    let empty = rows(json!([]));
    let mut cases = vec![
        guard_case(
            "guard-empty-pass",
            source(name, "pass"),
            empty.clone(),
            "plan",
            Some((14, 142, "pass")),
        ),
        guard_case(
            "guard-empty-abort",
            source(name, "abort"),
            empty,
            "plan",
            Some((14, 144, "abort")),
        ),
        guard_case(
            "guard-one-false-pass",
            source(name, "pass"),
            other.clone(),
            "plan",
            Some((34, 158, "pass")),
        ),
        guard_case(
            "guard-and-short-false",
            source(&format!("{name} && {value}"), "pass"),
            other.clone(),
            "plan",
            Some((34, 158, "pass")),
        ),
        guard_case(
            "guard-and-second-false",
            source(&format!("{name} && {value}"), "pass"),
            rows(json!([{"name":"x-probe","value":"no"}])),
            "plan",
            Some((42, 158, "pass")),
        ),
        guard_case(
            "guard-or-all-false",
            source(&format!("{name} || {value}"), "abort"),
            other.clone(),
            "plan",
            Some((42, 160, "abort")),
        ),
        guard_case(
            "guard-not-equal-literal-left",
            source("'x-other' !== input.response.headers[row].name", "pass"),
            matched.clone(),
            "plan",
            None,
        ),
        guard_case(
            "guard-unicode-value",
            source("input.response.headers[row].value === 'café😀'", "pass"),
            rows(json!([{"name":"x-probe","value":"café😀"}])),
            "plan",
            None,
        ),
        guard_case(
            "guard-name-case-sensitive",
            source("input.response.headers[row].name === 'X-Probe'", "pass"),
            matched.clone(),
            "plan",
            Some((34, 158, "pass")),
        ),
        guard_case(
            "guard-duplicates-empty-values",
            source(&format!("{name} && {value}"), "pass"),
            rows(json!([{"name":"x-probe","value":""},{"name":"x-probe","value":"ok"}])),
            "plan",
            None,
        ),
        guard_case(
            "guard-empty-value-match",
            source("input.response.headers[row].value === ''", "pass"),
            rows(json!([{"name":"x-probe","value":""}])),
            "plan",
            None,
        ),
        guard_case(
            "guard-nul-quoted-value",
            source(
                &format!(
                    "input.response.headers[row].value === {}",
                    serde_json::to_string("a\0\"\\b").unwrap()
                ),
                "pass",
            ),
            rows(json!([{"name":"x-probe","value":"a\0\"\\b"}])),
            "plan",
            None,
        ),
        guard_case(
            "guard-prefix-increment",
            guarded_source(
                "response",
                "differentFlag",
                "cursor",
                "input.response.headers[cursor].name === 'x-probe'",
                "pass",
                true,
            ),
            matched.clone(),
            "plan",
            None,
        ),
        guard_case(
            "guard-request-path",
            guarded_source(
                "request",
                "ready",
                "position",
                "input.request.headers[position].value === 'ok'",
                "abort",
                false,
            ),
            guard_metadata("request", json!([{"name":"x-probe","value":"ok"}])),
            "plan",
            None,
        ),
        guard_case(
            "guard-missing-response",
            source(name, "pass"),
            json!({"body":{"kind":"text"}}),
            "input-fallback",
            None,
        ),
        guard_case(
            "guard-nonarray-headers",
            source(name, "pass"),
            rows(json!({"length":0})),
            "input-fallback",
            None,
        ),
        guard_case(
            "guard-shortcircuited-missing-value",
            source(&format!("{name} || {value}"), "pass"),
            rows(json!([{"name":"x-probe"}])),
            "input-fallback",
            None,
        ),
        guard_case(
            "guard-extra-row-field",
            source(name, "pass"),
            rows(json!([{"name":"x-probe","value":"ok","extra":true}])),
            "input-fallback",
            None,
        ),
        guard_case(
            "guard-string-row",
            source(name, "pass"),
            rows(json!(["primitive"])),
            "input-fallback",
            None,
        ),
        guard_case(
            "guard-row-count-bound",
            source(name, "pass"),
            rows(Value::Array(
                (0..101)
                    .map(|_| json!({"name":"x-other","value":"no"}))
                    .collect(),
            )),
            "input-fallback",
            None,
        ),
        guard_case(
            "guard-row-byte-bound",
            source(name, "pass"),
            rows(json!([{"name":"x-probe","value":"x".repeat(32768)}])),
            "input-fallback",
            None,
        ),
        guard_case(
            "guard-unknown-while",
            source(name, "pass").replace("let seen=false;", "let seen=false;while(false){}"),
            matched.clone(),
            "ast-fallback",
            None,
        ),
        guard_case(
            "guard-flag-write-false",
            source(name, "pass").replace("seen=true;", "seen=false;"),
            matched.clone(),
            "ast-fallback",
            None,
        ),
        guard_case(
            "guard-extra-break",
            source(name, "pass").replace("seen=true;", "seen=true;break;"),
            matched.clone(),
            "ast-fallback",
            None,
        ),
        guard_case(
            "guard-alternate-update",
            source(name, "pass").replace("row++", "row+=1"),
            matched.clone(),
            "ast-fallback",
            None,
        ),
        guard_case(
            "guard-wrong-index",
            source("input.response.headers[0].name === 'x-probe'", "pass"),
            matched.clone(),
            "ast-fallback",
            None,
        ),
        guard_case(
            "guard-unused-flag-alias",
            source(name, "pass").replace(
                "const mappedBody=",
                "const unusedAlias=seen;const mappedBody=",
            ),
            matched.clone(),
            "ast-fallback",
            None,
        ),
    ];
    for (id, predicate, metadata, canary) in [
        (
            "guard-one-true-64k",
            name.to_owned(),
            matched.clone(),
            Some((52, 131488, "modify")),
        ),
        (
            "guard-or-short-true",
            format!("{name} || {value}"),
            matched.clone(),
            Some((52, 131488, "modify")),
        ),
        (
            "guard-or-second-true",
            format!("{name} || {value}"),
            rows(json!([{"name":"x-other","value":"ok"}])),
            Some((60, 131488, "modify")),
        ),
        (
            "guard-and-both-true",
            format!("{name} && {value}"),
            matched.clone(),
            Some((60, 131488, "modify")),
        ),
        (
            "guard-found-first-reads-all",
            name.to_owned(),
            rows(
                json!([{"name":"x-probe","value":"ok"},{"name":"x-other","value":"later"},{"name":"x-last","value":"later"}]),
            ),
            Some((92, 131520, "modify")),
        ),
        (
            "guard-found-last-reads-all",
            name.to_owned(),
            rows(
                json!([{"name":"x-other","value":"first"},{"name":"x-next","value":"middle"},{"name":"x-probe","value":"ok"}]),
            ),
            Some((92, 131520, "modify")),
        ),
    ] {
        let mut case = guard_case(id, source(&predicate, "pass"), metadata, "plan", canary);
        case.case.input = Input::Repeat(b'-', 65536);
        cases.push(case);
    }
    cases.push(guard_case(
        "guard-static-header-tail",
        source(name, "pass").replace(
            "return {type:'modify',body:",
            "return {headers:[{op:'set',name:'X-Proof',values:['static']}],type:'modify',body:",
        ),
        matched.clone(),
        "plan",
        None,
    ));
    for (id, count, canary) in [
        ("guard-unused-quota-15", 15, (210, 1966944, "modify")),
        (
            "guard-unused-quota-16",
            16,
            (204, 1966576, "error:InvalidData"),
        ),
    ] {
        let declarations = (0..count)
            .map(|i| format!("const unused{i}=input.body.data.replaceAll('-', '_');"))
            .collect::<String>();
        let final_tail = format!(
            "{declarations}return {{type:'modify',body:{{kind:'text',data:input.body.data}}}};"
        );
        let mut case=guard_case(id,source(name,"pass").replace("const mappedBody=input.body.data.replaceAll('-', '_');return {type:'modify',body:{kind:'text',data:mappedBody}};",&final_tail),matched.clone(),"plan",Some(canary));
        case.case.input = Input::Repeat(b'-', 65536);
        cases.push(case);
    }
    cases
}
fn compare_guard(case: &GuardCase, budget: &Budget) -> io::Result<Value> {
    let mut row = compare_metadata(&case.case, budget, Some(&case.metadata))?;
    let canary = case.canary.is_none_or(|(ticks, work, kind)| {
        let result = if let Some(error) = kind.strip_prefix("error:") {
            row["baseline"]["errorKind"] == error
        } else {
            row["baseline"]["resultType"] == kind
        };
        row["baseline"]["ticks"] == ticks && row["baseline"]["allocationWork"] == work && result
    });
    let early_empty = if matches!(
        row["candidate"]["resultType"].as_str(),
        Some("pass" | "abort")
    ) {
        row["candidate"]["outputBytes"] == 0
    } else {
        true
    };
    row["guardCanaryMet"] = json!(canary);
    row["earlyOutputEmpty"] = json!(early_empty);
    if !canary || !early_empty {
        row["passed"] = json!(false);
    }
    Ok(row)
}

fn output(budget: &Budget, bound: usize, body: bool) -> io::Result<BudgetedBytes> {
    if !body {
        return Ok(BudgetedBytes::empty(budget));
    }
    BudgetedBytes::new(
        budget,
        output_capacity(bound).ok_or(io::ErrorKind::FileTooLarge)?,
    )
    .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
}
fn fixture(budget: &Budget, input: &Input) -> io::Result<Option<BudgetedBytes>> {
    match input {
        Input::None => Ok(None),
        Input::Small(bytes) => BudgetedBytes::copy(budget, bytes)
            .map(Some)
            .ok_or_else(|| io::ErrorKind::OutOfMemory.into()),
        Input::Alphabet => {
            let mut value = BudgetedBytes::new(budget, 128).ok_or(io::ErrorKind::OutOfMemory)?;
            value.write_initialized_output(128, |bytes| {
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = index as u8;
                }
                Ok(128)
            })?;
            Ok(Some(value))
        }
        Input::Repeat(byte, length) => {
            let mut value =
                BudgetedBytes::new(budget, *length).ok_or(io::ErrorKind::OutOfMemory)?;
            value.write_initialized_output(*length, |bytes| {
                bytes.fill(*byte);
                Ok(*length)
            })?;
            Ok(Some(value))
        }
    }
}
fn run_jsc(
    program: &CompiledSource,
    metadata: &Value,
    input: Option<&BudgetedBytes>,
    output: &mut BudgetedBytes,
    budget: &Budget,
) -> io::Result<Observation> {
    // This guard stays live through ContextRelease and the actual scoped join.
    let bridge = input
        .map(|input| {
            let plan = BridgePlan::new(
                input.as_ref().len(),
                metadata["body"]["kind"] == "text",
                program.maximum_output_bytes(input.as_ref().len()),
            )
            .ok_or(io::ErrorKind::InvalidInput)?;
            budget
                .reserve(plan.cost().ok_or(io::ErrorKind::OutOfMemory)?)
                .ok_or(io::ErrorKind::OutOfMemory)
        })
        .transpose()?;
    let cancellation = CancellationToken::new();
    let deadline = Instant::now() + INVOCATION_LIMIT;
    let (result, trace) = super::run_on_scoped_thread(|| {
        Ok(apple::evaluate_for_validation(
            program,
            metadata,
            input.map(AsRef::as_ref),
            output,
            bridge.as_ref(),
            &cancellation,
            deadline,
        ))
    })?;
    // Reaching here proves the owner/TLS really joined, independently of ctx.
    let ticks = trace.ticks;
    let work = trace.allocation_work;
    Ok(Observation {
        result,
        ticks,
        work,
        backend: "javascriptcore",
        trace: serde_json::to_value(trace).map_err(io::Error::other)?,
    })
}
fn outcome(observation: &Observation, bytes: usize) -> Value {
    json!({"backend": observation.backend, "succeeded": observation.result.is_ok(),
        "errorKind": observation.result.as_ref().err().map(|error| format!("{:?}", error.kind())),
        "ticks": observation.ticks, "allocationWork": observation.work, "outputBytes": bytes,
        "ownerJoined": true, "resultType":observation.result.as_ref().ok().and_then(|v|v["type"].as_str()), "trace": observation.trace})
}
fn compare(case: &Case, budget: &Budget) -> io::Result<Value> {
    compare_metadata(case, budget, None)
}
fn compare_metadata(
    case: &Case,
    budget: &Budget,
    metadata_override: Option<&Value>,
) -> io::Result<Value> {
    let program = super::validate_source(&case.source)?;
    let plan = static_literal_plan::compile(&case.source);
    let input = fixture(budget, &case.input)?;
    let length = input.as_ref().map_or(0, |input| input.as_ref().len());
    let default_metadata = json!({"body":{"kind":case.kind}, "response":{"status":200,"headers":[{"name":"X-Unused","values":["fixture"]}]}});
    let metadata = metadata_override.unwrap_or(&default_metadata);
    let mut baseline_output = output(
        budget,
        program.maximum_output_bytes(length),
        input.is_some(),
    )?;
    let baseline = run_jsc(
        &program,
        metadata,
        input.as_ref(),
        &mut baseline_output,
        budget,
    )?;
    let bound = plan
        .as_ref()
        .and_then(|plan| plan.maximum_output_bytes(length))
        .unwrap_or_else(|| program.maximum_output_bytes(length));
    let mut candidate_output = output(budget, bound, input.is_some())?;
    // No JSC bridge is created or retained for a selected Plan invocation.
    let attempted = if let Some(plan) = &plan {
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + INVOCATION_LIMIT;
        super::run_on_script_thread(super::OwnerBackend::Plan, || {
            Ok(plan.try_execute(
                metadata,
                input.as_ref().map(BudgetedBytes::borrowed_body),
                &mut candidate_output,
                &cancellation,
                deadline,
            ))
        })?
    } else {
        None
    };
    let (selection, actual) = if let Some(attempt) = attempted {
        // Some(Err), including selected t=0 OOM, never reruns JavaScriptCore.
        (
            "plan",
            Observation {
                result: attempt.result,
                ticks: Some(attempt.ticks),
                work: Some(attempt.allocation_work),
                backend: attempt.backend,
                trace: json!({"kind":"plan-counters","contextCreated":false}),
            },
        )
    } else {
        let selection = if plan.is_some() {
            "input-fallback"
        } else {
            "ast-fallback"
        };
        (
            selection,
            run_jsc(
                &program,
                metadata,
                input.as_ref(),
                &mut candidate_output,
                budget,
            )?,
        )
    };

    // A third independently paid output runs the untouched DAG materializer.
    // The JSC bridge/owner has already really ended in run_jsc above.
    let dag_reference = if selection == "plan" {
        let plan = plan.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        let mut dag_output = BudgetedBytes::new(budget, bound).ok_or(io::ErrorKind::OutOfMemory)?;
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + INVOCATION_LIMIT;
        let attempt = super::run_on_script_thread(super::OwnerBackend::Plan, || {
            plan.try_execute_for_validation(
                metadata,
                input.as_ref().map(BudgetedBytes::borrowed_body),
                &mut dag_output,
                &cancellation,
                deadline,
                static_literal_plan::Validation {
                    force_dag: true,
                    after_chunk: None,
                },
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        })?;
        Some((
            Observation {
                result: attempt.result,
                ticks: Some(attempt.ticks),
                work: Some(attempt.allocation_work),
                backend: attempt.backend,
                trace: json!({"kind":"original-dag-reference","contextCreated":false}),
            },
            dag_output,
        ))
    } else {
        None
    };
    let dag_equal = dag_reference.as_ref().map(|(reference, bytes)| {
        let result_equal = match (&reference.result, &actual.result) {
            (Ok(a), Ok(b)) => a == b,
            (Err(a), Err(b)) => a.kind() == b.kind(),
            _ => false,
        };
        result_equal
            && reference.ticks == actual.ticks
            && reference.work == actual.work
            && bytes.as_ref() == candidate_output.as_ref()
    });
    let materializer = plan
        .as_ref()
        .filter(|_| selection == "plan")
        .map(|p| p.materializer_kind());
    let expected_materializer = if selection == "plan" {
        Some(match case.id {
            "first-only"
            | "nested-replace"
            | "literal-nul-dollar"
            | "del-search-and-replacement"
            | "writer-first-ancestor"
            | "writer-all-first-all" => "dag",
            _ => "recipe",
        })
    } else {
        None
    };
    let materializer_expected = materializer == expected_materializer;

    let result_equal = match (&baseline.result, &actual.result) {
        (Ok(a), Ok(b)) => a == b,
        (Err(a), Err(b)) => a.kind() == b.kind(),
        _ => false,
    };
    let bytes_equal = baseline_output.as_ref() == candidate_output.as_ref();
    let ticks_equal = baseline.ticks.is_some() && baseline.ticks == actual.ticks;
    let work_equal = baseline.work.is_some() && baseline.work == actual.work;
    let trace_complete = baseline.trace["contextReleased"] == true
        && baseline.trace["preludeLoaded"] == true
        && (selection == "plan"
            || (actual.trace["contextReleased"] == true && actual.trace["preludeLoaded"] == true));
    // Independent fixed boundary canaries prevent two unavailable/incorrect
    // observations from being mistaken for a successful differential.
    let boundary_expected = match case.id {
        "ascii-64k" => {
            baseline.result.is_ok() && baseline.ticks == Some(25) && baseline.work == Some(131472)
        }
        "unused-work-limit-16" => {
            baseline
                .result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
                && baseline.work == Some(1966560)
        }
        _ => true,
    };
    let passed = boundary_expected
        && selection == case.selection
        && result_equal
        && bytes_equal
        && ticks_equal
        && work_equal
        && trace_complete
        && dag_equal != Some(false)
        && materializer_expected;
    Ok(
        json!({"id":case.id,"passed":passed,"inputBytes":length,"planCompiled":plan.is_some(),
        "expectedSelection":case.selection,"selection":selection,"resultEqual":result_equal,"compiledHeaderGuard":plan.as_ref().is_some_and(|p|p.has_header_guard()),
        "bytesEqual":bytes_equal,"ticksEqual":ticks_equal,"allocationWorkEqual":work_equal,"traceComplete":trace_complete,"boundaryExpected":boundary_expected,
        "compiledFinalMaterializer":materializer,"expectedCompiledFinalMaterializer":expected_materializer,"materializerExpected":materializer_expected,"originalDagEqual":dag_equal,
        "dagReference":dag_reference.as_ref().map(|(o,b)|outcome(o,b.as_ref().len())),
        "baseline":outcome(&baseline,baseline_output.as_ref().len()),"candidate":outcome(&actual,candidate_output.as_ref().len())}),
    )
}
// Operational ownership/transaction checks are separate from the real JSC
// semantic differential: Rust Plan owns no fictional JSC bridge copies.
const OPERATIONAL_IDS: [&str; 7] = [
    "typed-foreign-ledger",
    "selected-state-oom",
    "selected-expired",
    "selected-cancelled-expired",
    "last-owner-refund",
    "invalid-metadata",
    "message-atomic-rollback",
];
fn operational(id: &str, budget: &Budget) -> io::Result<Value> {
    let source = body("input.body.data.replaceAll('-', '_')");
    let plan = static_literal_plan::compile(&source).ok_or(io::ErrorKind::InvalidData)?;
    let input = BudgetedBytes::copy(budget, b"---source").ok_or(io::ErrorKind::OutOfMemory)?;
    let metadata = json!({"body":{"kind":"text"}});
    let mut target =
        BudgetedBytes::new(budget, input.as_ref().len()).ok_or(io::ErrorKind::OutOfMemory)?;
    let cancellation = CancellationToken::new();
    let invoke = |target: &mut BudgetedBytes, metadata: &Value, deadline| {
        super::run_on_script_thread(super::OwnerBackend::Plan, || {
            plan.try_execute(
                metadata,
                Some(input.borrowed_body()),
                target,
                &cancellation,
                deadline,
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        })
    };
    let healthy = || Instant::now() + INVOCATION_LIMIT;
    let mut flags = json!({"scope":"direct typed Plan or Message operational check; not a second execution lane"});
    let passed = match id {
        "typed-foreign-ledger" => {
            let other = Budget::default();
            let mut foreign = BudgetedBytes::new(&other, input.as_ref().len())
                .ok_or(io::ErrorKind::OutOfMemory)?;
            let attempt = invoke(&mut foreign, &metadata, healthy())?;
            let passed = attempt
                .result
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::InvalidInput)
                && attempt.ticks == 0
                && attempt.allocation_work == 0
                && foreign.as_ref().is_empty();
            drop(foreign);
            passed && other.reserve(WORKSPACE).is_some()
        }
        "selected-state-oom" => {
            let charged = BudgetedBytes::allocation_cost(input.as_ref().len())
                .ok_or(io::ErrorKind::OutOfMemory)?
                .checked_mul(2)
                .ok_or(io::ErrorKind::OutOfMemory)?;
            let blocker = budget
                .reserve(WORKSPACE - charged)
                .ok_or(io::ErrorKind::OutOfMemory)?;
            let attempt = invoke(&mut target, &metadata, healthy())?;
            let passed = attempt
                .result
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory)
                && attempt.ticks == 0
                && attempt.allocation_work == 0
                && target.as_ref().is_empty();
            drop(blocker);
            passed
        }
        "selected-expired" | "selected-cancelled-expired" => {
            if id == "selected-cancelled-expired" {
                cancellation.cancel();
            }
            let attempt = invoke(
                &mut target,
                &metadata,
                Instant::now() - Duration::from_millis(1),
            )?;
            let expected = if cancellation.is_cancelled() {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::TimedOut
            };
            attempt.result.as_ref().is_err_and(|e| e.kind() == expected)
                && attempt.ticks == 0
                && attempt.allocation_work == 0
                && target.as_ref().is_empty()
        }
        "last-owner-refund" => {
            drop((input, target));
            let entity = Entity::identity(
                BudgetedBytes::copy(budget, b"---source").ok_or(io::ErrorKind::OutOfMemory)?,
            );
            let old = entity.wire().clone();
            let old_slice = old.slice(0..1);
            let mut output =
                BudgetedBytes::new(budget, old.len()).ok_or(io::ErrorKind::OutOfMemory)?;
            let attempt = super::run_on_script_thread(super::OwnerBackend::Plan, || {
                plan.try_execute(
                    &metadata,
                    entity.borrowed_body(),
                    &mut output,
                    &cancellation,
                    healthy(),
                )
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
            })?;
            let correct = attempt.result.is_ok() && output.as_ref() == b"___source";
            drop(entity);
            let output_cost =
                BudgetedBytes::allocation_cost(old.len()).ok_or(io::ErrorKind::OutOfMemory)?;
            let source_held = budget.reserve(WORKSPACE - output_cost).is_none();
            drop(old);
            let source_slice_held = budget.reserve(WORKSPACE - output_cost).is_none();
            drop(old_slice);
            let source_refunded = budget.reserve(WORKSPACE - output_cost).is_some();
            let sent = output.into_bytes();
            let sent_slice = sent.slice(0..1);
            drop(sent);
            let output_slice_held = budget.reserve(WORKSPACE).is_none()
                && budget.reserve(WORKSPACE - output_cost).is_some();
            drop(sent_slice);
            flags["ownerJoined"] = json!(true);
            flags["sourceRefundedAfterLastSlice"] = json!(source_refunded);
            flags["lastSourceSliceHeldPermit"] = json!(source_slice_held);
            flags["lastOutputSliceHeldPermit"] = json!(output_slice_held);
            return Ok(
                json!({"id":id,"kind":"operational","passed":correct && source_held && source_slice_held && source_refunded && output_slice_held && budget.reserve(WORKSPACE).is_some(),"checks":flags}),
            );
        }
        "invalid-metadata" => {
            let oversized = json!({"body":{"kind":"text"},"padding":"x".repeat(1024 * 1024)});
            let attempt = invoke(&mut target, &oversized, healthy())?;
            let compiled = super::validate_source(&source)?;
            let baseline = run_jsc(&compiled, &oversized, Some(&input), &mut target, budget)?;
            attempt
                .result
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::InvalidData)
                && baseline
                    .result
                    .as_ref()
                    .is_err_and(|e| e.kind() == io::ErrorKind::InvalidData)
                && attempt.ticks == 0
                && attempt.allocation_work == 0
                && target.as_ref().is_empty()
        }
        "message-atomic-rollback" => {
            drop((input, target));
            let url =
                url::Url::parse("https://fixture.invalid/original").map_err(io::Error::other)?;
            let entity = Entity::identity(
                BudgetedBytes::copy(budget, b"before").ok_or(io::ErrorKind::OutOfMemory)?,
            );
            let mut message = Message::request(
                OriginalSnapshot {
                    url: url.clone(),
                    method: "POST".into(),
                    identity_allowed: true,
                    asterisk: false,
                },
                RequestSnapshot {
                    url: url.clone(),
                    method: "POST".into(),
                    headers: vec![("authorization".into(), "fixture".into())],
                },
                Some(entity),
                &vec![],
                false,
            );
            let headers = message.request.headers.clone();
            let old_owner = message
                .body
                .as_ref()
                .ok_or(io::ErrorKind::InvalidData)?
                .wire()
                .clone();
            let other = Budget::default();
            let foreign =
                BudgetedBytes::copy(&other, b"after").ok_or(io::ErrorKind::OutOfMemory)?;
            let result: ScriptOutput = serde_json::from_value(json!({"type":"modify","url":"https://elsewhere.invalid/changed","method":"PUT","headers":[{"op":"set","name":"X-Changed","values":["yes"]}],"body":{"kind":"text"}})).map_err(io::Error::other)?;
            let rejected = message.apply(result, foreign, BodyMode::Text).is_err();
            let unchanged = message.request.url == url
                && message.request.method == "POST"
                && message.request.headers == headers
                && !message.crossed_origin
                && message.body.as_ref().is_some_and(|b| {
                    b.wire().as_ptr() == old_owner.as_ptr()
                        && b.logical() == Some(b"before".as_slice())
                });
            let invalid_header: ScriptOutput = serde_json::from_value(json!({"type":"modify","headers":[{"op":"set","name":"host","values":["rejected.invalid"]}],"body":{"kind":"text"}})).map_err(io::Error::other)?;
            let same = BudgetedBytes::copy(budget, b"after").ok_or(io::ErrorKind::OutOfMemory)?;
            let validation_rejected = message.apply(invalid_header, same, BodyMode::Text).is_err();
            let still_unchanged = message.request.headers == headers
                && message.request.url == url
                && message
                    .body
                    .as_ref()
                    .is_some_and(|b| b.wire().as_ptr() == old_owner.as_ptr());
            drop((message, old_owner));
            return Ok(
                json!({"id":id,"kind":"operational","passed":rejected && unchanged && validation_rejected && still_unchanged && other.reserve(WORKSPACE).is_some() && budget.reserve(WORKSPACE).is_some(),"checks":flags}),
            );
        }
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    drop((input, target));
    flags["ownerJoined"] = json!(true);
    Ok(json!({"id":id,"kind":"operational","passed":passed,"checks":flags}))
}

const MATERIALIZATION_OPERATIONAL_IDS: [&str; 6] = [
    "writer-cancel-after-first-chunk",
    "writer-expire-after-first-chunk",
    "writer-cancel-after-full-chunk",
    "writer-materialized-header-rollback",
    "single-writer-cancel-after-first-chunk",
    "single-writer-cancel-after-full-chunk",
];
fn materialization_operational(id: &str, budget: &Budget) -> io::Result<Value> {
    if id == "writer-materialized-header-rollback" {
        let source = "function rewrite(input){return {type:'modify',headers:[{op:'set',name:'X-Proof',values:['static']}],body:{kind:'text',data:input.body.data.replaceAll('-', '_')}};}";
        let plan = static_literal_plan::compile(source).ok_or(io::ErrorKind::InvalidData)?;
        let url = url::Url::parse("https://fixture.invalid/original").map_err(io::Error::other)?;
        let fields = vec![
            ("connection".into(), "x-proof".into()),
            ("authorization".into(), "fixture".into()),
        ];
        let entity = Entity::identity(
            BudgetedBytes::copy(budget, b"--source").ok_or(io::ErrorKind::OutOfMemory)?,
        );
        let mut message = Message::request(
            OriginalSnapshot {
                url: url.clone(),
                method: "POST".into(),
                identity_allowed: true,
                asterisk: false,
            },
            RequestSnapshot {
                url: url.clone(),
                method: "POST".into(),
                headers: fields.clone(),
            },
            Some(entity),
            &fields,
            true,
        );
        let before_headers = message.request.headers.clone();
        let before = message
            .body
            .as_ref()
            .ok_or(io::ErrorKind::InvalidData)?
            .wire()
            .clone();
        let mut output =
            BudgetedBytes::new(budget, before.len()).ok_or(io::ErrorKind::OutOfMemory)?;
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + INVOCATION_LIMIT;
        let attempt = super::run_on_script_thread(super::OwnerBackend::Plan, || {
            plan.try_execute(
                &json!({"body":{"kind":"text"}}),
                message.body.as_ref().and_then(Entity::borrowed_body),
                &mut output,
                &cancellation,
                deadline,
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        })?;
        let materialized = output.as_ref() == b"__source";
        let result: ScriptOutput =
            serde_json::from_value(attempt.result?).map_err(io::Error::other)?;
        let rejected = message
            .apply(result, output, BodyMode::Text)
            .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData);
        let unchanged = message.request.url == url
            && message.request.method == "POST"
            && message.request.headers == before_headers
            && message.crossed_origin
            && message.body.as_ref().is_some_and(|body| {
                body.wire().as_ptr() == before.as_ptr()
                    && body.logical() == Some(b"--source".as_slice())
            });
        drop((message, before));
        return Ok(
            json!({"id":id,"kind":"materialization-operational","passed":materialized && rejected && unchanged && budget.reserve(WORKSPACE).is_some(),
            "materializedAsExpected":materialized,"dynamicProtectedHeaderRejected":rejected,"transactionUnchanged":unchanged,"ownerJoined":true}),
        );
    }
    let length = if matches!(
        id,
        "writer-cancel-after-full-chunk" | "single-writer-cancel-after-full-chunk"
    ) {
        256
    } else {
        257
    };
    let input =
        fixture(budget, &Input::Repeat(b'a', length))?.ok_or(io::ErrorKind::InvalidInput)?;
    let expression = if id.starts_with("single-writer-") {
        "input.body.data.replaceAll('a','c')"
    } else {
        "input.body.data.replaceAll('a','b').replaceAll('b','c')"
    };
    let plan = static_literal_plan::compile(&body(expression)).ok_or(io::ErrorKind::InvalidData)?;
    let mut output = BudgetedBytes::new(budget, length).ok_or(io::ErrorKind::OutOfMemory)?;
    let cancellation = CancellationToken::new();
    let deadline = Instant::now() + INVOCATION_LIMIT;
    let mut completed_chunks = 0;
    let mut filled_bytes = 0;
    let attempt = {
        let mut hook = |filled| {
            completed_chunks += 1;
            filled_bytes = filled;
            if id == "writer-expire-after-first-chunk" {
                // Only a finite diagnostic synchronization hook waits. It does
                // not restart or extend the existing absolute100ms deadline.
                while Instant::now() < deadline {
                    std::thread::yield_now();
                }
            } else {
                cancellation.cancel();
            }
        };
        super::run_on_script_thread(super::OwnerBackend::Plan, || {
            plan.try_execute_for_validation(
                &json!({"body":{"kind":"text"}}),
                Some(input.borrowed_body()),
                &mut output,
                &cancellation,
                deadline,
                static_literal_plan::Validation {
                    force_dag: false,
                    after_chunk: Some(&mut hook),
                },
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        })?
    };
    let expected_error = if id == "writer-expire-after-first-chunk" {
        io::ErrorKind::TimedOut
    } else {
        io::ErrorKind::Interrupted
    };
    let error_matches = attempt
        .result
        .as_ref()
        .is_err_and(|error| error.kind() == expected_error);
    let output_expected = if length == 256 {
        output.as_ref().len() == 256 && output.as_ref().iter().all(|b| *b == b'c')
    } else {
        output.as_ref().is_empty()
    };
    let input_unchanged = input.as_ref().iter().all(|b| *b == b'a');
    let input_cost = BudgetedBytes::allocation_cost(length).ok_or(io::ErrorKind::OutOfMemory)?;
    let output_cost = input_cost;
    let output_still_paid = budget.reserve(WORKSPACE - input_cost).is_none();
    let state_refunded = budget
        .reserve(WORKSPACE - input_cost - output_cost)
        .is_some();
    drop((input, output));
    Ok(
        json!({"id":id,"kind":"materialization-operational","passed":error_matches && output_expected && input_unchanged && completed_chunks==1 && filled_bytes==256 && output_still_paid && state_refunded && budget.reserve(WORKSPACE).is_some(),
        "errorKind":attempt.result.as_ref().err().map(|error|format!("{:?}",error.kind())),"expectedErrorKind":format!("{:?}",expected_error),"errorMatches":error_matches,"completedChunks":completed_chunks,"filledBytesBeforeFailure":filled_bytes,
        "outputStateMatchesExistingErrorBoundary":output_expected,"sourceUnchanged":input_unchanged,"outputCapacityStillPaid":output_still_paid,"stateRefundedAfterRealJoin":state_refunded,
        "scope":"direct fill boundary; no Message commit is attempted on Err; no JSC replay","ownerJoined":true}),
    )
}

// Run only AFTER the outer diagnostic permit has actually been released.
// These exercise the unchanged production lane/CallBuffers/Message path;
// direct adapter comparisons above deliberately do not claim that coverage.
async fn production_case(
    id: &str,
    input: &[u8],
    expected: &[u8],
    selected_plan: bool,
) -> io::Result<Value> {
    let source = "function rewrite(input){const payload=input.body.data.replaceAll('-', '_');return {headers:[{op:'set',name:'X-Proof',values:['ok']}],type:'modify',body:{kind:'text',data:payload}};}";
    let policy = Policy::compile(&format!(
        "http-scripts:\n  enabled: true\n  scripts:\n    - name: diagnostic-transaction\n      phase: request\n      match: exact\n      url: https://fixture.invalid/original\n      body: text\n      source: {}\n",
        serde_json::to_string(source).map_err(io::Error::other)?
    ))?;
    let budget = policy.body_budget().clone();
    let url = url::Url::parse("https://fixture.invalid/original").map_err(io::Error::other)?;
    let entity =
        Entity::identity(BudgetedBytes::copy(&budget, input).ok_or(io::ErrorKind::OutOfMemory)?);
    let old = entity.wire().clone();
    let mut message = Message::request(
        OriginalSnapshot {
            url: url.clone(),
            method: "POST".into(),
            identity_allowed: true,
            asterisk: false,
        },
        RequestSnapshot {
            url: url.clone(),
            method: "POST".into(),
            headers: vec![],
        },
        Some(entity),
        &vec![],
        false,
    );
    let before = diagnostics::snapshot();
    let result = script_message::run(&policy, &url, &mut message, &CancellationToken::new()).await;
    let after = diagnostics::snapshot();
    let delta = |key: &str| {
        after["counters"][key]
            .as_u64()?
            .checked_sub(before["counters"][key].as_u64()?)
    };
    let changed = message
        .body
        .as_ref()
        .is_some_and(|body| body.logical() == Some(expected));
    let header = message
        .request
        .headers
        .iter()
        .any(|(k, v)| k == "x-proof" && v == "ok");
    let before_untouched = old.as_ref() == input;
    let accepted = delta("outputAccepted") == Some(1);
    let qos_unchanged = ["completedOwners", "setSucceeded", "setFailed"]
        .into_iter()
        .all(|key| {
            before["scopedScriptOwner"][key]
                .as_u64()
                .zip(after["scopedScriptOwner"][key].as_u64())
                .is_some_and(|(a, b)| a == b)
        });
    let backend_observed = if selected_plan {
        delta("planSelected") == Some(1)
            && delta("planOutputPendingAdmitted") == Some(1)
            && delta("planOutputQueueFailed") == Some(0)
            && delta("planOutputPayloadBudgetRejected") == Some(0)
            && delta("planEntered") == Some(1)
            && delta("planSucceeded") == Some(1)
            && delta("evaluationEntered") == Some(0)
            && delta("contextCreated") == Some(0)
            && delta("contextReleased") == Some(0)
            && delta("jscOwnerStarted") == Some(0)
            && delta("jscOwnerJoined") == Some(0)
            && delta("planFinalSingleStepEntered") == Some(1)
            && delta("planFinalRecipeEntered") == Some(1)
            && delta("planFinalDagEntered") == Some(0)
            && delta("planOwnerStarted") == Some(0)
            && delta("planOwnerJoined") == Some(0)
            && delta("planInlineEntered") == Some(1)
            && delta("planInlineReturned") == Some(1)
            && delta("planInlinePanicked") == Some(0)
            && qos_unchanged
    } else {
        delta("planOutputPendingAdmitted") == Some(0)
            && delta("planOutputQueueFailed") == Some(0)
            && delta("planOutputPayloadBudgetRejected") == Some(0)
            && delta("planFinalSingleStepEntered") == Some(0)
            && delta("planFinalRecipeEntered") == Some(0)
            && delta("planFinalDagEntered") == Some(0)
            && delta("planInputFallback") == Some(1)
            && delta("jscSelected") == Some(1)
            && delta("planEntered") == Some(0)
            && delta("planOwnerStarted") == Some(0)
            && delta("planOwnerJoined") == Some(0)
            && delta("evaluationEntered") == Some(1)
            && delta("evaluationSucceeded") == Some(1)
            && delta("contextCreated") == Some(1)
            && delta("contextReleased") == Some(1)
            && delta("jscOwnerStarted") == Some(1)
            && delta("jscOwnerJoined") == Some(1)
            && delta("planInlineEntered") == Some(0)
            && delta("planInlineReturned") == Some(0)
            && delta("planInlinePanicked") == Some(0)
    };
    let lane_observed = delta("queueRequested") == Some(1)
        && delta("queueAcquired") == Some(1)
        && delta("queueTimeout") == Some(0)
        && delta("queueCancelled") == Some(0);
    let forwarded = matches!(result, Ok(Outcome::Forward));
    drop((old, message, policy));
    let refunded = budget.reserve(WORKSPACE).is_some();
    Ok(
        json!({"id":id,"kind":"production-default-lane","passed":forwarded && changed && header && before_untouched && accepted && backend_observed && lane_observed && refunded,
        "expectedBackend":if selected_plan{"plan"}else{"javascriptcore"},"bodyChangedAsExpected":changed,"staticHeaderCommitted":header,
        "originalOwnerUnchanged":before_untouched,"outputAcceptedObserved":accepted,"backendCountersObserved":backend_observed,
        "scopedQoSUnchanged":qos_unchanged,"defaultLaneObserved":lane_observed,"budgetFullyRefunded":refunded,"timeoutIsNeverSuccess":true}),
    )
}
const GUARD_OPERATIONAL_IDS: [&str; 2] = ["guard-selected-pre-cancel", "guard-selected-state-oom"];
fn guard_operational(id: &str, budget: &Budget) -> io::Result<Value> {
    let source = guarded_source(
        "response",
        "seen",
        "row",
        "input.response.headers[row].name === 'x-probe'",
        "pass",
        false,
    );
    let metadata = guard_metadata("response", json!([]));
    let plan = static_literal_plan::compile(&source).ok_or(io::ErrorKind::InvalidInput)?;
    let input = BudgetedBytes::copy(budget, b"--source").ok_or(io::ErrorKind::OutOfMemory)?;
    let mut output =
        BudgetedBytes::new(budget, input.as_ref().len()).ok_or(io::ErrorKind::OutOfMemory)?;
    let eligible = plan.accepts_input(&metadata, Some(input.borrowed_body()));
    let cancellation = CancellationToken::new();
    let blocker = if id == "guard-selected-state-oom" {
        let cost = BudgetedBytes::allocation_cost(input.as_ref().len())
            .ok_or(io::ErrorKind::OutOfMemory)?
            * 2;
        Some(
            budget
                .reserve(WORKSPACE - cost)
                .ok_or(io::ErrorKind::OutOfMemory)?,
        )
    } else {
        cancellation.cancel();
        None
    };
    let deadline = Instant::now() + INVOCATION_LIMIT;
    let attempt = super::run_on_script_thread(super::OwnerBackend::Plan, || {
        plan.try_execute(
            &metadata,
            Some(input.borrowed_body()),
            &mut output,
            &cancellation,
            deadline,
        )
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
    })?;
    let expected = if id == "guard-selected-state-oom" {
        io::ErrorKind::OutOfMemory
    } else {
        io::ErrorKind::Interrupted
    };
    let refused = attempt
        .result
        .as_ref()
        .is_err_and(|error| error.kind() == expected);
    let unchanged = input.as_ref() == b"--source" && output.as_ref().is_empty();
    let passed =
        eligible && refused && attempt.ticks == 0 && attempt.allocation_work == 0 && unchanged;
    let actual_error = attempt
        .result
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    drop((blocker, input, output));
    Ok(
        json!({"id":id,"kind":"guard-operational","passed":passed && budget.reserve(WORKSPACE).is_some(),"eligibleBeforeExecution":eligible,
        "errorKind":actual_error,"expectedErrorKind":format!("{:?}",expected),"ticks":attempt.ticks,"allocationWork":attempt.allocation_work,
        "sourceAndEmptyOutputUnchanged":unchanged,"ownerJoined":true,"scope":"chosen Plan error is terminal; never rerun JSC"}),
    )
}

async fn production_guard_case(early: &str, found: bool) -> io::Result<Value> {
    let id = if found {
        "production-guard-tail"
    } else if early == "pass" {
        "production-guard-pass"
    } else {
        "production-guard-abort"
    };
    let source = guarded_source(
        "request",
        "seen",
        "row",
        "input.request.headers[row].name === 'x-probe'",
        early,
        false,
    )
    .replace(
        "return {type:'modify',body:",
        "return {headers:[{op:'set',name:'X-Proof',values:['ok']}],type:'modify',body:",
    );
    let policy = Policy::compile(&format!(
        "http-scripts:\n  enabled: true\n  scripts:\n    - name: diagnostic-guard-transaction\n      phase: request\n      match: exact\n      url: https://fixture.invalid/original\n      body: text\n      source: {}\n",
        serde_json::to_string(&source).map_err(io::Error::other)?
    ))?;
    let budget = policy.body_budget().clone();
    let url = url::Url::parse("https://fixture.invalid/original").map_err(io::Error::other)?;
    let entity = Entity::identity(
        BudgetedBytes::copy(&budget, b"--source").ok_or(io::ErrorKind::OutOfMemory)?,
    );
    let old = entity.wire().clone();
    let fields = if found {
        vec![("x-probe".into(), "ok".into())]
    } else {
        vec![]
    };
    let mut message = Message::request(
        OriginalSnapshot {
            url: url.clone(),
            method: "POST".into(),
            identity_allowed: true,
            asterisk: false,
        },
        RequestSnapshot {
            url: url.clone(),
            method: "POST".into(),
            headers: fields.clone(),
        },
        Some(entity),
        &fields,
        false,
    );
    let before = diagnostics::snapshot();
    let result = script_message::run(&policy, &url, &mut message, &CancellationToken::new()).await;
    let after = diagnostics::snapshot();
    let delta = |key: &str| {
        after["counters"][key]
            .as_u64()?
            .checked_sub(before["counters"][key].as_u64()?)
    };
    let outcome = if found || early == "pass" {
        matches!(result, Ok(Outcome::Forward))
    } else {
        matches!(result, Ok(Outcome::Abort))
    };
    let correct_body = message.body.as_ref().is_some_and(|body| {
        body.logical()
            == Some(if found {
                b"__source".as_slice()
            } else {
                b"--source".as_slice()
            })
    });
    let correct_headers = if found {
        message
            .request
            .headers
            .iter()
            .any(|(k, v)| k == "x-proof" && v == "ok")
    } else {
        message.request.headers == fields
    };
    let unchanged_owner = old.as_ref() == b"--source"
        && (found
            || message
                .body
                .as_ref()
                .is_some_and(|body| body.wire().as_ptr() == old.as_ptr()));
    let qos_unchanged = ["completedOwners", "setSucceeded", "setFailed"]
        .into_iter()
        .all(|key| {
            before["scopedScriptOwner"][key]
                .as_u64()
                .zip(after["scopedScriptOwner"][key].as_u64())
                .is_some_and(|(a, b)| a == b)
        });
    let guard = delta("planHeaderGuardEntered") == Some(1)
        && delta("planHeaderGuardTail") == Some(u64::from(found))
        && delta("planHeaderGuardPass") == Some(u64::from(!found && early == "pass"))
        && delta("planHeaderGuardAbort") == Some(u64::from(!found && early == "abort"));
    let backend = delta("planSelected") == Some(1)
        && delta("planOutputPendingAdmitted") == Some(1)
        && delta("planOutputQueueFailed") == Some(0)
        && delta("planOutputPayloadBudgetRejected") == Some(0)
        && delta("planEntered") == Some(1)
        && delta("planSucceeded") == Some(1)
        && delta("contextCreated") == Some(0)
        && delta("contextReleased") == Some(0)
        && delta("evaluationEntered") == Some(0)
        && delta("jscOwnerStarted") == Some(0)
        && delta("jscOwnerJoined") == Some(0)
        && delta("planOwnerStarted") == Some(0)
        && delta("planOwnerJoined") == Some(0)
        && delta("planInlineEntered") == Some(1)
        && delta("planInlineReturned") == Some(1)
        && delta("planInlinePanicked") == Some(0)
        && qos_unchanged
        && delta("planFinalSingleStepEntered") == Some(u64::from(found))
        && delta("planFinalRecipeEntered") == Some(u64::from(found))
        && delta("planFinalDagEntered") == Some(0);
    let lane = delta("queueRequested") == Some(1)
        && delta("queueAcquired") == Some(1)
        && delta("queueTimeout") == Some(0);
    let commit = delta("outputAccepted") == Some(u64::from(found || early == "pass"))
        && delta("outputTerminal") == Some(u64::from(!found && early == "abort"));
    drop((old, message, policy));
    let refund = budget.reserve(WORKSPACE).is_some();
    Ok(
        json!({"id":id,"kind":"production-guard-default-lane","passed":outcome && correct_body && correct_headers && unchanged_owner && guard && backend && lane && commit && refund,
        "correctOutcome":outcome,"bodyAndHeadersCorrect":correct_body && correct_headers,"originalOwnerUnchanged":unchanged_owner,
        "guardCountersObserved":guard,"backendCountersObserved":backend,"scopedQoSUnchanged":qos_unchanged,"defaultLaneObserved":lane,"commitCountersObserved":commit,"budgetFullyRefunded":refund}),
    )
}

fn production_cases() -> io::Result<Vec<Value>> {
    // Invoke is synchronous and admitted only in an otherwise uninitialized,
    // permanently diagnostic-only process. Do not nest a runtime accidentally.
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()?;
    let rows = runtime.block_on(async {
        let mut rows = Vec::new();
        for (id, input, expected, selected_plan) in [
            ("production-plan-default-lane", b"--source".as_slice(), b"__source".as_slice(), true),
            ("production-unicode-plan-default-lane", "-é".as_bytes(), "_é".as_bytes(), true),
        ] {
            rows.push(production_case(id,input,expected,selected_plan).await.unwrap_or_else(|error| json!({"id":id,"kind":"production-default-lane","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})));
        }
        for (early,found) in [("pass",true),("pass",false),("abort",false)] {
            rows.push(production_guard_case(early,found).await.unwrap_or_else(|error|json!({"id":"production-guard-setup","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})));
        }
        for (id,mode) in [
            ("plan-output-queued-bookkeeping-only",PlanAdmissionProbe::ReleaseThenRun),
            ("plan-output-queue-timeout-refund",PlanAdmissionProbe::QueueTimeout),
            ("plan-output-queue-cancel-refund",PlanAdmissionProbe::QueueCancel),
            ("plan-output-post-lane-budget-refusal",PlanAdmissionProbe::PayloadReject),
        ] {
            rows.push(plan_admission_case(id,mode).await.unwrap_or_else(|error|json!({"id":id,"kind":"plan-output-admission","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})));
        }
        for (id, mode) in [
            ("inline-abort-ownership", InlineProbe::Abort),
            ("inline-cancel-abort-ownership", InlineProbe::CancelAbort),
            ("inline-panic-unwind", InlineProbe::Panic),
        ] {
            rows.push(inline_lifecycle_case(id,mode).await.unwrap_or_else(|error| json!({"id":id,"kind":"inline-lifecycle","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})));
        }
        rows
    });
    // No detached future or shutdown_timeout: Runtime::drop really joins its
    // transient workers/blocking tasks before the suite can claim completion.
    drop(runtime);
    Ok(rows)
}

fn unix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub(crate) fn run() -> io::Result<Value> {
    // Direct adapters hold the existing lane, then release it before async
    // production Message regressions reacquire that very same default lane.
    let lane = super::EXECUTION_LANE
        .try_acquire()
        .map_err(|_| io::ErrorKind::WouldBlock)?;
    let started = Instant::now();
    let start_unix = unix();
    let before = diagnostics::snapshot();
    let cancellation = CancellationToken::new();
    let warmup_started = Instant::now();
    let warmup = super::prepare_platform(&cancellation);
    let warmup_us = warmup_started.elapsed().as_micros();
    let mut results = Vec::new();
    if warmup.is_ok() {
        for case in cases()
            .into_iter()
            .chain(extra_semantic_cases())
            .chain(materialization_cases())
            .chain(single_step_cases())
        {
            let budget = Budget::default();
            let result = compare(&case, &budget);
            // No testcase introspection/reset: a fresh entire-ledger owner
            // proves all body/API/state owners were actually released.
            let refunded = budget.reserve(WORKSPACE).is_some();
            let mut row = result.unwrap_or_else(|error| json!({"id":case.id,"passed":false,"harnessErrorKind":format!("{:?}",error.kind())}));
            row["budgetFullyRefunded"] = json!(refunded);
            if !refunded {
                row["passed"] = json!(false);
            }
            results.push(row);
        }
    }
    if warmup.is_ok() {
        for id in OPERATIONAL_IDS {
            let budget = Budget::default();
            let result = operational(id, &budget);
            let refunded = budget.reserve(WORKSPACE).is_some();
            let mut row = result.unwrap_or_else(|error| json!({"id":id,"passed":false,"harnessErrorKind":format!("{:?}",error.kind())}));
            row["budgetFullyRefunded"] = json!(refunded);
            if !refunded {
                row["passed"] = json!(false);
            }
            results.push(row);
        }
    }
    if warmup.is_ok() {
        for id in MATERIALIZATION_OPERATIONAL_IDS {
            let budget = Budget::default();
            let result = materialization_operational(id, &budget);
            let refunded = budget.reserve(WORKSPACE).is_some();
            let mut row=result.unwrap_or_else(|error|json!({"id":id,"passed":false,"harnessErrorKind":format!("{:?}",error.kind())}));
            row["budgetFullyRefunded"] = json!(refunded);
            if !refunded {
                row["passed"] = json!(false);
            }
            results.push(row);
        }
    }
    if warmup.is_ok() {
        for case in guard_cases() {
            let budget = Budget::default();
            let result = compare_guard(&case, &budget);
            let refunded = budget.reserve(WORKSPACE).is_some();
            let mut row=result.unwrap_or_else(|error|json!({"id":case.case.id,"passed":false,"harnessErrorKind":format!("{:?}",error.kind())}));
            row["budgetFullyRefunded"] = json!(refunded);
            if !refunded {
                row["passed"] = json!(false);
            }
            results.push(row);
        }
        for id in GUARD_OPERATIONAL_IDS {
            let budget = Budget::default();
            let result = guard_operational(id, &budget);
            let refunded = budget.reserve(WORKSPACE).is_some();
            let mut row=result.unwrap_or_else(|error|json!({"id":id,"passed":false,"harnessErrorKind":format!("{:?}",error.kind())}));
            row["budgetFullyRefunded"] = json!(refunded);
            if !refunded {
                row["passed"] = json!(false);
            }
            results.push(row);
        }
    }
    if warmup.is_ok() {
        results.push(crate::http_processing::body::validate_native_byte_map()
            .unwrap_or_else(|error| json!({"id":"native-byte-map-differential","kind":"native-differential","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})));
    }
    drop(lane);
    let mut production_runtime_joined = false;
    if warmup.is_ok() {
        match production_cases() {
            Ok(rows) => { results.extend(rows); production_runtime_joined = true; }
            Err(error) => results.push(json!({"id":"production-default-lane-setup","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})),
        }
    }
    if warmup.is_ok() {
        results.push(inline_runtime_drop_case().unwrap_or_else(|error| json!({"id":"inline-runtime-drop-barrier","kind":"inline-lifecycle","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})));
    }
    if warmup.is_ok() {
        results.push(crate::http_processing::h2_reuse::validate()
            .unwrap_or_else(|error| json!({"id":"h2-upstream-owner-lifecycle","kind":"h2-memory-owner-group","passed":false,"harnessErrorKind":format!("{:?}",error.kind())})));
    }
    let mismatches = results.iter().filter(|row| row["passed"] != true).count();
    let passed = warmup.is_ok()
        && results.len()
            == 91
                + OPERATIONAL_IDS.len()
                + MATERIALIZATION_OPERATIONAL_IDS.len()
                + GUARD_OPERATIONAL_IDS.len()
                + 5
                + 4
                + 4
                + 1
                + 1
        && production_runtime_joined
        && mismatches == 0;
    Ok(
        json!({"schemaVersion":1,"suite":"static-literal-plan-v1","started":true,"ended":true,"joined":true,
        "processID":std::process::id(),"startUnixMilliseconds":start_unix,"endUnixMilliseconds":unix(),"wallUs":started.elapsed().as_micros(),
        "passed":passed,"status":if passed{"PASS"}else{"FAIL"},"cases":results,"caseCount":results.len(),"mismatchCount":mismatches,
        "warmup":{"succeeded":warmup.is_ok(),"wallUs":warmup_us,"joined":true,"errorKind":warmup.err().map(|error|format!("{:?}",error.kind()))},
        "limits":{"invocationMilliseconds":100,"ticks":100000,"bodyBytes":262144,"workspaceBytes":WORKSPACE,"lanes":1},
        "processMustExitBeforePressure":true,"diagnosticCountersContainSuite":true,
        "counterScope":"fixed direct adapter comparisons, five production Message regressions, four real production output-admission probes, four labelled private shared-BIP lifecycle probes and one grouped native body differential/cost probe and one fixed duplex-H2 owner group (not TLS authentication); never pressure evidence",
        "expectedCaseCount":121,"semanticCaseCount":91,"operationalCaseCount":15,"productionCaseCount":5,"inlineLifecycleCaseCount":4,"planAdmissionCaseCount":4,"nativeBodyGroupCount":1,"h2OwnerGroupCount":1,
        "compiledRecipeStorageBytes":static_literal_plan::Plan::recipe_storage_bytes(),"recipeMaxSteps":64,
        "outerLaneReleasedBeforeProduction":true,"productionRuntimeJoined":production_runtime_joined,
        "diagnosticsBefore":before,"diagnosticsAfter":diagnostics::snapshot()}),
    )
}

// Private active diagnostics. No global hooks or production input can enable
// them. The target is a real running Tokio task, blocked inside the same BIP
// policy helper used by production Plan, while owning real input/output/state.
const INLINE_PROBE_BYTES: usize = 65536;
#[derive(Clone, Copy, PartialEq, Eq)]
enum InlineProbe {
    Abort,
    CancelAbort,
    Panic,
    RuntimeDrop,
}
struct DropMark(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for DropMark {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}
struct Tracked<T> {
    // Field drop order matters: the actual owner is dropped before the witness.
    value: T,
    _mark: DropMark,
}
struct InlineFixture {
    source: Tracked<Entity>,
    output: Tracked<BudgetedBytes>,
    last_source: bytes::Bytes,
    source_dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    output_dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    source_cost: usize,
    output_cost: usize,
}
#[derive(Clone, Copy, Default)]
struct InlineObserved {
    gate_entered: bool,
    gate_released: bool,
    operation_returned: bool,
    succeeded: bool,
    error: Option<io::ErrorKind>,
    output_bytes: usize,
    output_matches: bool,
}
type SharedInlineObserved = std::sync::Arc<std::sync::Mutex<InlineObserved>>;
fn observed(slot: &SharedInlineObserved) -> InlineObserved {
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn inline_fixture(budget: &Budget) -> io::Result<InlineFixture> {
    use std::sync::{Arc, atomic::AtomicBool};
    let source = Entity::identity(
        fixture(budget, &Input::Repeat(b'a', INLINE_PROBE_BYTES))?
            .ok_or(io::ErrorKind::OutOfMemory)?,
    );
    let last_source = source.wire().slice(0..1);
    let output =
        BudgetedBytes::new(budget, INLINE_PROBE_BYTES).ok_or(io::ErrorKind::OutOfMemory)?;
    let source_dropped = Arc::new(AtomicBool::new(false));
    let output_dropped = Arc::new(AtomicBool::new(false));
    let cost =
        BudgetedBytes::allocation_cost(INLINE_PROBE_BYTES).ok_or(io::ErrorKind::OutOfMemory)?;
    Ok(InlineFixture {
        source: Tracked {
            value: source,
            _mark: DropMark(source_dropped.clone()),
        },
        output: Tracked {
            value: output,
            _mark: DropMark(output_dropped.clone()),
        },
        last_source,
        source_dropped,
        output_dropped,
        source_cost: cost,
        output_cost: cost,
    })
}
async fn inline_probe_task(
    owners: (Tracked<Entity>, Tracked<BudgetedBytes>),
    mode: InlineProbe,
    cancellation: CancellationToken,
    deadline: Instant,
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
    state: SharedInlineObserved,
) -> io::Result<()> {
    let (source, mut output) = owners;
    let plan = static_literal_plan::compile(&body(
        "input.body.data.replaceAll('a','b').replaceAll('b','c')",
    ))
    .ok_or(io::ErrorKind::InvalidData)?;
    let _permit = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        super::EXECUTION_LANE.acquire(),
    )
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
    .map_err(|_| io::ErrorKind::BrokenPipe)?;
    let hook_state = state.clone();
    let mut entered = Some(entered);
    // Move Receiver into the hook: it is Send, not Sync, and must not be
    // captured through a shared borrowed reference by a Send callback.
    let mut hook = move |filled| {
        if filled != 256 {
            return;
        }
        hook_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .gate_entered = true;
        if let Some(sender) = entered.take() {
            let _ = sender.send(());
        }
        let released = release
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok();
        hook_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .gate_released = released;
        if mode == InlineProbe::Panic && released {
            panic!("fixed inline diagnostic unwind");
        }
    };
    let attempt = super::run_plan_inline(|| {
        plan.try_execute_for_validation(
            &json!({"body":{"kind":"text"}}),
            source.value.borrowed_body(),
            &mut output.value,
            &cancellation,
            deadline,
            static_literal_plan::Validation {
                force_dag: false,
                after_chunk: Some(&mut hook),
            },
        )
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
    })?;
    {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.operation_returned = true;
        state.succeeded = attempt.result.is_ok();
        state.error = attempt.result.as_ref().err().map(io::Error::kind);
        state.output_bytes = output.value.as_ref().len();
        state.output_matches = output.value.as_ref().len() == INLINE_PROBE_BYTES
            && output.value.as_ref().iter().all(|byte| *byte == b'c');
    }
    attempt.result.map(|_| ())
}
fn join_disposition(result: &Result<io::Result<()>, tokio::task::JoinError>) -> &'static str {
    match result {
        Ok(Ok(())) => "ready-ok",
        Ok(Err(_)) => "ready-error",
        Err(error) if error.is_cancelled() => "cancelled",
        Err(error) if error.is_panic() => "panic",
        Err(_) => "other-join-error",
    }
}
fn inline_counter_delta(before: &Value, after: &Value, key: &str) -> Option<u64> {
    after["counters"][key]
        .as_u64()?
        .checked_sub(before["counters"][key].as_u64()?)
}
async fn inline_lifecycle_case(id: &'static str, mode: InlineProbe) -> io::Result<Value> {
    use std::sync::{Arc, atomic::Ordering};
    let budget = Budget::default();
    let setup = inline_fixture(&budget)?;
    let state = Arc::new(std::sync::Mutex::new(InlineObserved::default()));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let cancellation = CancellationToken::new();
    let deadline = Instant::now() + INVOCATION_LIMIT;
    let before = diagnostics::snapshot();
    let task = tokio::spawn(inline_probe_task(
        (setup.source, setup.output),
        mode,
        cancellation.clone(),
        deadline,
        entered_tx,
        release_rx,
        state.clone(),
    ));
    let abort = task.abort_handle();
    let source_drop = setup.source_dropped.clone();
    let output_drop = setup.output_dropped.clone();
    let watched = state.clone();
    let observer_budget = budget.clone();
    let base_cost = setup.source_cost + setup.output_cost;
    // This is another actual task on a one-worker runtime. BIP must allow it
    // and its timer to progress while the target's synchronous poll is gated.
    let controller = tokio::spawn(async move {
        let entered = matches!(
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), entered_rx).await,
            Ok(Ok(()))
        );
        if mode == InlineProbe::Abort || mode == InlineProbe::CancelAbort {
            abort.abort();
        }
        if mode == InlineProbe::CancelAbort {
            cancellation.cancel();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        let source_live = !source_drop.load(Ordering::Acquire);
        let output_live = !output_drop.load(Ordering::Acquire);
        let not_returned = !observed(&watched).operation_returned && !abort.is_finished();
        let lane_held = super::EXECUTION_LANE.try_acquire().is_err();
        // Both real body owners plus Workspace must still be charged. No
        // synthetic pressure reservation or test-only Budget.used is needed.
        let owners_and_state_paid = observer_budget.reserve(WORKSPACE - base_cost).is_none();
        let released = release_tx.send(()).is_ok();
        (
            entered,
            source_live,
            output_live,
            not_returned,
            lane_held,
            owners_and_state_paid,
            released,
        )
    });
    // Always observe the actual target completion, including a controller
    // panic. The hook has the original absolute deadline as its watchdog.
    let proof_result = controller.await;
    let result = task.await;
    let proof = proof_result.map_err(io::Error::other)?;
    let after = diagnostics::snapshot();
    let actual = observed(&state);
    let panic_result = result.as_ref().is_err_and(|error| error.is_panic());
    // Abort of a running poll may still resolve Ready. Only explicit business
    // cancellation requires Interrupted from the actual Plan operation.
    let operation_expected = if mode == InlineProbe::Panic {
        panic_result && !actual.operation_returned
    } else if mode == InlineProbe::CancelAbort {
        actual.operation_returned
            && actual.error == Some(io::ErrorKind::Interrupted)
            && actual.output_bytes == 0
    } else {
        actual.operation_returned && actual.succeeded && actual.output_matches
    };
    let join_expected = if mode == InlineProbe::Panic {
        panic_result
    } else {
        result.is_ok() || result.as_ref().is_err_and(|error| error.is_cancelled())
    };
    let counter_expected = inline_counter_delta(&before, &after, "planInlineEntered") == Some(1)
        && inline_counter_delta(&before, &after, "planInlineReturned")
            == Some(u64::from(mode != InlineProbe::Panic))
        && inline_counter_delta(&before, &after, "planInlinePanicked")
            == Some(u64::from(mode == InlineProbe::Panic))
        && inline_counter_delta(&before, &after, "planOwnerStarted") == Some(0)
        && inline_counter_delta(&before, &after, "planOwnerJoined") == Some(0);
    let dropped = setup.source_dropped.load(Ordering::Acquire)
        && setup.output_dropped.load(Ordering::Acquire);
    let source_slice_held = budget.reserve(WORKSPACE).is_none()
        && budget.reserve(WORKSPACE - setup.source_cost).is_some()
        && setup.last_source.as_ref() == b"a";
    drop(setup.last_source);
    let refunded = budget.reserve(WORKSPACE).is_some();
    let proof_ok = proof.0 && proof.1 && proof.2 && proof.3 && proof.4 && proof.5 && proof.6;
    Ok(
        json!({"id":id,"kind":"inline-lifecycle","passed":proof_ok && actual.gate_entered && actual.gate_released && operation_expected && join_expected && counter_expected && dropped && source_slice_held && refunded,
        "targetGateEntered":proof.0,"sourceLiveDuringAbort":proof.1,"outputLiveDuringAbort":proof.2,
        "pollNotReturnedBeforeRelease":proof.3,"sameLaneHeldDuringAbort":proof.4,"ownersAndWorkspaceStillPaid":proof.5,
        "controllerAndTimerProgressed":proof.6,"operationReturned":actual.operation_returned,"operationSucceeded":actual.succeeded,"outputMatchesExpected":actual.output_matches,
        "actualErrorKind":actual.error.map(|kind|format!("{:?}",kind)),"joinDisposition":join_disposition(&result),
        "panicObserved":panic_result,"inlineCountersObserved":counter_expected,"ownersDroppedAfterCompletion":dropped,
        "lastSourceSliceHeldCredit":source_slice_held,"budgetFullyRefunded":refunded,"abortOnlyMayReturnReady":true,
        "scope":"real one-worker task abort/cancel/unwind during the shared BIP helper; no Message commit attempted"}),
    )
}

fn inline_runtime_drop_case() -> io::Result<Value> {
    use std::future::Future;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let budget = Budget::default();
    let setup = inline_fixture(&budget)?;
    let state = Arc::new(std::sync::Mutex::new(InlineObserved::default()));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()?;
    let deadline = Instant::now() + INVOCATION_LIMIT;
    let before = diagnostics::snapshot();
    let mut task = runtime.spawn(inline_probe_task(
        (setup.source, setup.output),
        InlineProbe::RuntimeDrop,
        CancellationToken::new(),
        deadline,
        entered_tx,
        release_rx,
        state.clone(),
    ));
    let entered = matches!(
        runtime.block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), entered_rx).await
        }),
        Ok(Ok(()))
    );
    let finished = Arc::new(AtomicBool::new(false));
    let drop_finished = finished.clone();
    let (drop_started_tx, drop_started_rx) = std::sync::mpsc::sync_channel(1);
    let (drop_done_tx, drop_done_rx) = std::sync::mpsc::sync_channel(1);
    let base_cost = setup.source_cost + setup.output_cost;
    let (drop_started, returned_early, owners_held, paid, lane_held, released, drop_thread_joined) =
        std::thread::scope(|scope| {
            let dropper = scope.spawn(move || {
                // This signal is before calling Drop: a2ms non-return observation
                // requires that this controller is subsequently scheduled. It
                // does not prove the destructor has already been entered.
                let _ = drop_started_tx.send(());
                // Actual normal Runtime drop, never shutdown_timeout/background.
                drop(runtime);
                drop_finished.store(true, Ordering::Release);
                let _ = drop_done_tx.send(());
            });
            let started = drop_started_rx.recv_timeout(INVOCATION_LIMIT).is_ok();
            let returned_early = drop_done_rx.recv_timeout(Duration::from_millis(2)).is_ok();
            let held = !setup.source_dropped.load(Ordering::Acquire)
                && !setup.output_dropped.load(Ordering::Acquire)
                && !observed(&state).operation_returned
                && !task.is_finished();
            let paid = budget.reserve(WORKSPACE - base_cost).is_none();
            let lane = super::EXECUTION_LANE.try_acquire().is_err();
            let released = release_tx.send(()).is_ok();
            let joined = dropper.join().is_ok();
            (started, returned_early, held, paid, lane, released, joined)
        });
    let context = &mut std::task::Context::from_waker(std::task::Waker::noop());
    let join = match std::pin::Pin::new(&mut task).poll(context) {
        std::task::Poll::Ready(result) => Some(result),
        std::task::Poll::Pending => None,
    };
    let after = diagnostics::snapshot();
    let actual = observed(&state);
    let counters = inline_counter_delta(&before, &after, "planInlineEntered") == Some(1)
        && inline_counter_delta(&before, &after, "planInlineReturned") == Some(1)
        && inline_counter_delta(&before, &after, "planInlinePanicked") == Some(0)
        && inline_counter_delta(&before, &after, "planOwnerStarted") == Some(0)
        && inline_counter_delta(&before, &after, "planOwnerJoined") == Some(0);
    let owners_dropped = setup.source_dropped.load(Ordering::Acquire)
        && setup.output_dropped.load(Ordering::Acquire);
    let slice_held = budget.reserve(WORKSPACE).is_none()
        && budget.reserve(WORKSPACE - setup.source_cost).is_some();
    drop(setup.last_source);
    let refunded = budget.reserve(WORKSPACE).is_some();
    let joined = finished.load(Ordering::Acquire) && drop_thread_joined && join.is_some();
    Ok(
        json!({"id":"inline-runtime-drop-barrier","kind":"inline-lifecycle","passed":entered && drop_started && !returned_early && owners_held && paid && lane_held && released && joined && actual.gate_released && actual.operation_returned && actual.succeeded && actual.output_matches && counters && owners_dropped && slice_held && refunded,
        "targetGateEntered":entered,"runtimeDropAboutToStart":drop_started,"runtimeReturnedBeforeGateRelease":returned_early,
        "ownersLiveWhileRuntimeDropping":owners_held,"ownersAndWorkspaceStillPaid":paid,"sameLaneHeld":lane_held,
        "runtimeActuallyDroppedAndJoined":joined,"joinDisposition":join.as_ref().map(join_disposition),
        "inlineCountersObserved":counters,"ownersDroppedAfterCompletion":owners_dropped,"lastSourceSliceHeldCredit":slice_held,
        "budgetFullyRefunded":refunded,"scope":"actual normal Runtime::drop on an owned scoped controller; no timeout shutdown or abandoned task"}),
    )
}

// Dedicated, real production Message regressions for output payload admission.
// Existing direct comparisons and the original 109 rows remain separate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PlanAdmissionProbe {
    ReleaseThenRun,
    QueueTimeout,
    QueueCancel,
    PayloadReject,
}
async fn plan_admission_case(id: &'static str, mode: PlanAdmissionProbe) -> io::Result<Value> {
    const LENGTH: usize = 65536;
    let source = "function rewrite(input){const payload=input.body.data.replaceAll('-', '_');return {headers:[{op:'set',name:'X-Proof',values:['ok']}],type:'modify',body:{kind:'text',data:payload}};}";
    let policy = Policy::compile(&format!(
        "http-scripts:\n  enabled: true\n  scripts:\n    - name: diagnostic-admission\n      phase: request\n      match: exact\n      url: https://fixture.invalid/original\n      body: text\n      source: {}\n",
        serde_json::to_string(source).map_err(io::Error::other)?
    ))?;
    let budget = policy.body_budget().clone();
    let url = url::Url::parse("https://fixture.invalid/original").map_err(io::Error::other)?;
    let entity = Entity::identity(
        fixture(&budget, &Input::Repeat(b'-', LENGTH))?.ok_or(io::ErrorKind::OutOfMemory)?,
    );
    let old = entity.wire().clone();
    let input_cost = BudgetedBytes::allocation_cost(LENGTH).ok_or(io::ErrorKind::OutOfMemory)?;
    let bookkeeping = BudgetedBytes::allocation_cost(0).ok_or(io::ErrorKind::OutOfMemory)?;
    // Exactly the existing output-owner bookkeeping remains available. A full
    // output cannot be allocated until this pressure is actually released.
    let mut pressure = Some(
        budget
            .reserve(WORKSPACE - input_cost - bookkeeping)
            .ok_or(io::ErrorKind::OutOfMemory)?,
    );
    let mut held_lane = if mode == PlanAdmissionProbe::PayloadReject {
        None
    } else {
        Some(
            super::EXECUTION_LANE
                .acquire()
                .await
                .map_err(|_| io::ErrorKind::BrokenPipe)?,
        )
    };
    let cancellation = CancellationToken::new();
    let target_cancellation = cancellation.clone();
    let before = diagnostics::snapshot();
    let mut task = tokio::spawn(async move {
        let mut message = Message::request(
            OriginalSnapshot {
                url: url.clone(),
                method: "POST".into(),
                identity_allowed: true,
                asterisk: false,
            },
            RequestSnapshot {
                url: url.clone(),
                method: "POST".into(),
                headers: vec![],
            },
            Some(entity),
            &vec![],
            false,
        );
        let initial_headers = message.request.headers.clone();
        let result = script_message::run(&policy, &url, &mut message, &target_cancellation).await;
        (result, message, initial_headers)
    });
    let mut queued_without_payload = false;
    if mode != PlanAdmissionProbe::PayloadReject {
        let observation_deadline = Instant::now() + INVOCATION_LIMIT;
        let seen = loop {
            if inline_counter_delta(&before, &diagnostics::snapshot(), "queueRequested") == Some(1)
            {
                break true;
            }
            if task.is_finished() || Instant::now() >= observation_deadline {
                break false;
            }
            tokio::task::yield_now().await;
        };
        let waiting = diagnostics::snapshot();
        queued_without_payload = seen
            && !task.is_finished()
            && inline_counter_delta(&before, &waiting, "planOutputPendingAdmitted") == Some(1)
            && inline_counter_delta(&before, &waiting, "callBuffersAdmitted") == Some(0)
            && inline_counter_delta(&before, &waiting, "planEntered") == Some(0)
            && budget.reserve(1).is_none();
        if mode == PlanAdmissionProbe::ReleaseThenRun {
            drop(pressure.take());
            drop(held_lane.take());
        } else if mode == PlanAdmissionProbe::QueueCancel {
            cancellation.cancel();
        }
    }
    // Never detach the target on a harness watchdog. Cancellation plus release
    // is followed by its actual JoinHandle completion before any owner proof.
    let completed_within_watchdog =
        tokio::time::timeout(Duration::from_millis(200), &mut task).await;
    let watchdog_observed = completed_within_watchdog.is_ok();
    let completed = match completed_within_watchdog {
        Ok(result) => result,
        Err(_) => {
            cancellation.cancel();
            drop(held_lane.take());
            drop(pressure.take());
            task.await
        }
    };
    let after = diagnostics::snapshot();
    let (result, message, initial_headers) = completed.map_err(io::Error::other)?;
    let delta = |key| inline_counter_delta(&before, &after, key);
    let success = mode == PlanAdmissionProbe::ReleaseThenRun;
    let payload_rejected = mode == PlanAdmissionProbe::PayloadReject;
    let queue_failed = matches!(
        mode,
        PlanAdmissionProbe::QueueTimeout | PlanAdmissionProbe::QueueCancel
    );
    let outcome = if mode == PlanAdmissionProbe::QueueCancel {
        result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::Interrupted)
    } else {
        matches!(&result, Ok(Outcome::Forward))
    };
    let expected_byte = if success { b'_' } else { b'-' };
    let body_correct = message
        .body
        .as_ref()
        .and_then(Entity::logical)
        .is_some_and(|bytes| {
            bytes.len() == LENGTH && bytes.iter().all(|byte| *byte == expected_byte)
        });
    let header_correct = if success {
        message
            .request
            .headers
            .iter()
            .any(|(name, value)| name == "x-proof" && value == "ok")
    } else {
        message.request.headers == initial_headers
    };
    let counters = delta("planSelected") == Some(1)
        && delta("planFinalSingleStepEntered") == Some(u64::from(success))
        && delta("planOutputPayloadBudgetRejected") == Some(u64::from(payload_rejected))
        && delta("planOutputPendingAdmitted") == Some(1)
        && delta("planOutputQueueFailed") == Some(u64::from(queue_failed))
        && delta("callBuffersRequested") == Some(1)
        && delta("callBuffersAdmitted") == Some(u64::from(success))
        && delta("callBuffersBudgetRejected") == Some(u64::from(payload_rejected))
        && delta("planBuffersRejected") == Some(u64::from(payload_rejected))
        && delta("skipCallBuffers") == Some(u64::from(payload_rejected))
        && delta("queueRequested") == Some(1)
        && delta("queueAcquired") == Some(u64::from(!queue_failed))
        && delta("queueTimeout") == Some(u64::from(mode == PlanAdmissionProbe::QueueTimeout))
        && delta("queueCancelled") == Some(u64::from(mode == PlanAdmissionProbe::QueueCancel))
        && delta("planEntered") == Some(u64::from(success))
        && delta("planSucceeded") == Some(u64::from(success))
        && delta("planInlineEntered") == Some(u64::from(success))
        && delta("planInlineReturned") == Some(u64::from(success))
        && delta("planInlinePanicked") == Some(0)
        && delta("evaluationEntered") == Some(0)
        && delta("contextCreated") == Some(0)
        && delta("contextReleased") == Some(0)
        && delta("jscOwnerStarted") == Some(0)
        && delta("jscOwnerJoined") == Some(0)
        && delta("planOwnerStarted") == Some(0)
        && delta("planOwnerJoined") == Some(0)
        && delta("outputAccepted") == Some(u64::from(success));
    // For queued failures and payload refusal, only the original input and
    // controller pressure may remain. The per-call Q must already be refunded.
    let pending_refunded = if success {
        None
    } else {
        Some(budget.reserve(bookkeeping).is_some())
    };
    let bookkeeping_resolved = if success {
        delta("callBuffersAdmitted") == Some(1)
    } else {
        pending_refunded == Some(true)
    };
    drop(held_lane.take());
    let lane_returned = super::EXECUTION_LANE.try_acquire().is_ok();
    drop(pressure.take());
    let original_unchanged = old.len() == LENGTH && old.iter().all(|byte| *byte == b'-');
    drop(message);
    let last_source = old.slice(0..1);
    drop(old);
    let last_slice_paid =
        budget.reserve(WORKSPACE).is_none() && budget.reserve(WORKSPACE - input_cost).is_some();
    drop(last_source);
    let refunded = budget.reserve(WORKSPACE).is_some();
    Ok(
        json!({"id":id,"kind":"plan-output-admission","passed":(mode==PlanAdmissionProbe::PayloadReject || queued_without_payload) && watchdog_observed && outcome && body_correct && header_correct && counters && bookkeeping_resolved && lane_returned && original_unchanged && last_slice_paid && refunded,
        "queueProbeApplicable":mode!=PlanAdmissionProbe::PayloadReject,"queuedWithOnlyOwnerBookkeeping":if mode==PlanAdmissionProbe::PayloadReject{None}else{Some(queued_without_payload)},"actualTargetJoined":true,"completedWithinHarnessWatchdog":watchdog_observed,
        "outcomeMatches":outcome,"bodyAndHeaderMatch":body_correct && header_correct,"admissionCountersMatch":counters,
        "actualErrorKind":result.as_ref().err().map(|error|format!("{:?}",error.kind())),
        "pendingBookkeepingRefunded":pending_refunded,"pendingOwnerDisposition":if success{"promoted-to-real-output"}else{"refunded"},"sameLaneReturned":lane_returned,"originalOwnerUnchanged":original_unchanged,
        "lastSourceSliceStillPaid":last_slice_paid,"budgetFullyRefunded":refunded,
        "scope":"actual Message.run/default lane; full output payload cannot coexist with held exact pressure; no JSC replay"}),
    )
}
