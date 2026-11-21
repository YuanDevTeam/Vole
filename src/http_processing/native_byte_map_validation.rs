//! Fixed tvOS-only native differential group in the existing active suite.
//! No caller data, sockets, VM, new runtime, source logging or host-only tests.
use super::*;
use crate::http_processing::rules::{
    ActionKind, MatchKind, Occurrences, RawRule, Search, SearchMode,
};
use serde_json::{Value, json};
use std::{io, time::Instant};

const URL: &str = "https://native-validation.invalid/body";
const N: usize = 65536;
const ASCII_CASES: usize = 128 * 128 * 2;
const EXPECTED: usize = ASCII_CASES + 24 + 10 + 6 + 3 + 8;

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn compiled(
    search: &str,
    replacement: &str,
    mode: SearchMode,
    occurrences: Occurrences,
) -> io::Result<Rule> {
    let raw = RawRule {
        url: URL.into(),
        match_kind: MatchKind::Exact,
        action: ActionKind::ResponseBodyReplace,
        enabled: true,
        name: None,
        replacement: Some(replacement.into()),
        replacement_mode: None,
        header: None,
        value: None,
        search: Some(search.into()),
        search_mode: Some(mode),
        occurrences: Some(occurrences),
        patch: None,
    };
    Rule::compile(raw, &mut 0)
}
fn search(rule: &Rule) -> io::Result<&Search> {
    match &rule.action {
        RuleAction::Body {
            operation: BodyOperation::Replace(value),
            ..
        } => Ok(value),
        _ => Err(invalid()),
    }
}
fn repeated(budget: &Budget, byte: u8, length: usize) -> io::Result<BudgetedBytes> {
    // Producer scratch is fixed1KiB, not an uncharged retained body-sized copy.
    let mut value = BudgetedBytes::new(budget, length).ok_or(io::ErrorKind::OutOfMemory)?;
    let chunk = [byte; 1024];
    while value.as_ref().len() < length {
        let count = (length - value.as_ref().len()).min(chunk.len());
        value.extend(&chunk[..count])?;
    }
    Ok(value)
}
fn fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |sum, byte| {
        (sum ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}
fn compare(
    rule: &Rule,
    input: &BudgetedBytes,
    budget: &Budget,
    eligible: bool,
) -> io::Result<bool> {
    let query = search(rule)?;
    let text = std::str::from_utf8(input.as_ref()).map_err(io::Error::other)?;
    let capacity = query.output_capacity(text.len(), MAX_BODY);
    let before = fingerprint(input.as_ref());
    let mut legacy = BudgetedBytes::new(budget, capacity).ok_or(io::ErrorKind::OutOfMemory)?;
    // This reference is the unchanged match_indices/captures/template helper,
    // also still used by headers, with its actual independently paid Vec.
    let old = legacy.write_text(|out| query.apply_into(text, out, MAX_BODY));
    let url = Url::parse(URL).map_err(io::Error::other)?;
    let actual = apply_operations(
        std::slice::from_ref(rule),
        &url,
        Phase::Response,
        input.as_ref(),
        budget,
        NativeMedia::default(),
    );
    let same = match (&old, &actual) {
        (Ok(()), Ok(Some(BodyCandidate { bytes: value, .. }))) => {
            value.as_ref() == legacy.as_ref()
                && value.as_ref().len() + value.remaining() == capacity
                && std::str::from_utf8(value.as_ref()).is_ok()
                && (value.as_ref().is_empty() || value.as_ref().as_ptr() != input.as_ref().as_ptr())
        }
        (Err(_), Err(Bypass::Transform)) => true,
        _ => false,
    };
    Ok(same
        && (query.ascii_literal_byte_map().is_some() == eligible)
        && before == fingerprint(input.as_ref()))
}
struct Group {
    count: usize,
    failures: usize,
    details: Value,
}
impl Group {
    fn new() -> Self {
        Self {
            count: 0,
            failures: 0,
            details: json!({}),
        }
    }
    fn check(&mut self, passed: bool) {
        self.count += 1;
        self.failures += usize::from(!passed);
    }
}
fn ascii_pairs(budget: &Budget) -> io::Result<Group> {
    const SUFFIX: &[u8] = "é😀中".as_bytes();
    let mut input =
        BudgetedBytes::new(budget, 256 + SUFFIX.len()).ok_or(io::ErrorKind::OutOfMemory)?;
    input.write_initialized_output(256 + SUFFIX.len(), |out| {
        for (index, byte) in out[..256].iter_mut().enumerate() {
            *byte = (index % 128) as u8;
        }
        out[256..].copy_from_slice(SUFFIX);
        Ok(out.len())
    })?;
    let mut group = Group::new();
    for from in 0u8..128 {
        for to in 0u8..128 {
            for occurrences in [Occurrences::First, Occurrences::All] {
                let rule = compiled(
                    &char::from(from).to_string(),
                    &char::from(to).to_string(),
                    SearchMode::Literal,
                    occurrences,
                )?;
                group.check(compare(&rule, &input, budget, true)?);
            }
        }
    }
    group.details = json!({"all128SearchAndReplacementBytes":true,"occurrencePolicies":2,"unicodeNulDollarInput":true,"independentlyPaidReferenceAndOutput":true});
    Ok(group)
}
fn boundaries(budget: &Budget) -> io::Result<Group> {
    let mut group = Group::new();
    for length in [0, 1, 255, 256, 257, 4095, 4096, N, MAX_BODY, MAX_BODY + 1] {
        let input = repeated(budget, b'q', length)?;
        for occurrences in [Occurrences::First, Occurrences::All] {
            group.check(compare(
                &compiled("q", "z", SearchMode::Literal, occurrences)?,
                &input,
                budget,
                true,
            )?);
        }
    }
    for bytes in ["q:é:q:😀:q:中".as_bytes(), "no target é😀\0$".as_bytes()] {
        let input = BudgetedBytes::copy(budget, bytes).ok_or(io::ErrorKind::OutOfMemory)?;
        for occurrences in [Occurrences::First, Occurrences::All] {
            group.check(compare(
                &compiled("q", "z", SearchMode::Literal, occurrences)?,
                &input,
                budget,
                true,
            )?);
        }
    }
    Ok(group)
}
fn fallback(budget: &Budget) -> io::Result<Group> {
    let mut group = Group::new();
    for (input, from, to, mode, occurrences) in [
        ("éaé", "é", "x", SearchMode::Literal, Occurrences::All),
        (
            "ab--abab",
            "ab",
            "$1",
            SearchMode::Literal,
            Occurrences::First,
        ),
        ("aa😀a", "a", "", SearchMode::Literal, Occurrences::All),
        ("aéa", "a", "aa", SearchMode::Literal, Occurrences::All),
        (
            "a ab",
            "(?P<letter>a)(b)?",
            "${letter}-$2-$$",
            SearchMode::Regex,
            Occurrences::First,
        ),
        ("aéa", "(a)", "${1}", SearchMode::Regex, Occurrences::All),
        ("aa", "a", "$$", SearchMode::Regex, Occurrences::All),
        ("ab", "", "x", SearchMode::Regex, Occurrences::All),
    ] {
        let input =
            BudgetedBytes::copy(budget, input.as_bytes()).ok_or(io::ErrorKind::OutOfMemory)?;
        group.check(compare(
            &compiled(from, to, mode, occurrences)?,
            &input,
            budget,
            false,
        )?);
    }
    group.check(
        Search::compile(
            String::new(),
            "x".into(),
            SearchMode::Literal,
            Occurrences::All,
        )
        .is_err(),
    );
    let input = BudgetedBytes::copy(budget, &[0xff, b'q']).ok_or(io::ErrorKind::OutOfMemory)?;
    let rules = [compiled("q", "z", SearchMode::Literal, Occurrences::All)?];
    let url = Url::parse(URL).map_err(io::Error::other)?;
    group.check(matches!(
        apply_operations(
            &rules,
            &url,
            Phase::Response,
            input.as_ref(),
            budget,
            NativeMedia::default()
        ),
        Err(Bypass::InvalidText)
    ));
    Ok(group)
}
fn push_repeat(transaction: &mut Transaction<'_>, byte: u8, length: usize) -> io::Result<()> {
    let chunk = [byte; 1024];
    for offset in (0..length).step_by(chunk.len()) {
        transaction
            .push(&chunk[..(length - offset).min(chunk.len())])
            .map_err(|_| invalid())?;
    }
    Ok(())
}
fn entity_budget(budget: &Budget) -> io::Result<Group> {
    let mut group = Group::new();
    let cost = BudgetedBytes::allocation_cost(N).ok_or(io::ErrorKind::OutOfMemory)?;
    for (from, to, changes) in [("q", "z", true), ("q", "q", false), ("x", "z", false)] {
        for missing in [0usize, 1] {
            let pressure_bytes = budget::WORKSPACE - 2 * cost + missing;
            let pressure = budget
                .reserve(pressure_bytes)
                .ok_or(io::ErrorKind::OutOfMemory)?;
            let rules = [compiled(from, to, SearchMode::Literal, Occurrences::All)?];
            let url = Url::parse(URL).map_err(io::Error::other)?;
            let request = OriginalRequestMeta::new("GET", &vec![]);
            let wire = WireBodyMeta::new(
                &vec![],
                &request,
                Phase::Response,
                Some(200),
                Some(N as u64),
                false,
            );
            let mut transaction =
                Transaction::begin_shared(budget, &rules, &url, Phase::Response, &wire, true)
                    .map_err(|_| invalid())?;
            push_repeat(&mut transaction, b'q', N)?;
            let old_ptr = transaction.raw.as_ref().as_ptr();
            let mut fields = vec![
                ("x-independent".into(), "kept".into()),
                ("etag".into(), "synthetic".into()),
            ];
            let before = fields.clone();
            let entity = transaction.finish_shared(false, &mut fields);
            let changed = missing == 0 && changes;
            let expected = if changed { b'z' } else { b'q' };
            let body = entity.changed() == changed
                && entity.wire().len() == N
                && entity.wire().iter().all(|b| *b == expected)
                && entity
                    .logical()
                    .is_some_and(|bytes| bytes.iter().all(|b| *b == expected));
            let fallback = entity.bypass
                == if missing == 1 {
                    Some(Bypass::Budget)
                } else {
                    None
                };
            let metadata = if changed {
                !fields
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("etag"))
                    && fields.iter().any(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length") && value == &N.to_string()
                    })
                    && fields
                        .iter()
                        .any(|(name, value)| name == "x-independent" && value == "kept")
            } else {
                fields == before && entity.wire().as_ptr() == old_ptr
            };
            let remaining = budget::WORKSPACE - pressure_bytes - cost;
            let only_one_owner =
                budget.reserve(remaining).is_some() && budget.reserve(remaining + 1).is_none();
            let sent = entity.into_wire();
            let final_slice = sent.slice(17..18);
            drop(sent);
            let still_paid = budget.reserve(remaining + 1).is_none()
                && final_slice.as_ref() == [expected].as_slice();
            drop(final_slice);
            let source_refunded = budget.reserve(budget::WORKSPACE - pressure_bytes).is_some();
            drop(pressure);
            group.check(
                body && fallback && metadata && only_one_owner && still_paid && source_refunded,
            );
        }
    }
    group.details = json!({"actualSharedCollectorEntity":true,"exactAndOneByteShort":true,"sameByteAndNoMatchStillAdmit":true,"actualFinalBytesSliceRetainsCredit":true});
    Ok(group)
}
fn rollback(budget: &Budget) -> io::Result<Group> {
    let mut group = Group::new();
    let url = Url::parse(URL).map_err(io::Error::other)?;
    let old = br#"{"key":"qq","number":1}"#;
    let mut rules = vec![compiled("q", "$", SearchMode::Literal, Occurrences::All)?];
    let patch: RawRule = serde_json::from_value(json!({"url":URL,"match":"exact","action":"response-body-json-patch","patch":[{"op":"test","path":"/key","value":"other"}]})).map_err(io::Error::other)?;
    rules.push(Rule::compile(patch, &mut 0)?);
    let request = OriginalRequestMeta::new("GET", &vec![]);
    let wire = WireBodyMeta::new(
        &vec![],
        &request,
        Phase::Response,
        Some(200),
        Some(old.len() as u64),
        false,
    );
    let mut transaction =
        Transaction::begin_shared(budget, &rules, &url, Phase::Response, &wire, true)
            .map_err(|_| invalid())?;
    transaction.push(old).map_err(|_| invalid())?;
    let mut fields = vec![
        ("x-independent".into(), "kept".into()),
        ("etag".into(), "synthetic".into()),
    ];
    let before = fields.clone();
    let old_ptr = transaction.raw.as_ref().as_ptr();
    let entity = transaction.finish_shared(false, &mut fields);
    group.check(
        !entity.changed()
            && entity.bypass == Some(Bypass::Transform)
            && fields == before
            && entity.wire().as_ref() == old
            && entity.wire().as_ptr() == old_ptr
            && entity.logical() == Some(old.as_slice()),
    );
    drop(entity);

    let rules = [compiled("q", "z", SearchMode::Literal, Occurrences::All)?];
    let wire = WireBodyMeta::new(
        &vec![],
        &request,
        Phase::Response,
        Some(200),
        Some(8),
        false,
    );
    let mut transaction =
        Transaction::begin_shared(budget, &rules, &url, Phase::Response, &wire, true)
            .map_err(|_| invalid())?;
    transaction.push(b"qqsource").map_err(|_| invalid())?;
    let old_ptr = transaction.raw.as_ref().as_ptr();
    let mut fields = vec![(
        "x-pad".into(),
        "a".repeat(super::super::headers::MAX_BYTES - 32 - 5),
    )];
    let before = fields.clone();
    let entity = transaction.finish_shared(false, &mut fields);
    group.check(
        !entity.changed()
            && entity.bypass == Some(Bypass::Budget)
            && fields == before
            && entity.wire().as_ref() == b"qqsource"
            && entity.wire().as_ptr() == old_ptr,
    );
    drop(entity);

    let mut entity = Entity::identity(
        BudgetedBytes::copy(budget, b"qqsource").ok_or(io::ErrorKind::OutOfMemory)?,
    );
    let before_wire = entity.wire().clone();
    let mut fields = vec![("etag".into(), "synthetic".into())];
    let before = fields.clone();
    let foreign = Budget::default();
    let output = apply_operations(
        &rules,
        &url,
        Phase::Response,
        entity.logical().ok_or_else(invalid)?,
        &foreign,
        NativeMedia::default(),
    )
    .map_err(|_| invalid())?
    .ok_or_else(invalid)?;
    let mapped = output.bytes.as_ref() == b"zzsource";
    let refused = commit_shared_body(&mut entity, &mut fields, output) == Err(Bypass::Budget);
    group.check(
        mapped
            && refused
            && fields == before
            && entity.wire().as_ptr() == before_wire.as_ptr()
            && entity.wire().as_ref() == b"qqsource"
            && foreign.reserve(budget::WORKSPACE).is_some(),
    );
    drop((entity, before_wire));
    group.details = json!({"laterOperationRollsBackWholeNativeStage":true,"headerFinalizeFailureAtomic":true,"foreignLedgerActualMappedOutputRejected":true});
    Ok(group)
}

fn cpu() -> Option<u128> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: same public current-thread clock used by scoped_qos; initialized
    // writable timespec, tvOS-only diagnostics, no QoS setter or private API.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
    (rc == 0 && time.tv_sec >= 0 && (0..1_000_000_000).contains(&time.tv_nsec))
        .then(|| (time.tv_sec as u128) * 1_000_000_000 + time.tv_nsec as u128)
}
fn measured<T>(operation: impl FnOnce() -> T) -> (T, Value) {
    let start_cpu = cpu();
    let start = Instant::now();
    let value = operation();
    let elapsed = start.elapsed().as_micros();
    let cpu_us = cpu()
        .zip(start_cpu)
        .and_then(|(end, start)| end.checked_sub(start))
        .map(|value| value / 1000);
    (
        value,
        json!({"sampleCount":1,"wallUs":elapsed,"threadCpuUs":cpu_us,"threadCpuAvailable":cpu_us.is_some()}),
    )
}
fn timing(budget: &Budget) -> io::Result<Group> {
    let mut group = Group::new();
    let mut samples = Vec::new();
    for dense in [true, false] {
        let mut input = BudgetedBytes::new(budget, N).ok_or(io::ErrorKind::OutOfMemory)?;
        input.write_initialized_output(N, |bytes| {
            bytes.fill(if dense { b'q' } else { b'x' });
            if !dense {
                bytes[17] = b'q';
                bytes[N - 17] = b'q';
            }
            Ok(N)
        })?;
        for occurrences in [Occurrences::First, Occurrences::All] {
            let rule = compiled("q", "z", SearchMode::Literal, occurrences)?;
            let query = search(&rule)?;
            let text = std::str::from_utf8(input.as_ref()).map_err(io::Error::other)?;
            for iteration in 0..2 {
                let mut old = BudgetedBytes::new(budget, N).ok_or(io::ErrorKind::OutOfMemory)?;
                let mut new = BudgetedBytes::new(budget, N).ok_or(io::ErrorKind::OutOfMemory)?;
                let legacy = |out: &mut BudgetedBytes| {
                    out.write_text(|out| query.apply_into(text, out, MAX_BODY))
                        .map_err(|_| Bypass::Transform)
                };
                let (old_result, old_time, new_result, new_time) = if iteration == 0 {
                    let (a, ta) = measured(|| legacy(&mut old));
                    let (b, tb) = measured(|| fill_replacement(text, query, &mut new));
                    (a, ta, b, tb)
                } else {
                    let (b, tb) = measured(|| fill_replacement(text, query, &mut new));
                    let (a, ta) = measured(|| legacy(&mut old));
                    (a, ta, b, tb)
                };
                let same = old_result.is_ok()
                    && new_result.is_ok()
                    && old.as_ref() == new.as_ref()
                    && old.as_ref().len() == N
                    && new.as_ref().len() + new.remaining() == N;
                group.check(same);
                samples.push(json!({"shape":if dense{"dense"}else{"sparse-two-matches"},"policy":if occurrences==Occurrences::First{"first"}else{"all"},"iteration":iteration,
                    "order":if iteration==0{"legacy-then-new"}else{"new-then-legacy"},"bytes":N,"equal":same,"legacy":old_time,"candidate":new_time}));
            }
        }
    }
    group.details = json!({"scope":"real helper operations on separately pre-admitted equal-capacity outputs; excludes source construction, output allocation and final owner drop; new helper includes zero initialization, legacy includes Vec/String handoff; native has no JS tick/100ms limit added",
        "processID":std::process::id(),"threadScope":"same diagnostic caller thread, no QoS setter or worker selection", "notWholeNeProfile":true,"noTimingThreshold":true,"samples":samples});
    Ok(group)
}

pub(super) fn run() -> io::Result<Value> {
    let mut groups = Vec::new();
    for (id, expected, function) in [
        (
            "all-ascii-pairs",
            ASCII_CASES,
            ascii_pairs as fn(&Budget) -> io::Result<Group>,
        ),
        ("body-boundaries", 24, boundaries),
        ("legacy-fallback", 10, fallback),
        ("entity-budget-last-slice", 6, entity_budget),
        ("body-metadata-rollback", 3, rollback),
        ("dense-sparse-helper-cost", 8, timing),
    ] {
        let budget = Budget::default();
        let result = function(&budget);
        let refunded = budget.reserve(budget::WORKSPACE).is_some();
        let row = match result {
            Ok(group) => {
                json!({"id":id,"passed":group.count==expected && group.failures==0 && refunded,"caseCount":group.count,"expectedCaseCount":expected,"mismatchCount":group.failures,"budgetFullyRefunded":refunded,"details":group.details})
            }
            Err(error) => {
                json!({"id":id,"passed":false,"caseCount":0,"expectedCaseCount":expected,"harnessErrorKind":format!("{:?}",error.kind()),"budgetFullyRefunded":refunded})
            }
        };
        groups.push(row);
    }
    let count: u64 = groups
        .iter()
        .filter_map(|row| row["caseCount"].as_u64())
        .sum();
    let mismatches = groups.iter().filter(|row| row["passed"] != true).count();
    let passed = count == EXPECTED as u64 && groups.len() == 6 && mismatches == 0;
    Ok(
        json!({"id":"native-byte-map-differential","kind":"native-differential","passed":passed,"caseCount":count,"expectedCaseCount":EXPECTED,"groupCount":groups.len(),"mismatchGroupCount":mismatches,"groups":groups,
        "realCompiledRulesAndBodyOperations":true,"legacySearchReferenceRetained":true,"noJscEquivalenceClaim":true,"performanceAcceptance":false,"scope":"fixed active tvOS native helper/Entity/ledger evidence, not a network or process-memory qualification"}),
    )
}
