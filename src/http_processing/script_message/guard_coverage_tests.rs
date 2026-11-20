//! Actual Message metadata is the business guard proof boundary, not arbitrary JSON.
use super::*;
use crate::http_processing::{
    body_budget::{BridgePlan, output_capacity},
    scripts,
};

fn source(array: &str) -> String {
    format!(
        "function rewrite(input){{let found=false;for(let i=0;i<input.{array}.headers.length;i++){{if(input.{array}.headers[i].name==='x-check'&&input.{array}.headers[i].value==='中文😀'){{found=true;}}}}if(!found){{return {{type:'pass'}};}}return {{type:'modify',body:{{kind:'text',data:input.body.data.replaceAll('-', '_')}}}};}}"
    )
}

fn message(phase: Phase, request: Fields, response: Fields, budget: &Budget) -> Message {
    let url = Url::parse("https://guard.example/path").unwrap();
    let original = OriginalSnapshot {
        url: url.clone(),
        method: "GET".into(),
        identity_allowed: true,
        asterisk: false,
    };
    let request = RequestSnapshot {
        url,
        method: "GET".into(),
        headers: request,
    };
    let body = Some(Entity::identity(
        BudgetedBytes::copy(budget, "中文-😀".as_bytes()).unwrap(),
    ));
    match phase {
        Phase::Request => Message::request(original, request, body, &vec![], false),
        Phase::Response => Message::response(
            original,
            request,
            ResponseSnapshot {
                status: 200,
                headers: response,
            },
            body,
            &vec![],
        ),
    }
}

fn selected(compiled: &scripts::CompiledSource, message: &Message) -> bool {
    let metadata = message.metadata(BodyMode::Text).unwrap();
    compiled
        .backend(
            &metadata,
            message.body.as_ref().and_then(Entity::borrowed_body),
        )
        .is_plan()
}

async fn compare_actual_jsc(
    compiled: &scripts::CompiledSource,
    message: &Message,
    budget: &Budget,
) -> (Value, Vec<u8>) {
    let metadata = message.metadata(BodyMode::Text).unwrap();
    let entity = message.body.as_ref().unwrap();
    let input = entity.logical().unwrap();
    let original_owner = entity.wire().clone();
    let ledger = message.body.as_ref().unwrap().borrowed_body().unwrap();
    let local_budget = Budget::default();
    // The reference uses a separately witnessed owner/ledger; business input
    // remains unchanged and no owner is relabelled or refunded early.
    let reference = BudgetedBytes::copy(&local_budget, input).unwrap();
    let bound = compiled.maximum_output_bytes(input.len());
    let mut jsc_body = BudgetedBytes::new(&local_budget, output_capacity(bound).unwrap()).unwrap();
    let bridge = local_budget
        .reserve(
            BridgePlan::new(input.len(), true, bound)
                .unwrap()
                .cost()
                .unwrap(),
        )
        .unwrap();
    scripts::prepare_platform(&CancellationToken::new()).unwrap();
    let jsc = scripts::evaluate_until(
        compiled,
        &metadata,
        Some(reference.as_ref()),
        &mut jsc_body,
        Some(&bridge),
        &CancellationToken::new(),
        Instant::now() + Duration::from_secs(1),
    )
    .await
    .unwrap();
    let expected = jsc_body.as_ref().to_vec();
    drop((reference, jsc_body, bridge));
    assert_eq!(local_budget.used(), 0);

    // A real Message's current body carries this exact ledger provenance.
    let metadata = message.metadata(BodyMode::Text).unwrap();
    let mut plan_body = BudgetedBytes::new(budget, output_capacity(bound).unwrap()).unwrap();
    let backend = compiled.backend(&metadata, Some(ledger));
    assert!(backend.is_plan());
    let plan = scripts::evaluate_backend_until(
        backend,
        &metadata,
        Some(ledger),
        &mut plan_body,
        None,
        &CancellationToken::new(),
        Instant::now() + Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(plan, jsc);
    assert_eq!(plan_body.as_ref(), expected);
    assert_eq!(
        message.body.as_ref().unwrap().wire().as_ptr(),
        original_owner.as_ptr()
    );
    (plan, expected)
}

#[tokio::test(flavor = "current_thread")]
async fn canonical_message_guards_cover_both_request_domains_and_response_domain() {
    for (phase, array) in [
        (Phase::Request, "request"),
        (Phase::Response, "request"),
        (Phase::Response, "response"),
    ] {
        let budget = Budget::default();
        let fields = vec![
            ("X-Check".into(), "other".into()),
            ("x-check".into(), "中文😀".into()),
        ];
        let message = message(phase, fields.clone(), fields, &budget);
        let compiled = scripts::validate_source(&source(array)).unwrap();
        assert!(!compiled.needs_jsc_for_business(BodyMode::Text, phase));
        assert!(selected(&compiled, &message));
        let (output, bytes) = compare_actual_jsc(&compiled, &message, &budget).await;
        assert_eq!(output["type"], "modify");
        assert_eq!(bytes, "中文_😀".as_bytes());
    }
    for (phase, array) in [
        (Phase::Request, "request"),
        (Phase::Response, "request"),
        (Phase::Response, "response"),
    ] {
        let budget = Budget::default();
        let message = message(phase, vec![], vec![], &budget);
        let compiled = scripts::validate_source(&source(array)).unwrap();
        assert!(selected(&compiled, &message));
        let (output, bytes) = compare_actual_jsc(&compiled, &message, &budget).await;
        assert_eq!(output["type"], "pass");
        assert!(bytes.is_empty());
    }
}

#[test]
fn metadata_byte_boundary_is_checked_before_a_guard_can_execute() {
    let budget = Budget::default();
    let value = "v".repeat(headers::MAX_BYTES - "x-limit".len() - 32);
    let mut message = message(
        Phase::Response,
        vec![],
        vec![("X-Limit".into(), value)],
        &budget,
    );
    let compiled = scripts::validate_source(&source("response")).unwrap();
    assert!(selected(&compiled, &message));
    message
        .response
        .as_mut()
        .unwrap()
        .headers
        .push(("x-extra".into(), String::new()));
    assert!(message.metadata(BodyMode::Text).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn guard_reads_the_current_native_and_previous_script_header_snapshot() {
    let budget = Budget::default();
    let mut message = message(Phase::Response, vec![], vec![], &budget);
    let url = message.original.url.clone();
    let raw: rules::RawRule = serde_json::from_value(
        json!({"url":".","action":"response-header-add","header":"X-Check","value":"other"}),
    )
    .unwrap();
    let rule = rules::Rule::compile(raw, &mut 0).unwrap();
    assert_eq!(
        headers::apply(
            &[rule],
            &url,
            Phase::Response,
            &mut message.response.as_mut().unwrap().headers
        ),
        headers::Outcome::Changed
    );
    let compiled = scripts::validate_source(&source("response")).unwrap();
    let (output, _) = compare_actual_jsc(&compiled, &message, &budget).await;
    assert_eq!(output["type"], "pass");
    let output: ScriptOutput = serde_json::from_value(
        json!({"type":"modify","headers":[{"op":"set","name":"X-Check","values":["中文😀"]}]}),
    )
    .unwrap();
    assert!(matches!(
        message
            .apply(output, BudgetedBytes::empty(&budget), BodyMode::Text)
            .unwrap(),
        Outcome::Forward
    ));
    let (output, bytes) = compare_actual_jsc(&compiled, &message, &budget).await;
    assert_eq!(output["type"], "modify");
    assert_eq!(bytes, "中文_😀".as_bytes());
}

#[tokio::test(flavor = "current_thread")]
async fn request_phase_response_guard_keeps_the_actual_jsc_exception() {
    let budget = Budget::default();
    let message = message(Phase::Request, vec![], vec![], &budget);
    let compiled = scripts::validate_source(&source("response")).unwrap();
    assert!(compiled.needs_jsc_for_business(BodyMode::Text, Phase::Request));
    let metadata = message.metadata(BodyMode::Text).unwrap();
    let entity = message.body.as_ref().unwrap();
    let input = entity.borrowed_body().unwrap();
    let before = entity.wire().clone();
    let bound = compiled.maximum_output_bytes(input.as_bytes().len());
    let mut output = BudgetedBytes::new(&budget, output_capacity(bound).unwrap()).unwrap();
    let bridge = budget
        .reserve(
            BridgePlan::new(input.as_bytes().len(), true, bound)
                .unwrap()
                .cost()
                .unwrap(),
        )
        .unwrap();
    scripts::prepare_platform(&CancellationToken::new()).unwrap();
    let backend = compiled.backend(&metadata, Some(input));
    assert!(!backend.is_plan());
    assert!(
        scripts::evaluate_backend_until(
            backend,
            &metadata,
            Some(input),
            &mut output,
            Some(&bridge),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    assert!(output.as_ref().is_empty());
    assert_eq!(
        message.body.as_ref().unwrap().wire().as_ptr(),
        before.as_ptr()
    );
}
