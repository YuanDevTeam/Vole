//! Memory-only mapped script-output ownership and transaction regressions.
use super::*;

const LENGTH: usize = 64 * 1024;

fn mapped(budget: &Budget, value: &[u8]) -> BudgetedBytes {
    assert_eq!(value.len(), LENGTH);
    let cost = BudgetedBytes::allocation_cost(value.len()).unwrap();
    let reservation = budget.reserve(cost).unwrap();
    let mut output = BudgetedBytes::from_reserved_fixed_output(reservation, value.len()).unwrap();
    assert!(
        output.is_mapped_for_test(),
        "must test actual mapped storage"
    );
    output
        .write_initialized_output(value.len(), |target| {
            target.copy_from_slice(value);
            Ok(value.len())
        })
        .unwrap();
    output
}

fn request_with(body: BudgetedBytes) -> Message {
    let url = Url::parse("https://a.example/path").unwrap();
    let fields = vec![
        ("authorization".into(), "old-secret".into()),
        ("cookie".into(), "a=1".into()),
    ];
    Message::request(
        OriginalSnapshot {
            url: url.clone(),
            method: "GET".into(),
            identity_allowed: true,
            asterisk: false,
        },
        RequestSnapshot {
            url,
            method: "GET".into(),
            headers: fields.clone(),
        },
        Some(Entity::identity(body)),
        &fields,
        false,
    )
}

fn output(value: Value) -> ScriptOutput {
    serde_json::from_value(value).unwrap()
}

#[test]
fn rejected_mapped_text_preserves_prior_body_headers_origin_and_owner() {
    let budget = Budget::default();
    let mut message = request_with(BudgetedBytes::copy(&budget, b"original").unwrap());
    let accepted = vec![b'a'; LENGTH];
    assert!(matches!(
        message
            .apply(
                output(json!({
                    "type": "modify",
                    "headers": [{"op": "set", "name": "x-first", "values": ["accepted"]}],
                    "body": {"kind": "text"}
                })),
                mapped(&budget, &accepted),
                BodyMode::Text,
            )
            .unwrap(),
        Outcome::Forward
    ));
    let headers = message.request.headers.clone();
    let owner = message.body.as_ref().unwrap().wire().slice(0..1);
    let pointer = message.body.as_ref().unwrap().wire().as_ptr();
    let cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
    assert_eq!(budget.used(), cost);

    // URL cleanup and header changes are valid candidates; strict text body
    // validation rejects this already-filled, independently owned mapping.
    // None of that invocation's metadata may commit before body validation.
    let mut invalid_text = vec![b'b'; LENGTH];
    invalid_text[0] = 0xff;
    let candidate = mapped(&budget, &invalid_text);
    assert_eq!(budget.used(), 2 * cost);
    assert!(
        message
            .apply(
                output(json!({
                    "type": "modify",
                    "url": "https://b.example/changed",
                    "headers": [{"op": "set", "name": "x-second", "values": ["uncommitted"]}],
                    "body": {"kind": "text"}
                })),
                candidate,
                BodyMode::Text,
            )
            .is_err()
    );
    assert_eq!(message.request.url.as_str(), "https://a.example/path");
    assert_eq!(message.request.headers, headers);
    assert!(!message.crossed_origin);
    assert_eq!(message.body.as_ref().unwrap().logical().unwrap(), accepted);
    assert_eq!(message.body.as_ref().unwrap().wire().as_ptr(), pointer);
    assert_eq!(budget.used(), cost, "rejected candidate alone is refunded");
    drop(message);
    assert_eq!(
        budget.used(),
        cost,
        "actual Bytes slice still owns the mapping"
    );
    assert_eq!(owner.as_ref(), b"a");
    drop(owner);
    assert_eq!(budget.used(), 0);
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "current_thread")]
async fn later_real_plan_reads_mapped_entity_and_preserves_sender_ownership() {
    const SOURCE: &str = "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b')}};}";
    let policy = Policy::compile(&format!(
        "http-scripts:\n  enabled: true\n  scripts:\n    - name: read-owned-body\n      phase: request\n      match: exact\n      url: https://a.example/path\n      body: text\n      source: {}\n",
        serde_json::to_string(SOURCE).unwrap(),
    ))
    .unwrap();
    let budget = policy.body_budget();
    let initial = vec![b'a'; LENGTH];
    let mut message = request_with(mapped(budget, &initial));
    let original_owner = message.body.as_ref().unwrap().wire().clone();
    let url = message.original.url.clone();
    let metadata = message.metadata(BodyMode::Text).unwrap();
    let compiled = super::super::scripts::validate_source(SOURCE).unwrap();
    assert!(
        compiled
            .backend(
                &metadata,
                message.body.as_ref().and_then(Entity::borrowed_body)
            )
            .is_plan(),
        "the later invocation must read the actual mapped Entity through its ledger witness"
    );
    drop(compiled);

    assert!(matches!(
        run(&policy, &url, &mut message, &CancellationToken::new())
            .await
            .unwrap(),
        Outcome::Forward
    ));
    assert_eq!(original_owner.as_ref(), initial);
    assert_eq!(
        message.body.as_ref().unwrap().logical().unwrap(),
        vec![b'b'; LENGTH]
    );
    assert_ne!(
        original_owner.as_ptr(),
        message.body.as_ref().unwrap().wire().as_ptr()
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let pointer = message.body.as_ref().unwrap().wire().as_ptr();
    assert!(matches!(
        run(&policy, &url, &mut message, &cancelled).await,
        Err(error) if error.kind() == io::ErrorKind::Interrupted
    ));
    assert_eq!(message.body.as_ref().unwrap().wire().as_ptr(), pointer);
    assert_eq!(
        message.body.as_ref().unwrap().logical().unwrap(),
        vec![b'b'; LENGTH]
    );
    let final_owner = message.body.as_ref().unwrap().wire().slice(0..1);
    let cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
    assert_eq!(budget.used(), 2 * cost);
    drop(message);
    assert_eq!(budget.used(), 2 * cost);
    drop(original_owner);
    assert_eq!(budget.used(), cost);
    assert_eq!(final_owner.as_ref(), b"b");
    drop(final_owner);
    assert_eq!(budget.used(), 0);
}
