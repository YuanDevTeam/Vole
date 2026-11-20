//! Unexecuted memory-only candidate regressions. No sockets or peers.
use super::*;

#[test]
fn borrowed_input_admits_at_the_same_budget_where_a_real_input_copy_cannot() {
    const LENGTH: usize = 65536;
    let budget = Budget::default();
    let original = BudgetedBytes::copy(&budget, &vec![b'a'; LENGTH])
        .unwrap()
        .into_bytes();
    let original_slice = original.slice(1..2);
    let original_cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
    let output_cost =
        BudgetedBytes::allocation_cost(super::super::body_budget::output_capacity(LENGTH).unwrap())
            .unwrap();
    let bridge_cost = super::super::body_budget::BridgePlan::new(LENGTH, true, LENGTH)
        .unwrap()
        .cost()
        .unwrap();
    let borrowed_cost = output_cost + bridge_cost;
    let copied_cost = original_cost + borrowed_cost;
    let occupied = budget
        .reserve(super::super::body_budget::WORKSPACE - original_cost - copied_cost + 1)
        .unwrap();
    let before = budget.used();

    // Materialize the removed copy, rather than merely comparing formulas.
    // With that actual owner retained, the unchanged output+bridge cannot fit.
    let copied_input = BudgetedBytes::copy(&budget, &original).unwrap();
    assert!(
        CallBuffers::with_output_bound(&budget, Some(&original), BodyMode::Text, LENGTH).is_err()
    );
    drop(copied_input);
    assert_eq!(budget.used(), before);

    // The old production CallBuffers also fails this assertion: available
    // budget is exactly one byte short of its combined copied-input charge.
    let mut buffers =
        CallBuffers::with_output_bound(&budget, Some(&original), BodyMode::Text, LENGTH)
            .expect("an already charged immutable input needs no second Rust copy");
    assert_eq!(budget.used(), before + borrowed_cost);
    buffers.output.extend(&vec![b'b'; LENGTH]).unwrap();
    let CallBuffers {
        output,
        bridge_workspace,
        ..
    } = buffers;
    drop(bridge_workspace);
    let output = output.into_bytes();
    let output_slice = output.slice(1..2);
    drop(occupied);
    assert_eq!(budget.used(), original_cost + output_cost);
    drop(original);
    assert_eq!(budget.used(), original_cost + output_cost);
    drop(original_slice);
    assert_eq!(budget.used(), output_cost);
    drop(output);
    assert_eq!(budget.used(), output_cost);
    assert_eq!(output_slice.as_ref(), b"b");
    drop(output_slice);
    assert_eq!(budget.used(), 0);
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "current_thread")]
async fn borrowed_input_production_text_unicode_nul_and_writable_bytes_stay_isolated() {
    let cases: &[(BodyMode, &str, &[u8], &[u8])] = &[
        (
            BodyMode::Text,
            "function rewrite(input){input.body.data='after\\u0000caf\\u00e9\\ud83d\\ude00';return {type:'modify',body:{kind:'text',data:input.body.data}};}",
            "before\0café😀".as_bytes(),
            "after\0café😀".as_bytes(),
        ),
        (
            BodyMode::Bytes,
            "function rewrite(input){input.body.data[1]=90;return {type:'modify',body:{kind:'bytes',data:input.body.data}};}",
            &[0, 1, 255, 0, 2],
            &[0, 90, 255, 0, 2],
        ),
    ];
    for &(mode, source, input, expected) in cases {
        let mode_name = match mode {
            BodyMode::Text => "text",
            BodyMode::Bytes => "bytes",
            BodyMode::None => unreachable!(),
        };
        let policy = Policy::compile(&format!(
            "http-scripts:\n  enabled: true\n  scripts:\n    - name: owned-input\n      phase: request\n      match: exact\n      url: https://borrowed.example/path\n      body: {mode_name}\n      source: {}\n",
            serde_json::to_string(source).unwrap(),
        ))
        .unwrap();
        let url = Url::parse("https://borrowed.example/path").unwrap();
        let entity = Entity::identity(BudgetedBytes::copy(policy.body_budget(), input).unwrap());
        let original_owner = entity.wire().clone();
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
        assert!(matches!(
            run(&policy, &url, &mut message, &CancellationToken::new())
                .await
                .unwrap(),
            Outcome::Forward
        ));
        assert_eq!(original_owner.as_ref(), input);
        assert_eq!(message.body.as_ref().unwrap().logical().unwrap(), expected);
        assert_ne!(
            original_owner.as_ptr(),
            message.body.as_ref().unwrap().wire().as_ptr()
        );
    }
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "current_thread")]
async fn borrowed_input_mutation_then_invalid_result_keeps_the_original_entity() {
    let policy = Policy::compile(
        r#"http-scripts:
  enabled: true
  scripts:
    - name: reject-after-input-mutation
      phase: request
      match: exact
      url: https://borrowed.example/path
      body: bytes
      source: 'function rewrite(input){input.body.data[0]=90;return {type:"modify",headers:[{op:"set",name:"host",values:["rejected.example"]}],body:{kind:"bytes",data:input.body.data}};}'
"#,
    )
    .unwrap();
    let url = Url::parse("https://borrowed.example/path").unwrap();
    let input = [1, 2, 255, 0];
    let entity = Entity::identity(BudgetedBytes::copy(policy.body_budget(), &input).unwrap());
    let original_owner = entity.wire().clone();
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
    let original_headers = message.request.headers.clone();
    assert!(matches!(
        run(&policy, &url, &mut message, &CancellationToken::new())
            .await
            .unwrap(),
        Outcome::Forward
    ));
    assert_eq!(message.body.as_ref().unwrap().logical().unwrap(), input);
    assert_eq!(
        message.body.as_ref().unwrap().wire().as_ptr(),
        original_owner.as_ptr()
    );
    assert_eq!(message.request.headers, original_headers);
    assert_eq!(original_owner.as_ref(), input);
}

#[cfg(target_vendor = "apple")]
#[test]
fn static_plan_admission_pays_real_output_without_a_jsc_bridge() {
    const LENGTH: usize = 65536;
    let budget = Budget::default();
    let entity = Entity::identity(BudgetedBytes::copy(&budget, &vec![b'-'; LENGTH]).unwrap());
    let source = super::super::scripts::validate_source("function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('-', '_')}};}").unwrap();
    let metadata = json!({"body":{"kind":"text"}});
    let backend = source.backend(&metadata, entity.borrowed_body());
    assert!(backend.is_plan());
    let input_cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
    let output_cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
    let blocker = budget
        .reserve(super::super::body_budget::WORKSPACE - input_cost - output_cost)
        .unwrap();
    assert!(
        CallBuffers::with_output_bound(&budget, entity.logical(), BodyMode::Text, LENGTH).is_err()
    );
    let buffers =
        CallBuffers::for_backend(&budget, entity.logical(), BodyMode::Text, backend).unwrap();
    assert!(buffers.bridge_workspace.is_none());
    assert_eq!(buffers.output.remaining(), LENGTH);
    assert_eq!(budget.used(), super::super::body_budget::WORKSPACE);
    drop((buffers, blocker, entity));
    assert_eq!(budget.used(), 0);
}
