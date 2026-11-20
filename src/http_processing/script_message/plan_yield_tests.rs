//! Actual Message futures, without a test hook or a mirrored yield predicate.
use super::*;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};
use tokio::runtime::{Builder, Runtime};

const LENGTH: usize = 65536;
const SOURCE: &str = "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('a','b')}};}";
fn runtime() -> Runtime {
    // Test capability fixture only; no production/benchmark worker override.
    let runtime = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(runtime.handle().metrics().num_workers(), 2);
    runtime
}
fn policy() -> std::sync::Arc<Policy> {
    Policy::compile(&format!(
        "http-scripts:\n  enabled: true\n  scripts:\n    - name: yield-owner\n      phase: request\n      match: exact\n      url: https://a.example/path\n      body: text\n      source: {}\n",
        serde_json::to_string(SOURCE).unwrap(),
    )).unwrap()
}
fn message(policy: &Policy) -> (Message, Bytes, Fields) {
    let url = Url::parse("https://a.example/path").unwrap();
    let body =
        Entity::identity(BudgetedBytes::copy(policy.body_budget(), &vec![b'a'; LENGTH]).unwrap());
    let last = body.wire().slice(0..1);
    let fields = vec![("authorization".into(), "original-secret".into())];
    let message = Message::request(
        OriginalSnapshot {
            url: url.clone(),
            method: "POST".into(),
            identity_allowed: true,
            asterisk: false,
        },
        RequestSnapshot {
            url,
            method: "POST".into(),
            headers: fields.clone(),
        },
        Some(body),
        &fields,
        false,
    );
    let compiled = super::super::scripts::validate_source(SOURCE).unwrap();
    assert!(
        compiled
            .backend(
                &message.metadata(BodyMode::Text).unwrap(),
                message.body.as_ref().and_then(Entity::borrowed_body),
            )
            .is_plan(),
        "fixture must select the actual closed Plan"
    );
    let headers = message.request.headers.clone();
    (message, last, headers)
}
async fn suspend_with_paid_output(
    mut future: Pin<&mut impl Future<Output = io::Result<Outcome>>>,
    budget: &Budget,
    expected: usize,
) {
    // Queue contention may first yield with only Q. Stop only at a real Pending
    // after the full output owner is charged, before synchronous Plan starts.
    poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Pending if budget.used() == expected => Poll::Ready(()),
        Poll::Pending => Poll::Pending,
        Poll::Ready(_) => panic!("Message did not suspend with its paid output"),
    })
    .await;
}
fn unchanged(message: &Message, headers: &Fields, pointer: *const u8) {
    assert_eq!(message.request.url.as_str(), "https://a.example/path");
    assert_eq!(message.original.url, message.request.url);
    assert_eq!(message.request.method, "POST");
    assert_eq!(&message.request.headers, headers);
    assert!(!message.crossed_origin);
    let body = message.body.as_ref().unwrap();
    assert_eq!(body.wire().as_ptr(), pointer);
    assert_eq!(body.logical().unwrap().len(), LENGTH);
    assert!(body.logical().unwrap().iter().all(|byte| *byte == b'a'));
}

#[test]
fn direct_plan_yield_drop_keeps_same_lane_and_refunds_actual_output() {
    let runtime = runtime();
    runtime.block_on(async {
        let policy = policy();
        let budget = policy.body_budget();
        let cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
        let q = BudgetedBytes::allocation_cost(0).unwrap();
        let (mut first, first_last, first_headers) = message(&policy);
        let (mut second, second_last, second_headers) = message(&policy);
        let first_pointer = first.body.as_ref().unwrap().wire().as_ptr();
        let second_pointer = second.body.as_ref().unwrap().wire().as_ptr();
        let url = first.original.url.clone();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut running = Box::pin(run_until(
            &policy,
            &url,
            &mut first,
            &cancellation,
            deadline,
        ));
        suspend_with_paid_output(running.as_mut(), budget, 3 * cost).await;
        let mut waiting = Box::pin(run_until(
            &policy,
            &url,
            &mut second,
            &cancellation,
            deadline,
        ));
        let queued = poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx))).await;
        assert!(matches!(queued, Poll::Pending));
        assert_eq!(
            budget.used(),
            3 * cost + q,
            "second actual Message cannot acquire the same lane/output"
        );
        drop(waiting);
        assert_eq!(budget.used(), 3 * cost);
        unchanged(&second, &second_headers, second_pointer);
        drop(running);
        assert_eq!(
            budget.used(),
            2 * cost,
            "dropped future refunds its real output owner"
        );
        unchanged(&first, &first_headers, first_pointer);
        // A new actual invocation must be healthy: the dropped future released
        // the real permit, rather than only decreasing an accounting number.
        assert!(matches!(
            run_until(&policy, &url, &mut second, &cancellation, deadline)
                .await
                .unwrap(),
            Outcome::Forward
        ));
        assert_eq!(second.request.url.as_str(), "https://a.example/path");
        assert!(
            second
                .body
                .as_ref()
                .unwrap()
                .logical()
                .unwrap()
                .iter()
                .all(|byte| *byte == b'b')
        );
        drop((first, second));
        assert_eq!(
            budget.used(),
            2 * cost,
            "both real original last slices still retain credit"
        );
        assert_eq!(first_last.as_ref(), b"a");
        assert_eq!(second_last.as_ref(), b"a");
        drop(first_last);
        assert_eq!(budget.used(), cost);
        drop(second_last);
        assert_eq!(budget.used(), 0);
    });
    drop(runtime); // Actual normal Runtime drop joins its workers.
}

#[test]
fn direct_plan_yield_cancel_or_original_phase_deadline_rolls_back_before_execution() {
    let runtime = runtime();
    runtime.block_on(async {
        let policy = policy();
        for cancel in [true, false] {
            let budget = policy.body_budget();
            let cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
            let (mut value, last, headers) = message(&policy);
            let pointer = value.body.as_ref().unwrap().wire().as_ptr();
            let url = value.original.url.clone();
            let token = CancellationToken::new();
            let phase_deadline = Instant::now()
                + if cancel {
                    Duration::from_secs(1)
                } else {
                    Duration::from_millis(10)
                };
            let mut running =
                Box::pin(run_until(&policy, &url, &mut value, &token, phase_deadline));
            suspend_with_paid_output(running.as_mut(), budget, 2 * cost).await;
            if cancel {
                token.cancel();
                assert_eq!(
                    budget.used(),
                    2 * cost,
                    "cancellation signal is not owner completion"
                );
            } else {
                // Original phase clock, not a replacement deadline after yield.
                tokio::time::sleep_until(tokio::time::Instant::from_std(phase_deadline)).await;
            }
            let result = running.as_mut().await;
            drop(running);
            let expected = if cancel {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::TimedOut
            };
            assert!(matches!(result, Err(error) if error.kind() == expected));
            assert_eq!(budget.used(), cost);
            unchanged(&value, &headers, pointer);
            drop(value);
            assert_eq!(budget.used(), cost);
            assert_eq!(last.as_ref(), b"a");
            drop(last);
            assert_eq!(budget.used(), 0);
        }
    });
    drop(runtime);
}

#[test]
fn direct_plan_yield_preserves_invocation_expiry_while_original_phase_is_live() {
    let runtime = runtime();
    runtime.block_on(async {
        let policy = policy();
        let budget = policy.body_budget();
        let cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
        let (mut value, last, headers) = message(&policy);
        let pointer = value.body.as_ref().unwrap().wire().as_ptr();
        let url = value.original.url.clone();
        let token = CancellationToken::new();
        let phase_deadline = Instant::now() + Duration::from_secs(1);
        let mut running = Box::pin(run_until(&policy, &url, &mut value, &token, phase_deadline));
        suspend_with_paid_output(running.as_mut(), budget, 2 * cost).await;
        // The original invocation started before this real suspension. Waiting
        // 110ms here exceeds its 100ms bound without expiring the 1s phase.
        tokio::time::sleep(Duration::from_millis(110)).await;
        assert!(
            Instant::now() < phase_deadline,
            "setup no longer isolates invocation expiry"
        );
        assert_eq!(budget.used(), 2 * cost, "sleeping is not owner completion");
        let result = running.as_mut().await;
        drop(running);
        // Invocation timeout is recoverable; phase timeout would be Err.
        assert!(matches!(result, Ok(Outcome::Forward)));
        unchanged(&value, &headers, pointer);
        assert_eq!(budget.used(), cost);
        drop(value);
        assert_eq!(budget.used(), cost);
        assert_eq!(last.as_ref(), b"a");
        drop(last);
        assert_eq!(budget.used(), 0);
    });
    drop(runtime);
}
