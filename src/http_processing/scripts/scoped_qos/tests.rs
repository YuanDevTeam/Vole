use super::*;
use crate::http_processing::{
    body_budget::{Budget, BudgetedBytes},
    scripts,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_util::sync::CancellationToken;

#[test]
fn failed_qos_request_preserves_original_success_and_error_results() {
    LAST_REQUEST.with(|slot| slot.set(None));
    let success = run_with_request(|| libc::EPERM, || Ok::<_, io::Error>(37));
    assert_eq!(success.unwrap(), 37);
    assert_eq!(LAST_REQUEST.with(std::cell::Cell::take), Some(libc::EPERM));
    let failure = run_with_request(
        || libc::EINVAL,
        || Err::<(), _>(io::Error::from(io::ErrorKind::InvalidData)),
    );
    assert_eq!(failure.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(LAST_REQUEST.with(std::cell::Cell::take), Some(libc::EINVAL));
}

#[test]
fn real_qos_request_is_on_disposable_owner_without_changing_parent_requested_class() {
    LAST_REQUEST.with(|slot| slot.set(None));
    let parent_thread = std::thread::current().id();
    let parent_before = requested();
    let (owner_thread, name, return_code, after_request) = scripts::run_on_scoped_thread(|| {
        Ok((
            std::thread::current().id(),
            std::thread::current().name().map(str::to_owned),
            LAST_REQUEST.with(std::cell::Cell::get),
            requested(),
        ))
    })
    .unwrap();
    let parent_after = requested();
    assert_ne!(owner_thread, parent_thread);
    assert_eq!(name.as_deref(), Some("vole-http-js"));
    let return_code =
        return_code.expect("the real disposable owner must request QoS before operation");
    if return_code == 0 && after_request.return_code == 0 {
        assert_eq!(after_request.value, Some((USER_INITIATED, 0)));
    }
    // A nonzero return remains observable, rather than inventing a successful
    // effective class; candidate admission does not depend on OS policy.
    if parent_before.return_code == 0 && parent_after.return_code == 0 {
        assert_eq!(parent_before.value, parent_after.value);
    }
    assert_eq!(LAST_REQUEST.with(std::cell::Cell::take), None);
}

#[test]
fn scoped_qos_owner_still_joins_tls_destructors_and_preserves_panic_payload() {
    struct AtExit(Arc<AtomicBool>);
    impl Drop for AtExit {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    thread_local! { static EXIT: std::cell::RefCell<Option<AtExit>> = const { std::cell::RefCell::new(None) }; }
    let exited = Arc::new(AtomicBool::new(false));
    let observed = exited.clone();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scripts::run_on_scoped_thread::<()>(move || {
            EXIT.with(|slot| *slot.borrow_mut() = Some(AtExit(observed)));
            assert!(LAST_REQUEST.with(std::cell::Cell::get).is_some());
            std::panic::panic_any(812_u32);
        })
    }))
    .expect_err("scoped panic must reach the original caller");
    assert_eq!(
        *panic
            .downcast::<u32>()
            .expect("panic payload must remain unchanged"),
        812
    );
    assert!(
        exited.load(Ordering::SeqCst),
        "actual TLS destructors must finish before join returns"
    );
}

#[test]
fn warmup_named_scoped_owner_does_not_request_qos() {
    LAST_REQUEST.with(|slot| slot.set(None));
    let parent = std::thread::current().id();
    let before = requested();
    // Actual platform preparation uses this same named helper, not the
    // user-execution wrapper. This test performs no JSC initialization.
    let (owner, name, request) = scripts::run_on_scoped_thread_named("vole-http-js-init", || {
        Ok((
            std::thread::current().id(),
            std::thread::current().name().map(str::to_owned),
            LAST_REQUEST.with(std::cell::Cell::get),
        ))
    })
    .unwrap();
    assert_ne!(owner, parent);
    assert_eq!(name.as_deref(), Some("vole-http-js-init"));
    assert_eq!(request, None);
    assert_eq!(LAST_REQUEST.with(std::cell::Cell::take), None);
    let after = requested();
    if before.return_code == 0 && after.return_code == 0 {
        assert_eq!(before.value, after.value);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn inline_jsc_keeps_its_thread_without_any_qos_request() {
    LAST_REQUEST.with(|slot| slot.set(None));
    let first_tick = Arc::new(AtomicBool::new(false));
    let tick_seen = first_tick.clone();
    scripts::apple::on_first_tick_for_test(move || tick_seen.store(true, Ordering::SeqCst));
    let source =
        scripts::validate_source("function rewrite(input){return {type:'pass'};}").unwrap();
    let budget = Budget::default();
    let mut output = BudgetedBytes::empty(&budget);
    let result = scripts::evaluate(
        &source,
        &serde_json::json!({}),
        None,
        &mut output,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(result.unwrap(), serde_json::json!({"type":"pass"}));
    assert!(
        first_tick.load(Ordering::SeqCst),
        "JSC must remain on the current thread's hook"
    );
    assert_eq!(LAST_REQUEST.with(std::cell::Cell::take), None);
    assert_eq!(budget.used(), 0);
}
