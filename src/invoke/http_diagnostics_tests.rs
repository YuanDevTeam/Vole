// Included inside invoke::tests so the existing lifecycle test lock is shared.
// These tests read JSON and atomics only; they never initialize or start Core.

const HTTP_DIAGNOSTICS_REQUEST: &[u8] =
    br#"{"method":"getHttpDiagnostics","payload":{}}"#;

fn http_diagnostics_response(request: &[u8], owned: bool) -> Value {
    let bytes = if owned {
        super::invoke_owned_bytes(request.to_vec())
    } else {
        super::invoke_bytes(request)
    };
    serde_json::from_slice(&bytes).unwrap()
}

#[cfg(not(feature = "http-diagnostics"))]
#[test]
fn http_diagnostics_is_unknown_without_the_feature() {
    let _guard = TEST_LOCK.lock().unwrap();
    let registry_before = super::REGISTRY.get().map(std::ptr::from_ref);
    for owned in [false, true] {
        let response = http_diagnostics_response(HTTP_DIAGNOSTICS_REQUEST, owned);
        assert_failure(&response);
        assert!(response["error"].as_str().unwrap().contains(
            "unknown method `getHttpDiagnostics`"
        ));
    }
    assert_eq!(super::REGISTRY.get().map(std::ptr::from_ref), registry_before);
}

#[test]
fn http_diagnostics_cannot_reenter_from_a_runtime_thread() {
    // Both builds must preserve the shared admission rule, even for reads.
    let _runtime_thread = super::RuntimeThreadGuard::enter();
    for owned in [false, true] {
        let bytes = if owned {
            super::invoke_owned_bytes(HTTP_DIAGNOSTICS_REQUEST.to_vec())
        } else {
            super::invoke_bytes(HTTP_DIAGNOSTICS_REQUEST)
        };
        assert_eq!(bytes, super::runtime_thread_response());
    }
}

#[cfg(feature = "http-diagnostics")]
fn http_diagnostics_registry_state() -> Option<(usize, bool, Option<u64>, u64)> {
    super::REGISTRY.get().map(|registry| {
        (
            std::ptr::from_ref(registry) as usize,
            super::lock(&registry.runtime_data).is_some(),
            super::lock(&registry.inner).instance.as_ref().map(|value| value.id),
            registry.next_id.load(Ordering::Relaxed),
        )
    })
}

#[cfg(feature = "http-diagnostics")]
#[test]
fn http_diagnostics_reads_without_initialization_or_resources() {
    use crate::resources::observation::ResourceProbe;

    let _guard = TEST_LOCK.lock().unwrap();
    let registry_before = http_diagnostics_registry_state();
    let probe = ResourceProbe::default();
    let resources_before = probe.snapshot();
    let queues_before = probe.queues();
    for owned in [false, true] {
        let response = probe.scope_sync(|| {
            http_diagnostics_response(HTTP_DIAGNOSTICS_REQUEST, owned)
        });
        assert_eq!(response.as_object().unwrap().len(), 3);
        assert_eq!(response["success"], true);
        assert_eq!(response["error"], "");
        let data = &response["data"];
        assert!(data["scope"].as_str().unwrap().contains("process-lifetime"));
        for name in ["counters", "timings", "stages", "callBuffers", "bodyBypasses"] {
            assert!(data[name].is_object(), "missing aggregate {name}");
        }
        for counter in ["callBuffersBudgetRejected", "queueTimeout", "evaluationEntered"] {
            assert!(data["counters"][counter].is_u64(), "missing counter {counter}");
        }
        for stage in ["contextAndCallback", "prelude", "program", "input", "invokeAndFinish", "export"] {
            for outcome in ["succeeded", "failed"] {
                for aggregate in ["count", "total", "max"] {
                    assert!(data["stages"][stage][outcome][aggregate].is_u64());
                }
            }
        }
        assert!(data["bodyWorkspace"]["current"].is_u64());
        assert!(data["contexts"]["current"].is_u64());
        assert!(data["queue"]["current"].is_u64());
        assert!(data.get("instanceId").is_none());
        // Fixed aggregate data cannot become per-request retained observations.
        assert!(serde_json::to_vec(&response).unwrap().len() < 64 * 1024);
    }
    assert_eq!(http_diagnostics_registry_state(), registry_before);
    assert_eq!(probe.snapshot(), resources_before);
    assert_eq!(probe.queues(), queues_before);
}

#[cfg(feature = "http-diagnostics")]
#[test]
fn http_diagnostics_rejects_instance_reset_and_unknown_envelope_or_payload() {
    let _guard = TEST_LOCK.lock().unwrap();
    let registry_before = http_diagnostics_registry_state();
    for request in [
        r#"{"method":"getHttpDiagnostics","instanceId":"1","payload":{}}"#,
        r#"{"method":"getHttpDiagnostics","instanceId":"","payload":{}}"#,
        r#"{"method":"getHttpDiagnostics","instanceId":null,"payload":{}}"#,
        r#"{"method":"getHttpDiagnostics","payload":{"reset":true}}"#,
        r#"{"method":"getHttpDiagnostics","payload":{"windowID":"test"}}"#,
        r#"{"method":"getHttpDiagnostics","payload":{},"revision":1}"#,
        r#"{"method":"getHttpDiagnostics","payload":null}"#,
        r#"{"method":"getHttpDiagnostics","payload":[]}"#,
        r#"{"method":"getHttpDiagnostics","payload":""}"#,
        r#"{"method":"getHttpDiagnostics"}"#,
        r#"{"method":"getHttpDiagnostics","payload":{},"payload":{}}"#,
    ] {
        let borrowed = http_diagnostics_response(request.as_bytes(), false);
        let owned = http_diagnostics_response(request.as_bytes(), true);
        assert_failure(&borrowed);
        assert_eq!(borrowed, owned);
    }
    assert_eq!(http_diagnostics_registry_state(), registry_before);
}
