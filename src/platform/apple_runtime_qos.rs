//! Best-effort public Apple QoS on fresh Core-owned runtime threads only.
use libc::{c_int, c_uint};

const USER_INITIATED: c_uint = 0x19;
unsafe extern "C" {
    fn pthread_set_qos_class_self_np(class: c_uint, relative_priority: c_int) -> c_int;
    #[cfg(any(test, feature = "http-diagnostics"))]
    fn pthread_get_qos_class_np(
        thread: libc::pthread_t,
        class: *mut c_uint,
        relative: *mut c_int,
    ) -> c_int;
}

#[derive(Clone, Copy)]
pub(crate) enum Role {
    EngineOwner,
    Tokio,
}

/// Only call from the engine's fresh std-thread closure or Tokio start hook.
/// No caller/host thread is promoted, and this never affects startup success.
pub(crate) fn request(role: Role) {
    #[cfg(any(test, feature = "http-diagnostics"))]
    let before = requested();
    // SAFETY: public current-thread API; SDK USER_INITIATED and relative zero.
    // Callers own this fresh thread until real engine/runtime shutdown joins it.
    let code = unsafe { pthread_set_qos_class_self_np(USER_INITIATED, 0) };
    #[cfg(any(test, feature = "http-diagnostics"))]
    stats(role).record(before, code, requested());
    #[cfg(not(any(test, feature = "http-diagnostics")))]
    let _ = (role, code);
}

#[cfg(any(test, feature = "http-diagnostics"))]
#[derive(Clone, Copy)]
struct Requested {
    code: c_int,
    value: Option<(c_uint, c_int)>,
}

#[cfg(any(test, feature = "http-diagnostics"))]
fn requested() -> Requested {
    let (mut class, mut relative) = (0, 0);
    // SAFETY: pthread_self is this live owned thread, outputs are valid scalars.
    let code = unsafe { pthread_get_qos_class_np(libc::pthread_self(), &mut class, &mut relative) };
    Requested {
        code,
        value: (code == 0).then_some((class, relative)),
    }
}

#[cfg(any(test, feature = "http-diagnostics"))]
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

#[cfg(any(test, feature = "http-diagnostics"))]
struct Stats {
    requests: AtomicU64,
    succeeded: AtomicU64,
    failed: AtomicU64,
    before_error: AtomicU64,
    after_error: AtomicU64,
    verified: AtomicU64,
    last_set_code: AtomicI32,
    last_failed_set_code: AtomicI32,
    before_classes: [AtomicU64; 7],
    after_classes: [AtomicU64; 7],
}

#[cfg(any(test, feature = "http-diagnostics"))]
impl Stats {
    const fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            succeeded: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            before_error: AtomicU64::new(0),
            after_error: AtomicU64::new(0),
            verified: AtomicU64::new(0),
            last_set_code: AtomicI32::new(0),
            last_failed_set_code: AtomicI32::new(0),
            before_classes: [const { AtomicU64::new(0) }; 7],
            after_classes: [const { AtomicU64::new(0) }; 7],
        }
    }
    fn class(query: Requested, errors: &AtomicU64, classes: &[AtomicU64; 7]) {
        if query.code != 0 || query.value.is_none() {
            errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let index = match query.value.map(|value| value.0) {
            Some(0) => 0,
            Some(9) => 1,
            Some(17) => 2,
            Some(21) => 3,
            Some(25) => 4,
            Some(33) => 5,
            _ => 6,
        };
        classes[index].fetch_add(1, Ordering::Relaxed);
    }
    fn record(&self, before: Requested, code: c_int, after: Requested) {
        // The API returns errno directly; never sample last_os_error here.
        self.last_set_code.store(code, Ordering::Relaxed);
        if code != 0 {
            self.last_failed_set_code.store(code, Ordering::Relaxed);
        }
        self.requests.fetch_add(1, Ordering::Relaxed);
        let counter = if code == 0 {
            &self.succeeded
        } else {
            &self.failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
        Self::class(before, &self.before_error, &self.before_classes);
        Self::class(after, &self.after_error, &self.after_classes);
        if code == 0 && after.code == 0 && after.value == Some((USER_INITIATED, 0)) {
            self.verified.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[cfg(feature = "http-diagnostics")]
    fn snapshot(&self) -> serde_json::Value {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        let classes = |values: &[AtomicU64; 7]| {
            serde_json::json!({
            "unspecified":load(&values[0]), "background":load(&values[1]), "utility":load(&values[2]),
            "default":load(&values[3]), "userInitiated":load(&values[4]),
            "userInteractive":load(&values[5]), "other":load(&values[6])})
        };
        serde_json::json!({"requests":load(&self.requests), "setSucceeded":load(&self.succeeded),
            "setFailed":load(&self.failed), "beforeQueryFailed":load(&self.before_error),
            "afterQueryFailed":load(&self.after_error), "verifiedRequestedAfterSet":load(&self.verified),
            "lastSetReturnCode":(load(&self.requests) != 0).then(|| self.last_set_code.load(Ordering::Relaxed)),
            "lastFailedSetReturnCode":(load(&self.failed) != 0).then(|| self.last_failed_set_code.load(Ordering::Relaxed)),
            "beforeRequestedClasses":classes(&self.before_classes), "afterRequestedClasses":classes(&self.after_classes)})
    }
}

#[cfg(any(test, feature = "http-diagnostics"))]
fn stats(role: Role) -> &'static Stats {
    static OWNER: Stats = Stats::new();
    static TOKIO: Stats = Stats::new();
    match role {
        Role::EngineOwner => &OWNER,
        Role::Tokio => &TOKIO,
    }
}

#[cfg(feature = "http-diagnostics")]
pub(crate) fn snapshot() -> serde_json::Value {
    serde_json::json!({"enabled":true, "targetRequestedClass":USER_INITIATED,
        "targetRequestedRelativePriority":0, "effectiveClassAvailable":false, "cpuPlacementAvailable":false,
        "scope":"fresh Core engine owner and its Tokio threads only; excludes host/caller, preparation, current-thread measurements and disposable script owners",
        "units":"process-lifetime fixed counts; before/after requested-class histograms; quiescent snapshots required for conservation",
        "engineOwner":stats(Role::EngineOwner).snapshot(), "tokioThreads":stats(Role::Tokio).snapshot()})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn current() -> (c_int, Option<(c_uint, c_int)>) {
        let observation = requested();
        (observation.code, observation.value)
    }

    #[test]
    fn owned_thread_request_preserves_the_host_calling_thread() {
        let caller = current();
        assert_eq!(caller.0, 0);
        std::thread::spawn(|| {
            request(Role::EngineOwner);
            assert_eq!(current(), (0, Some((USER_INITIATED, 0))));
        })
        .join()
        .unwrap();
        assert_eq!(current(), caller);
    }

    #[test]
    fn runtime_hook_covers_scheduler_and_blocking_threads_without_promoting_the_caller() {
        let caller = current();
        assert_eq!(caller.0, 0);
        let runtime = crate::invoke::engine_runtime_builder()
            .worker_threads(1)
            .max_blocking_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert_eq!(
                tokio::spawn(async { current() }).await.unwrap(),
                (0, Some((USER_INITIATED, 0)))
            );
            assert_eq!(
                tokio::task::spawn_blocking(current).await.unwrap(),
                (0, Some((USER_INITIATED, 0)))
            );
            assert_eq!(current(), caller);
        });
        drop(runtime);
        assert_eq!(current(), caller);
    }

    fn query(code: c_int, value: Option<(c_uint, c_int)>) -> Requested {
        Requested { code, value }
    }
    #[test]
    fn successful_request_requires_a_successful_target_getter() {
        let stats = Stats::new();
        stats.record(
            query(0, Some((21, 0))),
            0,
            query(0, Some((USER_INITIATED, 0))),
        );
        assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
        assert_eq!(stats.verified.load(Ordering::Relaxed), 1);
        assert_eq!(stats.before_classes[3].load(Ordering::Relaxed), 1);
        assert_eq!(stats.after_classes[4].load(Ordering::Relaxed), 1);
    }
    #[test]
    fn failure_or_getter_error_never_becomes_verified_success() {
        let stats = Stats::new();
        stats.record(query(5, None), 22, query(0, Some((USER_INITIATED, 0))));
        stats.record(query(0, Some((21, 0))), 0, query(5, None));
        stats.record(
            query(0, Some((21, 0))),
            0,
            query(0, Some((USER_INITIATED, -1))),
        );
        assert_eq!(stats.requests.load(Ordering::Relaxed), 3);
        assert_eq!(stats.succeeded.load(Ordering::Relaxed), 2);
        assert_eq!(stats.failed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.before_error.load(Ordering::Relaxed), 1);
        assert_eq!(stats.after_error.load(Ordering::Relaxed), 1);
        assert_eq!(stats.verified.load(Ordering::Relaxed), 0);
        assert_eq!(stats.last_set_code.load(Ordering::Relaxed), 0);
        assert_eq!(stats.last_failed_set_code.load(Ordering::Relaxed), 22);
    }
}
