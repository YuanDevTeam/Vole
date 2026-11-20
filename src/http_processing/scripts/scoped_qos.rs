//! Public Apple QoS request confined to the disposable scoped script owner.
use libc::{c_int, c_uint};

// AppleTVOS SDK sys/qos.h: qos_class_t is unsigned int; USER_INITIATED=0x19.
// pthread/qos.h declares both functions public since macOS10.10/iOS8.
// libc0.2.191 supplies pthread_t/pthread_self but not these QoS declarations.
const USER_INITIATED: c_uint = 0x19;
unsafe extern "C" {
    fn pthread_set_qos_class_self_np(class: c_uint, relative_priority: c_int) -> c_int;
    #[cfg(any(test, feature = "http-diagnostics"))]
    fn pthread_get_qos_class_np(
        thread: libc::pthread_t,
        class: *mut c_uint,
        relative_priority: *mut c_int,
    ) -> c_int;
}

pub(super) fn run<T>(operation: impl FnOnce() -> T) -> T {
    run_with_request(
        || {
            // SAFETY: public current-thread API, valid SDK class/relative0.
            // Its production caller wraps only the user-execution operation
            // on the new scoped owner, never warmup or a persistent worker.
            unsafe { pthread_set_qos_class_self_np(USER_INITIATED, 0) }
        },
        operation,
    )
}

fn run_with_request<T>(request: impl FnOnce() -> c_int, operation: impl FnOnce() -> T) -> T {
    #[cfg(feature = "http-diagnostics")]
    let start = diagnostic::Start::new();
    // A failed scheduling request does not change JavaScript error/fallback
    // semantics. The return value itself is errno, not last_os_error().
    let return_code = request();
    #[cfg(test)]
    LAST_REQUEST.with(|slot| slot.set(Some(return_code)));
    #[cfg(feature = "http-diagnostics")]
    let _guard = diagnostic::Guard::new(start, return_code);
    #[cfg(not(any(test, feature = "http-diagnostics")))]
    let _ = return_code;
    operation()
}

#[cfg(any(test, feature = "http-diagnostics"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Requested {
    return_code: c_int,
    value: Option<(c_uint, c_int)>,
}

#[cfg(any(test, feature = "http-diagnostics"))]
fn requested() -> Requested {
    let mut class = 0;
    let mut relative = 0;
    // SAFETY: pthread_self supplies this live owner; the output pointers are
    // valid initialized scalar storage. Failed queries never expose values.
    let return_code =
        unsafe { pthread_get_qos_class_np(libc::pthread_self(), &mut class, &mut relative) };
    Requested {
        return_code,
        value: (return_code == 0).then_some((class, relative)),
    }
}

#[cfg(test)]
thread_local! {
    static LAST_REQUEST: std::cell::Cell<Option<c_int>> = const { std::cell::Cell::new(None) };
}

#[cfg(feature = "http-diagnostics")]
pub(super) fn snapshot() -> serde_json::Value {
    diagnostic::snapshot()
}

#[cfg(feature = "http-diagnostics")]
mod diagnostic {
    use super::{Requested, USER_INITIATED, c_int, requested};
    use serde_json::{Value, json};
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Instant,
    };

    #[derive(Clone, Copy)]
    pub(super) struct Cpu {
        return_code: c_int,
        nanoseconds: Option<u128>,
    }

    pub(super) fn cpu_sample() -> Cpu {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: public per-current-thread clock and a valid writable timespec.
        let return_code = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
        let nanoseconds =
            if return_code == 0 && time.tv_sec >= 0 && (0..1_000_000_000).contains(&time.tv_nsec) {
                (time.tv_sec as u128)
                    .checked_mul(1_000_000_000)
                    .and_then(|seconds| seconds.checked_add(time.tv_nsec as u128))
            } else {
                None
            };
        Cpu {
            return_code,
            nanoseconds,
        }
    }

    pub(super) fn elapsed_cpu(before: Cpu, after: Cpu) -> Option<u64> {
        let nanoseconds = after.nanoseconds?.checked_sub(before.nanoseconds?)?;
        Some((nanoseconds / 1000).min(u128::from(u64::MAX)) as u64)
    }

    pub(super) struct Start {
        wall: Instant,
        cpu: Cpu,
        before: Requested,
    }
    impl Start {
        pub(super) fn new() -> Self {
            let wall = Instant::now();
            let cpu = cpu_sample();
            let before = requested();
            Self { wall, cpu, before }
        }
    }

    pub(super) struct Guard {
        start: Start,
        return_code: c_int,
        after_request: Requested,
    }
    impl Guard {
        pub(super) fn new(start: Start, return_code: c_int) -> Self {
            Self {
                start,
                return_code,
                after_request: requested(),
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Record {
        before: Requested,
        set_return_code: c_int,
        after_request: Requested,
        after_operation: Requested,
        cpu_before_return_code: c_int,
        cpu_after_return_code: c_int,
        cpu_microseconds: Option<u64>,
        wall_microseconds: u64,
        panicking: bool,
    }

    fn add(counter: &AtomicU64, value: u64) {
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            Some(old.saturating_add(value))
        });
    }

    struct Aggregate {
        count: AtomicU64,
        total: AtomicU64,
        maximum: AtomicU64,
    }
    impl Aggregate {
        const fn new() -> Self {
            Self {
                count: AtomicU64::new(0),
                total: AtomicU64::new(0),
                maximum: AtomicU64::new(0),
            }
        }
        fn record(&self, value: u64) {
            add(&self.count, 1);
            add(&self.total, value);
            self.maximum.fetch_max(value, Ordering::Relaxed);
        }
        fn snapshot(&self) -> Value {
            json!({"count": self.count.load(Ordering::Relaxed), "total": self.total.load(Ordering::Relaxed), "max": self.maximum.load(Ordering::Relaxed)})
        }
    }

    struct Stats {
        completed: AtomicU64,
        set_succeeded: AtomicU64,
        set_failed: AtomicU64,
        before_query_failed: AtomicU64,
        after_query_failed: AtomicU64,
        exit_query_failed: AtomicU64,
        verified_after_request: AtomicU64,
        cpu_unavailable: AtomicU64,
        panicked: AtomicU64,
        last_busy_skipped: AtomicU64,
        wall: Aggregate,
        cpu: Aggregate,
        last: Mutex<Option<Record>>,
    }
    static STATS: Stats = Stats {
        completed: AtomicU64::new(0),
        set_succeeded: AtomicU64::new(0),
        set_failed: AtomicU64::new(0),
        before_query_failed: AtomicU64::new(0),
        after_query_failed: AtomicU64::new(0),
        exit_query_failed: AtomicU64::new(0),
        verified_after_request: AtomicU64::new(0),
        cpu_unavailable: AtomicU64::new(0),
        panicked: AtomicU64::new(0),
        last_busy_skipped: AtomicU64::new(0),
        wall: Aggregate::new(),
        cpu: Aggregate::new(),
        last: Mutex::new(None),
    };

    impl Drop for Guard {
        fn drop(&mut self) {
            // No formatting, body buffers, assertion, API failure propagation or
            // QoS restoration on this normal/error/panic cleanup path. The
            // fresh owner retains the requested class through its TLS exit.
            let after_operation = requested();
            let cpu = cpu_sample();
            let record = Record {
                before: self.start.before,
                set_return_code: self.return_code,
                after_request: self.after_request,
                after_operation,
                cpu_before_return_code: self.start.cpu.return_code,
                cpu_after_return_code: cpu.return_code,
                cpu_microseconds: elapsed_cpu(self.start.cpu, cpu),
                wall_microseconds: self
                    .start
                    .wall
                    .elapsed()
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64,
                panicking: std::thread::panicking(),
            };
            add(&STATS.completed, 1);
            add(
                if record.set_return_code == 0 {
                    &STATS.set_succeeded
                } else {
                    &STATS.set_failed
                },
                1,
            );
            if record.before.return_code != 0 {
                add(&STATS.before_query_failed, 1);
            }
            if record.after_request.return_code != 0 {
                add(&STATS.after_query_failed, 1);
            }
            if record.after_operation.return_code != 0 {
                add(&STATS.exit_query_failed, 1);
            }
            if record.set_return_code == 0
                && record.after_request.value == Some((USER_INITIATED, 0))
            {
                add(&STATS.verified_after_request, 1);
            }
            STATS.wall.record(record.wall_microseconds);
            if let Some(cpu) = record.cpu_microseconds {
                STATS.cpu.record(cpu);
            } else {
                add(&STATS.cpu_unavailable, 1);
            }
            if record.panicking {
                add(&STATS.panicked, 1);
            }
            // Snapshot collection can never block this owner or its unwind.
            match STATS.last.try_lock() {
                Ok(mut last) => *last = Some(record),
                Err(std::sync::TryLockError::Poisoned(error)) => *error.into_inner() = Some(record),
                Err(std::sync::TryLockError::WouldBlock) => add(&STATS.last_busy_skipped, 1),
            }
        }
    }

    fn requested_value(value: Requested) -> Value {
        json!({"queryReturnCode": value.return_code,
            "requestedClass": value.value.map(|(class, _)| class),
            "requestedRelativePriority": value.value.map(|(_, relative)| relative)})
    }
    fn record_value(record: Record) -> Value {
        json!({"before": requested_value(record.before), "setReturnCode": record.set_return_code,
            "afterRequest": requested_value(record.after_request), "afterOperation": requested_value(record.after_operation),
            "threadCpuBeforeReturnCode": record.cpu_before_return_code,
            "threadCpuAfterReturnCode": record.cpu_after_return_code,
            "threadCpuAvailable": record.cpu_microseconds.is_some(), "threadCpuMicroseconds": record.cpu_microseconds,
            "wallMicroseconds": record.wall_microseconds, "panicking": record.panicking})
    }
    pub(super) fn snapshot() -> Value {
        // Copy fixed scalars and release the lock before JSON allocation.
        let last = match STATS.last.try_lock() {
            Ok(last) => *last,
            Err(std::sync::TryLockError::Poisoned(error)) => *error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        json!({"scope": "disposable user-script owner (JSC or static plan) after tracing entry through operation cleanup; excludes warmup, inline execution, spawn, tracing entry/exit, TLS destructors and parent join; process-lifetime fixed aggregates",
            "targetRequestedClass": USER_INITIATED, "targetRequestedRelativePriority": 0,
            "effectiveClassAvailable": false, "effectiveClass": null,
            "effectiveClassScope": "public getter reports requested class, not priority overrides or process scheduling limits",
            "completedOwners": STATS.completed.load(Ordering::Relaxed),
            "setSucceeded": STATS.set_succeeded.load(Ordering::Relaxed), "setFailed": STATS.set_failed.load(Ordering::Relaxed),
            "beforeQueryFailed": STATS.before_query_failed.load(Ordering::Relaxed),
            "afterQueryFailed": STATS.after_query_failed.load(Ordering::Relaxed),
            "exitQueryFailed": STATS.exit_query_failed.load(Ordering::Relaxed),
            "verifiedRequestedAfterSet": STATS.verified_after_request.load(Ordering::Relaxed),
            "threadCpuUnavailable": STATS.cpu_unavailable.load(Ordering::Relaxed), "panickedOwners": STATS.panicked.load(Ordering::Relaxed),
            "lastBusySkipped": STATS.last_busy_skipped.load(Ordering::Relaxed),
            "units": "microseconds; count/total/max are not quantiles",
            "ownerWallAvailable": STATS.wall.count.load(Ordering::Relaxed) > 0,
            "ownerThreadCpuAvailable": STATS.cpu.count.load(Ordering::Relaxed) > 0,
            "ownerWall": STATS.wall.snapshot(), "ownerThreadCpu": STATS.cpu.snapshot(),
            "last": last.map(record_value)})
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn failed_query_and_nonmonotonic_cpu_remain_unavailable_not_zero() {
            let value = requested_value(Requested {
                return_code: libc::EPERM,
                value: None,
            });
            assert!(value["requestedClass"].is_null());
            assert!(value["requestedRelativePriority"].is_null());
            assert_eq!(value["queryReturnCode"], libc::EPERM);
            assert_eq!(
                elapsed_cpu(
                    Cpu {
                        return_code: -1,
                        nanoseconds: None
                    },
                    Cpu {
                        return_code: 0,
                        nanoseconds: Some(2)
                    }
                ),
                None
            );
            assert_eq!(
                elapsed_cpu(
                    Cpu {
                        return_code: 0,
                        nanoseconds: Some(3)
                    },
                    Cpu {
                        return_code: 0,
                        nanoseconds: Some(2)
                    }
                ),
                None
            );
        }
    }
}

#[cfg(test)]
mod tests;

// A synchronous, same-thread operation clock. This never requests or queries
// QoS and never contributes to disposable scoped-owner/setter statistics.
#[cfg(feature = "http-diagnostics")]
pub(super) struct OperationClock {
    wall: std::time::Instant,
    cpu: diagnostic::Cpu,
}
#[cfg(feature = "http-diagnostics")]
impl OperationClock {
    pub(super) fn start() -> Self {
        Self {
            wall: std::time::Instant::now(),
            cpu: diagnostic::cpu_sample(),
        }
    }
    pub(super) fn elapsed(&self) -> (u128, Option<u64>) {
        let cpu = diagnostic::cpu_sample();
        (
            self.wall.elapsed().as_micros(),
            diagnostic::elapsed_cpu(self.cpu, cpu),
        )
    }
}
