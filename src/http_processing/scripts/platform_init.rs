//! Process state only: neither this owner nor Ready retains a JSC object.
use std::{
    io,
    sync::{Condvar, Mutex, MutexGuard},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
enum State {
    Cold,
    Initializing,
    Ready,
}

pub(super) struct Initialization {
    state: Mutex<State>,
    changed: Condvar,
    #[cfg(test)]
    waiting: std::sync::atomic::AtomicUsize,
}

impl Initialization {
    pub(super) const fn new() -> Self {
        Self {
            state: Mutex::new(State::Cold),
            changed: Condvar::new(),
            #[cfg(test)]
            waiting: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Only this private enum is protected. Never permanently cache a
        // poisoned initialization failure or hold this lock across platform API.
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(super) fn ensure(
        &self,
        cancellation: &CancellationToken,
        initialize: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut state = self.lock();
        // An initially cancelled caller never joins an attempt. Once a caller
        // has observed Initializing, spurious wakes must not let it escape the
        // real initializer's joined completion barrier.
        if cancellation.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        loop {
            match *state {
                State::Ready | State::Cold => {
                    if cancellation.is_cancelled() {
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                    if matches!(*state, State::Ready) {
                        return Ok(());
                    }
                    *state = State::Initializing;
                    break;
                }
                State::Initializing => {
                    // An in-flight platform API cannot be interrupted. Wait
                    // for its actual joined end before observing cancellation.
                    #[cfg(test)]
                    self.waiting
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    state = self
                        .changed
                        .wait(state)
                        .unwrap_or_else(|error| error.into_inner());
                    #[cfg(test)]
                    self.waiting
                        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        drop(state);
        let mut attempt = Attempt {
            owner: self,
            finished: false,
        };
        let result = initialize();
        attempt.finish(result.is_ok());
        // Successful platform initialization remains Ready even if its caller
        // was cancelled while the thread was running. No user VM is retained.
        if cancellation.is_cancelled() {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            result
        }
    }
}

struct Attempt<'a> {
    owner: &'a Initialization,
    finished: bool,
}
impl Attempt<'_> {
    fn finish(&mut self, successful: bool) {
        *self.owner.lock() = if successful {
            State::Ready
        } else {
            State::Cold
        };
        self.finished = true;
        self.owner.changed.notify_all();
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // The scoped worker has already joined before unwinding reaches
            // this guard; a later preparation may retry a failed attempt.
            self.finish(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    #[test]
    fn platform_initialization_cancelled_waiter_survives_spurious_wake_until_join() {
        let initialization = Arc::new(Initialization::new());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let owner = {
            let initialization = initialization.clone();
            let entered = entered.clone();
            let release = release.clone();
            std::thread::spawn(move || {
                initialization.ensure(&CancellationToken::new(), || {
                    entered.wait();
                    release.wait();
                    Ok(())
                })
            })
        };
        entered.wait();
        let cancellation = CancellationToken::new();
        let (finished, finishes) = mpsc::channel();
        let waiter = {
            let initialization = initialization.clone();
            let cancellation = cancellation.clone();
            std::thread::spawn(move || {
                let result = initialization.ensure(&cancellation, || panic!("second initializer"));
                finished.send(result.map_err(|error| error.kind())).unwrap();
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while initialization.waiting.load(Ordering::SeqCst) == 0
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        let observed_waiter = initialization.waiting.load(Ordering::SeqCst) > 0;
        {
            // Lock acquisition also waits for the waiter to enter its real
            // Condvar wait and release this mutex; the wake cannot be missed.
            let _state = initialization.lock();
            cancellation.cancel();
            initialization.changed.notify_all();
        }
        let premature = finishes.recv_timeout(std::time::Duration::from_millis(100));
        release.wait();
        owner.join().unwrap().unwrap();
        let final_result = match premature {
            Ok(value) => value,
            Err(_) => finishes
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
        };
        waiter.join().unwrap();
        assert!(
            observed_waiter,
            "fixture did not enter the actual waiter path"
        );
        assert!(
            premature.is_err(),
            "cancelled waiter escaped before owner join"
        );
        assert_eq!(final_result, Err(io::ErrorKind::Interrupted));
    }

    #[test]
    fn success_is_process_state_only_and_error_can_retry() {
        let initialization = Initialization::new();
        let cancellation = CancellationToken::new();
        assert_eq!(
            initialization
                .ensure(&cancellation, || Err(io::ErrorKind::OutOfMemory.into()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::OutOfMemory
        );
        let calls = AtomicUsize::new(0);
        initialization
            .ensure(&cancellation, || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        initialization
            .ensure(&cancellation, || {
                panic!("successful initialization repeated")
            })
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn panic_resets_state_for_retry() {
        let initialization = Initialization::new();
        let cancellation = CancellationToken::new();
        let panic = std::panic::catch_unwind(|| {
            let _ = initialization.ensure(&cancellation, || panic!("initialization fixture"));
        });
        assert!(panic.is_err());
        initialization.ensure(&cancellation, || Ok(())).unwrap();
    }

    #[test]
    fn concurrent_preparation_has_one_initializer_and_no_abandoned_worker() {
        let initialization = Arc::new(Initialization::new());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let owner = {
            let initialization = initialization.clone();
            let entered = entered.clone();
            let release = release.clone();
            let calls = calls.clone();
            std::thread::spawn(move || {
                initialization.ensure(&CancellationToken::new(), || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    entered.wait();
                    release.wait();
                    Ok(())
                })
            })
        };
        entered.wait();
        let (starting, starts) = mpsc::channel();
        let (finished, finishes) = mpsc::channel();
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let initialization = initialization.clone();
                let starting = starting.clone();
                let finished = finished.clone();
                std::thread::spawn(move || {
                    starting.send(()).unwrap();
                    initialization
                        .ensure(&CancellationToken::new(), || {
                            panic!("concurrent second initializer")
                        })
                        .unwrap();
                    finished.send(()).unwrap();
                })
            })
            .collect();
        for _ in 0..4 {
            starts.recv().unwrap();
        }
        assert!(matches!(
            finishes.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release.wait();
        owner.join().unwrap().unwrap();
        for waiter in waiters {
            waiter.join().unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_cannot_complete_before_real_worker_join() {
        let initialization = Arc::new(Initialization::new());
        let cancellation = CancellationToken::new();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_ended = Arc::new(AtomicUsize::new(0));
        let (finished, finishes) = mpsc::channel();
        let parent = {
            let initialization = initialization.clone();
            let cancellation = cancellation.clone();
            let entered = entered.clone();
            let release = release.clone();
            let worker_ended = worker_ended.clone();
            std::thread::spawn(move || {
                let result = initialization.ensure(&cancellation, || {
                    std::thread::scope(|scope| {
                        let worker = scope.spawn(|| {
                            entered.wait();
                            release.wait();
                            worker_ended.store(1, Ordering::SeqCst);
                        });
                        worker.join().unwrap();
                    });
                    Ok(())
                });
                finished.send(result.map_err(|error| error.kind())).unwrap();
            })
        };
        entered.wait();
        cancellation.cancel();
        assert!(matches!(
            finishes.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert_eq!(worker_ended.load(Ordering::SeqCst), 0);
        release.wait();
        assert_eq!(finishes.recv().unwrap(), Err(io::ErrorKind::Interrupted));
        parent.join().unwrap();
        assert_eq!(worker_ended.load(Ordering::SeqCst), 1);
        initialization
            .ensure(&CancellationToken::new(), || {
                panic!("completed warmup lost after cancel")
            })
            .unwrap();
    }

    #[test]
    fn cancelled_cold_preparation_does_not_start_initialization() {
        let initialization = Initialization::new();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            initialization
                .ensure(&cancellation, || panic!("cancelled initialization started"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        initialization
            .ensure(&CancellationToken::new(), || Ok(()))
            .unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn real_platform_context_is_released_on_a_joined_owner_thread() {
        let initialization = Initialization::new();
        let parent = std::thread::current().id();
        initialization
            .ensure(&CancellationToken::new(), || {
                super::super::run_on_scoped_thread_named("vole-http-js-init-test", || {
                    assert_ne!(std::thread::current().id(), parent);
                    super::super::apple::initialize_platform()
                })
            })
            .unwrap();
        initialization
            .ensure(&CancellationToken::new(), || panic!("real warmup repeated"))
            .unwrap();
    }
}
