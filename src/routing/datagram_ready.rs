//! Deduplicated readiness for independently polled datagram receivers.
use crate::session::Destination;
use futures_util::task::{ArcWake, AtomicWaker};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, Weak},
    task::Waker,
};

#[derive(Default)]
pub(super) struct ReadyQueue {
    entries: Mutex<VecDeque<Arc<ReadyFlow>>>,
    parent: AtomicWaker,
}

pub(super) struct ReadyFlow {
    key: Destination,
    queue: Weak<ReadyQueue>,
    state: Mutex<FlowState>,
}

struct FlowState {
    active: bool,
    queued: bool,
}

impl ReadyQueue {
    pub fn registration(self: &Arc<Self>, key: Destination) -> Arc<ReadyFlow> {
        Arc::new(ReadyFlow {
            key,
            queue: Arc::downgrade(self),
            state: Mutex::new(FlowState {
                active: true,
                queued: false,
            }),
        })
    }

    /// Register before inspecting readiness on each poll. An enqueue before
    /// registration remains visible in the queue; one after it wakes the task.
    pub fn register(&self, waker: &Waker) {
        self.parent.register(waker);
    }

    pub fn pop(&self) -> Option<Arc<ReadyFlow>> {
        let mut entries = self.entries.lock().unwrap();
        while let Some(flow) = entries.pop_front() {
            let active = {
                let mut state = flow.state.lock().unwrap();
                state.queued = false;
                state.active
            };
            if active {
                return Some(flow);
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    pub fn shrink(&self) {
        let mut entries = self.entries.lock().unwrap();
        if entries.capacity() > entries.len().saturating_mul(4).max(8) {
            let retained = entries.len().saturating_mul(2);
            entries.shrink_to(retained);
        }
    }
}

impl ReadyFlow {
    pub fn key(&self) -> &Destination {
        &self.key
    }

    pub fn enqueue(self: &Arc<Self>) {
        let Some(queue) = self.queue.upgrade() else {
            return;
        };
        {
            // Every operation needing both locks takes queue before state.
            let mut entries = queue.entries.lock().unwrap();
            let mut state = self.state.lock().unwrap();
            if !state.active || state.queued {
                return;
            }
            state.queued = true;
            entries.push_back(self.clone());
        }
        // A parent wake is allowed to poll immediately and reacquire the locks.
        queue.parent.wake();
    }

    /// Permanently retire this registration, including its outstanding item.
    /// Replacements for the same endpoint have a distinct registration owner.
    pub fn deactivate(&self) {
        let Some(queue) = self.queue.upgrade() else {
            let mut state = self.state.lock().unwrap();
            state.active = false;
            state.queued = false;
            return;
        };
        let mut entries = queue.entries.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        if !state.active {
            return;
        }
        state.active = false;
        if state.queued {
            entries.retain(|flow| !std::ptr::eq(flow.as_ref(), self));
            state.queued = false;
        }
    }
}

impl ArcWake for ReadyFlow {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.enqueue();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::task::{waker, waker_ref};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn key() -> Destination {
        Destination::Ip("198.51.100.1:443".parse().unwrap())
    }

    #[test]
    fn readiness_before_registration_and_cross_thread_wake_are_not_lost() {
        let queue = Arc::new(ReadyQueue::default());
        let flow = queue.registration(key());
        let wakes = Arc::new(WakeCount::default());
        let parent = waker(wakes.clone());

        flow.enqueue();
        queue.register(&parent);
        assert!(Arc::ptr_eq(&queue.pop().unwrap(), &flow));
        assert!(queue.is_empty());

        queue.register(&parent);
        std::thread::scope(|scope| {
            scope.spawn(|| waker_ref(&flow).wake_by_ref());
        });
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(queue.pop().unwrap().key(), &key());
        assert!(queue.is_empty());
    }

    #[test]
    fn duplicate_notifications_have_one_item_and_reenqueue_is_fifo() {
        let queue = Arc::new(ReadyQueue::default());
        let first = queue.registration(key());
        let second = queue.registration(Destination::Ip("198.51.100.2:443".parse().unwrap()));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        waker_ref(&first).wake_by_ref();
                    }
                });
            }
        });
        second.enqueue();
        assert!(Arc::ptr_eq(&queue.pop().unwrap(), &first));
        first.enqueue();
        assert!(Arc::ptr_eq(&queue.pop().unwrap(), &second));
        assert!(Arc::ptr_eq(&queue.pop().unwrap(), &first));
        assert!(queue.is_empty());
    }

    #[test]
    fn retirement_removes_queued_items_and_old_waker_cannot_notify_replacement() {
        let queue = Arc::new(ReadyQueue::default());
        let old = queue.registration(key());
        let stale_waker = waker(old.clone());
        old.enqueue();
        old.deactivate();
        assert!(queue.is_empty());
        let replacement = queue.registration(key());
        stale_waker.wake_by_ref();
        assert!(queue.is_empty());
        replacement.enqueue();
        assert!(Arc::ptr_eq(&queue.pop().unwrap(), &replacement));
        old.deactivate();
        replacement.enqueue();
        assert!(Arc::ptr_eq(&queue.pop().unwrap(), &replacement));
        assert!(queue.is_empty());
        let weak_queue = Arc::downgrade(&queue);
        drop(queue);
        assert!(weak_queue.upgrade().is_none());
        stale_waker.wake_by_ref();
        replacement.deactivate();
    }

    #[test]
    fn synchronous_parent_notification_does_not_hold_queue_locks() {
        struct PopWake(Arc<ReadyQueue>, AtomicUsize);
        impl ArcWake for PopWake {
            fn wake_by_ref(arc_self: &Arc<Self>) {
                if arc_self.0.pop().is_some() {
                    arc_self.1.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let queue = Arc::new(ReadyQueue::default());
        let flow = queue.registration(key());
        let parent = Arc::new(PopWake(queue.clone(), AtomicUsize::new(0)));
        queue.register(&waker(parent.clone()));
        flow.enqueue();
        assert_eq!(parent.1.load(Ordering::Relaxed), 1);
        assert!(queue.is_empty());
    }
}
