//! Retired physical sessions outlive their existing logical owners, not forever.
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Activity {
    state: Mutex<State>,
    changed: Notify,
}
#[derive(Default)]
struct State {
    active: usize,
    retired: bool,
}
pub(super) struct Lease(Arc<Activity>);
impl Activity {
    pub fn acquire(self: &Arc<Self>) -> Lease {
        self.state.lock().unwrap().active += 1;
        Lease(self.clone())
    }
    pub fn try_acquire(self: &Arc<Self>, limit: usize) -> Option<Lease> {
        let mut state = self.state.lock().unwrap();
        if state.retired || state.active >= limit {
            return None;
        }
        state.active += 1;
        Some(Lease(self.clone()))
    }
    pub fn retire(&self) {
        self.state.lock().unwrap().retired = true;
        self.changed.notify_one();
    }
    pub async fn retired_and_idle(&self) {
        loop {
            let notified = self.changed.notified();
            {
                let state = self.state.lock().unwrap();
                if state.retired && state.active == 0 {
                    return;
                }
            }
            notified.await;
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active -= 1;
        self.0.changed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn logical_limit_retirement_waits_for_existing_owners() {
        let activity = Arc::new(Activity::default());
        assert!(activity.try_acquire(0).is_none());
        let first = activity.try_acquire(2).unwrap();
        let second = activity.try_acquire(2).unwrap();
        assert!(activity.try_acquire(2).is_none());
        activity.retire();
        assert!(activity.try_acquire(2).is_none());
        drop(first);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(1),
                activity.retired_and_idle()
            )
            .await
            .is_err()
        );
        drop(second);
        activity.retired_and_idle().await;
    }
}
