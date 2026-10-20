//! Bounded refresh ownership, separate from foreground DNS query lifetimes.
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(super) const CONCURRENCY: usize = 4;
pub(super) const BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

pub(super) struct Owner {
    pub(super) budget: Arc<Semaphore>,
    admission: Mutex<bool>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

impl Owner {
    pub(super) fn new(budget: Option<Arc<Semaphore>>) -> Arc<Self> {
        Arc::new(Self {
            budget: budget.unwrap_or_else(|| Arc::new(Semaphore::new(CONCURRENCY))),
            admission: Mutex::new(true),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
        })
    }

    pub(super) fn reserve(&self) -> Option<OwnedSemaphorePermit> {
        if self.cancel.is_cancelled() {
            return None;
        }
        self.budget.clone().try_acquire_owned().ok()
    }

    pub(super) fn spawn<F>(&self, permit: OwnedSemaphorePermit, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !*admission {
            return;
        }
        let cancel = self.cancel.clone();
        self.tasks
            .spawn(crate::resources::observation::task(async move {
                let _permit = permit;
                tokio::select! { biased; () = cancel.cancelled() => {}, () = future => {} }
            }));
    }

    pub(super) fn close(&self) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *admission = false;
        self.cancel.cancel();
        self.tasks.close();
    }

    pub(super) fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub(super) async fn shutdown(&self) {
        self.close();
        self.tasks.wait().await;
    }
}
