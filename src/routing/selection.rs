//! Selection and probe activity shared by route and upstream groups.
use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::time::Instant;
#[derive(Debug)]
pub(crate) struct GroupSelection {
    index: AtomicUsize,
    balance: Mutex<Option<super::balance::Balance>>,
    forced: Mutex<Option<usize>>,
    touched: Mutex<Instant>,
    failures: Mutex<(Instant, u32)>,
    urgent: AtomicBool,
    maximum: AtomicU32,
    window_ms: AtomicU64,
}
pub(super) struct InspectedSelection<'a> {
    owner: &'a GroupSelection,
    balance: MutexGuard<'a, Option<super::balance::Balance>>,
    pub index: usize,
}
impl InspectedSelection<'_> {
    pub fn commit(mut self) {
        if let Some(balance) = self.balance.as_mut() {
            balance.commit(self.index);
        }
        self.owner.touch();
    }
}
impl GroupSelection {
    pub fn new(index: usize) -> Self {
        let now = Instant::now();
        Self {
            index: AtomicUsize::new(index),
            balance: Mutex::new(None),
            forced: Mutex::new(None),
            touched: Mutex::new(now),
            failures: Mutex::new((now, 0)),
            urgent: AtomicBool::new(false),
            maximum: AtomicU32::new(5),
            window_ms: AtomicU64::new(5000),
        }
    }
    pub fn configure_balance(&self, config: &crate::config::SelectProxyGroupConfig) {
        if config.kind == crate::config::GroupKind::LoadBalance {
            let mut state = self.balance.lock().unwrap();
            if state.is_none() {
                *state = Some(
                    super::balance::Balance::new(config.strategy, config.members.len())
                        .with_hash_key(config.hash_key),
                );
            }
        }
    }
    #[cfg(test)]
    pub fn choose(
        &self,
        source: Option<std::net::SocketAddr>,
        destination: Option<&crate::session::Destination>,
    ) -> usize {
        self.choose_for(source, destination, None)
    }
    pub fn choose_for(
        &self,
        source: Option<std::net::SocketAddr>,
        destination: Option<&crate::session::Destination>,
        user: Option<&str>,
    ) -> usize {
        self.touch();
        self.balance.lock().unwrap().as_mut().map_or_else(
            || self.load(Ordering::Acquire),
            |s| s.choose(source, destination, user),
        )
    }
    pub(super) fn inspect(
        &self,
        source: Option<std::net::SocketAddr>,
        destination: Option<&crate::session::Destination>,
        user: Option<&str>,
    ) -> InspectedSelection<'_> {
        let mut balance = self.balance.lock().unwrap();
        let index = balance.as_mut().map_or_else(
            || self.load(Ordering::Acquire),
            |state| state.inspect(source, destination, user, false),
        );
        InspectedSelection {
            owner: self,
            balance,
            index,
        }
    }
    pub fn balance_health(&self, samples: &[Option<u64>]) {
        if let Some(balance) = self.balance.lock().unwrap().as_mut() {
            balance.health(samples);
        }
    }
    pub fn load(&self, order: Ordering) -> usize {
        self.index.load(order)
    }
    pub fn store(&self, index: usize, order: Ordering) {
        self.index.store(index, order);
    }
    pub fn touch(&self) {
        *self.touched.lock().unwrap() = Instant::now();
    }
    pub fn active(&self, interval: Duration) -> bool {
        self.touched.lock().unwrap().elapsed() < interval
    }
    pub fn configure(&self, maximum: u32, window: u64) {
        self.maximum.store(maximum, Ordering::Relaxed);
        self.window_ms.store(window, Ordering::Relaxed);
    }
    pub fn force(&self, index: usize) {
        *self.forced.lock().unwrap() = Some(index);
        self.store(index, Ordering::Release);
    }
    pub fn forced(&self) -> Option<usize> {
        *self.forced.lock().unwrap()
    }
    pub fn clear_forced(&self) {
        *self.forced.lock().unwrap() = None;
    }
    pub fn take_urgent(&self) -> bool {
        self.urgent.swap(false, Ordering::Relaxed)
    }
    pub fn outcome(&self, success: bool) {
        let mut failures = self.failures.lock().unwrap();
        if success {
            failures.1 = 0;
            return;
        }
        if failures.0.elapsed() > Duration::from_millis(self.window_ms.load(Ordering::Relaxed))
            || failures.1 == 0
        {
            *failures = (Instant::now(), 0);
        }
        failures.1 = failures.1.saturating_add(1);
        if failures.1 >= self.maximum.load(Ordering::Relaxed) {
            self.urgent.store(true, Ordering::Relaxed);
            failures.1 = 0;
        }
    }
}
