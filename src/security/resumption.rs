//! Exact per-node ticket bounds within the runtime's aggregate session budget.
//! A node has one immutable SNI and verifier; caches never cross node policies.
use super::identity::IdentityEpoch;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use rustls::{
    NamedGroup,
    client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue},
    pki_types::ServerName,
};

struct State {
    generation: u64,
    hint: Option<NamedGroup>,
    tls12: Option<Tls12ClientSessionValue>,
    tickets: VecDeque<Tls13ClientSessionValue>,
}

pub(super) struct NodeSessionStore {
    name: ServerName<'static>,
    capacity: usize,
    state: Mutex<State>,
}

impl std::fmt::Debug for NodeSessionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeSessionStore")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl NodeSessionStore {
    #[cfg(test)]
    pub(super) fn stored_sessions(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.tickets.len() + usize::from(state.tls12.is_some())
    }

    pub(super) fn new(name: ServerName<'static>, capacity: usize) -> Self {
        Self {
            name,
            capacity,
            state: Mutex::new(State {
                generation: 0,
                hint: None,
                tls12: None,
                tickets: VecDeque::with_capacity(capacity),
            }),
        }
    }

    pub(super) fn for_epoch(self: &Arc<Self>, epoch: IdentityEpoch) -> Arc<dyn ClientSessionStore> {
        Arc::new(EpochSessionStore {
            store: self.clone(),
            epoch,
        })
    }
}

struct EpochSessionStore {
    store: Arc<NodeSessionStore>,
    epoch: IdentityEpoch,
}

impl std::fmt::Debug for EpochSessionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EpochSessionStore")
            .finish_non_exhaustive()
    }
}

impl EpochSessionStore {
    fn state(&self) -> Option<MutexGuard<'_, State>> {
        let mut state = self.store.state.lock().ok()?;
        if !self.epoch.is_current() || self.epoch.generation() < state.generation {
            return None;
        }
        if self.epoch.generation() != state.generation {
            state.generation = self.epoch.generation();
            state.hint = None;
            state.tls12 = None;
            state.tickets.clear();
        }
        Some(state)
    }
}

impl ClientSessionStore for EpochSessionStore {
    fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
        if name == self.store.name
            && let Some(mut state) = self.state()
        {
            state.hint = Some(group);
        }
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
        if *name == self.store.name {
            self.state().and_then(|state| state.hint)
        } else {
            None
        }
    }
    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        if name != self.store.name || self.store.capacity == 0 {
            return;
        }
        let Some(mut state) = self.state() else {
            return;
        };
        state.tickets.clear();
        state.tls12 = Some(value);
    }
    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        if *name == self.store.name {
            self.state().and_then(|state| state.tls12.clone())
        } else {
            None
        }
    }
    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        if *name == self.store.name
            && let Some(mut state) = self.state()
        {
            state.tls12 = None;
        }
    }
    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        if name != self.store.name || self.store.capacity == 0 {
            return;
        }
        let Some(mut state) = self.state() else {
            return;
        };
        state.tls12 = None;
        if state.tickets.len() == self.store.capacity {
            state.tickets.pop_front();
        }
        state.tickets.push_back(value);
    }
    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        if *name == self.store.name {
            self.state().and_then(|mut state| state.tickets.pop_back())
        } else {
            None
        }
    }
}
