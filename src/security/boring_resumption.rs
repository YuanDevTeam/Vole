//! Node-owned tickets. No native/global cache or cross-policy ticket import.
use boring::{
    ex_data::Index,
    ssl::{
        ConnectConfiguration, Ssl, SslConnectorBuilder, SslSession, SslSessionCacheMode, SslVersion,
    },
};
use rustls::pki_types::UnixTime;
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, LazyLock, Mutex},
};

use super::identity::IdentityEpoch;

type SessionIndex = Index<Ssl, Arc<SessionSink>>;
// Only the slot number is global, never the tickets or a verification policy.
static SESSION_INDEX: LazyLock<Result<SessionIndex, boring::error::ErrorStack>> =
    LazyLock::new(Ssl::new_ex_index);

#[derive(Clone)]
pub(super) struct Sessions {
    queue: Arc<Mutex<Cache>>,
    capacity: usize,
    index: SessionIndex,
}

#[derive(Default)]
struct Cache {
    generation: u64,
    tickets: VecDeque<SslSession>,
}

impl Cache {
    fn select_epoch(&mut self, epoch: &IdentityEpoch) -> bool {
        if !epoch.is_current() || epoch.generation() < self.generation {
            return false;
        }
        if epoch.generation() != self.generation {
            self.tickets.clear();
            self.generation = epoch.generation();
        }
        true
    }
}

impl Sessions {
    pub(super) fn new(builder: &mut SslConnectorBuilder, capacity: usize) -> io::Result<Self> {
        if capacity > super::TLS_RESUMPTION_SESSION_BUDGET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS ticket capacity exceeds the runtime budget",
            ));
        }
        let index = *SESSION_INDEX.as_ref().map_err(|_| cache_error())?;
        if capacity == 0 {
            builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        } else {
            builder.set_session_cache_mode(
                SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL,
            );
            builder.set_new_session_callback(move |ssl, session| {
                if let Some(sink) = ssl.ex_data(index) {
                    sink.store(session);
                }
            });
        }
        Ok(Self {
            queue: Arc::default(),
            capacity,
            index,
        })
    }

    pub(super) fn configure(
        &self,
        config: &mut ConnectConfiguration,
        epoch: IdentityEpoch,
    ) -> io::Result<Arc<SessionSink>> {
        let sink = Arc::new(SessionSink {
            cache: self.clone(),
            epoch: epoch.clone(),
            state: Mutex::new(State {
                accepted: false,
                pending: VecDeque::new(),
            }),
        });
        config.set_ex_data(self.index, sink.clone());
        let session = {
            let now = UnixTime::now().as_secs();
            let mut cache = self.queue.lock().map_err(|_| cache_error())?;
            if !cache.select_epoch(&epoch) {
                return Ok(sink);
            }
            cache.tickets.retain(|session| {
                let hint = session.ticket_lifetime_hint();
                let lifetime = if hint == 0 {
                    session.timeout()
                } else {
                    session.timeout().min(hint)
                };
                now < session.time().saturating_add(u64::from(lifetime))
            });
            if cache
                .tickets
                .back()
                .is_some_and(|s| s.protocol_version() == SslVersion::TLS1_2)
            {
                // TLS 1.2 abbreviated handshakes need not issue another ticket.
                cache.tickets.back().cloned()
            } else {
                // A TLS 1.3 ticket is consumed once.
                cache.tickets.pop_back()
            }
        };
        if let Some(session) = session {
            // SAFETY: Only this client's SSL_CTX and the same current identity
            // generation populate its node-owned cache. Clone shares policy.
            unsafe { config.set_session(&session) }.map_err(|_| cache_error())?;
        }
        Ok(sink)
    }
}

struct State {
    accepted: bool,
    pending: VecDeque<SslSession>,
}

pub(super) struct SessionSink {
    cache: Sessions,
    epoch: IdentityEpoch,
    state: Mutex<State>,
}

impl SessionSink {
    fn store(&self, session: SslSession) {
        // Native callbacks must not panic, including after a poisoned lock.
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if !self.epoch.is_current() {
            state.pending.clear();
            return;
        }
        if state.accepted {
            if let Ok(mut cache) = self.cache.queue.lock()
                && cache.select_epoch(&self.epoch)
            {
                bounded_push(&mut cache.tickets, session, self.cache.capacity);
            }
        } else {
            bounded_push(&mut state.pending, session, self.cache.capacity);
        }
    }

    pub(super) fn accept(&self) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| cache_error())?;
        let mut cache = self.cache.queue.lock().map_err(|_| cache_error())?;
        state.accepted = true;
        if !cache.select_epoch(&self.epoch) {
            state.pending.clear();
            return Ok(());
        }
        for session in state.pending.drain(..) {
            bounded_push(&mut cache.tickets, session, self.cache.capacity);
        }
        Ok(())
    }
}

fn bounded_push(queue: &mut VecDeque<SslSession>, session: SslSession, capacity: usize) {
    if capacity != 0 {
        while queue.len() >= capacity {
            queue.pop_front();
        }
        queue.push_back(session);
    }
}

fn cache_error() -> io::Error {
    io::Error::other("TLS session cache unavailable")
}
