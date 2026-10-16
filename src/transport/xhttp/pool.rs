//! Node-owned transport leases. Thresholds choose candidates, not admission.
use super::{ConnectionGuard, ConnectionLease, SendRequest, connection_closed};
use crate::{
    config::{XHttpReuseConfig, XHttpVersion},
    resources::observation::{Guard, ResourceKind, track},
};
use std::{
    future::Future,
    io,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::time::Instant;

const MAX_IDLE_ENTRIES: usize = crate::limits::XHTTP_IDLE_ENTRIES;
const MAX_IDLE_HTTP1_CONNECTIONS: usize = crate::limits::XHTTP_IDLE_H1_CONNECTIONS;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Policy {
    Multiplexed,
    Exclusive,
    Recyclable,
}

#[derive(Debug)]
pub(super) struct Pool {
    options: Option<Arc<XHttpReuseConfig>>,
    share_active: bool,
    concurrency: usize,
    connections: usize,
    state: Arc<Mutex<State>>,
    opening: tokio::sync::Mutex<()>,
}
#[derive(Debug, Default)]
struct State {
    entries: Vec<Entry>,
    next_id: u64,
    closed: bool,
    idle_limit: usize,
}
#[derive(Clone, Debug)]
struct Physical {
    sender: SendRequest,
    driver: Arc<ConnectionGuard>,
}
#[derive(Debug)]
enum Transport {
    Multiplexed(Physical),
    Http1(Vec<Physical>),
}
#[derive(Debug)]
struct Entry {
    id: u64,
    transport: Transport,
    active: usize,
    reuses: usize,
    max_reuses: usize,
    remaining: Option<usize>,
    expires: Option<Instant>,
    _observation: Guard,
}
impl Entry {
    fn retired(&self) -> bool {
        matches!(&self.transport, Transport::Multiplexed(physical) if physical.driver.task.is_finished() || matches!(&physical.sender, SendRequest::H3(sender) if !sender.requests.can_open_request()))
            || self.remaining == Some(0)
            || self.max_reuses > 0 && self.reuses >= self.max_reuses
            || self.expires.is_some_and(|at| Instant::now() >= at)
    }
    fn reserve(&mut self, state: &Arc<Mutex<State>>, reused: bool) -> io::Result<Usage> {
        self.active = self
            .active
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if reused {
            self.reuses = self.reuses.saturating_add(1);
        }
        if let Some(left) = &mut self.remaining {
            *left = left.saturating_sub(1);
        }
        Ok(Usage {
            state: Arc::downgrade(state),
            id: self.id,
            recycle: None,
            reusable: false,
        })
    }
    fn take(&mut self, policy: Policy) -> Option<Physical> {
        match &mut self.transport {
            Transport::Multiplexed(physical) => Some(physical.clone()),
            Transport::Http1(idle) if policy == Policy::Recyclable => {
                while let Some(physical) = idle.pop() {
                    if !physical.driver.task.is_finished() {
                        return Some(physical);
                    }
                }
                None
            }
            Transport::Http1(_) => None,
        }
    }
}
impl State {
    fn cleanup(&mut self) {
        let mut idle = 0;
        self.entries.retain(|entry| {
            // Logical streams own driver leases independently of candidate retention.
            if entry.retired() {
                return false;
            }
            if entry.active != 0 {
                return true;
            }
            idle += 1;
            idle <= self.idle_limit
        });
    }
}
impl Pool {
    pub(super) fn new(options: Option<Arc<XHttpReuseConfig>>, version: XHttpVersion) -> Self {
        let share_active = options.is_none() && version == XHttpVersion::Http3;
        Self {
            concurrency: options.as_ref().map_or(
                if share_active {
                    crate::limits::XHTTP_ACTIVE_H3_LEASES
                } else {
                    0
                },
                |options| options.concurrency.sample(),
            ),
            connections: options
                .as_ref()
                .map_or(0, |options| options.connections.sample()),
            options,
            share_active,
            state: Arc::new(Mutex::new(State {
                idle_limit: if share_active { 0 } else { MAX_IDLE_ENTRIES },
                ..State::default()
            })),
            opening: tokio::sync::Mutex::default(),
        }
    }
    pub(super) async fn acquire<F, Fut>(
        &self,
        policy: Policy,
        make: F,
    ) -> io::Result<(SendRequest, ConnectionLease)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<(SendRequest, Arc<ConnectionGuard>)>>,
    {
        if self.options.is_none() && !self.share_active {
            let (sender, driver) = make().await?;
            return Ok((sender, driver.into()));
        }
        let options = self.options.as_deref();
        let _opening = self.opening.lock().await;
        let existing = {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(connection_closed());
            }
            state.cleanup();
            if self.connections == 0 || state.entries.len() >= self.connections {
                state
                    .entries
                    .iter_mut()
                    .filter(|entry| self.concurrency == 0 || entry.active < self.concurrency)
                    .min_by_key(|entry| entry.active)
                    .map(|entry| -> io::Result<_> {
                        Ok((entry.take(policy), entry.reserve(&self.state, true)?))
                    })
                    .transpose()?
            } else {
                None
            }
        };
        let (physical, mut usage) = if let Some((physical, usage)) = existing {
            let physical = if let Some(physical) = physical {
                physical
            } else {
                let (sender, driver) = make().await?;
                Physical { sender, driver }
            };
            (physical, usage)
        } else {
            let (sender, driver) = make().await?;
            let physical = Physical { sender, driver };
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(connection_closed());
            }
            let id = state.next_id;
            state.next_id = id.checked_add(1).ok_or_else(connection_closed)?;
            let mut entry = Entry {
                id,
                transport: if policy == Policy::Multiplexed {
                    Transport::Multiplexed(physical.clone())
                } else {
                    Transport::Http1(Vec::new())
                },
                active: 0,
                reuses: 0,
                max_reuses: options.map_or(0, |options| options.reuse_times.sample()),
                remaining: options
                    .filter(|options| options.requests.max > 0)
                    .map(|options| options.requests.sample()),
                expires: options
                    .filter(|options| options.age_seconds.max > 0)
                    .map(|options| {
                        Instant::now() + Duration::from_secs(options.age_seconds.sample() as u64)
                    }),
                _observation: track(ResourceKind::Pool),
            };
            let usage = entry.reserve(&self.state, false)?;
            state.entries.push(entry);
            (physical, usage)
        };
        if policy == Policy::Recyclable {
            usage.recycle = Some(physical.clone());
        }
        Ok((
            physical.sender,
            ConnectionLease {
                _driver: physical.driver,
                _usage: Some(usage),
            },
        ))
    }
    pub(super) fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.entries.clear();
    }

    #[cfg(feature = "interop-test")]
    pub(super) fn quic_pings(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap()
            .entries
            .iter()
            .filter_map(|entry| {
                let Transport::Multiplexed(Physical {
                    sender: SendRequest::H3(sender),
                    ..
                }) = &entry.transport
                else {
                    return None;
                };
                Some(sender.observation.stats().frame_tx.ping)
            })
            .collect()
    }
}
#[derive(Debug)]
pub(super) struct Usage {
    state: Weak<Mutex<State>>,
    id: u64,
    recycle: Option<Physical>,
    reusable: bool,
}
impl Usage {
    pub(super) fn permit_recycle(&mut self) {
        self.reusable = true;
    }
}
impl Drop for Usage {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            let mut state = state.lock().unwrap();
            if let Some(entry) = state.entries.iter_mut().find(|entry| entry.id == self.id) {
                entry.active = entry.active.saturating_sub(1);
                if self.reusable
                    && !entry.retired()
                    && let Some(physical) = self.recycle.take()
                    && !physical.driver.task.is_finished()
                    && let Transport::Http1(idle) = &mut entry.transport
                    && idle.len() < MAX_IDLE_HTTP1_CONNECTIONS
                {
                    idle.push(physical);
                }
            }
            state.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::XHttpVersion,
        transport::xhttp::{XHttpClient, XHttpConfig, XHttpMode},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_util::task::TaskTracker;

    #[tokio::test]
    async fn implicit_h3_shares_three_active_leases_and_reconnects_after_idle() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut config = XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap();
            config.http_version = XHttpVersion::Http3;
            let client = XHttpClient::new(config);
            let transport = XHttpClient::new(
                XHttpConfig::new("example.com", "/x", XHttpMode::StreamOne).unwrap(),
            );
            let calls = AtomicUsize::new(0);
            let peers = TaskTracker::new();
            // Admission and leases are transport-independent. Real memory H2
            // drivers expose factory calls and cleanup without QUIC scheduling.
            let make = || async {
                calls.fetch_add(1, Ordering::Relaxed);
                let (io, remote) = tokio::io::duplex(8192);
                peers.spawn(async move {
                    let mut connection = h2::server::handshake(remote).await.unwrap();
                    while let Some(request) = connection.accept().await {
                        request.unwrap();
                    }
                });
                transport.handshake(Box::new(io)).await
            };
            let mut leases = Vec::new();
            for _ in 0..3 {
                let (_, lease) = client
                    .pool
                    .acquire(Policy::Multiplexed, &make)
                    .await
                    .unwrap();
                leases.push(lease);
            }
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            let (_, fourth) = client
                .pool
                .acquire(Policy::Multiplexed, &make)
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 2);
            drop(fourth);
            drop(leases);
            let (_, fresh) = client
                .pool
                .acquire(Policy::Multiplexed, &make)
                .await
                .unwrap();
            assert_eq!(
                calls.load(Ordering::Relaxed),
                3,
                "idle physical transport was retained"
            );
            drop(fresh);
            client.stop().await;
            transport.stop().await;
            peers.close();
            peers.wait().await;
        })
        .await
        .expect("active transport leases did not stop");
    }
}
