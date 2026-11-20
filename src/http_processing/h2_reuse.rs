//! A downstream-local H2 admission slot. Its parent owns every I/O driver.
use crate::dispatch::{BoxStream, HttpTcpReuseKey};
use bytes::Bytes;
use futures_util::{StreamExt, future::poll_fn, stream::FuturesUnordered};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
};
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    time::{Duration, Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

pub(super) const SETUP: Duration = Duration::from_secs(10);
pub(super) type Driver = Pin<Box<dyn Future<Output = Result<(), h2::Error>> + Send + 'static>>;
type OwnedDriver = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

fn failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "HTTP upstream session failed",
    )
}

pub(super) async fn handshake(
    io: BoxStream,
    deadline: Instant,
) -> io::Result<(h2::client::SendRequest<Bytes>, Driver)> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(64 * 1024)
        .initial_connection_window_size(64 * 1024)
        .header_table_size(0)
        .max_header_list_size(32 * 1024)
        .max_frame_size(16 * 1024)
        .max_send_buffer_size(16 * 1024)
        .enable_push(false)
        // This advertises receive concurrency. Peer SETTINGS / ready() still
        // govern our sends; downstream admission remains eight requests.
        .max_concurrent_streams(1);
    let (sender, driver) = timeout_at(deadline, builder.handshake::<_, Bytes>(io))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(|_| failed())?;
    Ok((sender, Box::pin(driver)))
}

pub(super) struct Identity {
    route: HttpTcpReuseKey,
    origin: url::Origin,
}
impl Identity {
    pub(super) fn new(route: HttpTcpReuseKey, url: &url::Url) -> Self {
        Self {
            route,
            origin: url.origin(),
        }
    }
    fn same(&self, other: &Self) -> bool {
        self.route.same(&other.route) && self.origin == other.origin
    }
}

struct State {
    retired: AtomicBool,
    closed: AtomicBool,
    leases: AtomicUsize,
    retire_unleased: CancellationToken,
}
impl State {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            retired: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            leases: AtomicUsize::new(0),
            retire_unleased: CancellationToken::new(),
        })
    }
    fn retire(&self) {
        // These two atomics form one retirement/last-lease handshake. SeqCst
        // excludes both sides missing the other's write under store buffering.
        self.retired.store(true, Ordering::SeqCst);
        if self.leases.load(Ordering::SeqCst) == 0 {
            self.retire_unleased.cancel();
        }
    }
    fn usable(&self) -> bool {
        !self.retired.load(Ordering::SeqCst) && !self.closed.load(Ordering::SeqCst)
    }
    fn release_lease(&self) {
        if self.leases.fetch_sub(1, Ordering::SeqCst) == 1 && self.retired.load(Ordering::SeqCst) {
            self.retire_unleased.cancel();
        }
    }
}

struct Provisional(Option<Arc<State>>);
impl Drop for Provisional {
    fn drop(&mut self) {
        if let Some(state) = &self.0 {
            state.retire();
        }
    }
}
struct DriverEnd {
    driver: Option<Driver>,
    state: Arc<State>,
}
impl Drop for DriverEnd {
    fn drop(&mut self) {
        // Also ordered when the wrapper was never polled: closed means the
        // actual I/O owner was destroyed, not merely that cleanup was entered.
        drop(self.driver.take());
        self.state.closed.store(true, Ordering::SeqCst);
        self.state.retire();
    }
}
struct Registration {
    driver: Driver,
    state: Arc<State>,
    accepted: oneshot::Sender<()>,
}
struct Slot {
    identity: Identity,
    sender: h2::client::SendRequest<Bytes>,
    state: Arc<State>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.state.retire();
    }
}

/// The lease is held through complete body relay, not merely send_request.
pub(super) struct Lease {
    sender: h2::client::SendRequest<Bytes>,
    state: Arc<State>,
    deadline: Instant,
}
impl Lease {
    fn new(slot: &Slot, deadline: Instant) -> io::Result<Self> {
        slot.state.leases.fetch_add(1, Ordering::SeqCst);
        if !slot.state.usable() {
            slot.state.release_lease();
            return Err(failed());
        }
        Ok(Self {
            sender: slot.sender.clone(),
            state: slot.state.clone(),
            deadline,
        })
    }
    pub(super) async fn ready(&self) -> io::Result<h2::client::SendRequest<Bytes>> {
        let result = match timeout_at(self.deadline, self.sender.clone().ready()).await {
            Ok(result) => result.map_err(|_| failed()),
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        };
        if result.is_err() {
            self.retire();
        }
        result
    }
    pub(super) fn retire(&self) {
        self.state.retire();
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.state.release_lease();
    }
}
pub(super) enum Acquired {
    Shared(Lease),
    H1(BoxStream),
}

/// Never escapes this serve_h2's fixed HttpContext/security scope.
pub(super) struct Sessions {
    slot: Mutex<Option<Slot>>,
    registrations: mpsc::Sender<Registration>,
}
/// All registered drivers remain inline in this parent, including while idle.
pub(super) struct Parent {
    registrations: mpsc::Receiver<Registration>,
    drivers: FuturesUnordered<OwnedDriver>,
}
pub(super) fn new() -> (Sessions, Parent) {
    let (send, receive) = mpsc::channel(1);
    (
        Sessions {
            slot: Mutex::new(None),
            registrations: send,
        },
        Parent {
            registrations: receive,
            drivers: FuturesUnordered::new(),
        },
    )
}
impl Sessions {
    /// `open` is the production authenticated StandardTlsClient path. It is
    /// lazy: on a hit its already-selected route plan is dropped, not dialed.
    pub(super) async fn acquire<F, O>(
        &self,
        identity: Identity,
        connect_deadline: Instant,
        open: F,
    ) -> io::Result<Acquired>
    where
        F: FnOnce() -> O,
        O: Future<Output = io::Result<(BoxStream, Option<Vec<u8>>)>>,
    {
        let mut slot = timeout_at(connect_deadline, self.slot.lock())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?;
        if let Some(current) = slot.as_ref()
            && current.identity.same(&identity)
            && current.state.usable()
        {
            return Ok(Acquired::Shared(Lease::new(current, connect_deadline)?));
        }
        // Drop the root sender immediately. Existing leases keep their stream
        // driver until they finish; a silent peer cannot retain an empty one.
        drop(slot.take());
        let (io, protocol) = timeout_at(connect_deadline, open())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        match protocol.as_deref() {
            Some(b"h2") => {}
            None | Some(b"http/1.1") => return Ok(Acquired::H1(io)),
            Some(_) => return Err(failed()),
        }
        let deadline = Instant::now() + SETUP;
        let (sender, driver) = handshake(io, deadline).await?;
        let state = State::new();
        let mut provisional = Provisional(Some(state.clone()));
        let (accepted, acknowledgement) = oneshot::channel();
        timeout_at(
            deadline,
            self.registrations.send(Registration {
                driver,
                state: state.clone(),
                accepted,
            }),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(|_| failed())?;
        timeout_at(deadline, acknowledgement)
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map_err(|_| failed())?;
        if !state.usable() {
            return Err(failed());
        }
        let current = Slot {
            identity,
            sender,
            state,
        };
        let lease = Lease::new(&current, deadline)?;
        *slot = Some(current);
        // Only this initial guard must be disarmed; do not mark the published
        // slot retired. No fallible operation or await separates publication.
        drop(provisional.0.take());
        Ok(Acquired::Shared(lease))
    }
}
impl Parent {
    /// Drain completed/signalled retirees before accepting a new registration.
    /// This future never locks Sessions: an initializer holds that mutex while
    /// waiting for this parent's acknowledgement.
    pub(super) async fn progress(&mut self) {
        poll_fn(|cx| {
            let mut changed = false;
            while let Poll::Ready(Some(())) = self.drivers.poll_next_unpin(cx) {
                changed = true;
            }
            if let Poll::Ready(Some(registration)) = self.registrations.poll_recv(cx) {
                let Registration {
                    driver,
                    state,
                    accepted,
                } = registration;
                let end = DriverEnd {
                    driver: Some(driver),
                    state: state.clone(),
                };
                self.drivers.push(Box::pin(async move {
                    let mut end = end;
                    tokio::select! {biased;
                        ()=state.retire_unleased.cancelled()=>{},
                        _=end.driver.as_mut().expect("registered driver owner")=>{},
                    }
                    drop(end);
                }));
                // Ownership is in FuturesUnordered before sender publication.
                let _ = accepted.send(());
                changed = true;
            }
            if changed {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

#[cfg(any(test, all(target_os = "tvos", feature = "http-diagnostics")))]
#[path = "h2_reuse_validation.rs"]
mod validation;

#[cfg(all(target_os = "tvos", feature = "http-diagnostics"))]
pub(super) fn validate() -> io::Result<serde_json::Value> {
    validation::run()
}

#[cfg(test)]
#[path = "https_h2_reuse_memory_tests.rs"]
mod integration_tests;
