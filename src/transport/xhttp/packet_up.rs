//! Timer-driven bounded aggregation. Writes acknowledge admitted bytes; flush
//! waits for their POST responses. The node owns and joins the timer/IO driver.
#[path = "packet_up_overlap.rs"]
mod overlap;
use super::{ConnectionGuard, DriverOwner, RequestTemplate, SendRequest, connection_closed};
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::AsyncWrite, sync::Notify, time::Instant};

struct State {
    buffer: Vec<u8>,
    accepted: u64,
    committed: u64,
    error: Option<Arc<io::Error>>,
    closed: bool,
    in_flight: bool,
    #[cfg(test)]
    occupied_responses: usize,
    #[cfg(test)]
    ready_responses: usize,
    #[cfg(test)]
    ready_out_of_order: bool,
}
struct Shared {
    state: Mutex<State>,
    changed: Notify,
    finishing: AtomicBool,
    finish: Notify,
    writer: AtomicWaker,
    flush: AtomicWaker,
    reader: AtomicWaker,
}
impl Shared {
    fn wake(&self) {
        self.writer.wake();
        self.flush.wake();
        self.reader.wake();
    }
}
impl State {
    fn check(&self) -> io::Result<()> {
        if let Some(error) = &self.error {
            return Err(io::Error::new(error.kind(), error.clone()));
        }
        if self.closed {
            return Err(connection_closed());
        }
        Ok(())
    }
}
struct Lifetime(Arc<Shared>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().closed = true;
        self.0.wake();
    }
}

#[cfg(test)]
pub(super) struct Snapshot {
    pub(super) buffer_ptr: usize,
    pub(super) buffer_len: usize,
    pub(super) buffer_capacity: usize,
    pub(super) accepted: u64,
    pub(super) committed: u64,
    pub(super) in_flight: bool,
    pub(super) occupied_responses: usize,
    pub(super) ready_responses: usize,
    pub(super) ready_out_of_order: bool,
}

pub(super) struct Writer {
    shared: Arc<Shared>,
    capacity: usize,
    chunk: usize,
    _task: ConnectionGuard,
}
impl Writer {
    pub(super) fn new(
        sender: SendRequest,
        request: RequestTemplate,
        session: Arc<str>,
        chunk: usize,
        owner: &DriverOwner,
    ) -> io::Result<Self> {
        Self::with_responses(sender, request, session, chunk, owner, false)
    }

    pub(super) fn new_overlapping(
        sender: SendRequest,
        request: RequestTemplate,
        session: Arc<str>,
        chunk: usize,
        owner: &DriverOwner,
    ) -> io::Result<Self> {
        Self::with_responses(sender, request, session, chunk, owner, true)
    }

    fn with_responses(
        sender: SendRequest,
        request: RequestTemplate,
        session: Arc<str>,
        chunk: usize,
        owner: &DriverOwner,
        overlap_responses: bool,
    ) -> io::Result<Self> {
        // Mihomo samples this maximum once per logical writer. Never allocate
        // the configurable (up to 16 MiB) maximum per connection.
        let batch_limit = if matches!(&sender, SendRequest::H3(_)) {
            if overlap_responses {
                crate::limits::XHTTP_H3_PACKET_BATCH_BYTES
            } else {
                crate::limits::XHTTP_H3_SERIAL_PACKET_BATCH_BYTES
            }
        } else if matches!(&sender, SendRequest::H1 { .. }) {
            crate::limits::XHTTP_H1_PACKET_BATCH_BYTES
        } else {
            crate::limits::XHTTP_PACKET_BATCH_BYTES
        };
        let capacity = request.options.post_bytes.sample().min(batch_limit);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                buffer: Vec::new(),
                accepted: 0,
                committed: 0,
                error: None,
                closed: false,
                in_flight: false,
                #[cfg(test)]
                occupied_responses: 0,
                #[cfg(test)]
                ready_responses: 0,
                #[cfg(test)]
                ready_out_of_order: false,
            }),
            changed: Notify::new(),
            finishing: AtomicBool::new(false),
            finish: Notify::new(),
            writer: AtomicWaker::new(),
            flush: AtomicWaker::new(),
            reader: AtomicWaker::new(),
        });
        let eager_capacity = (!request.options.post_interval_explicit).then_some(capacity);
        let lifetime = Lifetime(shared.clone());
        let worker = shared.clone();
        // Branch before spawning: ordinary writers keep the original future layout.
        let task = if overlap_responses {
            owner.spawn(async move {
                let _lifetime = lifetime;
                if let Err(error) =
                    overlap::transmit(&worker, sender, request, session, eager_capacity).await
                {
                    worker.state.lock().unwrap().error = Some(Arc::new(error));
                }
            })?
        } else {
            owner.spawn(async move {
                let _lifetime = lifetime;
                if let Err(error) =
                    transmit(&worker, sender, request, session, eager_capacity).await
                {
                    worker.state.lock().unwrap().error = Some(Arc::new(error));
                }
            })?
        };
        Ok(Self {
            shared,
            capacity,
            chunk,
            _task: task,
        })
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> Snapshot {
        let state = self.shared.state.lock().unwrap();
        Snapshot {
            buffer_ptr: state.buffer.as_ptr() as usize,
            buffer_len: state.buffer.len(),
            buffer_capacity: state.buffer.capacity(),
            accepted: state.accepted,
            committed: state.committed,
            in_flight: state.in_flight,
            occupied_responses: state.occupied_responses,
            ready_responses: state.ready_responses,
            ready_out_of_order: state.ready_out_of_order,
        }
    }

    pub(super) fn check_read(&self, cx: &mut Context<'_>) -> io::Result<()> {
        self.shared.reader.register(cx.waker());
        self.shared.state.lock().unwrap().check()
    }
}
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.shared.writer.register(cx.waker());
        if self.shared.finishing.load(Ordering::Acquire) {
            return Poll::Ready(Err(connection_closed()));
        }
        let mut state = self.shared.state.lock().unwrap();
        state.check()?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if state.in_flight {
            return Poll::Pending;
        }
        let count = input
            .len()
            .min(self.chunk)
            .min(self.capacity - state.buffer.len());
        if count == 0 {
            return Poll::Pending;
        }
        let accepted = state
            .accepted
            .checked_add(count as u64)
            .ok_or_else(connection_closed)?;
        let needed = state.buffer.len() + count;
        if state.buffer.capacity() < needed {
            // Irregular packet sizes must not double the allocation past the
            // batch limit. Keep amortized growth without reserving an idle
            // writer's entire configured POST maximum.
            let capacity = needed.next_power_of_two().min(self.capacity);
            let additional = capacity - state.buffer.len();
            state.buffer.reserve_exact(additional);
        }
        state.buffer.extend_from_slice(&input[..count]);
        state.accepted = accepted;
        drop(state);
        self.shared.changed.notify_one();
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.flush.register(cx.waker());
        let state = self.shared.state.lock().unwrap();
        state.check()?;
        if state.committed == state.accepted {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.finishing.store(true, Ordering::Release);
        self.shared.finish.notify_one();
        self.poll_flush(cx)
    }
}

async fn transmit(
    shared: &Shared,
    sender: SendRequest,
    request: RequestTemplate,
    session: Arc<str>,
    eager_capacity: Option<usize>,
) -> io::Result<()> {
    let mut sequence = 0_u64;
    let mut last_post_started = None;
    loop {
        loop {
            let changed = shared.changed.notified();
            if !shared.state.lock().unwrap().buffer.is_empty() {
                break;
            }
            changed.await;
        }
        let delay = || Duration::from_millis(request.options.post_interval_ms.sample() as u64);
        wait_interval(shared, last_post_started, delay(), eager_capacity).await;
        // Only one bounded batch, including while HTTP owns its immutable body.
        // Keep writes backpressured until the POSTs have acknowledged this batch.
        let mut batch = {
            let mut state = shared.state.lock().unwrap();
            state.in_flight = true;
            Bytes::from(std::mem::take(&mut state.buffer))
        };
        while !batch.is_empty() {
            let headers =
                request.build(http::Method::POST, Some(&session), Some(sequence), false)?;
            let (headers, payload, count) =
                super::request::packet_payload(headers, &batch, &request.options.data)?;
            sequence = sequence.checked_add(1).ok_or_else(connection_closed)?;
            batch.advance(count);
            last_post_started = Some(Instant::now());
            super::post_packet(sender.clone(), headers, payload).await?;
            shared.state.lock().unwrap().committed += count as u64;
            shared.flush.wake();
            if !batch.is_empty() {
                wait_interval(shared, last_post_started, delay(), None).await;
            }
        }
        // The consumed Bytes retains its backing. Recover it only if HTTP has
        // released every reference; never copy a still-shared body to recycle it.
        let recycled = batch.try_into_mut().map(Vec::from).unwrap_or_default();
        {
            let mut state = shared.state.lock().unwrap();
            state.buffer = recycled;
            state.in_flight = false;
        }
        shared.writer.wake();
    }
}

async fn wait_interval(
    shared: &Shared,
    last_post_started: Option<Instant>,
    delay: Duration,
    eager_capacity: Option<usize>,
) {
    // A partial default batch keeps its original deadline; filling it need not
    // pay another aggregation delay. Explicit user intervals remain unchanged.
    let deadline = last_post_started.unwrap_or_else(Instant::now) + delay;
    loop {
        let finish = shared.finish.notified();
        let changed = shared.changed.notified();
        if shared.finishing.load(Ordering::Acquire)
            || eager_capacity
                .is_some_and(|capacity| shared.state.lock().unwrap().buffer.len() >= capacity)
        {
            return;
        }
        tokio::select! { biased;
            () = finish => return,
            () = changed, if eager_capacity.is_some() => {},
            () = tokio::time::sleep_until(deadline) => return,
        }
    }
}

#[cfg(test)]
#[path = "packet_up_timing_tests.rs"]
mod timing_tests;
