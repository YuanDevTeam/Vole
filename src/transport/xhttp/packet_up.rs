//! Timer-driven bounded aggregation. Writes acknowledge admitted bytes; flush
//! waits for their POST responses. The node owns and joins the timer/IO driver.
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
        // Mihomo samples this maximum once per logical writer. Never allocate
        // the configurable (up to 16 MiB) maximum per connection.
        let capacity = request
            .options
            .post_bytes
            .sample()
            .min(crate::limits::XHTTP_PACKET_BATCH_BYTES);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                buffer: Vec::new(),
                accepted: 0,
                committed: 0,
                error: None,
                closed: false,
            }),
            changed: Notify::new(),
            finishing: AtomicBool::new(false),
            finish: Notify::new(),
            writer: AtomicWaker::new(),
            flush: AtomicWaker::new(),
            reader: AtomicWaker::new(),
        });
        let lifetime = Lifetime(shared.clone());
        let worker = shared.clone();
        let task = owner.spawn(async move {
            let _lifetime = lifetime;
            if let Err(error) = transmit(&worker, sender, request, session).await {
                worker.state.lock().unwrap().error = Some(Arc::new(error));
            }
        })?;
        Ok(Self {
            shared,
            capacity,
            chunk,
            _task: task,
        })
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
        wait_interval(shared, last_post_started, delay()).await;
        // One bounded batch in flight and one filling batch. Only this driver
        // owns POST completion; read cannot acknowledge a pending caller write.
        let mut batch = {
            let mut state = shared.state.lock().unwrap();
            Bytes::from(std::mem::take(&mut state.buffer))
        };
        shared.writer.wake();
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
                wait_interval(shared, last_post_started, delay()).await;
            }
        }
    }
}

async fn wait_interval(shared: &Shared, last_post_started: Option<Instant>, delay: Duration) {
    let finish = shared.finish.notified();
    if !shared.finishing.load(Ordering::Acquire) {
        // The first batch retains its aggregation delay. Later POST starts are
        // separated by the sampled interval, including the previous exchange.
        let deadline = last_post_started.unwrap_or_else(Instant::now) + delay;
        tokio::select! { biased;
            () = finish => {},
            () = tokio::time::sleep_until(deadline) => {},
        }
    }
}

#[cfg(test)]
#[path = "packet_up_timing_tests.rs"]
mod timing_tests;
