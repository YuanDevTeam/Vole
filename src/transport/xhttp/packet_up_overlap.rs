//! Serial Body uploads with two bounded, in-order response acknowledgements.
use super::{RequestTemplate, SendRequest, Shared, connection_closed, wait_interval};
use bytes::Bytes;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

type Response = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

// Bytes owns this lease until the last body reference disappears. Returning the
// Vec is an event, not a uniqueness retry or a second body allocation.
struct BodyLease {
    buffer: Vec<u8>,
    shared: Weak<Shared>,
}
impl AsRef<[u8]> for BodyLease {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}
impl Drop for BodyLease {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            let mut buffer = std::mem::take(&mut self.buffer);
            buffer.clear();
            let mut state = shared.state.lock().unwrap();
            // Cancellation may already have closed the writer. Never replace
            // another workspace; live workers have taken its sole allocation.
            if !state.closed && state.buffer.is_empty() && state.buffer.capacity() == 0 {
                state.buffer = buffer;
                drop(state);
                shared.changed.notify_one();
            }
        }
    }
}

struct Slot {
    sequence: u64,
    end: u64,
    finished: bool,
    complete: bool,
    response: Option<Response>,
}
#[derive(Default)]
struct Responses {
    slots: [Option<Slot>; 2],
}
impl Responses {
    fn full(&self) -> bool {
        self.slots[1].is_some()
    }

    fn push(&mut self, sequence: u64, end: u64, response: super::super::ResponseFuture) {
        let response = Box::pin(async move {
            let response = response.await?;
            super::super::ensure_success(response.status(), "packet-up upload", false)?;
            let mut body = response.into_body();
            let mut drained = 0usize;
            while let Some(data) = poll_fn(|cx| body.poll_data(cx)).await {
                let data = data?;
                drained = drained.saturating_add(data.len());
                if drained > super::super::request::MAX_REQUEST_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "XHTTP upload response exceeds its drain budget",
                    ));
                }
                body.release_capacity(data.len())?;
                tokio::task::yield_now().await;
            }
            Ok(())
        });
        let index = usize::from(self.slots[0].is_some());
        debug_assert!(self.slots[index].is_none());
        self.slots[index] = Some(Slot {
            sequence,
            end,
            finished: false,
            complete: false,
            response: Some(response),
        });
    }

    fn retire(&mut self, shared: &Shared) -> bool {
        let mut committed = None;
        while self.slots[0]
            .as_ref()
            .is_some_and(|slot| slot.finished && slot.complete)
        {
            committed = self.slots[0].take().map(|slot| slot.end);
            self.slots[0] = self.slots[1].take();
        }
        if let Some(committed) = committed {
            shared.state.lock().unwrap().committed = committed;
            shared.flush.wake();
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn publish(&self, shared: &Shared) {
        let mut state = shared.state.lock().unwrap();
        state.occupied_responses = self.slots.iter().flatten().count();
        state.ready_responses = self
            .slots
            .iter()
            .flatten()
            .filter(|slot| slot.complete)
            .count();
        state.ready_out_of_order = self.slots[0]
            .as_ref()
            .is_some_and(|slot| !slot.finished || !slot.complete)
            && self.slots[1].as_ref().is_some_and(|slot| slot.complete);
    }

    fn poll(&mut self, shared: &Shared, cx: &mut Context<'_>) -> io::Result<()> {
        let mut completed = false;
        let mut failure = None;
        for slot in self.slots.iter_mut().flatten() {
            let Some(response) = &mut slot.response else {
                continue;
            };
            if let Poll::Ready(result) = response.as_mut().poll(cx) {
                // Dropping the completed future also releases its receive half.
                slot.response = None;
                match result {
                    Ok(()) => {
                        slot.complete = true;
                        completed = true;
                    }
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
        }
        let retired = self.retire(shared);
        if completed || retired {
            #[cfg(test)]
            self.publish(shared);
        }
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }

    fn finished(&mut self, shared: &Shared, sequence: u64) {
        for slot in self.slots.iter_mut().flatten() {
            if slot.sequence == sequence {
                slot.finished = true;
                break;
            }
        }
        if self.retire(shared) {
            #[cfg(test)]
            self.publish(shared);
        }
    }

    async fn drive<T>(
        &mut self,
        shared: &Shared,
        operation: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let mut operation = std::pin::pin!(operation);
        poll_fn(|cx| {
            self.poll(shared, cx)?;
            operation.as_mut().poll(cx)
        })
        .await
    }

    async fn wait_room(&mut self, shared: &Shared) -> io::Result<()> {
        poll_fn(|cx| {
            self.poll(shared, cx)?;
            if self.full() {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        })
        .await
    }
}

pub(super) async fn transmit(
    shared: &Arc<Shared>,
    mut sender: SendRequest,
    request: RequestTemplate,
    session: Arc<str>,
    eager_capacity: Option<usize>,
) -> io::Result<()> {
    let mut responses = Responses::default();
    let mut sequence = 0_u64;
    let mut last_post_started = None;
    loop {
        responses
            .drive(shared, async {
                loop {
                    let changed = shared.changed.notified();
                    if !shared.state.lock().unwrap().buffer.is_empty() {
                        return Ok(());
                    }
                    changed.await;
                }
            })
            .await?;
        // Shorten only this shared-H3 writer's default partial-batch deadline.
        let delay = if eager_capacity.is_some() {
            Duration::from_millis(5)
        } else {
            Duration::from_millis(request.options.post_interval_ms.sample() as u64)
        };
        responses
            .drive(shared, async {
                wait_interval(shared, last_post_started, delay, eager_capacity).await;
                Ok(())
            })
            .await?;
        let (buffer, end) = {
            let mut state = shared.state.lock().unwrap();
            state.in_flight = true;
            (std::mem::take(&mut state.buffer), state.accepted)
        };
        let batch = Bytes::from_owner(BodyLease {
            buffer,
            shared: Arc::downgrade(shared),
        });
        let current = sequence;
        let headers = request.build(http::Method::POST, Some(&session), Some(current), false)?;
        sequence = sequence.checked_add(1).ok_or_else(connection_closed)?;
        last_post_started = Some(Instant::now());
        let (response, mut upload) = responses
            .drive(shared, sender.send_request(headers, false))
            .await?;
        responses.push(current, end, response);
        // The factory only selects normalized Body. Transfer its lease outright;
        // retaining a root Bytes here would prevent the final-owner handback.
        responses
            .drive(shared, async {
                upload.send_data(batch, true)?;
                poll_fn(|cx| upload.poll_finish(cx)).await
            })
            .await?;
        drop(upload);
        responses.finished(shared, current);
        responses
            .drive(shared, async {
                loop {
                    let changed = shared.changed.notified();
                    if shared.state.lock().unwrap().buffer.capacity() != 0 {
                        return Ok(());
                    }
                    changed.await;
                }
            })
            .await?;
        // A ready response behind a hole still occupies one of these two slots.
        // Do not admit even a prefill until both the sole Vec and a slot are free.
        responses.wait_room(shared).await?;
        shared.state.lock().unwrap().in_flight = false;
        shared.writer.wake();
    }
}

#[cfg(test)]
mod lease_memory_tests {
    use super::super::State;
    use super::{BodyLease, Shared};
    use bytes::Bytes;
    use futures_util::{poll, task::AtomicWaker};
    use std::sync::{Arc, Mutex, atomic::AtomicBool};
    use tokio::{
        sync::Notify,
        time::{Duration, timeout},
    };

    fn shared(closed: bool) -> Arc<Shared> {
        Arc::new(Shared {
            state: Mutex::new(State {
                buffer: Vec::new(),
                accepted: 0,
                committed: 0,
                error: None,
                closed,
                in_flight: true,
                occupied_responses: 0,
                ready_responses: 0,
                ready_out_of_order: false,
            }),
            changed: Notify::new(),
            finishing: AtomicBool::new(false),
            finish: Notify::new(),
            writer: AtomicWaker::new(),
            flush: AtomicWaker::new(),
            reader: AtomicWaker::new(),
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn last_body_clone_returns_same_vec_and_notifies_existing_waiter() {
        let shared = shared(false);
        let buffer = vec![0x5a; 5000];
        let pointer = buffer.as_ptr() as usize;
        let capacity = buffer.capacity();
        let bytes = Bytes::from_owner(BodyLease {
            buffer,
            shared: Arc::downgrade(&shared),
        });
        let last = bytes.clone();
        let changed = shared.changed.notified();
        tokio::pin!(changed);
        assert!(poll!(changed.as_mut()).is_pending());
        drop(bytes);
        {
            let state = shared.state.lock().unwrap();
            assert_eq!(state.buffer.capacity(), 0);
            assert!(state.buffer.is_empty());
            assert!(state.in_flight);
        }
        assert!(poll!(changed.as_mut()).is_pending());
        // No mutex guard is live at either final body Drop or Notify polling.
        drop(last);
        timeout(Duration::from_secs(5), changed.as_mut())
            .await
            .unwrap();
        {
            let state = shared.state.lock().unwrap();
            assert_eq!(state.buffer.as_ptr() as usize, pointer);
            assert_eq!(state.buffer.capacity(), capacity);
            assert!(state.buffer.is_empty());
            // Storage return alone neither acknowledges bytes nor opens admission.
            assert!(state.in_flight);
            assert_eq!(state.committed, 0);
        }
        assert_eq!(Arc::weak_count(&shared), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closed_or_destroyed_shared_does_not_retain_or_revive_body_owner() {
        {
            let shared = shared(true);
            let bytes = Bytes::from_owner(BodyLease {
                buffer: vec![0x7b; 5000],
                shared: Arc::downgrade(&shared),
            });
            let last = bytes.clone();
            let changed = shared.changed.notified();
            tokio::pin!(changed);
            assert!(poll!(changed.as_mut()).is_pending());
            drop(bytes);
            assert_eq!(Arc::weak_count(&shared), 1);
            drop(last);
            // The real owner was destroyed; closed storage received no buffer.
            assert_eq!(Arc::weak_count(&shared), 0);
            assert_eq!(Arc::strong_count(&shared), 1);
            {
                let state = shared.state.lock().unwrap();
                assert!(state.closed);
                assert!(state.buffer.is_empty());
                assert_eq!(state.buffer.capacity(), 0);
            }
            assert!(poll!(changed.as_mut()).is_pending());
        }
        {
            let shared = shared(false);
            let weak = Arc::downgrade(&shared);
            let bytes = Bytes::from_owner(BodyLease {
                buffer: vec![0x7b; 5000],
                shared: weak.clone(),
            });
            let last = bytes.clone();
            drop(shared);
            assert!(weak.upgrade().is_none());
            drop(bytes);
            assert!(weak.upgrade().is_none());
            drop(last);
            assert!(weak.upgrade().is_none());
            assert_eq!(weak.strong_count(), 0);
        }
    }
}
