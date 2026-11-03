//! The packet reader and transport each own one end of this one-response slot.
use futures_util::task::AtomicWaker;
use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

struct State<T> {
    value: Option<T>,
    sender_alive: bool,
    receiver_alive: bool,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    sender: AtomicWaker,
    receiver: AtomicWaker,
}

// Neither endpoint is Clone; mutable methods serialize each direction's waker.
pub(super) struct Sender<T>(Arc<Shared<T>>);
pub(super) struct Receiver<T>(Arc<Shared<T>>);

struct SendWait<'a>(&'a AtomicWaker);
impl Drop for SendWait<'_> {
    fn drop(&mut self) {
        self.0.take();
    }
}

pub(super) fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            value: None,
            sender_alive: true,
            receiver_alive: true,
        }),
        sender: AtomicWaker::new(),
        receiver: AtomicWaker::new(),
    });
    (Sender(shared.clone()), Receiver(shared))
}

impl<T> Sender<T> {
    pub(super) async fn send(&mut self, value: T) -> Result<(), T> {
        let mut value = Some(value);
        let _wait = SendWait(&self.0.sender);
        poll_fn(|context| {
            let mut registered = false;
            loop {
                let mut state = self.0.state.lock().unwrap();
                if !state.receiver_alive {
                    drop(state);
                    return Poll::Ready(Err(value.take().unwrap()));
                }
                if state.value.is_none() {
                    state.value = value.take();
                    drop(state);
                    self.0.receiver.wake();
                    return Poll::Ready(Ok(()));
                }
                drop(state);
                if registered {
                    return Poll::Pending;
                }
                // Register only for a full slot, then recheck any concurrent take.
                self.0.sender.register(context.waker());
                registered = true;
            }
        })
        .await
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().sender_alive = false;
        // A final packet or codec error remains available before EOF.
        self.0.receiver.wake();
    }
}

impl<T> Receiver<T> {
    pub(super) fn poll_recv(&mut self, context: &mut Context<'_>) -> Poll<Option<T>> {
        self.0.receiver.register(context.waker());
        let mut state = self.0.state.lock().unwrap();
        if !state.receiver_alive {
            return Poll::Ready(None);
        }
        if let Some(value) = state.value.take() {
            drop(state);
            self.0.sender.wake();
            return Poll::Ready(Some(value));
        }
        if state.sender_alive {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }

    pub(super) fn close(&mut self) {
        let queued = {
            let mut state = self.0.state.lock().unwrap();
            if !state.receiver_alive {
                return;
            }
            state.receiver_alive = false;
            state.value.take()
        };
        // Dropping a response or waking its producer may execute other code.
        drop(queued);
        self.0.sender.wake();
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.state.lock().unwrap().value.is_none()
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
#[path = "packet_response_tests.rs"]
mod tests;
