use super::*;
use futures_util::task::{ArcWake, waker};
use std::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl ArcWake for WakeCount {
    fn wake_by_ref(owner: &Arc<Self>) {
        owner.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn mieru_response_slot_empty_send_does_not_register_a_producer_wake() {
    let (mut sender, mut receiver) = channel();
    let wakes = Arc::new(WakeCount::default());
    let wake = waker(wakes.clone());
    let mut context = Context::from_waker(&wake);
    {
        let sending = sender.send(1);
        let mut sending = std::pin::pin!(sending);
        assert_eq!(sending.as_mut().poll(&mut context), Poll::Ready(Ok(())));
    }
    assert_eq!(receiver.poll_recv(&mut context), Poll::Ready(Some(1)));
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
}

#[test]
fn mieru_response_slot_backpressure_wakes_both_directions() {
    let (mut sender, mut receiver) = channel();
    let receive_wakes = Arc::new(WakeCount::default());
    let receive_waker = waker(receive_wakes.clone());
    let mut receiving = Context::from_waker(&receive_waker);
    let send_wakes = Arc::new(WakeCount::default());
    let send_waker = waker(send_wakes.clone());
    let mut sending = Context::from_waker(&send_waker);

    assert!(receiver.poll_recv(&mut receiving).is_pending());
    {
        let sending = sender.send(1);
        let mut sending = std::pin::pin!(sending);
        assert_eq!(sending.as_mut().poll(&mut receiving), Poll::Ready(Ok(())));
    }
    assert!(receive_wakes.0.load(Ordering::Relaxed) > 0);
    let sending_second = sender.send(2);
    let mut sending_second = std::pin::pin!(sending_second);
    assert!(sending_second.as_mut().poll(&mut sending).is_pending());
    let before = send_wakes.0.load(Ordering::Relaxed);
    assert_eq!(receiver.poll_recv(&mut receiving), Poll::Ready(Some(1)));
    assert!(send_wakes.0.load(Ordering::Relaxed) > before);
    assert!(receiver.poll_recv(&mut receiving).is_pending());
    let before = receive_wakes.0.load(Ordering::Relaxed);
    assert_eq!(
        sending_second.as_mut().poll(&mut sending),
        Poll::Ready(Ok(()))
    );
    assert!(receive_wakes.0.load(Ordering::Relaxed) > before);
    assert_eq!(receiver.poll_recv(&mut receiving), Poll::Ready(Some(2)));
}

#[test]
fn mieru_response_slot_sender_end_preserves_final_error_then_eof() {
    let (mut sender, mut receiver) = channel::<Result<(), &'static str>>();
    let wakes = Arc::new(WakeCount::default());
    let wake = waker(wakes.clone());
    let mut context = Context::from_waker(&wake);
    assert!(receiver.poll_recv(&mut context).is_pending());
    {
        let sending = sender.send(Err("final codec error"));
        let mut sending = std::pin::pin!(sending);
        assert_eq!(sending.as_mut().poll(&mut context), Poll::Ready(Ok(())));
    }
    drop(sender);
    assert_eq!(
        receiver.poll_recv(&mut context),
        Poll::Ready(Some(Err("final codec error")))
    );
    assert_eq!(receiver.poll_recv(&mut context), Poll::Ready(None));

    let (sender, mut receiver) = channel::<()>();
    assert!(receiver.poll_recv(&mut context).is_pending());
    let before = wakes.0.load(Ordering::Relaxed);
    drop(sender);
    assert!(wakes.0.load(Ordering::Relaxed) > before);
    assert_eq!(receiver.poll_recv(&mut context), Poll::Ready(None));
}

struct CountDrop(Arc<AtomicUsize>);
impl Drop for CountDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn mieru_response_slot_receiver_close_or_drop_releases_blocked_sender() {
    for explicit_close in [false, true] {
        let (mut sender, mut receiver) = channel();
        let drops = Arc::new(AtomicUsize::new(0));
        let wakes = Arc::new(WakeCount::default());
        let wake = waker(wakes.clone());
        let mut context = Context::from_waker(&wake);
        {
            let sending = sender.send(CountDrop(drops.clone()));
            let mut sending = std::pin::pin!(sending);
            assert!(matches!(
                sending.as_mut().poll(&mut context),
                Poll::Ready(Ok(()))
            ));
        }
        let blocked = sender.send(CountDrop(drops.clone()));
        let mut blocked = std::pin::pin!(blocked);
        assert!(blocked.as_mut().poll(&mut context).is_pending());
        let before = wakes.0.load(Ordering::Relaxed);
        if explicit_close {
            receiver.close();
            receiver.close();
            assert!(matches!(
                receiver.poll_recv(&mut context),
                Poll::Ready(None)
            ));
        }
        drop(receiver);
        assert!(wakes.0.load(Ordering::Relaxed) > before);
        assert_eq!(drops.load(Ordering::Relaxed), 1, "queued item discarded");
        let Poll::Ready(Err(unsubmitted)) = blocked.as_mut().poll(&mut context) else {
            panic!("receiver termination must return the unsubmitted item");
        };
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        drop(unsubmitted);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn mieru_response_slot_cancelled_send_keeps_the_committed_item() {
    let (mut sender, mut receiver) = channel();
    let wake = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&wake);
    {
        let sending = sender.send(1);
        let mut sending = std::pin::pin!(sending);
        assert_eq!(sending.as_mut().poll(&mut context), Poll::Ready(Ok(())));
    }
    {
        let blocked = sender.send(2);
        let mut blocked = std::pin::pin!(blocked);
        assert!(blocked.as_mut().poll(&mut context).is_pending());
        // Drop the actual pending send future, rather than just its Pin handle.
    }
    assert_eq!(receiver.poll_recv(&mut context), Poll::Ready(Some(1)));
    let sending = sender.send(3);
    let mut sending = std::pin::pin!(sending);
    assert_eq!(sending.as_mut().poll(&mut context), Poll::Ready(Ok(())));
    assert_eq!(receiver.poll_recv(&mut context), Poll::Ready(Some(3)));
    assert!(receiver.poll_recv(&mut context).is_pending());
}

#[tokio::test]
async fn mieru_response_slot_cross_thread_handoffs_drain_and_join() {
    let (mut sender, mut receiver) = channel::<usize>();
    let producer = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let sent = runtime.block_on(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                for value in 0..2048 {
                    sender.send(value).await?;
                    if value % 3 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                Ok::<_, usize>(())
            })
            .await
        });
        (std::thread::current().id(), sent)
    });
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        while let Some(value) = poll_fn(|context| receiver.poll_recv(context)).await {
            received.push(value);
            if received.len() % 5 == 0 {
                tokio::task::yield_now().await;
            }
        }
        received
    })
    .await;
    // Always unblock and join the other thread before asserting timeout/results.
    receiver.close();
    let (producer_thread, sent) = producer.join().unwrap();
    assert_ne!(producer_thread, std::thread::current().id());
    assert!(matches!(sent, Ok(Ok(()))));
    assert_eq!(received.unwrap(), (0..2048).collect::<Vec<_>>());
}
