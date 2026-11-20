use super::*;
use futures_util::task::noop_waker;
use std::{future::Future, task::Context};

fn fixture() -> (PacketSink, mpsc::Receiver<Packet>, CancellationToken) {
    let (sender, receiver) = mpsc::channel(32);
    let cancellation = CancellationToken::new();
    (
        PacketSink {
            sender,
            cancellation: cancellation.clone(),
            mtu: 1408,
        },
        receiver,
        cancellation,
    )
}
fn packet(id: u8) -> Packet {
    let mut bytes = vec![0x45; 40];
    bytes[1] = id;
    Packet::new(bytes)
}

#[tokio::test(flavor = "current_thread")]
async fn packet_recover_returns_same_full_owner_and_persistent_send_keeps_fifo() {
    let (sink, mut receiver, _) = fixture();
    for id in 0..32 {
        sink.try_send_recover(packet(id)).unwrap();
    }
    let original = packet(32);
    let address = original.data().as_ptr();
    let (error, recovered) = sink.try_send_recover(original).unwrap_err();
    assert!(matches!(error, NetStackError::Backpressure));
    assert_eq!(recovered.data().as_ptr(), address);
    let mut first = Box::pin(sink.send(recovered));
    let mut second = Box::pin(sink.send(packet(33)));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    // Re-polling wrappers must not replace first's actual semaphore waiter.
    for _ in 0..3 {
        assert!(first.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(receiver.try_recv().unwrap().data()[1], 0);
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert!(matches!(first.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    drop(first);
    assert_eq!(receiver.try_recv().unwrap().data()[1], 1);
    assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    drop(second);
    for id in 2..34 {
        assert_eq!(receiver.try_recv().unwrap().data()[1], id);
    }
    assert!(receiver.try_recv().is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn packet_recover_validation_closed_and_cancel_return_original_packet() {
    let (sink, receiver, cancellation) = fixture();
    for original in [
        Packet::new(Vec::new()),
        Packet::new(vec![0; 40]),
        Packet::new(vec![0x45; 1409]),
    ] {
        let expected = original.clone();
        let (error, returned) = sink.try_send_recover(original).unwrap_err();
        assert!(!matches!(
            error,
            NetStackError::Backpressure | NetStackError::Stopped
        ));
        assert_eq!(returned, expected);
    }
    drop(receiver);
    let original = packet(1);
    let address = original.data().as_ptr();
    let (error, returned) = sink.try_send_recover(original).unwrap_err();
    assert!(matches!(error, NetStackError::Stopped));
    assert_eq!(returned.data().as_ptr(), address);
    cancellation.cancel();
    let original = packet(2);
    let expected = original.clone();
    let (error, returned) = sink.try_send_recover(original).unwrap_err();
    assert!(matches!(error, NetStackError::Stopped));
    assert_eq!(returned, expected);
}

#[tokio::test(flavor = "current_thread")]
async fn packet_recover_pending_send_cancel_precedes_simultaneously_ready_capacity() {
    let (sink, mut receiver, cancellation) = fixture();
    for id in 0..32 {
        sink.try_send(packet(id)).unwrap();
    }
    let mut admission = Box::pin(sink.send(packet(99)));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(admission.as_mut().poll(&mut cx).is_pending());
    receiver.try_recv().unwrap();
    cancellation.cancel();
    assert!(matches!(
        admission.as_mut().poll(&mut cx),
        Poll::Ready(Err(NetStackError::Stopped))
    ));
    drop(admission);
    while let Ok(value) = receiver.try_recv() {
        assert_ne!(value.data()[1], 99);
    }
}
