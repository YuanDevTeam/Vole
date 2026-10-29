//! Real RawStream/PacketTransport boundaries over the existing bounded command FIFO.
//! Manual done signals are physical-first-send witnesses, not a second UDP driver.
use super::super::{packet::PacketTransport, stream::Stream};
use super::*;
use crate::{
    dispatch::DatagramTransport,
    outbound::DatagramRequest,
    session::{Datagram, DatagramSession, Destination},
};
use std::{
    future::Future,
    task::{Wake, Waker},
};

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(1), future)
        .await
        .expect("Mieru memory seam did not complete within its original ownership boundary")
}

#[tokio::test]
async fn mieru_udp_admission_empty_write_keeps_pending_barrier_and_error_priority() {
    let (mut raw, mut commands, state, credit) = fixture(true, 16);
    bounded(raw.write_all(b"AAAA")).await.unwrap();
    let command = commands.try_recv().unwrap();
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(matches!(
        Pin::new(&mut raw).poll_write(&mut cx, &[]),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(credit.available_permits(), 12);
    assert!(Pin::new(&mut raw).poll_flush(&mut cx).is_pending());
    let permit = first_sent(command);
    bounded(raw.flush()).await.unwrap();
    assert_eq!(credit.available_permits(), 12);
    drop(permit);
    assert_eq!(credit.available_permits(), 16);
    state.close();

    let (mut raw, mut commands, state, _) = fixture(true, 16);
    bounded(raw.write_all(b"AAAA")).await.unwrap();
    let WriterCommand { done, _bytes, .. } = commands.try_recv().unwrap();
    done.send(Err(io::ErrorKind::TimedOut.into())).unwrap();
    assert!(matches!(
        Pin::new(&mut raw).poll_write(&mut cx, &[]),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut
    ));
    drop(_bytes);
    state.close();

    let (mut raw, mut commands, state, _) = fixture(true, 16);
    bounded(raw.write_all(b"AAAA")).await.unwrap();
    let command = commands.try_recv().unwrap();
    state.close();
    assert!(matches!(
        Pin::new(&mut raw).poll_write(&mut cx, &[]),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
    drop(command);
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn fixture(
    queued: bool,
    capacity: usize,
) -> (
    RawStream,
    mpsc::Receiver<WriterCommand>,
    Arc<State>,
    Arc<Semaphore>,
) {
    fixture_chunk(queued, capacity, capacity)
}
fn fixture_chunk(
    queued: bool,
    capacity: usize,
    chunk: usize,
) -> (
    RawStream,
    mpsc::Receiver<WriterCommand>,
    Arc<State>,
    Arc<Semaphore>,
) {
    let shared = Shared::output_test_shared(CancellationToken::new());
    let business = if queued {
        Business::UdpAssociate
    } else {
        Business::TcpConnect
    };
    let state = State::new_for_business(
        7,
        capacity,
        business,
        &shared.cancel,
        shared.activity.clone(),
    );
    shared.sessions.lock().unwrap().insert(7, state.clone());
    let (writer, commands) = mpsc::channel(WRITER_COMMANDS);
    let bytes = Arc::new(Semaphore::new(capacity));
    let carrier = Arc::new(Carrier {
        shared,
        writer,
        bytes: bytes.clone(),
    });
    (
        RawStream::new(carrier, state.clone(), chunk).with_queued_writes(queued),
        commands,
        state,
        bytes,
    )
}
fn first_sent(command: WriterCommand) -> OwnedSemaphorePermit {
    let WriterCommand { done, _bytes, .. } = command;
    let _ = done.send(Ok(())); // A cancelled owner may already have dropped its witness.
    _bytes // Keep the original payload permit through simulated ACK/retirement.
}

#[tokio::test]
async fn mieru_udp_admission_latest_first_send_barrier_and_byte_ownership() {
    let (mut raw, mut commands, state, credit) = fixture(true, 32);
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let mut admitted = Vec::new();
    for data in [b"AAAA", b"BBBB", b"CCCC", b"DDDD"] {
        bounded(raw.write_all(data)).await.unwrap();
        admitted.push(commands.try_recv().unwrap());
    }
    assert_eq!(credit.available_permits(), 16);
    let mut next = Box::pin(raw.write_all(b"EEEE"));
    assert!(next.as_mut().poll(&mut cx).is_pending());
    assert!(commands.try_recv().is_err());
    assert_eq!(
        credit.available_permits(),
        16,
        "fifth write allocates no permit before its barrier"
    );
    let fourth = admitted.pop().unwrap();
    let mut held: Vec<_> = admitted.into_iter().map(first_sent).collect();
    assert!(
        next.as_mut().poll(&mut cx).is_pending(),
        "latest covers all replaced first-send witnesses"
    );
    assert_eq!(credit.available_permits(), 16);
    let wakes = wake.0.load(Ordering::Relaxed);
    held.push(first_sent(fourth));
    assert!(wake.0.load(Ordering::Relaxed) > wakes);
    assert!(matches!(next.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    drop(next);
    let fifth = commands.try_recv().unwrap();
    assert_eq!(&fifth.data[..], b"EEEE");
    assert_eq!(credit.available_permits(), 12);
    let mut flushing = Box::pin(raw.flush());
    assert!(flushing.as_mut().poll(&mut cx).is_pending());
    drop(flushing);
    let mut shutdown = Box::pin(raw.shutdown());
    assert!(shutdown.as_mut().poll(&mut cx).is_pending());
    assert!(!state.local_closed.load(Ordering::Acquire));
    held.push(first_sent(fifth));
    assert!(matches!(
        shutdown.as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    drop(shutdown);
    assert!(state.local_closed.load(Ordering::Acquire));
    assert_eq!(
        credit.available_permits(),
        12,
        "first-send and shutdown retain actor credit"
    );
    bounded(raw.shutdown()).await.unwrap();
    drop(held);
    assert_eq!(credit.available_permits(), 32);
}

#[tokio::test]
async fn mieru_udp_admission_depth4_never_bypasses_a_ready_first_send_error() {
    for dropped in [false, true] {
        let (mut raw, mut commands, state, credit) = fixture(true, 16);
        bounded(raw.write_all(b"AAAA")).await.unwrap();
        let WriterCommand { done, _bytes, .. } = commands.try_recv().unwrap();
        if dropped {
            drop(done);
        } else {
            done.send(Err(io::ErrorKind::TimedOut.into())).unwrap();
        }
        let mut cx = Context::from_waker(Waker::noop());
        let result = Pin::new(&mut raw).poll_write(&mut cx, b"B");
        assert!(
            matches!(result, Poll::Ready(Err(error)) if error.kind() == if dropped { io::ErrorKind::BrokenPipe } else { io::ErrorKind::TimedOut })
        );
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(credit.available_permits(), 12);
        state.close();
        drop(_bytes);
        assert_eq!(credit.available_permits(), 16);
    }
}

#[tokio::test]
async fn mieru_udp_admission_depth4_state_failure_wakes_without_releasing_actor_credit() {
    let (mut raw, mut commands, state, credit) = fixture(true, 32);
    let mut admitted = Vec::new();
    for data in [b"AAAA", b"BBBB", b"CCCC", b"DDDD"] {
        bounded(raw.write_all(data)).await.unwrap();
        admitted.push(commands.try_recv().unwrap());
    }
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let mut fifth = Box::pin(raw.write_all(b"E"));
    assert!(fifth.as_mut().poll(&mut cx).is_pending());
    let before = wake.0.load(Ordering::Relaxed);
    state.finish(true);
    assert!(wake.0.load(Ordering::Relaxed) > before);
    assert!(matches!(fifth.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
    drop(fifth);
    assert!(bounded(raw.flush()).await.is_err());
    assert!(bounded(raw.shutdown()).await.is_err());
    assert!(matches!(
        Pin::new(&mut raw).poll_write(&mut cx, &[]),
        Poll::Ready(Err(_))
    ));
    assert_eq!(credit.available_permits(), 16);
    drop((raw, admitted, commands));
    assert_eq!(credit.available_permits(), 32);
}

#[tokio::test]
async fn mieru_udp_admission_classic_write_and_budget_cancel_keep_original_boundaries() {
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let (mut raw, mut commands, _state, credit) = fixture(false, 4);
    let mut writing = Box::pin(raw.write_all(b"AAAA"));
    assert!(
        writing.as_mut().poll(&mut cx).is_pending(),
        "classic mode still waits physical first-send"
    );
    let permit = first_sent(commands.try_recv().unwrap());
    assert!(matches!(
        writing.as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    drop(writing);
    drop(permit);
    drop(raw);
    assert_eq!(credit.available_permits(), 4);

    for complete_first in [false, true] {
        let capacity = if complete_first { 4 } else { 32 };
        let (mut raw, mut commands, state, credit) = fixture(true, capacity);
        bounded(raw.write_all(b"AAAA")).await.unwrap();
        let first = commands.try_recv().unwrap();
        let (mut retained, retained_permit) = if complete_first {
            (Vec::new(), Some(first_sent(first)))
        } else {
            (vec![first], None)
        };
        if !complete_first {
            for data in [b"BBBB", b"CCCC", b"DDDD"] {
                bounded(raw.write_all(data)).await.unwrap();
                retained.push(commands.try_recv().unwrap());
            }
        }
        assert_eq!(
            credit.available_permits(),
            capacity - if complete_first { 4 } else { 16 }
        );
        let mut blocked = Box::pin(raw.write_all(b"B"));
        assert!(
            blocked.as_mut().poll(&mut cx).is_pending(),
            "block at depth4 latest with free bytes, or original budget after first-send"
        );
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let wakes = wake.0.load(Ordering::Relaxed);
        state.close();
        assert!(wake.0.load(Ordering::Relaxed) > wakes);
        assert!(matches!(
            blocked.as_mut().poll(&mut cx),
            Poll::Ready(Err(_))
        ));
        drop(blocked);
        drop(raw);
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        drop((retained, retained_permit));
        assert_eq!(credit.available_permits(), capacity);
    }
}

#[tokio::test]
async fn mieru_udp_admission_packet_send_cancel_never_reuses_a_partial_record() {
    let shared = Shared::output_test_shared(CancellationToken::new());
    let state = State::new(7, 128, &shared.cancel, shared.activity.clone());
    shared.sessions.lock().unwrap().insert(7, state.clone());
    let sibling = State::new(8, 128, &shared.cancel, shared.activity.clone());
    let credit = Arc::new(Semaphore::new(128));
    let (writer, mut commands) = mpsc::channel(WRITER_COMMANDS);
    // Another logical source fills the original FIFO, so our SID can cancel
    // its first admission while waiting on mpsc, independently of the first-send burst gate.
    for data in [b"AAAA", b"BBBB"] {
        let (done, _receiver) = oneshot::channel();
        writer
            .try_send(WriterCommand {
                state: sibling.clone(),
                data: Bytes::copy_from_slice(data),
                piggyback: false,
                done,
                _bytes: credit.clone().try_acquire_many_owned(4).unwrap(),
            })
            .unwrap();
    }
    let carrier = Arc::new(Carrier {
        shared,
        writer,
        bytes: credit.clone(),
    });
    let raw = RawStream::new(carrier, state.clone(), 128).with_queued_writes(true);
    let parent = CancellationToken::new();
    let request = DatagramRequest::new(DatagramSession::for_tun(
        "192.0.2.1:1234".parse().unwrap(),
        1500,
    ));
    let context = EstablishContext::with_timeout(Duration::from_secs(1));
    let mut packet = PacketTransport::new(Box::new(raw), &request, &context, parent, |reader| {
        Ok(tokio::spawn(reader))
    })
    .unwrap()
    .with_queued_sends(true);
    let datagram = || Datagram {
        remote: Destination::Ip("198.51.100.1:443".parse().unwrap()),
        payload: Bytes::from_static(b"cancelled"),
        sniffed_domain: None,
    };
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut sending = Box::pin(packet.send(datagram()));
    assert!(sending.as_mut().poll(&mut cx).is_pending());
    drop(sending); // Exercise the production SendGuard, not raw AsyncWrite cancellation/reuse.
    assert!(bounded(packet.send(datagram())).await.is_err());
    bounded(packet.close()).await.unwrap();
    assert!(state.local_closed.load(Ordering::Acquire));
    let first = commands.try_recv().unwrap();
    let second = commands.try_recv().unwrap();
    assert_eq!(&first.data[..], b"AAAA");
    assert_eq!(&second.data[..], b"BBBB");
    assert!(
        commands.try_recv().is_err(),
        "cancelled pending mpsc admission is never replayed"
    );
    drop((first, second, commands, packet));
    assert_eq!(credit.available_permits(), 128);
}

#[tokio::test]
async fn mieru_udp_admission_no_wait_shutdown_retains_the_started_handshake_barrier() {
    let (raw, mut commands, state, credit) = fixture(true, 256);
    let target = Destination::Ip("0.0.0.0:0".parse().unwrap());
    let mut stream = Stream::no_wait(raw, &target, crate::socks5::COMMAND_UDP_ASSOCIATE).unwrap();
    let wake = Arc::new(WakeCount::default());
    let waker = Waker::from(wake);
    let mut cx = Context::from_waker(&waker);
    let mut writing = Box::pin(stream.write_all(b"AAAA"));
    assert!(writing.as_mut().poll(&mut cx).is_pending());
    drop(writing); // The Stream retains its original in-progress business handshake.
    let command = commands.try_recv().unwrap();
    let queued = command.data.len();
    state
        .deliver(Bytes::from_static(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        .await
        .unwrap();
    let mut shutdown = Box::pin(stream.shutdown());
    assert!(
        shutdown.as_mut().poll(&mut cx).is_pending(),
        "successful response must not drop the outstanding first-send barrier"
    );
    assert!(!state.local_closed.load(Ordering::Acquire));
    let permit = first_sent(command);
    assert!(matches!(
        shutdown.as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    drop(shutdown);
    bounded(stream.shutdown()).await.unwrap(); // Idempotent after successful queued shutdown.
    assert!(state.local_closed.load(Ordering::Acquire));
    assert_eq!(credit.available_permits(), 256 - queued);
    drop((stream, permit, commands));
    assert_eq!(credit.available_permits(), 256);
}

#[tokio::test]
async fn mieru_udp_admission_depth4_partial_packet_chunks_preserve_send_guard() {
    for cancel in [false, true] {
        let (raw, mut commands, state, credit) = fixture_chunk(true, 128, 4);
        let request = DatagramRequest::new(DatagramSession::for_tun(
            "192.0.2.1:1234".parse().unwrap(),
            1500,
        ));
        let context = EstablishContext::with_timeout(Duration::from_secs(1));
        let mut packet = PacketTransport::new(
            Box::new(raw),
            &request,
            &context,
            CancellationToken::new(),
            |reader| Ok(tokio::spawn(reader)),
        )
        .unwrap()
        .with_queued_sends(true);
        let target = Destination::Ip("198.51.100.1:443".parse().unwrap());
        let datagram = || Datagram {
            remote: target.clone(),
            payload: Bytes::from_static(b"cancelled"),
            sniffed_domain: None,
        };
        let mut cx = Context::from_waker(Waker::noop());
        let mut sending = Box::pin(packet.send(datagram()));
        let result = sending.as_mut().poll(&mut cx);
        assert!(result.is_pending());
        assert_eq!(
            credit.available_permits(),
            116,
            "FIFO2 holds two chunks and the pending third owns its original permit"
        );
        let first = commands.try_recv().unwrap();
        let second = commands.try_recv().unwrap();
        assert_eq!(first.data.len(), 4);
        assert_eq!(second.data.len(), 4);
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        // Free the original FIFO2, then allow the third and fourth chunks.
        assert!(sending.as_mut().poll(&mut cx).is_pending());
        let third = commands.try_recv().unwrap();
        let fourth = commands.try_recv().unwrap();
        assert_eq!(third.data.len(), 4);
        assert_eq!(fourth.data.len(), 4);
        assert_eq!(credit.available_permits(), 112);
        assert!(
            commands.try_recv().is_err(),
            "fifth chunk waits before allocation"
        );
        if cancel {
            drop(sending);
            assert!(
                bounded(packet.send(datagram())).await.is_err(),
                "cancelled partial record poisons the stream"
            );
            bounded(packet.close()).await.unwrap();
            assert!(state.local_closed.load(Ordering::Acquire));
            assert!(
                commands.try_recv().is_err(),
                "cancelled next chunk is never admitted or replayed"
            );
            assert_eq!(credit.available_permits(), 112);
            drop((first, second, third, fourth, packet, commands));
            assert_eq!(credit.available_permits(), 128);
            continue;
        }
        let mut wire = first.data.to_vec();
        wire.extend_from_slice(&second.data);
        wire.extend_from_slice(&third.data);
        wire.extend_from_slice(&fourth.data);
        let mut held = vec![
            first_sent(first),
            first_sent(second),
            first_sent(third),
            first_sent(fourth),
        ];
        loop {
            let result = sending.as_mut().poll(&mut cx);
            let mut admitted = 0;
            while let Ok(command) = commands.try_recv() {
                assert!(command.data.len() <= 4);
                wire.extend_from_slice(&command.data);
                held.push(first_sent(command));
                admitted += 1;
            }
            assert!(
                (1..=2).contains(&admitted),
                "remaining record chunks keep the original FIFO2 bound"
            );
            if let Poll::Ready(value) = result {
                value.unwrap();
                break;
            }
        }
        drop(sending);
        assert_eq!(wire[0], 0);
        assert_eq!(wire.last(), Some(&255));
        let length = usize::from(u16::from_be_bytes([wire[1], wire[2]]));
        assert_eq!(wire.len(), length + 4);
        let (remote, payload) =
            crate::socks5::decode_udp_packet(&wire[3..wire.len() - 1], usize::from(u16::MAX))
                .unwrap();
        assert_eq!(remote, target);
        assert_eq!(payload, b"cancelled");
        assert_eq!(credit.available_permits(), 128 - wire.len());
        bounded(packet.close()).await.unwrap();
        drop((held, packet, commands));
        assert_eq!(credit.available_permits(), 128);
    }
}
