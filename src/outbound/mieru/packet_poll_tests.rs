//! Actual packet parser/channel boundaries; no sockets or duplicate receive queue.
use super::*;
use crate::{resources::observation::ResourceProbe, session::DatagramSession};
use futures_util::task::{ArcWake, waker};
use std::{future::Future, sync::atomic::AtomicUsize, time::Duration};
use tokio::io::DuplexStream;
use tokio_util::task::TaskTracker;

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl ArcWake for WakeCount {
    fn wake_by_ref(owner: &Arc<Self>) {
        owner.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn memory_packet() -> (
    PacketTransport,
    DuplexStream,
    CancellationToken,
    TaskTracker,
) {
    let (client, peer) = tokio::io::duplex(128);
    let parent = CancellationToken::new();
    let tasks = TaskTracker::new();
    let request = DatagramRequest::new(DatagramSession::for_tun(
        "192.0.2.10:1000".parse().unwrap(),
        1500,
    ));
    let context = EstablishContext::with_timeout(Duration::from_secs(1));
    let transport = PacketTransport::new(
        Box::new(client),
        &request,
        &context,
        parent.clone(),
        |reader| Ok(tasks.spawn(observation::task(reader))),
    )
    .unwrap();
    (transport, peer, parent, tasks)
}

async fn reader_finished(alive: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while alive.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn close(mut transport: PacketTransport, tasks: TaskTracker) {
    transport.close().await.unwrap();
    drop(transport);
    tasks.close();
    tasks.wait().await;
}

#[tokio::test]
async fn mieru_packet_pending_terminal_error_survives_reader_exit() {
    let probe = ResourceProbe::default();
    let results = probe
        .scope(async {
            let mut results = Vec::new();
            for asynchronous in [false, true] {
                let (mut transport, mut peer, _parent, tasks) = memory_packet();
                let alive = transport.alive.clone();
                let wakes = Arc::new(WakeCount::default());
                let wake = waker(wakes.clone());
                let mut context = Context::from_waker(&wake);
                let mut scratch = Vec::new();
                let (pending, result) = if asynchronous {
                    let receiving = transport.receive();
                    tokio::pin!(receiving);
                    let pending = receiving.as_mut().poll(&mut context).is_pending();
                    peer.write_all(&[1]).await.unwrap(); // Invalid real frame prefix.
                    reader_finished(&alive).await;
                    (pending, Poll::Ready(receiving.await))
                } else {
                    let pending = transport
                        .poll_receive(&mut context, &mut scratch)
                        .is_pending();
                    peer.write_all(&[1]).await.unwrap();
                    reader_finished(&alive).await;
                    let result = transport.poll_receive(&mut context, &mut scratch);
                    (pending, result)
                };
                let notified = wakes.0.load(Ordering::Relaxed) > 0;
                close(transport, tasks).await;
                drop(peer);
                results.push((pending, notified, result));
            }
            results
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (pending, notified, result) in results {
        assert!(
            pending,
            "receive must actually register Pending before the bad frame"
        );
        assert!(
            notified,
            "the sole sender must wake its registered receiver"
        );
        assert!(
            matches!(result, Poll::Ready(Err(DispatchError::Other(ref message)))
            if message == &io::Error::from(io::ErrorKind::InvalidData).to_string()),
            "alive=false must not hide the queued codec error"
        );
    }
}

#[tokio::test]
async fn mieru_packet_pending_cancel_wakes_and_closed_or_cancelled_queues_do_not_deliver() {
    let probe = ResourceProbe::default();
    let results = probe
        .scope(async {
            let (mut transport, peer, parent, tasks) = memory_packet();
            let alive = transport.alive.clone();
            let wakes = Arc::new(WakeCount::default());
            let wake = waker(wakes.clone());
            let mut context = Context::from_waker(&wake);
            let mut scratch = Vec::new();
            let pending = transport
                .poll_receive(&mut context, &mut scratch)
                .is_pending();
            parent.cancel();
            reader_finished(&alive).await;
            let notified = wakes.0.load(Ordering::Relaxed) > 0;
            let cancelled = transport.poll_receive(&mut context, &mut scratch);
            close(transport, tasks).await;
            drop(peer);
            let mut cached = Vec::new();
            for cancel in [false, true] {
                let (mut transport, mut peer, parent, tasks) = memory_packet();
                let body = socks5::encode_udp_packet(
                    &Destination::Ip("198.51.100.1:53".parse().unwrap()),
                    b"buffered",
                    usize::from(u16::MAX),
                )
                .unwrap();
                let mut frame = vec![0];
                frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
                frame.extend_from_slice(&body);
                frame.push(255);
                peer.write_all(&frame).await.unwrap();
                tokio::time::timeout(Duration::from_secs(1), async {
                    while transport.responses.is_empty() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                if cancel {
                    parent.cancel();
                } else {
                    transport.close().await.unwrap();
                }
                let result = transport.poll_receive(&mut context, &mut scratch);
                let asynchronous = transport.receive().await;
                close(transport, tasks).await;
                drop(peer);
                cached.push((result, asynchronous));
            }
            (pending, notified, cancelled, cached)
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(
        results.0 && results.1,
        "parent cancellation must wake a real Pending receive"
    );
    assert!(matches!(
        results.2,
        Poll::Ready(Err(DispatchError::NotAllowed))
    ));
    for (polled, asynchronous) in results.3 {
        assert!(matches!(
            polled,
            Poll::Ready(Err(DispatchError::NotAllowed))
        ));
        assert!(matches!(asynchronous, Err(DispatchError::NotAllowed)));
    }
}

#[tokio::test]
async fn mieru_packet_cancelled_partial_send_revokes_shared_stream_without_cancelling_parent() {
    let probe = ResourceProbe::default();
    tokio::time::timeout(
        Duration::from_secs(2),
        probe.scope(async {
            let (client, mut peer) = tokio::io::duplex(1);
            let parent = CancellationToken::new();
            let tasks = TaskTracker::new();
            let request = DatagramRequest::new(DatagramSession::for_tun(
                "192.0.2.10:1000".parse().unwrap(),
                1500,
            ));
            let mut transport = PacketTransport::new(
                Box::new(client),
                &request,
                &EstablishContext::default(),
                parent.clone(),
                |reader| Ok(tasks.spawn(observation::task(reader))),
            )
            .unwrap();
            let packet = Datagram {
                remote: Destination::Ip("198.51.100.1:53".parse().unwrap()),
                payload: Bytes::from_static(b"partially-written"),
                sniffed_domain: None,
            };
            let mut sending = Box::pin(transport.send(packet.clone()));
            assert!(futures_util::poll!(&mut sending).is_pending());
            drop(sending);
            let mut partial = Vec::new();
            peer.read_to_end(&mut partial).await.unwrap();
            assert_eq!(partial, vec![0]);
            assert!(transport.send(packet).await.is_err());
            assert!(transport.receive().await.is_err());
            close(transport, tasks).await;
            assert!(!parent.is_cancelled());
        }),
    )
    .await
    .expect("cancelled Mieru shared stream must release both halves");
    assert!(probe.snapshot().is_idle());
}
