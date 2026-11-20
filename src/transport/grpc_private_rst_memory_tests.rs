//! Real h2 duplex peers: capacity/reset ordering, not CPU or throughput proof.
use super::*;
use futures_util::{FutureExt, future::poll_fn};
use std::{
    panic::{AssertUnwindSafe, resume_unwind},
    sync::atomic::{AtomicUsize, Ordering},
    task::{Wake, Waker},
    time::Duration,
};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    ZeroCapacity,
    ReadyCapacity,
    EmptyWrite,
    CapacityThenReset,
    FinAfterPrefix,
    PeerEof,
}

#[derive(Default)]
struct WriteWake {
    count: AtomicUsize,
    changed: tokio::sync::Notify,
}
impl Wake for WriteWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
    }
}

async fn exercise(scenario: Scenario) {
    let (raw, peer) = tokio::io::duplex(64 * 1024);
    let (raw, writes) = Writes::wrap(Box::new(raw));
    let (mut sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .max_send_buffer_size(CHUNK)
        .handshake::<_, Payload>(raw)
        .await
        .unwrap();
    let (ready, ready_rx) = tokio::sync::oneshot::channel();
    let (reset, reset_rx) = tokio::sync::oneshot::channel();
    let (prefix, prefix_rx) = tokio::sync::oneshot::channel();
    let server = async move {
        let window = if matches!(scenario, Scenario::ZeroCapacity | Scenario::PeerEof) {
            0
        } else {
            CHUNK as u32
        };
        let mut connection = h2::server::Builder::new()
            .initial_window_size(window)
            .handshake::<_, Bytes>(peer)
            .await
            .unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        let mut output = response
            .send_response(http::Response::new(()), false)
            .unwrap();
        drop(response);
        let mut input = request.into_body();
        let mut ping = connection.ping_pong().unwrap();
        macro_rules! drive {
            ($future:expr) => {{
                let future = $future; tokio::pin!(future);
                loop {
                    tokio::select! { biased;
                        result = &mut future => break result,
                        next = connection.accept() => {
                            assert!(matches!(next, Some(Ok(_))), "peer closed before control barrier");
                        }
                    }
                }
            }};
        }
        // The second genuine PING is after the initial SETTINGS, as in the
        // existing partial-credit fixture; no simulated capacity/reset state.
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        ready.send(()).unwrap();
        if scenario == Scenario::FinAfterPrefix {
            let bytes = drive!(input.data()).unwrap().unwrap();
            assert_eq!(bytes.as_ref(), b"before");
            input.flow_control().release_capacity(bytes.len()).unwrap();
            prefix.send(()).unwrap();
        } else {
            drop(prefix);
        }
        drive!(reset_rx).unwrap();
        if scenario == Scenario::PeerEof {
            // Dropping the actual peer connection/IO exercises the library's
            // connection error wake-up, not a manual CoalescedAck failure.
            drop((input, output, ping, connection));
            return;
        }
        output.send_reset(h2::Reason::CANCEL);
        drop((input, output, ping));
        while let Some(result) = connection.accept().await {
            result.unwrap();
        }
    };
    let client = async move {
        let request = http::Request::builder()
            .method("CONNECT")
            .uri("https://fixture.invalid")
            .body(())
            .unwrap();
        let (response, send) = sender.send_request(request, false).unwrap();
        // Same typed constructor and marker as private mux_stream. Keep the
        // actual native SendStream visible to observe its protocol barriers.
        let mut stream = Grpc::new(
            response,
            send,
            Framing::Plain,
            true,
            Instant::now() + Duration::from_secs(5),
            Arc::default(),
            None,
            None,
            writes,
        );
        let ack = Arc::new(CoalescedAck::default());
        stream.coalesced = Some(ack.clone());
        stream.response_deadline = false;
        ready_rx.await.unwrap();
        let rejected;
        let mut fin_stayed_open = true;
        if matches!(scenario, Scenario::ZeroCapacity | Scenario::PeerEof) {
            let mut writing = Box::pin(stream.write(b"blocked"));
            let wake = Arc::new(WriteWake::default());
            let waker = Waker::from(wake.clone());
            let mut observed = wake.count.load(Ordering::SeqCst);
            assert!(
                writing
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            reset.send(()).unwrap();
            // The peer and driver share the parent task, but the write is not
            // repolled by those wakes. Only its own registered waiter permits it.
            let completed = loop {
                while wake.count.load(Ordering::SeqCst) == observed {
                    wake.changed.notified().await;
                }
                observed = wake.count.load(Ordering::SeqCst);
                if let Poll::Ready(result) = writing.as_mut().poll(&mut Context::from_waker(&waker))
                {
                    break result;
                }
            };
            let error = completed.unwrap_err();
            rejected = error.kind() == io::ErrorKind::BrokenPipe;
        } else {
            if scenario == Scenario::FinAfterPrefix {
                stream.write_all(b"before").await.unwrap();
                stream.flush().await.unwrap();
                prefix_rx.await.unwrap();
            } else {
                stream.send.reserve_capacity(CHUNK);
                let capacity = poll_fn(|cx| stream.send.poll_capacity(cx))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    capacity > 0,
                    "fixture did not establish genuine spare credit"
                );
            }
            reset.send(()).unwrap();
            // Establish receipt of the peer's real RST before checking writes.
            // poll_reset observes state only; it does not fail CoalescedAck.
            let reason = poll_fn(|cx| stream.send.poll_reset(cx)).await.unwrap();
            assert_eq!(reason, h2::Reason::CANCEL);
            rejected = match scenario {
                Scenario::CapacityThenReset => {
                    // This tests the native guard for the capacity->send race;
                    // it does not pretend to interleave inside Grpc's function.
                    let payload = stream
                        .writes
                        .coalesced_payload(Bytes::from_static(b"late"), &ack)
                        .unwrap();
                    stream.send.send_data(payload, false).is_err()
                }
                Scenario::EmptyWrite => {
                    poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, &[]))
                        .await
                        .unwrap_err()
                        .kind()
                        == io::ErrorKind::BrokenPipe
                }
                Scenario::FinAfterPrefix => {
                    let rejected =
                        stream.shutdown().await.unwrap_err().kind() == io::ErrorKind::BrokenPipe;
                    fin_stayed_open = !stream.upload_closed;
                    rejected
                }
                Scenario::ReadyCapacity => {
                    stream.write(b"late").await.unwrap_err().kind() == io::ErrorKind::BrokenPipe
                }
                _ => unreachable!(),
            };
        }
        let ack_failed_before_drop =
            poll_fn(|cx| Poll::Ready(matches!(ack.poll_flushed(cx), Poll::Ready(Err(_))))).await;
        // Dropping this logical stream then the last sender lets both real h2
        // connection futures finish. No spawned task/abort is used as a PASS.
        drop((stream, sender));
        (rejected, ack_failed_before_drop, fin_stayed_open)
    };
    let result = AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(client, server, connection)
    }))
    .catch_unwind()
    .await;
    let ((rejected, ack_failed, fin_stayed_open), (), driver) = match result {
        Ok(result) => result.expect("duplex protocol owners did not finish"),
        Err(panic) => resume_unwind(panic),
    };
    if scenario != Scenario::PeerEof {
        assert!(driver.is_ok(), "client owner failed: {driver:?}");
    }
    assert!(
        rejected,
        "RST/EOF admitted a late write or FIN: {scenario:?}"
    );
    if scenario != Scenario::FinAfterPrefix {
        assert!(
            ack_failed,
            "terminal write did not fail/wake its private ack before Drop: {scenario:?}"
        );
    }
    assert!(fin_stayed_open, "failed FIN changed local upload state");
}

#[tokio::test]
async fn private_h2mux_real_peer_reset_covers_credit_empty_write_fin_and_eof() {
    for scenario in [
        Scenario::ZeroCapacity,
        Scenario::ReadyCapacity,
        Scenario::EmptyWrite,
        Scenario::CapacityThenReset,
        Scenario::FinAfterPrefix,
        Scenario::PeerEof,
    ] {
        exercise(scenario).await;
    }
}
