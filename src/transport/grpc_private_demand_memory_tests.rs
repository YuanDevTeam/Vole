//! Real native h2 credit after full private writes; no modeled demand state.
use super::*;
use futures_util::future::poll_fn;
use std::time::Duration;

async fn exercise_full_accept_idle(buffered_prefix: bool) {
    let first = vec![b'a'; if buffered_prefix { CHUNK / 4 } else { CHUNK }];
    let second = buffered_prefix.then(|| vec![b'b'; CHUNK / 2]);
    let mut expected = first.clone();
    if let Some(second) = &second {
        expected.extend_from_slice(second);
    }
    let expected_len = expected.len();
    let (raw, peer) = tokio::io::duplex(64 * 1024);
    let (raw, writes) = Writes::wrap(Box::new(raw));
    let (mut sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .max_send_buffer_size(CHUNK)
        .handshake::<_, Payload>(raw)
        .await
        .unwrap();
    let (ready, ready_rx) = tokio::sync::oneshot::channel();
    let (observed, observed_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let server = async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(CHUNK as u32)
            .handshake::<_, Bytes>(peer)
            .await
            .unwrap();
        let (request, mut reply) = connection.accept().await.unwrap().unwrap();
        let output = reply.send_response(http::Response::new(()), false).unwrap();
        drop(reply);
        let mut input = request.into_body();
        let mut ping = connection.ping_pong().unwrap();
        macro_rules! drive {
            ($future:expr) => {{
                let future = $future;
                tokio::pin!(future);
                loop {
                    tokio::select! { biased;
                        result = &mut future => break result,
                        next = connection.accept() => {
                            assert!(matches!(next, Some(Ok(_))), "peer closed before credit barrier");
                        }
                    }
                }
            }};
        }
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        ready.send(()).unwrap();
        let mut received = Vec::with_capacity(expected_len);
        let mut held = Vec::new();
        while received.len() < expected_len {
            let bytes = drive!(input.data()).unwrap().unwrap();
            received.extend_from_slice(&bytes);
            // No consumed credit is returned before the idle observation.
            held.push(bytes);
        }
        connection
            .set_initial_window_size((CHUNK * 2) as u32)
            .unwrap();
        // As in the existing partial-write test, the second PING is ordered
        // after genuine SETTINGS. Its ACK proves the client processed them.
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        drive!(ping.ping(h2::Ping::opaque())).unwrap();
        observed.send(received).unwrap();
        drive!(release_rx).unwrap();
        drop((held, input, output, ping));
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
        stream.coalesced = Some(Arc::new(CoalescedAck::default()));
        stream.response_deadline = false;
        ready_rx.await.unwrap();
        // Both real writes occur in one application poll. The driver future
        // below cannot run between them, so the second full write sees actual
        // previously buffered native DATA, rather than a copied state model.
        let (first_count, second_poll) = poll_fn(|cx| {
            let first_count = std::task::ready!(Pin::new(&mut stream).poll_write(cx, &first))?;
            let second_poll = second
                .as_ref()
                .map(|bytes| Pin::new(&mut stream).poll_write(cx, bytes));
            Poll::Ready(Ok::<_, io::Error>((first_count, second_poll)))
        })
        .await
        .unwrap();
        assert_eq!(
            first_count,
            first.len(),
            "full-write fixture admitted a prefix"
        );
        if let Some(second) = &second {
            match second_poll {
                Some(Poll::Ready(Ok(count))) => {
                    assert_eq!(count, second.len(), "buffered fixture admitted a prefix");
                }
                result => panic!("second full write was not immediately accepted: {result:?}"),
            }
        } else {
            assert!(second_poll.is_none());
        }
        // Do not flush, reserve or write again: those operations could hide
        // stale unaccepted demand while the peer grants genuine fresh credit.
        let received = observed_rx.await.unwrap();
        let unused = match &stream.send {
            H2Send::Direct(native) => Some(native.capacity()),
            H2Send::Shared(_) => None,
        };
        release.send(()).unwrap();
        drop((stream, sender));
        (received, unused)
    };
    let ((received, unused), (), driver) = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(client, server, connection)
    })
    .await
    .expect("full-write duplex owners did not finish");
    // The behavioral assertions follow natural completion of both owners.
    assert!(driver.is_ok(), "client cleanup failed: {driver:?}");
    assert_eq!(received, expected, "full-write DATA changed bytes or order");
    assert_eq!(
        unused,
        Some(0),
        "idle full writer retained unaccepted credit"
    );
}

#[tokio::test]
async fn private_h2mux_full_write_leaves_no_idle_unaccepted_credit() {
    for buffered_prefix in [false, true] {
        exercise_full_accept_idle(buffered_prefix).await;
    }
}
