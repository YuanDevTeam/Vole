//! Real H2 encoding over a bounded moving-prefix supplied IO.
//! No Payload::advance or private receipt-state mutation is used here.
use super::*;
use futures_util::task::noop_waker;
use std::future::Future;
use tokio::io::DuplexStream;

#[derive(Default)]
struct Progress {
    accepted: usize,
    committed: usize,
    automatic: bool,
    pending_flushes: usize,
    acknowledged: Option<usize>,
    writes_after_ack: usize,
}
#[derive(Default)]
struct Control {
    progress: Mutex<Progress>,
    flush: AtomicWaker,
}
impl Control {
    fn automatic(&self, enabled: bool) {
        let mut progress = self.progress.lock().unwrap();
        progress.automatic = enabled;
        if enabled {
            progress.committed = progress.accepted;
        }
        drop(progress);
        self.flush.wake();
    }
    fn acknowledge_current_prefix(&self) -> usize {
        let mut progress = self.progress.lock().unwrap();
        progress.committed = progress.accepted;
        progress.acknowledged = Some(progress.accepted);
        let target = progress.accepted;
        drop(progress);
        self.flush.wake();
        target
    }
}
struct MovingIo {
    raw: DuplexStream,
    control: Arc<Control>,
}
impl AsyncRead for MovingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_read(cx, out)
    }
}
impl AsyncWrite for MovingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.raw).poll_write(cx, input);
        if let Poll::Ready(Ok(count)) = &result {
            let mut progress = self.control.progress.lock().unwrap();
            progress.accepted += *count;
            if progress.acknowledged.is_some() {
                progress.writes_after_ack += *count;
            }
            if progress.automatic {
                progress.committed = progress.accepted;
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.control.flush.register(cx.waker());
        let mut progress = self.control.progress.lock().unwrap();
        if progress.committed != progress.accepted {
            progress.pending_flushes += 1;
            return Poll::Pending;
        }
        drop(progress);
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

struct Fixture {
    client: Pin<Box<dyn Future<Output = Result<(), h2::Error>> + Send>>,
    peer: h2::server::Connection<DuplexStream, Bytes>,
    sender: Option<h2::client::SendRequest<Payload>>,
    requests: [Option<h2::SendStream<Payload>>; 2],
    responses: [Option<h2::client::ResponseFuture>; 2],
    client_bodies: [Option<h2::RecvStream>; 2],
    peer_bodies: [Option<h2::RecvStream>; 2],
    replies: [Option<h2::SendStream<Bytes>>; 2],
    received: [Vec<u8>; 2],
    held: Vec<Bytes>,
    release_udp_credit: bool,
    peer_eof: [bool; 2],
    client_eof: [bool; 2],
    writes: Writes,
    control: Arc<Control>,
    accepted_requests: usize,
    client_done: bool,
    peer_done: bool,
}
impl Fixture {
    async fn open() -> Self {
        let (raw, peer) = tokio::io::duplex(65536);
        let control = Arc::new(Control::default());
        control.automatic(true);
        let (raw, writes) = Writes::wrap(Box::new(MovingIo {
            raw,
            control: control.clone(),
        }));
        let (client, peer) = tokio::join!(
            h2::client::Builder::new()
                .enable_push(false)
                .initial_window_size(65536)
                .initial_connection_window_size(524288)
                .max_frame_size(16384)
                .max_header_list_size(16384)
                .max_concurrent_streams(0)
                .max_send_buffer_size(16384)
                .handshake::<_, Payload>(raw),
            h2::server::Builder::new().handshake::<_, Bytes>(peer),
        );
        let (sender, client) = client.unwrap();
        let mut fixture = Self {
            client: Box::pin(client),
            peer: peer.unwrap(),
            sender: Some(sender),
            requests: [None, None],
            responses: [None, None],
            client_bodies: [None, None],
            peer_bodies: [None, None],
            replies: [None, None],
            received: [Vec::new(), Vec::new()],
            held: Vec::new(),
            release_udp_credit: false,
            peer_eof: [false; 2],
            client_eof: [false; 2],
            writes,
            control,
            accepted_requests: 0,
            client_done: false,
            peer_done: false,
        };
        for index in 0..2 {
            for _ in 0..128 {
                let waker = noop_waker();
                let mut cx = Context::from_waker(&waker);
                if let Poll::Ready(result) = fixture.sender.as_mut().unwrap().poll_ready(&mut cx) {
                    result.unwrap();
                    let request = http::Request::builder()
                        .method("CONNECT")
                        .uri("https://localhost")
                        .body(())
                        .unwrap();
                    let (response, send) = fixture
                        .sender
                        .as_mut()
                        .unwrap()
                        .send_request(request, false)
                        .unwrap();
                    fixture.requests[index] = Some(send);
                    fixture.responses[index] = Some(response);
                    break;
                }
                fixture.drive();
            }
            assert!(
                fixture.requests[index].is_some(),
                "CONNECT admission stalled"
            );
        }
        for _ in 0..128 {
            fixture.drive();
            if fixture.accepted_requests == 2 && fixture.client_bodies.iter().all(Option::is_some) {
                // Drain handshake/SETTINGS traffic before the controlled phase.
                for _ in 0..8 {
                    fixture.drive();
                }
                return fixture;
            }
        }
        panic!("real H2 CONNECT setup did not finish within bounded polls");
    }
    fn drive(&mut self) {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        if !self.client_done {
            if let Poll::Ready(result) = self.client.as_mut().poll(&mut cx) {
                result.unwrap();
                self.client_done = true;
            }
        }
        if !self.peer_done {
            match self.peer.poll_accept(&mut cx) {
                Poll::Ready(Some(Ok((request, mut reply)))) => {
                    let index = self.accepted_requests;
                    assert!(index < 2, "fixture opened an unexpected stream");
                    assert_eq!(request.method(), "CONNECT");
                    self.peer_bodies[index] = Some(request.into_body());
                    self.replies[index] =
                        Some(reply.send_response(http::Response::new(()), false).unwrap());
                    self.accepted_requests += 1;
                }
                Poll::Ready(Some(Err(error))) => panic!("H2 peer failed: {error}"),
                Poll::Ready(None) => self.peer_done = true,
                Poll::Pending => {}
            }
        }
        for index in 0..2 {
            if let Some(response) = &mut self.responses[index] {
                if let Poll::Ready(result) = Pin::new(response).poll(&mut cx) {
                    self.client_bodies[index] = Some(result.unwrap().into_body());
                    self.responses[index] = None;
                }
            }
            if let Some(body) = &mut self.peer_bodies[index] {
                for _ in 0..8 {
                    match body.poll_data(&mut cx) {
                        Poll::Ready(Some(Ok(bytes))) => {
                            self.received[index].extend_from_slice(&bytes);
                            if index == 1 && self.release_udp_credit {
                                // Only the sustained sibling control replenishes
                                // credit, after retaining a bounded payload copy.
                                body.flow_control().release_capacity(bytes.len()).unwrap();
                            } else {
                                // Existing tests keep their no-credit-rescue control.
                                self.held.push(bytes);
                            }
                        }
                        Poll::Ready(Some(Err(error))) => panic!("request body failed: {error}"),
                        Poll::Ready(None) => {
                            self.peer_eof[index] = true;
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
            }
            if let Some(body) = &mut self.client_bodies[index] {
                match body.poll_data(&mut cx) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        assert!(bytes.is_empty(), "unexpected response DATA");
                    }
                    Poll::Ready(Some(Err(error))) => panic!("response body failed: {error}"),
                    Poll::Ready(None) => self.client_eof[index] = true,
                    Poll::Pending => {}
                }
            }
        }
    }
    fn finish(mut self) -> bool {
        self.control.automatic(true);
        for stream in self.requests.iter_mut().flatten() {
            stream.send_data(Payload::empty(), true).unwrap();
        }
        for stream in self.replies.iter_mut().flatten() {
            stream.send_data(Bytes::new(), true).unwrap();
        }
        for _ in 0..128 {
            self.drive();
            if self.peer_eof == [true; 2] && self.client_eof == [true; 2] {
                break;
            }
        }
        let streams_finished = self.peer_eof == [true; 2] && self.client_eof == [true; 2];
        self.requests = [None, None];
        self.responses = [None, None];
        self.client_bodies = [None, None];
        self.peer_bodies = [None, None];
        self.replies = [None, None];
        self.sender = None;
        self.held.clear();
        for _ in 0..128 {
            self.drive();
            if self.client_done && self.peer_done {
                break;
            }
        }
        streams_finished && self.client_done && self.peer_done
    }
}

#[tokio::test]
async fn acknowledged_raw_prefix_progresses_tcp_metadata_without_signing_new_udp() {
    let mut fixture = Fixture::open().await;
    let ack = Arc::new(CoalescedAck::default());
    let metadata = Bytes::from_static(b"tcp-metadata");
    let udp = Bytes::from_static(b"new-udp-body");
    fixture.control.automatic(false);
    let payload = fixture
        .writes
        .coalesced_payload(metadata.clone(), &ack)
        .unwrap();
    fixture.requests[0]
        .as_mut()
        .unwrap()
        .send_data(payload, false)
        .unwrap();
    for _ in 0..128 {
        fixture.drive();
        if fixture.received[0] == metadata
            && fixture.control.progress.lock().unwrap().pending_flushes > 0
        {
            break;
        }
    }
    let metadata_reached_peer = fixture.received[0] == metadata;
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let original_pending = ack.poll_flushed(&mut cx).is_pending();
    let old_prefix = fixture.control.acknowledge_current_prefix();
    // ACK wakes the connection, but do not poll it before a sibling admits DATA.
    // Only the real Connection advances/encodes either Payload.
    let (payload, mut receipt) = fixture.writes.payload(udp.clone());
    fixture.requests[1]
        .as_mut()
        .unwrap()
        .send_data(payload, false)
        .unwrap();
    for _ in 0..128 {
        fixture.drive();
        if fixture.received[1] == udp {
            break;
        }
    }
    let tcp_ready = matches!(ack.poll_flushed(&mut cx), Poll::Ready(Ok(())));
    let udp_pending = matches!(receipt.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    let udp_reached_peer = fixture.received[1] == udp;
    let (accepted, committed, new_raw_bytes) = {
        let progress = fixture.control.progress.lock().unwrap();
        (
            progress.accepted,
            progress.committed,
            progress.writes_after_ack,
        )
    };
    let joined = fixture.finish();
    // All inline protocol futures have naturally completed before candidate assertions.
    assert!(joined, "real H2 client/peer did not naturally complete");
    assert!(
        metadata_reached_peer && original_pending,
        "old prefix was not pending"
    );
    assert!(
        udp_reached_peer && new_raw_bytes > 0 && accepted > old_prefix && committed == old_prefix,
        "fixture did not witness new real DATA/rawWrite after acknowledging the old prefix"
    );
    assert!(
        udp_pending,
        "new UDP receipt crossed an unacknowledged raw prefix"
    );
    assert!(
        tcp_ready,
        "old TCP metadata flush chased newly accepted sibling UDP bytes"
    );
}

#[tokio::test]
async fn sustained_udp_fair_drain_stops_at_raw_budget_inside_a_real_h2_frame() {
    // This manually polled codec model does not test Tokio scheduling.
    // Isolate its longer fixed sequence from the surrounding test task budget.
    tokio::task::unconstrained(async {
        let mut fixture = Fixture::open().await;
        fixture.release_udp_credit = true;
        let ack = Arc::new(CoalescedAck::default());
        let metadata = Bytes::from_static(b"tcp-metadata");
        fixture.control.automatic(false);
        let payload = fixture
            .writes
            .coalesced_payload(metadata.clone(), &ack)
            .unwrap();
        fixture.requests[0]
            .as_mut()
            .unwrap()
            .send_data(payload, false)
            .unwrap();
        for _ in 0..128 {
            fixture.drive();
            if fixture.received[0] == metadata
                && fixture.control.progress.lock().unwrap().pending_flushes > 0
            {
                break;
            }
        }
        let old_reached_peer = fixture.received[0] == metadata;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let old_initially_pending = ack.poll_flushed(&mut cx).is_pending();
        let base = fixture.control.progress.lock().unwrap().accepted;
        let budget = crate::limits::XHTTP_H3_PACKET_BATCH_BYTES;
        let chunk = Bytes::from(vec![b'u'; 4096]);
        let mut submitted = 0;
        let mut receipts = Vec::new();
        // Real flow-credit feedback keeps one sibling producing well beyond a
        // single H2 receive window. At most one new 4KiB Payload is queued per turn.
        for _ in 0..64 {
            let (payload, receipt) = fixture.writes.payload(chunk.clone());
            fixture.requests[1]
                .as_mut()
                .unwrap()
                .send_data(payload, false)
                .unwrap();
            receipts.push(receipt);
            submitted += chunk.len();
            for _ in 0..128 {
                fixture.drive();
                let accepted = fixture.control.progress.lock().unwrap().accepted - base;
                if accepted >= budget || fixture.received[1].len() >= submitted {
                    break;
                }
            }
            if fixture.control.progress.lock().unwrap().accepted - base >= budget {
                break;
            }
        }
        let admitted = fixture.control.progress.lock().unwrap().accepted - base;
        let partial_frame_waiting = fixture.received[1].len() < submitted;
        // No new write, ACK, empty-write or shutdown may renew the allowance.
        for _ in 0..8 {
            fixture.drive();
        }
        let still_admitted = fixture.control.progress.lock().unwrap().accepted - base;
        let old_still_pending = ack.poll_flushed(&mut cx).is_pending();
        let last_before_ack = matches!(
            receipts.last_mut().unwrap().try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        // ACK the actual raw byte prefix, including only part of the last DATA.
        // This models independent PacketUp response feedback, not h2 frame progress.
        let acknowledged_prefix = fixture.control.acknowledge_current_prefix();
        for _ in 0..128 {
            fixture.drive();
            if fixture.received[1].len() == submitted {
                break;
            }
        }
        let tcp_ready = matches!(ack.poll_flushed(&mut cx), Poll::Ready(Ok(())));
        let resumed_frame = fixture.received[1].len() == submitted;
        let accepted_after_resume = fixture.control.progress.lock().unwrap().accepted;
        let last_after_prefix_ack = matches!(
            receipts.last_mut().unwrap().try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        let joined = fixture.finish();
        let all_receipts_finished = receipts
            .iter_mut()
            .all(|receipt| matches!(receipt.try_recv(), Ok(Ok(()))));

        assert!(joined, "real client/peer protocol owners did not finish");
        assert!(old_reached_peer && old_initially_pending);
        assert_eq!(budget, 128 * 1024);
        assert_eq!(
            admitted, budget,
            "pending private raw admission exceeded its fixed allowance"
        );
        assert_eq!(
            still_admitted, admitted,
            "Pending polls renewed fair-drain admission"
        );
        assert!(
            partial_frame_waiting,
            "the byte cap did not stop inside the actual last DATA"
        );
        assert!(old_still_pending && last_before_ack);
        assert!(
            tcp_ready && resumed_frame,
            "raw-prefix ACK failed to resume the incomplete frame"
        );
        assert!(accepted_after_resume > acknowledged_prefix);
        assert!(
            last_after_prefix_ack,
            "the incomplete frame's Strong receipt completed before its suffix was acknowledged"
        );
        assert!(
            all_receipts_finished,
            "normal cleanup lost a submitted Strong receipt"
        );
    })
    .await;
}

#[tokio::test]
async fn ordinary_data_exceeds_the_quiet_budget_until_a_late_flush_requests_it() {
    tokio::task::unconstrained(async {
        let mut fixture = Fixture::open().await;
        fixture.release_udp_credit = true;
        let quiet = Arc::new(CoalescedAck::default());
        let data = Arc::new(CoalescedAck::default());
        let prefix = Bytes::from_static(b"ordinary-prefix");
        fixture.control.automatic(false);
        let payload = fixture
            .writes
            .coalesced_payload(prefix.clone(), &quiet)
            .unwrap();
        fixture.requests[0]
            .as_mut()
            .unwrap()
            .send_data(payload, false)
            .unwrap();
        for _ in 0..128 {
            fixture.drive();
            if fixture.received[0] == prefix
                && fixture.control.progress.lock().unwrap().pending_flushes > 0
            {
                break;
            }
        }
        let prefix_arrived = fixture.received[0] == prefix;
        let base = fixture.control.progress.lock().unwrap().accepted;
        let chunk = Bytes::from(vec![b'u'; 4096]);
        let target = 40 * chunk.len();
        let mut submitted = 0;
        // Never poll either logical ACK during this ordinary DATA phase.
        // One new 4KiB Payload is produced only after the preceding peer DATA.
        for _ in 0..40 {
            let payload = fixture
                .writes
                .coalesced_payload(chunk.clone(), &data)
                .unwrap();
            fixture.requests[1]
                .as_mut()
                .unwrap()
                .send_data(payload, false)
                .unwrap();
            submitted += chunk.len();
            for _ in 0..128 {
                fixture.drive();
                if fixture.received[1].len() == submitted {
                    break;
                }
            }
            if fixture.received[1].len() != submitted {
                break;
            }
        }
        let ordinary_received = fixture.received[1].len();
        let before_waiter = fixture.control.progress.lock().unwrap().accepted;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        // A request arriving after the cohort was frozen must close an already
        // exhausted gate. This is an actual logical ACK poll, not a flag edit.
        let late_pending = quiet.poll_flushed(&mut cx).is_pending();
        let payload = fixture
            .writes
            .coalesced_payload(chunk.clone(), &data)
            .unwrap();
        fixture.requests[1]
            .as_mut()
            .unwrap()
            .send_data(payload, false)
            .unwrap();
        submitted += chunk.len();
        for _ in 0..8 {
            fixture.drive();
        }
        let late_stopped = fixture.control.progress.lock().unwrap().accepted == before_waiter;
        let strong_bytes = Bytes::from_static(b"current-strong");
        let (payload, mut strong) = fixture.writes.payload(strong_bytes.clone());
        fixture.requests[0]
            .as_mut()
            .unwrap()
            .send_data(payload, false)
            .unwrap();
        for _ in 0..8 {
            fixture.drive();
        }
        let strong_before = matches!(strong.try_recv(), Err(oneshot::error::TryRecvError::Empty));
        let acknowledged = fixture.control.acknowledge_current_prefix();
        for _ in 0..128 {
            fixture.drive();
            if fixture.received[1].len() == submitted
                && fixture.received[0].len() == prefix.len() + strong_bytes.len()
            {
                break;
            }
        }
        let prefix_ready = matches!(quiet.poll_flushed(&mut cx), Poll::Ready(Ok(())));
        let resumed = fixture.received[1].len() == submitted
            && fixture.received[0] == [prefix.as_ref(), strong_bytes.as_ref()].concat();
        let wrote_suffix = fixture.control.progress.lock().unwrap().accepted > acknowledged;
        let strong_after = matches!(strong.try_recv(), Err(oneshot::error::TryRecvError::Empty));
        let joined = fixture.finish();
        let strong_finished = matches!(strong.try_recv(), Ok(Ok(())));
        let ordinary_ack_finished = matches!(data.poll_flushed(&mut cx), Poll::Ready(Ok(())));
        // Intended old-behavior red comes only after actual natural owner exit.
        assert!(joined, "real H2 protocol owners did not naturally finish");
        assert!(prefix_arrived && late_pending && late_stopped);
        assert!(strong_before && strong_after && strong_finished && ordinary_ack_finished);
        assert!(prefix_ready && resumed && wrote_suffix);
        assert_eq!(
            ordinary_received, target,
            "ordinary DATA gained an unrequested quiet barrier"
        );
        assert!(before_waiter - base > crate::limits::XHTTP_H3_PACKET_BATCH_BYTES);
    })
    .await;
}
