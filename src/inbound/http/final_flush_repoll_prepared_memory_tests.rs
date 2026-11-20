// Actual shared collection/native rewrite, Message forwarding and paid owners.
use super::*;
use crate::http_processing::{
    Policy, body,
    h1_body::{self, Message},
    rules::Phase,
};
use std::sync::Mutex;
use url::Url;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Native {
    Replace,
    Shorten,
    Rejected,
}
struct CountSource {
    io: SourceIo,
    bytes: Arc<AtomicUsize>,
}
impl AsyncRead for CountSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, out);
        self.bytes
            .fetch_add(out.filled().len() - before, Ordering::Release);
        result
    }
}
struct LimitLast {
    io: TailIo,
    bytes: usize,
    block: bool,
}
impl AsyncRead for LimitLast {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}
impl AsyncWrite for LimitLast {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let data = if self.block && self.io.head_flushed && !data.is_empty() {
            let remaining = self
                .bytes
                .saturating_sub(1)
                .saturating_sub(self.io.control.body_written.load(Ordering::Acquire));
            if remaining == 0 {
                self.io
                    .control
                    .body_write_polls
                    .fetch_add(1, Ordering::Release);
                self.io.control.wake.register(cx.waker());
                return Poll::Pending;
            }
            &data[..data.len().min(remaining)]
        } else {
            data
        };
        Pin::new(&mut self.io).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn shared(native: Native, case: Case) -> (bool, bool, usize) {
    let policy = Policy::compile(if native == Native::Shorten {
        "rewrite:\n  enabled: true\n  rules:\n  - {url: '.', action: request-body-replace, search: aa, replacement: b}\n"
    } else {
        "rewrite:\n  enabled: true\n  rules:\n  - {url: '.', action: request-body-replace, search: a, replacement: b}\n"
    }).unwrap();
    let original = Url::parse("http://origin.test/upload").unwrap();
    let request = parse_request_head(
        b"POST http://origin.test/upload HTTP/1.1\r\nHost: origin.test\r\nContent-Type: text/plain\r\nContent-Length: 65536\r\nConnection: keep-alive",
        Vec::new(),
    ).unwrap();
    let original_plan = RequestPlan::new(&request).unwrap();
    let original_meta = body::OriginalRequestMeta::new(&request.method, &request.headers);
    let wire = body::WireBodyMeta::new(
        &request.headers,
        &original_meta,
        Phase::Request,
        None,
        Some(BODY_BYTES as u64),
        false,
    );
    let config = HttpServerConfig::processing();
    let budget = body::Budget::default();
    // Reserve the actual independent ledger to refusal, without duplicating its limit.
    let mut blockers = Vec::new();
    if native == Native::Rejected {
        for _ in 0..64 {
            match budget.reserve(body::MAX_BODY) {
                Some(owner) => blockers.push(owner),
                None => break,
            }
        }
    }
    let transaction = body::Transaction::begin_shared(
        &budget,
        policy.rules(),
        &original,
        Phase::Request,
        &wire,
        true,
    );
    let rejected = matches!(&transaction, Err(body::Bypass::Budget));
    let (mut source, source_reader) = tokio::io::duplex(128 * 1024);
    let (release, source_released) = oneshot::channel();
    let supplied = if case == Case::MissingSource {
        BODY_BYTES - 1
    } else {
        BODY_BYTES
    };
    let source_owner = tokio::spawn(tokio::task::unconstrained(async move {
        let result = source.write_all(&vec![b'a'; supplied]).await;
        let _ = source_released.await;
        result
    }));
    let control = Arc::new(Control::default());
    let source_bytes = Arc::new(AtomicUsize::new(0));
    let mut input = BufReader::new(CountSource {
        io: SourceIo {
            io: source_reader,
            control: control.clone(),
        },
        bytes: source_bytes.clone(),
    });
    let mut outgoing = request.clone();
    let collected = timeout(
        Duration::from_secs(2),
        tokio::task::unconstrained(h1_body::prepare_shared(
            &mut input,
            original_plan.body,
            &original_plan.trailer_blocklist,
            config.body_idle_timeout,
            transaction.ok(),
            &mut outgoing.headers,
        )),
    )
    .await;
    let (prepared, entity) = match collected {
        Ok(Ok(value)) => value,
        error => {
            drop(input);
            let _ = release.send(());
            let joined = source_owner.await;
            drop(blockers);
            panic!(
                "real shared collection did not complete: timeout/error={}, source={joined:?}",
                error.is_err()
            );
        }
    };
    let source_after_collection = source_bytes.load(Ordering::Acquire);
    let entity_changed = entity
        .as_ref()
        .is_some_and(|entity| entity.changed() && entity.bypass.is_none());
    let entity_length = entity.as_ref().map(|entity| entity.wire().len());
    // A real slice shares the paid allocation; no synthetic identity/proof is built.
    let retained = entity.map(|entity| entity.into_wire().slice(1..));
    let charge = budget.used();
    let plan = match RequestPlan::new(&outgoing) {
        Ok(plan) => plan,
        Err(error) => {
            drop(prepared);
            drop(retained);
            drop(input);
            let _ = release.send(());
            let joined = source_owner.await;
            drop(blockers);
            panic!("real processed framing invalid: {error}; source={joined:?}");
        }
    };
    let output_bytes = match plan.body {
        Body::Length(bytes) => bytes as usize,
        _ => 0,
    };
    let (upstream_io, peer) = tokio::io::duplex(128 * 1024);
    let (first_tail, tail_entered) = oneshot::channel();
    let peer_control = control.clone();
    let peer_owner = tokio::spawn(tokio::task::unconstrained(async move {
        let mut peer = BufReader::new(peer);
        let head = read_head(&mut peer, 16384).await?;
        let prefix = if matches!(case, Case::MissingSource | Case::LastWritePending) {
            output_bytes.saturating_sub(1)
        } else {
            output_bytes
        };
        let mut body = vec![0; prefix];
        peer.read_exact(&mut body).await?;
        if prefix == output_bytes {
            tail_entered
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        let polls = (
            peer_control.source_read_polls.load(Ordering::Acquire),
            peer_control.body_write_polls.load(Ordering::Acquire),
        );
        peer_control
            .mode
            .store(if case == Case::Ready { 1 } else { 0 }, Ordering::Release);
        peer_control.wake.wake();
        peer.get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nack")
            .await?;
        let mut trailing = Vec::new();
        peer.read_to_end(&mut trailing).await?;
        Ok::<_, io::Error>((head, body, trailing, polls))
    }));
    let message = Message {
        policy: &policy,
        original: &original,
        request: &request,
        meta: original_meta,
        continued: std::sync::atomic::AtomicBool::new(false),
        prepared: Mutex::new(Some(prepared)),
        scripts: None,
    };
    let mut upstream = UpstreamIo::new(Box::new(LimitLast {
        io: TailIo {
            io: upstream_io,
            control: control.clone(),
            head_flushed: false,
            block_last: false,
            first_tail: Some(first_tail),
        },
        bytes: output_bytes,
        block: case == Case::LastWritePending,
    }));
    let mut response = Vec::new();
    let began = Instant::now();
    let outcome = timeout(
        Duration::from_secs(2),
        tokio::task::unconstrained(forward_on_stream(
            &mut input,
            &mut response,
            &mut upstream,
            &request,
            plan,
            &config,
            Some(&message),
            true,
        )),
    )
    .await;
    let elapsed = began.elapsed();
    let polls = (
        control.source_read_polls.load(Ordering::Acquire),
        control.body_write_polls.load(Ordering::Acquire),
    );
    let source_after_forward = source_bytes.load(Ordering::Acquire);
    let written = control.body_written.load(Ordering::Acquire);
    let tail_polls = control.tail_polls.load(Ordering::Acquire);
    drop(upstream);
    drop(message);
    drop(input);
    let _ = release.send(());
    let source_result = source_owner.await;
    let peer_result = peer_owner.await;
    let retained_charge = budget.used();
    drop(retained);
    drop(blockers);
    let refunded = budget.used();
    // All IO/task/body owners have been released before any behavior assertion.
    source_result.unwrap().unwrap();
    let (head, body, trailing, before) = peer_result.unwrap().unwrap();
    assert_eq!(
        elapsed,
        Duration::ZERO,
        "unexpected wait: {native:?}/{case:?}"
    );
    assert_eq!(
        polls, before,
        "extra source/write poll after final response"
    );
    assert!(head.starts_with(b"POST /upload HTTP/1.1\r\n"));
    let wire_head = parse_request_head(&head, Vec::new()).unwrap();
    let wire_lengths: Vec<_> = wire_head
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.parse::<usize>().ok())
        .collect();
    assert_eq!(
        wire_lengths,
        vec![Some(output_bytes)],
        "real output header/framing disagree"
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n") && response.ends_with(b"\r\n\r\nack"));
    assert!(trailing.is_empty());
    assert_eq!(written, body.len());
    assert_eq!(refunded, 0, "real paid allocation outlived its last owner");
    assert!(
        charge > 0 && retained_charge == charge,
        "last real alias/blocker did not retain its ledger charge"
    );
    if native == Native::Rejected {
        assert!(rejected && !entity_changed && entity_length.is_none());
        assert_eq!(source_after_collection, 0);
        assert_eq!(source_after_forward, BODY_BYTES - 1);
        assert_eq!(body, vec![b'a'; BODY_BYTES - 1]);
    } else {
        assert!(!rejected && entity_changed);
        let expected = if native == Native::Shorten {
            BODY_BYTES / 2
        } else {
            BODY_BYTES
        };
        assert_eq!(entity_length, Some(expected));
        assert_eq!(output_bytes, expected);
        assert_eq!(source_after_collection, BODY_BYTES);
        assert_eq!(source_after_forward, BODY_BYTES);
        assert_eq!(
            body,
            vec![b'b'; expected - usize::from(case == Case::LastWritePending)]
        );
    }
    let outcome = outcome.expect("forward fixture fail-safe expired").unwrap();
    (
        outcome.downstream_keep_alive,
        outcome.upstream_reusable,
        tail_polls,
    )
}

#[tokio::test(start_paused = true)]
async fn shared_native_64k_real_message_repolls_and_refunds_the_last_owner() {
    let (downstream, upstream, polls) = shared(Native::Replace, Case::Ready).await;
    assert!(polls >= 1);
    assert!(
        downstream && upstream,
        "real precollected Message lost already-ready upload completion"
    );
}
#[tokio::test(start_paused = true)]
async fn shorter_output_keeps_the_complete_original_source_identity() {
    let (downstream, upstream, polls) = shared(Native::Shorten, Case::Ready).await;
    assert!(polls >= 1);
    assert!(
        downstream && upstream,
        "changed wire length replaced the real source proof"
    );
}
#[tokio::test(start_paused = true)]
async fn precollected_shorter_output_last_write_pending_still_closes() {
    let (downstream, upstream, polls) = shared(Native::Shorten, Case::LastWritePending).await;
    assert!(!downstream && !upstream);
    assert_eq!(
        polls, 0,
        "source completion alone was treated as final flush"
    );
}
#[tokio::test(start_paused = true)]
async fn real_budget_refusal_does_not_complete_an_incomplete_streaming_source() {
    let (downstream, upstream, polls) = shared(Native::Rejected, Case::MissingSource).await;
    assert!(!downstream && !upstream);
    assert_eq!(polls, 0);
}
