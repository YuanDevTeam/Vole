// Real H1 body/flush/response ordering; no new production witness is referenced.
use super::*;
use futures_util::task::AtomicWaker;
use std::{
    pin::Pin,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncReadExt, DuplexStream, ReadBuf},
    sync::oneshot,
};

const BODY_BYTES: usize = 65536;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Case {
    Ready,
    Pending,
    Error,
    MissingSource,
    LastWritePending,
}
#[derive(Default)]
struct Control {
    mode: AtomicU8,
    tail_polls: AtomicUsize,
    body_written: AtomicUsize,
    body_write_polls: AtomicUsize,
    source_read_polls: AtomicUsize,
    wake: AtomicWaker,
}
struct SourceIo {
    io: DuplexStream,
    control: Arc<Control>,
}
impl AsyncRead for SourceIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.control
            .source_read_polls
            .fetch_add(1, Ordering::Release);
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}
struct TailIo {
    io: DuplexStream,
    control: Arc<Control>,
    head_flushed: bool,
    block_last: bool,
    first_tail: Option<oneshot::Sender<()>>,
}
impl AsyncRead for TailIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}
impl AsyncWrite for TailIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let body = self.head_flushed;
        if body {
            self.control
                .body_write_polls
                .fetch_add(1, Ordering::Release);
        }
        let written = self.control.body_written.load(Ordering::Acquire);
        let data = if body && self.block_last && !data.is_empty() {
            self.control.wake.register(cx.waker());
            let remaining = (BODY_BYTES - 1).saturating_sub(written);
            if remaining == 0 {
                return Poll::Pending;
            }
            &data[..data.len().min(remaining)]
        } else {
            data
        };
        let result = Pin::new(&mut self.io).poll_write(cx, data);
        if body && let Poll::Ready(Ok(count)) = &result {
            self.control
                .body_written
                .fetch_add(*count, Ordering::Release);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.head_flushed {
            let result = Pin::new(&mut self.io).poll_flush(cx);
            if matches!(&result, Poll::Ready(Ok(()))) {
                self.head_flushed = true;
            }
            return result;
        }
        self.control.tail_polls.fetch_add(1, Ordering::Release);
        self.control.wake.register(cx.waker());
        if let Some(first) = self.first_tail.take() {
            let _ = first.send(());
        }
        match self.control.mode.load(Ordering::Acquire) {
            0 => Poll::Pending,
            1 => Pin::new(&mut self.io).poll_flush(cx),
            _ => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn exercise(case: Case) -> (bool, bool, Vec<u8>, usize) {
    let (source, source_reader) = tokio::io::duplex(128 * 1024);
    let (source_release, release_source) = oneshot::channel();
    let supplied = if case == Case::MissingSource {
        BODY_BYTES - 1
    } else {
        BODY_BYTES
    };
    let source_owner = tokio::spawn(tokio::task::unconstrained(async move {
        let mut source = source;
        let result = source.write_all(&vec![b'a'; supplied]).await;
        let _ = release_source.await;
        result
    }));
    let (upstream_io, peer) = tokio::io::duplex(128 * 1024);
    let control = Arc::new(Control::default());
    let (first_tail, tail_entered) = oneshot::channel();
    let peer_control = control.clone();
    let peer_owner = tokio::spawn(tokio::task::unconstrained(async move {
        let mut peer = BufReader::new(peer);
        let head = read_head(&mut peer, 16384).await?;
        let prefix = if matches!(case, Case::MissingSource | Case::LastWritePending) {
            BODY_BYTES - 1
        } else {
            BODY_BYTES
        };
        let mut body = vec![0; prefix];
        peer.read_exact(&mut body).await?;
        if prefix == BODY_BYTES {
            tail_entered
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        // Make final flush Ready/error and response head Ready in the same
        // peer poll. The real parent select remains biased response-first.
        let polls_before_response = (
            peer_control.source_read_polls.load(Ordering::Acquire),
            peer_control.body_write_polls.load(Ordering::Acquire),
        );
        peer_control.mode.store(
            match case {
                Case::Ready => 1,
                Case::Error => 2,
                _ => 0,
            },
            Ordering::Release,
        );
        peer_control.wake.wake();
        peer.get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nack")
            .await?;
        let mut trailing = Vec::new();
        peer.read_to_end(&mut trailing).await?;
        Ok::<_, io::Error>((head, body, trailing, polls_before_response))
    }));
    let request = parse_request_head(
        b"POST http://origin.test/upload HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 65536\r\nConnection: keep-alive",
        Vec::new(),
    ).unwrap();
    let plan = RequestPlan::new(&request).unwrap();
    let config = HttpServerConfig::processing();
    let mut input = BufReader::new(SourceIo {
        io: source_reader,
        control: control.clone(),
    });
    let mut response = Vec::new();
    let mut upstream = UpstreamIo::new(Box::new(TailIo {
        io: upstream_io,
        control: control.clone(),
        head_flushed: false,
        block_last: case == Case::LastWritePending,
        first_tail: Some(first_tail),
    }));
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
            None,
            true,
        )),
    )
    .await;
    let elapsed = began.elapsed();
    let tail_polls = control.tail_polls.load(Ordering::Acquire);
    let body_written = control.body_written.load(Ordering::Acquire);
    let polls_after_response = (
        control.source_read_polls.load(Ordering::Acquire),
        control.body_write_polls.load(Ordering::Acquire),
    );
    drop(upstream);
    drop(input);
    let _ = source_release.send(());
    // Both exact owned tasks finish before even the expected old-code red.
    let source_result = source_owner.await;
    let peer_result = peer_owner.await;
    assert!(
        source_result.is_ok(),
        "source owner did not join: {source_result:?}"
    );
    source_result.unwrap().unwrap();
    let (head, body, trailing, polls_before_response) = peer_result.unwrap().unwrap();
    assert_eq!(
        polls_after_response, polls_before_response,
        "candidate polled source/body write after final head: {case:?}"
    );
    assert_eq!(
        elapsed,
        Duration::ZERO,
        "one-poll candidate awaited a Pending tail or reset a deadline: {case:?}"
    );
    assert!(head.starts_with(b"POST /upload HTTP/1.1\r\n"));
    assert_eq!(
        body.len(),
        if matches!(case, Case::MissingSource | Case::LastWritePending) {
            BODY_BYTES - 1
        } else {
            BODY_BYTES
        }
    );
    assert!(body.iter().all(|byte| *byte == b'a'));
    assert!(
        trailing.is_empty(),
        "candidate replayed or sent more body after final: {case:?}"
    );
    assert_eq!(body_written, body.len());
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n") && response.ends_with(b"\r\n\r\nack"));
    let outcome = outcome
        .expect("forward owner hit fixture fail-safe")
        .unwrap();
    (
        outcome.downstream_keep_alive,
        outcome.upstream_reusable,
        response,
        tail_polls,
    )
}

#[tokio::test(start_paused = true)]
async fn final_response_repolls_an_already_ready_real_tail_flush_once() {
    let (downstream, upstream, response, polls) = exercise(Case::Ready).await;
    assert!(polls >= 1, "real upload never reached its final flush");
    // Old behavior reaches this assertion only after all bytes, response and joins.
    assert!(
        downstream && upstream,
        "response-first selection hid the completed upload flush"
    );
    assert!(
        response
            .windows(b"Connection: keep-alive".len())
            .any(|bytes| bytes == b"Connection: keep-alive")
    );
}

#[tokio::test(start_paused = true)]
async fn pending_error_missing_source_and_last_write_keep_the_original_close() {
    for case in [
        Case::Pending,
        Case::Error,
        Case::MissingSource,
        Case::LastWritePending,
    ] {
        let (downstream, upstream, response, polls) = exercise(case).await;
        assert!(!downstream && !upstream, "unsafe reuse after {case:?}");
        assert!(
            response
                .windows(b"Connection: close".len())
                .any(|bytes| bytes == b"Connection: close")
        );
        if matches!(case, Case::MissingSource | Case::LastWritePending) {
            assert_eq!(
                polls, 0,
                "incomplete read/write reached a final-flush witness"
            );
        } else {
            assert!(polls >= 1);
        }
    }
}

mod prepared_cases {
    include!("final_flush_repoll_prepared_memory_tests.rs");
}
