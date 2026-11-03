//! Caller-owned h2mux with Mihomo's 30-second read-idle PING policy.
use super::*;
use crate::transport::h2_write::{Sender, Writes};
use std::time::Duration;

pub(super) async fn new(raw: BoxStream) -> io::Result<(Sender, impl Future<Output = ()> + Send)> {
    let last_read = Arc::new(Mutex::new(Instant::now()));
    let (raw, writes) = Writes::wrap(raw);
    let (sender, mut connection) = h2::client::Builder::new()
        .enable_push(false)
        .initial_window_size(65536)
        // Leave bounded connection credit for other streams when a few TCP
        // consumers hold their individual receive windows.
        .initial_connection_window_size(524288)
        .max_frame_size(16384)
        .max_header_list_size(16384)
        .max_concurrent_streams(0)
        .max_send_buffer_size(16384)
        .handshake(ActivityIo {
            raw: Box::new(raw),
            last_read: last_read.clone(),
        })
        .await
        .map_err(|_| io::ErrorKind::ConnectionAborted)?;
    let mut ping = connection.ping_pong().expect("single sing-mux PING owner");
    Ok((
        Sender {
            request: sender,
            writes,
        },
        async move {
            let interval = Duration::from_secs(30);
            loop {
                let at = *last_read.lock().unwrap() + interval;
                tokio::select! {
                    _ = &mut connection => break,
                    () = tokio::time::sleep_until(at) => {
                        if Instant::now() < *last_read.lock().unwrap() + interval {continue;}
                        tokio::select! {
                            _ = &mut connection => break,
                            result = tokio::time::timeout(Duration::from_secs(15), ping.ping(h2::Ping::opaque())) => {
                                if !matches!(result, Ok(Ok(_))) {break;}
                            }
                        }
                    }
                }
            }
        },
    ))
}

struct ActivityIo {
    raw: BoxStream,
    last_read: Arc<Mutex<Instant>>,
}
impl AsyncRead for ActivityIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        let result = Pin::new(&mut self.raw).poll_read(cx, out);
        if out.filled().len() > before {
            *self.last_read.lock().unwrap() = Instant::now();
        }
        result
    }
}
impl AsyncWrite for ActivityIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod prequeued_flush_memory_tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::task::AtomicWaker;
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::{Wake, Waker},
    };
    use tokio::io::DuplexStream;

    #[derive(Default)]
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Count {
        fn take(&self) -> usize {
            self.0.swap(0, Ordering::SeqCst)
        }
    }

    #[derive(Default)]
    struct Gate {
        blocked: AtomicBool,
        pending: AtomicUsize,
        written: AtomicUsize,
        wake: AtomicWaker,
    }
    struct MemoryIo {
        raw: DuplexStream,
        gate: Arc<Gate>,
    }
    impl AsyncRead for MemoryIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_read(cx, out)
        }
    }
    impl AsyncWrite for MemoryIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            match Pin::new(&mut self.raw).poll_write(cx, input) {
                Poll::Ready(Ok(count)) => {
                    self.gate.written.fetch_add(count, Ordering::SeqCst);
                    Poll::Ready(Ok(count))
                }
                result => result,
            }
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.gate.wake.register(cx.waker());
            if self.gate.blocked.load(Ordering::SeqCst) {
                self.gate.pending.fetch_add(1, Ordering::SeqCst);
                Poll::Pending
            } else {
                Pin::new(&mut self.raw).poll_flush(cx)
            }
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_shutdown(cx)
        }
    }

    struct Fixture {
        driver: Pin<Box<dyn Future<Output = ()> + Send>>,
        server: h2::server::Connection<MemoryIo, Bytes>,
        sender: Option<Sender>,
        stream: Option<BoxStream>,
        input: Option<h2::RecvStream>,
        output: Option<h2::SendStream<Bytes>>,
        gate: Arc<Gate>,
        peer_gate: Arc<Gate>,
        driver_count: Arc<Count>,
        peer_count: Arc<Count>,
        caller_waker: Waker,
        received: Vec<u8>,
        held: Vec<Bytes>,
        driver_done: bool,
        peer_done: bool,
        peer_eof: bool,
    }
    impl Fixture {
        async fn open() -> Self {
            let (raw, peer) = tokio::io::duplex(65536);
            let gate = Arc::new(Gate::default());
            let peer_gate = Arc::new(Gate::default());
            let (client, server) = tokio::join!(
                new(Box::new(MemoryIo {
                    raw,
                    gate: gate.clone(),
                })),
                h2::server::Builder::new().handshake::<_, Bytes>(MemoryIo {
                    raw: peer,
                    gate: peer_gate.clone(),
                }),
            );
            let (sender, driver) = client.unwrap();
            let mut fixture = Self {
                driver: Box::pin(driver),
                server: server.unwrap(),
                sender: Some(sender.clone()),
                stream: None,
                input: None,
                output: None,
                gate,
                peer_gate,
                driver_count: Arc::default(),
                peer_count: Arc::default(),
                caller_waker: Waker::from(Arc::new(Count::default())),
                received: Vec::new(),
                held: Vec::new(),
                driver_done: false,
                peer_done: false,
                peer_eof: false,
            };
            let mut opening = Box::pin(crate::transport::grpc::mux_stream(
                sender,
                Instant::now() + Duration::from_secs(3),
                true,
            ));
            for _ in 0..64 {
                fixture.driver_count.take();
                fixture.peer_count.take();
                if fixture.stream.is_none() {
                    let mut cx = Context::from_waker(&fixture.caller_waker);
                    if let Poll::Ready(result) = opening.as_mut().poll(&mut cx) {
                        fixture.stream = Some(result.unwrap());
                    }
                }
                fixture.drive();
                if fixture.stream.is_some()
                    && fixture.input.is_some()
                    && fixture.driver_count.0.load(Ordering::SeqCst) == 0
                    && fixture.peer_count.0.load(Ordering::SeqCst) == 0
                {
                    return fixture;
                }
            }
            panic!("fixture handshake did not reach counted-waker quiescence");
        }

        fn drive(&mut self) {
            let driver_waker = Waker::from(self.driver_count.clone());
            let mut driver_cx = Context::from_waker(&driver_waker);
            if !self.driver_done {
                self.driver_done = self.driver.as_mut().poll(&mut driver_cx).is_ready();
            }
            let peer_waker = Waker::from(self.peer_count.clone());
            let mut peer_cx = Context::from_waker(&peer_waker);
            if !self.peer_done {
                match self.server.poll_accept(&mut peer_cx) {
                    Poll::Ready(Some(Ok((request, mut reply)))) => {
                        assert!(self.input.is_none(), "fixture opened a second request");
                        self.output =
                            Some(reply.send_response(http::Response::new(()), false).unwrap());
                        self.input = Some(request.into_body());
                    }
                    Poll::Ready(Some(Err(error))) => panic!("memory peer failed: {error}"),
                    Poll::Ready(None) => self.peer_done = true,
                    Poll::Pending => {}
                }
            }
        }

        fn collect(&mut self) {
            let peer_waker = Waker::from(self.peer_count.clone());
            let mut cx = Context::from_waker(&peer_waker);
            let body = self.input.as_mut().expect("fixture CONNECT request");
            loop {
                match body.poll_data(&mut cx) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        self.received.extend_from_slice(&bytes);
                        // No released flow credit or response data rescues the driver.
                        self.held.push(bytes);
                    }
                    Poll::Ready(Some(Err(error))) => panic!("memory body failed: {error}"),
                    Poll::Ready(None) => {
                        self.peer_eof = true;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }

        fn admit(&mut self, bytes: &[u8]) {
            let mut cx = Context::from_waker(&self.caller_waker);
            match Pin::new(self.stream.as_mut().unwrap()).poll_write(&mut cx, bytes) {
                Poll::Ready(Ok(count)) => {
                    assert_eq!(count, bytes.len(), "fixture partial admission")
                }
                result => panic!("fixture DATA was not immediately admitted: {result:?}"),
            }
        }

        fn naturally_drive_until_quiet(&mut self) -> usize {
            let mut polls = 0;
            for _ in 0..32 {
                if self.driver_count.take() == 0 {
                    return polls;
                }
                self.drive();
                self.collect();
                polls += 1;
            }
            panic!("automatic driver phase did not quiesce after bounded work");
        }

        fn finish(mut self) {
            self.gate.blocked.store(false, Ordering::SeqCst);
            self.gate.wake.wake();
            let mut flushed = false;
            let mut shutdown = false;
            for _ in 0..64 {
                self.drive();
                let mut cx = Context::from_waker(&self.caller_waker);
                let stream = self.stream.as_mut().unwrap();
                if !flushed {
                    match Pin::new(&mut *stream).poll_flush(&mut cx) {
                        Poll::Ready(Ok(())) => flushed = true,
                        Poll::Ready(Err(error)) => panic!("memory flush cleanup failed: {error}"),
                        Poll::Pending => {}
                    }
                }
                if flushed && !shutdown {
                    match Pin::new(stream).poll_shutdown(&mut cx) {
                        Poll::Ready(Ok(())) => shutdown = true,
                        Poll::Ready(Err(error)) => panic!("memory FIN cleanup failed: {error}"),
                        Poll::Pending => {}
                    }
                }
                self.collect();
                if shutdown && self.peer_eof {
                    break;
                }
            }
            self.output
                .as_mut()
                .unwrap()
                .send_data(Bytes::new(), true)
                .unwrap();
            let mut client_eof = false;
            for _ in 0..64 {
                self.drive();
                let mut cx = Context::from_waker(&self.caller_waker);
                let mut byte = [0];
                let mut out = ReadBuf::new(&mut byte);
                match Pin::new(self.stream.as_mut().unwrap()).poll_read(&mut cx, &mut out) {
                    Poll::Ready(Ok(())) => {
                        assert!(out.filled().is_empty(), "unexpected response DATA");
                        client_eof = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => panic!("memory read cleanup failed: {error}"),
                    Poll::Pending => {}
                }
            }
            drop((
                self.stream.take(),
                self.sender.take(),
                self.input.take(),
                self.output.take(),
            ));
            self.held.clear();
            for _ in 0..64 {
                self.drive();
                if self.driver_done && self.peer_done {
                    break;
                }
            }
            assert!(
                flushed
                    && shutdown
                    && self.peer_eof
                    && client_eof
                    && self.driver_done
                    && self.peer_done,
                "memory fixture did not naturally join: flush={flushed}, FIN={shutdown}, peer_EOF={}, client_EOF={client_eof}, driver={}, peer={}",
                self.peer_eof,
                self.driver_done,
                self.peer_done,
            );
        }
    }

    #[tokio::test]
    async fn already_queued_large_data_progresses_before_pending_raw_flush_completes() {
        let mut fixture = Fixture::open().await;
        let peer_before = fixture.peer_gate.written.load(Ordering::SeqCst);
        fixture.gate.blocked.store(true, Ordering::SeqCst);
        fixture.driver_count.take();
        let a = [b'a'; 2048];
        let b = [b'b'; 2048];
        // Both DATA frames are admitted before any driver flush registration.
        fixture.admit(&a);
        fixture.admit(&b);
        let natural_polls = fixture.naturally_drive_until_quiet();
        let independent = fixture.received.len();
        let pending = fixture.gate.pending.load(Ordering::SeqCst);
        assert!(
            natural_polls > 0,
            "fixture never received the initial native driver wake"
        );
        assert!(
            pending > 0,
            "fixture never reached the blocked physical flush"
        );
        assert!(!fixture.driver_done && !fixture.peer_done && !fixture.peer_eof);
        // An external re-poll is a counterfactual, never counted as autonomy.
        fixture.drive();
        fixture.collect();
        let rescued = fixture.received.len();
        assert_eq!(fixture.received, [a.as_slice(), b.as_slice()].concat());
        assert_eq!(
            fixture.peer_gate.written.load(Ordering::SeqCst),
            peer_before,
            "peer emitted credit/control/data during the observation"
        );
        let mut cx = Context::from_waker(&fixture.caller_waker);
        assert!(
            Pin::new(fixture.stream.as_mut().unwrap())
                .poll_flush(&mut cx)
                .is_pending(),
            "explicit logical flush completed before physical flush"
        );
        fixture.finish();
        assert_eq!(
            rescued,
            a.len() + b.len(),
            "external re-poll did not rescue both DATA frames"
        );
        assert_eq!(
            independent,
            a.len() + b.len(),
            "already queued h2mux DATA must progress after a productive pending flush: independent={independent}, rescued={rescued}, natural_polls={natural_polls}"
        );
    }
}
