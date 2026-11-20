// Included inside h3_connect::tests; the existing real memory Peer is reused.
mod write_waker_memory_tests {
    use super::*;
    use futures_util::{
        FutureExt,
        future::poll_fn,
        task::{ArcWake, waker_ref},
    };
    use std::panic::{AssertUnwindSafe, resume_unwind};

    #[derive(Default)]
    struct Gate {
        paused: AtomicBool,
        blocked: AtomicBool,
        failed: AtomicBool,
        changed: Notify,
        observed: Arc<Notify>,
    }
    impl Gate {
        async fn wait(&self) {
            loop {
                let changed = self.changed.notified();
                if !self.paused.load(Ordering::Acquire) {
                    return;
                }
                self.blocked.store(true, Ordering::Release);
                self.observed.notify_one();
                changed.await;
            }
        }
        fn release(&self) {
            self.paused.store(false, Ordering::Release);
            self.changed.notify_waiters();
        }
    }
    struct GatedPackets {
        inner: Box<dyn DatagramTransport>,
        gate: Arc<Gate>,
    }
    #[async_trait]
    impl DatagramTransport for GatedPackets {
        fn supports_shared_destinations(&self) -> bool {
            self.inner.supports_shared_destinations()
        }
        fn payload_budget(&self, peer: &Destination) -> DatagramBudget {
            self.inner.payload_budget(peer)
        }
        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            self.gate.wait().await;
            if self.gate.failed.load(Ordering::Acquire) {
                return Err(DispatchError::ConnectionRefused);
            }
            self.inner.send(packet).await
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.inner.receive().await
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.inner.close().await
        }
    }

    struct Relay {
        target: AtomicWaker,
        armed: AtomicBool,
        wakes: AtomicUsize,
        observed: Arc<Notify>,
    }
    impl Relay {
        fn new(observed: Arc<Notify>) -> Arc<Self> {
            Arc::new(Self {
                target: AtomicWaker::new(),
                armed: AtomicBool::new(false),
                wakes: AtomicUsize::new(0),
                observed,
            })
        }
    }
    impl ArcWake for Relay {
        fn wake_by_ref(this: &Arc<Self>) {
            // Setup wakes cannot leave an already-runnable writer behind the
            // reader's final native registration. No IO result is fabricated.
            if this.armed.load(Ordering::Acquire) {
                this.wakes.fetch_add(1, Ordering::AcqRel);
                this.observed.notify_one();
                this.target.wake();
            }
        }
    }
    struct NativeTap {
        caller: AtomicWaker,
        notifications: AtomicUsize,
        pending_polls: AtomicUsize,
        observed: Arc<Notify>,
    }
    impl NativeTap {
        fn new(observed: Arc<Notify>) -> Arc<Self> {
            Arc::new(Self {
                caller: AtomicWaker::new(),
                notifications: AtomicUsize::new(0),
                pending_polls: AtomicUsize::new(0),
                observed,
            })
        }
    }
    impl ArcWake for NativeTap {
        fn wake_by_ref(this: &Arc<Self>) {
            // Only the real retained send_data future receives this waker.
            // Response-header and response-channel wakes cannot increment it.
            this.caller.wake();
            this.notifications.fetch_add(1, Ordering::AcqRel);
            this.observed.notify_one();
        }
    }
    struct TappedOperation {
        inner: SendOperation,
        tap: Arc<NativeTap>,
    }
    impl Future for TappedOperation {
        type Output = (SendHalf, io::Result<()>);
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.tap.caller.register(cx.waker());
            let wake = waker_ref(&this.tap);
            let result = this.inner.as_mut().poll(&mut Context::from_waker(&wake));
            if result.is_pending() {
                this.tap.pending_polls.fetch_add(1, Ordering::AcqRel);
                this.tap.observed.notify_one();
            }
            result
        }
    }

    async fn open_typed(pool: &Pool, peer: &Arc<Peer>, target: &str) -> io::Result<Stream> {
        let factory = peer.clone();
        let (mut sender, lease) = pool
            .acquire(Instant::now() + Duration::from_secs(5), move || {
                factory.connect()
            })
            .await?;
        let request = sender
            .send_request(request(target))
            .await
            .map_err(|_| closed())?;
        let (send, receive) = request.split();
        let close = Arc::new(Close::default());
        let headers_close = close.clone();
        let physical = lease.0.clone();
        let cancel = pool.cancellation.clone();
        let (ready, response) = oneshot::channel();
        pool.spawn(async move {
            let mut receive = ReceiveHalf(receive);
            let result = tokio::select! { biased;
                ()=cancel.cancelled()=>Err(closed()),
                ()=headers_close.cancel.cancelled()=>Err(closed()),
                ()=physical.cancel.cancelled()=>Err(closed()),
                response=receive.0.recv_response()=>response
                    .map_err(|_| closed()).and_then(|response| {
                        if response.status() == 200 { Ok(()) } else { Err(closed()) }
                    }),
            };
            if result.is_err() {
                headers_close.stop(true);
            }
            let _ = ready.send(result.map(|()| receive));
        })?;
        Ok(Stream {
            response: Some(response),
            receive: None,
            send: Some(SendHalf { stream: send }),
            pending: None,
            data: Bytes::new(),
            close,
            lease: Some(lease),
            finishing: false,
            finished: false,
            _observation: observation::track(ResourceKind::Session),
        })
    }
    async fn observe(notify: &Notify, ready: impl Fn() -> bool) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let changed = notify.notified();
                if ready() {
                    return;
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native-wake setup/event watchdog"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn trusttunnel_h3_native_write_wake_reaches_writer_while_reader_response_is_full() {
        let probe = ResourceProbe::default();
        let (result, cleanup, empty, calls, closed, close_released) = probe.scope(async {
            let peer = Peer::new();
            let pool = Pool::new(None);
            let users = TaskTracker::new();
            let cancel = CancellationToken::new();
            let observed = Arc::new(Notify::new());
            let gate = Arc::new(Gate { observed: observed.clone(), ..Default::default() });
            let writer = Relay::new(observed.clone());
            let reader = Relay::new(observed.clone());
            let write_pending = Arc::new(AtomicBool::new(false));
            let read_pending = Arc::new(AtomicBool::new(false));
            let response_pending = Arc::new(AtomicBool::new(false));
            let (responses, mut response) = mpsc::channel(1);
            responses.try_send(()).unwrap();
            let mut close_weak = None;
            let result = AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(15), async {
                let factory = peer.clone();
                let transport_gate = gate.clone();
                pool.probe(request("_check"), Instant::now() + Duration::from_secs(5), move || async move {
                    let mut raw = factory.connect().await?;
                    raw.transport = Box::new(GatedPackets { inner: raw.transport, gate: transport_gate });
                    Ok(raw)
                }).await?;
                gate.paused.store(true, Ordering::Release);
                let (finished, fin) = oneshot::channel();
                *peer.duplex_fin.lock().unwrap() = Some(finished);
                let typed = open_typed(&pool, &peer, "large-duplex.invalid:443").await?;
                close_weak = Some(Arc::downgrade(&typed.close));
                let stream = Arc::new(Mutex::new(typed));
                let payload = Arc::new((0..LARGE_DUPLEX_BYTES)
                    .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7)).collect::<Vec<_>>());
                let read_complete = Arc::new(Notify::new());
                let (sent, upload) = oneshot::channel();
                let task_stream = stream.clone();
                let task_payload = payload.clone();
                let task_writer = writer.clone();
                let task_pending = write_pending.clone();
                let task_read_complete = read_complete.clone();
                let task_cancel = cancel.clone();
                users.spawn(observation::task(async move {
                    let operation = async {
                        let mut offset = 0;
                        poll_fn(|cx| {
                            task_writer.target.register(cx.waker());
                            let wake = waker_ref(&task_writer);
                            let mut native = Context::from_waker(&wake);
                            let mut stream = task_stream.lock().unwrap();
                            while offset < task_payload.len() {
                                match Pin::new(&mut *stream).poll_write(&mut native, &task_payload[offset..]) {
                                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                                    Poll::Ready(Ok(n)) => offset += n,
                                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                    Poll::Pending => {
                                        // poll_write can be Pending here only in drain's real
                                        // SendOperation::send_data poll, not in this test gate.
                                        task_pending.store(true, Ordering::Release);
                                        task_writer.observed.notify_one();
                                        return Poll::Pending;
                                    }
                                }
                            }
                            Pin::new(&mut *stream).poll_flush(&mut native)
                        }).await?;
                        task_read_complete.notified().await;
                        poll_fn(|cx| {
                            task_writer.target.register(cx.waker());
                            let wake = waker_ref(&task_writer);
                            Pin::new(&mut *task_stream.lock().unwrap())
                                .poll_shutdown(&mut Context::from_waker(&wake))
                        }).await
                    };
                    let result = tokio::select! { biased;
                        ()=task_cancel.cancelled()=>Err(io::ErrorKind::Interrupted.into()),
                        result=operation=>result,
                    };
                    let _ = sent.send(result);
                }));
                observe(&observed, || write_pending.load(Ordering::Acquire) && gate.blocked.load(Ordering::Acquire)).await?;

                let tap = NativeTap::new(observed.clone());
                {
                    let mut stream = stream.lock().unwrap();
                    let inner = stream.pending.take().ok_or_else(|| io::Error::other("no real retained send operation"))?;
                    stream.pending = Some(Box::pin(TappedOperation { inner, tap: tap.clone() }));
                }
                // Re-poll the real writer once after insertion, so the native
                // Signals::write slot holds the tap, not a pre-tap caller.
                writer.target.wake();
                observe(&observed, || tap.pending_polls.load(Ordering::Acquire) > 0).await?;
                let writer_pending_polls = tap.pending_polls.load(Ordering::Acquire);

                let (received, download) = oneshot::channel();
                let task_stream = stream.clone();
                let task_reader = reader.clone();
                let task_read_pending = read_pending.clone();
                let task_response_pending = response_pending.clone();
                let task_cancel = cancel.clone();
                users.spawn(observation::task(async move {
                    let operation = async {
                        poll_fn(|cx| {
                            task_reader.target.register(cx.waker());
                            let wake = waker_ref(&task_reader);
                            let mut byte = [0];
                            let mut buffer = ReadBuf::new(&mut byte);
                            match Pin::new(&mut *task_stream.lock().unwrap())
                                .poll_read(&mut Context::from_waker(&wake), &mut buffer) {
                                Poll::Pending => {
                                    task_read_pending.store(true, Ordering::Release);
                                    Poll::Ready(Ok(()))
                                }
                                _ => Poll::Ready(Err(io::Error::other("reader did not replace a real Pending send registration"))),
                            }
                        }).await?;
                        let send = responses.send(());
                        tokio::pin!(send);
                        poll_fn(|cx| {
                            let result = send.as_mut().poll(cx);
                            if result.is_pending() {
                                task_response_pending.store(true, Ordering::Release);
                                task_reader.observed.notify_one();
                            }
                            result
                        }).await.map_err(|_| closed())?;
                        let mut echoed = vec![0; LARGE_DUPLEX_BYTES];
                        let mut offset = 0;
                        poll_fn(|cx| {
                            let mut stream = task_stream.lock().unwrap();
                            while offset < echoed.len() {
                                let mut buffer = ReadBuf::new(&mut echoed[offset..]);
                                ready!(Pin::new(&mut *stream).poll_read(cx, &mut buffer))?;
                                let n = buffer.filled().len();
                                if n == 0 { return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())); }
                                offset += n;
                            }
                            let mut extra = [0];
                            let mut buffer = ReadBuf::new(&mut extra);
                            ready!(Pin::new(&mut *stream).poll_read(cx, &mut buffer))?;
                            if !buffer.filled().is_empty() { return Poll::Ready(Err(io::Error::other("extra duplex response bytes"))); }
                            Poll::Ready(Ok(()))
                        }).await?;
                        if echoed != *payload { return Err(io::Error::other("duplex response mismatch")); }
                        read_complete.notify_one();
                        Ok(())
                    };
                    let result = tokio::select! { biased;
                        ()=task_cancel.cancelled()=>Err(io::ErrorKind::Interrupted.into()),
                        result=operation=>result,
                    };
                    let _ = received.send(result);
                }));
                observe(&observed, || read_pending.load(Ordering::Acquire) && response_pending.load(Ordering::Acquire)).await?;
                if tap.pending_polls.load(Ordering::Acquire) <= writer_pending_polls {
                    return Err(io::Error::other("reader did not poll the real retained native Pending operation"));
                }
                let setup_wakes_clear = writer.wakes.load(Ordering::Acquire) == 0 && reader.wakes.load(Ordering::Acquire) == 0;
                let native_before = tap.notifications.load(Ordering::Acquire);
                writer.armed.store(true, Ordering::Release);
                reader.armed.store(true, Ordering::Release);
                gate.release();
                observe(&observed, || tap.notifications.load(Ordering::Acquire) > native_before).await?;
                // Freeze BEFORE rescue, reader unpark and Close::stop: each of
                // those may legitimately wake the writer for another reason.
                let native_wakes = (writer.wakes.load(Ordering::Acquire), reader.wakes.load(Ordering::Acquire));
                let native_notifications = tap.notifications.load(Ordering::Acquire) - native_before;
                let rescue = native_wakes.0 == 0;
                response.recv().await.ok_or_else(closed)?;
                let complete = async {
                    upload.await.map_err(|_| closed())??;
                    download.await.map_err(|_| closed())??;
                    let bytes = fin.await.map_err(|_| closed())??;
                    if bytes != LARGE_DUPLEX_BYTES { return Err(io::Error::other("short real request FIN witness")); }
                    Ok::<_, io::Error>(())
                };
                tokio::pin!(complete);
                loop {
                    tokio::select! {
                        result=&mut complete=>{ result?; break; },
                        ()=tokio::time::sleep(Duration::from_millis(1)), if rescue=>{
                            // Recovery only: never enters Relay::wakes or the
                            // already frozen native verdict. Old source still
                            // finishes wire/FIN and joins before semantic RED.
                            writer.target.wake();
                        },
                    }
                }
                drop(stream);
                Ok::<_, io::Error>((setup_wakes_clear, native_wakes, native_notifications))
            })).catch_unwind().await;
            gate.release();
            response.close();
            cancel.cancel();
            writer.target.wake();
            let cleanup = tokio::time::timeout(Duration::from_secs(7), async {
                users.close(); users.wait().await;
                pool.shutdown().await;
                peer.stop().await;
            }).await;
            let empty = users.is_empty() && pool.tasks.is_empty() && peer.tasks.is_empty();
            let calls = peer.calls.load(Ordering::Acquire);
            let closed = peer.closed.load(Ordering::Acquire);
            drop((pool, peer));
            let close_released = close_weak.as_ref().is_none_or(|close| close.upgrade().is_none());
            (result, cleanup, empty, calls, closed, close_released)
        }).await;
        let result = match result {
            Ok(result) => result,
            Err(panic) => resume_unwind(panic),
        };
        cleanup.expect("write-waker Stop/pool/peer join watchdog");
        assert!(empty);
        assert_eq!(calls, 1);
        assert_eq!(closed, 1);
        assert!(probe.snapshot().is_idle());
        assert!(
            close_released,
            "stream Close waker owner survived joined cleanup"
        );
        let (setup_wakes_clear, native_wakes, native_notifications) = result
            .expect("write-waker fixture watchdog, not semantic RED")
            .expect("write-waker real IO/FIN setup failed, not semantic RED");
        assert!(setup_wakes_clear);
        assert!(native_notifications > 0);
        assert!(
            native_wakes.1 > 0,
            "native Pending reader registration never woke"
        );
        assert!(
            native_wakes.0 > 0,
            "native write readiness woke only the parked reader; independent writer required rescue"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn trusttunnel_h3_reader_ready_handoff_wakes_waiting_writer_without_another_native_event()
    {
        // The same-waker arm also rejects an optimization that skips handoff
        // merely because reader and writer currently share one caller task.
        for same_caller in [false, true] {
            ready_handoff(same_caller).await;
        }
    }

    async fn ready_handoff(same_caller: bool) {
        let probe = ResourceProbe::default();
        let (result, cleanup, empty, calls, closed, close_released) =
            probe
                .scope(async {
                    let peer = Peer::new();
                    let pool = Pool::new(None);
                    let observed = Arc::new(Notify::new());
                    let gate = Arc::new(Gate {
                        observed: observed.clone(),
                        ..Default::default()
                    });
                    let writer = Relay::new(observed.clone());
                    let reader = Relay::new(observed.clone());
                    writer.armed.store(true, Ordering::Release);
                    reader.armed.store(true, Ordering::Release);
                    let mut close_weak = None;
                    let result =
                    AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(15), async {
                        let factory = peer.clone();
                        let transport_gate = gate.clone();
                        pool.probe(
                            request("_check"),
                            Instant::now() + Duration::from_secs(5),
                            move || async move {
                                let mut raw = factory.connect().await?;
                                raw.transport = Box::new(GatedPackets {
                                    inner: raw.transport,
                                    gate: transport_gate,
                                });
                                Ok(raw)
                            },
                        )
                        .await?;
                        gate.paused.store(true, Ordering::Release);
                        let (finished, fin) = oneshot::channel();
                        *peer.duplex_fin.lock().unwrap() = Some(finished);
                        let mut stream =
                            open_typed(&pool, &peer, "large-duplex.invalid:443").await?;
                        close_weak = Some(Arc::downgrade(&stream.close));
                        let payload = (0..LARGE_DUPLEX_BYTES)
                            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
                            .collect::<Vec<_>>();
                        let write_wake = waker_ref(&writer);
                        let read_wake = if same_caller {
                            waker_ref(&writer)
                        } else {
                            waker_ref(&reader)
                        };
                        let mut write_context = Context::from_waker(&write_wake);
                        let first = match Pin::new(&mut stream)
                            .poll_write(&mut write_context, &payload[..CHUNK])
                        {
                            Poll::Ready(Ok(n)) if n == CHUNK => n,
                            _ => {
                                return Err(io::Error::other(
                                    "real initial DATA admission did not accept one CHUNK",
                                ));
                            }
                        };
                        if !Pin::new(&mut stream)
                            .poll_flush(&mut write_context)
                            .is_pending()
                        {
                            return Err(io::Error::other(
                                "real native send never reached Pending before the gate opened",
                            ));
                        }
                        let tap = NativeTap::new(observed.clone());
                        let inner = stream
                            .pending
                            .take()
                            .ok_or_else(|| io::Error::other("missing native pending half"))?;
                        stream.pending = Some(Box::pin(TappedOperation {
                            inner,
                            tap: tap.clone(),
                        }));
                        if !stream.drain(&mut write_context).is_pending()
                            || tap.pending_polls.load(Ordering::Acquire) == 0
                        {
                            return Err(io::Error::other(
                                "writer did not re-poll the retained native Pending operation",
                            ));
                        }
                        stream.close.reader.register(&read_wake);
                        if !stream
                            .progress(&mut Context::from_waker(&read_wake))
                            .is_pending()
                        {
                            return Err(io::Error::other(
                                "reader did not take over the retained native Pending operation",
                            ));
                        }
                        gate.release();
                        let ready_delta = loop {
                            let native_before = tap.notifications.load(Ordering::Acquire);
                            // Re-arm the already-observed waiting writer after earlier
                            // native wakes. This is a controlled handoff registration,
                            // not a synthetic send operation or a fake credit result.
                            stream.close.writer.register(&write_wake);
                            let before = writer.wakes.load(Ordering::Acquire);
                            let had_pending = stream.pending.is_some();
                            let progress = stream.progress(&mut Context::from_waker(&read_wake));
                            let after = writer.wakes.load(Ordering::Acquire);
                            // No await or driver poll between before/after on this
                            // current-thread runtime: only this Ready handoff counts.
                            match progress {
                                Poll::Ready(Ok(())) if had_pending && stream.pending.is_none() => {
                                    break after - before;
                                }
                                Poll::Ready(_) => {
                                    return Err(io::Error::other("native reader completion failed"));
                                }
                                Poll::Pending => {
                                    observe(&observed, || {
                                        tap.notifications.load(Ordering::Acquire) > native_before
                                    })
                                    .await?;
                                }
                            }
                        };
                        let (mut read, mut write) = tokio::io::split(stream);
                        let read_complete = Notify::new();
                        let upload = async {
                            write.write_all(&payload[first..]).await?;
                            write.flush().await?;
                            read_complete.notified().await;
                            write.shutdown().await
                        };
                        let download = async {
                            let mut echoed = vec![0; LARGE_DUPLEX_BYTES];
                            read.read_exact(&mut echoed).await?;
                            if echoed != payload {
                                return Err(io::Error::other("Ready handoff echo mismatch"));
                            }
                            let mut extra = [0];
                            if read.read(&mut extra).await? != 0 {
                                return Err(io::Error::other("extra Ready handoff response bytes"));
                            }
                            read_complete.notify_one();
                            Ok::<_, io::Error>(())
                        };
                        tokio::try_join!(upload, download)?;
                        if fin.await.map_err(|_| closed())?? != LARGE_DUPLEX_BYTES {
                            return Err(io::Error::other(
                                "Ready handoff request FIN witness was short",
                            ));
                        }
                        drop((read, write));
                        Ok::<_, io::Error>(ready_delta)
                    }))
                    .catch_unwind()
                    .await;
                    gate.release();
                    let cleanup = tokio::time::timeout(Duration::from_secs(7), async {
                        pool.shutdown().await;
                        peer.stop().await;
                    })
                    .await;
                    let empty = pool.tasks.is_empty() && peer.tasks.is_empty();
                    let calls = peer.calls.load(Ordering::Acquire);
                    let closed = peer.closed.load(Ordering::Acquire);
                    drop((pool, peer));
                    let close_released = close_weak
                        .as_ref()
                        .is_none_or(|close| close.upgrade().is_none());
                    (result, cleanup, empty, calls, closed, close_released)
                })
                .await;
        let result = match result {
            Ok(result) => result,
            Err(panic) => resume_unwind(panic),
        };
        cleanup.expect("Ready handoff Stop/pool/peer join watchdog");
        assert!(empty);
        assert_eq!(calls, 1);
        assert_eq!(closed, 1);
        assert!(probe.snapshot().is_idle());
        assert!(
            close_released,
            "Ready handoff Close waker owner survived joined cleanup"
        );
        let ready_delta = result
            .expect("Ready handoff fixture watchdog, not semantic RED")
            .expect("Ready handoff real IO/FIN setup failed, not semantic RED");
        assert!(
            ready_delta > 0,
            "reader completed native pending DATA without waking the waiting writer"
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum PendingEnd {
        PoolStop,
        StreamDrop,
        PhysicalError,
    }

    async fn pending_waiter(
        stream: Arc<Mutex<Stream>>,
        write: bool,
        pending: Arc<AtomicBool>,
        observed: Arc<Notify>,
        cancel: CancellationToken,
    ) -> Option<Result<(), io::ErrorKind>> {
        let operation = poll_fn(|cx| {
            let mut stream = stream.lock().unwrap();
            let result = if write {
                Pin::new(&mut *stream).poll_flush(cx)
            } else {
                let mut byte = [0];
                Pin::new(&mut *stream).poll_read(cx, &mut ReadBuf::new(&mut byte))
            };
            match result {
                Poll::Pending => {
                    pending.store(true, Ordering::Release);
                    observed.notify_one();
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result.map_err(|error| error.kind())),
            }
        });
        tokio::select! { biased;
            ()=cancel.cancelled()=>None,
            result=operation=>Some(result),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn trusttunnel_h3_native_pending_stop_drop_and_transport_error_release_all_owners() {
        for end in [
            PendingEnd::PoolStop,
            PendingEnd::StreamDrop,
            PendingEnd::PhysicalError,
        ] {
            pending_end(end).await;
        }
    }

    async fn pending_end(end: PendingEnd) {
        let probe = ResourceProbe::default();
        let (result, cleanup, empty, calls, closed, close_released) = probe
            .scope(async {
                let peer = Peer::new();
                let pool = Pool::new(None);
                let users = TaskTracker::new();
                let cancel = CancellationToken::new();
                let observed = Arc::new(Notify::new());
                let gate = Arc::new(Gate {
                    observed: observed.clone(),
                    ..Default::default()
                });
                let mut close_weak = None;
                let result =
                    AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(15), async {
                        let factory = peer.clone();
                        let transport_gate = gate.clone();
                        pool.probe(
                            request("_check"),
                            Instant::now() + Duration::from_secs(5),
                            move || async move {
                                let mut raw = factory.connect().await?;
                                raw.transport = Box::new(GatedPackets {
                                    inner: raw.transport,
                                    gate: transport_gate,
                                });
                                Ok(raw)
                            },
                        )
                        .await?;
                        gate.paused.store(true, Ordering::Release);
                        // This real peer handler waits for its existing reject gate,
                        // so cancellation before request DATA cannot panic an echo
                        // handler that expected a first body record.
                        let mut stream = open_typed(&pool, &peer, "reject.invalid:443").await?;
                        close_weak = Some(Arc::downgrade(&stream.close));
                        let physical = stream.lease.as_ref().ok_or_else(closed)?.0.clone();
                        let mut context = Context::from_waker(std::task::Waker::noop());
                        let payload = [7; CHUNK];
                        match Pin::new(&mut stream).poll_write(&mut context, &payload) {
                            Poll::Ready(Ok(n)) if n == CHUNK => {}
                            _ => {
                                return Err(io::Error::other(
                                    "pending-end initial native admission failed",
                                ));
                            }
                        }
                        if !Pin::new(&mut stream).poll_flush(&mut context).is_pending() {
                            return Err(io::Error::other(
                                "pending-end initial native flush was not Pending",
                            ));
                        }
                        let tap = NativeTap::new(observed.clone());
                        let inner = stream
                            .pending
                            .take()
                            .ok_or_else(|| io::Error::other("pending-end missing native half"))?;
                        stream.pending = Some(Box::pin(TappedOperation {
                            inner,
                            tap: tap.clone(),
                        }));
                        if !Pin::new(&mut stream).poll_flush(&mut context).is_pending() {
                            return Err(io::Error::other(
                                "pending-end tapped native operation was not Pending",
                            ));
                        }
                        let stream = Arc::new(Mutex::new(stream));
                        let read_pending = Arc::new(AtomicBool::new(false));
                        let write_pending = Arc::new(AtomicBool::new(false));
                        let (read_return, read_result) = oneshot::channel();
                        let read = pending_waiter(
                            stream.clone(),
                            false,
                            read_pending.clone(),
                            observed.clone(),
                            cancel.clone(),
                        );
                        users.spawn(observation::task(async move {
                            let _ = read_return.send(read.await);
                        }));
                        let (write_return, write_result) = oneshot::channel();
                        let write = pending_waiter(
                            stream.clone(),
                            true,
                            write_pending.clone(),
                            observed.clone(),
                            cancel.clone(),
                        );
                        users.spawn(observation::task(async move {
                            let _ = write_return.send(write.await);
                        }));
                        observe(&observed, || {
                            read_pending.load(Ordering::Acquire)
                                && write_pending.load(Ordering::Acquire)
                                && gate.blocked.load(Ordering::Acquire)
                                && tap.pending_polls.load(Ordering::Acquire) >= 3
                        })
                        .await?;
                        let registered_pending = {
                            let stream = stream.lock().unwrap();
                            stream.pending.is_some() && stream.send.is_none()
                        };
                        // Every verdict below follows a positive real native Pending
                        // and both task registrations. No successful credit or IO
                        // completion is synthesized for shutdown.
                        match end {
                            PendingEnd::PoolStop => pool.shutdown().await,
                            PendingEnd::StreamDrop => cancel.cancel(),
                            PendingEnd::PhysicalError => {
                                gate.failed.store(true, Ordering::Release);
                                gate.release();
                            }
                        }
                        let read_end = read_result.await.map_err(|_| closed())?;
                        let write_end = write_result.await.map_err(|_| closed())?;
                        users.close();
                        users.wait().await;
                        let still_pending = {
                            let stream = stream.lock().unwrap();
                            stream.pending.is_some() && stream.send.is_none()
                        };
                        let owned_half_valid = {
                            let stream = stream.lock().unwrap();
                            // An error may leave the original operation pending or
                            // return its half before reporting failure. Either owner
                            // state must release normally when this Stream is dropped.
                            stream.pending.is_some() != stream.send.is_some()
                        };
                        let sole_owner = Arc::strong_count(&stream) == 1;
                        // For Drop, cancel and join the two borrowing IO futures first,
                        // then actually drop their shared Stream. A dropped future
                        // returns no IO result; it is not relabeled ConnectionAborted.
                        drop(stream);
                        let active_after_drop = physical.usage.lock().unwrap().active;
                        drop((physical, tap));
                        Ok::<_, io::Error>((
                            registered_pending,
                            still_pending,
                            owned_half_valid,
                            sole_owner,
                            active_after_drop,
                            read_end,
                            write_end,
                        ))
                    }))
                    .catch_unwind()
                    .await;
                // Failure paths also release the test gate and cancel/join both
                // application tasks before stopping the actual pool and peer.
                gate.release();
                cancel.cancel();
                let cleanup = tokio::time::timeout(Duration::from_secs(7), async {
                    users.close();
                    users.wait().await;
                    pool.shutdown().await;
                    peer.stop().await;
                })
                .await;
                let empty = users.is_empty() && pool.tasks.is_empty() && peer.tasks.is_empty();
                let calls = peer.calls.load(Ordering::Acquire);
                let closed = peer.closed.load(Ordering::Acquire);
                drop((pool, peer));
                let close_released = close_weak
                    .as_ref()
                    .is_none_or(|close| close.upgrade().is_none());
                (result, cleanup, empty, calls, closed, close_released)
            })
            .await;
        let result = match result {
            Ok(result) => result,
            Err(panic) => resume_unwind(panic),
        };
        cleanup.expect("pending-end normal Stop/pool/peer join watchdog");
        assert!(empty, "{end:?}");
        assert_eq!(calls, 1, "{end:?}");
        assert_eq!(closed, 1, "{end:?}");
        assert!(probe.snapshot().is_idle(), "{end:?}");
        assert!(
            close_released,
            "pending-end Close owner survived joined cleanup: {end:?}"
        );
        let (
            registered_pending,
            still_pending,
            owned_half_valid,
            sole_owner,
            active_after_drop,
            read_end,
            write_end,
        ) = result
            .expect("pending-end fixture watchdog, not a successful cancellation")
            .expect("pending-end real native setup/control failed");
        assert!(
            registered_pending && owned_half_valid && sole_owner,
            "{end:?}"
        );
        assert_eq!(active_after_drop, 0, "{end:?}");
        match end {
            PendingEnd::StreamDrop => {
                assert!(still_pending);
                assert_eq!(read_end, None);
                assert_eq!(write_end, None);
            }
            PendingEnd::PoolStop | PendingEnd::PhysicalError => {
                assert_eq!(
                    read_end,
                    Some(Err(io::ErrorKind::ConnectionAborted)),
                    "{end:?}"
                );
                assert_eq!(
                    write_end,
                    Some(Err(io::ErrorKind::ConnectionAborted)),
                    "{end:?}"
                );
            }
        }
    }
}
