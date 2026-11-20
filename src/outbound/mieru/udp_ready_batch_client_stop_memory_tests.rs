// Included only in the existing udp::tests module on macOS. Peer/Memory/serve
// remain the actual real-client factory; no production seam is replaced.
struct ReadyBatchStopGate {
    armed: AtomicBool,
    entered: AtomicUsize,
    active: AtomicUsize,
    retained_bytes: AtomicUsize,
    dropped: AtomicUsize,
    submitted: AtomicUsize,
    authenticated_data: AtomicUsize,
    invalid: AtomicBool,
    closes: AtomicUsize,
    close_with_owner: AtomicBool,
    memory_joined: AtomicUsize,
    entered_notify: tokio::sync::Notify,
    decoder: Mutex<PacketDecoder>,
}
impl ReadyBatchStopGate {
    fn new() -> Arc<Self> {
        let key = crypto::derive_packet_key(
            "vole", "fixture-password", super::super::tcp::now().unwrap(),
        );
        Arc::new(Self {
            armed: AtomicBool::new(false), entered: AtomicUsize::new(0),
            active: AtomicUsize::new(0), retained_bytes: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0), submitted: AtomicUsize::new(0),
            authenticated_data: AtomicUsize::new(0), invalid: AtomicBool::new(false),
            closes: AtomicUsize::new(0), close_with_owner: AtomicBool::new(false),
            memory_joined: AtomicUsize::new(0), entered_notify: tokio::sync::Notify::new(),
            decoder: Mutex::new(PacketDecoder::new(&key, true).unwrap()),
        })
    }
    fn send_owned(
        self: &Arc<Self>,
        packets: Vec<Datagram>,
    ) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
        if !self.armed.load(Ordering::Acquire) {
            return Err(packets);
        }
        if crate::dispatch::datagram_batch_peer(&packets).is_none() {
            self.invalid.store(true, Ordering::Release);
            return Err(packets);
        }
        let bytes = packets.iter().map(|packet| packet.payload.len()).sum();
        self.active.fetch_add(1, Ordering::AcqRel);
        self.retained_bytes.fetch_add(bytes, Ordering::AcqRel);
        let held = ReadyBatchStopOwned { packets, bytes, gate: self.clone() };
        Ok(Box::pin(async move {
            // Authentication observes attempted DATA preparation, not physical
            // acceptance. The controlled physical future never returns Ready.
            let mut sid = None;
            let mut authenticated = 0;
            for packet in &held.packets {
                let decoded = super::super::tcp::now().and_then(|now| {
                    held.gate.decoder.lock().unwrap().decode_frame(packet.payload.clone(), now)
                });
                match decoded {
                    Ok(Frame { metadata: Metadata::Data(meta), .. })
                        if meta.kind == DataKind::ClientData
                            && sid.is_none_or(|sid| sid == meta.session_id) =>
                    {
                        sid = Some(meta.session_id);
                        authenticated += 1;
                    }
                    _ => held.gate.invalid.store(true, Ordering::Release),
                }
            }
            held.gate.submitted.store(held.packets.len(), Ordering::Release);
            held.gate.authenticated_data.store(authenticated, Ordering::Release);
            held.gate.entered.fetch_add(1, Ordering::AcqRel);
            held.gate.entered_notify.notify_one();
            let result = std::future::pending::<io::Result<usize>>().await;
            drop(held);
            result
        }))
    }
    async fn wait_entered(&self) {
        loop {
            let notified = self.entered_notify.notified();
            if self.entered.load(Ordering::Acquire) != 0 {
                return;
            }
            notified.await;
        }
    }
}
struct ReadyBatchStopOwned {
    packets: Vec<Datagram>,
    bytes: usize,
    gate: Arc<ReadyBatchStopGate>,
}
impl Drop for ReadyBatchStopOwned {
    fn drop(&mut self) {
        self.gate.retained_bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.gate.active.fetch_sub(1, Ordering::AcqRel);
        self.gate.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_pattern_ready_batch_real_client_stop_joins_active_owned_send() {
    for polled in [false, true] {
        let probe = ResourceProbe::default();
        let outcome = probe.scope(async {
            let gate = ReadyBatchStopGate::new();
            let weak_gate = Arc::downgrade(&gate);
            let mut peer = Peer::new(false, false);
            {
                let exclusive = Arc::get_mut(&mut peer).unwrap();
                exclusive.polled_receive = polled;
                exclusive.ready_batch_stop_gate = Some(gate.clone());
            }
            let weak_peer = Arc::downgrade(&peer);
            let mut configuration = config();
            configuration.handshake_mode = crate::config::MieruHandshake::Standard;
            configuration.traffic_pattern = Some(
                "CAAaBAgAEAAiEAgDEAEYACAAKgZhYWJiY2MqBAgAEAAyBAgBEAA=".into(),
            );
            let node = super::super::MieruOutbound::new(
                &configuration, UpstreamPath::proxy(Arc::new(peer.clone())), 32768,
            ).unwrap();
            // Keep the optional gate unarmed through ordinary OPEN, real SOCKS
            // CONNECT and an authenticated business roundtrip on the same peer.
            let setup = tokio::time::timeout(Duration::from_secs(5), async {
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                let mut stream = node.connect_stream(super::super::tests::session(), &context)
                    .await.map_err(|_| closed())?.io;
                stream.write_all(b"ready").await?;
                let mut echo = [0; 5];
                stream.read_exact(&mut echo).await?;
                if &echo != b"ready" {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "warmup echo differs"));
                }
                Ok::<_, io::Error>(stream)
            }).await;
            let mut stream = match setup {
                Ok(Ok(stream)) => Some(stream),
                _ => None,
            };
            let setup_ok = stream.is_some();
            let opens_before_arm = peer.opens.load(Ordering::Acquire);
            let mut entered = false;
            let mut write_pending = false;
            let mut held_stop = false;
            let mut writer_rejected = false;
            let mut active_before_stop = 0;
            let mut bytes_before_stop = 0;
            if let Some(stream) = stream.as_mut() {
                gate.armed.store(true, Ordering::Release);
                let payload = vec![0x61; 32768];
                let mut writing = Box::pin(stream.write_all(&payload));
                // This bounded wait is a GREEN integration prerequisite, not
                // an old-source RED. Every branch rejoins owners before assert.
                let first = tokio::time::timeout(Duration::from_secs(2), async {
                    tokio::select! { biased;
                        () = gate.wait_entered() => None,
                        result = &mut writing => Some(result.is_err()),
                    }
                }).await;
                let mut early_write = match first {
                    Ok(None) => { entered = true; None }
                    Ok(Some(rejected)) => Some(rejected),
                    Err(_) => None,
                };
                if entered && early_write.is_none() {
                    // Use the actual caller Context: no noop waker, fabricated
                    // readiness or mirrored write-completion state.
                    match std::future::poll_fn(|cx| std::task::Poll::Ready(
                        std::future::Future::poll(writing.as_mut(), cx),
                    )).await {
                        std::task::Poll::Pending => write_pending = true,
                        std::task::Poll::Ready(result) => early_write = Some(result.is_err()),
                    }
                }
                active_before_stop = gate.active.load(Ordering::Acquire);
                bytes_before_stop = gate.retained_bytes.load(Ordering::Acquire);
                node.begin_shutdown();
                // Both the actual boxed Stream/RawStream and its write waiter
                // remain alive while real Client::shutdown waits its TaskTracker.
                held_stop = tokio::time::timeout(Duration::from_secs(2), node.shutdown()).await.is_ok();
                writer_rejected = if let Some(rejected) = early_write {
                    rejected
                } else {
                    matches!(tokio::time::timeout(Duration::from_secs(2), writing.as_mut()).await, Ok(Err(_)))
                };
                drop(writing);
            }
            drop(stream);
            // Even a failed bounded observation/held-stop takes this final real
            // join after releasing caller-held IO; it is never skipped by assert.
            node.begin_shutdown();
            node.shutdown().await;
            drop(node);
            peer.stop().await;
            let peer_joined = peer.tasks.is_empty();
            let receipt = (
                gate.entered.load(Ordering::Acquire), gate.dropped.load(Ordering::Acquire),
                gate.active.load(Ordering::Acquire), gate.retained_bytes.load(Ordering::Acquire),
                gate.submitted.load(Ordering::Acquire), gate.authenticated_data.load(Ordering::Acquire),
                gate.invalid.load(Ordering::Acquire), gate.closes.load(Ordering::Acquire),
                gate.close_with_owner.load(Ordering::Acquire), gate.memory_joined.load(Ordering::Acquire),
            );
            drop((peer, gate));
            (setup_ok, opens_before_arm, entered, write_pending, held_stop, writer_rejected,
                active_before_stop, bytes_before_stop, peer_joined, receipt, weak_peer, weak_gate)
        }).await;
        // All assertions follow real node/peer joins and owner release.
        assert!(probe.snapshot().is_idle());
        let (setup_ok, opens, entered, pending, stopped, rejected, active, bytes,
            peer_joined, receipt, weak_peer, weak_gate) = outcome;
        assert!(weak_peer.upgrade().is_none() && weak_gate.upgrade().is_none());
        assert!(setup_ok && opens > 0 && peer_joined);
        assert!(entered && pending && stopped && rejected);
        assert_eq!(active, 1);
        assert!(bytes > 0);
        let (entered, dropped, active, bytes, submitted, authenticated, invalid, closes, close_with_owner, joined) = receipt;
        assert_eq!((entered, dropped, active, bytes), (1, 1, 0, 0));
        assert!((2..=4).contains(&submitted));
        assert_eq!(authenticated, submitted);
        assert!(!invalid && !close_with_owner);
        assert_eq!((closes, joined), (1, 1));
    }
}
