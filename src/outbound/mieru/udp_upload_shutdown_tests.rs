// Real client/codec/driver feedback; no application bytes are credited by a model.
const UPLOAD_PREFIX: &[u8] = &[0x21; 256];
const UPLOAD_TAIL: &[u8] = &[0x5a; 32];

struct UploadFixture {
    target: std::sync::atomic::AtomicU32,
    arm: AtomicBool,
    dropped: AtomicBool,
    dropped_sequence: std::sync::atomic::AtomicU32,
    retried: AtomicBool,
    closed: AtomicBool,
    close_before_retry: AtomicBool,
    physical_opens: AtomicUsize,
    hold_ack: AtomicBool,
    outgoing: Mutex<Option<mpsc::Sender<Datagram>>>,
    remote: Mutex<Option<Destination>>,
    server_next: std::sync::atomic::AtomicU32,
    dropped_notify: tokio::sync::Notify,
    origin: tokio::sync::Mutex<Option<tokio::io::DuplexStream>>,
}

impl UploadFixture {
    fn new(origin: tokio::io::DuplexStream) -> Self {
        Self {
            target: std::sync::atomic::AtomicU32::new(0),
            arm: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            dropped_sequence: std::sync::atomic::AtomicU32::new(u32::MAX),
            retried: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            close_before_retry: AtomicBool::new(false),
            physical_opens: AtomicUsize::new(0),
            hold_ack: AtomicBool::new(false),
            outgoing: Mutex::new(None),
            remote: Mutex::new(None),
            server_next: std::sync::atomic::AtomicU32::new(0),
            dropped_notify: tokio::sync::Notify::new(),
            origin: tokio::sync::Mutex::new(Some(origin)),
        }
    }

    fn select(&self, id: u32, remote: &Destination) {
        if self
            .target
            .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            *self.remote.lock().unwrap() = Some(remote.clone());
        }
    }

    fn observe_server(&self, metadata: Metadata) {
        if self.is_target(session_id(metadata)) {
            self.server_next
                .fetch_max(sequence(metadata).saturating_add(1), Ordering::AcqRel);
        }
    }

    fn withholds(&self, metadata: Metadata) -> bool {
        self.hold_ack.load(Ordering::Acquire)
            && self.is_target(session_id(metadata))
            && matches!(metadata, Metadata::Data(_))
    }

    async fn send_remote_close(&self) -> io::Result<()> {
        let key = crypto::derive_packet_key("vole", "fixture-password", super::super::tcp::now()?);
        let mut encoder = PacketEncoder::new(&key, false)?;
        let mut bytes = Vec::new();
        encoder.encode_frame(
            Metadata::Session(SessionMetadata {
                kind: SessionKind::CloseRequest,
                session_id: self.target.load(Ordering::Acquire),
                sequence: self.server_next.load(Ordering::Acquire),
                status: 0,
            }),
            &[],
            Padding {
                prefix: &[],
                suffix: &[],
            },
            rand::random(),
            super::super::tcp::now()?,
            &mut bytes,
        )?;
        let sender = self.outgoing.lock().unwrap().clone().ok_or_else(closed)?;
        let remote = self.remote.lock().unwrap().clone().ok_or_else(closed)?;
        sender
            .send(Datagram {
                remote,
                payload: bytes.into(),
                sniffed_domain: None,
            })
            .await
            .map_err(|_| closed())
    }

    fn is_target(&self, id: u32) -> bool {
        self.target.load(Ordering::Acquire) == id
    }

    fn drop_or_observe(&self, id: u32, frame: &Frame, ready: bool) -> bool {
        if !ready || !self.is_target(id) {
            return false;
        }
        let Metadata::Data(meta) = frame.metadata else {
            return false;
        };
        if meta.kind != DataKind::ClientData || frame.payload.is_empty() {
            return false;
        }
        if self.arm.swap(false, Ordering::AcqRel) {
            self.dropped_sequence
                .store(meta.sequence, Ordering::Release);
            self.dropped.store(true, Ordering::Release);
            self.dropped_notify.notify_one();
            return true;
        }
        if self.dropped.load(Ordering::Acquire)
            && meta.sequence == self.dropped_sequence.load(Ordering::Acquire)
        {
            self.retried.store(true, Ordering::Release);
        }
        false
    }

    async fn wait_dropped(&self) {
        while !self.dropped.load(Ordering::Acquire) {
            self.dropped_notify.notified().await;
        }
    }

    async fn write_origin(&self, bytes: &[u8]) -> io::Result<()> {
        self.origin
            .lock()
            .await
            .as_mut()
            .ok_or_else(closed)?
            .write_all(bytes)
            .await
    }

    async fn close_origin(&self, id: u32) {
        if self.is_target(id) {
            self.close_before_retry
                .store(!self.retried.load(Ordering::Acquire), Ordering::Release);
            self.closed.store(true, Ordering::Release);
            let writer = self.origin.lock().await.take();
            drop(writer);
        }
    }
}

struct UploadHarness {
    node: super::super::MieruOutbound,
    peer: Arc<Peer>,
    fixture: Arc<UploadFixture>,
    origin: tokio::io::DuplexStream,
    stream: crate::dispatch::BoxStream,
    prefix: Vec<u8>,
}

impl UploadHarness {
    async fn stop(self) {
        drop(self.stream);
        self.node.shutdown().await;
        self.peer.stop().await;
    }
}

async fn faulted_upload() -> UploadHarness {
    let (origin_writer, mut origin) = tokio::io::duplex(4096);
    let fixture = Arc::new(UploadFixture::new(origin_writer));
    let mut peer = Peer::new(false, false);
    Arc::get_mut(&mut peer).unwrap().upload = Some(fixture.clone());
    let mut settings = config();
    settings.handshake_mode = crate::config::MieruHandshake::Standard;
    settings.multiplexing = crate::config::MieruMultiplexing::Low;
    settings.traffic_pattern = Some("CAAaBAgAEAAiEAgDEAEYACAAKgZhYWJiY2MqBAgAEAAyBAgBEAA=".into());
    let node = super::super::MieruOutbound::new(
        &settings,
        UpstreamPath::proxy(Arc::new(peer.clone())),
        32768,
    )
    .unwrap();
    let context = EstablishContext::with_timeout(Duration::from_secs(5));
    let mut stream = node
        .connect_stream(super::super::tests::session(), &context)
        .await
        .unwrap()
        .io;
    stream.write_all(UPLOAD_PREFIX).await.unwrap();
    let mut prefix = vec![0; UPLOAD_PREFIX.len()];
    origin.read_exact(&mut prefix).await.unwrap();
    assert_eq!(prefix, UPLOAD_PREFIX);
    fixture.arm.store(true, Ordering::Release);
    stream.write_all(UPLOAD_TAIL).await.unwrap();
    // The client first-send receipt succeeded, but the peer did not admit the tail.
    fixture.wait_dropped().await;
    UploadHarness {
        node,
        peer,
        fixture,
        origin,
        stream,
        prefix,
    }
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_upload_shutdown_delivers_a_successfully_sent_but_lost_tail_before_eof() {
    let probe = ResourceProbe::default();
    let (actual, dropped, retried, closed, close_before_retry, physical_opens) = probe
        .scope(async {
            let mut h = faulted_upload().await;
            h.stream.shutdown().await.unwrap();
            let mut tail = Vec::new();
            h.origin.read_to_end(&mut tail).await.unwrap();
            let mut actual = h.prefix.clone();
            actual.extend_from_slice(&tail);
            let result = (
                actual,
                h.fixture.dropped.load(Ordering::Acquire),
                h.fixture.retried.load(Ordering::Acquire),
                h.fixture.closed.load(Ordering::Acquire),
                h.fixture.close_before_retry.load(Ordering::Acquire),
                h.fixture.physical_opens.load(Ordering::Acquire),
            );
            h.stop().await;
            result
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(
        dropped && closed && physical_opens == 1,
        "required real-wire loss/close condition was absent"
    );
    let mut expected = UPLOAD_PREFIX.to_vec();
    expected.extend_from_slice(UPLOAD_TAIL);
    assert_eq!(
        actual, expected,
        "origin received EOF before the accepted upload tail"
    );
    assert!(
        retried && !close_before_retry,
        "close overtook the tail's reliable retry"
    );
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_upload_pending_ack_shutdown_does_not_delay_active_stop() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut h = faulted_upload().await;
            h.fixture.hold_ack.store(true, Ordering::Release);
            {
                let mut shutting_down = Box::pin(h.stream.shutdown());
                assert!(shutting_down.as_mut().now_or_never().is_none());
                h.node.shutdown().await;
                assert!(shutting_down.await.is_err());
            }
            h.stop().await;
        })
        .await;
    assert!(probe.snapshot().is_idle());
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_upload_cancelled_shutdown_keeps_same_carrier_sibling_live() {
    let probe = ResourceProbe::default();
    let (actual, physical_opens) = probe
        .scope(async {
            let mut h = faulted_upload().await;
            h.fixture.hold_ack.store(true, Ordering::Release);
            let raw = h.node.client.attach_tcp_stream_for_test().unwrap();
            let session = super::super::tests::session();
            let context = EstablishContext::with_timeout(Duration::from_secs(5));
            let mut sibling: crate::dispatch::BoxStream = Box::new(
                super::super::stream::Stream::standard(
                    raw,
                    &session.destination,
                    crate::socks5::COMMAND_CONNECT,
                    context.deadline(),
                )
                .await
                .unwrap(),
            );
            assert_eq!(h.fixture.physical_opens.load(Ordering::Acquire), 1);
            assert_eq!(h.peer.opens.load(Ordering::Acquire), 2);
            {
                let mut shutting_down = Box::pin(h.stream.shutdown());
                assert!(shutting_down.as_mut().now_or_never().is_none());
                // A live ACK waiter must not reserve the carrier's sibling credit.
                super::super::tests::echo(&mut sibling, b"sibling while ACK wait is pending").await;
                assert!(shutting_down.as_mut().now_or_never().is_none());
                // Dropping only this future must not close/replay the underlying stream.
                drop(shutting_down);
            }
            assert!(!h.fixture.closed.load(Ordering::Acquire));
            super::super::tests::echo(&mut sibling, b"same physical carrier remains live").await;
            h.fixture.hold_ack.store(false, Ordering::Release);
            h.stream.shutdown().await.unwrap();
            let mut actual = h.prefix.clone();
            h.origin.read_to_end(&mut actual).await.unwrap();
            let physical_opens = h.fixture.physical_opens.load(Ordering::Acquire);
            drop(sibling);
            h.stop().await;
            (actual, physical_opens)
        })
        .await;
    assert!(probe.snapshot().is_idle());
    let mut expected = UPLOAD_PREFIX.to_vec();
    expected.extend_from_slice(UPLOAD_TAIL);
    assert_eq!(
        actual, expected,
        "cancelled shutdown replayed or lost application data"
    );
    assert_eq!(physical_opens, 1);
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_upload_drop_keeps_immediate_close_without_waiting_for_ack() {
    let probe = ResourceProbe::default();
    let (actual, close_before_retry) = probe
        .scope(async {
            let mut h = faulted_upload().await;
            h.fixture.hold_ack.store(true, Ordering::Release);
            {
                let mut shutting_down = Box::pin(h.stream.shutdown());
                assert!(shutting_down.as_mut().now_or_never().is_none());
            }
            let UploadHarness {
                node,
                peer,
                fixture,
                mut origin,
                stream,
                mut prefix,
            } = h;
            drop(stream);
            origin.read_to_end(&mut prefix).await.unwrap();
            let close_before_retry = fixture.close_before_retry.load(Ordering::Acquire);
            node.shutdown().await;
            peer.stop().await;
            (prefix, close_before_retry)
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert_eq!(
        actual, UPLOAD_PREFIX,
        "Drop unexpectedly waited to retry the missing tail"
    );
    assert!(close_before_retry, "Drop was delayed behind ACK drain");
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_upload_peer_close_releases_ack_wait_with_original_close_result() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut h = faulted_upload().await;
            h.fixture.hold_ack.store(true, Ordering::Release);
            {
                let mut shutting_down = Box::pin(h.stream.shutdown());
                assert!(shutting_down.as_mut().now_or_never().is_none());
                h.fixture.send_remote_close().await.unwrap();
                // TX_LIMIT failure is not evidence that our Close was processed.
                h.peer.close_replied.notified().await;
                let result = shutting_down.await;
                assert!(
                    result.is_ok()
                        || result
                            .as_ref()
                            .is_err_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
                );
            }
            h.stop().await;
        })
        .await;
    assert!(probe.snapshot().is_idle());
}
