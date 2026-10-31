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
    quiet_close_loss: bool,
    drop_all_close: AtomicBool,
    physical_close_sends: AtomicUsize,
    input_before_close_retry: AtomicUsize,
    drop_first_close: AtomicBool,
    close_dropped: AtomicBool,
    target_close_count: AtomicUsize,
    last_target_close: Mutex<Option<(SessionMetadata, usize)>>,
    close_dropped_notify: tokio::sync::Notify,
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
            quiet_close_loss: false,
            drop_all_close: AtomicBool::new(false),
            physical_close_sends: AtomicUsize::new(0),
            input_before_close_retry: AtomicUsize::new(0),
            drop_first_close: AtomicBool::new(false),
            close_dropped: AtomicBool::new(false),
            target_close_count: AtomicUsize::new(0),
            last_target_close: Mutex::new(None),
            close_dropped_notify: tokio::sync::Notify::new(),
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

    async fn send_late_ack(&self, unack_sequence: u32) -> io::Result<()> {
        let key = crypto::derive_packet_key("vole", "fixture-password", super::super::tcp::now()?);
        let mut encoder = PacketEncoder::new(&key, false)?;
        let mut bytes = Vec::new();
        encoder.encode_frame(
            Metadata::Data(DataMetadata {
                kind: DataKind::ServerAck,
                session_id: self.target.load(Ordering::Acquire),
                sequence: self.server_next.load(Ordering::Acquire).saturating_sub(1),
                unack_sequence,
                window: 64,
                fragment: 0,
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

    async fn wait_close_dropped(&self) {
        while !self.close_dropped.load(Ordering::Acquire) {
            self.close_dropped_notify.notified().await;
        }
    }

    fn is_target(&self, id: u32) -> bool {
        self.target.load(Ordering::Acquire) == id
    }

    fn drop_or_observe(&self, id: u32, frame: &Frame, ready: bool) -> bool {
        if !ready || !self.is_target(id) {
            return false;
        }
        if let Metadata::Session(meta) = frame.metadata {
            if meta.kind == SessionKind::CloseRequest {
                self.target_close_count.fetch_add(1, Ordering::AcqRel);
                *self.last_target_close.lock().unwrap() = Some((meta, frame.payload.len()));
                if self.drop_first_close.swap(false, Ordering::AcqRel)
                    || self.drop_all_close.load(Ordering::Acquire)
                {
                    if self.quiet_close_loss {
                        self.hold_ack.store(true, Ordering::Release);
                    }
                    self.close_dropped.store(true, Ordering::Release);
                    self.close_dropped_notify.notify_one();
                    return true;
                }
            }
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
    upload_harness(true).await
}

async fn upload_harness(drop_tail: bool) -> UploadHarness {
    upload_harness_with_quiet_close_loss(drop_tail, false).await
}

async fn upload_harness_with_quiet_close_loss(drop_tail: bool, quiet: bool) -> UploadHarness {
    let (origin_writer, mut origin) = tokio::io::duplex(4096);
    let mut fixture = UploadFixture::new(origin_writer);
    fixture.quiet_close_loss = quiet;
    let fixture = Arc::new(fixture);
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
    fixture.arm.store(drop_tail, Ordering::Release);
    stream.write_all(UPLOAD_TAIL).await.unwrap();
    if drop_tail {
        // The client first-send receipt succeeded, but the peer did not admit the tail.
        fixture.wait_dropped().await;
    }
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

// Both controls exercise the actual client, packet codecs, physical memory carrier,
// and origin socket. No cleanup-induced EOF is credited as business progress.
async fn close_loss_recovers_via_late_ack(with_sibling: bool) {
    const LATE_ACK: u32 = 0x1357_2468;
    let probe = ResourceProbe::default();
    let outcome = probe
        .scope(async {
            let mut h = upload_harness(false).await;
            let mut sibling: Option<crate::dispatch::BoxStream> = None;
            let result: io::Result<_> = async {
                if with_sibling {
                    let raw = h.node.client.attach_tcp_stream_for_test()?;
                    let session = super::super::tests::session();
                    let context = EstablishContext::with_timeout(Duration::from_secs(5));
                    sibling = Some(Box::new(
                        super::super::stream::Stream::standard(
                            raw,
                            &session.destination,
                            crate::socks5::COMMAND_CONNECT,
                            context.deadline(),
                        )
                        .await?,
                    ));
                }
                let expected_opens = if with_sibling { 2 } else { 1 };
                if h.fixture.physical_opens.load(Ordering::Acquire) != 1
                    || h.peer.opens.load(Ordering::Acquire) != expected_opens
                {
                    return Err(io::Error::other(
                        "Close-loss controls did not share one physical carrier",
                    ));
                }
                h.fixture.drop_first_close.store(true, Ordering::Release);
                h.stream.shutdown().await?;
                tokio::time::timeout(Duration::from_secs(5), h.fixture.wait_close_dropped())
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
                if h.fixture.target_close_count.load(Ordering::Acquire) != 1
                    || h.fixture.closed.load(Ordering::Acquire)
                {
                    return Err(io::Error::other(
                        "first real Close was not uniquely dropped before origin close",
                    ));
                }
                h.fixture.send_late_ack(LATE_ACK).await?;
                let mut actual = h.prefix.clone();
                tokio::time::timeout(Duration::from_secs(5), h.origin.read_to_end(&mut actual))
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
                let observed = *h.fixture.last_target_close.lock().unwrap();
                Ok((
                    actual,
                    observed,
                    h.fixture.target_close_count.load(Ordering::Acquire),
                    h.fixture.target.load(Ordering::Acquire),
                    h.fixture.closed.load(Ordering::Acquire),
                    h.fixture.physical_opens.load(Ordering::Acquire),
                    h.peer.opens.load(Ordering::Acquire),
                ))
            }
            .await;
            drop(sibling);
            h.stop().await;
            result
        })
        .await;
    assert!(
        probe.snapshot().is_idle(),
        "RED and GREEN must both join and release before assertions"
    );
    let (actual, observed, count, id, closed, physical_opens, opens) =
        outcome.expect("late ACK did not reach the existing unknown-SID Close path before cleanup");
    let mut expected = UPLOAD_PREFIX.to_vec();
    expected.extend_from_slice(UPLOAD_TAIL);
    assert_eq!(actual, expected);
    assert_eq!(
        <sha2::Sha256 as sha2::Digest>::digest(&actual),
        <sha2::Sha256 as sha2::Digest>::digest(&expected)
    );
    assert_eq!(
        observed,
        Some((
            SessionMetadata {
                kind: SessionKind::CloseRequest,
                session_id: id,
                sequence: LATE_ACK,
                status: 0,
            },
            0
        ))
    );
    assert_eq!(
        count, 2,
        "only the injected late ACK should cause the second Close"
    );
    assert!(
        closed,
        "origin EOF must follow actual peer Close handling, before Stop"
    );
    assert_eq!(physical_opens, 1);
    assert_eq!(opens, if with_sibling { 2 } else { 1 });
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_closed_last_sid_accepts_late_ack_after_first_close_loss() {
    close_loss_recovers_via_late_ack(false).await;
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_closed_sid_with_live_sibling_accepts_late_ack_after_first_close_loss() {
    close_loss_recovers_via_late_ack(true).await;
}

// A real Close loss must recover without any incoming DATA/ACK trigger.
#[tokio::test(start_paused = true)]
async fn mieru_udp_first_close_loss_recovers_with_silent_peer_before_origin_eof() {
    let probe = ResourceProbe::default();
    let outcome = probe
        .scope(async {
            let mut h = upload_harness_with_quiet_close_loss(false, true).await;
            let result: io::Result<_> = async {
                h.fixture.drop_first_close.store(true, Ordering::Release);
                tokio::time::timeout(Duration::from_secs(5), h.stream.shutdown())
                    .await
                    .map_err(|_| io::Error::other("setup: DATA ACK drain did not complete"))??;
                tokio::time::timeout(Duration::from_secs(5), h.fixture.wait_close_dropped())
                    .await
                    .map_err(|_| io::Error::other("setup: first real Close was not dropped"))?;
                if h.fixture.physical_close_sends.load(Ordering::Acquire) == 0 {
                    return Err(io::Error::other(
                        "setup: Close transport never returned Ready-OK",
                    ));
                }
                let mut actual = h.prefix.clone();
                let read =
                    tokio::time::timeout(Duration::from_secs(5), h.origin.read_to_end(&mut actual))
                        .await;
                // Snapshot before Stop: cleanup EOF cannot satisfy the assertion.
                Ok((
                    read,
                    actual,
                    h.fixture.physical_close_sends.load(Ordering::Acquire),
                    h.fixture.target_close_count.load(Ordering::Acquire),
                    h.fixture.input_before_close_retry.load(Ordering::Acquire),
                    h.fixture.closed.load(Ordering::Acquire),
                    h.fixture.physical_opens.load(Ordering::Acquire),
                    h.peer.opens.load(Ordering::Acquire),
                ))
            }
            .await;
            h.stop().await;
            result
        })
        .await;
    assert!(
        probe.snapshot().is_idle(),
        "cleanup must complete before RED/GREEN assertions"
    );
    let (read, actual, sends, peer_closes, input, closed, physical_opens, opens) =
        outcome.expect("invalid fixture/setup; not the intended Close-loss RED");
    let mut expected = UPLOAD_PREFIX.to_vec();
    expected.extend_from_slice(UPLOAD_TAIL);
    assert_eq!(actual, expected);
    assert_eq!(
        <sha2::Sha256 as sha2::Digest>::digest(&actual),
        <sha2::Sha256 as sha2::Digest>::digest(&expected)
    );
    assert_eq!(
        input, 0,
        "a later peer packet supplied an opportunistic Close trigger"
    );
    assert_eq!((physical_opens, opens), (1, 1));
    assert!(
        read.as_ref().is_ok_and(|r| r.is_ok()),
        "no normal origin EOF before the original 5s guard: {read:?}; Close Ready-OK={sends}, peer Close={peer_closes}, input before retry={input}"
    );
    assert!(
        sends >= 2 && peer_closes >= 2,
        "EOF did not follow a real repeated Close"
    );
    assert!(
        closed,
        "origin was not closed by the original peer Close handler before Stop"
    );
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_close_retry_without_response_stops_after_two_timer_resends() {
    let probe = ResourceProbe::default();
    let outcome = probe
        .scope(async {
            let mut h = upload_harness_with_quiet_close_loss(false, true).await;
            let result: io::Result<_> = async {
                h.fixture.drop_all_close.store(true, Ordering::Release);
                let mut actual = h.prefix.clone();
                let mut tail = [0; UPLOAD_TAIL.len()];
                tokio::time::timeout(Duration::from_secs(5), h.origin.read_exact(&mut tail))
                    .await
                    .map_err(|_| {
                        io::Error::other("setup: origin did not receive the DATA tail")
                    })??;
                actual.extend_from_slice(&tail);
                tokio::time::timeout(Duration::from_secs(5), h.stream.shutdown())
                    .await
                    .map_err(|_| io::Error::other("setup: DATA ACK drain did not complete"))??;
                tokio::time::timeout(Duration::from_secs(5), h.fixture.wait_close_dropped())
                    .await
                    .map_err(|_| io::Error::other("setup: no actual first Close drop"))?;
                let first = *h.fixture.last_target_close.lock().unwrap();
                let third = tokio::time::timeout(Duration::from_secs(5), async {
                    while h.fixture.target_close_count.load(Ordering::Acquire) < 3 {
                        h.fixture.close_dropped_notify.notified().await;
                    }
                })
                .await;
                // A second full fixture guard is an observation horizon, not a retry constant.
                tokio::time::advance(Duration::from_secs(5)).await;
                for _ in 0..16 {
                    tokio::task::yield_now().await;
                }
                let mut byte = [0];
                let origin_pending = h.origin.read(&mut byte).now_or_never().is_none();
                Ok((
                    third.is_ok(),
                    actual,
                    h.fixture.physical_close_sends.load(Ordering::Acquire),
                    h.fixture.target_close_count.load(Ordering::Acquire),
                    h.fixture.input_before_close_retry.load(Ordering::Acquire),
                    origin_pending,
                    h.fixture.closed.load(Ordering::Acquire),
                    first,
                    *h.fixture.last_target_close.lock().unwrap(),
                ))
            }
            .await;
            h.stop().await;
            result
        })
        .await;
    assert!(probe.snapshot().is_idle());
    let (third, actual, sends, seen, input, pending, closed, first, last) = outcome.unwrap();
    let mut expected = UPLOAD_PREFIX.to_vec();
    expected.extend_from_slice(UPLOAD_TAIL);
    assert_eq!(actual, expected);
    assert_eq!(
        <sha2::Sha256 as sha2::Digest>::digest(&actual),
        <sha2::Sha256 as sha2::Digest>::digest(&expected)
    );
    assert!(
        third,
        "two timer resends did not reach the real peer decoder"
    );
    assert_eq!(
        (sends, seen),
        (3, 3),
        "original Close plus exactly two timer resends"
    );
    assert_eq!(
        input, 0,
        "a peer packet supplied an opportunistic resend trigger"
    );
    assert!(
        pending && !closed,
        "all Closes were dropped; Stop must not supply business EOF"
    );
    assert!(first.is_some());
    assert_eq!(
        first, last,
        "retry changed the original Close metadata or payload length"
    );
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_close_retry_active_stop_releases_driver_and_peer_owners() {
    let probe = ResourceProbe::default();
    let outcome = probe
        .scope(async {
            let mut h = upload_harness_with_quiet_close_loss(false, true).await;
            let fixture = Arc::downgrade(&h.fixture);
            let peer = Arc::downgrade(&h.peer);
            let result: io::Result<_> = async {
                h.fixture.drop_all_close.store(true, Ordering::Release);
                tokio::time::timeout(Duration::from_secs(5), h.stream.shutdown())
                    .await
                    .map_err(|_| io::Error::other("setup: DATA ACK drain did not complete"))??;
                tokio::time::timeout(Duration::from_secs(5), h.fixture.wait_close_dropped())
                    .await
                    .map_err(|_| io::Error::other("setup: no actual first Close drop"))?;
                let before = (
                    h.fixture.physical_close_sends.load(Ordering::Acquire),
                    h.fixture.target_close_count.load(Ordering::Acquire),
                );
                let start = Instant::now();
                let stopped = tokio::time::timeout(Duration::from_secs(1), h.node.shutdown()).await;
                let elapsed = Instant::now().saturating_duration_since(start);
                Ok((
                    before,
                    stopped.is_ok(),
                    elapsed,
                    h.fixture.physical_close_sends.load(Ordering::Acquire),
                    h.fixture.target_close_count.load(Ordering::Acquire),
                    h.fixture.input_before_close_retry.load(Ordering::Acquire),
                    h.fixture.closed.load(Ordering::Acquire),
                ))
            }
            .await;
            h.stop().await;
            (
                result,
                fixture.upgrade().is_none(),
                peer.upgrade().is_none(),
            )
        })
        .await;
    assert!(probe.snapshot().is_idle());
    let (result, fixture_gone, peer_gone) = outcome;
    let (before, stopped, elapsed, sends, seen, input, closed) = result.unwrap();
    assert_eq!(
        before,
        (1, 1),
        "Stop did not begin with an active retry obligation"
    );
    assert!(stopped, "active Stop did not join the physical driver");
    assert_eq!(
        elapsed,
        Duration::ZERO,
        "paused-clock Stop waited for a retry timer"
    );
    assert_eq!((sends, seen, input), (1, 1, 0));
    assert!(
        !closed,
        "peer logical Close was not allowed in this all-loss control"
    );
    assert!(
        fixture_gone && peer_gone,
        "driver/peer retained fixture ownership after Stop/drop"
    );
}
