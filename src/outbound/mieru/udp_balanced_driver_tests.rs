#[cfg(test)]
mod balanced_driver_tests {
    use super::*;
    use crate::{dispatch::DispatchError, resources::observation::ResourceProbe};
    use async_trait::async_trait;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::Semaphore;

    const WRITES: usize = 12;
    const READS: usize = 16;
    const TX_CREDIT: usize = 64;
    const RX_CREDIT: usize = 32768;
    fn failed(message: &'static str) -> io::Error {
        io::Error::other(message)
    }

    #[derive(Default)]
    struct Control {
        started: AtomicBool,
        tx: AtomicUsize,
        rx: AtomicUsize,
        invalid: AtomicUsize,
        first_rx: AtomicUsize,
        first_data_rx: AtomicUsize,
        receive_calls: AtomicUsize,
        allow_send: AtomicBool,
        close_requests: AtomicUsize,
        queued: Mutex<VecDeque<WriterCommand>>,
        sent: Mutex<Vec<(u32, Bytes)>>,
    }
    struct Packets {
        incoming: mpsc::Receiver<Datagram>,
        inject: mpsc::Sender<Datagram>,
        commands: mpsc::Sender<WriterCommand>,
        control: Arc<Control>,
        encoder: PacketEncoder,
        decoder: PacketDecoder,
        peer: Destination,
        invalid_first: bool,
        ready_invalid: Option<Datagram>,
        invalid_remaining: usize,
    }
    impl Packets {
        fn inject(&mut self, metadata: Metadata, payload: &[u8]) -> Result<(), DispatchError> {
            let mut encoded = Vec::new();
            self.encoder
                .encode_frame(
                    metadata,
                    payload,
                    super::super::wire::Padding {
                        prefix: &[],
                        suffix: &[],
                    },
                    rand::random(),
                    super::super::tcp::now().unwrap(),
                    &mut encoded,
                )
                .map_err(|_| DispatchError::NotAllowed)?;
            self.inject
                .try_send(Datagram {
                    remote: self.peer.clone(),
                    payload: Bytes::from(encoded),
                    sniffed_domain: None,
                })
                .map_err(|_| DispatchError::NotAllowed)
        }
        fn feed_next(&self) -> Result<(), DispatchError> {
            let command = self.control.queued.lock().unwrap().pop_front();
            if let Some(command) = command {
                self.commands
                    .try_send(command)
                    .map_err(|_| DispatchError::NotAllowed)?;
            }
            Ok(())
        }
    }
    #[async_trait]
    impl DatagramTransport for Packets {
        fn supports_shared_destinations(&self) -> bool {
            false
        }

        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            if self.ready_invalid.is_some() {
                std::future::poll_fn(|_| {
                    if self.control.allow_send.load(Ordering::Acquire) {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
            }
            let frame = self
                .decoder
                .decode_frame(packet.payload, super::super::tcp::now().unwrap())
                .map_err(|_| DispatchError::NotAllowed)?;
            if self.ready_invalid.is_some() {
                match frame.metadata {
                    Metadata::Session(meta) if meta.kind == SessionKind::OpenRequest => {
                        self.control
                            .sent
                            .lock()
                            .unwrap()
                            .push((meta.sequence, frame.payload));
                        self.control.started.store(true, Ordering::Release);
                    }
                    Metadata::Session(meta) if meta.kind == SessionKind::CloseRequest => {
                        self.control.close_requests.fetch_add(1, Ordering::AcqRel);
                    }
                    _ => {}
                }
                self.control.tx.fetch_add(1, Ordering::AcqRel);
                return Ok(()); // No fake OPEN response or ACK is synthesized.
            }
            if let Metadata::Session(meta) = frame.metadata {
                if meta.kind == SessionKind::OpenRequest {
                    self.inject(
                        Metadata::Session(SessionMetadata {
                            kind: SessionKind::OpenResponse,
                            session_id: meta.session_id,
                            sequence: 0,
                            status: 0,
                        }),
                        &[],
                    )?;
                    self.inject(
                        Metadata::Data(DataMetadata {
                            kind: DataKind::ServerAck,
                            session_id: meta.session_id,
                            sequence: 0,
                            unack_sequence: 1,
                            window: 64,
                            fragment: 0,
                        }),
                        &[],
                    )?;
                }
            }
            if matches!(frame.metadata, Metadata::Data(m) if m.kind == DataKind::ClientAck)
                && !self.control.started.swap(true, Ordering::AcqRel)
            {
                // Supply both competitors at one real physical-send boundary.
                self.control.tx.store(0, Ordering::Release);
                if self.invalid_first {
                    for sequence in 100..100 + READS as u32 {
                        self.inject(
                            Metadata::Data(DataMetadata {
                                kind: DataKind::ClientData,
                                session_id: 1,
                                sequence,
                                unack_sequence: 1,
                                window: 64,
                                fragment: 0,
                            }),
                            b"x",
                        )?;
                    }
                }
                for sequence in 1..=READS as u32 {
                    self.inject(
                        Metadata::Data(DataMetadata {
                            kind: DataKind::ServerData,
                            session_id: 1,
                            sequence,
                            unack_sequence: 1,
                            window: 64,
                            fragment: 0,
                        }),
                        &[sequence as u8],
                    )?;
                }
                self.feed_next()?;
            } else if let Metadata::Data(meta) = frame.metadata {
                if meta.kind == DataKind::ClientData {
                    let received = if self.invalid_first {
                        &self.control.invalid
                    } else {
                        &self.control.rx
                    };
                    let _ = self.control.first_data_rx.compare_exchange(
                        usize::MAX,
                        received.load(Ordering::Acquire),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    self.control
                        .sent
                        .lock()
                        .unwrap()
                        .push((meta.sequence, frame.payload));
                    // Refill the real size-two command FIFO only after successful DATA.
                    self.feed_next()?;
                }
            }
            if self.control.started.load(Ordering::Acquire) {
                self.control.tx.fetch_add(1, Ordering::AcqRel);
            }
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.control.receive_calls.fetch_add(1, Ordering::AcqRel);
            if let Some(packet) = &self.ready_invalid {
                if self.control.started.load(Ordering::Acquire) && self.invalid_remaining != 0 {
                    self.invalid_remaining -= 1;
                    self.control.invalid.fetch_add(1, Ordering::AcqRel);
                    return Ok(packet.clone()); // Reuse one encoded Bytes; no fixture per-packet allocation.
                }
                return std::future::pending().await;
            }
            let packet = self
                .incoming
                .recv()
                .await
                .ok_or(DispatchError::NotAllowed)?;
            if let Ok(frame) = self
                .decoder
                .decode_frame(packet.payload.clone(), super::super::tcp::now().unwrap())
            {
                if matches!(frame.metadata, Metadata::Data(m) if m.kind == DataKind::ClientData) {
                    self.control.invalid.fetch_add(1, Ordering::AcqRel);
                }
                if matches!(frame.metadata, Metadata::Data(m) if m.kind == DataKind::ServerData) {
                    self.control.rx.fetch_add(1, Ordering::AcqRel);
                    let _ = self.control.first_rx.compare_exchange(
                        usize::MAX,
                        self.control.tx.load(Ordering::Acquire),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
            }
            Ok(packet)
        }
    }

    async fn exercise(invalid_first: bool) {
        let probe = ResourceProbe::default();
        let (first_rx, first_data_rx) = probe
            .scope(async {
                let shared = Shared::output_test_shared(tokio_util::sync::CancellationToken::new());
                let state = State::new(1, RX_CREDIT, &shared.cancel, shared.activity.clone());
                shared.sessions.lock().unwrap().insert(1, state.clone());
                let credit = Arc::new(Semaphore::new(TX_CREDIT));
                let (commands, receiver) = mpsc::channel(2);
                let (incoming, packets) = mpsc::channel(64);
                let control = Arc::new(Control::default());
                control.first_rx.store(usize::MAX, Ordering::Release);
                control.first_data_rx.store(usize::MAX, Ordering::Release);
                let mut writes = Vec::new();
                for index in 0..WRITES {
                    let (done, result) = oneshot::channel();
                    control.queued.lock().unwrap().push_back(WriterCommand {
                        state: state.clone(),
                        data: Bytes::from(vec![0x81 + index as u8]),
                        piggyback: false,
                        done,
                        _bytes: credit.clone().try_acquire_many_owned(1).unwrap(),
                    });
                    writes.push(result);
                }
                let key = crypto::derive_packet_key(
                    "vole",
                    "fixture-password",
                    super::super::tcp::now().unwrap(),
                );
                let mut encoder = PacketEncoder::new(&key, false).unwrap();
                let mut decoder = PacketDecoder::new(&key, false).unwrap();
                let pattern = EffectivePattern::compile(
                    None,
                    super::super::pattern::HostProfile::capture(),
                    "vole",
                )
                .unwrap();
                let peer = Destination::Ip("192.0.2.1:2000".parse().unwrap());
                let mut transport = Packets {
                    incoming: packets,
                    inject: incoming,
                    commands: commands.clone(),
                    control: control.clone(),
                    encoder: PacketEncoder::new(&key, false).unwrap(),
                    decoder: PacketDecoder::new(&key, false).unwrap(),
                    peer: peer.clone(),
                    invalid_first,
                    ready_invalid: None,
                    invalid_remaining: 0,
                };
                let (done, opening) = oneshot::channel();
                commands
                    .try_send(WriterCommand {
                        state: state.clone(),
                        data: Bytes::from_static(b"q"),
                        piggyback: true,
                        done,
                        _bytes: credit.clone().try_acquire_many_owned(1).unwrap(),
                    })
                    .map_err(|_| failed("test opening command rejected"))
                    .unwrap();
                let (driver, work) = tokio::join!(
                    run(
                        &mut transport,
                        &peer,
                        DatagramBudget::new(MTU, MTU),
                        &mut encoder,
                        &mut decoder,
                        "vole",
                        &pattern,
                        &shared,
                        receiver
                    ),
                    async {
                        let work = tokio::time::timeout(Duration::from_secs(1), async {
                            opening
                                .await
                                .map_err(|_| failed("opening result dropped"))??;
                            let (sent, received) = tokio::join!(
                                async {
                                    for write in writes {
                                        write
                                            .await
                                            .map_err(|_| failed("write result dropped"))??;
                                    }
                                    Ok::<_, io::Error>(())
                                },
                                async {
                                    let mut received = vec![0; READS];
                                    let mut offset = 0;
                                    while offset < READS {
                                        let mut buffer =
                                            tokio::io::ReadBuf::new(&mut received[offset..]);
                                        futures_util::future::poll_fn(|cx| {
                                            state.poll_read(cx, &mut buffer)
                                        })
                                        .await?;
                                        if buffer.filled().is_empty() {
                                            return Err(failed("early stream EOF"));
                                        }
                                        offset += buffer.filled().len();
                                    }
                                    Ok::<_, io::Error>(received)
                                }
                            );
                            sent?;
                            received
                        })
                        .await
                        .unwrap_or_else(|_| Err(failed("bounded driver work timed out")));
                        shared.fail(); // Also runs on failure; join waits for the actual driver.
                        work
                    }
                );
                state.close();
                shared.sessions.lock().unwrap().clear();
                drop(transport);
                drop(commands);
                control.queued.lock().unwrap().clear();
                assert!(
                    driver.is_ok()
                        || driver
                            .as_ref()
                            .is_err_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
                );
                assert_eq!(work.unwrap(), (1..=READS as u8).collect::<Vec<_>>());
                let sent = control.sent.lock().unwrap();
                assert_eq!(
                    sent.iter()
                        .map(|(sequence, _)| *sequence)
                        .collect::<Vec<_>>(),
                    (1..=WRITES as u32).collect::<Vec<_>>()
                );
                assert_eq!(
                    sent.iter()
                        .flat_map(|(_, bytes)| bytes.iter().copied())
                        .collect::<Vec<_>>(),
                    (0x81..0x81 + WRITES as u8).collect::<Vec<_>>()
                );
                assert_eq!(control.rx.load(Ordering::Acquire), READS);
                assert_eq!(
                    control.invalid.load(Ordering::Acquire),
                    if invalid_first { READS } else { 0 }
                );
                assert_eq!(credit.available_permits(), TX_CREDIT);
                assert_eq!(state.receive_bytes.available_permits(), RX_CREDIT);
                (
                    control.first_rx.load(Ordering::Acquire),
                    control.first_data_rx.load(Ordering::Acquire),
                )
            })
            .await;
        assert!(probe.snapshot().is_idle());
        // Scheduling assertions follow content, completion and credit cleanup.
        assert!(
            first_rx <= 8,
            "ready RX followed {first_rx} successful physical sends"
        );
        assert!(
            first_data_rx <= 8,
            "selected DATA followed {first_data_rx} receives"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_udp_empty_sid_ready_invalid_preserves_idle_retirement_cancel_and_first_send_gate()
     {
        use std::{future::Future, task::Poll};

        const INVALID_PACKETS: usize = 16_384;
        async fn once<F: Future>(mut future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
            std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
        }
        let resources = ResourceProbe::default();
        resources
            .scope(async {
                for cancel in [false, true] {
                    let shared =
                        Shared::output_test_shared(tokio_util::sync::CancellationToken::new());
                    let state = State::new(1, RX_CREDIT, &shared.cancel, shared.activity.clone());
                    shared.sessions.lock().unwrap().insert(1, state.clone());
                    let credit = Arc::new(Semaphore::new(TX_CREDIT));
                    let (commands, receiver) = mpsc::channel(2);
                    let (inject, incoming) = mpsc::channel(1);
                    let control = Arc::new(Control::default());
                    let key = crypto::derive_packet_key(
                        "vole",
                        "fixture-password",
                        super::super::tcp::now().unwrap(),
                    );
                    let mut encoder = PacketEncoder::new(&key, false).unwrap();
                    let mut decoder = PacketDecoder::new(&key, false).unwrap();
                    let pattern = EffectivePattern::compile(
                        None,
                        super::super::pattern::HostProfile::capture(),
                        "vole",
                    )
                    .unwrap();
                    let peer = Destination::Ip("192.0.2.1:2000".parse().unwrap());
                    let mut bytes = Vec::new();
                    PacketEncoder::new(&key, false)
                        .unwrap()
                        .encode_frame(
                            Metadata::Data(DataMetadata {
                                kind: DataKind::ClientData,
                                session_id: 1,
                                sequence: 100,
                                unack_sequence: 0,
                                window: 64,
                                fragment: 0,
                            }),
                            b"x",
                            super::super::wire::Padding {
                                prefix: &[],
                                suffix: &[],
                            },
                            [7; crypto::NONCE_LEN],
                            super::super::tcp::now().unwrap(),
                            &mut bytes,
                        )
                        .unwrap();
                    let mut transport = Packets {
                        incoming,
                        inject,
                        commands: commands.clone(),
                        control: control.clone(),
                        encoder: PacketEncoder::new(&key, false).unwrap(),
                        decoder: PacketDecoder::new(&key, false).unwrap(),
                        peer: peer.clone(),
                        invalid_first: false,
                        ready_invalid: Some(Datagram {
                            remote: peer.clone(),
                            payload: Bytes::from(bytes),
                            sniffed_domain: None,
                        }),
                        invalid_remaining: INVALID_PACKETS,
                    };
                    let created = Instant::now();
                    let mut driver = Box::pin(run(
                        &mut transport,
                        &peer,
                        DatagramBudget::new(MTU, MTU),
                        &mut encoder,
                        &mut decoder,
                        "vole",
                        &pattern,
                        &shared,
                        receiver,
                    ));
                    let mut completed = None;
                    // Empty original command sender stays alive. RX must not run before
                    // the first physical send, including while that actual send is Pending.
                    for _ in 0..2 {
                        if let Poll::Ready(result) = once(driver.as_mut()).await {
                            completed = Some(result);
                            break;
                        }
                    }
                    let (done, mut opening) = oneshot::channel();
                    commands
                        .try_send(WriterCommand {
                            state: state.clone(),
                            data: Bytes::from_static(b"q"),
                            piggyback: true,
                            done,
                            _bytes: credit.clone().try_acquire_many_owned(1).unwrap(),
                        })
                        .map_err(|_| failed("empty-SID opening command rejected"))
                        .unwrap();
                    for _ in 0..4 {
                        if completed.is_some() {
                            break;
                        }
                        if let Poll::Ready(result) = once(driver.as_mut()).await {
                            completed = Some(result);
                            break;
                        }
                    }
                    let before_send_ok = completed.is_none()
                        && control.tx.load(Ordering::Acquire) == 0
                        && control.receive_calls.load(Ordering::Acquire) == 0
                        && matches!(opening.try_recv(), Err(oneshot::error::TryRecvError::Empty));
                    control.allow_send.store(true, Ordering::Release);
                    for _ in 0..8 {
                        if completed.is_some() || control.tx.load(Ordering::Acquire) != 0 {
                            break;
                        }
                        if let Poll::Ready(result) = once(driver.as_mut()).await {
                            completed = Some(result);
                        }
                    }
                    let sent_first = control.tx.load(Ordering::Acquire) == 1
                        && matches!(opening.try_recv(), Ok(Ok(())))
                        && state.opened.load(Ordering::Acquire);
                    state.close();
                    for _ in 0..16 {
                        if completed.is_some() || shared.sessions.lock().unwrap().is_empty() {
                            break;
                        }
                        if let Poll::Ready(result) = once(driver.as_mut()).await {
                            completed = Some(result);
                        }
                    }
                    let empty_after_close = shared.sessions.lock().unwrap().is_empty()
                        && control.close_requests.load(Ordering::Acquire) == 1
                        && control.tx.load(Ordering::Acquire) == 2
                        && credit.available_permits() == TX_CREDIT;
                    let mut progressed = true;
                    let mut bounded_rx = true;
                    let steps = if cancel { 16 } else { 190 };
                    for _ in 0..steps {
                        if completed.is_some() {
                            break;
                        }
                        let before = control.invalid.load(Ordering::Acquire);
                        // Less than the original idle sleep; continuously Ready invalid
                        // selected RX discards/recreates that sleep before it can win.
                        tokio::time::advance(Duration::from_secs(1)).await;
                        if let Poll::Ready(result) = once(driver.as_mut()).await {
                            completed = Some(result);
                        }
                        let after = control.invalid.load(Ordering::Acquire);
                        if completed.is_none() {
                            progressed &= after > before;
                        }
                        bounded_rx &= after - before <= usize::from(RECEIVE_BATCH);
                        tokio::task::yield_now().await;
                    }
                    let completed_before_cancel = completed.is_some();
                    let elapsed = Instant::now().saturating_duration_since(created);
                    let reads = control.invalid.load(Ordering::Acquire);
                    shared.cancel.cancel();
                    for _ in 0..8 {
                        if completed.is_some() {
                            break;
                        }
                        if let Poll::Ready(result) = once(driver.as_mut()).await {
                            completed = Some(result);
                        }
                        tokio::task::yield_now().await;
                    }
                    drop(driver);
                    state.close();
                    shared.sessions.lock().unwrap().clear();
                    drop((transport, commands));
                    let tx_credit = credit.available_permits();
                    let rx_credit = state.receive_bytes.available_permits();
                    drop((state, shared, encoder, decoder));

                    assert!(
                        before_send_ok,
                        "receive callback ran before first successful physical send"
                    );
                    assert!(
                        sent_first && empty_after_close,
                        "actual OPEN/Close/local-SID removal was not established"
                    );
                    assert!(
                        progressed && bounded_rx,
                        "ready invalid RX did not progress with the original RX8 yield bound"
                    );
                    assert!(
                        reads > 0 && reads < INVALID_PACKETS,
                        "finite shared-Bytes flood exhausted or was not received"
                    );
                    assert_eq!(
                        completed_before_cancel, !cancel,
                        "empty-map retirement or cancellation phase did not match"
                    );
                    if !cancel {
                        assert!(
                            (Duration::from_secs(180)..=Duration::from_secs(190))
                                .contains(&elapsed),
                            "retirement skipped original created60 + idle120 policy: {elapsed:?}"
                        );
                    }
                    assert!(
                        matches!(completed, Some(Ok(()))),
                        "actual driver failed to retire/cancel cleanly"
                    );
                    assert_eq!(OUTPUT_QUANTUM, 8);
                    assert_eq!(RECEIVE_BATCH, 8);
                    assert_eq!(tx_credit, TX_CREDIT);
                    assert_eq!(rx_credit, RX_CREDIT);
                }
            })
            .await;
        assert!(resources.snapshot().is_idle());
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_udp_balanced_ready_reads_and_writes_complete() {
        exercise(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_udp_balanced_invalid_supplement_keeps_selected_output() {
        exercise(true).await;
    }
}
