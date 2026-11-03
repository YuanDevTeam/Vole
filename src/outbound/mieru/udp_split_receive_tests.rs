#[cfg(test)]
mod split_receive_tests {
    use super::*;
    use crate::{
        config::{MieruHandshake, MieruMultiplexing},
        dispatch::DispatchError,
        outbound::{ConnectedStream, OutboundConnector},
        resources::observation::ResourceProbe,
    };
    use async_trait::async_trait;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CAPACITY: usize = 32768;
    const CHUNK: usize = 1312;

    fn failed(message: &'static str) -> io::Error {
        io::Error::other(message)
    }

    struct Packets {
        incoming: mpsc::Receiver<Datagram>,
        sent: mpsc::Sender<Metadata>,
        received: Arc<AtomicUsize>,
        closed: Arc<AtomicBool>,
        decoder: PacketDecoder,
        delay_after_close_reply: Duration,
        hold_until: Option<Instant>,
    }

    #[async_trait]
    impl DatagramTransport for Packets {
        fn supports_shared_destinations(&self) -> bool {
            false
        }

        fn payload_budget(&self, _: &Destination) -> DatagramBudget {
            DatagramBudget::new(MTU, MTU)
        }

        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            let frame = self
                .decoder
                .decode_frame(packet.payload, super::super::tcp::now().unwrap())
                .map_err(|_| DispatchError::NotAllowed)?;
            if matches!(frame.metadata, Metadata::Session(meta)
                if meta.kind == SessionKind::CloseResponse)
                && self.hold_until.is_none()
                && !self.delay_after_close_reply.is_zero()
            {
                // First response alone activates the test physical Pending edge.
                self.hold_until = Some(Instant::now() + self.delay_after_close_reply);
            }
            self.sent
                .try_send(frame.metadata)
                .map_err(|_| DispatchError::NotAllowed)
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if let Some(until) = self.hold_until {
                // Pending cancellation retains the same prequeued DATA.
                tokio::time::sleep_until(until).await;
            }
            let packet = self
                .incoming
                .recv()
                .await
                .ok_or(DispatchError::NotAllowed)?;
            self.received.fetch_add(1, Ordering::AcqRel);
            Ok(packet)
        }

        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }

    struct Peer {
        incoming: Mutex<Option<mpsc::Receiver<Datagram>>>,
        sent: mpsc::Sender<Metadata>,
        received: Arc<AtomicUsize>,
        closed: Arc<AtomicBool>,
        delay_after_close_reply: Duration,
    }

    #[async_trait]
    impl OutboundConnector for Arc<Peer> {
        async fn connect_stream(
            &self,
            _: StreamSession,
            _: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            Err(DispatchError::NotAllowed)
        }

        async fn open_datagram(
            &self,
            _: DatagramRequest,
            _: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            let incoming = self
                .incoming
                .lock()
                .unwrap()
                .take()
                .ok_or(DispatchError::NotAllowed)?;
            let key = crypto::derive_packet_key(
                "vole",
                "fixture-password",
                super::super::tcp::now().map_err(|_| DispatchError::NotAllowed)?,
            );
            Ok(Box::new(Packets {
                incoming,
                sent: self.sent.clone(),
                received: self.received.clone(),
                closed: self.closed.clone(),
                decoder: PacketDecoder::new(&key, false).map_err(|_| DispatchError::NotAllowed)?,
                delay_after_close_reply: self.delay_after_close_reply,
                hold_until: None,
            }))
        }
    }

    struct Fixture {
        node: super::super::MieruOutbound,
        raw: Option<super::super::stream::RawStream>,
        state: Arc<State>,
        capacity: usize,
        incoming: mpsc::Sender<Datagram>,
        sent: mpsc::Receiver<Metadata>,
        closed: Arc<AtomicBool>,
        encoder: PacketEncoder,
        remote: Destination,
    }

    impl Fixture {
        async fn new(capacity: usize) -> io::Result<Self> {
            Self::with_close_gate(capacity, super::super::tcp::Business::TcpConnect, Duration::ZERO).await
        }
        async fn with_close_gate(
            capacity: usize,
            business: super::super::tcp::Business,
            delay_after_close_reply: Duration,
        ) -> io::Result<Self> {
            let (incoming, packets) = mpsc::channel(64);
            let (sent, observations) = mpsc::channel(128);
            let received = Arc::new(AtomicUsize::new(0));
            let closed = Arc::new(AtomicBool::new(false));
            let peer = Arc::new(Peer {
                incoming: Mutex::new(Some(packets)),
                sent,
                received: received.clone(),
                closed: closed.clone(),
                delay_after_close_reply,
            });
            let mut config = super::super::tests::config(MieruHandshake::NoWait);
            config.address = "192.0.2.1".into();
            config.port = 2000;
            config.port_end = 2000;
            config.transport = MieruTransport::Udp;
            config.multiplexing = MieruMultiplexing::Off;
            let node = super::super::MieruOutbound::new(
                &config,
                UpstreamPath::proxy(Arc::new(peer)),
                capacity,
            )?;
            let context = EstablishContext::with_timeout(Duration::from_secs(1));
            let raw = match node
                .client
                .open(
                    super::super::tests::session(),
                    business,
                    None,
                    &context,
                )
                .await
            {
                Ok(raw) => raw,
                Err(error) => {
                    node.shutdown().await;
                    return Err(error);
                }
            };
            let state = raw.state.clone();
            let key = crypto::derive_packet_key(
                "vole",
                "fixture-password",
                super::super::tcp::now()?,
            );
            Ok(Self {
                node,
                raw: Some(raw),
                state,
                capacity,
                incoming,
                sent: observations,
                closed,
                encoder: PacketEncoder::new(&key, false)?,
                remote: Destination::Ip("192.0.2.1:2000".parse().unwrap()),
            })
        }

        fn inject(&mut self, metadata: Metadata, payload: &[u8]) -> io::Result<()> {
            let mut bytes = Vec::new();
            self.encoder.encode_frame(
                metadata,
                payload,
                super::super::wire::Padding {
                    prefix: &[],
                    suffix: &[],
                },
                rand::random(),
                super::super::tcp::now()?,
                &mut bytes,
            )?;
            self.incoming
                .try_send(Datagram {
                    remote: self.remote.clone(),
                    payload: Bytes::from(bytes),
                    sniffed_domain: None,
                })
                .map_err(|_| failed("bounded test input is full or closed"))
        }

        fn data(&mut self, sequence: u32) -> io::Result<()> {
            self.inject(
                Metadata::Data(DataMetadata {
                    kind: DataKind::ServerData,
                    session_id: self.state.id,
                    sequence,
                    unack_sequence: 1,
                    window: 64,
                    fragment: 0,
                }),
                &vec![sequence as u8; CHUNK],
            )
        }

        async fn ack(&mut self, prefix: u32, window: Option<u16>) -> io::Result<u16> {
            tokio::time::timeout(Duration::from_millis(200), async {
                while let Some(metadata) = self.sent.recv().await {
                    if matches!(metadata, Metadata::Data(meta)
                        if meta.kind == DataKind::ClientAck
                            && meta.unack_sequence == prefix && window.is_none_or(|window| meta.window == window))
                    {
                        if let Metadata::Data(meta) = metadata {
                            return Ok(meta.window);
                        }
                    }
                }
                Err(failed("driver output ended before the expected ACK"))
            })
            .await
            .map_err(|_| failed("expected cumulative ACK did not arrive"))?
        }

        async fn bootstrap(&mut self) -> io::Result<()> {
            self.raw.as_mut().unwrap().write_all(&[0x71]).await?;
            let open = tokio::time::timeout(Duration::from_millis(200), self.sent.recv())
                .await
                .map_err(|_| failed("open request did not arrive"))?
                .ok_or_else(|| failed("driver output closed before open request"))?;
            if !matches!(open, Metadata::Session(meta)
                if meta.kind == SessionKind::OpenRequest && meta.session_id == self.state.id)
            {
                return Err(failed("first output is not this session's open request"));
            }
            self.inject(
                Metadata::Session(SessionMetadata {
                    kind: SessionKind::OpenResponse,
                    session_id: self.state.id,
                    sequence: 0,
                    status: 0,
                }),
                &[],
            )?;
            self.inject(
                Metadata::Data(DataMetadata {
                    kind: DataKind::ServerAck,
                    session_id: self.state.id,
                    sequence: 0,
                    unack_sequence: 1,
                    window: 64,
                    fragment: 0,
                }),
                &[],
            )?;
            self.ack(
                1,
                Some(if self.capacity < CHUNK {
                    1
                } else {
                    (self.capacity / CHUNK) as u16
                }),
            )
            .await?;
            Ok(())
        }

        fn data_bytes(&mut self, sequence: u32, payload: &[u8]) -> io::Result<()> {
            self.inject(
                Metadata::Data(DataMetadata {
                    kind: DataKind::ServerData,
                    session_id: self.state.id,
                    sequence,
                    unack_sequence: 1,
                    window: 64,
                    fragment: 0,
                }),
                payload,
            )
        }
        async fn fill_app(&mut self) -> io::Result<Vec<u8>> {
            let mut expected = Vec::new();
            for sequence in 1..=24 {
                self.data(sequence)?;
                expected.extend(std::iter::repeat_n(sequence as u8, CHUNK));
            }
            let last = vec![25; CAPACITY - 24 * CHUNK];
            self.data_bytes(25, &last)?;
            expected.extend(last);
            self.ack(26, None).await?;
            if self.state.next_receive.load(Ordering::Acquire) != 26
                || self.state.receive_bytes.available_permits() != 0
            {
                return Err(failed("authenticated DATA did not fill app capacity"));
            }
            Ok(expected)
        }
        fn remote_close(&mut self, sequence: u32) -> io::Result<()> {
            self.inject(
                Metadata::Session(SessionMetadata {
                    kind: SessionKind::CloseRequest,
                    session_id: self.state.id,
                    sequence,
                    status: 0,
                }),
                &[],
            )
        }
        async fn close_reply(&mut self) -> io::Result<()> {
            tokio::time::timeout(Duration::from_millis(200), async {
                while let Some(metadata) = self.sent.recv().await {
                    if matches!(metadata, Metadata::Session(meta) if meta.kind == SessionKind::CloseResponse) {
                        return Ok(());
                    }
                }
                Err(failed("driver ended before responding to Close"))
            })
            .await
            .map_err(|_| failed("Close was not consumed before app reads"))?
        }
        async fn stop(&mut self) -> io::Result<()> {
            self.node.begin_shutdown();
            tokio::time::timeout(Duration::from_secs(1), self.node.shutdown())
                .await
                .map_err(|_| failed("driver Stop waited for unread app credit"))?;
            self.raw.take();
            if !self.closed.load(Ordering::Acquire)
                || self.state.receive_bytes.available_permits() != self.capacity
            {
                return Err(failed(
                    "Stop did not close transport or stream release did not refund credit",
                ));
            }
            Ok(())
        }
    }

    struct Wire {
        encoder: PacketEncoder,
        decoder: PacketDecoder,
        unix: u64,
        nonce: u64,
    }
    impl Wire {
        fn new() -> Self {
            let unix = super::super::tcp::now().unwrap();
            let key = crypto::derive_packet_key("vole", "fixture-password", unix);
            Self {
                encoder: PacketEncoder::new(&key, false).unwrap(),
                decoder: PacketDecoder::new(&key, false).unwrap(),
                unix,
                nonce: 0,
            }
        }
        fn input(
            &mut self,
            reliable: &mut Reliable,
            partial: &mut Option<Partial>,
            metadata: Metadata,
            payload: &[u8],
        ) -> Bytes {
            self.nonce += 1;
            let mut nonce = [0; 24];
            nonce[..8].copy_from_slice(&self.nonce.to_be_bytes());
            let mut packet = Vec::new();
            self.encoder
                .encode_frame(
                    metadata,
                    payload,
                    super::super::wire::Padding::default(),
                    nonce,
                    self.unix,
                    &mut packet,
                )
                .unwrap();
            let frame = self
                .decoder
                .decode_frame(Bytes::from(packet), self.unix)
                .unwrap();
            let owner = frame.payload.clone();
            reliable.input(frame, Instant::now(), partial);
            owner
        }
        fn data(
            &mut self,
            reliable: &mut Reliable,
            partial: &mut Option<Partial>,
            sequence: u32,
            payload: &[u8],
        ) -> Bytes {
            self.input(
                reliable,
                partial,
                Metadata::Data(DataMetadata {
                    kind: DataKind::ServerData,
                    session_id: 1,
                    sequence,
                    unack_sequence: 0,
                    window: 64,
                    fragment: 0,
                }),
                payload,
            )
        }
    }
    fn content(first: u32, end: u32) -> Vec<u8> {
        (first..end)
            .flat_map(|sequence| std::iter::repeat_n(sequence as u8, CHUNK))
            .collect()
    }
    fn read_exact(state: &State, expected: &[u8]) {
        let mut actual = Vec::with_capacity(expected.len());
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        while actual.len() < expected.len() {
            let mut storage = [0; 257];
            let len = (expected.len() - actual.len()).min(storage.len());
            let mut read = tokio::io::ReadBuf::new(&mut storage[..len]);
            assert!(matches!(
                state.poll_read(&mut cx, &mut read),
                std::task::Poll::Ready(Ok(()))
            ));
            assert!(!read.filled().is_empty());
            actual.extend_from_slice(read.filled());
        }
        assert_eq!(actual, expected);
    }
    fn direct_prefix_proof() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let state = State::new(
            1,
            CAPACITY,
            &cancellation,
            Arc::new(tokio::sync::Notify::new()),
        );
        let mut reliable = Reliable::new(state.clone(), CHUNK);
        let receive_pool = reliable.reorder_bytes.clone();
        assert_eq!(receive_pool.available_permits(), 2 * CAPACITY);
        let mut partial = None;
        let mut wire = Wire::new();
        wire.input(
            &mut reliable,
            &mut partial,
            Metadata::Session(SessionMetadata {
                kind: SessionKind::OpenResponse,
                session_id: 1,
                sequence: 0,
                status: 0,
            }),
            &[],
        );
        for sequence in 1..=24 {
            wire.data(
                &mut reliable,
                &mut partial,
                sequence,
                &vec![sequence as u8; CHUNK],
            );
        }
        let mut app_content = content(1, 25);
        let last = vec![25; CAPACITY - 24 * CHUNK];
        wire.data(&mut reliable, &mut partial, 25, &last);
        app_content.extend(last);
        assert_eq!(state.receive_bytes.available_permits(), 0);
        // Fill the new 64KiB reorder pool up to its reserved head slot:
        // 48 full future frames + one 1248-byte tail = 64,224 bytes.
        for sequence in 50..=97 {
            wire.data(
                &mut reliable,
                &mut partial,
                sequence,
                &vec![sequence as u8; CHUNK],
            );
        }
        let far_owner = wire.data(&mut reliable, &mut partial, 98, &[98; 1248]);
        assert_eq!(reliable.reorder.len(), 49);
        assert_eq!(receive_pool.available_permits(), CHUNK);
        assert_eq!(state.unread_bytes(), CAPACITY);
        assert!(
            (2 * CAPACITY - receive_pool.available_permits()) + state.unread_bytes()
                <= 3 * CAPACITY
        );
        wire.data(&mut reliable, &mut partial, 30, &[30; CHUNK]);
        let head_owner = wire.data(&mut reliable, &mut partial, 26, &[26; CHUNK]);
        // The authenticated head stays retained until app transfer can commit.
        assert!(reliable.reorder.contains_key(&26));
        assert_eq!(state.next_receive.load(Ordering::Acquire), 26);
        assert_eq!(state.receive_bytes.available_permits(), 0);
        assert!(far_owner.is_unique());
        drop(far_owner);
        assert!(!head_owner.is_unique());
        for sequence in 27..=29 {
            wire.data(
                &mut reliable,
                &mut partial,
                sequence,
                &vec![sequence as u8; CHUNK],
            );
        }
        // Duplicate content must not overwrite the retained nearer prefix.
        wire.data(&mut reliable, &mut partial, 30, &[0xfe; CHUNK]);
        for sequence in 31..=48 {
            wire.data(
                &mut reliable,
                &mut partial,
                sequence,
                &vec![sequence as u8; CHUNK],
            );
        }
        assert_eq!(reliable.reorder.len(), 48);
        assert_eq!(receive_pool.available_permits(), 2 * CAPACITY - 48 * CHUNK);
        for sequence in 26..=48 {
            assert!(reliable.reorder.contains_key(&sequence));
        }
        for sequence in 50..=74 {
            assert!(reliable.reorder.contains_key(&sequence));
        }
        assert!(!reliable.reorder.contains_key(&49));
        let far_survivor = reliable.reorder.get(&50).unwrap().frame.payload.clone();
        assert!(!far_survivor.is_unique());
        assert_eq!(state.next_receive.load(Ordering::Acquire), 26);
        let retained = reliable
            .reorder
            .values()
            .map(|inbound| inbound.frame.payload.len())
            .sum::<usize>();
        assert!(retained <= 2 * CAPACITY);
        assert!(retained + CAPACITY - state.receive_bytes.available_permits() <= 3 * CAPACITY);
        read_exact(&state, &app_content);
        assert_eq!(state.receive_bytes.available_permits(), CAPACITY);
        reliable.deliver_contiguous();
        assert_eq!(state.next_receive.load(Ordering::Acquire), 49);
        // The nearer prefix is committed, but seq49 still separates the
        // retained far DATA from the app. It must survive without delivery.
        assert_eq!(reliable.reorder.len(), 25);
        assert_eq!(receive_pool.available_permits(), 2 * CAPACITY - 25 * CHUNK);
        read_exact(&state, &content(26, 49));
        assert_eq!(state.receive_bytes.available_permits(), CAPACITY);
        assert!(!reliable.deliver_contiguous());
        assert_eq!(state.next_receive.load(Ordering::Acquire), 49);
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut storage = [0; CHUNK];
        let mut read = tokio::io::ReadBuf::new(&mut storage);
        assert!(matches!(
            state.poll_read(&mut cx, &mut read),
            std::task::Poll::Pending
        ));
        assert!(!far_survivor.is_unique());
        assert!(head_owner.is_unique());
        drop(head_owner);
        assert!(partial.is_none());
        state.close();
        drop(reliable);
        assert_eq!(state.receive_bytes.available_permits(), CAPACITY);
        assert_eq!(receive_pool.available_permits(), 2 * CAPACITY);
        assert!(far_survivor.is_unique());
        drop(far_survivor);
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_split_receive_protects_prefix_and_commits_ack_after_app_transfer() {
        let probe = ResourceProbe::default();
        let result: io::Result<()> = probe
            .scope(async {
                direct_prefix_proof();
                let mut fixture = Fixture::new(CAPACITY).await?;
                let result = async {
                    fixture.bootstrap().await?;
                    let mut expected = fixture.fill_app().await?;
                    fixture.data_bytes(26, &[26; 40])?;
                    fixture.data_bytes(27, &[27; 40])?;
                    fixture.ack(26, None).await?;
                    if fixture.state.next_receive.load(Ordering::Acquire) != 26
                        || fixture.state.receive_bytes.available_permits() != 0
                    {
                        return Err(failed("cumulative ACK moved before app enqueue"));
                    }
                    let mut first = [0; 40];
                    fixture.raw.as_mut().unwrap().read_exact(&mut first).await?;
                    if first != [1; 40] {
                        return Err(failed("first app bytes changed"));
                    }
                    // No new peer input follows the read. The real driver must
                    // commit seq26 and ACK it even though RX window stays at24.
                    fixture.ack(27, Some(24)).await?;
                    if fixture.state.next_receive.load(Ordering::Acquire) != 27 {
                        return Err(failed(
                            "driver did not retry app transfer on reader activity",
                        ));
                    }
                    expected.extend_from_slice(&[26; 40]);
                    expected.extend_from_slice(&[27; 40]);
                    let mut tail = vec![0; expected.len() - first.len()];
                    tokio::time::timeout(
                        Duration::from_millis(200),
                        fixture.raw.as_mut().unwrap().read_exact(&mut tail),
                    )
                    .await
                    .map_err(|_| failed("pending app transfer did not complete"))??;
                    if tail != expected[first.len()..] {
                        return Err(failed("split app transfer changed or duplicated content"));
                    }
                    fixture.ack(28, Some(24)).await?;
                    if fixture.state.receive_bytes.available_permits() != CAPACITY {
                        return Err(failed("actual app reads did not refund all app credit"));
                    }
                    Ok(())
                }
                .await;
                fixture.stop().await?;
                result
            })
            .await;
        assert!(probe.snapshot().is_idle());
        result.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_split_receive_remote_close_drains_contiguous_prefix_to_eof() {
        let probe = ResourceProbe::default();
        let result: io::Result<()> = probe
            .scope(async {
                let mut fixture = Fixture::new(CAPACITY).await?;
                let result = async {
                    fixture.bootstrap().await?;
                    let mut expected = fixture.fill_app().await?;
                    fixture.data(27)?;
                    fixture.data(26)?;
                    fixture.data(29)?; // seq28 is absent; this future must be dropped on Close.
                    fixture.remote_close(30)?;
                    fixture.close_reply().await?;
                    // Close is observed before there is any app reader. Retained
                    // seq26/27 must later become readable; seq29 must not cross the gap.
                    let mut actual = Vec::new();
                    tokio::time::timeout(
                        Duration::from_millis(200),
                        fixture.raw.as_mut().unwrap().read_to_end(&mut actual),
                    )
                    .await
                    .map_err(|_| failed("deferred close did not produce EOF after draining"))??;
                    expected.extend_from_slice(&[26; CHUNK]);
                    expected.extend_from_slice(&[27; CHUNK]);
                    if actual != expected {
                        return Err(failed(
                            "closed accepted contiguous DATA was truncated or future gap crossed",
                        ));
                    }
                    if fixture.state.receive_bytes.available_permits() != CAPACITY
                        || !fixture.state.remote_closed.load(Ordering::Acquire)
                    {
                        return Err(failed("closed app credit or EOF state was not completed"));
                    }
                    Ok(())
                }
                .await;
                fixture.stop().await?;
                result
            })
            .await;
        assert!(probe.snapshot().is_idle());
        result.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_split_receive_unread_closed_stream_does_not_block_stop() {
        let probe = ResourceProbe::default();
        let result: io::Result<()> = probe
            .scope(async {
                let mut fixture = Fixture::new(CAPACITY).await?;
                let result = async {
                    fixture.bootstrap().await?;
                    fixture.fill_app().await?;
                    fixture.data_bytes(26, &[26; 40])?;
                    fixture.data_bytes(27, &[27; 40])?;
                    fixture.remote_close(28)?;
                    fixture.close_reply().await?;
                    // No app read occurs. Stop must cancel the bounded deferred drain.
                    Ok(())
                }
                .await;
                fixture.stop().await?;
                result
            })
            .await;
        assert!(probe.snapshot().is_idle());
        result.unwrap();
    }
    async fn grace_read_to_eof(mut fixture: Fixture) -> io::Result<(Vec<u8>, io::Result<usize>)> {
        let mut raw = fixture.raw.take().unwrap();
        let mut bytes = Vec::new();
        let read = tokio::time::timeout(Duration::from_millis(200), raw.read_to_end(&mut bytes)).await;
        drop(raw);
        fixture.stop().await?;
        let read = read.map_err(|_| failed("invalid RED: no real EOF before fixture guard"))?;
        Ok((bytes, read))
    }
    fn grace_read_is_pending(raw: &mut super::super::stream::RawStream) -> io::Result<bool> {
        let mut storage = [0u8; 16];
        let mut buffer = tokio::io::ReadBuf::new(&mut storage);
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        match tokio::io::AsyncRead::poll_read(std::pin::Pin::new(raw), &mut cx, &mut buffer) {
            std::task::Poll::Pending => Ok(true),
            std::task::Poll::Ready(Ok(())) => Ok(false),
            std::task::Poll::Ready(Err(error)) => Err(error),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_close_grace_recovers_head_after_original_turn() {
        let probe = ResourceProbe::default();
        probe.scope(async {
            let mut fixture = Fixture::with_close_gate(CAPACITY,
                super::super::tcp::Business::TcpConnect, Duration::from_millis(10)).await?;
            fixture.bootstrap().await?;
            // All DATA exists before Close. Only physical readiness of the head
            // is delayed, avoiding inject-after-closed errors as a fake RED.
            fixture.data_bytes(2, b"FUTURE")?;
            fixture.remote_close(3)?;
            fixture.data_bytes(1, b"HEAD")?;
            fixture.data_bytes(3, b"BEYOND-HINT")?;
            fixture.close_reply().await?;
            let (bytes, read) = grace_read_to_eof(fixture).await?;
            read?;
            // Only actual old-driver EOF/0B is expected assertion RED.
            assert_eq!(bytes, b"HEADFUTURE");
            Ok::<_, io::Error>(())
        }).await.unwrap();
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_close_grace_first_deadline_is_hard_and_duplicates_do_not_extend() {
        let probe = ResourceProbe::default();
        probe.scope(async {
            let mut fixture = Fixture::new(CAPACITY).await?;
            fixture.bootstrap().await?;
            fixture.data_bytes(2, b"FUTURE")?;
            fixture.remote_close(3)?;
            fixture.close_reply().await?;
            let closed_at = Instant::now();
            let mut raw = fixture.raw.take().unwrap();
            let first_pending = grace_read_is_pending(&mut raw)?;
            tokio::time::advance(Duration::from_millis(90)).await;
            fixture.remote_close(3)?;
            fixture.close_reply().await?;
            tokio::time::advance(Duration::from_millis(9)).await;
            let before_deadline_pending = grace_read_is_pending(&mut raw)?;
            tokio::time::advance(Duration::from_millis(1)).await;
            let mut bytes = Vec::new();
            let end = tokio::time::timeout(Duration::from_millis(1), raw.read_to_end(&mut bytes)).await;
            let elapsed = Instant::now().saturating_duration_since(closed_at);
            drop(raw);
            fixture.stop().await?;
            let end = end.map_err(|_| failed("first 100ms deadline was not observed"))?;
            end?;
            assert!(first_pending && before_deadline_pending);
            assert!(bytes.is_empty());
            assert!(elapsed >= Duration::from_millis(100) && elapsed < Duration::from_millis(102));
            Ok::<_, io::Error>(())
        }).await.unwrap();
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_close_grace_rejects_new_write_without_losing_read() {
        let probe = ResourceProbe::default();
        probe.scope(async {
            let mut fixture = Fixture::with_close_gate(CAPACITY,
                super::super::tcp::Business::TcpConnect, Duration::from_millis(10)).await?;
            fixture.bootstrap().await?; // Prior write already physically first-sent.
            fixture.data_bytes(2, b"FUTURE")?;
            fixture.remote_close(3)?;
            fixture.data_bytes(1, b"HEAD")?;
            fixture.close_reply().await?;
            let mut raw = fixture.raw.take().unwrap();
            let write = raw.write_all(b"MUST-NOT-SEND").await;
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(Duration::from_millis(200), raw.read_to_end(&mut bytes)).await;
            drop(raw);
            let mut new_client_data = false;
            while let Ok(metadata) = fixture.sent.try_recv() {
                new_client_data |= matches!(metadata, Metadata::Data(meta) if meta.kind == DataKind::ClientData);
            }
            fixture.stop().await?;
            let read = read.map_err(|_| failed("read was cancelled by rejected write"))?;
            read?;
            assert_eq!(write.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
            assert!(!new_client_data);
            assert_eq!(bytes, b"HEADFUTURE");
            Ok::<_, io::Error>(())
        }).await.unwrap();
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    }

    #[tokio::test(start_paused = true)]
    async fn mieru_close_grace_stop_and_excluded_paths_keep_original_boundaries() {
        let probe = ResourceProbe::default();
        probe.scope(async {
            let mut fixture = Fixture::with_close_gate(CAPACITY,
                super::super::tcp::Business::TcpConnect, Duration::from_millis(10)).await?;
            fixture.bootstrap().await?;
            let _unread = fixture.fill_app().await?;
            fixture.data_bytes(27, b"FUTURE")?;
            fixture.remote_close(28)?;
            fixture.data_bytes(26, b"HEAD")?;
            fixture.close_reply().await?;
            let stopped_at = Instant::now();
            fixture.stop().await?;
            assert!(Instant::now().saturating_duration_since(stopped_at) < Duration::from_millis(100));
            for (business, capacity, kind, status) in [
                (super::super::tcp::Business::TcpConnect, CAPACITY, SessionKind::CloseResponse, 0),
                (super::super::tcp::Business::TcpConnect, CAPACITY, SessionKind::CloseRequest, 1),
                (super::super::tcp::Business::UdpAssociate, CAPACITY, SessionKind::CloseRequest, 0),
                (super::super::tcp::Business::TcpConnect, 64, SessionKind::CloseRequest, 0),
            ] {
                let mut fixture = Fixture::with_close_gate(capacity, business, Duration::ZERO).await?;
                fixture.bootstrap().await?;
                fixture.data_bytes(2, b"FUTURE")?;
                fixture.inject(Metadata::Session(SessionMetadata {
                    kind, session_id: fixture.state.id, sequence: 3, status,
                }), &[])?;
                fixture.data_bytes(1, b"HEAD")?;
                if kind == SessionKind::CloseRequest { fixture.close_reply().await?; }
                let (bytes, read) = grace_read_to_eof(fixture).await?;
                assert!(bytes.is_empty());
                if status != 0 { assert_eq!(read.unwrap_err().kind(), io::ErrorKind::BrokenPipe); }
                else { read?; }
            }
            let mut fixture = Fixture::new(CAPACITY).await?;
            fixture.bootstrap().await?;
            fixture.inject(Metadata::Session(SessionMetadata {
                kind: SessionKind::CloseRequest, session_id: fixture.state.id.wrapping_add(1), sequence: 3, status: 0,
            }), &[])?;
            fixture.data_bytes(1, b"HEAD")?;
            fixture.remote_close(2)?;
            fixture.close_reply().await?;
            let (bytes, read) = grace_read_to_eof(fixture).await?;
            read?;
            assert_eq!(bytes, b"HEAD");
            Ok::<_, io::Error>(())
        }).await.unwrap();
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    }

}
