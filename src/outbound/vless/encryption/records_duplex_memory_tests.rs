// Synthetic full-1rtt Records handoff; no resumption or direct mode. The
// existing Go KDF/cipher vector is a control, not a new nonce4/5 Go vector.
#[derive(Default)]
struct NativeDuplexState {
    block_writes: bool,
    write_allowance: Option<usize>,
    write_error: Option<io::ErrorKind>,
    block_reads: bool,
    pending_read_polls: usize,
    first_read_output_len: Option<usize>,
    raw_write_pulses: usize,
    read_waker: Option<std::task::Waker>,
    output: Vec<u8>,
    read_polls: usize,
    pending_write_polls: usize,
    flush_polls: usize,
    shutdown_polls: usize,
    remaining_input: usize,
    write_waker: Option<std::task::Waker>,
    dropped: bool,
}
struct NativeDuplexRaw {
    input: Vec<u8>,
    read: usize,
    state: Arc<Mutex<NativeDuplexState>>,
}
impl Drop for NativeDuplexRaw {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.write_waker.take();
        state.read_waker.take();
        state.dropped = true;
    }
}
impl AsyncRead for NativeDuplexRaw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.state.lock().unwrap();
        state.read_polls += 1;
        if state.first_read_output_len.is_none() {
            state.first_read_output_len = Some(state.output.len());
        }
        if state.block_reads {
            state.pending_read_polls += 1;
            state.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = output.remaining().min(this.input.len() - this.read);
        output.put_slice(&this.input[this.read..this.read + count]);
        this.read += count;
        state.remaining_input = this.input.len() - this.read;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for NativeDuplexRaw {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.lock().unwrap();
        if let Some(kind) = state.write_error {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        if state.block_writes || state.write_allowance == Some(0) {
            state.pending_write_polls += 1;
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = state
            .write_allowance
            .unwrap_or(input.len())
            .min(input.len());
        state.output.extend_from_slice(&input[..count]);
        if let Some(allowance) = &mut state.write_allowance {
            *allowance -= count;
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().flush_polls += 1;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().shutdown_polls += 1;
        Poll::Ready(Ok(()))
    }
}
struct NativeDuplexReport {
    vector_ok: bool,
    bootstrap_ok: bool,
    metadata_accepted: bool,
    metadata_flushed: bool,
    metadata_wire_ok: bool,
    response_header_ok: bool,
    native_header_state: bool,
    rx_available_before: bool,
    app_accepted: bool,
    tx_flush_pending: bool,
    raw_tx_pending: bool,
    tx_unchanged: bool,
    raw_dropped: bool,
    waker_released: bool,
    read_polls_before: usize,
    read_polls_after: usize,
    read: Poll<io::Result<()>>,
    actual: Vec<u8>,
    expected: Vec<u8>,
}
fn native_duplex_frame(peer: &mut Aead, plain: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(plain.len() + 16).map_err(|_| failure())?;
    let header = [23, 3, 3, (length >> 8) as u8, length as u8];
    let mut wire = header.to_vec();
    wire.extend_from_slice(&peer.seal(plain, &header, None)?);
    Ok(wire)
}
struct NativeDuplexFixture {
    stream: Records,
    state: Arc<Mutex<NativeDuplexState>>,
    metadata: bytes::Bytes,
    expected_metadata_wire: Vec<u8>,
    expected: Vec<u8>,
    vector_ok: bool,
    bootstrap_ok: bool,
}
fn native_duplex_fixture(
    v: &serde_json::Value,
    buffered_plain: bool,
) -> io::Result<NativeDuplexFixture> {
    let material: [u8; 96] = bytes(&v["key"]).try_into().map_err(|_| failure())?;
    let rx_context = bytes(&v["context"]);
    let tx_context = b"native-full1rtt-duplex-upload-context";
    let suite = if v["cipher"] == "aes256gcm" {
        Suite::Aes
    } else {
        Suite::ChaCha
    };
    let expected = bytes(&v["plaintext"]);
    let mut known = Aead::new(&rx_context, &material, suite)?;
    let nonce = bytes(&v["nonce"]).try_into().map_err(|_| failure())?;
    let vector_ok =
        known.seal(&expected, &bytes(&v["aad"]), Some(nonce))? == bytes(&v["ciphertext"]);

    // Mirror Handshake::finish's authenticated RX handoff: ticket nonce1,
    // length nonce2, then Records::new consumes padding nonce3. New DATA
    // starts at nonce4. Never seed/set a nonce or use Records::resumed.
    let mut peer_tx = Aead::new(&rx_context, &material, suite)?;
    let ticket = [0_u8; 16]; // Zero lifetime, uncached1rtt.
    let ticket_wire = peer_tx.seal(&ticket, &[], None)?;
    let padding = [0_u8; 1];
    let padding_size = u16::try_from(padding.len() + 16).map_err(|_| failure())?;
    let length_wire = peer_tx.seal(&padding_size.to_be_bytes(), &[], None)?;
    let padding_wire = peer_tx.seal(&padding, &[], None)?;
    let mut rx = Aead::new(&rx_context, &material, suite)?;
    let decoded_ticket = rx.open(&ticket_wire, &[], None)?;
    let decoded_length = rx.open(&length_wire, &[], None)?;
    let bootstrap_ok = decoded_ticket == ticket
        && decoded_length == padding_size.to_be_bytes()
        && padding_wire.len() == usize::from(padding_size);
    let mut first_plain = vec![0, 0]; // Ordinary VLESS response, no addons.
    if buffered_plain {
        first_plain.extend_from_slice(&expected);
    }
    let mut input = padding_wire;
    input.extend_from_slice(&native_duplex_frame(&mut peer_tx, &first_plain)?);
    if !buffered_plain {
        input.extend_from_slice(&native_duplex_frame(&mut peer_tx, &expected)?);
    }
    let target = crate::session::Destination::Ip("192.0.2.9:443".parse().unwrap());
    let metadata = crate::outbound::vless::codec::encode_request_header(
        uuid::Uuid::from_bytes([7; 16]),
        crate::outbound::vless::codec::VlessCommand::Tcp,
        Some(&target),
    )?;
    let mut peer_rx = Aead::new(tx_context, &material, suite)?;
    let expected_metadata_wire = native_duplex_frame(&mut peer_rx, &metadata)?;
    let state = Arc::new(Mutex::new(NativeDuplexState {
        remaining_input: input.len(),
        ..Default::default()
    }));
    let stream = Records::new(
        Box::new(NativeDuplexRaw {
            input,
            read: 0,
            state: state.clone(),
        }),
        Zeroizing::new(material),
        suite,
        Aead::new(tx_context, &material, suite)?,
        rx,
        None,
        None,
        usize::from(padding_size),
        Arc::new(Cache::default()),
        None,
    );
    Ok(NativeDuplexFixture {
        stream,
        state,
        metadata,
        expected_metadata_wire,
        expected,
        vector_ok,
        bootstrap_ok,
    })
}
fn native_duplex_case(
    v: &serde_json::Value,
    buffered_plain: bool,
) -> io::Result<NativeDuplexReport> {
    let NativeDuplexFixture {
        mut stream,
        state,
        metadata,
        expected_metadata_wire,
        expected,
        vector_ok,
        bootstrap_ok,
    } = native_duplex_fixture(v, buffered_plain)?;
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let metadata_accepted = matches!(
        Pin::new(&mut stream).poll_write(&mut cx, &metadata),
        Poll::Ready(Ok(count)) if count == metadata.len()
    );
    let metadata_flushed = matches!(
        Pin::new(&mut stream).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    );
    let metadata_wire_ok = state.lock().unwrap().output == expected_metadata_wire;
    let mut response_header = [255_u8; 2];
    let response_header_poll = {
        let mut output = ReadBuf::new(&mut response_header);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut output);
        matches!(result, Poll::Ready(Ok(()))) && output.filled().len() == 2
    };
    let response_header_ok = response_header_poll && response_header == [0, 0];
    let native_header_state = matches!(stream.reading, Reading::Header)
        && stream.filled == 0
        && stream.input.len() == 5
        && stream.rx.is_some()
        && stream.tx_ctr.is_none()
        && stream.rx_ctr.is_none()
        && stream.ticket.is_none();
    let rx_available_before = if buffered_plain {
        stream.plain[stream.consumed..] == expected
    } else {
        stream.plain.len() == stream.consumed
            && state.lock().unwrap().remaining_input == expected.len() + 21
    };
    state.lock().unwrap().block_writes = true;
    let app = b"queued app TX must not gate readable RX";
    let app_accepted = matches!(
        Pin::new(&mut stream).poll_write(&mut cx, app),
        Poll::Ready(Ok(count)) if count == app.len()
    );
    let tx_flush_pending = Pin::new(&mut stream).poll_flush(&mut cx).is_pending();
    let raw_tx_pending = {
        let state = state.lock().unwrap();
        state.pending_write_polls > 0 && state.write_waker.is_some()
    };
    let pending_before = stream.pending.clone();
    let sent_before = stream.sent;
    let read_polls_before = state.lock().unwrap().read_polls;
    let mut buffer = vec![0; expected.len()];
    let (read, actual) = {
        let mut output = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut output);
        (result, output.filled().to_vec())
    };
    let tx_unchanged = pending_before.len() == app.len() + 21
        && sent_before == 0
        && stream.pending == pending_before
        && stream.sent == sent_before
        && state.lock().unwrap().output == expected_metadata_wire;
    let read_polls_after = state.lock().unwrap().read_polls;
    // No future, socket, background owner or real-time wait exists here.
    // Drop Records/raw and release its registered waker BEFORE any verdict.
    drop(stream);
    let (raw_dropped, waker_released) = {
        let state = state.lock().unwrap();
        (
            state.dropped,
            state.write_waker.is_none() && state.read_waker.is_none(),
        )
    };
    drop(state);
    Ok(NativeDuplexReport {
        vector_ok,
        bootstrap_ok,
        metadata_accepted,
        metadata_flushed,
        metadata_wire_ok,
        response_header_ok,
        native_header_state,
        rx_available_before,
        app_accepted,
        tx_flush_pending,
        raw_tx_pending,
        tx_unchanged,
        raw_dropped,
        waker_released,
        read_polls_before,
        read_polls_after,
        read,
        actual,
        expected,
    })
}
fn native_duplex_controls(report: &NativeDuplexReport) {
    assert!(report.raw_dropped && report.waker_released);
    assert!(report.vector_ok && report.bootstrap_ok);
    assert!(report.metadata_accepted && report.metadata_flushed && report.metadata_wire_ok);
    assert!(report.response_header_ok && report.native_header_state);
    assert!(report.rx_available_before && report.app_accepted);
    assert!(report.tx_flush_pending && report.raw_tx_pending && report.tx_unchanged);
}
#[test]
fn native_full1rtt_authenticated_plain_remainder_progresses_with_tx_blocked() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let report = native_duplex_case(&group[0], true)?;
        native_duplex_controls(&report);
        // Old production must pass every control above and fail this actual
        // single-poll liveness assertion, never a missing field/API.
        assert!(
            matches!(&report.read, Poll::Ready(Ok(()))),
            "authenticated plaintext was held behind unrelated pending TX"
        );
        assert_eq!(report.actual, report.expected);
        assert_eq!(report.read_polls_after, report.read_polls_before);
    }
    Ok(())
}
#[test]
fn native_full1rtt_ready_ciphertext_progresses_with_tx_blocked() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let report = native_duplex_case(&group[0], false)?;
        native_duplex_controls(&report);
        assert!(
            matches!(&report.read, Poll::Ready(Ok(()))),
            "ready authenticated peer direction was held behind unrelated pending TX"
        );
        assert_eq!(report.actual, report.expected);
        assert!(report.read_polls_after > report.read_polls_before);
    }
    Ok(())
}

struct NativeCallerWake(std::sync::atomic::AtomicUsize);
impl std::task::Wake for NativeCallerWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
struct NativeCallers {
    a: Arc<NativeCallerWake>,
    b: Arc<NativeCallerWake>,
    wa: std::task::Waker,
    wb: std::task::Waker,
}
impl NativeCallers {
    fn new() -> Self {
        let a = Arc::new(NativeCallerWake(std::sync::atomic::AtomicUsize::new(0)));
        let b = Arc::new(NativeCallerWake(std::sync::atomic::AtomicUsize::new(0)));
        Self {
            wa: std::task::Waker::from(a.clone()),
            wb: std::task::Waker::from(b.clone()),
            a,
            b,
        }
    }
    fn counts(&self) -> [usize; 2] {
        [
            self.a.0.load(Ordering::SeqCst),
            self.b.0.load(Ordering::SeqCst),
        ]
    }
}
fn native_raw_write_ready(state: &Arc<Mutex<NativeDuplexState>>, notify: bool) -> bool {
    let wake = {
        let mut state = state.lock().unwrap();
        state.block_writes = false;
        if notify {
            let wake = state.write_waker.take();
            if wake.is_some() {
                state.raw_write_pulses += 1;
            }
            wake
        } else {
            None
        }
    };
    if let Some(wake) = wake {
        wake.wake();
        true
    } else {
        false
    }
}
fn native_wake_close(
    stream: Records,
    state: Arc<Mutex<NativeDuplexState>>,
    callers: NativeCallers,
) -> (bool, bool) {
    let raw_weak = Arc::downgrade(&state);
    let a_weak = Arc::downgrade(&callers.a);
    let b_weak = Arc::downgrade(&callers.b);
    drop(stream);
    let raw_closed = {
        let state = state.lock().unwrap();
        state.dropped && state.write_waker.is_none() && state.read_waker.is_none()
    };
    drop(state);
    drop(callers);
    let weak_closed =
        raw_weak.upgrade().is_none() && a_weak.upgrade().is_none() && b_weak.upgrade().is_none();
    (raw_closed, weak_closed)
}
fn native_wake_fixture(
    v: &serde_json::Value,
    buffered_plain: bool,
    drain_payload: bool,
) -> io::Result<(NativeDuplexFixture, bool)> {
    native_warm_fixture(native_duplex_fixture(v, buffered_plain)?, drain_payload)
}
fn native_warm_fixture(
    mut fixture: NativeDuplexFixture,
    drain_payload: bool,
) -> io::Result<(NativeDuplexFixture, bool)> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let accepted = matches!(
        Pin::new(&mut fixture.stream).poll_write(&mut cx, &fixture.metadata),
        Poll::Ready(Ok(count)) if count == fixture.metadata.len()
    );
    let flushed = matches!(
        Pin::new(&mut fixture.stream).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    );
    let mut header = [255_u8; 2];
    let header_ok = {
        let mut output = ReadBuf::new(&mut header);
        let read = Pin::new(&mut fixture.stream).poll_read(&mut cx, &mut output);
        matches!(read, Poll::Ready(Ok(()))) && output.filled().len() == 2
    };
    let payload_ok = if drain_payload {
        let mut bytes = vec![0; fixture.expected.len()];
        let mut output = ReadBuf::new(&mut bytes);
        let read = Pin::new(&mut fixture.stream).poll_read(&mut cx, &mut output);
        matches!(read, Poll::Ready(Ok(()))) && output.filled() == fixture.expected.as_slice()
    } else {
        true
    };
    let warm = fixture.vector_ok
        && fixture.bootstrap_ok
        && accepted
        && flushed
        && header_ok
        && header == [0, 0]
        && payload_ok
        && fixture.state.lock().unwrap().output == fixture.expected_metadata_wire
        && fixture.stream.pending.is_empty()
        && fixture.stream.sent == 0
        && fixture.stream.rx.is_some()
        && matches!(fixture.stream.reading, Reading::Header);
    Ok((fixture, warm))
}

#[test]
fn native_full1rtt_raw_tx_ready_wakes_both_independent_pending_callers() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let (mut fixture, warm) = native_wake_fixture(&group[0], false, true)?;
        let callers = NativeCallers::new();
        let app = b"queued writer A business bytes";
        {
            let mut state = fixture.state.lock().unwrap();
            state.block_writes = true;
            state.block_reads = true;
        }
        let accepted = matches!(
            Pin::new(&mut fixture.stream).poll_write(&mut Context::from_waker(&callers.wa), app),
            Poll::Ready(Ok(count)) if count == app.len()
        );
        let writer_pending = Pin::new(&mut fixture.stream)
            .poll_flush(&mut Context::from_waker(&callers.wa))
            .is_pending();
        let pending_cipher = fixture.stream.pending.clone();
        let mut bytes = [0_u8; 1];
        let (reader_pending, no_plain) = {
            let mut output = ReadBuf::new(&mut bytes);
            let read = Pin::new(&mut fixture.stream)
                .poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read.is_pending(), output.filled().is_empty())
        };
        let before_pulse = callers.counts();
        let control = {
            let state = fixture.state.lock().unwrap();
            state.block_reads
                && state.remaining_input == 0
                && state.pending_write_polls > 0
                && state.write_waker.is_some()
        };
        let fired = native_raw_write_ready(&fixture.state, true);
        // Capture the READY event now. Drop's wake cannot satisfy liveness.
        let at_pulse = callers.counts();
        let read_pending_polls = fixture.state.lock().unwrap().pending_read_polls;
        let untouched = fixture.stream.pending == pending_cipher
            && fixture.stream.sent == 0
            && fixture.state.lock().unwrap().output == fixture.expected_metadata_wire;
        let NativeDuplexFixture { stream, state, .. } = fixture;
        let closed = native_wake_close(stream, state, callers);
        assert!(closed.0 && closed.1);
        assert!(warm && accepted && writer_pending && reader_pending && no_plain && control);
        assert_eq!(before_pulse, [0, 0]);
        assert!(fired && untouched);
        assert!(
            at_pulse[0] > 0 && at_pulse[1] > 0,
            "one raw TX readiness event stranded an independently pending caller"
        );
        assert!(read_pending_polls > 0);
    }
    Ok(())
}

#[test]
fn native_full1rtt_read_assisted_drain_wakes_writer_without_raw_event() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let (mut fixture, warm) = native_wake_fixture(&group[0], true, false)?;
        let callers = NativeCallers::new();
        fixture.state.lock().unwrap().block_writes = true;
        let app = b"writer A waits while reader B can assist";
        let accepted = matches!(
            Pin::new(&mut fixture.stream).poll_write(&mut Context::from_waker(&callers.wa), app),
            Poll::Ready(Ok(count)) if count == app.len()
        );
        let writer_pending = Pin::new(&mut fixture.stream)
            .poll_flush(&mut Context::from_waker(&callers.wa))
            .is_pending();
        let pending_cipher = fixture.stream.pending.clone();
        let raw_waiting = fixture.state.lock().unwrap().write_waker.is_some();
        let no_pulse = !native_raw_write_ready(&fixture.state, false);
        let before_assist = callers.counts();
        let mut bytes = vec![0_u8; fixture.expected.len()];
        let (read, actual) = {
            let mut output = ReadBuf::new(&mut bytes);
            let read = Pin::new(&mut fixture.stream)
                .poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read, output.filled().to_vec())
        };
        // Snapshot BEFORE Drop, which is permitted to wake both slots.
        let at_assist = callers.counts();
        let expected_wire = [fixture.expected_metadata_wire.clone(), pending_cipher].concat();
        let drained = fixture.stream.pending.is_empty()
            && fixture.stream.sent == 0
            && fixture.state.lock().unwrap().output == expected_wire;
        let raw_pulses = fixture.state.lock().unwrap().raw_write_pulses;
        let expected = fixture.expected.clone();
        let NativeDuplexFixture { stream, state, .. } = fixture;
        let closed = native_wake_close(stream, state, callers);
        assert!(closed.0 && closed.1);
        assert!(warm && accepted && writer_pending && raw_waiting && no_pulse);
        assert_eq!(before_assist, [0, 0]);
        assert_eq!(raw_pulses, 0);
        assert!(matches!(&read, Poll::Ready(Ok(()))) && drained);
        assert_eq!(actual, expected);
        assert!(
            at_assist[0] > 0,
            "read completed the queued TX without waking its pending writer"
        );
    }
    Ok(())
}

#[test]
fn resumed_opaque_prefix_blocks_rx_until_sent_then_business_tx_is_duplex() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let v = &group[0];
        let key: [u8; 96] = bytes(&v["key"]).try_into().map_err(|_| failure())?;
        let suite = if v["cipher"] == "aes256gcm" {
            Suite::Aes
        } else {
            Suite::ChaCha
        };
        let context = bytes(&v["context"]);
        let expected_first = bytes(&v["plaintext"]);
        let expected_second = bytes(&group[1]["plaintext"]);
        let prefix = b"opaque-owned-resumption-prefix-not-a-handshake-vector".to_vec();
        let input = [context.clone(), wire(v), wire(&group[1])].concat();
        let state = Arc::new(Mutex::new(NativeDuplexState {
            block_writes: true,
            remaining_input: input.len(),
            ..Default::default()
        }));
        let mut stream = Records::resumed(
            Box::new(NativeDuplexRaw {
                input,
                read: 0,
                state: state.clone(),
            }),
            Zeroizing::new(key),
            suite,
            Aead::new(&context, &key, suite)?,
            None,
            false,
            prefix.clone(),
            Arc::new(Cache::default()),
            Arc::new(Ticket {
                pfs: Zeroizing::new([0; 64]),
                bytes: Zeroizing::new([0; 16]),
                expires: tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            }),
        );
        let callers = NativeCallers::new();
        let prefix_flush_pending = Pin::new(&mut stream)
            .poll_flush(&mut Context::from_waker(&callers.wa))
            .is_pending();
        let mut first = vec![0_u8; expected_first.len()];
        let (prefix_read_pending, no_early_plain) = {
            let mut output = ReadBuf::new(&mut first);
            let read =
                Pin::new(&mut stream).poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read.is_pending(), output.filled().is_empty())
        };
        let prefix_held = {
            let state = state.lock().unwrap();
            state.read_polls == 0
                && state.first_read_output_len.is_none()
                && state.remaining_input > 0
                && state.output.is_empty()
                && stream.pending == prefix
                && stream.sent == 0
                && stream.rx.is_none()
        };
        let prefix_ready_fired = native_raw_write_ready(&state, true);
        let (first_read, first_actual) = {
            let mut output = ReadBuf::new(&mut first);
            let read =
                Pin::new(&mut stream).poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read, output.filled().to_vec())
        };
        let prefix_sent_once = {
            let state = state.lock().unwrap();
            state.output == prefix
                && state.first_read_output_len == Some(prefix.len())
                && stream.pending.is_empty()
                && stream.sent == 0
                && stream.rx.is_some()
        };
        state.lock().unwrap().block_writes = true;
        let app = b"ordinary accepted business record after the prefix";
        let accepted = matches!(
            Pin::new(&mut stream).poll_write(&mut Context::from_waker(&callers.wa), app),
            Poll::Ready(Ok(count)) if count == app.len()
        );
        let business_flush_pending = Pin::new(&mut stream)
            .poll_flush(&mut Context::from_waker(&callers.wa))
            .is_pending();
        let business_cipher = stream.pending.clone();
        let ready_cipher = state.lock().unwrap().remaining_input == wire(&group[1]).len();
        let mut second = vec![0_u8; expected_second.len()];
        let (second_read, second_actual) = {
            let mut output = ReadBuf::new(&mut second);
            let read =
                Pin::new(&mut stream).poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read, output.filled().to_vec())
        };
        let business_unchanged = stream.pending == business_cipher
            && stream.sent == 0
            && state.lock().unwrap().output == prefix;
        let closed = native_wake_close(stream, state, callers);
        assert!(closed.0 && closed.1);
        // Opaque prefix tests only ownership/order, not a complete0rtt handshake.
        assert!(prefix_flush_pending && prefix_read_pending && no_early_plain && prefix_held);
        assert!(prefix_ready_fired && prefix_sent_once);
        assert!(matches!(&first_read, Poll::Ready(Ok(()))));
        assert_eq!(first_actual, expected_first);
        assert!(accepted && business_flush_pending && ready_cipher && business_unchanged);
        assert!(
            matches!(&second_read, Poll::Ready(Ok(()))),
            "established resumed RX still waited for unrelated business TX"
        );
        assert_eq!(second_actual, expected_second);
    }
    Ok(())
}

#[test]
fn resumed_partial_opaque_prefix_survives_cancelled_flush_and_read_assist() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let v = &group[0];
        let key: [u8; 96] = bytes(&v["key"]).try_into().map_err(|_| failure())?;
        let suite = if v["cipher"] == "aes256gcm" {
            Suite::Aes
        } else {
            Suite::ChaCha
        };
        let context = bytes(&v["context"]);
        let expected_first = bytes(&v["plaintext"]);
        let expected_second = bytes(&group[1]["plaintext"]);
        let prefix = b"opaque-partial-resumption-prefix-owned-by-test".to_vec();
        let input = [context.clone(), wire(v), wire(&group[1])].concat();
        let state = Arc::new(Mutex::new(NativeDuplexState {
            write_allowance: Some(7),
            remaining_input: input.len(),
            ..Default::default()
        }));
        let mut stream = Records::resumed(
            Box::new(NativeDuplexRaw {
                input,
                read: 0,
                state: state.clone(),
            }),
            Zeroizing::new(key),
            suite,
            Aead::new(&context, &key, suite)?,
            None,
            false,
            prefix.clone(),
            Arc::new(Cache::default()),
            Arc::new(Ticket {
                pfs: Zeroizing::new([0; 64]),
                bytes: Zeroizing::new([0; 16]),
                expires: tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            }),
        );
        let callers = NativeCallers::new();
        let cancelled_flush_pending = {
            let mut flush = Box::pin(stream.flush());
            let pending =
                std::future::Future::poll(flush.as_mut(), &mut Context::from_waker(&callers.wa))
                    .is_pending();
            // Cancel only this borrow/future, preserving the Records owner.
            drop(flush);
            pending
        };
        let mut first = vec![0_u8; expected_first.len()];
        let prefix_read_pending = {
            let mut output = ReadBuf::new(&mut first);
            let read =
                Pin::new(&mut stream).poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            read.is_pending() && output.filled().is_empty()
        };
        let partial_held = {
            let raw = state.lock().unwrap();
            raw.output.as_slice() == &prefix[..7]
                && raw.read_polls == 0
                && raw.first_read_output_len.is_none()
                && raw.remaining_input > 0
                && stream.pending == prefix
                && stream.sent == 7
                && stream.rx.is_none()
        };
        state.lock().unwrap().write_allowance = None;
        // No raw wake/event: the reader itself must resume the exact offset.
        let no_raw_pulse = !native_raw_write_ready(&state, false);
        let (first_read, first_actual) = {
            let mut output = ReadBuf::new(&mut first);
            let read =
                Pin::new(&mut stream).poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read, output.filled().to_vec())
        };
        let prefix_sent_once = {
            let raw = state.lock().unwrap();
            raw.output == prefix
                && raw.first_read_output_len == Some(prefix.len())
                && stream.pending.is_empty()
                && stream.sent == 0
                && stream.rx.is_some()
        };
        state.lock().unwrap().block_writes = true;
        let app = b"ordinary business TX after a partially sent prefix";
        let accepted = matches!(
            Pin::new(&mut stream).poll_write(&mut Context::from_waker(&callers.wa), app),
            Poll::Ready(Ok(count)) if count == app.len()
        );
        let business_flush_pending = Pin::new(&mut stream)
            .poll_flush(&mut Context::from_waker(&callers.wa))
            .is_pending();
        let business_cipher = stream.pending.clone();
        let ready_cipher = state.lock().unwrap().remaining_input == wire(&group[1]).len();
        let mut second = vec![0_u8; expected_second.len()];
        let (second_read, second_actual) = {
            let mut output = ReadBuf::new(&mut second);
            let read =
                Pin::new(&mut stream).poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read, output.filled().to_vec())
        };
        let business_unchanged = stream.pending == business_cipher
            && stream.sent == 0
            && state.lock().unwrap().output == prefix;
        let closed = native_wake_close(stream, state, callers);
        // Opaque prefix is an ownership/order seam, not a full0rtt handshake.
        assert!(closed.0 && closed.1);
        assert!(cancelled_flush_pending && prefix_read_pending && partial_held);
        assert!(no_raw_pulse && prefix_sent_once);
        assert!(matches!(&first_read, Poll::Ready(Ok(()))));
        assert_eq!(first_actual, expected_first);
        assert!(accepted && business_flush_pending && ready_cipher && business_unchanged);
        assert!(
            matches!(&second_read, Poll::Ready(Ok(()))),
            "partial prefix left an established stream permanently RX-blocked"
        );
        assert_eq!(second_actual, expected_second);
    }
    Ok(())
}

#[test]
fn native_full1rtt_ready_tx_error_precedes_buffered_plain_and_preserves_new_ticket()
-> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let fixture = native_duplex_fixture(&group[0], true)?;
        let (fixture, warm) = native_warm_fixture(fixture, false)?;
        let NativeDuplexFixture {
            mut stream,
            state,
            expected,
            expected_metadata_wire,
            ..
        } = fixture;
        let cache = stream.cache.clone();
        // The real authenticated-body path has no live stream ticket here.
        // Do not manufacture buffered plaintext plus an unconsumed ticket.
        let authenticated_cache_open = stream.ticket.is_none()
            && cache.lookup()?.is_none()
            && !cache.cancellation.is_cancelled();
        let buffered_authenticated_plain = stream.plain.get(stream.consumed..)
            == Some(expected.as_slice())
            && state.lock().unwrap().remaining_input == 0;
        let newer = Arc::new(Ticket {
            pfs: Zeroizing::new([0; 64]),
            bytes: Zeroizing::new([1; 16]),
            expires: tokio::time::Instant::now() + std::time::Duration::from_secs(60),
        });
        cache.publish(newer.clone())?;
        let callers = NativeCallers::new();
        let app = b"accepted business TX must report its ready transport error";
        let accepted = matches!(
            Pin::new(&mut stream).poll_write(&mut Context::from_waker(&callers.wa), app),
            Poll::Ready(Ok(count)) if count == app.len()
        );
        let pending_business = !stream.pending.is_empty() && stream.sent == 0;
        state.lock().unwrap().write_error = Some(io::ErrorKind::ConnectionReset);
        let mut bytes = vec![0_u8; expected.len()];
        let (read, leaked) = {
            let mut output = ReadBuf::new(&mut bytes);
            let read =
                Pin::new(&mut stream).poll_read(&mut Context::from_waker(&callers.wb), &mut output);
            (read, output.filled().to_vec())
        };
        let error_kind = match &read {
            Poll::Ready(Err(error)) => Some(error.kind()),
            _ => None,
        };
        let failure_closed_raw = stream.raw.is_none()
            && stream.pending.is_empty()
            && stream.input.is_empty()
            && state.lock().unwrap().dropped;
        let exact_wire = state.lock().unwrap().output == expected_metadata_wire;
        let newer_retained = cache
            .lookup()?
            .is_some_and(|current| Arc::ptr_eq(&current, &newer));
        let newer_weak = Arc::downgrade(&newer);
        let closed = native_wake_close(stream, state, callers);
        drop(cache);
        drop(newer);
        let tickets_closed = newer_weak.upgrade().is_none();
        assert!(closed.0 && closed.1 && tickets_closed);
        assert!(
            warm && buffered_authenticated_plain
                && authenticated_cache_open
                && accepted
                && pending_business
        );
        assert_eq!(
            error_kind,
            Some(io::ErrorKind::ConnectionReset),
            "ready TX error was hidden behind authenticated buffered plaintext"
        );
        assert!(leaked.is_empty() && failure_closed_raw && exact_wire && newer_retained);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum NativeCancelOperation {
    ReadReady,
    FlushReady,
    HalfShutdownReady,
}
#[derive(Debug)]
struct NativeCancelReport {
    controls: bool,
    before_cancel: [usize; 2],
    at_cancel: [usize; 2],
    raw_pulses: usize,
    closed: (bool, bool),
}
fn native_guarded_cancel_case(
    v: &serde_json::Value,
    operation: NativeCancelOperation,
) -> io::Result<NativeCancelReport> {
    let mut fixture = native_duplex_fixture(v, false)?;
    let cache = fixture.stream.cache.clone();
    let raw = fixture.stream.raw.take().ok_or_else(failure)?;
    // The actual handshake guard uses a CHILD token: dropping one stream
    // must not cancel its node/siblings. Install it before metadata/RX setup.
    fixture.stream.raw = Some(Box::new(crate::outbound::owned_stream::OwnedStream::new(
        raw,
        cache.cancellation.child_token(),
    )));
    let drain_payload = !matches!(operation, NativeCancelOperation::ReadReady);
    let (fixture, warm) = native_warm_fixture(fixture, drain_payload)?;
    let NativeDuplexFixture {
        mut stream,
        state,
        expected,
        ..
    } = fixture;
    let callers = NativeCallers::new();
    let operation_ok = match operation {
        NativeCancelOperation::ReadReady => {
            state.lock().unwrap().block_writes = true;
            let app = b"writer A waits while completed reader B overwrites cancel context";
            let accepted = matches!(
                Pin::new(&mut stream).poll_write(&mut Context::from_waker(&callers.wa), app),
                Poll::Ready(Ok(count)) if count == app.len()
            );
            let writer_pending = Pin::new(&mut stream)
                .poll_flush(&mut Context::from_waker(&callers.wa))
                .is_pending();
            let read_before = state.lock().unwrap().read_polls;
            let mut bytes = vec![0; expected.len()];
            let read_ready = {
                let mut output = ReadBuf::new(&mut bytes);
                let read = Pin::new(&mut stream)
                    .poll_read(&mut Context::from_waker(&callers.wb), &mut output);
                matches!(read, Poll::Ready(Ok(()))) && output.filled() == expected.as_slice()
            }; // Completed reader/context is gone; it is never polled again.
            let raw = state.lock().unwrap();
            accepted
                && writer_pending
                && read_ready
                && raw.read_polls > read_before
                && raw.block_writes
                && raw.pending_write_polls > 0
        }
        NativeCancelOperation::FlushReady | NativeCancelOperation::HalfShutdownReady => {
            if matches!(operation, NativeCancelOperation::HalfShutdownReady) {
                let control = SpliceControl::default();
                control.write_direct();
                stream = stream.with_vision(Some((control, Arc::default())));
            }
            state.lock().unwrap().block_reads = true;
            let mut bytes = [0_u8; 1];
            let reader_pending = {
                let mut output = ReadBuf::new(&mut bytes);
                let read = Pin::new(&mut stream)
                    .poll_read(&mut Context::from_waker(&callers.wa), &mut output);
                read.is_pending() && output.filled().is_empty()
            };
            let (flush_before, shutdown_before) = {
                let raw = state.lock().unwrap();
                (raw.flush_polls, raw.shutdown_polls)
            };
            let ready = if matches!(operation, NativeCancelOperation::FlushReady) {
                Pin::new(&mut stream).poll_flush(&mut Context::from_waker(&callers.wb))
            } else {
                Pin::new(&mut stream).poll_shutdown(&mut Context::from_waker(&callers.wb))
            };
            let raw = state.lock().unwrap();
            let raw_operation = if matches!(operation, NativeCancelOperation::FlushReady) {
                raw.flush_polls > flush_before && !stream.write_closed
            } else {
                raw.shutdown_polls > shutdown_before && stream.write_closed
            };
            reader_pending
                && matches!(ready, Poll::Ready(Ok(())))
                && raw_operation
                && raw.pending_read_polls > 0
                && stream.pending.is_empty()
                && stream.raw.is_some()
                && !raw.dropped
        }
    };
    let before_cancel = callers.counts();
    let cache_open = !cache.cancellation.is_cancelled();
    cache.close();
    // This immutable snapshot is the cancel event, BEFORE Records/IO Drop.
    // Drop may wake both waiter slots, so postmortem counts are never proof.
    let at_cancel = callers.counts();
    let raw_pulses = state.lock().unwrap().raw_write_pulses;
    let closed = native_wake_close(stream, state, callers);
    drop(cache);
    Ok(NativeCancelReport {
        controls: warm && operation_ok && cache_open,
        before_cancel,
        at_cancel,
        raw_pulses,
        closed,
    })
}
fn native_guarded_cancel_verdict(report: &NativeCancelReport) {
    assert!(report.closed.0 && report.closed.1, "owners: {report:?}");
    assert!(
        report.controls,
        "invalid cancellation prerequisite: {report:?}"
    );
    assert_eq!(report.raw_pulses, 0);
    // A was still awaiting IO, with no earlier wake in lieu of this event.
    assert_eq!(
        report.before_cancel[0], 0,
        "already-notified control: {report:?}"
    );
    assert!(
        report.at_cancel[0] > report.before_cancel[0],
        "node cancellation stranded the pending caller: {report:?}"
    );
}
#[test]
fn native_full1rtt_owned_raw_rx_ready_preserves_writer_cancel_wake() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let report = native_guarded_cancel_case(&group[0], NativeCancelOperation::ReadReady)?;
        native_guarded_cancel_verdict(&report);
    }
    Ok(())
}
#[test]
fn native_full1rtt_owned_raw_flush_ready_preserves_reader_cancel_wake() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let report = native_guarded_cancel_case(&group[0], NativeCancelOperation::FlushReady)?;
        native_guarded_cancel_verdict(&report);
    }
    Ok(())
}
#[test]
fn native_full1rtt_owned_raw_half_shutdown_preserves_reader_cancel_wake() -> io::Result<()> {
    for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
        let report =
            native_guarded_cancel_case(&group[0], NativeCancelOperation::HalfShutdownReady)?;
        native_guarded_cancel_verdict(&report);
    }
    Ok(())
}

// Real H2 framing/flow-control over paired record layers, NOT a KEM/VLESS handshake.
mod native_h2_duplex_memory {
    use super::*;
    use futures_util::{StreamExt as _, stream::FuturesUnordered};
    use tokio::io::DuplexStream;
    #[derive(Default)]
    struct Counts {
        incoming: [usize; 2],
        read: [usize; 2],
        pending: usize,
        witness: usize,
        live: usize,
        underflow: bool,
        active: bool,
    }
    struct Raw {
        io: DuplexStream,
        side: usize,
        counts: Arc<Mutex<Counts>>,
    }
    impl Drop for Raw {
        fn drop(&mut self) {
            self.counts.lock().unwrap().live -= 1;
        }
    }
    impl AsyncRead for Raw {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = out.filled().len();
            let result = Pin::new(&mut self.io).poll_read(cx, out);
            let read = out.filled().len() - before;
            let mut counts = self.counts.lock().unwrap();
            counts.read[self.side] += read;
            if let Some(left) = counts.incoming[self.side].checked_sub(read) {
                counts.incoming[self.side] = left;
            } else {
                counts.underflow = true;
            }
            result
        }
    }
    impl AsyncWrite for Raw {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let result = Pin::new(&mut self.io).poll_write(cx, bytes);
            let mut counts = self.counts.lock().unwrap();
            match &result {
                Poll::Ready(Ok(written)) => counts.incoming[1 - self.side] += *written,
                Poll::Pending => {
                    counts.pending += 1;
                    if counts.active
                        && counts.read[self.side] >= 16
                        && counts.incoming[self.side] != 0
                    {
                        counts.witness += 1;
                    }
                }
                _ => {}
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }
    fn err(error: impl std::fmt::Display) -> String {
        error.to_string()
    }
    async fn receive(mut body: h2::RecvStream, expected: u8) -> Result<(), String> {
        let mut total = 0;
        while let Some(data) = body.data().await {
            let data = data.map_err(err)?;
            total += data.len();
            if total > 65536 || data.iter().any(|byte| *byte != expected) {
                return Err("incorrect synthetic H2 entity".into());
            }
            body.flow_control()
                .release_capacity(data.len())
                .map_err(err)?;
        }
        if total != 65536 || body.trailers().await.map_err(err)?.is_some() {
            return Err("incomplete or unexpected H2 entity trailers".into());
        }
        Ok(())
    }
    async fn serve(
        raw: Records,
        mut client_done: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), String> {
        let mut connection = h2::server::handshake(raw).await.map_err(err)?;
        let mut work = FuturesUnordered::new();
        let (mut accepted, mut completed, mut responses_received) = (0, 0, false);
        let mut connection_open = true;
        while completed != 4 || !responses_received {
            tokio::select! {
                done = &mut client_done, if !responses_received => {
                    done.map_err(err)?;
                    responses_received = true;
                }
                done = work.next(), if accepted == 4 && !work.is_empty() => {
                    done.ok_or_else(|| "missing request owner".to_string())??;
                    completed += 1;
                }
                next = connection.accept(), if connection_open => {
                    let Some(next) = next else {
                        if accepted != 4 { return Err("H2 server closed before four requests".into()); }
                        // All streams may close before their ready body/done owners
                        // are polled. Continue checking those owners after EOF.
                        connection_open = false;
                        continue;
                    };
                    let (request, mut response) = next.map_err(err)?;
                    let id = request.uri().path().trim_start_matches('/').parse::<u8>().map_err(err)?;
                    accepted += 1;
                    if id >= 4 || accepted > 4 { return Err("unexpected synthetic request".into()); }
                    let reply = http::Response::builder().status(200).body(()).map_err(err)?;
                    let mut body = response.send_response(reply, false).map_err(err)?;
                    body.send_data(bytes::Bytes::from(vec![id + 16; 65536]), true).map_err(err)?;
                    work.push(async move { receive(request.into_body(), id).await });
                }
            }
        }
        Ok(())
    }
    struct Report {
        vector: bool,
        transfer: Result<(), String>,
        server: Result<(), String>,
        live: usize,
        pending: usize,
        witness: usize,
        underflow: bool,
        weak_closed: bool,
        random_state: bool,
    }
    async fn case(v: &serde_json::Value, capacity: usize) -> io::Result<Report> {
        case_with_random_headers(v, capacity, false).await
    }
    async fn case_with_random_headers(
        v: &serde_json::Value,
        capacity: usize,
        random_headers: bool,
    ) -> io::Result<Report> {
        let key: [u8; 96] = bytes(&v["key"]).try_into().map_err(|_| failure())?;
        let contexts = [bytes(&v["context"]), vec![0x42; 16]];
        let suite = if v["cipher"] == "aes256gcm" {
            Suite::Aes
        } else {
            Suite::ChaCha
        };
        let mut known = Aead::new(&contexts[0], &key, suite)?;
        let nonce = bytes(&v["nonce"]).try_into().map_err(|_| failure())?;
        let vector = known.seal(&bytes(&v["plaintext"]), &bytes(&v["aad"]), Some(nonce))?
            == bytes(&v["ciphertext"]);
        let counts = Arc::new(Mutex::new(Counts {
            live: 2,
            ..Default::default()
        }));
        let weak = Arc::downgrade(&counts);
        let (left, right) = tokio::io::duplex(capacity);
        let mut left = Raw {
            io: left,
            side: 0,
            counts: counts.clone(),
        };
        let mut right = Raw {
            io: right,
            side: 1,
            counts: counts.clone(),
        };
        // Each peer's context is physically queued before Records owns that raw IO.
        left.write_all(&contexts[0]).await?;
        right.write_all(&contexts[1]).await?;
        let record = |raw: Raw, context: &[u8]| -> io::Result<Records> {
            let tx_ctr = if random_headers {
                let iv: &[u8; 16] = context.try_into().map_err(|_| failure())?;
                Some(Ctr::new(&key, iv)?)
            } else {
                None
            };
            Ok(Records::resumed(
                Box::new(raw),
                Zeroizing::new(key),
                suite,
                Aead::new(context, &key, suite)?,
                tx_ctr,
                random_headers,
                Vec::new(),
                Arc::new(Cache::default()),
                Arc::new(Ticket {
                    pfs: Zeroizing::new([0; 64]),
                    bytes: Zeroizing::new([0; 16]),
                    expires: tokio::time::Instant::now() + std::time::Duration::from_secs(60),
                }),
            ))
        };
        let left = record(left, &contexts[0])?;
        let right = record(right, &contexts[1])?;
        let random_state = left.tx_ctr.is_some() && right.tx_ctr.is_some()
            && left.random_headers && right.random_headers;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve(right, done_rx));
        let mut driver = None;
        let transfer = tokio::time::timeout_at(deadline, async {
            let (mut sender, connection) = h2::client::handshake(left).await.map_err(err)?;
            driver = Some(tokio::spawn(connection));
            let mut work = FuturesUnordered::new();
            for id in 0_u8..4 {
                sender = sender.ready().await.map_err(err)?;
                let request = http::Request::builder()
                    .method("POST")
                    .uri(format!("https://records.invalid/{id}"))
                    .body(())
                    .map_err(err)?;
                let (response, mut body) = sender.send_request(request, false).map_err(err)?;
                body.send_data(bytes::Bytes::from(vec![id; 65536]), true)
                    .map_err(err)?;
                counts.lock().unwrap().active = true;
                work.push(async move {
                    let response = response.await.map_err(err)?;
                    if response.status() != 200 {
                        return Err("unexpected H2 response status".into());
                    }
                    receive(response.into_body(), id + 16).await
                });
            }
            drop(sender);
            while let Some(done) = work.next().await {
                done?;
            }
            done_tx
                .send(())
                .map_err(|_| "server owner closed before all responses".to_string())?;
            Ok::<_, String>(())
        })
        .await
        .unwrap_or_else(|_| Err("bounded H2 progress guard expired".into()));
        // The timed-out transfer future (and all request futures) is dropped above.
        // Always abort AND await every remaining task before returning any verdict.
        let server_result = match tokio::time::timeout_at(deadline, &mut server).await {
            Ok(result) => result.map_err(err).and_then(|result| result),
            Err(_) => {
                server.abort();
                let _ = server.await;
                Err("server guard expired; aborted/joined".into())
            }
        };
        if let Some(driver) = driver {
            driver.abort();
            let _ = driver.await;
        }
        let (live, pending, witness, underflow) = {
            let c = counts.lock().unwrap();
            (c.live, c.pending, c.witness, c.underflow)
        };
        drop(counts);
        Ok(Report {
            vector,
            transfer,
            server: server_result,
            live,
            pending,
            witness,
            underflow,
            weak_closed: weak.upgrade().is_none(),
            random_state,
        })
    }
    #[tokio::test(flavor = "current_thread")]
    async fn paired_records_real_h2_four_bidirectional_entities_progress_with_buffered_rx()
    -> io::Result<()> {
        for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
            for capacity in [64, 256] {
                let report = case(&group[0], capacity).await?;
                assert_eq!(report.live, 0, "raw owner survived cleanup");
                assert!(report.weak_closed && !report.underflow && report.vector);
                assert!(
                    report.pending > 0 && report.witness > 0,
                    "invalid seam: no observed raw TX Pending with peer RX bytes buffered"
                );
                assert!(report.transfer.is_ok(), "transfer: {:?}", report.transfer);
                assert!(report.server.is_ok(), "server: {:?}", report.server);
            }
        }
        Ok(())
    }
    #[tokio::test(flavor = "current_thread")]
    async fn random_normal_records_real_h2_four_bidirectional_entities_preserve_ctr_under_backpressure()
    -> io::Result<()> {
        for group in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
            for capacity in [64, 256] {
                let report = case_with_random_headers(&group[0], capacity, true).await?;
                assert_eq!(report.live, 0, "raw owner survived cleanup");
                assert!(report.weak_closed && !report.underflow && report.vector);
                assert!(report.random_state, "invalid Random CTR construction control");
                assert!(
                    report.pending > 0 && report.witness > 0,
                    "invalid seam: no observed raw TX Pending with peer RX bytes buffered"
                );
                assert!(report.transfer.is_ok(), "Random transfer: {:?}", report.transfer);
                assert!(report.server.is_ok(), "Random server: {:?}", report.server);
            }
        }
        Ok(())
    }
}
