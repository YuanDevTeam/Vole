//! Real old-API output/reliability tests; no socket, helper mirror or new production API.
use super::*;
use crate::{dispatch::DispatchError, resources::observation::ResourceProbe};
use async_trait::async_trait;
use std::{future::Future, task::Poll};
use tokio_util::sync::CancellationToken;

// Existing independently encoded MODE32 pattern: no frame padding or control
// fragmentation, fixed UDP nonce prefix. Compile it through the real policy.
const PATTERN: &str = "CAAaBAgAEAAiEAgDEAEYACAAKgZhYWJiY2MqBAgAEAAyBAgBEAA=";
const CREDIT: usize = 32768;
type Business = super::super::tcp::Business;

#[derive(Clone, Copy)]
enum Action {
    Full,
    PrefixOne,
    Unsupported,
    Fatal,
    Zero,
    Overflow,
    Pending,
}

#[derive(Default)]
struct Owner {
    active: AtomicUsize,
    entered: AtomicUsize,
    dropped: AtomicUsize,
}
struct Held {
    packets: Vec<Datagram>,
    owner: Arc<Owner>,
}
impl Drop for Held {
    fn drop(&mut self) {
        self.owner.active.fetch_sub(1, Ordering::AcqRel);
        self.owner.dropped.fetch_add(1, Ordering::AcqRel);
    }
}
#[derive(Clone)]
struct Accepted {
    wire: Bytes,
    metadata: Metadata,
    payload: Bytes,
}
struct Log {
    decoder: PacketDecoder,
    completion: Arc<Mutex<oneshot::Receiver<io::Result<()>>>>,
    batches: Vec<Vec<Bytes>>,
    singles: Vec<Bytes>,
    accepted: Vec<Accepted>,
    early_completion: bool,
    invalid_admission: bool,
    closed_with_owner: bool,
    closes: usize,
}
impl Log {
    fn accept(&mut self, packet: &Datagram) -> io::Result<()> {
        // A fragmented application write cannot complete before its last
        // physical Ready-OK. No assertion interrupts the owner's cleanup.
        if !matches!(
            self.completion.lock().unwrap().try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ) {
            self.early_completion = true;
        }
        let frame = self
            .decoder
            .decode_frame(packet.payload.clone(), super::super::tcp::now()?)?;
        self.accepted.push(Accepted {
            wire: packet.payload.clone(),
            metadata: frame.metadata,
            payload: frame.payload,
        });
        Ok(())
    }
}
struct Memory {
    log: Arc<Mutex<Log>>,
    owner: Arc<Owner>,
    action: Action,
    first_batch: bool,
    fail_single: Option<usize>,
}
#[async_trait]
impl DatagramTransport for Memory {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(MTU, MTU)
    }
    fn send_batch_owned(
        &mut self,
        packets: Vec<Datagram>,
    ) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
        let mut log = self.log.lock().unwrap();
        log.batches.push(
            packets
                .iter()
                .map(|packet| packet.payload.clone())
                .collect(),
        );
        if crate::dispatch::datagram_batch_peer(&packets).is_none()
            || packets
                .iter()
                .any(|packet| packet.payload.len() > usize::from(MTU))
        {
            log.invalid_admission = true;
            return Err(packets);
        }
        let action = if self.first_batch {
            self.first_batch = false;
            self.action
        } else {
            Action::Full
        };
        if matches!(action, Action::Unsupported) {
            return Err(packets); // Admission rejection: no physical acceptance.
        }
        drop(log);
        self.owner.active.fetch_add(1, Ordering::AcqRel);
        let held = Held {
            packets,
            owner: self.owner.clone(),
        };
        let log = self.log.clone();
        Ok(Box::pin(async move {
            held.owner.entered.fetch_add(1, Ordering::AcqRel);
            let count = match action {
                Action::Full => held.packets.len(),
                Action::PrefixOne => 1,
                Action::Fatal => return Err(io::ErrorKind::PermissionDenied.into()),
                Action::Zero => return Ok(0),
                Action::Overflow => return Ok(held.packets.len() + 1),
                Action::Pending => std::future::pending::<usize>().await,
                Action::Unsupported => unreachable!("rejected before owned IO"),
            };
            for packet in &held.packets[..count] {
                log.lock().unwrap().accept(packet)?;
            }
            drop(held);
            Ok(count)
        }))
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        let mut log = self.log.lock().unwrap();
        log.singles.push(packet.payload.clone());
        if self.fail_single == Some(log.singles.len()) {
            return Err(DispatchError::ConnectionRefused);
        }
        log.accept(&packet).map_err(DispatchError::from)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        let mut log = self.log.lock().unwrap();
        log.closes += 1;
        log.closed_with_owner |= self.owner.active.load(Ordering::Acquire) != 0;
        Ok(())
    }
}

struct Fixture {
    shared: Arc<Shared>,
    state: Arc<State>,
    reliable: Reliable,
    credit: Arc<Semaphore>,
    completion: Arc<Mutex<oneshot::Receiver<io::Result<()>>>>,
    encoder: PacketEncoder,
    ack_encoder: PacketEncoder,
    ack_decoder: PacketDecoder,
    pattern: EffectivePattern,
    memory: Memory,
    expected: Vec<u8>,
    remaining: usize,
    buffer: Vec<u8>,
}
struct View {
    batches: Vec<Vec<Bytes>>,
    singles: Vec<Bytes>,
    accepted: Vec<Accepted>,
    pending: usize,
    outstanding: Vec<(u32, u32, bool, u64)>,
    remaining: usize,
    first_check: bool,
    credit: usize,
    completion: u8,
    early_completion: bool,
    invalid_admission: bool,
}
struct Cleanup {
    closed: bool,
    closed_with_owner: bool,
    closes: usize,
    active: usize,
    entered: usize,
    dropped: usize,
    credit: usize,
    completion: u8,
}
fn completion_status(receiver: &Mutex<oneshot::Receiver<io::Result<()>>>) -> u8 {
    match receiver.lock().unwrap().try_recv() {
        Err(oneshot::error::TryRecvError::Empty) => 0,
        Ok(Ok(())) => 1,
        Ok(Err(_)) => 2,
        Err(oneshot::error::TryRecvError::Closed) => 3,
    }
}
impl Fixture {
    fn new(business: Business, low: bool, fragments: usize, action: Action) -> Self {
        let pattern = EffectivePattern::compile(
            low.then_some(PATTERN),
            super::super::pattern::HostProfile::capture(),
            "vole",
        )
        .unwrap();
        let chunk = pattern
            .plaintext_fragment_limit(MieruTransport::Udp, MTU.into())
            .unwrap();
        let expected: Vec<_> = (0..chunk * fragments)
            .map(|index| b'A' + (index / chunk) as u8)
            .collect();
        let shared = Shared::output_test_shared(CancellationToken::new());
        let state =
            State::new_for_business(7, CREDIT, business, &shared.cancel, shared.activity.clone());
        state.opened.store(true, Ordering::Release);
        shared.sessions.lock().unwrap().insert(7, state.clone());
        let credit = Arc::new(Semaphore::new(CREDIT));
        let (done, completion) = oneshot::channel();
        let completion = Arc::new(Mutex::new(completion));
        let command = WriterCommand {
            state: state.clone(),
            data: Bytes::copy_from_slice(&expected),
            piggyback: false,
            done,
            _bytes: credit
                .clone()
                .try_acquire_many_owned(expected.len() as u32)
                .unwrap(),
        };
        let mut reliable = Reliable::new(state.clone(), 1312);
        reliable.established = true;
        reliable.heartbeat_interval = Duration::from_secs(30);
        reliable.heartbeat = Instant::now() + reliable.heartbeat_interval;
        reliable.enqueue(command, chunk, false);
        let key = crypto::derive_packet_key(
            "vole",
            "fixture-password",
            super::super::tcp::now().unwrap(),
        );
        let log = Arc::new(Mutex::new(Log {
            decoder: PacketDecoder::new(&key, low).unwrap(),
            completion: completion.clone(),
            batches: Vec::new(),
            singles: Vec::new(),
            accepted: Vec::new(),
            early_completion: false,
            invalid_admission: false,
            closed_with_owner: false,
            closes: 0,
        }));
        Self {
            shared,
            state,
            reliable,
            credit,
            completion,
            encoder: PacketEncoder::new(&key, false).unwrap(),
            ack_encoder: PacketEncoder::new(&key, false).unwrap(),
            ack_decoder: PacketDecoder::new(&key, low).unwrap(),
            pattern,
            memory: Memory {
                log,
                owner: Arc::default(),
                action,
                first_batch: true,
                fail_single: None,
            },
            expected,
            remaining: OUTPUT_QUANTUM,
            buffer: Vec::new(),
        }
    }
    async fn output(&mut self) -> io::Result<bool> {
        let mut pattern = PacketPattern {
            pattern: &self.pattern,
            nonce: NonceState::new(),
            wire_budget: MTU.into(),
            remaining: self.remaining,
            truncated: false,
        };
        let result = output(
            &mut self.memory,
            &Destination::Ip("192.0.2.1:2000".parse().unwrap()),
            &mut self.encoder,
            "vole",
            &self.shared,
            &mut pattern,
            &mut self.reliable,
            true,
            &mut self.buffer,
        )
        .await;
        self.remaining = pattern.remaining;
        result
    }
    fn view(&self) -> View {
        let log = self.memory.log.lock().unwrap();
        View {
            batches: log.batches.clone(),
            singles: log.singles.clone(),
            accepted: log.accepted.clone(),
            pending: self.reliable.pending.len(),
            outstanding: self
                .reliable
                .outstanding
                .iter()
                .map(|(sequence, segment)| {
                    (
                        *sequence,
                        segment.tx_count,
                        segment.sent.is_some(),
                        segment.timeout_nanos,
                    )
                })
                .collect(),
            remaining: self.remaining,
            first_check: self.reliable.first_check.is_some(),
            credit: self.credit.available_permits(),
            completion: completion_status(&self.completion),
            early_completion: log.early_completion,
            invalid_admission: log.invalid_admission,
        }
    }
    fn ack(&mut self, unack: u32) {
        let mut wire = Vec::new();
        self.ack_encoder
            .encode_frame(
                Metadata::Data(DataMetadata {
                    kind: DataKind::ServerAck,
                    session_id: 7,
                    sequence: 0,
                    unack_sequence: unack,
                    window: 16,
                    fragment: 0,
                }),
                &[],
                super::super::wire::Padding::default(),
                rand::random(),
                super::super::tcp::now().unwrap(),
                &mut wire,
            )
            .unwrap();
        let frame = self
            .ack_decoder
            .decode_frame(Bytes::from(wire), super::super::tcp::now().unwrap())
            .unwrap();
        self.reliable.input(frame, Instant::now(), &mut None);
    }
    async fn cleanup(self) -> Cleanup {
        let Self {
            shared,
            state,
            reliable,
            credit,
            completion,
            mut memory,
            encoder,
            ack_encoder,
            ack_decoder,
            pattern,
            expected,
            buffer,
            ..
        } = self;
        shared.cancel.cancel();
        let closed = memory.close().await.is_ok();
        state.close();
        drop(reliable);
        shared.sessions.lock().unwrap().clear();
        drop((
            state,
            shared,
            encoder,
            ack_encoder,
            ack_decoder,
            pattern,
            expected,
            buffer,
        ));
        let log = memory.log.lock().unwrap();
        let result = Cleanup {
            closed,
            closed_with_owner: log.closed_with_owner,
            closes: log.closes,
            active: memory.owner.active.load(Ordering::Acquire),
            entered: memory.owner.entered.load(Ordering::Acquire),
            dropped: memory.owner.dropped.load(Ordering::Acquire),
            credit: credit.available_permits(),
            completion: completion_status(&completion),
        };
        drop(log);
        drop((memory, completion, credit));
        result
    }
}
fn assert_cleanup(cleanup: &Cleanup) {
    assert!(cleanup.closed && !cleanup.closed_with_owner);
    assert_eq!(
        (cleanup.closes, cleanup.active, cleanup.credit),
        (1, 0, CREDIT)
    );
    assert_eq!(cleanup.entered, cleanup.dropped);
}
fn assert_data(view: &View, expected: &[u8], fragments: usize, udp: bool) {
    assert!(!view.early_completion && !view.invalid_admission);
    assert_eq!(
        (view.accepted.len(), view.pending, view.outstanding.len()),
        (fragments, 0, fragments)
    );
    let mut payload = Vec::new();
    for (index, accepted) in view.accepted.iter().enumerate() {
        assert!(matches!(accepted.metadata, Metadata::Data(meta)
            if meta.kind == DataKind::ClientData && meta.session_id == 7
                && meta.sequence == index as u32 && meta.fragment as usize == fragments - index - 1));
        payload.extend_from_slice(&accepted.payload);
        assert!(accepted.wire.len() <= usize::from(MTU));
    }
    assert_eq!(payload, expected);
    for (index, entry) in view.outstanding.iter().enumerate() {
        assert_eq!((entry.0, entry.1, entry.2), (index as u32, 1, true));
        assert_eq!(
            entry.3 != 0,
            udp,
            "saved RTO is qualified by each State's business"
        );
    }
    assert!(view.first_check);
    assert_eq!(view.completion, 1);
    assert_eq!(
        view.credit,
        CREDIT - expected.len(),
        "first-send is not an ACK refund"
    );
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_pattern_ready_batch_real_output_eight_fragments_both_businesses() {
    let probe = ResourceProbe::default();
    let cases = probe
        .scope(async {
            let mut cases = Vec::new();
            for business in [Business::UdpAssociate, Business::TcpConnect] {
                let mut fixture = Fixture::new(business, true, 8, Action::Full);
                let expected = fixture.expected.clone();
                let result = fixture.output().await;
                let view = fixture.view();
                fixture.ack(8);
                let ack_credit = fixture.credit.available_permits();
                let outstanding_after_ack = fixture.reliable.outstanding.len();
                let cleanup = fixture.cleanup().await;
                cases.push((
                    business,
                    expected,
                    result,
                    view,
                    ack_credit,
                    outstanding_after_ack,
                    cleanup,
                ));
            }
            cases
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (business, expected, result, view, ack_credit, outstanding_after_ack, cleanup) in cases {
        assert_cleanup(&cleanup);
        assert!(matches!(result, Ok(true)));
        assert_data(
            &view,
            &expected,
            8,
            matches!(business, Business::UdpAssociate),
        );
        assert_eq!((ack_credit, outstanding_after_ack), (CREDIT, 0));
        assert_eq!(view.remaining, 0);
        // Old 5de naturally finishes eight ordinary sends and all cleanup above;
        // it then fails this batch-use policy assertion, never a gate timeout.
        assert_eq!(
            view.batches.iter().map(Vec::len).collect::<Vec<_>>(),
            [4, 4]
        );
        assert!(view.singles.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_pattern_ready_batch_partial_preserves_ciphertext_and_real_ack_credit() {
    let probe = ResourceProbe::default();
    let cases = probe
        .scope(async {
            let mut cases = Vec::new();
            for business in [Business::UdpAssociate, Business::TcpConnect] {
                let mut fixture = Fixture::new(business, true, 4, Action::PrefixOne);
                let expected = fixture.expected.clone();
                let result = fixture.output().await;
                let view = fixture.view();
                fixture.ack(1);
                let partial_credit = fixture.credit.available_permits();
                fixture.ack(4);
                let full_credit = fixture.credit.available_permits();
                let cleanup = fixture.cleanup().await;
                cases.push((
                    business,
                    expected,
                    result,
                    view,
                    partial_credit,
                    full_credit,
                    cleanup,
                ));
            }
            cases
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (business, expected, result, view, partial_credit, full_credit, cleanup) in cases {
        assert_cleanup(&cleanup);
        assert!(matches!(result, Ok(true)));
        assert_data(
            &view,
            &expected,
            4,
            matches!(business, Business::UdpAssociate),
        );
        assert_eq!(
            (partial_credit, full_credit),
            (CREDIT - expected.len(), CREDIT)
        );
        assert_eq!(view.remaining, 4);
        assert_eq!(view.batches.len(), 1);
        assert_eq!(view.batches[0].len(), 4);
        assert_eq!(view.singles, view.batches[0][1..]);
        for (single, original) in view.singles.iter().zip(&view.batches[0][1..]) {
            assert_eq!(
                single.as_ptr(),
                original.as_ptr(),
                "suffix keeps its original encoded allocation"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_pattern_ready_batch_errors_and_partial_suffix_failure_do_not_replay() {
    let probe = ResourceProbe::default();
    let (errors, suffix) = probe
        .scope(async {
            let mut errors = Vec::new();
            for action in [Action::Fatal, Action::Zero, Action::Overflow] {
                let mut fixture = Fixture::new(Business::UdpAssociate, true, 4, action);
                let result = fixture.output().await;
                let view = fixture.view();
                let cleanup = fixture.cleanup().await;
                errors.push((result, view, cleanup));
            }
            let mut fixture = Fixture::new(Business::UdpAssociate, true, 4, Action::PrefixOne);
            fixture.memory.fail_single = Some(2);
            let result = fixture.output().await;
            let view = fixture.view();
            fixture.ack(2);
            let credit_after_prefix_ack = fixture.credit.available_permits();
            let cleanup = fixture.cleanup().await;
            (errors, (result, view, credit_after_prefix_ack, cleanup))
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (result, view, cleanup) in errors {
        assert_cleanup(&cleanup);
        assert!(result.is_err());
        assert_eq!(
            (view.batches.len(), view.singles.len(), view.accepted.len()),
            (1, 0, 0)
        );
        assert_eq!(
            (
                view.pending,
                view.outstanding.len(),
                view.remaining,
                view.completion
            ),
            (4, 0, 8, 0)
        );
        assert!(!view.first_check && !view.early_completion);
        assert_eq!(
            cleanup.completion, 2,
            "terminal drop rejects the unconfirmed write"
        );
    }
    let (result, view, credit_after_prefix_ack, cleanup) = suffix;
    assert_cleanup(&cleanup);
    assert!(result.is_err());
    assert_eq!(
        (view.batches.len(), view.singles.len(), view.accepted.len()),
        (1, 2, 2)
    );
    assert_eq!(view.singles, view.batches[0][1..3]);
    assert_eq!(
        (
            view.pending,
            view.outstanding.len(),
            view.remaining,
            view.completion
        ),
        (2, 2, 6, 0)
    );
    assert!(
        view.outstanding
            .iter()
            .all(|entry| entry.1 == 1 && entry.2 && entry.3 != 0)
    );
    assert_eq!(
        view.accepted
            .iter()
            .map(|frame| sequence(frame.metadata))
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(
        credit_after_prefix_ack, view.credit,
        "unconfirmed fragments retain the shared write lease"
    );
    assert_eq!(cleanup.completion, 2);
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_pattern_ready_batch_pending_cancel_and_timeout_drop_before_close() {
    let probe = ResourceProbe::default();
    let cases = probe
        .scope(async {
            let mut cases = Vec::new();
            for timeout in [false, true] {
                let mut fixture = Fixture::new(Business::UdpAssociate, true, 4, Action::Pending);
                let cancel = fixture.shared.cancel.clone();
                let mut operation = Box::pin(fixture.output());
                // Poll the real output exactly once with the caller's real Context.
                // Old ordinary output may finish immediately; never wait for a
                // batch-entered event which old production cannot produce.
                let first =
                    std::future::poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx))).await;
                let was_pending = first.is_pending();
                let result = match first {
                    Poll::Ready(result) => result,
                    Poll::Pending => {
                        if timeout {
                            tokio::time::advance(Duration::from_secs(10)).await;
                        } else {
                            cancel.cancel();
                        }
                        operation.as_mut().await
                    }
                };
                drop(operation);
                let view = fixture.view();
                let cleanup = fixture.cleanup().await;
                cases.push((timeout, was_pending, result, view, cleanup));
            }
            cases
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (timeout, was_pending, result, view, cleanup) in cases {
        assert_cleanup(&cleanup);
        assert!(was_pending && result.is_err());
        if timeout {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        }
        assert_eq!((cleanup.entered, cleanup.dropped), (1, 1));
        assert_eq!(
            (view.batches.len(), view.singles.len(), view.accepted.len()),
            (1, 0, 0)
        );
        assert_eq!(
            (
                view.pending,
                view.outstanding.len(),
                view.remaining,
                view.completion
            ),
            (4, 0, 8, 0)
        );
        assert_eq!(cleanup.completion, 2);
    }
}

#[tokio::test(start_paused = true)]
async fn mieru_udp_pattern_ready_batch_fallback_scope_and_original_window_quantum() {
    let probe = ResourceProbe::default();
    let cases = probe
        .scope(async {
            let mut cases = Vec::new();
            // Capability rejection preserves already encoded ciphertext. The other
            // controls exercise actual eligibility through existing output.
            for case in 0..6 {
                let mut fixture = Fixture::new(
                    Business::UdpAssociate,
                    case != 1,
                    if case == 2 { 1 } else { 4 },
                    if case == 0 {
                        Action::Unsupported
                    } else {
                        Action::Full
                    },
                );
                if case == 3 {
                    fixture.reliable.established = false;
                }
                if case == 4 {
                    fixture.reliable.remote_window = 1;
                }
                if case == 5 {
                    fixture.remaining = 1;
                }
                let result = fixture.output().await;
                let view = fixture.view();
                let cleanup = fixture.cleanup().await;
                cases.push((case, result, view, cleanup));
            }
            cases
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (case, result, view, cleanup) in cases {
        assert_cleanup(&cleanup);
        assert!(matches!(result, Ok(true)));
        assert!(!view.early_completion && !view.invalid_admission);
        if case == 0 {
            assert_eq!(view.batches.len(), 1);
            assert_eq!(view.singles, view.batches[0]);
            for (single, original) in view.singles.iter().zip(&view.batches[0]) {
                assert_eq!(single.as_ptr(), original.as_ptr());
            }
        } else {
            assert!(view.batches.is_empty());
        }
        let accepted = match case {
            0 | 1 => 4,
            3 => 0,
            _ => 1,
        };
        assert_eq!(
            (view.singles.len(), view.accepted.len()),
            (accepted, accepted)
        );
    }
}
