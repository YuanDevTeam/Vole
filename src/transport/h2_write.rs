//! Strong receipts at the supplied IO's flush boundary. Private autonomous
//! h2mux writers coalesce confirmation state without per-DATA oneshots.
use crate::dispatch::BoxStream;
use bytes::{Buf, Bytes};
#[cfg(feature = "sing-mux")]
use futures_util::task::AtomicWaker;
#[cfg(feature = "sing-mux")]
use std::sync::Weak;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};

pub(super) type Receipt = oneshot::Receiver<io::Result<()>>;
type Completion = oneshot::Sender<io::Result<()>>;

#[derive(Clone, Debug)]
pub(super) struct Sender {
    pub request: h2::client::SendRequest<Payload>,
    pub writes: Writes,
}

#[derive(Clone, Default, Debug)]
pub(super) struct Writes(Arc<Mutex<State>>);

#[derive(Debug)]
enum Done {
    Strong(Completion),
    #[cfg(feature = "sing-mux")]
    Coalesced(Arc<CoalescedAck>, u64),
}

#[derive(Debug)]
enum Encoded {
    Strong(Completion),
    #[cfg(feature = "sing-mux")]
    Coalesced(Weak<CoalescedAck>),
}

#[derive(Default, Debug)]
struct State {
    closed: bool,
    encoded: Vec<Encoded>,
    #[cfg(feature = "sing-mux")]
    prune_remaining: usize,
}

#[cfg(feature = "sing-mux")]
#[derive(Default, Debug)]
pub(super) struct CoalescedAck {
    state: Mutex<AckState>,
    wake: AtomicWaker,
}

#[cfg(feature = "sing-mux")]
#[derive(Default, Debug)]
struct AckState {
    submitted: u64,
    encoded: u64,
    flushed: u64,
    registered: bool,
    error: Option<io::ErrorKind>,
}

#[cfg(feature = "sing-mux")]
impl CoalescedAck {
    pub(super) fn check(&self, cx: &mut Context<'_>) -> io::Result<()> {
        self.wake.register(cx.waker());
        self.state
            .lock()
            .unwrap()
            .error
            .map_or(Ok(()), |error| Err(error.into()))
    }

    pub(super) fn poll_flushed(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wake.register(cx.waker());
        let state = self.state.lock().unwrap();
        if let Some(error) = state.error {
            Poll::Ready(Err(error.into()))
        } else if state.flushed == state.submitted {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    pub(super) fn fail(&self, error: io::ErrorKind) {
        self.state.lock().unwrap().error.get_or_insert(error);
        self.wake.wake();
    }
}

impl State {
    // Always called under Writes; nested lock order is Writes -> Ack.
    fn record(&mut self, done: Done) -> Option<Done> {
        match done {
            Done::Strong(done) => {
                if self.closed {
                    Some(Done::Strong(done))
                } else {
                    self.encoded.push(Encoded::Strong(done));
                    None
                }
            }
            #[cfg(feature = "sing-mux")]
            Done::Coalesced(ack, ticket) => {
                let mut progress = ack.state.lock().unwrap();
                if self.closed || progress.error.is_some() {
                    progress.error.get_or_insert(io::ErrorKind::BrokenPipe);
                    drop(progress);
                    return Some(Done::Coalesced(ack, ticket));
                }
                progress.encoded = ticket;
                if !progress.registered {
                    progress.registered = true;
                    // Only a newly registered writer reaches this branch.
                    // Amortize scans over the surviving list, not tiny DATA.
                    if self.prune_remaining == 0 {
                        self.encoded.retain(|entry| match entry {
                            Encoded::Strong(_) => true,
                            Encoded::Coalesced(weak) => weak.strong_count() != 0,
                        });
                        self.prune_remaining = self.encoded.len().max(16);
                    }
                    self.prune_remaining -= 1;
                    self.encoded.push(Encoded::Coalesced(Arc::downgrade(&ack)));
                }
                None
            }
        }
    }

    // Only the h2 Connection advances Payloads and flushes its supplied IO.
    // Its codec drains encoded bytes before entering raw.poll_flush. Marking
    // and deregistration stay in one Writes critical section; wake outside it.
    fn finish(&mut self, _error: Option<io::ErrorKind>) -> Vec<Encoded> {
        let encoded = std::mem::take(&mut self.encoded);
        #[cfg(feature = "sing-mux")]
        {
            self.prune_remaining = 0;
        }
        #[cfg(feature = "sing-mux")]
        for entry in &encoded {
            if let Encoded::Coalesced(weak) = entry
                && let Some(ack) = weak.upgrade()
            {
                let mut progress = ack.state.lock().unwrap();
                progress.registered = false;
                if let Some(error) = _error {
                    progress.error.get_or_insert(error);
                } else if progress.error.is_none() {
                    progress.flushed = progress.encoded;
                }
            }
        }
        encoded
    }
}

fn notify_finished(encoded: Vec<Encoded>, error: Option<io::ErrorKind>, strong: bool) {
    for entry in encoded {
        match entry {
            Encoded::Strong(done) => {
                if strong {
                    let _ = done.send(error.map_or(Ok(()), |error| Err(error.into())));
                }
                // Driver Drop still cancels the legacy oneshot as before.
            }
            #[cfg(feature = "sing-mux")]
            Encoded::Coalesced(weak) => {
                if let Some(ack) = weak.upgrade() {
                    ack.wake.wake();
                }
            }
        }
    }
}

impl Writes {
    pub fn wrap(raw: BoxStream) -> (impl AsyncRead + AsyncWrite + Unpin + Send, Self) {
        let writes = Self::default();
        (
            FlushIo {
                raw,
                writes: writes.clone(),
                #[cfg(feature = "sing-mux")]
                wrote_since_flush: false,
            },
            writes,
        )
    }

    pub fn payload(&self, bytes: Bytes) -> (Payload, Receipt) {
        assert!(!bytes.is_empty());
        let (done, receipt) = oneshot::channel();
        (
            Payload {
                bytes,
                done: Some(Done::Strong(done)),
                writes: self.clone(),
            },
            receipt,
        )
    }

    #[cfg(feature = "sing-mux")]
    pub(super) fn coalesced_payload(
        &self,
        bytes: Bytes,
        ack: &Arc<CoalescedAck>,
    ) -> io::Result<Payload> {
        assert!(!bytes.is_empty());
        let ticket = {
            let state = self.0.lock().unwrap();
            if state.closed {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let mut progress = ack.state.lock().unwrap();
            if let Some(error) = progress.error {
                return Err(error.into());
            }
            // FIFO tickets wrap; equality tracks bounded outstanding progress.
            progress.submitted = progress.submitted.wrapping_add(1);
            progress.submitted
        };
        Ok(Payload {
            bytes,
            done: Some(Done::Coalesced(ack.clone(), ticket)),
            writes: self.clone(),
        })
    }
}

pub(super) struct Payload {
    bytes: Bytes,
    done: Option<Done>,
    writes: Writes,
}

impl Payload {
    pub fn empty() -> Self {
        Self {
            bytes: Bytes::new(),
            done: None,
            writes: Writes::default(),
        }
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        #[cfg(feature = "sing-mux")]
        if let Some(Done::Coalesced(ack, _)) = &self.done {
            ack.fail(io::ErrorKind::BrokenPipe);
        }
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Payload")
            .field("remaining", &self.bytes.len())
            .finish()
    }
}

impl Buf for Payload {
    fn remaining(&self) -> usize {
        self.bytes.remaining()
    }
    fn chunk(&self) -> &[u8] {
        let bytes = self.bytes.chunk();
        // Keep a whole packet-up POST in one backing, but feed HTTP's supplied
        // IO in streaming-sized pieces instead of buffering 64 KiB in TLS.
        &bytes[..bytes.len().min(crate::limits::XHTTP_BODY_CHUNK)]
    }
    fn advance(&mut self, count: usize) {
        self.bytes.advance(count);
        if self.bytes.is_empty()
            && let Some(done) = self.done.take()
        {
            let notification = self.writes.0.lock().unwrap().record(done);
            #[cfg(feature = "sing-mux")]
            if let Some(Done::Coalesced(ack, _)) = &notification {
                ack.wake.wake();
            }
            drop(notification); // Legacy cancellation also happens lock-free.
        }
    }
}

struct FlushIo {
    raw: BoxStream,
    writes: Writes,
    #[cfg(feature = "sing-mux")]
    wrote_since_flush: bool,
}
impl Drop for FlushIo {
    fn drop(&mut self) {
        let encoded = {
            let mut state = self.writes.0.lock().unwrap();
            state.closed = true;
            state.finish(Some(io::ErrorKind::BrokenPipe))
        };
        notify_finished(encoded, Some(io::ErrorKind::BrokenPipe), false);
    }
}
impl AsyncRead for FlushIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_read(cx, out)
    }
}
impl AsyncWrite for FlushIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.raw).poll_write(cx, input);
        #[cfg(feature = "sing-mux")]
        if matches!(&result, Poll::Ready(Ok(count)) if *count > 0) {
            self.wrote_since_flush = true;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.raw).poll_flush(cx);
        #[cfg(feature = "sing-mux")]
        {
            // A chained h2 DATA can drain before its stronger IO flush is
            // ready. Re-poll productive private owners once so already queued
            // frames can fill the same bounded PacketUp batch.
            let repoll = result.is_pending() && std::mem::take(&mut self.wrote_since_flush) && {
                let state = self.writes.0.lock().unwrap();
                state.encoded.iter().any(
                    |entry| matches!(entry, Encoded::Coalesced(weak) if weak.strong_count() != 0),
                )
            };
            if repoll {
                cx.waker().wake_by_ref();
            }
        }
        let result = std::task::ready!(result);
        #[cfg(feature = "sing-mux")]
        {
            self.wrote_since_flush = false;
        }
        let error = result.as_ref().err().map(io::Error::kind);
        let encoded = self.writes.0.lock().unwrap().finish(error);
        notify_finished(encoded, error, true);
        Poll::Ready(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::poll_fn,
        sync::atomic::{AtomicU8, Ordering},
    };
    use tokio::io::AsyncWriteExt;

    struct Gate(Arc<AtomicU8>);
    impl AsyncRead for Gate {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for Gate {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.0.load(Ordering::SeqCst) {
                0 => Poll::Pending,
                1 => Poll::Ready(Ok(())),
                _ => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn receipt_waits_for_every_byte_and_the_supplied_io_flush() {
        let gate = Arc::new(AtomicU8::new(1));
        let (mut raw, writes) = Writes::wrap(Box::new(Gate(gate.clone())));
        let (mut data, mut receipt) = writes.payload(Bytes::from_static(b"data"));
        data.advance(2);
        raw.flush().await.unwrap();
        assert!(matches!(
            receipt.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        gate.store(0, Ordering::SeqCst);
        data.advance(2);
        assert!(
            poll_fn(|cx| Poll::Ready(Pin::new(&mut raw).poll_flush(cx)))
                .await
                .is_pending()
        );
        assert!(matches!(
            receipt.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        gate.store(1, Ordering::SeqCst);
        raw.flush().await.unwrap();
        receipt.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn failed_flush_and_dropped_payload_or_driver_never_report_success() {
        let (mut raw, writes) = Writes::wrap(Box::new(Gate(Arc::new(AtomicU8::new(2)))));
        let (mut data, receipt) = writes.payload(Bytes::from_static(b"data"));
        data.advance(4);
        assert!(raw.flush().await.is_err());
        assert_eq!(
            receipt.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        let (data, receipt) = writes.payload(Bytes::from_static(b"reset before encoding"));
        drop(data);
        assert!(receipt.await.is_err());
        let (mut data, receipt) = writes.payload(Bytes::from_static(b"data"));
        data.advance(4);
        drop(raw);
        assert!(receipt.await.is_err());
    }

    #[cfg(feature = "sing-mux")]
    #[tokio::test]
    async fn coalesced_writer_bounds_markers_and_never_flushes_unencoded_or_failed_payloads() {
        use std::{
            sync::atomic::AtomicUsize,
            task::{Wake, Waker},
        };
        #[derive(Default)]
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let counter = Arc::new(Count::default());
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let gate = Arc::new(AtomicU8::new(0));
        let (mut raw, writes) = Writes::wrap(Box::new(Gate(gate.clone())));
        let ack = Arc::new(CoalescedAck::default());
        for _ in 0..256 {
            let mut payload = writes
                .coalesced_payload(Bytes::from_static(b"a"), &ack)
                .unwrap();
            payload.advance(1);
            drop(payload);
        }
        let markers = writes.0.lock().unwrap().encoded.len();
        for _ in 0..1024 {
            let short = Arc::new(CoalescedAck::default());
            let mut payload = writes
                .coalesced_payload(Bytes::from_static(b"s"), &short)
                .unwrap();
            payload.advance(1);
            drop(payload);
            drop(short);
        }
        let short_flow_markers = writes.0.lock().unwrap().encoded.len();
        assert!(ack.poll_flushed(&mut cx).is_pending());
        assert!(Pin::new(&mut raw).poll_flush(&mut cx).is_pending());
        assert!(ack.poll_flushed(&mut cx).is_pending());
        let sibling = Arc::new(CoalescedAck::default());
        let mut partial = writes
            .coalesced_payload(Bytes::from_static(b"xy"), &sibling)
            .unwrap();
        partial.advance(1);
        gate.store(1, Ordering::SeqCst);
        raw.flush().await.unwrap();
        assert!(matches!(ack.poll_flushed(&mut cx), Poll::Ready(Ok(()))));
        assert!(
            sibling.poll_flushed(&mut cx).is_pending(),
            "a sibling flush acknowledged unencoded bytes"
        );
        partial.advance(1);
        drop(partial);
        raw.flush().await.unwrap();
        assert!(matches!(sibling.poll_flushed(&mut cx), Poll::Ready(Ok(()))));
        let unencoded = Arc::new(CoalescedAck::default());
        let payload = writes
            .coalesced_payload(Bytes::from_static(b"cancel"), &unencoded)
            .unwrap();
        assert!(unencoded.poll_flushed(&mut cx).is_pending());
        let before_cancel = counter.0.load(Ordering::SeqCst);
        drop(payload);
        assert!(counter.0.load(Ordering::SeqCst) > before_cancel);
        assert!(matches!(
            unencoded.poll_flushed(&mut cx),
            Poll::Ready(Err(_))
        ));
        let failed = Arc::new(CoalescedAck::default());
        let mut payload = writes
            .coalesced_payload(Bytes::from_static(b"fail"), &failed)
            .unwrap();
        payload.advance(4);
        gate.store(2, Ordering::SeqCst);
        assert!(failed.poll_flushed(&mut cx).is_pending());
        let before_failure = counter.0.load(Ordering::SeqCst);
        assert_eq!(
            raw.flush().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert!(counter.0.load(Ordering::SeqCst) > before_failure);
        assert!(
            matches!(failed.poll_flushed(&mut cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset)
        );
        let stopped = Arc::new(CoalescedAck::default());
        let mut payload = writes
            .coalesced_payload(Bytes::from_static(b"stop"), &stopped)
            .unwrap();
        payload.advance(4);
        assert!(stopped.poll_flushed(&mut cx).is_pending());
        let before_stop = counter.0.load(Ordering::SeqCst);
        drop(raw);
        assert!(counter.0.load(Ordering::SeqCst) > before_stop);
        assert!(matches!(stopped.poll_flushed(&mut cx), Poll::Ready(Err(_))));
        assert_eq!(
            markers, 1,
            "one logical writer accumulated per-payload completion markers"
        );
        assert!(
            short_flow_markers < 64,
            "blocked flush retained short-flow markers without cleanup: {short_flow_markers}"
        );
    }
}

#[cfg(all(test, feature = "sing-mux"))]
mod productive_repoll_memory_tests {
    use super::*;
    use futures_util::task::noop_waker;
    use std::{
        sync::atomic::{AtomicU8, AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

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

    #[derive(Default)]
    struct Control {
        write: AtomicU8,
        flush: AtomicU8,
    }
    struct MemoryIo(Arc<Control>);
    impl AsyncRead for MemoryIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for MemoryIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.0.write.load(Ordering::SeqCst) {
                0 => Poll::Ready(Ok(input.len())),
                1 => Poll::Pending,
                2 => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                _ => Poll::Ready(Ok(0)),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.0.flush.load(Ordering::SeqCst) {
                0 => Poll::Pending,
                1 => Poll::Ready(Ok(())),
                _ => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    struct Fixture {
        raw: BoxStream,
        writes: Writes,
        control: Arc<Control>,
        driver: Arc<Count>,
        waker: Waker,
    }
    impl Fixture {
        fn new() -> Self {
            let control = Arc::new(Control::default());
            let driver = Arc::new(Count::default());
            let (raw, writes) = Writes::wrap(Box::new(MemoryIo(control.clone())));
            Self {
                raw: Box::new(raw),
                writes,
                control,
                waker: Waker::from(driver.clone()),
                driver,
            }
        }
        fn write(&mut self, input: &[u8]) -> Poll<io::Result<usize>> {
            let mut cx = Context::from_waker(&self.waker);
            Pin::new(&mut self.raw).poll_write(&mut cx, input)
        }
        fn flush(&mut self) -> Poll<io::Result<()>> {
            let mut cx = Context::from_waker(&self.waker);
            Pin::new(&mut self.raw).poll_flush(&mut cx)
        }
        fn wakes(&self) -> usize {
            self.driver.0.load(Ordering::SeqCst)
        }
        fn coalesced(&self) -> Arc<CoalescedAck> {
            let ack = Arc::new(CoalescedAck::default());
            let mut payload = self
                .writes
                .coalesced_payload(Bytes::from_static(b"private"), &ack)
                .unwrap();
            payload.advance(7);
            drop(payload);
            ack
        }
        fn strong(&self) -> Receipt {
            let (mut payload, receipt) = self.writes.payload(Bytes::from_static(b"strong"));
            payload.advance(6);
            drop(payload);
            receipt
        }
    }

    fn acknowledged(ack: &CoalescedAck) -> Poll<io::Result<()>> {
        // Logical confirmation must not share the physical driver's counter.
        let waker = noop_waker();
        ack.poll_flushed(&mut Context::from_waker(&waker))
    }

    #[tokio::test]
    async fn ordinary_owner_never_self_wakes_for_a_productive_pending_flush() {
        let mut fixture = Fixture::new();
        let mut receipt = fixture.strong();
        assert!(matches!(fixture.write(b"wire"), Poll::Ready(Ok(4))));
        assert!(fixture.flush().is_pending());
        assert_eq!(
            fixture.wakes(),
            0,
            "ordinary strong owner gained private wakes"
        );
        assert!(matches!(
            receipt.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        fixture.control.flush.store(1, Ordering::SeqCst);
        assert!(matches!(fixture.flush(), Poll::Ready(Ok(()))));
        receipt.await.unwrap().unwrap();
        assert_eq!(fixture.wakes(), 0);
    }

    #[tokio::test]
    async fn productive_pending_repoll_is_once_per_new_positive_write() {
        let mut fixture = Fixture::new();
        let ack = fixture.coalesced();
        assert!(fixture.flush().is_pending());
        assert_eq!(fixture.wakes(), 0, "marker presence alone scheduled work");
        assert!(matches!(fixture.write(b"wire"), Poll::Ready(Ok(4))));
        assert!(fixture.flush().is_pending());
        assert_eq!(
            fixture.wakes(),
            1,
            "productive private flush needs one re-poll"
        );
        for _ in 0..128 {
            assert!(fixture.flush().is_pending());
        }
        assert_eq!(
            fixture.wakes(),
            1,
            "Pending without progress self-woke repeatedly"
        );
        assert!(acknowledged(&ack).is_pending());
        assert!(matches!(fixture.write(b"next"), Poll::Ready(Ok(4))));
        assert!(fixture.flush().is_pending());
        assert_eq!(
            fixture.wakes(),
            2,
            "new positive progress did not re-arm once"
        );
        assert!(acknowledged(&ack).is_pending());
    }

    #[tokio::test]
    async fn pending_failed_and_zero_writes_do_not_arm_repoll() {
        for mode in 0..4 {
            let mut fixture = Fixture::new();
            let ack = fixture.coalesced();
            fixture.control.write.store(mode, Ordering::SeqCst);
            let input = if mode == 0 { &b""[..] } else { &b"wire"[..] };
            let result = fixture.write(input);
            match mode {
                0 | 3 => assert!(matches!(result, Poll::Ready(Ok(0)))),
                1 => assert!(result.is_pending()),
                _ => assert!(matches!(result, Poll::Ready(Err(_)))),
            }
            assert!(fixture.flush().is_pending());
            assert_eq!(fixture.wakes(), 0, "non-progress write armed mode {mode}");
            assert!(acknowledged(&ack).is_pending());
        }
    }

    #[tokio::test]
    async fn only_true_flush_confirms_both_receipt_kinds_and_clears_progress() {
        let mut fixture = Fixture::new();
        let ack = fixture.coalesced();
        let mut receipt = fixture.strong();
        assert!(matches!(fixture.write(b"wire"), Poll::Ready(Ok(4))));
        assert!(fixture.flush().is_pending());
        assert!(matches!(
            receipt.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(acknowledged(&ack).is_pending());
        fixture.control.flush.store(1, Ordering::SeqCst);
        assert!(matches!(fixture.flush(), Poll::Ready(Ok(()))));
        receipt.await.unwrap().unwrap();
        assert!(matches!(acknowledged(&ack), Poll::Ready(Ok(()))));
        fixture.driver.0.store(0, Ordering::SeqCst);
        fixture.control.flush.store(0, Ordering::SeqCst);
        assert!(fixture.flush().is_pending());
        assert_eq!(
            fixture.wakes(),
            0,
            "completed flush retained stale progress"
        );
    }

    #[tokio::test]
    async fn error_and_driver_drop_fail_waiters_without_private_rescheduling() {
        let mut fixture = Fixture::new();
        let ack = fixture.coalesced();
        let receipt = fixture.strong();
        assert!(matches!(fixture.write(b"wire"), Poll::Ready(Ok(4))));
        fixture.control.flush.store(2, Ordering::SeqCst);
        assert!(matches!(fixture.flush(), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::ConnectionReset));
        assert_eq!(fixture.wakes(), 0, "flush error scheduled a progress retry");
        assert_eq!(
            receipt.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert!(matches!(acknowledged(&ack), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::ConnectionReset));

        let mut fixture = Fixture::new();
        let ack = fixture.coalesced();
        let receipt = fixture.strong();
        assert!(matches!(fixture.write(b"wire"), Poll::Ready(Ok(4))));
        let driver = fixture.driver.clone();
        drop(fixture.raw);
        assert!(
            receipt.await.is_err(),
            "driver Drop reported a strong receipt"
        );
        assert!(matches!(acknowledged(&ack), Poll::Ready(Err(_))));
        assert_eq!(
            driver.0.load(Ordering::SeqCst),
            0,
            "driver Drop scheduled new work"
        );
    }

    #[tokio::test]
    async fn expired_coalesced_owner_does_not_qualify_ordinary_progress() {
        let mut fixture = Fixture::new();
        let ack = fixture.coalesced();
        drop(ack);
        assert!(matches!(fixture.write(b"wire"), Poll::Ready(Ok(4))));
        assert!(fixture.flush().is_pending());
        assert_eq!(fixture.wakes(), 0, "dead private marker scheduled work");
    }
}
