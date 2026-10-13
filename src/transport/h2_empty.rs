//! TrustTunnel's legal empty DATA compatibility at the supplied H2 IO boundary.
//! Official h2 still owns decoding, flow control and every non-noop frame.
use super::h2_write::Payload;
use crate::dispatch::BoxStream;
use futures_util::task::AtomicWaker;
use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, TryLockError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Default)]
pub(super) struct Registry(Arc<RegistryInner>);

#[derive(Default)]
struct RegistryInner {
    streams: Mutex<BTreeMap<u32, Arc<Slot>>>,
    reader: Arc<AtomicWaker>,
    waiting: AtomicBool,
    stopped: AtomicBool,
    #[cfg(test)]
    filtered: std::sync::atomic::AtomicUsize,
}

struct Slot {
    admitted: AtomicBool,
    closed: AtomicBool,
    send: Weak<SharedSend>,
}

pub(super) struct Ticket {
    registry: Weak<RegistryInner>,
    id: u32,
    slot: Arc<Slot>,
}

pub(super) struct Admission(Weak<Slot>);

impl Admission {
    pub fn activate(&self) {
        if let Some(slot) = self.0.upgrade()
            && !slot.closed.load(Ordering::Acquire)
        {
            slot.admitted.store(true, Ordering::Release);
        }
    }
}

impl Ticket {
    pub fn admission(&self) -> Admission {
        Admission(Arc::downgrade(&self.slot))
    }
    pub fn close(&self) {
        self.slot.closed.store(true, Ordering::Release);
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.close();
        if let Some(registry) = self.registry.upgrade() {
            registry.streams.lock().unwrap().remove(&self.id);
            registry.wake_waiter();
        }
    }
}

impl RegistryInner {
    fn wake_waiter(&self) {
        if self.waiting.swap(false, Ordering::AcqRel) {
            self.reader.wake();
        }
    }
}

impl Registry {
    pub fn wrap(&self, raw: BoxStream) -> BoxStream {
        Box::new(EmptyIo {
            raw,
            registry: self.clone(),
            header: [0; 9],
            have: 0,
            emitted: 0,
            ready: false,
            remaining: 0,
            progress: false,
            eof: false,
            continuation: None,
            disabled: false,
            consecutive: 0,
            failed: false,
        })
    }

    pub fn request(
        &self,
        sender: &mut h2::client::SendRequest<Payload>,
        request: http::Request<()>,
        end: bool,
    ) -> Result<(h2::client::ResponseFuture, Send, Ticket), h2::Error> {
        // Register the actual ID before the connection reader can inspect its
        // response. Its try_lock path never blocks while h2 holds another lock.
        let mut streams = self.0.streams.lock().unwrap();
        let result = sender.send_request(request, end).map(|(response, raw)| {
            let id = raw.stream_id().as_u32();
            let send = Arc::new(SharedSend {
                raw: Mutex::new(raw),
                wake: Arc::new(StreamWake {
                    writer: AtomicWaker::new(),
                    reader: self.0.reader.clone(),
                    waiting: AtomicBool::new(false),
                }),
            });
            let slot = Arc::new(Slot {
                admitted: AtomicBool::new(false),
                closed: AtomicBool::new(self.0.stopped.load(Ordering::Acquire)),
                send: Arc::downgrade(&send),
            });
            streams.insert(id, slot.clone());
            (
                response,
                Send::Shared(send),
                Ticket {
                    registry: Arc::downgrade(&self.0),
                    id,
                    slot,
                },
            )
        });
        drop(streams);
        self.0.wake_waiter();
        result
    }

    pub fn stop(&self) {
        self.0.stopped.store(true, Ordering::Release);
        let mut streams = self.0.streams.lock().unwrap();
        for slot in streams.values() {
            slot.closed.store(true, Ordering::Release);
        }
        streams.clear();
        drop(streams);
        self.0.wake_waiter();
    }

    fn slot(&self, id: u32, cx: &mut Context<'_>) -> Poll<Option<Arc<Slot>>> {
        self.0.reader.register(cx.waker());
        let mut streams = self.0.streams.try_lock();
        if matches!(streams, Err(TryLockError::WouldBlock)) {
            self.0.waiting.store(true, Ordering::Release);
            streams = self.0.streams.try_lock();
        }
        match streams {
            Ok(streams) => {
                let slot = streams.get(&id).cloned();
                drop(streams);
                self.0.wake_waiter();
                Poll::Ready(slot)
            }
            Err(TryLockError::WouldBlock) => Poll::Pending,
            Err(TryLockError::Poisoned(_)) => Poll::Ready(None),
        }
    }

    fn open(slot: &Slot) -> bool {
        slot.admitted.load(Ordering::Acquire) && !slot.closed.load(Ordering::Acquire)
    }

    fn eligible(&self, id: u32, cx: &mut Context<'_>) -> Poll<bool> {
        if self.0.stopped.load(Ordering::Acquire) {
            return Poll::Ready(false);
        }
        let Some(slot) = std::task::ready!(self.slot(id, cx)) else {
            return Poll::Ready(false);
        };
        if !Self::open(&slot) {
            return Poll::Ready(false);
        }
        let Some(send) = slot.send.upgrade() else {
            slot.closed.store(true, Ordering::Release);
            return Poll::Ready(false);
        };
        let mut raw = send.raw.try_lock();
        if matches!(raw, Err(TryLockError::WouldBlock)) {
            send.wake.waiting.store(true, Ordering::Release);
            raw = send.raw.try_lock();
        }
        let mut raw = match raw {
            Ok(raw) => raw,
            Err(TryLockError::WouldBlock) => return Poll::Pending,
            Err(TryLockError::Poisoned(_)) => return Poll::Ready(false),
        };
        let waker = Waker::from(send.wake.clone());
        let reset = raw.poll_reset(&mut Context::from_waker(&waker));
        drop(raw);
        send.wake.release_waiter();
        if reset.is_ready() {
            slot.closed.store(true, Ordering::Release);
        }
        Poll::Ready(reset.is_pending() && Self::open(&slot))
    }

    #[cfg(test)]
    pub fn filtered(&self) -> usize {
        self.0.filtered.load(Ordering::Acquire)
    }
}

struct StreamWake {
    writer: AtomicWaker,
    reader: Arc<AtomicWaker>,
    waiting: AtomicBool,
}

impl StreamWake {
    fn release_waiter(&self) {
        if self.waiting.swap(false, Ordering::AcqRel) {
            self.reader.wake();
        }
    }
}

impl Wake for StreamWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.writer.wake();
        self.reader.wake();
    }
}

pub(super) struct SharedSend {
    raw: Mutex<h2::SendStream<Payload>>,
    wake: Arc<StreamWake>,
}

pub(super) enum Send {
    Direct(h2::SendStream<Payload>),
    Shared(Arc<SharedSend>),
}

impl From<h2::SendStream<Payload>> for Send {
    fn from(raw: h2::SendStream<Payload>) -> Self {
        Self::Direct(raw)
    }
}

impl Send {
    fn with<T>(&mut self, operation: impl FnOnce(&mut h2::SendStream<Payload>) -> T) -> T {
        match self {
            Self::Direct(raw) => operation(raw),
            Self::Shared(send) => {
                let mut raw = send.raw.lock().unwrap();
                let result = operation(&mut raw);
                drop(raw);
                send.wake.release_waiter();
                result
            }
        }
    }
    fn poll<T>(
        &mut self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&mut h2::SendStream<Payload>, &mut Context<'_>) -> T,
    ) -> T {
        match self {
            Self::Direct(raw) => operation(raw, cx),
            Self::Shared(send) => {
                send.wake.writer.register(cx.waker());
                let waker = Waker::from(send.wake.clone());
                let mut raw = send.raw.lock().unwrap();
                let result = operation(&mut raw, &mut Context::from_waker(&waker));
                drop(raw);
                send.wake.release_waiter();
                result
            }
        }
    }
    pub fn reserve_capacity(&mut self, size: usize) {
        self.with(|raw| raw.reserve_capacity(size));
    }
    pub fn poll_capacity(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<usize, h2::Error>>> {
        self.poll(cx, |raw, cx| raw.poll_capacity(cx))
    }
    pub fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<h2::Reason, h2::Error>> {
        self.poll(cx, |raw, cx| raw.poll_reset(cx))
    }
    pub fn send_data(&mut self, payload: Payload, end: bool) -> Result<(), h2::Error> {
        self.with(|raw| raw.send_data(payload, end))
    }
    pub fn send_reset(&mut self, reason: h2::Reason) {
        self.with(|raw| raw.send_reset(reason));
    }
}

struct EmptyIo {
    raw: BoxStream,
    registry: Registry,
    header: [u8; 9],
    have: usize,
    emitted: usize,
    ready: bool,
    remaining: usize,
    progress: bool,
    eof: bool,
    continuation: Option<u32>,
    disabled: bool,
    consecutive: usize,
    failed: bool,
}

impl EmptyIo {
    fn frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let length = (usize::from(self.header[0]) << 16)
            | (usize::from(self.header[1]) << 8)
            | usize::from(self.header[2]);
        let kind = self.header[3];
        let flags = self.header[4];
        let wire_id = u32::from_be_bytes(self.header[5..9].try_into().unwrap());
        let id = wire_id & 0x7fff_ffff;
        let valid_id = id != 0 && wire_id == id;
        // Resolve locks before changing parser state: Pending retries the same
        // header and must not commit a CONTINUATION transition twice.
        let slot = if valid_id && matches!(kind, 0 | 1 | 3) {
            std::task::ready!(self.registry.slot(id, cx))
        } else {
            None
        };
        let candidate = kind == 0
            && length == 0
            && flags == 0
            && valid_id
            && id & 1 == 1
            && !self.disabled
            && self.continuation.is_none();
        let eligible = candidate && std::task::ready!(self.registry.eligible(id, cx));
        if let Some(expected) = self.continuation
            && (kind != 9 || id != expected)
        {
            self.disabled = true;
        }
        if kind == 9 {
            if self.continuation != Some(id) {
                self.disabled = true;
            } else if flags & 4 != 0 {
                self.continuation = None;
            }
        } else if kind == 1 && flags & 4 == 0 {
            self.continuation = Some(id);
        }
        if kind == 7 {
            self.disabled = true;
        }
        if let Some(slot) = slot {
            if kind == 3
                || (matches!(kind, 0 | 1) && flags & 1 != 0)
                || (kind == 1 && slot.admitted.load(Ordering::Acquire))
            {
                slot.closed.store(true, Ordering::Release);
            }
            self.progress = kind == 0 && length > 0 && flags & 8 == 0 && Registry::open(&slot);
        }
        if eligible {
            self.consecutive += 1;
            if self.consecutive > 100 {
                self.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP2 consecutive empty DATA limit",
                )));
            }
            #[cfg(test)]
            self.registry.0.filtered.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(true));
        }
        self.remaining = length;
        Poll::Ready(Ok(false))
    }
}

impl AsyncRead for EmptyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if this.ready && this.emitted < this.have {
                let count = (this.have - this.emitted).min(out.remaining());
                out.put_slice(&this.header[this.emitted..this.emitted + count]);
                this.emitted += count;
                if this.emitted == this.have && this.remaining == 0 {
                    this.ready = false;
                    this.have = 0;
                    this.emitted = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.remaining > 0 {
                let limit = this.remaining.min(out.remaining());
                let mut part = ReadBuf::new(out.initialize_unfilled_to(limit));
                let result = Pin::new(&mut this.raw).poll_read(cx, &mut part);
                let count = part.filled().len();
                out.advance(count);
                this.remaining -= count;
                if this.remaining == 0 {
                    if this.progress {
                        this.consecutive = 0;
                    }
                    this.progress = false;
                    this.ready = false;
                    this.have = 0;
                    this.emitted = 0;
                }
                // Never read ahead past a forwarded frame. h2 must process
                // it (including internal resets) before we inspect a noop.
                return result;
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.have < 9 {
                let mut header = ReadBuf::new(&mut this.header[this.have..]);
                std::task::ready!(Pin::new(&mut this.raw).poll_read(cx, &mut header))?;
                let count = header.filled().len();
                this.have += count;
                if count == 0 {
                    this.eof = true;
                    this.ready = this.have != 0;
                    continue;
                }
                if this.have < 9 {
                    continue;
                }
            }
            if std::task::ready!(this.frame(cx))? {
                this.have = 0;
                this.emitted = 0;
            } else {
                this.ready = true;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for EmptyIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::h2_write::{Payload, Writes};
    use super::{Registry, Send, Ticket};
    use crate::{
        dispatch::BoxStream,
        resources::observation::{self, ResourceKind, ResourceProbe},
    };
    use bytes::Bytes;
    use std::{future::poll_fn, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        sync::{mpsc, oneshot},
        time::timeout,
    };
    use tokio_util::{sync::CancellationToken, task::TaskTracker};

    const DEADLINE: Duration = Duration::from_secs(5);

    struct Client {
        registry: Registry,
        sender: Option<h2::client::SendRequest<Payload>>,
        cancellation: CancellationToken,
        tasks: TaskTracker,
        completed: Option<oneshot::Receiver<Option<Result<(), h2::Error>>>>,
    }

    impl Client {
        async fn new(
            raw: DuplexStream,
            cancellation: CancellationToken,
            tasks: TaskTracker,
        ) -> Self {
            let registry = Registry::default();
            let (raw, _writes) = Writes::wrap(Box::new(raw) as BoxStream);
            let (sender, connection) = h2::client::Builder::new()
                .enable_push(false)
                .initial_window_size(64 * 1024)
                .initial_connection_window_size(128 * 1024)
                .handshake::<_, Payload>(registry.wrap(Box::new(raw)))
                .await
                .unwrap();
            let (done, completed) = oneshot::channel();
            let cancel = cancellation.clone();
            tasks.spawn(observation::task(async move {
                let result = tokio::select! { biased;
                    () = cancel.cancelled() => None,
                    result = connection => Some(result),
                };
                let _ = done.send(result);
            }));
            Self {
                registry,
                sender: Some(sender),
                cancellation,
                tasks,
                completed: Some(completed),
            }
        }

        async fn request(&mut self) -> (h2::client::ResponseFuture, Send, Ticket, u32) {
            let sender = self.sender.as_mut().unwrap();
            poll_fn(|cx| sender.poll_ready(cx)).await.unwrap();
            let request = http::Request::builder()
                .method("CONNECT")
                .uri(
                    http::Uri::builder()
                        .authority("memory.invalid:443")
                        .build()
                        .unwrap(),
                )
                .body(())
                .unwrap();
            let (response, send, ticket) = self.registry.request(sender, request, false).unwrap();
            let id = response.stream_id().as_u32();
            (response, send, ticket, id)
        }

        async fn failure(&mut self) -> h2::Error {
            self.completed
                .take()
                .unwrap()
                .await
                .unwrap()
                .expect("driver was cancelled before its protocol result")
                .expect_err("driver accepted the invalid sequence")
        }

        async fn stop(&mut self) {
            self.registry.stop();
            self.cancellation.cancel();
            self.tasks.close();
            self.tasks.wait().await;
            assert!(self.tasks.is_empty());
            self.sender.take();
            if let Some(completed) = self.completed.take() {
                let _ = completed.await.unwrap();
            }
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            self.registry.stop();
            self.cancellation.cancel();
        }
    }

    struct Request {
        response: h2::server::SendResponse<Bytes>,
        _receive: h2::RecvStream,
    }

    async fn official_peer() -> (Client, mpsc::Receiver<Request>) {
        let (raw, peer) = tokio::io::duplex(64 * 1024);
        let tasks = TaskTracker::new();
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let (requests, accepted) = mpsc::channel(2);
        tasks.spawn(observation::task(async move {
            let handshake = tokio::select! { biased;
                () = cancel.cancelled() => return,
                result = h2::server::handshake(peer) => result,
            };
            let Ok(mut connection) = handshake else {
                return;
            };
            loop {
                let request = tokio::select! { biased;
                    () = cancel.cancelled() => break,
                    request = connection.accept() => request,
                };
                let Some(Ok((request, response))) = request else {
                    break;
                };
                let owned = Request {
                    response,
                    _receive: request.into_body(),
                };
                tokio::select! { biased;
                    () = cancel.cancelled() => break,
                    result = requests.send(owned) => if result.is_err() { break; },
                }
            }
        }));
        (Client::new(raw, cancellation, tasks).await, accepted)
    }

    async fn body(receive: &mut h2::RecvStream) -> Vec<u8> {
        let mut output = Vec::new();
        while let Some(frame) = receive.data().await {
            let frame = frame.unwrap();
            output.extend_from_slice(&frame);
            receive
                .flow_control()
                .release_capacity(frame.len())
                .unwrap();
        }
        output
    }

    async fn next_data(receive: &mut h2::RecvStream) -> Bytes {
        loop {
            let frame = receive.data().await.unwrap().unwrap();
            receive
                .flow_control()
                .release_capacity(frame.len())
                .unwrap();
            if !frame.is_empty() {
                return frame;
            }
        }
    }

    fn frame(kind: u8, flags: u8, id: u32, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u32;
        let mut bytes = Vec::with_capacity(9 + payload.len());
        bytes.extend_from_slice(&length.to_be_bytes()[1..]);
        bytes.extend_from_slice(&[kind, flags]);
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    async fn read_frame(peer: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
        let mut head = [0; 9];
        peer.read_exact(&mut head).await.unwrap();
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        assert!(length <= 16 * 1024);
        let mut payload = vec![0; length];
        peer.read_exact(&mut payload).await.unwrap();
        (
            head[3],
            head[4],
            u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff,
            payload,
        )
    }

    async fn raw_peer() -> (Client, DuplexStream) {
        let (raw, mut peer) = tokio::io::duplex(64 * 1024);
        let client = Client::new(raw, CancellationToken::new(), TaskTracker::new()).await;
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let (kind, flags, id, _) = read_frame(&mut peer).await;
        assert_eq!((kind, flags, id), (4, 0, 0));
        let mut settings = frame(4, 0, 0, &[]);
        settings.extend(frame(4, 1, 0, &[]));
        peer.write_all(&settings).await.unwrap();
        (client, peer)
    }

    async fn request_reached_peer(peer: &mut DuplexStream, id: u32) {
        loop {
            let (kind, flags, incoming_id, _) = read_frame(peer).await;
            if kind == 1 && incoming_id == id {
                assert_ne!(flags & 4, 0, "small request should fit one HEADERS frame");
                return;
            }
        }
    }

    async fn admit_raw(
        peer: &mut DuplexStream,
        response: h2::client::ResponseFuture,
        ticket: &Ticket,
        id: u32,
        content_length_zero: bool,
    ) -> h2::RecvStream {
        request_reached_peer(peer, id).await;
        // HPACK indexed :status=200, optionally followed by a literal header.
        let mut headers = vec![0x88];
        if content_length_zero {
            headers.extend_from_slice(&[0x00, 14]);
            headers.extend_from_slice(b"content-length");
            headers.extend_from_slice(&[1, b'0']);
        }
        peer.write_all(&frame(1, 4, id, &headers)).await.unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        ticket.admission().activate();
        response.into_body()
    }

    #[tokio::test]
    async fn interleaved_empty_data_preserves_payload_final_sibling_and_joined_stop() {
        let probe = ResourceProbe::default();
        timeout(
            DEADLINE,
            probe.scope(async {
                let (mut client, mut requests) = official_peer().await;
                let (first_response, mut first_send, first_ticket, _) = client.request().await;
                let mut first_request = requests.recv().await.unwrap();
                let mut first_peer = first_request
                    .response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut first_receive = first_response.await.unwrap().into_body();
                first_ticket.admission().activate();

                let (sibling_response, _sibling_send, sibling_ticket, _) = client.request().await;
                let mut sibling_request = requests.recv().await.unwrap();
                let mut sibling_peer = sibling_request
                    .response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut sibling_receive = sibling_response.await.unwrap().into_body();
                sibling_ticket.admission().activate();

                for value in 0..101u8 {
                    first_peer.send_data(Bytes::new(), false).unwrap();
                    first_peer
                        .send_data(Bytes::copy_from_slice(&[value]), false)
                        .unwrap();
                }
                first_peer.send_data(Bytes::new(), true).unwrap();
                assert_eq!(
                    body(&mut first_receive).await,
                    (0..101u8).collect::<Vec<_>>()
                );
                assert_eq!(client.registry.filtered(), 101);
                first_ticket.close();
                first_send.send_reset(h2::Reason::CANCEL);
                sibling_peer
                    .send_data(Bytes::from_static(b"alive"), false)
                    .unwrap();
                assert_eq!(next_data(&mut sibling_receive).await.as_ref(), b"alive");
                assert_eq!(
                    client.registry.filtered(),
                    101,
                    "final DATA must remain visible to h2"
                );

                client.stop().await;
                assert!(!matches!(sibling_receive.data().await, Some(Ok(_))));
                assert_eq!(probe.snapshot().current(ResourceKind::Task), 0);
                assert!(probe.snapshot().peak(ResourceKind::Task) >= 2);
            }),
        )
        .await
        .unwrap();
        assert!(probe.snapshot().is_idle());
    }

    #[tokio::test]
    async fn ineligible_and_invalid_data_remain_owned_by_the_official_h2_validator() {
        let probe = ResourceProbe::default();
        timeout(
            DEADLINE,
            probe.scope(async {
                // DATA before response HEADERS and DATA on an unknown stream.
                for unknown in [false, true] {
                    let (mut client, mut peer) = raw_peer().await;
                    let (_response, _send, _ticket, id) = client.request().await;
                    request_reached_peer(&mut peer, id).await;
                    peer.write_all(&frame(0, 0, if unknown { id + 2 } else { id }, &[]))
                        .await
                        .unwrap();
                    assert_eq!(
                        client.failure().await.reason(),
                        Some(h2::Reason::PROTOCOL_ERROR)
                    );
                    assert_eq!(client.registry.filtered(), 0);
                    client.stop().await;
                }

                // A DATA frame cannot interrupt even an already admitted stream's
                // unfinished trailing header block.
                {
                    let (mut client, mut peer) = raw_peer().await;
                    let (response, _send, ticket, id) = client.request().await;
                    let _receive = admit_raw(&mut peer, response, &ticket, id, false).await;
                    let mut bytes = frame(1, 0, id, &[]);
                    bytes.extend(frame(0, 0, id, &[]));
                    peer.write_all(&bytes).await.unwrap();
                    assert_eq!(
                        client.failure().await.reason(),
                        Some(h2::Reason::PROTOCOL_ERROR)
                    );
                    assert_eq!(client.registry.filtered(), 0);
                    client.stop().await;
                }

                // A valid split response becomes eligible only after the official
                // decoder has accepted its CONTINUATION and final response.
                {
                    let (mut client, mut peer) = raw_peer().await;
                    let (response, _send, ticket, id) = client.request().await;
                    request_reached_peer(&mut peer, id).await;
                    let mut bytes = frame(1, 0, id, &[0x88]);
                    bytes.extend(frame(9, 4, id, &[]));
                    peer.write_all(&bytes).await.unwrap();
                    let mut receive = response.await.unwrap().into_body();
                    ticket.admission().activate();
                    let mut bytes = frame(0, 0, id, &[]);
                    bytes.extend(frame(0, 0, id, b"continued"));
                    bytes.extend(frame(0, 1, id, &[]));
                    peer.write_all(&bytes).await.unwrap();
                    assert_eq!(body(&mut receive).await, b"continued");
                    assert_eq!(client.registry.filtered(), 1);
                    client.stop().await;
                }

                // Padding consumes flow control even when its application payload
                // is empty. Neither PADDED DATA nor final empty DATA may be filtered.
                {
                    let (mut client, mut peer) = raw_peer().await;
                    let (response, _send, ticket, id) = client.request().await;
                    let mut receive = admit_raw(&mut peer, response, &ticket, id, false).await;
                    let mut bytes = frame(0, 8, id, &[0]);
                    bytes.extend(frame(0, 0, id, b"padded"));
                    bytes.extend(frame(0, 1, id, &[]));
                    peer.write_all(&bytes).await.unwrap();
                    assert_eq!(body(&mut receive).await, b"padded");
                    assert_eq!(client.registry.filtered(), 0);
                    client.stop().await;
                }

                // Close, Drop and registry Stop must each win over a late
                // admission callback while the underlying h2 stream is alive.
                for revocation in 0..3 {
                    let (mut client, mut peer) = raw_peer().await;
                    let (response, _send, ticket, id) = client.request().await;
                    let mut receive = admit_raw(&mut peer, response, &ticket, id, false).await;
                    let late = ticket.admission();
                    match revocation {
                        0 => ticket.close(),
                        1 => drop(ticket),
                        2 => client.registry.stop(),
                        _ => unreachable!(),
                    }
                    late.activate();
                    let mut bytes = frame(0, 0, id, &[]);
                    bytes.extend(frame(0, 0, id, b"closed-ticket"));
                    peer.write_all(&bytes).await.unwrap();
                    assert_eq!(next_data(&mut receive).await.as_ref(), b"closed-ticket");
                    assert_eq!(
                        client.registry.filtered(),
                        0,
                        "revocation {revocation} was undone"
                    );
                    client.stop().await;
                }

                // Empty DATA after remote END_STREAM must still reach h2's
                // closed-stream validation; it is not an eligible no-op.
                {
                    let (mut client, mut peer) = raw_peer().await;
                    let (response, _send, ticket, id) = client.request().await;
                    let _receive = admit_raw(&mut peer, response, &ticket, id, false).await;
                    let mut bytes = frame(0, 1, id, &[]);
                    bytes.extend(frame(0, 0, id, &[]));
                    peer.write_all(&bytes).await.unwrap();
                    assert_eq!(
                        client.failure().await.reason(),
                        Some(h2::Reason::PROTOCOL_ERROR)
                    );
                    assert_eq!(client.registry.filtered(), 0);
                    client.stop().await;
                }

                // A content-length violation causes an internally generated stream reset.
                // Its following empty DATA is in the SAME peer write, before the
                // queued RST_STREAM needs to reach the peer. A sibling marker proves
                // the client processed the complete input batch without swallowing it.
                {
                    let (mut client, mut peer) = raw_peer().await;
                    let (response, _send, ticket, id) = client.request().await;
                    let mut receive = admit_raw(&mut peer, response, &ticket, id, true).await;
                    let (response, _sibling_send, sibling_ticket, sibling_id) =
                        client.request().await;
                    let mut sibling =
                        admit_raw(&mut peer, response, &sibling_ticket, sibling_id, false).await;
                    let mut bytes = frame(0, 0, id, b"x");
                    bytes.extend(frame(0, 0, id, &[]));
                    bytes.extend(frame(0, 0, sibling_id, b"alive"));
                    peer.write_all(&bytes).await.unwrap();
                    let error = receive.data().await.unwrap().unwrap_err();
                    assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
                    assert_eq!(next_data(&mut sibling).await.as_ref(), b"alive");
                    assert_eq!(
                        client.registry.filtered(),
                        0,
                        "internally reset stream DATA was filtered"
                    );
                    client.stop().await;
                }
            }),
        )
        .await
        .unwrap();
        assert!(probe.snapshot().is_idle());
    }

    #[tokio::test]
    async fn consecutive_empty_data_without_payload_progress_is_bounded_and_stopped() {
        let probe = ResourceProbe::default();
        timeout(
            DEADLINE,
            probe.scope(async {
                let (mut client, mut requests) = official_peer().await;
                let (response, _send, ticket, _) = client.request().await;
                let mut request = requests.recv().await.unwrap();
                let mut peer = request
                    .response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let _receive = response.await.unwrap().into_body();
                ticket.admission().activate();
                for _ in 0..101 {
                    peer.send_data(Bytes::new(), false).unwrap();
                }
                let error = client.failure().await;
                assert!(error.is_io() || error.reason() == Some(h2::Reason::ENHANCE_YOUR_CALM));
                assert_eq!(
                    client.registry.filtered(),
                    100,
                    "101st empty frame must terminate a no-progress flood"
                );
                client.stop().await;
                assert_eq!(probe.snapshot().current(ResourceKind::Task), 0);
            }),
        )
        .await
        .unwrap();
        assert!(probe.snapshot().is_idle());
    }
    // Insert inside h2_empty.rs's existing `mod tests`; no network peer is created.
    #[tokio::test]
    async fn registry_contention_retries_split_headers_without_disabling_noop_admission() {
        let (mut peer, raw) = tokio::io::duplex(64);
        let registry = Registry::default();
        let mut io = super::EmptyIo {
            raw: Box::new(raw),
            registry: registry.clone(),
            header: [0; 9],
            have: 0,
            emitted: 0,
            ready: false,
            remaining: 0,
            progress: false,
            eof: false,
            continuation: None,
            disabled: false,
            consecutive: 0,
            failed: false,
        };
        let mut expected = frame(1, 0, 1, &[0x88]);
        expected.extend(frame(9, 4, 1, &[]));
        peer.write_all(&expected).await.unwrap();

        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        let mut storage = [0; 32];
        let mut output = tokio::io::ReadBuf::new(&mut storage);
        // The mutex is held only across this synchronous poll, never across await.
        let held = registry.0.streams.lock().unwrap();
        assert!(
            tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut io), &mut cx, &mut output)
                .is_pending()
        );
        assert!(output.filled().is_empty());
        drop(held);

        let mut received = Vec::with_capacity(expected.len());
        for _ in 0..3 {
            output.clear();
            assert!(matches!(
                tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut io), &mut cx, &mut output),
                std::task::Poll::Ready(Ok(()))
            ));
            received.extend_from_slice(output.filled());
            assert!(
                !io.disabled,
                "retry turned a valid header chain into an error"
            );
        }
        assert_eq!(received, expected);
        assert_eq!(io.continuation, None);
        assert_eq!(io.consecutive, 0);
    }
}
