//! Memory WS/mux/SS continuity, with independent logical Data and WS Message
//! boundaries. The mux peer is a finite model of official frame.go/writer.go;
//! WS handshake/frame validation and SS authentication use the actual libraries.
//! It is not execution of an official Go server or static qualification proof.
use super::Owner;
use crate::{
    config::{Config, ProxyProtocol, ShadowsocksCipher},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    },
    security::SecurityContext,
    session::{Destination, InboundKind, StreamSession},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf, Bytes};
use futures_util::{FutureExt, Sink, Stream};
use shadowsocks::{
    ServerConfig, config::ServerType, context::Context as SsContext, crypto::CipherKind,
    relay::tcprelay::proxy_stream::ProxyServerStream,
};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::oneshot,
    time::timeout,
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
        protocol::WebSocketConfig,
    },
};

const ENTITY: usize = 64 * 1024;
const WAIT: Duration = Duration::from_secs(20);
const DATA_BOUND: usize = 8 * 1024;
const WS_MESSAGE_BOUND: usize = 16 * 1024;
const META_BOUND: usize = 512;
const MAX_QUEUED_MESSAGES: usize = 3;
type Accept = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>>;
#[derive(Debug)]
struct StageError {
    name: &'static str,
    kind: io::ErrorKind,
    expected_synthetic_byte: Option<u8>,
}
impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stage={}; kind={:?}; expected-synthetic-byte={:?}",
            self.name, self.kind, self.expected_synthetic_byte
        )
    }
}
impl std::error::Error for StageError {}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        StageError {
            name: message,
            kind: io::ErrorKind::InvalidData,
            expected_synthetic_byte: None,
        },
    )
}
fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value { Ok(()) } else { Err(invalid(message)) }
}
fn stage<T>(name: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            StageError {
                name,
                kind: error.kind(),
                expected_synthetic_byte: None,
            },
        )
    })
}
fn require_pending<T>(result: Poll<io::Result<T>>, message: &'static str) -> io::Result<()> {
    match result {
        Poll::Pending => Ok(()),
        Poll::Ready(Err(error)) => Err(error),
        Poll::Ready(Ok(_)) => Err(invalid(message)),
    }
}
#[derive(Clone, Copy, Debug)]
enum FirstBoundary {
    Whole,
    DataSplit,
    MessageSplit,
}
#[derive(Default, Debug)]
struct Counts {
    opens: AtomicUsize,
    ws_accepts: AtomicUsize,
    targets: AtomicUsize,
    client_new: AtomicUsize,
    client_end: AtomicUsize,
    server_end_built: AtomicUsize,
    server_keepalive_built: AtomicUsize,
    server_binary_messages_started: AtomicUsize,
    server_close_started: AtomicUsize,
    first_data_length: AtomicUsize,
    first_cipher_message_part: AtomicUsize,
    client_write_pending: AtomicUsize,
    peer_write_pending: AtomicUsize,
    partial_writes: AtomicUsize,
    client_drops: AtomicUsize,
    peer_drops: AtomicUsize,
    response_phase: AtomicBool,
}
#[derive(Clone, Copy, Debug)]
struct Snapshot {
    opens: usize,
    ws_accepts: usize,
    targets: usize,
    client_new: usize,
    client_end: usize,
    server_end_built: usize,
    server_keepalive_built: usize,
    server_binary_messages_started: usize,
    server_close_started: usize,
    first_data_length: usize,
    first_cipher_message_part: usize,
    client_write_pending: usize,
    peer_write_pending: usize,
    partial_writes: usize,
    client_drops: usize,
    peer_drops: usize,
    response_phase: bool,
}
impl Counts {
    fn snapshot(&self) -> Snapshot {
        let load = |n: &AtomicUsize| n.load(Ordering::SeqCst);
        Snapshot {
            opens: load(&self.opens),
            ws_accepts: load(&self.ws_accepts),
            targets: load(&self.targets),
            client_new: load(&self.client_new),
            client_end: load(&self.client_end),
            server_end_built: load(&self.server_end_built),
            server_keepalive_built: load(&self.server_keepalive_built),
            server_binary_messages_started: load(&self.server_binary_messages_started),
            server_close_started: load(&self.server_close_started),
            first_data_length: load(&self.first_data_length),
            first_cipher_message_part: load(&self.first_cipher_message_part),
            client_write_pending: load(&self.client_write_pending),
            peer_write_pending: load(&self.peer_write_pending),
            partial_writes: load(&self.partial_writes),
            client_drops: load(&self.client_drops),
            peer_drops: load(&self.peer_drops),
            response_phase: self.response_phase.load(Ordering::SeqCst),
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct CleanupReceipt {
    shutdown_returned: bool,
    owner_cancelled: bool,
    owner_closed: bool,
    tracker_closed: bool,
    tracker_empty: bool,
    client_drops: usize,
    peer_drops: usize,
    counter_weak_released: bool,
}
impl CleanupReceipt {
    fn complete(self) -> bool {
        self.shutdown_returned
            && self.owner_cancelled
            && self.owner_closed
            && self.tracker_closed
            && self.tracker_empty
            && self.client_drops == 1
            && self.peer_drops == 1
            && self.counter_weak_released
    }
}
#[derive(Clone, Copy, Debug)]
enum FailureClass {
    Io,
    Deadline,
    Unwind,
    Invariant,
}
#[derive(Debug)]
struct CaseFailure {
    class: FailureClass,
    stage: &'static str,
    kind: Option<io::ErrorKind>,
    expected_synthetic_byte: Option<u8>,
    cancelled_before_cleanup: bool,
    cleanup: CleanupReceipt,
    counts: Snapshot,
}
impl std::fmt::Display for CaseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "class={:?}; stage={}; kind={:?}; expected-synthetic-byte={:?}; cancelled-before-cleanup={}; cleanup={:?}; counts={:?}",
            self.class,
            self.stage,
            self.kind,
            self.expected_synthetic_byte,
            self.cancelled_before_cleanup,
            self.cleanup,
            self.counts
        )
    }
}
fn io_label(error: &io::Error) -> (&'static str, io::ErrorKind, Option<u8>) {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<StageError>())
    {
        Some(label) => (label.name, label.kind, label.expected_synthetic_byte),
        None => ("unlabelled-io", error.kind(), None),
    }
}

struct Raw {
    io: DuplexStream,
    counts: Arc<Counts>,
    server: bool,
    blocked: Option<oneshot::Sender<()>>,
}
impl Drop for Raw {
    fn drop(&mut self) {
        let counter = if self.server {
            &self.counts.peer_drops
        } else {
            &self.counts.client_drops
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsyncRead for Raw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, out)
    }
}
impl AsyncWrite for Raw {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let limit = if this.server {
            input.len().min(31)
        } else {
            input.len()
        };
        let result = Pin::new(&mut this.io).poll_write(cx, &input[..limit]);
        match &result {
            Poll::Pending if this.server => {
                this.counts
                    .peer_write_pending
                    .fetch_add(1, Ordering::SeqCst);
                // Upgrade backpressure must not satisfy the response-body gate.
                if this.counts.response_phase.load(Ordering::SeqCst) {
                    if let Some(signal) = this.blocked.take() {
                        let _ = signal.send(());
                    }
                }
            }
            Poll::Pending => {
                this.counts
                    .client_write_pending
                    .fetch_add(1, Ordering::SeqCst);
            }
            Poll::Ready(Ok(n)) if *n < input.len() => {
                this.counts.partial_writes.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
struct MemoryUpstream {
    io: Mutex<Option<BoxStream>>,
    counts: Arc<Counts>,
    server: Destination,
}
#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        if session.destination != self.server {
            return Err(DispatchError::NotAllowed);
        }
        let io = self
            .io
            .lock()
            .unwrap()
            .take()
            .ok_or(DispatchError::NotAllowed)?;
        self.counts.opens.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectedStream {
            io,
            effective_peer: self.server.clone(),
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

// This model only serves the one channel the actual client opens. It consumes
// real WS Messages as a byte stream, independently of TCP read fragmentation.
struct MuxPeer {
    ws: WebSocketStream<Raw>,
    incoming: Bytes,
    meta: Vec<u8>,
    remaining: usize,
    got_new: bool,
    channel_end: bool,
    transport_end: bool,
    outgoing: VecDeque<Message>,
    prefix: Vec<u8>,
    first_length: usize,
    first_done: bool,
    ending: bool,
    boundary: FirstBoundary,
    counts: Arc<Counts>,
}
impl MuxPeer {
    fn poll_messages(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.outgoing.is_empty() {
                return Pin::new(&mut self.ws)
                    .poll_flush(cx)
                    .map_err(|_| invalid("mux.peer.ws.flush"));
            }
            ready!(Pin::new(&mut self.ws).poll_ready(cx))
                .map_err(|_| invalid("mux.peer.ws.ready"))?;
            let message = self.outgoing.pop_front().expect("bounded message present");
            match &message {
                Message::Binary(_) => {
                    self.counts
                        .server_binary_messages_started
                        .fetch_add(1, Ordering::SeqCst);
                }
                Message::Close(_) => {
                    self.counts
                        .server_close_started
                        .fetch_add(1, Ordering::SeqCst);
                }
                _ => return Poll::Ready(Err(invalid("unexpected model output"))),
            }
            Pin::new(&mut self.ws)
                .start_send(message)
                .map_err(|_| invalid("mux.peer.ws.start"))?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn poll_ws_read(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if !self.incoming.is_empty() {
                let amount = out.remaining().min(self.incoming.len());
                out.put_slice(&self.incoming[..amount]);
                self.incoming.advance(amount);
                return Poll::Ready(Ok(()));
            }
            if self.transport_end {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => {
                    check(bytes.len() <= WS_MESSAGE_BOUND, "client WS message bound")?;
                    self.incoming = bytes;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    self.transport_end = true;
                }
                Some(Ok(Message::Text(_) | Message::Frame(_))) | Some(Err(_)) => {
                    return Poll::Ready(Err(invalid("mux.peer.ws.read")));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn fill(&mut self, cx: &mut Context<'_>, target: usize) -> Poll<io::Result<bool>> {
        check(target <= META_BOUND + 4, "mux metadata bound")?;
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.meta.len() >= target {
                return Poll::Ready(Ok(true));
            }
            let mut bytes = [0; 64];
            let amount = (target - self.meta.len()).min(bytes.len());
            let mut read = ReadBuf::new(&mut bytes[..amount]);
            ready!(self.poll_ws_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return if self.meta.is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(invalid("truncated client mux metadata")))
                };
            }
            self.meta.extend_from_slice(read.filled());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn queue_binary(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        check(
            bytes.len() <= WS_MESSAGE_BOUND && self.outgoing.len() < MAX_QUEUED_MESSAGES,
            "bounded model WS queue",
        )?;
        self.outgoing.push_back(Message::Binary(bytes.into()));
        Ok(())
    }
    fn first_messages(&mut self) -> io::Result<()> {
        check(
            self.prefix.len() == self.first_length,
            "complete synthetic server framing prefix",
        )?;
        self.counts.response_phase.store(true, Ordering::SeqCst);
        // A real non-data KeepAlive precedes the first response Keep/Data.
        self.queue_binary(vec![0, 4, 0, 0, 4, 0])?;
        self.counts
            .server_keepalive_built
            .fetch_add(1, Ordering::SeqCst);
        let prefix = std::mem::take(&mut self.prefix);
        match self.boundary {
            FirstBoundary::Whole => {
                self.counts
                    .first_data_length
                    .store(prefix.len(), Ordering::SeqCst);
                self.counts
                    .first_cipher_message_part
                    .store(prefix.len(), Ordering::SeqCst);
                self.queue_binary(keep_data(&prefix)?)?;
            }
            FirstBoundary::DataSplit => {
                let cut = prefix.len() - 1;
                self.counts.first_data_length.store(cut, Ordering::SeqCst);
                // Two legal Data records in ONE actual Binary Message.
                self.counts
                    .first_cipher_message_part
                    .store(prefix.len(), Ordering::SeqCst);
                let mut bytes = keep_data(&prefix[..cut])?;
                bytes.extend_from_slice(&keep_data(&prefix[cut..])?);
                self.queue_binary(bytes)?;
            }
            FirstBoundary::MessageSplit => {
                self.counts
                    .first_data_length
                    .store(prefix.len(), Ordering::SeqCst);
                self.counts
                    .first_cipher_message_part
                    .store(prefix.len() - 1, Ordering::SeqCst);
                let bytes = keep_data(&prefix)?;
                let cut = 8 + prefix.len() - 1;
                // ONE legal Data record split across TWO Binary Messages,
                // not a raw TCP fragment or an unfinished WS continuation.
                self.queue_binary(bytes[..cut].to_vec())?;
                self.queue_binary(bytes[cut..].to_vec())?;
            }
        }
        self.first_done = true;
        Ok(())
    }
}
fn keep_data(payload: &[u8]) -> io::Result<Vec<u8>> {
    check(
        !payload.is_empty() && payload.len() <= DATA_BOUND,
        "server mux Data bound",
    )?;
    let mut bytes = vec![0, 4, 0, 0, 2, 1];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
impl AsyncRead for MuxPeer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(result) = this.poll_messages(cx) {
            result?;
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if this.remaining != 0 {
                let amount = this.remaining.min(out.remaining());
                let mut limited = ReadBuf::new(out.initialize_unfilled_to(amount));
                ready!(this.poll_ws_read(cx, &mut limited))?;
                let amount = limited.filled().len();
                check(amount != 0, "truncated client mux Data")?;
                out.advance(amount);
                this.remaining -= amount;
                return Poll::Ready(Ok(()));
            }
            if this.channel_end {
                return Poll::Ready(Ok(()));
            }
            check(ready!(this.fill(cx, 2))?, "client WS closed before mux End")?;
            let metadata = usize::from(u16::from_be_bytes([this.meta[0], this.meta[1]]));
            check(
                (4..=META_BOUND).contains(&metadata),
                "client mux metadata length",
            )?;
            check(
                ready!(this.fill(cx, 2 + metadata))?,
                "client mux metadata EOF",
            )?;
            check(this.meta[2..4] == [0, 0], "single channel0")?;
            let status = this.meta[4];
            let flags = this.meta[5];
            check(flags & !3 == 0, "client mux flags")?;
            if flags & 1 != 0 {
                check(
                    ready!(this.fill(cx, 4 + metadata))?,
                    "client mux Data length EOF",
                )?;
            }
            match status {
                1 => {
                    check(
                        !this.got_new
                            && metadata == 12
                            && this.meta[2..14] == [0, 0, 1, 0, 1, 0, 0, 1, 127, 0, 0, 1],
                        "one exact client TCP New",
                    )?;
                    this.got_new = true;
                    this.counts.client_new.fetch_add(1, Ordering::SeqCst);
                }
                2 => {
                    check(
                        this.got_new && metadata == 4 && flags == 1,
                        "client Keep/Data shape",
                    )?;
                }
                3 => {
                    check(
                        this.got_new && metadata == 4 && flags == 0,
                        "clean client End shape",
                    )?;
                    this.channel_end = true;
                    this.counts.client_end.fetch_add(1, Ordering::SeqCst);
                }
                4 => {
                    check(metadata == 4 && flags == 0, "client KeepAlive shape")?;
                }
                _ => return Poll::Ready(Err(invalid("client mux status"))),
            }
            if flags & 1 != 0 {
                this.remaining = usize::from(u16::from_be_bytes([
                    this.meta[2 + metadata],
                    this.meta[3 + metadata],
                ]));
                check(this.remaining <= 16 * 1024, "client mux Data body bound")?;
            }
            this.meta.clear();
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for MuxPeer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        check(!this.ending, "server write after End")?;
        ready!(this.poll_messages(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let amount = if !this.first_done {
            let amount = input.len().min(this.first_length - this.prefix.len());
            this.prefix.extend_from_slice(&input[..amount]);
            if this.prefix.len() == this.first_length {
                this.first_messages()?;
            }
            amount
        } else {
            let amount = input.len().min(DATA_BOUND);
            this.queue_binary(keep_data(&input[..amount])?)?;
            amount
        };
        if let Poll::Ready(result) = this.poll_messages(cx) {
            result?;
        }
        Poll::Ready(Ok(amount))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        check(
            this.first_done || this.prefix.is_empty(),
            "partial server SS prefix on flush",
        )?;
        this.poll_messages(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_messages(cx))?;
        if !this.ending {
            check(this.first_done, "server End before response")?;
            this.queue_binary(vec![0, 4, 0, 0, 3, 0])?;
            this.outgoing.push_back(Message::Close(None));
            this.counts.server_end_built.fetch_add(1, Ordering::SeqCst);
            this.ending = true;
        }
        ready!(this.poll_messages(cx))?;
        // Flush a real WS Close without waiting for an acknowledgement from a
        // proxy client whose normal shutdown half-closes the raw write side.
        Pin::new(this.ws.get_mut()).poll_shutdown(cx)
    }
}

async fn carrier(
    owner: &Owner,
    cipher: ShadowsocksCipher,
    boundary: FirstBoundary,
    counts: Arc<Counts>,
) -> io::Result<(BoxStream, Accept, oneshot::Receiver<()>)> {
    carrier_to(
        owner,
        cipher,
        boundary,
        counts,
        Destination::domain("memory-mux.invalid", 443).unwrap(),
        64,
    )
    .await
}

async fn carrier_to(
    owner: &Owner,
    cipher: ShadowsocksCipher,
    boundary: FirstBoundary,
    counts: Arc<Counts>,
    target: Destination,
    capacity: usize,
) -> io::Result<(BoxStream, Accept, oneshot::Receiver<()>)> {
    let method: CipherKind = cipher
        .as_str()
        .parse()
        .map_err(|_| invalid("test cipher"))?;
    let key = vec![7; cipher.key_len()];
    let config = ServerConfig::new(("192.0.2.10", 8443), STANDARD.encode(&key), method)
        .map_err(|_| invalid("test SS server config"))?;
    let first_length = method.salt_len() * 2 + 1 + 8 + 2 + method.tag_len();
    check(
        (59..=91).contains(&first_length),
        "actual first response bound",
    )?;
    let server = Destination::Ip("192.0.2.10:8443".parse().unwrap());
    let (client, peer) = tokio::io::duplex(capacity);
    let (signal, blocked) = oneshot::channel();
    let upstream = UpstreamPath::Proxy(Arc::new(MemoryUpstream {
        io: Mutex::new(Some(Box::new(Raw {
            io: client,
            counts: counts.clone(),
            server: false,
            blocked: None,
        }))),
        counts: counts.clone(),
        server: server.clone(),
    }));
    let peer = Raw {
        io: peer,
        counts: counts.clone(),
        server: true,
        blocked: Some(signal),
    };
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::Http,
        source: "127.0.0.1:10000".parse().unwrap(),
        destination: target.clone(),
        sniffed_domain: None,
    };
    let mut ws_config = WebSocketConfig::default();
    ws_config.write_buffer_size = 0;
    ws_config.max_write_buffer_size = 64 * 1024;
    ws_config.max_message_size = Some(WS_MESSAGE_BOUND);
    ws_config.max_frame_size = Some(WS_MESSAGE_BOUND);
    let accept_ws = async {
        accept_hdr_async_with_config(
            peer,
            |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
                if request.uri().path() != "/mux"
                    || request.headers().get("host").and_then(|v| v.to_str().ok())
                        != Some("cover.invalid")
                    || request
                        .headers()
                        .get("x-memory-test")
                        .and_then(|v| v.to_str().ok())
                        != Some("fixed")
                {
                    let mut error = ErrorResponse::new(Some("synthetic WS field mismatch".into()));
                    *error.status_mut() = http::StatusCode::BAD_REQUEST;
                    return Err(error);
                }
                Ok(response)
            },
            Some(ws_config),
        )
        .await
        .map_err(|_| invalid("actual server WS handshake"))
    };
    let context = EstablishContext::default();
    let open = async {
        owner
            .open(&upstream, &server, session, &context)
            .await
            .map_err(|_| invalid("actual mux Owner.open"))
    };
    let (raw, ws) = tokio::try_join!(open, accept_ws)?;
    counts.ws_accepts.fetch_add(1, Ordering::SeqCst);
    let raw = owner.prepare_ss_response(raw, method)?;
    let destination = super::super::address(&target);
    let stream = super::super::stream::SsStream::new(
        SsContext::new_shared(ServerType::Local),
        raw,
        &config,
        destination.clone(),
    );
    let client = owner.bind_stream(Box::new(stream));
    let peer = MuxPeer {
        ws,
        incoming: Bytes::new(),
        meta: Vec::new(),
        remaining: 0,
        got_new: false,
        channel_end: false,
        transport_end: false,
        outgoing: VecDeque::new(),
        prefix: Vec::with_capacity(first_length),
        first_length,
        first_done: false,
        ending: false,
        boundary,
        counts: counts.clone(),
    };
    let mut peer = ProxyServerStream::from_stream(
        SsContext::new_shared(ServerType::Server),
        peer,
        method,
        &key,
    );
    let accept = Box::pin(async move {
        let target = stage(
            "peer.official-handshake",
            peer.handshake().await.map_err(Into::into),
        )?;
        check(target == destination, "official SS target mismatch")?;
        counts.targets.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(peer) as BoxStream)
    });
    Ok((client, accept, blocked))
}

fn carrier_config(
    cipher: ShadowsocksCipher,
) -> io::Result<crate::config::ShadowsocksOutboundConfig> {
    let input = serde_json::json!({"proxies":[{"name":"mux","type":"ss","server":"192.0.2.10","port":8443,
        "cipher":cipher.as_str(),"password":STANDARD.encode(vec![7;cipher.key_len()]),"plugin":"v2ray-plugin",
        "plugin-opts":{"mode":"websocket","host":"cover.invalid","path":"/mux","mux":true,"tls":false,
            "headers":{"Host":"cover.invalid","X-Memory-Test":"fixed"}}}],"rules":["MATCH,mux"]});
    let parsed = Config::parse_yaml(&serde_json::to_vec(&input).unwrap())
        .map_err(|_| invalid("actual memory SS mux configuration"))?;
    let ProxyProtocol::Shadowsocks(config) = &parsed.proxies[0].protocol else {
        return Err(invalid("actual SS config expected"));
    };
    Ok(config.clone())
}

pub(in crate::outbound::shadowsocks) struct MuxMemoryGuard {
    owner: Arc<Owner>,
    counts: Arc<Counts>,
    waited: AtomicBool,
}
impl MuxMemoryGuard {
    pub(in crate::outbound::shadowsocks) fn begin_shutdown(&self) {
        self.owner.begin_shutdown();
    }
    pub(in crate::outbound::shadowsocks) async fn shutdown(&self) {
        self.owner.shutdown().await;
        self.waited.store(true, Ordering::SeqCst);
    }
    pub(in crate::outbound::shadowsocks) fn client_new(&self) -> usize {
        self.counts.client_new.load(Ordering::SeqCst)
    }
    pub(in crate::outbound::shadowsocks) fn receipt(
        &self,
    ) -> super::obfs_reuse_memory_tests::ObfsMemoryReceipt {
        let load = |value: &AtomicUsize| value.load(Ordering::SeqCst);
        super::obfs_reuse_memory_tests::ObfsMemoryReceipt {
            opens: load(&self.counts.opens),
            target_handshakes: load(&self.counts.targets),
            cover_requests: load(&self.counts.ws_accepts),
            cover_responses: load(&self.counts.ws_accepts),
            client_drops: load(&self.counts.client_drops),
            peer_drops: load(&self.counts.peer_drops),
            client_write_pending: load(&self.counts.client_write_pending),
            peer_write_pending: load(&self.counts.peer_write_pending),
            partial_writes: load(&self.counts.partial_writes),
            owner_cancelled: self.owner.cancel.is_cancelled(),
            owner_closed: *self.owner.closed.lock().unwrap(),
            owner_wait_returned: self.waited.load(Ordering::SeqCst),
        }
    }
}
impl Drop for MuxMemoryGuard {
    fn drop(&mut self) {
        self.owner.begin_shutdown();
    }
}
pub(in crate::outbound::shadowsocks) struct MuxMemoryCarrier {
    pub(in crate::outbound::shadowsocks) client: BoxStream,
    pub(in crate::outbound::shadowsocks) accept: Accept,
    pub(in crate::outbound::shadowsocks) guard: MuxMemoryGuard,
}

pub(in crate::outbound::shadowsocks) async fn memory_mux_carrier(
    cipher: ShadowsocksCipher,
    target: Destination,
    capacity: usize,
) -> io::Result<MuxMemoryCarrier> {
    let config = carrier_config(cipher)?;
    let owner = Arc::new(Owner::new(
        config.plugin.as_ref().unwrap(),
        &SecurityContext::new(),
        0,
        16 * 1024,
        config.port,
    )?);
    let guard = MuxMemoryGuard {
        owner: owner.clone(),
        counts: Arc::new(Counts::default()),
        waited: AtomicBool::new(false),
    };
    let opened = carrier_to(
        &owner,
        cipher,
        FirstBoundary::Whole,
        guard.counts.clone(),
        target,
        capacity,
    )
    .await;
    match opened {
        Ok((client, accept, blocked)) => {
            // HTTP/TLS peers drive their own original future, not this R3-only notification.
            drop(blocked);
            Ok(MuxMemoryCarrier {
                client,
                accept,
                guard,
            })
        }
        Err(error) => {
            guard.shutdown().await;
            Err(error)
        }
    }
}

async fn entity(
    io: &mut (impl AsyncRead + Unpin),
    expected: u8,
    name: &'static str,
) -> io::Result<()> {
    let mut bytes = vec![0; ENTITY];
    stage(name, io.read_exact(&mut bytes).await)?;
    if bytes.iter().all(|byte| *byte == expected) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            StageError {
                name,
                kind: io::ErrorKind::InvalidData,
                expected_synthetic_byte: Some(expected),
            },
        ))
    }
}

// All covered and plain controls execute this identical gate/payload sequence.
async fn exchange_io(
    client: BoxStream,
    accept: Accept,
    peer_write_blocked: oneshot::Receiver<()>,
    counts: Arc<Counts>,
) -> io::Result<((), ())> {
    let (allow, allowed) = oneshot::channel();
    tokio::try_join!(
        async move {
            let (mut read, mut write) = tokio::io::split(client);
            stage("client.marker.write", write.write_all(b"!").await)?;
            stage("client.marker.flush", write.flush().await)?;
            let before = counts.client_write_pending.load(Ordering::SeqCst);
            let mut payload = vec![0x31; ENTITY];
            payload.extend_from_slice(&vec![0x32; ENTITY]);
            let mut upload = Box::pin(async {
                stage("client.upload.write", write.write_all(&payload).await)?;
                stage("client.upload.flush", write.flush().await)
            });
            require_pending(
                poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx))).await,
                "duplex must block real SS upload",
            )?;
            check(
                counts.client_write_pending.load(Ordering::SeqCst) > before,
                "upload must hit actual raw backpressure",
            )?;
            peer_write_blocked
                .await
                .map_err(|_| invalid("peer never hit real TX backpressure"))?;
            entity(&mut read, 0x91, "client.response-one.read").await?;
            require_pending(
                poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx))).await,
                "RX must finish while TX remains blocked",
            )?;
            let mut second = Box::pin(entity(&mut read, 0x92, "client.response-two.read"));
            require_pending(
                poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx))).await,
                "second entity must await upload",
            )?;
            allow
                .send(())
                .map_err(|_| invalid("peer upload gate lost"))?;
            tokio::try_join!(upload.as_mut(), second.as_mut())?;
            drop((upload, second));
            stage("client.shutdown", write.shutdown().await)?;
            let mut extra = [0];
            check(
                stage("client.response-eof.read", read.read(&mut extra).await)? == 0,
                "extra response bytes",
            )?;
            Ok::<_, io::Error>(())
        },
        async move {
            let mut peer = accept.await?;
            let mut begin = [0];
            stage("peer.marker.read", peer.read_exact(&mut begin).await)?;
            check(begin == [b'!'], "SS initial payload")?;
            stage(
                "peer.response-one.write",
                peer.write_all(&vec![0x91; ENTITY]).await,
            )?;
            stage("peer.response-one.flush", peer.flush().await)?;
            allowed
                .await
                .map_err(|_| invalid("client did not release RX gate"))?;
            entity(&mut peer, 0x31, "peer.upload-one.read").await?;
            entity(&mut peer, 0x32, "peer.upload-two.read").await?;
            stage(
                "peer.response-two.write",
                peer.write_all(&vec![0x92; ENTITY]).await,
            )?;
            stage("peer.response-two.flush", peer.flush().await)?;
            let mut extra = [0];
            check(
                stage("peer.upload-eof.read", peer.read(&mut extra).await)? == 0,
                "duplicate target or upload bytes",
            )?;
            stage("peer.shutdown", peer.shutdown().await)?;
            Ok::<_, io::Error>(())
        }
    )
}

async fn run(cipher: ShadowsocksCipher, boundary: FirstBoundary) -> Result<(), CaseFailure> {
    let config = carrier_config(cipher).unwrap();
    let owner = Owner::new(
        config.plugin.as_ref().unwrap(),
        &SecurityContext::new(),
        0,
        16 * 1024,
        config.port,
    )
    .unwrap();
    let counts = Arc::new(Counts::default());
    // This Weak tracks the same allocation held by both real raw endpoints,
    // the mux peer and all inline operations. Cancellation cannot clear it.
    let counters_weak = Arc::downgrade(&counts);
    let outcome = AssertUnwindSafe(timeout(WAIT, async {
        let (client, accept, blocked) = carrier(&owner, cipher, boundary, counts.clone()).await?;
        exchange_io(client, accept, blocked, counts.clone()).await
    }))
    .catch_unwind()
    .await;
    let cancelled_before_cleanup = owner.cancel.is_cancelled();
    // The completed/cancelled try_join future has dropped every endpoint and
    // accept future before this real tracker barrier, on ALL outcomes.
    owner.shutdown().await;
    let owner_cancelled = owner.cancel.is_cancelled();
    let owner_closed = *owner.closed.lock().unwrap();
    let tracker_closed = owner.tasks.is_closed();
    let tracker_empty = owner.tasks.len() == 0;
    drop(owner);
    let snapshot = counts.snapshot();
    drop(counts);
    let cleanup = CleanupReceipt {
        shutdown_returned: true,
        owner_cancelled,
        owner_closed,
        tracker_closed,
        tracker_empty,
        client_drops: snapshot.client_drops,
        peer_drops: snapshot.peer_drops,
        counter_weak_released: counters_weak.upgrade().is_none(),
    };
    // Extract only typed labels for a combined cleanup failure; never format
    // an arbitrary IO error or caught panic payload.
    let original_io = outcome
        .as_ref()
        .ok()
        .and_then(|timer| timer.as_ref().ok())
        .and_then(|result| result.as_ref().err())
        .map(io_label);
    let original_unwind = outcome.is_err();
    let original_deadline = outcome.as_ref().is_ok_and(|timer| timer.is_err());
    // This strict independent assertion precedes error/deadline/unwind
    // classification, so an expected header RED also proves actual release.
    assert!(
        cleanup.complete(),
        "{cipher:?}/{boundary:?}: cleanup failed; original_io={original_io:?}; original_deadline={original_deadline}; original_unwind={original_unwind}; cleanup={cleanup:?}; counts={snapshot:?}"
    );
    let fail = |class, stage, kind, expected_synthetic_byte| CaseFailure {
        class,
        stage,
        kind,
        expected_synthetic_byte,
        cancelled_before_cleanup,
        cleanup,
        counts: snapshot,
    };
    match outcome {
        Err(_panic_payload) => {
            return Err(fail(FailureClass::Unwind, "exchange-unwind", None, None));
        }
        Ok(Err(_)) => {
            return Err(fail(
                FailureClass::Deadline,
                "exchange-deadline",
                Some(io::ErrorKind::TimedOut),
                None,
            ));
        }
        Ok(Ok(Err(error))) => {
            let (stage, kind, expected) = io_label(&error);
            return Err(fail(FailureClass::Io, stage, Some(kind), expected));
        }
        Ok(Ok(Ok(_))) => {}
    }
    let method: CipherKind = cipher.as_str().parse().unwrap();
    let required = method.salt_len() * 2 + 1 + 8 + 2 + method.tag_len();
    let expected_data = match boundary {
        FirstBoundary::DataSplit => required - 1,
        _ => required,
    };
    let expected_message_part = match boundary {
        FirstBoundary::MessageSplit => required - 1,
        _ => required,
    };
    let invariant = if (
        snapshot.first_data_length,
        snapshot.first_cipher_message_part,
    ) != (expected_data, expected_message_part)
    {
        Some("exact-first-boundary-witness")
    } else if cancelled_before_cleanup {
        Some("unexpected-parent-cancellation")
    } else if (
        snapshot.opens,
        snapshot.ws_accepts,
        snapshot.targets,
        snapshot.client_new,
        snapshot.client_end,
    ) != (1, 1, 1, 1, 1)
    {
        Some("one-open-ws-target-new-end")
    } else if (
        snapshot.server_end_built,
        snapshot.server_close_started,
        snapshot.server_keepalive_built,
    ) != (1, 1, 1)
    {
        Some("normal-peer-end-close-keepalive")
    } else if !snapshot.response_phase
        || snapshot.server_binary_messages_started < 3
        || snapshot.client_write_pending == 0
        || snapshot.peer_write_pending == 0
        || snapshot.partial_writes == 0
    {
        Some("real-cross-direction-backpressure")
    } else {
        None
    };
    if let Some(name) = invariant {
        return Err(fail(FailureClass::Invariant, name, None, None));
    }
    Ok(())
}
async fn run_all(boundary: FirstBoundary) {
    let mut outcomes = Vec::new();
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        outcomes.push((cipher, run(cipher, boundary).await));
    }
    assert_eq!(outcomes.len(), 3);
    let failures: Vec<_> = outcomes
        .iter()
        .filter_map(|(cipher, result)| {
            result
                .as_ref()
                .err()
                .map(|failure| (*cipher, failure.to_string()))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{boundary:?}: failures after all three actual cipher cases={failures:?}"
    );
}

#[tokio::test]
async fn v2ray_mux_whole_response_header_real_ws_ss_three_ciphers_cross_direction_control() {
    run_all(FirstBoundary::Whole).await;
}
#[tokio::test]
async fn v2ray_mux_legal_split_data_records_require_complete_response_header() {
    run_all(FirstBoundary::DataSplit).await;
}
#[tokio::test]
async fn v2ray_mux_legal_split_ws_messages_require_complete_response_header() {
    run_all(FirstBoundary::MessageSplit).await;
}
