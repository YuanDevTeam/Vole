//! Memory-only SS2022 plus simple-obfs continuity. The cover peer is a finite
//! Rust model, not an execution of the official C or Go peer. Its fields follow
//! shadowsocks/simple-obfs src/obfs_tls.c and MetaCubeX/mihomo's
//! transport/simple-obfs/{http_server,tls_server}.go. SS authentication and the
//! destination prelude are decoded by the official Rust ProxyServerStream.
//! The injected upstream supplies IO only and provides no static-reuse proof.
use super::Owner;
use crate::{
    config::{ShadowsocksCipher, ShadowsocksPlugin},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    },
    security::SecurityContext,
    session::{Destination, InboundKind, StreamSession},
};
use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use bytes::{Buf, Bytes};
use futures_util::FutureExt;
use shadowsocks::{
    ServerConfig, config::ServerType, context::Context as SsContext,
    relay::tcprelay::proxy_stream::ProxyServerStream,
};
use std::{
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

const ENTITY: usize = 64 * 1024;
const COVER_HOST: &str = "cover.invalid";
const PEER_CHUNK: usize = 1024;
const CLIENT_CHUNK: usize = 16 * 1024;
const WAIT: Duration = Duration::from_secs(20);

pub(in crate::outbound::shadowsocks) type Accept =
    Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>>;
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value { Ok(()) } else { Err(invalid(message)) }
}
// Fixed operation labels and ErrorKind only: never format the underlying
// official-codec error, a key, nonce, payload, or arbitrary peer data.
fn stage<T>(name: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("stage={name}; kind={:?}", error.kind()),
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
#[derive(Default)]
struct Counts {
    opens: AtomicUsize,
    target_handshakes: AtomicUsize,
    cover_requests: AtomicUsize,
    cover_responses: AtomicUsize,
    client_drops: AtomicUsize,
    peer_drops: AtomicUsize,
    client_write_pending: AtomicUsize,
    peer_write_pending: AtomicUsize,
    partial_writes: AtomicUsize,
}
#[derive(Clone, Copy, Debug)]
pub(in crate::outbound::shadowsocks) struct ObfsMemoryReceipt {
    pub(in crate::outbound::shadowsocks) opens: usize,
    pub(in crate::outbound::shadowsocks) target_handshakes: usize,
    pub(in crate::outbound::shadowsocks) cover_requests: usize,
    pub(in crate::outbound::shadowsocks) cover_responses: usize,
    pub(in crate::outbound::shadowsocks) client_drops: usize,
    pub(in crate::outbound::shadowsocks) peer_drops: usize,
    pub(in crate::outbound::shadowsocks) client_write_pending: usize,
    pub(in crate::outbound::shadowsocks) peer_write_pending: usize,
    pub(in crate::outbound::shadowsocks) partial_writes: usize,
    pub(in crate::outbound::shadowsocks) owner_cancelled: bool,
    pub(in crate::outbound::shadowsocks) owner_closed: bool,
    pub(in crate::outbound::shadowsocks) owner_wait_returned: bool,
}
pub(in crate::outbound::shadowsocks) struct ObfsMemoryGuard {
    owner: Arc<Owner>,
    counts: Arc<Counts>,
    waited: AtomicBool,
}
impl ObfsMemoryGuard {
    pub(in crate::outbound::shadowsocks) fn begin_shutdown(&self) {
        self.owner.begin_shutdown();
    }
    pub(in crate::outbound::shadowsocks) async fn shutdown(&self) {
        self.owner.shutdown().await;
        self.waited.store(true, Ordering::SeqCst);
    }
    pub(in crate::outbound::shadowsocks) fn receipt(&self) -> ObfsMemoryReceipt {
        let load = |value: &AtomicUsize| value.load(Ordering::SeqCst);
        ObfsMemoryReceipt {
            opens: load(&self.counts.opens),
            target_handshakes: load(&self.counts.target_handshakes),
            cover_requests: load(&self.counts.cover_requests),
            cover_responses: load(&self.counts.cover_responses),
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
impl Drop for ObfsMemoryGuard {
    fn drop(&mut self) {
        self.owner.begin_shutdown();
    }
}
pub(in crate::outbound::shadowsocks) struct MemoryCarrier {
    pub(in crate::outbound::shadowsocks) client: BoxStream,
    pub(in crate::outbound::shadowsocks) accept: Accept,
    pub(in crate::outbound::shadowsocks) guard: ObfsMemoryGuard,
    pub(in crate::outbound::shadowsocks) peer_write_blocked: oneshot::Receiver<()>,
}

struct Raw {
    io: DuplexStream,
    counts: Arc<Counts>,
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.counts.client_drops.fetch_add(1, Ordering::SeqCst);
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
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.io).poll_write(cx, bytes);
        match &result {
            Poll::Pending => {
                this.counts
                    .client_write_pending
                    .fetch_add(1, Ordering::SeqCst);
            }
            Poll::Ready(Ok(n)) if *n < bytes.len() => {
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
    server: Destination,
    counts: Arc<Counts>,
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

// A bounded cover decoder/encoder. Collect the first declared cover payload
// before exposing it to the official SS codec's existing first-read probe.
// Subsequent bytes are transparent HTTP data or bounded TLS-shaped records.
struct CoverPeer {
    io: DuplexStream,
    tls: bool,
    counts: Arc<Counts>,
    first_read: bool,
    head: Vec<u8>,
    initial_head: Option<usize>,
    initial_length: usize,
    payload: Bytes,
    remaining: usize,
    first_write: bool,
    pending: Bytes,
    write_blocked: Option<oneshot::Sender<()>>,
}
impl Drop for CoverPeer {
    fn drop(&mut self) {
        self.counts.peer_drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl CoverPeer {
    fn fill(&mut self, cx: &mut Context<'_>, target: usize) -> Poll<io::Result<bool>> {
        if target > CLIENT_CHUNK + 512 {
            return Poll::Ready(Err(invalid("cover head bound")));
        }
        for _ in 0..64 {
            if self.head.len() >= target {
                return Poll::Ready(Ok(true));
            }
            let mut bytes = [0; 64];
            let amount = (target - self.head.len()).min(bytes.len());
            let mut read = ReadBuf::new(&mut bytes[..amount]);
            ready!(Pin::new(&mut self.io).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return if self.head.is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(invalid("truncated cover")))
                };
            }
            self.head.extend_from_slice(read.filled());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn initial(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.initial_head.is_none() {
            if self.tls {
                check(ready!(self.fill(cx, 5))?, "missing ClientHello")?;
                check(self.head[..3] == [22, 3, 1], "ClientHello record")?;
                self.initial_length = usize::from(u16::from_be_bytes([self.head[3], self.head[4]]));
                self.initial_head = Some(5);
            } else {
                for _ in 0..256 {
                    let target = self.head.len() + 1;
                    check(ready!(self.fill(cx, target))?, "missing HTTP cover")?;
                    if self.head.ends_with(b"\r\n\r\n") {
                        self.initial_length = http_length(&self.head)?;
                        self.initial_head = Some(self.head.len());
                        break;
                    }
                }
                if self.initial_head.is_none() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
        let head = self.initial_head.expect("initialized cover prefix");
        check(
            ready!(self.fill(cx, head + self.initial_length))?,
            "missing initial cover payload",
        )?;
        self.payload = if self.tls {
            tls_ticket(&self.head[head..])?
        } else {
            Bytes::copy_from_slice(&self.head[head..])
        };
        self.head.clear();
        self.first_read = false;
        self.counts.cover_requests.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..64 {
            if self.pending.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let result = Pin::new(&mut self.io).poll_write(cx, &self.pending);
            if result.is_pending() {
                self.counts
                    .peer_write_pending
                    .fetch_add(1, Ordering::SeqCst);
                if let Some(signal) = self.write_blocked.take() {
                    let _ = signal.send(());
                }
            }
            let count = ready!(result)?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            if count < self.pending.len() {
                self.counts.partial_writes.fetch_add(1, Ordering::SeqCst);
            }
            self.pending.advance(count);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
fn http_length(head: &[u8]) -> io::Result<usize> {
    let text = std::str::from_utf8(head).map_err(|_| invalid("HTTP cover text"))?;
    let mut lines = text.split("\r\n");
    check(lines.next() == Some("GET / HTTP/1.1"), "HTTP request line")?;
    let mut length = None;
    let mut host = false;
    let mut key = false;
    let mut connection_upgrade = false;
    let mut websocket_upgrade = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| invalid("HTTP field"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host = value == "cover.invalid:443";
        }
        if name.eq_ignore_ascii_case("content-length") {
            check(length.is_none(), "duplicate length")?;
            length = Some(value.parse::<usize>().map_err(|_| invalid("HTTP length"))?);
        }
        if name.eq_ignore_ascii_case("connection") {
            connection_upgrade = value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        }
        if name.eq_ignore_ascii_case("upgrade") {
            websocket_upgrade = value.eq_ignore_ascii_case("websocket");
        }
        if name.eq_ignore_ascii_case("sec-websocket-key") {
            key = URL_SAFE.decode(value).is_ok_and(|nonce| nonce.len() == 16);
        }
    }
    let length = length.ok_or_else(|| invalid("missing HTTP length"))?;
    check(
        host && key
            && connection_upgrade
            && websocket_upgrade
            && length > 0
            && length <= CLIENT_CHUNK,
        "HTTP cover metadata",
    )?;
    Ok(length)
}
fn tls_ticket(hello: &[u8]) -> io::Result<Bytes> {
    check(
        hello.len() >= 137 && hello[..1] == [1] && hello[4..6] == [3, 3],
        "ClientHello shape",
    )?;
    let length =
        (usize::from(hello[1]) << 16) | (usize::from(hello[2]) << 8) | usize::from(hello[3]);
    check(
        length + 4 == hello.len()
            && hello[38] == 32
            && hello[71..73] == [0, 56]
            && hello[129..131] == [1, 0],
        "ClientHello fixed fields",
    )?;
    let extensions = usize::from(u16::from_be_bytes([hello[131], hello[132]]));
    check(
        extensions == hello.len() - 133,
        "ClientHello extensions length",
    )?;
    let mut position = 133;
    let mut ticket = None;
    let mut sni = false;
    while position < hello.len() {
        check(hello.len() - position >= 4, "short extension")?;
        let kind = u16::from_be_bytes([hello[position], hello[position + 1]]);
        let size = usize::from(u16::from_be_bytes([
            hello[position + 2],
            hello[position + 3],
        ]));
        position += 4;
        check(size <= hello.len() - position, "extension bound")?;
        let value = &hello[position..position + size];
        if kind == 35 {
            check(
                ticket.is_none() && !value.is_empty() && value.len() <= CLIENT_CHUNK,
                "ticket bound",
            )?;
            ticket = Some(Bytes::copy_from_slice(value));
        } else if kind == 0 {
            check(value.len() >= 5 && value[2] == 0, "SNI shape")?;
            let list = usize::from(u16::from_be_bytes([value[0], value[1]]));
            let name = usize::from(u16::from_be_bytes([value[3], value[4]]));
            sni = list + 2 == value.len()
                && name + 5 == value.len()
                && &value[5..] == COVER_HOST.as_bytes();
        }
        position += size;
    }
    check(sni, "cover SNI")?;
    ticket.ok_or_else(|| invalid("missing session ticket"))
}
fn server_hello(length: usize) -> Vec<u8> {
    // The 96-byte ServerHello + 6-byte CCS + 5-byte encrypted-handshake
    // prefix follows simple-obfs/Mihomo. Nonces are finite synthetic cover
    // bytes; only the official SS codec below authenticates this test data.
    let mut head = vec![22, 3, 1, 0, 91, 2, 0, 0, 87, 3, 3];
    head.extend_from_slice(&[0; 32]);
    head.push(32);
    head.extend_from_slice(&[0; 32]);
    head.extend_from_slice(&[
        0xcc, 0xa8, 0, 0, 0, 0xff, 1, 0, 1, 0, 0, 0x17, 0, 0, 0, 0x0b, 0, 2, 1, 0,
    ]);
    head.extend_from_slice(&[20, 3, 3, 0, 1, 1, 22, 3, 3]);
    head.extend_from_slice(&(length as u16).to_be_bytes());
    head
}
impl AsyncRead for CoverPeer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(result) = this.drain(cx) {
            result?;
        }
        if this.first_read {
            ready!(this.initial(cx))?;
        }
        if !this.payload.is_empty() {
            let count = this.payload.len().min(out.remaining());
            out.put_slice(&this.payload[..count]);
            this.payload.advance(count);
            return Poll::Ready(Ok(()));
        }
        if !this.tls {
            return Pin::new(&mut this.io).poll_read(cx, out);
        }
        if this.remaining == 0 {
            if !ready!(this.fill(cx, 5))? {
                return Poll::Ready(Ok(()));
            }
            check(this.head[..3] == [23, 3, 3], "subsequent TLS record")?;
            this.remaining = usize::from(u16::from_be_bytes([this.head[3], this.head[4]]));
            check(
                this.remaining > 0 && this.remaining <= CLIENT_CHUNK,
                "TLS record payload bound",
            )?;
            this.head.clear();
        }
        let count = this.remaining.min(out.remaining());
        let mut part = ReadBuf::new(out.initialize_unfilled_to(count));
        ready!(Pin::new(&mut this.io).poll_read(cx, &mut part))?;
        let count = part.filled().len();
        check(count > 0, "truncated TLS data")?;
        out.advance(count);
        this.remaining -= count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for CoverPeer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(PEER_CHUNK);
        let mut bytes = if this.first_write {
            this.counts.cover_responses.fetch_add(1, Ordering::SeqCst);
            if this.tls {
                server_hello(count)
            } else {
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_vec()
            }
        } else if this.tls {
            let mut prefix = vec![23, 3, 3];
            prefix.extend_from_slice(&(count as u16).to_be_bytes());
            prefix
        } else {
            Vec::new()
        };
        bytes.extend_from_slice(&input[..count]);
        this.first_write = false;
        this.pending = bytes.into();
        if let Poll::Ready(result) = this.drain(cx) {
            result?;
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

pub(in crate::outbound::shadowsocks) async fn memory_carrier(
    cipher: ShadowsocksCipher,
    tls: bool,
    target: Destination,
    capacity: usize,
) -> io::Result<MemoryCarrier> {
    check(
        (1..=4096).contains(&capacity),
        "bounded memory carrier capacity",
    )?;
    let key = vec![7; cipher.key_len()];
    let method = cipher
        .as_str()
        .parse()
        .map_err(|_| invalid("test cipher"))?;
    let config = ServerConfig::new(("127.0.0.1", 12345), STANDARD.encode(&key), method)
        .map_err(|_| invalid("test server configuration"))?;
    let counts = Arc::new(Counts::default());
    let owner = Arc::new(Owner::new(
        &ShadowsocksPlugin::Obfs {
            tls,
            host: COVER_HOST.into(),
        },
        &SecurityContext::new(),
        0,
        16 * 1024,
        443,
    )?);
    let guard = ObfsMemoryGuard {
        owner: owner.clone(),
        counts: counts.clone(),
        waited: AtomicBool::new(false),
    };
    let server: Destination = Destination::Ip("127.0.0.1:12345".parse().unwrap());
    let (client, peer) = tokio::io::duplex(capacity);
    let upstream = UpstreamPath::Proxy(Arc::new(MemoryUpstream {
        io: Mutex::new(Some(Box::new(Raw {
            io: client,
            counts: counts.clone(),
        }))),
        server: server.clone(),
        counts: counts.clone(),
    }));
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::Http,
        source: "127.0.0.1:10000".parse().unwrap(),
        destination: target.clone(),
        sniffed_domain: None,
    };
    let raw = match owner
        .open(&upstream, &server, session, &EstablishContext::default())
        .await
    {
        Ok(raw) => raw,
        Err(_) => {
            guard.shutdown().await;
            return Err(invalid("actual plugin open failed"));
        }
    };
    // Use the actual production Obfs preparation exactly once, including R4.
    let raw = match owner.prepare_ss_response(raw, method) {
        Ok(raw) => raw,
        Err(error) => {
            guard.shutdown().await;
            return Err(error);
        }
    };
    let target = super::super::address(&target);
    let stream = super::super::stream::SsStream::new(
        SsContext::new_shared(ServerType::Local),
        raw,
        &config,
        target.clone(),
    );
    let client = owner.bind_stream(Box::new(stream));
    let (signal, peer_write_blocked) = oneshot::channel();
    let peer = CoverPeer {
        io: peer,
        tls,
        counts: counts.clone(),
        first_read: true,
        head: Vec::new(),
        initial_head: None,
        initial_length: 0,
        payload: Bytes::new(),
        remaining: 0,
        first_write: true,
        pending: Bytes::new(),
        write_blocked: Some(signal),
    };
    let mut peer = ProxyServerStream::from_stream(
        SsContext::new_shared(ServerType::Server),
        peer,
        method,
        &key,
    );
    let authenticated = counts.clone();
    let accept = Box::pin(async move {
        let observed = stage(
            "peer.official-handshake",
            peer.handshake().await.map_err(Into::into),
        )?;
        check(observed == target, "official SS target mismatch")?;
        authenticated
            .target_handshakes
            .fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(peer) as BoxStream)
    });
    Ok(MemoryCarrier {
        client,
        accept,
        guard,
        peer_write_blocked,
    })
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
            format!("stage={name}; kind=InvalidData; expected-synthetic-byte={expected:#04x}"),
        ))
    }
}

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

async fn exchange(cipher: ShadowsocksCipher, tls: bool) {
    let MemoryCarrier {
        client,
        accept,
        guard,
        peer_write_blocked,
    } = memory_carrier(
        cipher,
        tls,
        Destination::domain("memory-obfs.invalid", 443).unwrap(),
        64,
    )
    .await
    .unwrap();
    let counts = guard.counts.clone();
    let outcome = AssertUnwindSafe(timeout(
        WAIT,
        exchange_io(client, accept, peer_write_blocked, counts),
    ))
    .catch_unwind()
    .await;
    let owner_cancelled_before_cleanup = guard.owner.cancel.is_cancelled();
    guard.shutdown().await;
    let receipt = guard.receipt();
    drop(guard);
    match outcome {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(Err(_)) => panic!("{cipher:?}/tls={tls}: memory exchange deadline; {receipt:?}"),
        Ok(Ok(Err(error))) => panic!(
            "{cipher:?}/tls={tls}: {error}; owner_cancelled_before_cleanup={owner_cancelled_before_cleanup}; {receipt:?}"
        ),
        Ok(Ok(Ok(_))) => {}
    }
    assert_eq!(
        (
            receipt.opens,
            receipt.target_handshakes,
            receipt.cover_requests,
            receipt.cover_responses
        ),
        (1, 1, 1, 1)
    );
    assert_eq!((receipt.client_drops, receipt.peer_drops), (1, 1));
    assert!(
        receipt.client_write_pending > 0
            && receipt.peer_write_pending > 0
            && receipt.partial_writes > 0
    );
    assert!(receipt.owner_cancelled && receipt.owner_closed && receipt.owner_wait_returned);
}

#[tokio::test]
async fn header_probe_covered_ss_all_ciphers_and_modes_preserves_actual_owned_pipeline() {
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for tls in [false, true] {
            exchange(cipher, tls).await;
        }
    }
}

// The accept future owns the real peer before its first poll. Cancellation is
// observable independently of either endpoint drop and of the owner wait.
#[tokio::test]
async fn unpolled_memory_accept_drop_is_counted_separately_from_owner_shutdown() {
    for tls in [false, true] {
        let MemoryCarrier {
            client,
            accept,
            guard,
            peer_write_blocked,
        } = memory_carrier(
            ShadowsocksCipher::Aes128Gcm,
            tls,
            Destination::domain("memory-obfs.invalid", 443).unwrap(),
            64,
        )
        .await
        .unwrap();
        guard.begin_shutdown();
        let cancelled = guard.receipt();
        drop((client, accept, peer_write_blocked));
        guard.shutdown().await;
        let receipt = guard.receipt();
        drop(guard);
        assert!(
            cancelled.owner_cancelled && cancelled.owner_closed && !cancelled.owner_wait_returned
        );
        assert_eq!(
            (
                cancelled.client_drops,
                cancelled.peer_drops,
                cancelled.target_handshakes
            ),
            (0, 0, 0)
        );
        assert_eq!(
            (receipt.opens, receipt.client_drops, receipt.peer_drops),
            (1, 1, 1)
        );
        assert_eq!(
            (
                receipt.target_handshakes,
                receipt.cover_requests,
                receipt.cover_responses
            ),
            (0, 0, 0)
        );
        assert!(receipt.owner_cancelled && receipt.owner_closed && receipt.owner_wait_returned);
    }
}

// Actual UoT factory gate: this raw adapter never buffers or frames. It only
// counts calls and delegates to the memory duplex, so an accidental empty SS
// initialization would be observed as a write and nonempty peer bytes.
#[derive(Default)]
struct NeverSentCounts {
    reads: AtomicUsize,
    writes: AtomicUsize,
    flushes: AtomicUsize,
    shutdowns: AtomicUsize,
    drops: AtomicUsize,
}
#[derive(Clone, Copy, Debug)]
struct NeverSentSnapshot {
    reads: usize,
    writes: usize,
    flushes: usize,
    shutdowns: usize,
    drops: usize,
}
impl NeverSentCounts {
    fn snapshot(&self) -> NeverSentSnapshot {
        NeverSentSnapshot {
            reads: self.reads.load(Ordering::SeqCst),
            writes: self.writes.load(Ordering::SeqCst),
            flushes: self.flushes.load(Ordering::SeqCst),
            shutdowns: self.shutdowns.load(Ordering::SeqCst),
            drops: self.drops.load(Ordering::SeqCst),
        }
    }
}
struct NeverSentRaw {
    io: DuplexStream,
    counts: Arc<NeverSentCounts>,
}
impl Drop for NeverSentRaw {
    fn drop(&mut self) {
        self.counts.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsyncRead for NeverSentRaw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.counts.reads.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut this.io).poll_read(cx, out)
    }
}
impl AsyncWrite for NeverSentRaw {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.counts.writes.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut this.io).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.counts.flushes.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut this.io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.counts.shutdowns.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn obfs_uot_never_sent_actual_factory_close_drop_and_retained_stop_join_without_raw_io() {
    use crate::{
        config::{Config, ProxyProtocol},
        outbound::ShadowsocksOutbound,
        session::DatagramSession,
    };
    let request = || {
        DatagramRequest::new(DatagramSession::new(
            InboundKind::Socks5,
            "127.0.0.1:1234".parse().unwrap(),
        ))
    };
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for tls in [false, true] {
            for ending in ["close", "drop", "stop"] {
                // Same public UoT v2 construction as the existing standalone
                // never-sent regression, with actual Obfs added to the node.
                let input = serde_json::json!({
                    "mixed-port": 1080,
                    "proxies": [{
                        "name": "obfs-uot", "type": "ss", "server": "127.0.0.1", "port": 12345,
                        "cipher": cipher.as_str(), "password": STANDARD.encode(vec![7; cipher.key_len()]),
                        "udp": true, "udp-over-tcp": true, "udp-over-tcp-version": 2,
                        "plugin": "obfs", "plugin-opts": {"mode": if tls {"tls"} else {"http"}, "host": COVER_HOST},
                    }],
                    "rules": ["MATCH,obfs-uot"],
                });
                let parsed = Config::parse_yaml(&serde_json::to_vec(&input).unwrap()).unwrap();
                let ProxyProtocol::Shadowsocks(config) = &parsed.proxies[0].protocol else {
                    panic!("actual SS configuration expected")
                };
                let counts = Arc::new(NeverSentCounts::default());
                let opens = Arc::new(Counts::default());
                let (raw, mut peer) = tokio::io::duplex(64);
                let raw_weak = Arc::downgrade(&counts);
                let upstream = UpstreamPath::Proxy(Arc::new(MemoryUpstream {
                    io: Mutex::new(Some(Box::new(NeverSentRaw {
                        io: raw,
                        counts: counts.clone(),
                    }))),
                    server: Destination::Ip("127.0.0.1:12345".parse().unwrap()),
                    counts: opens.clone(),
                }));
                let outbound = ShadowsocksOutbound::new_with_path(config, upstream).unwrap();
                let mut association: Option<Box<dyn DatagramTransport>> = None;
                let outcome = AssertUnwindSafe(timeout(WAIT, async {
                    association = Some(
                        OutboundConnector::open_datagram(
                            &outbound,
                            request(),
                            &EstablishContext::default(),
                        )
                        .await
                        .map_err(|_| invalid("uot.actual-open-datagram"))?,
                    );
                    let shared = association.as_ref().unwrap().supports_shared_destinations();
                    // Give the actual registered UoT reader opportunities to
                    // poll its FirstWrite gate; no synthetic reader is used.
                    for _ in 0..16 {
                        tokio::task::yield_now().await;
                    }
                    let before = counts.snapshot();
                    match ending {
                        "close" => association
                            .as_mut()
                            .unwrap()
                            .close()
                            .await
                            .map_err(|_| invalid("uot.never-sent-close"))?,
                        "drop" => drop(association.take()),
                        "stop" => OutboundConnector::shutdown(&outbound).await,
                        _ => unreachable!(),
                    }
                    Ok::<_, io::Error>((before, shared))
                }))
                .catch_unwind()
                .await;
                // The actual node barrier joins both its plugin and UoT owner.
                // It runs even after open/close error, timeout or caught panic.
                OutboundConnector::shutdown(&outbound).await;
                let after_join = counts.snapshot();
                let retained_after_join = association.is_some();
                let open_count = opens.opens.load(Ordering::SeqCst);
                // Retained Stop must have released raw before this Drop. Then
                // release all remaining external handles on every outcome.
                drop(association.take());
                OutboundConnector::shutdown(&outbound).await;
                let mut wire = Vec::new();
                let eof = timeout(Duration::from_secs(1), peer.read_to_end(&mut wire)).await;
                let eof_clean = matches!(eof, Ok(Ok(0)));
                let wire_length = wire.len();
                drop(peer);
                drop(outbound);
                drop(opens);
                let final_snapshot = counts.snapshot();
                drop(counts);
                let raw_owner_released = raw_weak.upgrade().is_none();
                let (before, shared) = match outcome {
                    Err(panic) => std::panic::resume_unwind(panic),
                    Ok(Err(_)) => panic!(
                        "{cipher:?}/tls={tls}/ending={ending}: UoT gate deadline; after_join={after_join:?}; final={final_snapshot:?}"
                    ),
                    Ok(Ok(Err(error))) => panic!(
                        "{cipher:?}/tls={tls}/ending={ending}: {error}; after_join={after_join:?}; final={final_snapshot:?}"
                    ),
                    Ok(Ok(Ok(value))) => value,
                };
                // Every assertion is after actual shutdown/join, both endpoint
                // Drops and the peer EOF observation; no token-only receipt.
                assert!(
                    shared && raw_owner_released && eof_clean && wire_length == 0,
                    "{cipher:?}/tls={tls}/ending={ending}: opens={open_count}; before={before:?}; after_join={after_join:?}; final={final_snapshot:?}; eof_clean={eof_clean}; wire_length={wire_length}"
                );
                assert_eq!(open_count, 1);
                assert_eq!(
                    (
                        before.reads,
                        before.writes,
                        before.flushes,
                        before.shutdowns,
                        before.drops
                    ),
                    (0, 0, 0, 0, 0)
                );
                assert_eq!(
                    (
                        after_join.reads,
                        after_join.writes,
                        after_join.flushes,
                        after_join.shutdowns,
                        after_join.drops
                    ),
                    (0, 0, 0, 0, 1)
                );
                assert_eq!(
                    (
                        final_snapshot.reads,
                        final_snapshot.writes,
                        final_snapshot.flushes,
                        final_snapshot.shutdowns,
                        final_snapshot.drops
                    ),
                    (0, 0, 0, 0, 1)
                );
                if ending == "stop" {
                    assert!(
                        retained_after_join,
                        "Stop proof lost its retained association"
                    );
                }
            }
        }
    }
}
