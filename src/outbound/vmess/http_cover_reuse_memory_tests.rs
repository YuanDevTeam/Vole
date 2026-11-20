//! Real client construction with a bounded wire-authenticating memory peer.
//! Header parsing is a test-only finite model of v2ray-core AEAD/server.go.
//! BodyCodec is shared production code: this is not an official server run.
use super::*;
use crate::{
    config::{Config, ProxyProtocol},
    dispatch::{DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
    },
    session::{Destination, InboundKind, StreamSession},
};
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use async_trait::async_trait;
use futures_util::{FutureExt, future::poll_fn};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::oneshot,
    time::timeout,
};

const ENTITY: usize = 64 * 1024;
const WAIT: Duration = Duration::from_secs(20);
const SETUP: Duration = Duration::from_secs(1);
const HTTP_HEAD_LIMIT: usize = 4096;
const REQUEST_LIMIT: usize = 512;
const UUID_BYTES: [u8; 16] = [7; 16];
const HOST: &str = "cover.memory.invalid";
const PATH: &str = "/memory-cover";
const CIPHERS: [BodyCipher; 4] = [
    BodyCipher::Auto,
    BodyCipher::None,
    BodyCipher::Aes128Gcm,
    BodyCipher::Chacha20Poly1305,
];

fn invalid(stage: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, stage)
}
fn require(value: bool, stage: &'static str) -> io::Result<()> {
    if value { Ok(()) } else { Err(invalid(stage)) }
}
fn stage<T>(name: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| io::Error::new(error.kind(), name))
}
fn pending<T>(value: Poll<io::Result<T>>, name: &'static str) -> io::Result<()> {
    match value {
        Poll::Pending => Ok(()),
        Poll::Ready(Err(error)) => Err(error),
        _ => Err(invalid(name)),
    }
}
#[derive(Default, Debug)]
struct Counts {
    opens: AtomicUsize,
    requests: AtomicUsize,
    targets: AtomicUsize,
    responses: AtomicUsize,
    auth_failures: AtomicUsize,
    client_drops: AtomicUsize,
    peer_drops: AtomicUsize,
    client_write_pending: AtomicUsize,
    peer_write_pending: AtomicUsize,
    client_read_pending: AtomicUsize,
    peer_read_pending: AtomicUsize,
    partial_writes: AtomicUsize,
    short_reads: AtomicUsize,
    response_body_started: AtomicBool,
}
struct Raw {
    io: DuplexStream,
    counts: Arc<Counts>,
    peer: bool,
    blocked: Option<oneshot::Sender<()>>,
}
impl Drop for Raw {
    fn drop(&mut self) {
        let value = if self.peer {
            &self.counts.peer_drops
        } else {
            &self.counts.client_drops
        };
        value.fetch_add(1, Ordering::SeqCst);
    }
}
impl AsyncRead for Raw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let limit = output.remaining().min(7);
        let mut limited = ReadBuf::new(output.initialize_unfilled_to(limit));
        match Pin::new(&mut this.io).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let amount = limited.filled().len();
                if amount != 0 && amount < output.remaining() {
                    this.counts.short_reads.fetch_add(1, Ordering::SeqCst);
                }
                output.advance(amount);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                let count = if this.peer {
                    &this.counts.peer_read_pending
                } else {
                    &this.counts.client_read_pending
                };
                count.fetch_add(1, Ordering::SeqCst);
                Poll::Pending
            }
        }
    }
}
impl AsyncWrite for Raw {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.io).poll_write(cx, &bytes[..bytes.len().min(31)]);
        match &result {
            Poll::Pending => {
                let count = if this.peer {
                    &this.counts.peer_write_pending
                } else {
                    &this.counts.client_write_pending
                };
                count.fetch_add(1, Ordering::SeqCst);
                if this.peer && this.counts.response_body_started.load(Ordering::SeqCst) {
                    if let Some(blocked) = this.blocked.take() {
                        let _ = blocked.send(());
                    }
                }
            }
            Poll::Ready(Ok(amount)) if *amount < bytes.len() => {
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
    streams: Mutex<VecDeque<(BoxStream, Arc<Counts>)>>,
    expected: Destination,
}
#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        if session.destination != self.expected {
            return Err(DispatchError::NotAllowed);
        }
        let (io, counts) = self
            .streams
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(DispatchError::NotAllowed)?;
        counts.opens.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectedStream {
            io,
            effective_peer: self.expected.clone(),
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
fn cipher_name(cipher: BodyCipher) -> &'static str {
    match cipher {
        BodyCipher::Auto => "auto",
        BodyCipher::None => "none",
        BodyCipher::Aes128Gcm => "aes-128-gcm",
        BodyCipher::Chacha20Poly1305 => "chacha20-poly1305",
    }
}
fn config(cipher: BodyCipher) -> io::Result<crate::config::VmessOutboundConfig> {
    let source = serde_json::json!({"proxies":[{"name":"cover","type":"vmess","server":"192.0.2.10","port":8443,
        "uuid":"07070707-0707-0707-0707-070707070707","cipher":cipher_name(cipher),"network":"http",
        "http-opts":{"method":"GET","path":[PATH],"headers":{"Host":[HOST]}}}],"rules":["MATCH,cover"]});
    let mut parsed = Config::parse_yaml(&serde_json::to_vec(&source).unwrap())
        .map_err(|_| invalid("actual VMess Config"))?;
    let ProxyProtocol::Vmess(config) = parsed.proxies.remove(0).protocol else {
        return Err(invalid("actual VMess type"));
    };
    Ok(config)
}
fn session(target: Destination) -> StreamSession {
    StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:10000".parse().unwrap(),
        destination: target,
        sniffed_domain: None,
    }
}

struct Authenticated {
    key: [u8; 16],
    iv: [u8; 16],
    response_key: [u8; 16],
    response_iv: [u8; 16],
    tag: u8,
    options: BodyOptions,
}
fn command_key(uuid: [u8; 16]) -> [u8; 16] {
    let mut hash = Md5::new();
    Digest::update(&mut hash, uuid);
    Digest::update(&mut hash, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hash.finalize().into()
}
fn request_authenticate(
    mut wire: Vec<u8>,
    expected: &Destination,
    cipher: BodyCipher,
    uuid: [u8; 16],
) -> io::Result<Authenticated> {
    require(
        (42 + 16..=REQUEST_LIMIT).contains(&wire.len()),
        "bounded VMess request",
    )?;
    let auth: [u8; 16] = wire[..16].try_into().unwrap();
    let nonce: [u8; 8] = wire[34..42].try_into().unwrap();
    let command = command_key(uuid);
    let auth_key = kdf(&command, &[b"AES Auth ID Encryption"]);
    let mut decoded = auth;
    aes::Aes128::new_from_slice(&auth_key[..16])
        .map_err(|_| invalid("AuthID key"))?
        .decrypt_block((&mut decoded).into());
    let timestamp = u64::from_be_bytes(decoded[..8].try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("test clock"))?
        .as_secs();
    require(
        timestamp.abs_diff(now) <= 120
            && u32::from_be_bytes(decoded[12..].try_into().unwrap())
                == crc32fast::hash(&decoded[..12]),
        "actual AuthID CRC/time",
    )?;
    let length_key = kdf(&command, &[b"VMess Header AEAD Key_Length", &auth, &nonce]);
    let length_iv = kdf(
        &command,
        &[b"VMess Header AEAD Nonce_Length", &auth, &nonce],
    );
    let length = open(
        &aead_key(BodyCipher::Aes128Gcm, length_key[..16].try_into().unwrap()),
        length_iv[..12].try_into().unwrap(),
        &auth,
        &mut wire[16..34],
    )?;
    require(length.len() == 2, "actual request length")?;
    let length = usize::from(u16::from_be_bytes(length.try_into().unwrap()));
    require(
        (42..=320).contains(&length) && wire.len() == 42 + length + 16,
        "exact initial VMess prefix",
    )?;
    let payload_key = kdf(&command, &[b"VMess Header AEAD Key", &auth, &nonce]);
    let payload_iv = kdf(&command, &[b"VMess Header AEAD Nonce", &auth, &nonce]);
    let plain = open(
        &aead_key(BodyCipher::Aes128Gcm, payload_key[..16].try_into().unwrap()),
        payload_iv[..12].try_into().unwrap(),
        &auth,
        &mut wire[42..],
    )?;
    require(
        plain.len() == length && plain[0] == 1 && plain[36] == 0 && plain[37] == 1,
        "actual TCP request fields",
    )?;
    let options = BodyOptions::new(cipher, false, false)?;
    require(
        plain[34] == options.wire(Command::Tcp) && plain[35] & 15 == cipher.resolved().wire(),
        "actual body cipher/options",
    )?;
    let padding = usize::from(plain[35] >> 4);
    let end = plain
        .len()
        .checked_sub(4 + padding)
        .ok_or_else(|| invalid("request padding"))?;
    require(end >= 38, "request target length")?;
    let (target, used) = crate::outbound::address::decode_port_first(&plain[38..end])?;
    require(
        target == *expected && used == end - 38,
        "authenticated actual target",
    )?;
    let checksum = plain[..plain.len() - 4]
        .iter()
        .fold(0x811c9dc5u32, |sum, byte| {
            (sum ^ u32::from(*byte)).wrapping_mul(0x01000193)
        });
    require(
        checksum == u32::from_be_bytes(plain[plain.len() - 4..].try_into().unwrap()),
        "actual request FNV",
    )?;
    let key: [u8; 16] = plain[17..33].try_into().unwrap();
    let iv: [u8; 16] = plain[1..17].try_into().unwrap();
    Ok(Authenticated {
        key,
        iv,
        response_key: Sha256::digest(key)[..16].try_into().unwrap(),
        response_iv: Sha256::digest(iv)[..16].try_into().unwrap(),
        tag: plain[33],
        options,
    })
}
#[derive(Clone, Copy)]
enum ResponseMode {
    Valid,
    BadTag,
}
fn response_prefix(auth: &Authenticated, mode: ResponseMode) -> io::Result<Bytes> {
    let mut bytes = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
    for (mut data, key_salt, iv_salt) in [
        (
            4u16.to_be_bytes().to_vec(),
            b"AEAD Resp Header Len Key".as_slice(),
            b"AEAD Resp Header Len IV".as_slice(),
        ),
        (
            vec![auth.tag, 0, 0, 0],
            b"AEAD Resp Header Key".as_slice(),
            b"AEAD Resp Header IV".as_slice(),
        ),
    ] {
        let key = kdf(&auth.response_key, &[key_salt]);
        let iv = kdf(&auth.response_iv, &[iv_salt]);
        seal(
            &aead_key(BodyCipher::Aes128Gcm, key[..16].try_into().unwrap()),
            iv[..12].try_into().unwrap(),
            &[],
            &mut data,
        )?;
        bytes.extend_from_slice(&data);
    }
    if matches!(mode, ResponseMode::BadTag) {
        *bytes.last_mut().unwrap() ^= 1;
    }
    Ok(bytes.into())
}
async fn accept_request(
    mut raw: Raw,
    target: Destination,
    cipher: BodyCipher,
    uuid: [u8; 16],
    mode: ResponseMode,
) -> io::Result<Peer> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        require(head.len() < HTTP_HEAD_LIMIT, "bounded cover head")?;
        let mut byte = [0];
        stage("cover head read", raw.read_exact(&mut byte).await)?;
        head.push(byte[0]);
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Request::new(&mut headers);
    require(
        matches!(parsed.parse(&head).map_err(|_| invalid("cover parse"))?, httparse::Status::Complete(length) if length == head.len())
            && parsed.method == Some("GET")
            && parsed.path == Some(PATH)
            && parsed.version == Some(1),
        "actual fixed cover",
    )?;
    let mut length = None;
    let mut hosts = 0;
    for header in parsed.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            hosts += 1;
            require(header.value == HOST.as_bytes(), "cover Host")?;
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            require(
                length.is_none()
                    && !header.value.is_empty()
                    && header.value.iter().all(u8::is_ascii_digit),
                "single cover Content-Length",
            )?;
            length = Some(
                std::str::from_utf8(header.value)
                    .map_err(|_| invalid("cover length"))?
                    .parse::<usize>()
                    .map_err(|_| invalid("cover length"))?,
            );
        }
        require(
            !header.name.eq_ignore_ascii_case("transfer-encoding"),
            "cover has no transfer coding",
        )?;
    }
    let length = length.ok_or_else(|| invalid("cover length missing"))?;
    require(
        hosts == 1 && (58..=REQUEST_LIMIT).contains(&length),
        "cover prefix bound",
    )?;
    raw.counts.requests.fetch_add(1, Ordering::SeqCst);
    let mut wire = vec![0; length];
    stage("cover initial body", raw.read_exact(&mut wire).await)?;
    let auth = match request_authenticate(wire, &target, cipher, uuid) {
        Ok(auth) => auth,
        Err(error) => {
            raw.counts.auth_failures.fetch_add(1, Ordering::SeqCst);
            return Err(error);
        }
    };
    raw.counts.targets.fetch_add(1, Ordering::SeqCst);
    Peer::new(raw, auth, mode)
}

struct Peer {
    raw: Raw,
    read: BodyCodec,
    write: BodyCodec,
    input: BytesMut,
    expected: Option<(usize, usize)>,
    plain: Bytes,
    prefix: Bytes,
    output: Bytes,
    started: bool,
    response_counted: bool,
    eof: bool,
    shutdown_queued: bool,
}
impl Peer {
    fn new(raw: Raw, auth: Authenticated, mode: ResponseMode) -> io::Result<Self> {
        let prefix = response_prefix(&auth, mode)?;
        Ok(Self {
            raw,
            read: BodyCodec::new(
                auth.options,
                Command::Tcp,
                &auth.key,
                auth.iv,
                &auth.key,
                auth.iv,
            ),
            write: BodyCodec::new(
                auth.options,
                Command::Tcp,
                &auth.response_key,
                auth.response_iv,
                &auth.key,
                auth.iv,
            ),
            input: BytesMut::new(),
            expected: None,
            plain: Bytes::new(),
            prefix,
            output: Bytes::new(),
            started: false,
            response_counted: false,
            eof: false,
            shutdown_queued: false,
        })
    }
    fn fill(
        &mut self,
        wanted: usize,
        budget: &mut usize,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        while self.input.len() < wanted {
            if *budget == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            *budget -= 1;
            let mut scratch = [0; 512];
            let amount = (wanted - self.input.len()).min(scratch.len());
            let mut buffer = ReadBuf::new(&mut scratch[..amount]);
            ready!(Pin::new(&mut self.raw).poll_read(cx, &mut buffer))?;
            if buffer.filled().is_empty() {
                return Poll::Ready(Ok(false));
            }
            self.input.extend_from_slice(buffer.filled());
        }
        Poll::Ready(Ok(true))
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut budget = crate::limits::IO_POLL_BUDGET;
        if self.started {
            ready!(drain_wire(&mut self.raw, &mut self.prefix, &mut budget, cx))?;
            if !self.response_counted {
                self.raw.counts.responses.fetch_add(1, Ordering::SeqCst);
                self.raw
                    .counts
                    .response_body_started
                    .store(true, Ordering::SeqCst);
                self.response_counted = true;
            }
        }
        drain_wire(&mut self.raw, &mut self.output, &mut budget, cx)
    }
}
fn drain_wire(
    raw: &mut Raw,
    wire: &mut Bytes,
    budget: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while !wire.is_empty() {
        if *budget == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        *budget -= 1;
        let amount = ready!(Pin::new(&mut *raw).poll_write(cx, wire))?;
        if amount == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        wire.advance(amount);
    }
    Poll::Ready(Ok(()))
}
impl AsyncRead for Peer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        if !this.read.framed {
            return Pin::new(&mut this.raw).poll_read(cx, output);
        }
        let mut budget = crate::limits::IO_POLL_BUDGET;
        loop {
            if !this.plain.is_empty() {
                let amount = this.plain.len().min(output.remaining());
                output.put_slice(&this.plain.split_to(amount));
                return Poll::Ready(Ok(()));
            }
            if this.expected.is_none() {
                if !ready!(this.fill(this.read.length_size(), &mut budget, cx))? {
                    if !this.input.is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                let mut header = this.input.split_to(this.read.length_size());
                this.expected = Some(this.read.decode_length(&mut header)?);
            }
            let (length, padding) = this.expected.unwrap();
            if !ready!(this.fill(length, &mut budget, cx))? {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.plain = this
                .read
                .decode_body(this.input.split_to(length), padding)?;
            this.expected = None;
            if this.plain.is_empty() {
                this.eof = true;
                return Poll::Ready(Ok(()));
            }
        }
    }
}
impl AsyncWrite for Peer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown_queued {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.started = true;
        ready!(this.drain(cx))?;
        let amount = bytes.len().min(WRITE_CHUNK);
        this.output = this.write.encode(&bytes[..amount])?;
        Poll::Ready(Ok(amount))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.raw).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if !this.shutdown_queued {
            this.shutdown_queued = true;
            if this.started && this.write.framed {
                this.output = this.write.encode(&[])?;
            }
        }
        ready!(this.drain(cx))?;
        Pin::new(&mut this.raw).poll_shutdown(cx)
    }
}
struct Guard {
    node: Arc<super::super::VmessOutbound>,
    counts: Vec<Arc<Counts>>,
    waited: AtomicBool,
}
impl Guard {
    fn begin_shutdown(&self) {
        OutboundConnector::begin_shutdown(self.node.as_ref());
    }
    async fn shutdown(&self) {
        OutboundConnector::shutdown(self.node.as_ref()).await;
        self.waited.store(true, Ordering::SeqCst);
    }
    fn receipt(&self) -> MemoryVmessHttpCoverReceipt {
        let (cancelled, closed, empty) = self.node.http_cover_test_lifecycle();
        let mut r = MemoryVmessHttpCoverReceipt {
            owners: 1,
            owner_cancelled: usize::from(cancelled),
            owner_closed: usize::from(closed),
            owner_tasks_empty: usize::from(empty),
            owner_wait_returned: usize::from(self.waited.load(Ordering::SeqCst)),
            ..Default::default()
        };
        for c in &self.counts {
            r.opens += c.opens.load(Ordering::SeqCst);
            r.target_handshakes += c.targets.load(Ordering::SeqCst);
            r.cover_requests += c.requests.load(Ordering::SeqCst);
            r.cover_responses += c.responses.load(Ordering::SeqCst);
            r.client_drops += c.client_drops.load(Ordering::SeqCst);
            r.peer_drops += c.peer_drops.load(Ordering::SeqCst);
            r.auth_failures += c.auth_failures.load(Ordering::SeqCst);
            r.client_write_pending += c.client_write_pending.load(Ordering::SeqCst);
            r.peer_write_pending += c.peer_write_pending.load(Ordering::SeqCst);
            r.client_read_pending += c.client_read_pending.load(Ordering::SeqCst);
            r.peer_read_pending += c.peer_read_pending.load(Ordering::SeqCst);
            r.partial_writes += c.partial_writes.load(Ordering::SeqCst);
            r.short_reads += c.short_reads.load(Ordering::SeqCst);
        }
        r
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}
struct NodeFixture {
    guard: Arc<Guard>,
    peers: Vec<(Raw, oneshot::Receiver<()>)>,
}
fn node_fixture(cipher: BodyCipher, capacity: usize, count: usize) -> io::Result<NodeFixture> {
    require(
        capacity >= 1 && (1..=2).contains(&count),
        "finite memory fixture",
    )?;
    let mut streams = VecDeque::new();
    let mut peers = Vec::new();
    let mut counters = Vec::new();
    for _ in 0..count {
        let counts = Arc::new(Counts::default());
        let (client, peer) = tokio::io::duplex(capacity);
        let (blocked, signal) = oneshot::channel();
        streams.push_back((
            Box::new(Raw {
                io: client,
                counts: counts.clone(),
                peer: false,
                blocked: None,
            }) as BoxStream,
            counts.clone(),
        ));
        peers.push((
            Raw {
                io: peer,
                counts: counts.clone(),
                peer: true,
                blocked: Some(blocked),
            },
            signal,
        ));
        counters.push(counts);
    }
    let upstream = Arc::new(MemoryUpstream {
        streams: Mutex::new(streams),
        expected: Destination::Ip("192.0.2.10:8443".parse().unwrap()),
    });
    let node = Arc::new(super::super::VmessOutbound::new_with_path(
        &config(cipher)?,
        UpstreamPath::proxy(upstream),
    )?);
    Ok(NodeFixture {
        guard: Arc::new(Guard {
            node,
            counts: counters,
            waited: AtomicBool::new(false),
        }),
        peers,
    })
}
async fn open_wire(
    guard: &Guard,
    raw: Raw,
    target: Destination,
    cipher: BodyCipher,
    uuid: [u8; 16],
    mode: ResponseMode,
) -> io::Result<(BoxStream, Peer)> {
    let context = EstablishContext::with_timeout(SETUP);
    let client_target = target.clone();
    let client = async {
        guard
            .node
            .connect_stream(session(client_target), &context)
            .await
            .map(|connected| connected.io)
            .map_err(|_| invalid("actual VMess connect_stream"))
    };
    // Both halves are inline, and each owns its exact IO. No peer task is spawned.
    tokio::try_join!(client, accept_request(raw, target, cipher, uuid, mode))
}

pub(crate) type MemoryVmessAcceptedPeer =
    Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>>;
#[derive(Debug, Default)]
pub(crate) struct MemoryVmessHttpCoverReceipt {
    pub(crate) owners: usize,
    pub(crate) opens: usize,
    pub(crate) target_handshakes: usize,
    pub(crate) cover_requests: usize,
    pub(crate) cover_responses: usize,
    pub(crate) client_drops: usize,
    pub(crate) peer_drops: usize,
    pub(crate) owner_cancelled: usize,
    pub(crate) owner_closed: usize,
    pub(crate) owner_wait_returned: usize,
    pub(crate) owner_tasks_empty: usize,
    pub(crate) auth_failures: usize,
    pub(crate) client_write_pending: usize,
    pub(crate) peer_write_pending: usize,
    pub(crate) client_read_pending: usize,
    pub(crate) peer_read_pending: usize,
    pub(crate) partial_writes: usize,
    pub(crate) short_reads: usize,
}
pub(crate) struct MemoryVmessHttpCoverFactory {
    cipher: BodyCipher,
    capacity: usize,
    guards: Mutex<Vec<Arc<Guard>>>,
}
impl MemoryVmessHttpCoverFactory {
    pub(crate) fn new(cipher: BodyCipher, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            cipher,
            capacity,
            guards: Mutex::new(Vec::new()),
        })
    }
    pub(crate) async fn open(
        &self,
        target: Destination,
    ) -> io::Result<(BoxStream, crate::outbound::MemoryVmessAcceptedPeer)> {
        let mut fixture = node_fixture(self.cipher, self.capacity, 1)?;
        let (raw, blocked) = fixture.peers.remove(0);
        // Register before any await, so parent timeout/cancellation still has
        // this real node available for the later explicit shutdown barrier.
        self.guards
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(fixture.guard.clone());
        let opened = open_wire(
            &fixture.guard,
            raw,
            target,
            self.cipher,
            UUID_BYTES,
            ResponseMode::Valid,
        )
        .await;
        drop(blocked);
        match opened {
            Ok((client, peer)) => Ok((
                client,
                Box::pin(async move { Ok(Box::new(peer) as BoxStream) }),
            )),
            Err(error) => {
                fixture.guard.shutdown().await;
                Err(error)
            }
        }
    }
    pub(crate) fn begin_shutdown(&self) {
        for guard in self
            .guards
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            guard.begin_shutdown();
        }
    }
    pub(crate) async fn shutdown(&self) {
        let guards = self
            .guards
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        for guard in &guards {
            guard.begin_shutdown();
        }
        for guard in guards {
            guard.shutdown().await;
        }
    }
    pub(crate) fn snapshot(&self) -> crate::outbound::MemoryVmessHttpCoverReceipt {
        let guards = self
            .guards
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut total = MemoryVmessHttpCoverReceipt::default();
        for guard in guards.iter() {
            let r = guard.receipt();
            total.owners += r.owners;
            total.opens += r.opens;
            total.target_handshakes += r.target_handshakes;
            total.cover_requests += r.cover_requests;
            total.cover_responses += r.cover_responses;
            total.client_drops += r.client_drops;
            total.peer_drops += r.peer_drops;
            total.owner_cancelled += r.owner_cancelled;
            total.owner_closed += r.owner_closed;
            total.owner_wait_returned += r.owner_wait_returned;
            total.owner_tasks_empty += r.owner_tasks_empty;
            total.auth_failures += r.auth_failures;
            total.client_write_pending += r.client_write_pending;
            total.peer_write_pending += r.peer_write_pending;
            total.client_read_pending += r.client_read_pending;
            total.peer_read_pending += r.peer_read_pending;
            total.partial_writes += r.partial_writes;
            total.short_reads += r.short_reads;
        }
        total
    }
}

async fn entity(io: &mut (impl AsyncRead + Unpin), byte: u8) -> io::Result<()> {
    let mut data = vec![0; ENTITY];
    stage("complete synthetic entity", io.read_exact(&mut data).await)?;
    require(
        data.iter().all(|value| *value == byte),
        "synthetic entity bytes",
    )
}
async fn exchange(
    client: BoxStream,
    mut peer: Peer,
    blocked: oneshot::Receiver<()>,
) -> io::Result<()> {
    let (allow, allowed) = oneshot::channel();
    tokio::try_join!(
        async move {
            let (mut read, mut write) = tokio::io::split(client);
            write.write_all(b"!").await?;
            write.flush().await?;
            let mut payload = vec![0x31; ENTITY];
            payload.extend_from_slice(&vec![0x32; ENTITY]);
            let mut upload = Box::pin(async {
                write.write_all(&payload).await?;
                write.flush().await
            });
            pending(
                poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx))).await,
                "real upload must remain Pending",
            )?;
            // Read while awaiting peer backpressure: the lazy response prefix
            // can exceed64B, so waiting for a body-only event before reading
            // would itself deadlock the valid constructor/response contract.
            tokio::try_join!(entity(&mut read, 0x91), async {
                blocked
                    .await
                    .map_err(|_| invalid("real peer body TX never blocked"))
            })?;
            pending(
                poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx))).await,
                "response1 must finish while TX stays Pending",
            )?;
            let mut second = Box::pin(entity(&mut read, 0x92));
            pending(
                poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx))).await,
                "response2 must wait for upload",
            )?;
            allow.send(()).map_err(|_| invalid("upload gate lost"))?;
            tokio::try_join!(upload.as_mut(), second.as_mut())?;
            drop((upload, second));
            // HTTP transport deliberately whole-closes after the two fully
            // received responses; no later half-close read is claimed.
            write.shutdown().await?;
            Ok::<_, io::Error>(())
        },
        async move {
            let mut marker = [0];
            peer.read_exact(&mut marker).await?;
            require(marker == [b'!'], "actual initial payload")?;
            peer.write_all(&vec![0x91; ENTITY]).await?;
            peer.flush().await?;
            allowed.await.map_err(|_| invalid("client RX gate lost"))?;
            entity(&mut peer, 0x31).await?;
            entity(&mut peer, 0x32).await?;
            peer.write_all(&vec![0x92; ENTITY]).await?;
            peer.flush().await?;
            let mut extra = [0];
            require(
                peer.read(&mut extra).await? == 0,
                "no duplicate upload or target bytes",
            )?;
            Ok::<_, io::Error>(())
        }
    )?;
    Ok(())
}
async fn close_fixture(fixture: NodeFixture) -> MemoryVmessHttpCoverReceipt {
    fixture.guard.begin_shutdown();
    fixture.guard.shutdown().await;
    let counts = fixture.guard.counts.clone();
    let node_weak = Arc::downgrade(&fixture.guard.node);
    let guard_weak = Arc::downgrade(&fixture.guard);
    let weak: Vec<Weak<Counts>> = counts.iter().map(Arc::downgrade).collect();
    let expected = counts.len();
    let mut receipt = fixture.guard.receipt();
    drop(fixture);
    receipt.client_drops = counts
        .iter()
        .map(|c| c.client_drops.load(Ordering::SeqCst))
        .sum();
    receipt.peer_drops = counts
        .iter()
        .map(|c| c.peer_drops.load(Ordering::SeqCst))
        .sum();
    drop(counts);
    assert_eq!(
        receipt.client_drops, expected,
        "actual client IO survived: {receipt:?}"
    );
    assert_eq!(
        receipt.peer_drops, expected,
        "actual peer IO survived: {receipt:?}"
    );
    assert!(
        weak.iter().all(|weak| weak.upgrade().is_none()),
        "actual wire ownership survived real shutdown/drop"
    );
    assert!(
        node_weak.upgrade().is_none() && guard_weak.upgrade().is_none(),
        "actual node/guard ownership survived shutdown/drop"
    );
    assert_eq!(
        (
            receipt.owner_cancelled,
            receipt.owner_closed,
            receipt.owner_wait_returned,
            receipt.owner_tasks_empty
        ),
        (1, 1, 1, 1),
        "{receipt:?}"
    );
    receipt
}
fn operation_result(
    outcome: Result<
        Result<io::Result<()>, tokio::time::error::Elapsed>,
        Box<dyn std::any::Any + Send>,
    >,
    cipher: BodyCipher,
) -> Result<(), String> {
    match outcome {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(format!(
            "{cipher:?}: operation kind={:?}; stage={error}",
            error.kind()
        )),
        Ok(Err(_)) => Err(format!("{cipher:?}: bounded operation deadline")),
        Err(_) => Err(format!("{cipher:?}: operation unwind (payload omitted)")),
    }
}
#[tokio::test]
async fn vmess_http_cover_wire_auth_four_modes_two_entities_cross_direction() {
    let mut results = Vec::new();
    for cipher in CIPHERS {
        let mut fixture = node_fixture(cipher, 64, 1).unwrap();
        let (raw, blocked) = fixture.peers.remove(0);
        let outcome = AssertUnwindSafe(timeout(WAIT, async {
            let target = Destination::domain("body.memory.invalid", 443).unwrap();
            let (client, peer) = open_wire(
                &fixture.guard,
                raw,
                target,
                cipher,
                UUID_BYTES,
                ResponseMode::Valid,
            )
            .await?;
            exchange(client, peer, blocked).await
        }))
        .catch_unwind()
        .await;
        // The operation future owns both endpoints and is gone on every path.
        // Cleanup/Weak proof always precedes desired result classification.
        let receipt = close_fixture(fixture).await;
        let mut result = operation_result(outcome, cipher);
        if result.is_ok()
            && !(receipt.opens == 1
                && receipt.target_handshakes == 1
                && receipt.cover_requests == 1
                && receipt.cover_responses == 1
                && receipt.auth_failures == 0
                && receipt.client_write_pending > 0
                && receipt.peer_write_pending > 0
                && receipt.client_read_pending > 0
                && receipt.peer_read_pending > 0
                && receipt.partial_writes > 0
                && receipt.short_reads > 0)
        {
            result = Err(format!(
                "{cipher:?}: actual authentication/readiness receipt {receipt:?}"
            ));
        }
        results.push(result);
    }
    let errors: Vec<_> = results.into_iter().filter_map(Result::err).collect();
    assert!(
        errors.is_empty(),
        "all four real wire-auth cases: {errors:?}"
    );
}

#[tokio::test]
async fn vmess_http_cover_wire_auth_wrong_uuid_rejects_after_real_request() {
    let mut results = Vec::new();
    for cipher in CIPHERS {
        let mut fixture = node_fixture(cipher, 64, 1).unwrap();
        let (raw, blocked) = fixture.peers.remove(0);
        drop(blocked);
        let outcome = AssertUnwindSafe(timeout(WAIT, async {
            let target = Destination::domain("body.memory.invalid", 443).unwrap();
            match open_wire(
                &fixture.guard,
                raw,
                target,
                cipher,
                [8; 16],
                ResponseMode::Valid,
            )
            .await
            {
                Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(()),
                Err(error) => Err(io::Error::new(
                    error.kind(),
                    "wrong UUID failed outside authenticated request",
                )),
                Ok((client, peer)) => {
                    drop((client, peer));
                    Err(invalid("wrong UUID was authenticated"))
                }
            }
        }))
        .catch_unwind()
        .await;
        let receipt = close_fixture(fixture).await;
        let mut result = operation_result(outcome, cipher);
        if result.is_ok()
            && !(receipt.opens == 1
                && receipt.cover_requests == 1
                && receipt.target_handshakes == 0
                && receipt.cover_responses == 0
                && receipt.auth_failures == 1)
        {
            result = Err(format!("{cipher:?}: wrong UUID receipt {receipt:?}"));
        }
        results.push(result);
    }
    let errors: Vec<_> = results.into_iter().filter_map(Result::err).collect();
    assert!(errors.is_empty(), "wrong UUID controls: {errors:?}");
}

#[tokio::test]
async fn vmess_http_cover_wire_response_tag_rejects_before_plaintext_including_none() {
    let mut results = Vec::new();
    for cipher in CIPHERS {
        let mut fixture = node_fixture(cipher, 64, 1).unwrap();
        let (raw, blocked) = fixture.peers.remove(0);
        drop(blocked);
        let outcome = AssertUnwindSafe(timeout(WAIT, async {
            let target = Destination::domain("body.memory.invalid", 443).unwrap();
            let (mut client, mut peer) = open_wire(
                &fixture.guard,
                raw,
                target,
                cipher,
                UUID_BYTES,
                ResponseMode::BadTag,
            )
            .await?;
            let (read, write) = tokio::join!(
                async {
                    let mut bytes = [0; 1];
                    let mut output = ReadBuf::new(&mut bytes);
                    let result =
                        poll_fn(|cx| Pin::new(&mut client).poll_read(cx, &mut output)).await;
                    require(
                        output.filled().is_empty(),
                        "unauthenticated plaintext was delivered",
                    )?;
                    match result {
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(()),
                        _ => Err(invalid("response authentication was not rejected")),
                    }
                },
                async {
                    peer.write_all(b"must-not-deliver").await?;
                    peer.flush().await
                }
            );
            read?;
            if let Err(error) = write {
                require(
                    matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ),
                    "unexpected peer error after client auth rejection",
                )?;
            }
            Ok::<_, io::Error>(())
        }))
        .catch_unwind()
        .await;
        let receipt = close_fixture(fixture).await;
        let mut result = operation_result(outcome, cipher);
        if result.is_ok()
            && !(receipt.opens == 1
                && receipt.target_handshakes == 1
                && receipt.cover_requests == 1
                && receipt.cover_responses == 1
                && receipt.auth_failures == 0)
        {
            result = Err(format!(
                "{cipher:?}: response authentication receipt {receipt:?}"
            ));
        }
        results.push(result);
    }
    let errors: Vec<_> = results.into_iter().filter_map(Result::err).collect();
    assert!(
        errors.is_empty(),
        "response authentication controls: {errors:?}"
    );
}

#[tokio::test]
async fn vmess_http_cover_wire_child_drop_preserves_authenticated_sibling_until_stop() {
    let mut results = Vec::new();
    for cipher in CIPHERS {
        let mut fixture = node_fixture(cipher, 64, 2).unwrap();
        let (raw_one, signal_one) = fixture.peers.remove(0);
        let (raw_two, signal_two) = fixture.peers.remove(0);
        drop((signal_one, signal_two));
        let outcome = AssertUnwindSafe(timeout(WAIT, async {
            let target = Destination::domain("sibling.memory.invalid", 443).unwrap();
            let (first, first_peer) = open_wire(&fixture.guard, raw_one, target.clone(), cipher, UUID_BYTES, ResponseMode::Valid).await?;
            let (mut second, mut second_peer) = open_wire(&fixture.guard, raw_two, target, cipher, UUID_BYTES, ResponseMode::Valid).await?;
            drop((first, first_peer));
            require(!fixture.guard.node.http_cover_test_lifecycle().0, "single child Drop cancelled actual parent")?;
            tokio::try_join!(
                async { second.write_all(b"sibling").await?; second.flush().await },
                async { let mut marker = [0; 7]; second_peer.read_exact(&mut marker).await?; require(marker.as_slice() == b"sibling", "live sibling payload") }
            )?;
            let payload = vec![0x41; ENTITY];
            let (mut read, mut write) = tokio::io::split(second);
            let mut upload = Box::pin(async { write.write_all(&payload).await?; write.flush().await });
            pending(poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx))).await, "live sibling TX must really be Pending")?;
            let mut storage = [0; 1];
            let mut output = ReadBuf::new(&mut storage);
            pending(poll_fn(|cx| Poll::Ready(Pin::new(&mut read).poll_read(cx, &mut output))).await, "live sibling RX must really be Pending")?;
            fixture.guard.begin_shutdown();
            // Actual cancellation errors, followed by real IO Drop, not a
            // Boolean stop receipt or a synthetic readiness event.
            let read_result = poll_fn(|cx| Pin::new(&mut read).poll_read(cx, &mut output)).await;
            drop(upload);
            let write_result = write.write_all(b"forbidden").await;
            require(matches!(read_result, Err(ref error) if error.kind() == io::ErrorKind::ConnectionAborted)
                && matches!(write_result, Err(ref error) if error.kind() == io::ErrorKind::ConnectionAborted)
                && output.filled().is_empty(), "real sibling Stop did not revoke IO")?;
            drop((read, write, second_peer));
            Ok::<_, io::Error>(())
        })).catch_unwind().await;
        let receipt = close_fixture(fixture).await;
        let mut result = operation_result(outcome, cipher);
        if result.is_ok()
            && !(receipt.opens == 2
                && receipt.target_handshakes == 2
                && receipt.cover_requests == 2
                && receipt.cover_responses == 0
                && receipt.auth_failures == 0)
        {
            result = Err(format!("{cipher:?}: sibling receipt {receipt:?}"));
        }
        results.push(result);
    }
    let errors: Vec<_> = results.into_iter().filter_map(Result::err).collect();
    assert!(
        errors.is_empty(),
        "same-node authenticated sibling controls: {errors:?}"
    );
}

// Interactive HTTP-cover progress controls. These are intentionally separate
// from the full entity tests: no application write follows the one-byte tail.
#[derive(Clone, Copy, Debug)]
enum InteractiveCase {
    ExplicitFlush,
    NoFlushThenRead,
    ReadFirstExplicitFlush,
    ReadFirstNoFlush,
    ReadyReadWithPendingFlush,
}
async fn close_interactive_factory(
    factory: Arc<MemoryVmessHttpCoverFactory>,
) -> MemoryVmessHttpCoverReceipt {
    factory.begin_shutdown();
    factory.shutdown().await;
    let (guards, nodes, counts) = {
        let registry = factory
            .guards
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        (
            registry.iter().map(Arc::downgrade).collect::<Vec<_>>(),
            registry
                .iter()
                .map(|guard| Arc::downgrade(&guard.node))
                .collect::<Vec<_>>(),
            registry
                .iter()
                .flat_map(|guard| guard.counts.iter().cloned())
                .collect::<Vec<_>>(),
        )
    };
    let wires: Vec<_> = counts.iter().map(Arc::downgrade).collect();
    let owner = Arc::downgrade(&factory);
    let mut receipt = factory.snapshot();
    drop(factory);
    // Failed setup may leave an unused queue entry until its actual node is
    // dropped. Read the final drop counters only after that ownership release.
    receipt.client_drops = counts
        .iter()
        .map(|count| count.client_drops.load(Ordering::SeqCst))
        .sum();
    receipt.peer_drops = counts
        .iter()
        .map(|count| count.peer_drops.load(Ordering::SeqCst))
        .sum();
    drop(counts);
    assert!(
        owner.upgrade().is_none(),
        "interactive factory owner survived"
    );
    assert!(
        guards.iter().all(|weak| weak.upgrade().is_none()),
        "interactive guard survived"
    );
    assert!(
        nodes.iter().all(|weak| weak.upgrade().is_none()),
        "interactive node survived"
    );
    assert!(
        wires.iter().all(|weak| weak.upgrade().is_none()),
        "interactive wire survived"
    );
    assert_eq!(receipt.client_drops, receipt.owners, "{receipt:?}");
    assert_eq!(receipt.peer_drops, receipt.owners, "{receipt:?}");
    assert_eq!(receipt.owner_cancelled, receipt.owners, "{receipt:?}");
    assert_eq!(receipt.owner_closed, receipt.owners, "{receipt:?}");
    assert_eq!(receipt.owner_wait_returned, receipt.owners, "{receipt:?}");
    assert_eq!(receipt.owner_tasks_empty, receipt.owners, "{receipt:?}");
    receipt
}
async fn interactive_case(cipher: BodyCipher, case: InteractiveCase) -> Result<(), String> {
    let factory = MemoryVmessHttpCoverFactory::new(cipher, 64);
    let outcome = AssertUnwindSafe(timeout(WAIT, async {
        let (mut client, accept) = factory
            .open(Destination::domain("interactive.memory.invalid", 443).unwrap())
            .await?;
        let mut peer = accept.await?;
        match case {
            InteractiveCase::ExplicitFlush | InteractiveCase::NoFlushThenRead => {
                tokio::try_join!(
                    async {
                        client.write_all(b"x").await?;
                        if matches!(case, InteractiveCase::ExplicitFlush) {
                            client.flush().await?;
                        }
                        let mut reply = [0; 1];
                        client.read_exact(&mut reply).await?;
                        require(reply == [b'y'], "one-byte actual response differs")
                    },
                    async {
                        let mut request = [0; 1];
                        peer.read_exact(&mut request).await?;
                        require(
                            request == [b'x'],
                            "peer did not decode the accepted one-byte request",
                        )?;
                        peer.write_all(b"y").await?;
                        peer.flush().await
                    }
                )?;
            }
            InteractiveCase::ReadFirstExplicitFlush | InteractiveCase::ReadFirstNoFlush => {
                let (mut read, mut write) = tokio::io::split(client);
                // The source stays genuinely open without supplying another
                // byte. No EOF, timer, synthetic wake or second write can drive
                // the response future after the accepted one-byte tail.
                let (source_open, mut source) = tokio::io::duplex(1);
                let raw_reads_before = factory.snapshot().client_read_pending;
                let read_was_pending = AtomicBool::new(false);
                let upload_accepted = AtomicBool::new(false);
                let source_was_pending = AtomicBool::new(false);
                tokio::try_join!(
                    async {
                        let mut reply = [0; 1];
                        let mut read_reply = Box::pin(read.read_exact(&mut reply));
                        let mut reading = Box::pin(poll_fn(|cx| {
                            let result = read_reply.as_mut().poll(cx);
                            if result.is_pending() {
                                read_was_pending.store(true, Ordering::SeqCst);
                            }
                            result
                        }));
                        let mut uploading = Box::pin(async {
                            require(
                                read_was_pending.load(Ordering::SeqCst)
                                    && factory.snapshot().client_read_pending > raw_reads_before,
                                "read-first response did not really become Pending at raw IO before TX",
                            )?;
                            stage("read-first client write", write.write_all(b"x").await)?;
                            upload_accepted.store(true, Ordering::SeqCst);
                            if matches!(case, InteractiveCase::ReadFirstExplicitFlush) {
                                stage("read-first explicit flush", write.flush().await)?;
                            }
                            let mut remaining = [0; 1];
                            let mut source_read = Box::pin(source.read_exact(&mut remaining));
                            poll_fn(|cx| {
                                let result = source_read.as_mut().poll(cx);
                                if result.is_pending() {
                                    source_was_pending.store(true, Ordering::SeqCst);
                                }
                                result
                            })
                            .await?;
                            Err::<(), _>(invalid("read-first source unexpectedly supplied more bytes"))
                        });
                        // Match the H1 pump: response polling precedes upload
                        // polling in this same parent. Do not write first and
                        // then directly await a freshly polled response.
                        let result = tokio::select! {
                            biased;
                            result = &mut reading => result.map(|_| ()),
                            result = &mut uploading => result,
                        };
                        drop(uploading);
                        drop(reading);
                        drop(read_reply);
                        // Retain the real source writer across the whole wait.
                        drop(source_open);
                        stage("read-first client response", result)?;
                        require(
                            read_was_pending.load(Ordering::SeqCst)
                                && upload_accepted.load(Ordering::SeqCst)
                                && source_was_pending.load(Ordering::SeqCst),
                            "read-first response bypassed the blocked real upload source",
                        )?;
                        require(reply == [b'y'], "read-first actual response differs")
                    },
                    async {
                        let mut request = [0; 1];
                        stage("read-first peer request", peer.read_exact(&mut request).await)?;
                        require(request == [b'x'], "read-first peer did not decode the accepted tail")?;
                        stage("read-first peer response", peer.write_all(b"y").await)?;
                        stage("read-first peer flush", peer.flush().await)
                    }
                )?;
            }
            InteractiveCase::ReadyReadWithPendingFlush => {
                tokio::try_join!(
                    async {
                        client.write_all(b"x").await?;
                        client.flush().await?;
                        let mut first = [0; 1];
                        client.read_exact(&mut first).await?;
                        require(first == [b'a'], "ready-RX setup marker differs")
                    },
                    async {
                        let mut request = [0; 1];
                        peer.read_exact(&mut request).await?;
                        require(request == [b'x'], "ready-RX peer request differs")?;
                        // A single real response record contains a+y. Reading
                        // only a leaves y decoded or already physically ready.
                        peer.write_all(b"ay").await?;
                        peer.flush().await
                    }
                )?;
                let (mut read, mut write) = tokio::io::split(client);
                let payload = vec![0x51; WRITE_CHUNK];
                let accepted =
                    poll_fn(|cx| Poll::Ready(Pin::new(&mut write).poll_write(cx, &payload))).await;
                require(
                    matches!(accepted, Poll::Ready(Ok(amount)) if amount == payload.len()),
                    "ready-RX TX chunk was not accepted",
                )?;
                let before = factory.snapshot().client_write_pending;
                let mut flushing = Box::pin(write.flush());
                pending(
                    poll_fn(|cx| Poll::Ready(flushing.as_mut().poll(cx))).await,
                    "real TX flush must be Pending",
                )?;
                require(
                    factory.snapshot().client_write_pending > before,
                    "TX Pending never reached actual raw IO",
                )?;
                let mut reply = [0; 1];
                let mut output = ReadBuf::new(&mut reply);
                let ready =
                    poll_fn(|cx| Poll::Ready(Pin::new(&mut read).poll_read(cx, &mut output))).await;
                require(
                    matches!(ready, Poll::Ready(Ok(()))) && output.filled() == b"y",
                    "ready RX was blocked by pending TX flush",
                )?;
                pending(
                    poll_fn(|cx| Poll::Ready(flushing.as_mut().poll(cx))).await,
                    "RX must not silently complete the withheld upload",
                )?;
                drop(flushing);
                drop((read, write));
            }
        }
        Ok::<_, io::Error>(())
    }))
    .catch_unwind()
    .await;
    // Every completed/error/timeout/unwind future releases both endpoints
    // before the real node/guard/raw Weak cleanup and the desired verdict.
    let receipt = close_interactive_factory(factory).await;
    let result = operation_result(outcome, cipher);
    if let Err(error) = result {
        return Err(format!("{case:?}: {error}; actual receipt={receipt:?}"));
    }
    if !(receipt.owners == 1
        && receipt.opens == 1
        && receipt.target_handshakes == 1
        && receipt.cover_requests == 1
        && receipt.cover_responses == 1
        && receipt.auth_failures == 0)
    {
        return Err(format!(
            "{cipher:?}/{case:?}: actual authenticated path missing: {receipt:?}"
        ));
    }
    Ok(())
}

#[tokio::test]
async fn vmess_http_cover_one_byte_explicit_flush_and_ready_rx_controls() {
    let mut failures = Vec::new();
    for cipher in CIPHERS {
        for case in [
            InteractiveCase::ExplicitFlush,
            InteractiveCase::ReadyReadWithPendingFlush,
        ] {
            if let Err(error) = interactive_case(cipher, case).await {
                failures.push(error);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "interactive explicit-flush/RX-priority controls after cleanup: {failures:?}"
    );
}

#[tokio::test]
async fn vmess_http_cover_one_byte_read_drives_accepted_write_without_flush() {
    let mut failures = Vec::new();
    for cipher in CIPHERS {
        if let Err(error) = interactive_case(cipher, InteractiveCase::NoFlushThenRead).await {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "one-byte no-flush progress after cleanup: {failures:?}"
    );
}

#[tokio::test]
async fn vmess_http_cover_read_first_explicit_flush_reaches_peer_after_pending_read() {
    let mut failures = Vec::new();
    for cipher in CIPHERS {
        if let Err(error) = interactive_case(cipher, InteractiveCase::ReadFirstExplicitFlush).await
        {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "read-first explicit-flush controls after cleanup: {failures:?}"
    );
}

#[tokio::test]
async fn vmess_http_cover_read_first_accepted_write_reawakens_pending_response() {
    let mut failures = Vec::new();
    for cipher in CIPHERS {
        if let Err(error) = interactive_case(cipher, InteractiveCase::ReadFirstNoFlush).await {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "read-first no-flush progress after cleanup: {failures:?}"
    );
}
