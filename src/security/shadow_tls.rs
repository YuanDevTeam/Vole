//! Strict ShadowTLS v3 over caller-owned IO. Native TLS verifies the complete
//! cover handshake; only then may authenticated relay records carry SS bytes.
//! Wire reference: https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use ring::hmac;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroizing;

use super::{SecurityContext, TlsClientOptions, TlsVersions, boring::BoringTlsClient};
use crate::{config::ShadowTlsConfig, dispatch::BoxStream};

const MAX_RECORD: usize = 18_436;
const MAX_PAYLOAD: usize = 16_384;
const RECORD_HEADER: usize = 5;
const AUTH_HEADER: usize = 9;

/// An immutable cover policy. This client has no resolver, socket factory,
/// session cache or background task; cancellation drops all handshake state.
#[derive(Clone)]
pub struct ShadowTlsClient {
    tls: BoringTlsClient,
    password: Arc<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for ShadowTlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowTlsClient").finish_non_exhaustive()
    }
}

impl ShadowTlsClient {
    pub fn new(context: &SecurityContext, config: &ShadowTlsConfig) -> io::Result<Self> {
        config.validate().map_err(|_| invalid())?;
        Ok(Self {
            tls: BoringTlsClient::standard(
                context,
                &config.server_name,
                &TlsClientOptions {
                    versions: TlsVersions::Tls13,
                    alpn: config.alpn.clone(),
                    required_alpn: config.required_alpn.clone(),
                    identity: config
                        .identity
                        .as_ref()
                        .map(|identity| super::TlsClientIdentity::from_config(identity, context))
                        .transpose()?,
                    certificate: config.certificate.clone(),
                    client_fingerprint: config.client_fingerprint,
                    ..Default::default()
                },
                0,
            )?,
            password: Arc::new(Zeroizing::new(config.password.as_bytes().to_vec())),
        })
    }

    /// The caller retains its original establishment deadline and cancellation.
    /// No business bytes are written before TLS and relay authentication succeed.
    pub async fn connect(&self, raw: BoxStream) -> io::Result<BoxStream> {
        let mut relay = Relay::new(raw, self.password.clone());
        let mut tls = self
            .tls
            .handshake_configured(&mut relay, |config| {
                config
                    .set_shadow_tls_v3_client(&self.password)
                    .map_err(|_| invalid())
            })
            .await?;
        if tls.ssl().version2() != Some(boring::ssl::SslVersion::TLS1_3) || tls.ssl().pending() != 0
        {
            return Err(invalid());
        }
        tls.flush().await?;
        // Borrowing the relay lets us drop SSL without a new fork extraction API.
        // Record reads never over-read into the next record at this transition.
        drop(tls);
        Ok(Box::new(relay.verified()?))
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "ShadowTLS authentication or record failed",
    )
}

struct Mac(hmac::Context);
impl Mac {
    fn new(password: &[u8], seed: &[u8], direction: &[u8]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, password);
        let mut value = hmac::Context::with_key(&key);
        value.update(seed);
        value.update(direction);
        Self(value)
    }
    fn tag(&mut self, bytes: &[u8], chained: bool) -> [u8; 4] {
        self.0.update(bytes);
        let tag: [u8; 4] = self.0.clone().sign().as_ref()[..4].try_into().unwrap();
        if chained {
            self.0.update(&tag);
        }
        tag
    }
    fn verifies(&mut self, record: &[u8], chained: bool) -> bool {
        record.len() >= AUTH_HEADER
            && boring::memcmp::eq(&self.tag(&record[AUTH_HEADER..], chained), &record[5..9])
    }
}

/// One bounded record, retaining partial input across Pending/read cancellation.
struct Record {
    bytes: Vec<u8>,
    filled: usize,
    size: usize,
}
impl Record {
    fn new() -> Self {
        Self {
            bytes: vec![0; RECORD_HEADER],
            filled: 0,
            size: RECORD_HEADER,
        }
    }
    fn clear(&mut self) {
        self.bytes.clear();
        self.bytes.resize(RECORD_HEADER, 0);
        self.filled = 0;
        self.size = RECORD_HEADER;
    }
    fn poll(&mut self, raw: &mut BoxStream, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if self.filled < self.size {
                let mut read = ReadBuf::new(&mut self.bytes[self.filled..self.size]);
                ready!(Pin::new(&mut **raw).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return if self.filled == 0 {
                        Poll::Ready(Ok(false))
                    } else {
                        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                    };
                }
                self.filled += count;
                if self.filled < self.size {
                    continue;
                }
            }
            if self.size != RECORD_HEADER {
                return Poll::Ready(Ok(true));
            }
            let size = usize::from(u16::from_be_bytes([self.bytes[3], self.bytes[4]]));
            if self.bytes[1] != 3
                || !(1..=3).contains(&self.bytes[2])
                || !(1..=MAX_RECORD).contains(&size)
            {
                return Poll::Ready(Err(invalid()));
            }
            self.size = RECORD_HEADER + size;
            self.bytes.resize(self.size, 0);
        }
    }
}

struct Relay {
    raw: BoxStream,
    password: Arc<Zeroizing<Vec<u8>>>,
    record: Record,
    pending: Option<usize>,
    hello_prefix: Vec<u8>,
    seed: Option<[u8; 32]>,
    mask: Zeroizing<[u8; 32]>,
    ignore: Option<Mac>,
    authorized: bool,
}
impl Relay {
    fn new(raw: BoxStream, password: Arc<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            raw,
            password,
            record: Record::new(),
            pending: None,
            hello_prefix: Vec::new(),
            seed: None,
            mask: Zeroizing::new([0; 32]),
            ignore: None,
            authorized: false,
        }
    }
    fn decode(&mut self) -> io::Result<()> {
        let record = &mut self.record.bytes;
        match record[0] {
            22 if self.seed.is_none() => {
                let count = (38 - self.hello_prefix.len()).min(record.len() - RECORD_HEADER);
                self.hello_prefix.extend_from_slice(&record[5..5 + count]);
                if self.hello_prefix[0] != 2 {
                    return Err(invalid());
                }
                if self.hello_prefix.len() == 38 {
                    let seed: [u8; 32] = self.hello_prefix[6..38].try_into().unwrap();
                    self.ignore = Some(Mac::new(&self.password, &seed, &[]));
                    let mut digest = Sha256::new();
                    digest.update(&**self.password);
                    digest.update(seed);
                    *self.mask = digest.finalize().into();
                    // HRR and the final ServerHello share the first relay seed.
                    self.seed = Some(seed);
                }
            }
            23 => {
                self.authorized = false;
                if record.len() <= AUTH_HEADER
                    || record[1..3] != [3, 3]
                    || !self
                        .ignore
                        .as_mut()
                        .ok_or_else(invalid)?
                        .verifies(record, false)
                {
                    return Err(invalid());
                }
                for (index, byte) in record[AUTH_HEADER..].iter_mut().enumerate() {
                    *byte ^= self.mask[index % 32];
                }
                record.drain(5..9);
                let size = (record.len() - RECORD_HEADER) as u16;
                record[3..5].copy_from_slice(&size.to_be_bytes());
                self.authorized = true;
            }
            _ => {}
        }
        Ok(())
    }
    fn verified(self) -> io::Result<Verified> {
        if !self.authorized || self.pending.is_some() || self.record.filled != 0 {
            return Err(invalid());
        }
        let seed = self.seed.ok_or_else(invalid)?;
        Ok(Verified {
            raw: self.raw,
            record: self.record,
            pending: None,
            tx: Mac::new(&self.password, &seed, b"C"),
            rx: Mac::new(&self.password, &seed, b"S"),
            ignore: self.ignore,
            write: Vec::new(),
            written: 0,
            failed: false,
            closing: None,
            closed: false,
        })
    }
}
impl AsyncRead for Relay {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pending.is_none() {
            if !ready!(this.record.poll(&mut this.raw, cx))? {
                return Poll::Ready(Ok(()));
            }
            this.decode()?;
            this.pending = Some(0);
        }
        copy_pending(&mut this.record, &mut this.pending, out);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Relay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.raw).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.raw).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
    }
}

fn copy_pending(record: &mut Record, pending: &mut Option<usize>, out: &mut ReadBuf<'_>) {
    let at = pending.unwrap();
    let count = out.remaining().min(record.bytes.len() - at);
    out.put_slice(&record.bytes[at..at + count]);
    if at + count == record.bytes.len() {
        record.clear();
        *pending = None;
    } else {
        *pending = Some(at + count);
    }
}

struct Verified {
    raw: BoxStream,
    record: Record,
    pending: Option<usize>,
    tx: Mac,
    rx: Mac,
    ignore: Option<Mac>,
    write: Vec<u8>,
    written: usize,
    failed: bool,
    closing: Option<Pin<Box<tokio::time::Sleep>>>,
    closed: bool,
}
impl Verified {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.write.len() {
            let count =
                ready!(Pin::new(&mut *self.raw).poll_write(cx, &self.write[self.written..]))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += count;
        }
        self.write.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
    fn read(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(invalid()));
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Advance accepted writes, but don't let write backpressure block reads.
        if let Poll::Ready(result) = self.drain(cx) {
            result?;
        }
        for _ in 0..32 {
            if self.pending.is_some() {
                copy_pending(&mut self.record, &mut self.pending, out);
                return Poll::Ready(Ok(()));
            }
            if !ready!(self.record.poll(&mut self.raw, cx))? {
                return Poll::Ready(Ok(()));
            }
            let record = &self.record.bytes;
            if record[0..3] != [23, 3, 3] || record.len() < AUTH_HEADER {
                return Poll::Ready(Err(invalid()));
            }
            if let Some(ignore) = &mut self.ignore {
                if ignore.verifies(record, false) {
                    self.record.clear();
                    continue;
                }
                self.ignore = None;
            }
            if !self.rx.verifies(record, true) {
                return Poll::Ready(Err(invalid()));
            }
            if record.len() == AUTH_HEADER {
                self.record.clear();
                continue;
            }
            self.pending = Some(AUTH_HEADER);
        }
        // Bound work per poll without imposing a lifetime business-record quota.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncRead for Verified {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.read(cx, out);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
}
impl AsyncWrite for Verified {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed || this.closing.is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Err(error) = ready!(this.drain(cx)) {
            this.failed = true;
            return Poll::Ready(Err(error));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let size = bytes.len().min(MAX_PAYLOAD);
        let tag = this.tx.tag(&bytes[..size], true);
        this.write.extend_from_slice(&[23, 3, 3]);
        this.write
            .extend_from_slice(&((size + 4) as u16).to_be_bytes());
        this.write.extend_from_slice(&tag);
        this.write.extend_from_slice(&bytes[..size]);
        Poll::Ready(Ok(size))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid()));
        }
        if let Err(error) = ready!(this.drain(cx)) {
            this.failed = true;
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut *this.raw).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.closing.is_none() {
            self.closing = Some(Box::pin(tokio::time::sleep(super::CLOSE_NOTIFY_TIMEOUT)));
        }
        if self.closing.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            self.failed = true;
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        ready!(self.as_mut().poll_flush(cx))?;
        // This is now a relay stream, not a TLS application channel. Never send
        // a TLS close_notify into the SS payload or release unread relay bytes.
        let result = Pin::new(&mut *self.raw).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.closed = true;
        }
        if matches!(result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
}
