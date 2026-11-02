//! Record-bounded TLS IO for Vision, using only public TLS interfaces.
//! Never feed a second TLS record to the deframer in one read, and never
//! concatenate plaintext chunks before the framing layer sees its direct marker.

#[path = "vision_boring.rs"]
mod boring;
pub(super) use boring::BoringSplice;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{SecurityContext, StandardTlsClient, TlsClientOptions, TlsVersions};
    use rustls::{
        RootCertStore, ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;
    fn pair(profile: Option<crate::config::ClientFingerprint>) -> (StandardTlsClient, TlsAcceptor) {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let context = SecurityContext {
            provider: provider.clone(),
            tls_roots: Arc::new(roots),
            identities: Arc::default(),
        };
        let client = StandardTlsClient::with_options(
            &context,
            "localhost",
            TlsClientOptions {
                client_fingerprint: profile,
                versions: TlsVersions::Tls13,
                ..Default::default()
            },
            0,
            65536,
        )
        .unwrap();
        let server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    identity.signing_key.serialize_der(),
                )),
            )
            .unwrap();
        (client, TlsAcceptor::from(Arc::new(server)))
    }
    struct FragmentIo {
        raw: BoxStream,
        limit: usize,
    }
    impl AsyncRead for FragmentIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let size = buf.remaining().min(self.limit);
            let mut part = ReadBuf::new(&mut buf.initialize_unfilled()[..size]);
            ready!(Pin::new(&mut self.raw).poll_read(cx, &mut part))?;
            let count = part.filled().len();
            buf.advance(count);
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for FragmentIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = buf.len().min(self.limit);
            Pin::new(&mut self.raw).poll_write(cx, &buf[..count])
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_shutdown(cx)
        }
    }
    #[tokio::test]
    async fn record_boundary_preserves_buffered_plaintext_and_coalesced_raw_tail_and_flush_order() {
        for &profile in crate::security::test_profiles() {
            for limit in [1, 3, 65536] {
                tokio::time::timeout(Duration::from_secs(3), async {
                    let (client, acceptor) = pair(profile);
                    let (io, peer) = tokio::io::duplex(65536);
                    let server = tokio::spawn(async move {
                        let mut tls = acceptor
                            .accept(RecordIo::new(Box::new(peer)))
                            .await
                            .unwrap();
                        tls.write_all(b"marker-buffered").await.unwrap();
                        tls.flush().await.unwrap();
                        // Raw tail is immediately coalesced after the encrypted
                        // marker; a greedy TLS read loses or tries to decrypt it.
                        tls.get_mut()
                            .0
                            .raw
                            .write_all(b"raw-after-record")
                            .await
                            .unwrap();
                        let mut marker = [0; 16];
                        tls.read_exact(&mut marker).await.unwrap();
                        assert_eq!(&marker, b"encrypted-marker");
                        let mut raw = tls.into_inner().0.raw;
                        let mut written = [0; 9];
                        raw.read_exact(&mut written).await.unwrap();
                        assert_eq!(&written, b"raw-write");
                    });
                    let stats = Arc::new(SpliceStats::default());
                    let (mut tls, control) = client
                        .connect_vision(
                            Box::new(FragmentIo {
                                raw: Box::new(io),
                                limit,
                            }),
                            stats.clone(),
                        )
                        .await
                        .unwrap();
                    let mut marker = [0; 7];
                    tls.read_exact(&mut marker).await.unwrap();
                    assert_eq!(&marker, b"marker-");
                    control.read_direct();
                    let mut tail = [0; 24];
                    tls.read_exact(&mut tail).await.unwrap();
                    assert_eq!(&tail, b"bufferedraw-after-record");
                    tls.write_all(b"encrypted-marker").await.unwrap();
                    // No explicit flush; switching must flush the outer record.
                    control.write_direct();
                    tls.write_all(b"raw-write").await.unwrap();
                    tls.flush().await.unwrap();
                    server.await.unwrap();
                    assert_eq!(stats.bytes(), (16, 9));
                })
                .await
                .unwrap();
            }
        }
    }
}
use crate::dispatch::BoxStream;
use std::{
    future::Future,
    io::{self, Read},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub(crate) struct SpliceStats {
    read: AtomicU64,
    written: AtomicU64,
}
impl SpliceStats {
    pub(crate) fn record_read(&self, count: usize) {
        self.read.fetch_add(count as u64, Ordering::Relaxed);
    }
    pub(crate) fn record_written(&self, count: usize) {
        self.written.fetch_add(count as u64, Ordering::Relaxed);
    }
    #[cfg(any(test, feature = "interop-test"))]
    pub(crate) fn bytes(&self) -> (u64, u64) {
        (
            self.read.load(Ordering::Relaxed),
            self.written.load(Ordering::Relaxed),
        )
    }
}
#[derive(Clone, Default)]
pub(crate) struct SpliceControl {
    read: Arc<AtomicBool>,
    write: Arc<AtomicBool>,
}
impl SpliceControl {
    pub(crate) fn reading_direct(&self) -> bool {
        self.read.load(Ordering::Acquire)
    }
    pub(crate) fn writing_direct(&self) -> bool {
        self.write.load(Ordering::Acquire)
    }
    pub(crate) fn read_direct(&self) {
        self.read.store(true, Ordering::Release);
    }
    pub(crate) fn write_direct(&self) {
        self.write.store(true, Ordering::Release);
    }
}

pub(crate) struct RecordIo {
    raw: BoxStream,
    header: [u8; 5],
    header_read: usize,
    body_left: usize,
}
impl RecordIo {
    pub(crate) fn new(raw: BoxStream) -> Self {
        Self {
            raw,
            header: [0; 5],
            header_read: 0,
            body_left: 0,
        }
    }
    fn boundary(&self) -> bool {
        self.header_read == 0 && self.body_left == 0
    }
}
impl AsyncRead for RecordIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let header = this.header_read < 5;
        let count = out.remaining().min(if header {
            5 - this.header_read
        } else {
            this.body_left
        });
        let mut part = ReadBuf::new(&mut out.initialize_unfilled()[..count]);
        ready!(Pin::new(&mut this.raw).poll_read(cx, &mut part))?;
        let bytes = part.filled();
        let length = bytes.len();
        if header {
            this.header[this.header_read..this.header_read + length].copy_from_slice(bytes);
            this.header_read += length;
            if this.header_read == 5 {
                this.body_left = u16::from_be_bytes([this.header[3], this.header[4]]) as usize;
                // TLS ciphertext limit (TLS 1.2 worst case); rustls still owns
                // version/content-type/authentication checks.
                if this.body_left > crate::limits::VISION_TLS_RECORD_BYTES {
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                if this.body_left == 0 {
                    this.header_read = 0;
                }
            }
        } else {
            this.body_left -= length;
            if this.body_left == 0 {
                this.header_read = 0;
            }
        }
        out.advance(length);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for RecordIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

pub(crate) struct SpliceTls {
    tls: tokio_rustls::client::TlsStream<RecordIo>,
    control: SpliceControl,
    stats: Arc<SpliceStats>,
    write_switched: bool,
    closing: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl SpliceTls {
    pub(crate) fn wrap(
        tls: tokio_rustls::client::TlsStream<RecordIo>,
        stats: Arc<SpliceStats>,
    ) -> io::Result<(BoxStream, SpliceControl)> {
        if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Vision requires TLS 1.3",
            ));
        }
        let control = SpliceControl::default();
        Ok((
            Box::new(Self {
                tls,
                control: control.clone(),
                stats,
                write_switched: false,
                closing: None,
            }),
            control,
        ))
    }
    fn prepare_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.write.load(Ordering::Acquire) && !self.write_switched {
            // The marker's final encrypted bytes must precede every raw byte.
            ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
            self.write_switched = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for SpliceTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.control.read.load(Ordering::Acquire) {
            let (io, connection) = this.tls.get_mut();
            // Public reader drains plaintext already present after the marker.
            match connection.reader().read(out.initialize_unfilled()) {
                Ok(n) if n > 0 => {
                    out.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            if !io.boundary() {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            let before = out.filled().len();
            let result = Pin::new(&mut io.raw).poll_read(cx, out);
            this.stats
                .read
                .fetch_add((out.filled().len() - before) as u64, Ordering::Relaxed);
            return result;
        }
        // AsyncRead on tokio-rustls loops across chunks. Use one public
        // AsyncBufRead chunk so the caller can inspect a marker first.
        let mut tls = Pin::new(&mut this.tls);
        let bytes = ready!(tls.as_mut().poll_fill_buf(cx))?;
        let count = bytes.len().min(out.remaining());
        out.put_slice(&bytes[..count]);
        tls.consume(count);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for SpliceTls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing.is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.prepare_write(cx))?;
        if self.write_switched {
            let result = Pin::new(&mut self.tls.get_mut().0.raw).poll_write(cx, buf);
            if let Poll::Ready(Ok(n)) = result {
                self.stats.written.fetch_add(n as u64, Ordering::Relaxed);
            }
            result
        } else {
            Pin::new(&mut self.tls).poll_write(cx, buf)
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.prepare_write(cx))?;
        if self.write_switched {
            Pin::new(&mut self.tls.get_mut().0.raw).poll_flush(cx)
        } else {
            Pin::new(&mut self.tls).poll_flush(cx)
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.prepare_write(cx))?;
        if self.write_switched || self.control.read.load(Ordering::Acquire) {
            if self.closing.is_none() {
                self.closing = Some(Box::pin(tokio::time::sleep(super::CLOSE_NOTIFY_TIMEOUT)));
            }
            if self.closing.as_mut().unwrap().as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
            if !self.write_switched {
                ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
            }
            // Do not inject an outer TLS alert into the direct stream.
            return Pin::new(&mut self.tls.get_mut().0.raw).poll_shutdown(cx);
        }
        if self.closing.is_none() {
            self.tls.get_mut().1.send_close_notify();
            self.closing = Some(Box::pin(tokio::time::sleep(super::CLOSE_NOTIFY_TIMEOUT)));
        }
        if let Poll::Ready(result) = Pin::new(&mut self.tls).poll_flush(cx) {
            return Poll::Ready(result);
        }
        if self.closing.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Poll::Pending
    }
}
