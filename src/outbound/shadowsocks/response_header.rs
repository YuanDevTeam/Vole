//! Exact first SS2022 response ciphertext prefix for limited stream carriers.
//! Installed only by actual simple-obfs or plain standard WebSocket/non-Gost
//! single-mux factories without early data, independently of HTTP reuse features.
//! This bounded adapter neither decrypts nor authenticates. Bare SS, WSS,
//! non-mux WS, early data, HTTPUpgrade, Gost, JLS and ShadowTLS keep original reads.
use shadowsocks::crypto::CipherKind;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_RESPONSE_PREFIX: usize = 91;
pub(super) struct HeaderIo<S> {
    inner: S,
    prefix: [u8; MAX_RESPONSE_PREFIX],
    target: usize,
    filled: usize,
    emitted: usize,
    eof: bool,
    truncated: bool,
}
impl<S> HeaderIo<S> {
    pub(super) fn new(inner: S, method: CipherKind) -> io::Result<Self> {
        if !method.is_aead_2022() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Official aead_2022::poll_read_header for StreamType::Client:
        // salt + type + timestamp + request salt + length + authentication tag.
        let salt = method.salt_len();
        let target = salt
            .checked_mul(2)
            .and_then(|n| n.checked_add(1 + 8 + 2))
            .and_then(|n| n.checked_add(method.tag_len()))
            .filter(|n| *n != 0 && *n <= MAX_RESPONSE_PREFIX)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(Self {
            inner,
            prefix: [0; MAX_RESPONSE_PREFIX],
            target,
            filled: 0,
            emitted: 0,
            eof: false,
            truncated: false,
        })
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for HeaderIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        if this.truncated {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        if this.emitted == this.target {
            return Pin::new(&mut this.inner).poll_read(cx, out);
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if this.filled == this.target {
                break;
            }
            // The slice is exactly the missing prefix, so no ciphertext body
            // byte is over-read. Progress survives a real inner Pending.
            let amount = {
                let mut read = ReadBuf::new(&mut this.prefix[this.filled..this.target]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                read.filled().len()
            };
            if amount == 0 {
                if this.filled == 0 {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.truncated = true;
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.filled += amount;
        }
        if this.filled != this.target {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let amount = (this.target - this.emitted).min(out.remaining());
        out.put_slice(&this.prefix[this.emitted..this.emitted + amount]);
        this.emitted += amount;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for HeaderIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::task::noop_waker_ref;
    struct Source {
        bytes: Vec<u8>,
        position: usize,
        chunk: usize,
        pending_each: bool,
        pending: bool,
        reads: Vec<(usize, usize)>,
        writes: usize,
        flushes: usize,
        shutdowns: usize,
    }
    impl Source {
        fn new(bytes: Vec<u8>, chunk: usize, pending_each: bool) -> Self {
            Self {
                bytes,
                position: 0,
                chunk,
                pending_each,
                pending: pending_each,
                reads: Vec::new(),
                writes: 0,
                flushes: 0,
                shutdowns: 0,
            }
        }
    }
    impl AsyncRead for Source {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.reads.push((this.position, out.remaining()));
            if this.pending {
                this.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let amount = (this.bytes.len() - this.position)
                .min(this.chunk)
                .min(out.remaining());
            out.put_slice(&this.bytes[this.position..this.position + amount]);
            this.position += amount;
            this.pending = this.pending_each;
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Source {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().writes += 1;
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().flushes += 1;
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().shutdowns += 1;
            Poll::Ready(Ok(()))
        }
    }
    fn methods() -> [(CipherKind, usize); 3] {
        [
            ("2022-blake3-aes-128-gcm".parse().unwrap(), 59),
            ("2022-blake3-aes-256-gcm".parse().unwrap(), 91),
            ("2022-blake3-chacha20-poly1305".parse().unwrap(), 91),
        ]
    }
    #[test]
    fn header_probe_exact_prefix_survives_pending_and_never_reads_a_body_byte() {
        for (method, expected) in methods() {
            let mut bytes = vec![0x51; expected];
            bytes.push(0x52);
            let mut io = HeaderIo::new(Source::new(bytes, 7, true), method).unwrap();
            assert_eq!(io.target, expected);
            let mut output = [0; MAX_RESPONSE_PREFIX];
            let mut cx = Context::from_waker(noop_waker_ref());
            let mut complete = false;
            for _ in 0..(MAX_RESPONSE_PREFIX * 2) {
                let mut read = ReadBuf::new(&mut output);
                match Pin::new(&mut io).poll_read(&mut cx, &mut read) {
                    Poll::Pending => assert!(read.filled().is_empty()),
                    Poll::Ready(Ok(())) => {
                        assert_eq!(read.filled(), &vec![0x51; expected]);
                        complete = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => panic!("synthetic prefix kind={:?}", error.kind()),
                }
            }
            assert!(complete);
            assert_eq!(io.inner.position, expected);
            assert!(
                io.inner
                    .reads
                    .iter()
                    .all(|(position, limit)| position + limit == expected)
            );
            let mut last = [0];
            let mut body_complete = false;
            for _ in 0..(MAX_RESPONSE_PREFIX * 2) {
                let mut read = ReadBuf::new(&mut last);
                match Pin::new(&mut io).poll_read(&mut cx, &mut read) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(())) => {
                        assert_eq!(read.filled(), &[0x52]);
                        body_complete = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => panic!("synthetic body kind={:?}", error.kind()),
                }
            }
            assert!(body_complete);
        }
    }
    #[test]
    fn header_probe_clean_and_partial_eof_are_distinct_and_writes_stay_direct() {
        for (method, expected) in methods() {
            for amount in [0, expected - 1] {
                let mut io =
                    HeaderIo::new(Source::new(vec![0x53; amount], 7, true), method).unwrap();
                let mut cx = Context::from_waker(noop_waker_ref());
                let mut output = [0; MAX_RESPONSE_PREFIX];
                let mut completed = false;
                for _ in 0..(MAX_RESPONSE_PREFIX * 2) {
                    let mut read = ReadBuf::new(&mut output);
                    match Pin::new(&mut io).poll_read(&mut cx, &mut read) {
                        Poll::Pending => {}
                        Poll::Ready(result) => {
                            assert_eq!(
                                result.err().map(|e| e.kind()),
                                (amount != 0).then_some(io::ErrorKind::UnexpectedEof)
                            );
                            assert!(read.filled().is_empty());
                            completed = true;
                            break;
                        }
                    }
                }
                assert!(completed);
                let reads = io.inner.reads.len();
                let _ = Pin::new(&mut io).poll_read(&mut cx, &mut ReadBuf::new(&mut output));
                assert_eq!(io.inner.reads.len(), reads);
            }
            let mut io = HeaderIo::new(Source::new(vec![0x54; expected], 1, true), method).unwrap();
            let mut cx = Context::from_waker(noop_waker_ref());
            assert!(
                Pin::new(&mut io)
                    .poll_read(&mut cx, &mut ReadBuf::new(&mut [0; MAX_RESPONSE_PREFIX]))
                    .is_pending()
            );
            assert!(matches!(
                Pin::new(&mut io).poll_write(&mut cx, &[0x55]),
                Poll::Ready(Ok(1))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(matches!(
                Pin::new(&mut io).poll_shutdown(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(
                (io.inner.writes, io.inner.flushes, io.inner.shutdowns),
                (1, 1, 1)
            );
        }
    }
    #[test]
    fn header_probe_each_poll_obeys_the_existing_io_budget() {
        for (method, expected) in methods() {
            let mut io =
                HeaderIo::new(Source::new(vec![0x56; expected], 1, false), method).unwrap();
            let mut cx = Context::from_waker(noop_waker_ref());
            let mut output = [0; MAX_RESPONSE_PREFIX];
            let mut completed = false;
            for _ in 0..MAX_RESPONSE_PREFIX {
                let before = io.inner.reads.len();
                let mut read = ReadBuf::new(&mut output);
                let result = Pin::new(&mut io).poll_read(&mut cx, &mut read);
                assert!(io.inner.reads.len() - before <= crate::limits::IO_POLL_BUDGET);
                match result {
                    Poll::Pending => assert!(read.filled().is_empty()),
                    Poll::Ready(Ok(())) => {
                        assert_eq!(read.filled().len(), expected);
                        completed = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => panic!("synthetic budget kind={:?}", error.kind()),
                }
            }
            assert!(completed);
        }
    }
}
