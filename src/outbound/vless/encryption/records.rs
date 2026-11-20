use super::cache::{Cache, Ticket};
use super::crypto::{Aead, Ctr, Suite, failure};
use super::header_xor::HeaderXor;
use crate::dispatch::BoxStream;
use crate::security::vision::{SpliceControl, SpliceStats};
use futures_util::task::AtomicWaker;
use std::sync::Arc;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, Wake, Waker, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

pub(super) struct Records {
    raw: Option<BoxStream>,
    key: Zeroizing<[u8; 96]>,
    suite: Suite,
    tx: Aead,
    rx: Option<Aead>,
    tx_ctr: Option<Ctr>,
    rx_ctr: Option<Ctr>,
    pending: Vec<u8>,
    sent: usize,
    prefix_pending: bool,
    io_wake: Arc<IoWake>,
    input: Vec<u8>,
    filled: usize,
    reading: Reading,
    plain: Zeroizing<Vec<u8>>,
    consumed: usize,
    write_closed: bool,
    cache: Arc<Cache>,
    ticket: Option<Arc<Ticket>>,
    random_headers: bool,
    vision: Option<(SpliceControl, Arc<SpliceStats>)>,
    direct_write: bool,
    pending_direct: bool,
    direct_tx: HeaderXor,
    direct_rx: HeaderXor,
}

// Raw IO and its cancellation guard can share one latest-waker slot. Keep
// both Records owners behind the same stable waker for every raw operation.
struct IoWake {
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl IoWake {
    fn new() -> Self {
        Self {
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
        }
    }

    fn wake_all(&self) {
        self.reader.wake();
        self.writer.wake();
    }
}

impl Wake for IoWake {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

enum DrainSide {
    Read,
    Write,
}

enum Reading {
    Random,
    Padding,
    Header,
    Body([u8; 5]),
    Eof,
}

impl Records {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        raw: BoxStream,
        key: Zeroizing<[u8; 96]>,
        suite: Suite,
        tx: Aead,
        rx: Aead,
        tx_ctr: Option<Ctr>,
        rx_ctr: Option<Ctr>,
        padding: usize,
        cache: Arc<Cache>,
        ticket: Option<Arc<Ticket>>,
    ) -> Self {
        Self {
            raw: Some(raw),
            key,
            suite,
            tx,
            rx: Some(rx),
            tx_ctr,
            rx_ctr,
            pending: Vec::new(),
            sent: 0,
            prefix_pending: false,
            io_wake: Arc::new(IoWake::new()),
            input: vec![0; padding],
            filled: 0,
            reading: Reading::Padding,
            plain: Zeroizing::new(Vec::new()),
            consumed: 0,
            write_closed: false,
            cache,
            ticket,
            random_headers: false,
            vision: None,
            direct_write: false,
            pending_direct: false,
            direct_tx: HeaderXor::default(),
            direct_rx: HeaderXor::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resumed(
        raw: BoxStream,
        key: Zeroizing<[u8; 96]>,
        suite: Suite,
        tx: Aead,
        tx_ctr: Option<Ctr>,
        random_headers: bool,
        prefix: Vec<u8>,
        cache: Arc<Cache>,
        ticket: Arc<Ticket>,
    ) -> Self {
        let prefix_pending = !prefix.is_empty();
        Self {
            raw: Some(raw),
            key,
            suite,
            tx,
            rx: None,
            tx_ctr,
            rx_ctr: None,
            pending: prefix,
            sent: 0,
            prefix_pending,
            io_wake: Arc::new(IoWake::new()),
            input: vec![0; 16],
            filled: 0,
            reading: Reading::Random,
            plain: Zeroizing::new(Vec::new()),
            consumed: 0,
            write_closed: false,
            cache,
            ticket: Some(ticket),
            random_headers,
            vision: None,
            direct_write: false,
            pending_direct: false,
            direct_tx: HeaderXor::default(),
            direct_rx: HeaderXor::default(),
        }
    }

    pub(super) fn with_vision(mut self, vision: Option<(SpliceControl, Arc<SpliceStats>)>) -> Self {
        self.vision = vision;
        self
    }

    fn open(&self) -> io::Result<()> {
        if self.cache.cancellation.is_cancelled() {
            return Err(super::cache::closed());
        }
        if self.raw.is_none() {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "VLESS Encryption stream closed",
            ))
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        if let Some(ticket) = self.ticket.take() {
            self.cache.invalidate(&ticket);
        }
        self.raw.take();
        self.key.zeroize();
        self.plain.zeroize();
        self.pending.clear();
        self.prefix_pending = false;
        self.input.clear();
        self.io_wake.wake_all();
        error
    }

    fn drain(&mut self, side: DrainSide) -> Poll<io::Result<()>> {
        if let Err(error) = self.open() {
            return Poll::Ready(Err(self.fail(error)));
        }
        let had_pending = self.sent < self.pending.len();
        let waker = Waker::from(self.io_wake.clone());
        let mut io_cx = Context::from_waker(&waker);
        while self.sent < self.pending.len() {
            let result = ready!(
                Pin::new(self.raw.as_mut().unwrap())
                    .poll_write(&mut io_cx, &self.pending[self.sent..])
            );
            let count = match result {
                Ok(0) => {
                    return Poll::Ready(Err(self.fail(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VLESS Encryption transport closed",
                    ))));
                }
                Ok(count) => count,
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            };
            self.sent += count;
            if self.pending_direct {
                self.vision.as_ref().unwrap().1.record_written(count);
            }
        }
        self.pending.clear();
        self.sent = 0;
        self.prefix_pending = false;
        if had_pending {
            // Another owner can be parked on the exact frame just completed.
            match side {
                DrainSide::Read => self.io_wake.writer.wake(),
                DrainSide::Write => self.io_wake.reader.wake(),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn receive(&mut self, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.open()?;
        self.io_wake.reader.register(cx.waker());
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.drain(DrainSide::Read) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending if self.prefix_pending => return Poll::Pending,
            Poll::Pending | Poll::Ready(Ok(())) => {}
        }
        let waker = Waker::from(self.io_wake.clone());
        let mut io_cx = Context::from_waker(&waker);
        loop {
            if self.consumed < self.plain.len() {
                let count = output.remaining().min(self.plain.len() - self.consumed);
                output.put_slice(&self.plain[self.consumed..self.consumed + count]);
                self.consumed += count;
                return Poll::Ready(Ok(()));
            }
            self.plain.zeroize();
            self.plain.clear();
            self.consumed = 0;
            if let Some((control, stats)) = &self.vision
                && control.reading_direct()
            {
                if !matches!(self.reading, Reading::Header) || self.filled != 0 {
                    return Poll::Ready(Err(failure()));
                }
                let before = output.filled().len();
                ready!(Pin::new(self.raw.as_mut().unwrap()).poll_read(&mut io_cx, output))?;
                if let Some(ctr) = &mut self.rx_ctr {
                    self.direct_rx
                        .apply(ctr, &mut output.filled_mut()[before..], true)?;
                }
                stats.record_read(output.filled().len() - before);
                return Poll::Ready(Ok(()));
            }
            if matches!(self.reading, Reading::Eof) {
                return Poll::Ready(Ok(()));
            }
            while self.filled < self.input.len() {
                let mut buf = ReadBuf::new(&mut self.input[self.filled..]);
                ready!(Pin::new(self.raw.as_mut().unwrap()).poll_read(&mut io_cx, &mut buf))?;
                let count = buf.filled().len();
                if count == 0 {
                    if self.filled == 0 && matches!(self.reading, Reading::Header) {
                        self.reading = Reading::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated VLESS Encryption record",
                    )));
                }
                self.filled += count;
            }
            match self.reading {
                Reading::Random => {
                    self.rx = Some(Aead::new(&self.input, self.key.as_ref(), self.suite)?);
                    if self.random_headers {
                        self.rx_ctr = Some(Ctr::new(
                            self.key.as_ref(),
                            self.input.as_slice().try_into().map_err(|_| failure())?,
                        )?);
                    }
                    self.reading = Reading::Header;
                    self.input.resize(5, 0);
                }
                Reading::Padding => {
                    let _padding =
                        Zeroizing::new(self.rx.as_mut().unwrap().open(&self.input, &[], None)?);
                    self.reading = Reading::Header;
                    self.input.resize(5, 0);
                }
                Reading::Header => {
                    if let Some(ctr) = self.rx_ctr.as_mut() {
                        ctr.apply(&mut self.input)?;
                    }
                    let header: [u8; 5] =
                        self.input.as_slice().try_into().map_err(|_| failure())?;
                    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                    if header[..3] != [23, 3, 3] || !(17..=17000).contains(&length) {
                        return Poll::Ready(Err(failure()));
                    }
                    self.reading = Reading::Body(header);
                    self.input.resize(length, 0);
                }
                Reading::Body(header) => {
                    let rx = self.rx.as_mut().unwrap();
                    let rekey = rx.exhausted();
                    self.plain = Zeroizing::new(rx.open(&self.input, &header, None)?);
                    if rekey {
                        let mut context = header.to_vec();
                        context.extend_from_slice(&self.input);
                        self.rx = Some(Aead::new(&context, self.key.as_ref(), self.suite)?);
                    }
                    self.ticket.take();
                    self.reading = Reading::Header;
                    self.input.resize(5, 0);
                }
                Reading::Eof => unreachable!(),
            }
            self.filled = 0;
        }
    }
}

impl AsyncRead for Records {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = match self.receive(cx, output) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
            result => result,
        };
        if result.is_ready() {
            drop(self.io_wake.reader.take());
        }
        result
    }
}

impl AsyncWrite for Records {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io_wake.writer.register(cx.waker());
        let waker = Waker::from(self.io_wake.clone());
        let mut io_cx = Context::from_waker(&waker);
        let result = (|| {
            ready!(self.drain(DrainSide::Write))?;
            if self.write_closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "VLESS Encryption write side closed",
                )));
            }
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let count = input.len().min(8192);
            if self
                .vision
                .as_ref()
                .is_some_and(|(control, _)| control.writing_direct())
            {
                if !self.direct_write {
                    let result =
                        ready!(Pin::new(self.raw.as_mut().unwrap()).poll_flush(&mut io_cx));
                    if let Err(error) = result {
                        return Poll::Ready(Err(self.fail(error)));
                    }
                    self.direct_write = true;
                }
                self.pending.extend_from_slice(&input[..count]);
                let this = &mut *self;
                if let Some(ctr) = &mut this.tx_ctr
                    && let Err(error) = this.direct_tx.apply(ctr, &mut this.pending, false)
                {
                    return Poll::Ready(Err(this.fail(error)));
                }
                self.pending_direct = true;
                return Poll::Ready(Ok(count));
            }
            let length = (count + 16) as u16;
            let mut header = [23, 3, 3, (length >> 8) as u8, length as u8];
            let rekey = self.tx.exhausted();
            let result = (|| {
                let sealed = self.tx.seal(&input[..count], &header, None)?;
                if rekey {
                    let mut context = header.to_vec();
                    context.extend_from_slice(&sealed);
                    self.tx = Aead::new(&context, self.key.as_ref(), self.suite)?;
                }
                if let Some(ctr) = self.tx_ctr.as_mut() {
                    ctr.apply(&mut header)?;
                }
                self.pending.extend_from_slice(&header);
                self.pending.extend_from_slice(&sealed);
                Ok(count)
            })();
            Poll::Ready(result.map_err(|error| self.fail(error)))
        })();
        if result.is_ready() {
            drop(self.io_wake.writer.take());
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io_wake.writer.register(cx.waker());
        let waker = Waker::from(self.io_wake.clone());
        let mut io_cx = Context::from_waker(&waker);
        let result = (|| {
            ready!(self.drain(DrainSide::Write))?;
            match Pin::new(self.raw.as_mut().unwrap()).poll_flush(&mut io_cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
                result => result,
            }
        })();
        if result.is_ready() {
            drop(self.io_wake.writer.take());
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io_wake.writer.register(cx.waker());
        let waker = Waker::from(self.io_wake.clone());
        let mut io_cx = Context::from_waker(&waker);
        let result = (|| {
            if self.write_closed {
                return Poll::Ready(Ok(()));
            }
            ready!(self.drain(DrainSide::Write))?;
            if self.tx_ctr.is_none()
                && self.vision.as_ref().is_some_and(|(control, _)| {
                    control.writing_direct() || control.reading_direct()
                })
            {
                // Vision exposes the underlying transport after direct switching.
                // Native/xorpub therefore inherit its CloseWrite (TCP FIN or TLS
                // close_notify). Random's XorConn is not replaceable in Mihomo and
                // still has whole-connection close semantics.
                return match Pin::new(self.raw.as_mut().unwrap()).poll_shutdown(&mut io_cx) {
                    Poll::Ready(Ok(())) => {
                        self.write_closed = true;
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
                    result => result,
                };
            }
            // Mihomo CommonConn does not expose CloseWrite/replaceable upstream.
            // Flush pending records then release this whole logical transport.
            // A normal close must not invalidate a reusable node-local ticket.
            match Pin::new(self.raw.as_mut().unwrap()).poll_flush(&mut io_cx) {
                Poll::Ready(Ok(())) => {
                    self.write_closed = true;
                    self.raw.take();
                    self.key.zeroize();
                    self.plain.zeroize();
                    self.io_wake.wake_all();
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
                result => result,
            }
        })();
        if result.is_ready() {
            drop(self.io_wake.writer.take());
        }
        result
    }
}

impl Drop for Records {
    fn drop(&mut self) {
        // Raw transports can retain the fanout waker after their last poll.
        // Release task references even when an owner cancels without repolling.
        self.io_wake.wake_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct Fragmented {
        input: Vec<u8>,
        read: usize,
        output: Arc<Mutex<Vec<u8>>>,
        pending: bool,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for Fragmented {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
    impl Fragmented {
        fn yield_once(&mut self, cx: &mut Context<'_>) -> bool {
            self.pending = !self.pending;
            if self.pending {
                cx.waker().wake_by_ref();
            }
            self.pending
        }
    }
    impl AsyncRead for Fragmented {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.yield_once(cx) {
                return Poll::Pending;
            }
            if self.read < self.input.len() && b.remaining() != 0 {
                b.put_slice(&self.input[self.read..self.read + 1]);
                self.read += 1;
            }
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Fragmented {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.yield_once(cx) {
                return Poll::Pending;
            }
            let count = b.len().min(1);
            self.output.lock().unwrap().extend_from_slice(&b[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        v.as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../tests/protocols/encryption-crypto.json"
        ))
        .unwrap()
    }
    fn wire(v: &serde_json::Value) -> Vec<u8> {
        [bytes(&v["aad"]), bytes(&v["ciphertext"])].concat()
    }
    fn fixture(
        v: &serde_json::Value,
        input: Vec<u8>,
        output: Arc<Mutex<Vec<u8>>>,
        dropped: Arc<AtomicBool>,
    ) -> Records {
        let key: [u8; 96] = bytes(&v["key"]).try_into().unwrap();
        let suite = if v["cipher"] == "aes256gcm" {
            Suite::Aes
        } else {
            Suite::ChaCha
        };
        Records::resumed(
            Box::new(Fragmented {
                input,
                read: 0,
                output,
                pending: false,
                dropped,
            }),
            Zeroizing::new(key),
            suite,
            Aead::new(&bytes(&v["context"]), &key, suite).unwrap(),
            None,
            false,
            Vec::new(),
            Arc::new(Cache::default()),
            Arc::new(Ticket {
                pfs: Zeroizing::new([0; 64]),
                bytes: Zeroizing::new([0; 16]),
                expires: tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            }),
        )
    }

    #[tokio::test]
    async fn nonce_wrap_rekeys_both_directions_using_independent_go_records() {
        for v in vectors()["wrap_records"].as_array().unwrap() {
            let output = Arc::new(Mutex::new(Vec::new()));
            let mut stream = fixture(v, bytes(&v["wire"]), output.clone(), Arc::default());
            let suite = if v["cipher"] == "aes256gcm" {
                Suite::Aes
            } else {
                Suite::ChaCha
            };
            let mut rx = Aead::new(&bytes(&v["context"]), &bytes(&v["key"]), suite).unwrap();
            let mut nonce = [255; 12];
            nonce[11] = 254;
            rx.set_test_nonce(nonce);
            stream.tx.set_test_nonce(nonce);
            stream.rx = Some(rx);
            stream.reading = Reading::Header;
            stream.input = vec![0; 5];
            let plain = bytes(&v["plaintext"]);
            for record in plain.chunks(37) {
                stream.write_all(record).await.unwrap();
            }
            stream.flush().await.unwrap();
            assert_eq!(*output.lock().unwrap(), bytes(&v["wire"]));
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, plain);
        }
    }

    #[tokio::test]
    async fn vision_preserves_authenticated_buffer_then_switches_without_prefetching() {
        for v in vectors()["records"].as_array().unwrap().iter().step_by(3) {
            let payload = bytes(&v["plaintext"]);
            let tail = b"independent-direct-tail";
            let input = [bytes(&v["context"]), wire(v), tail.to_vec()].concat();
            let output = Arc::new(Mutex::new(Vec::new()));
            let stats = Arc::new(SpliceStats::default());
            let control = SpliceControl::default();
            let mut stream = fixture(v, input, output.clone(), Arc::default())
                .with_vision(Some((control.clone(), stats.clone())));
            let mut first = [0; 7];
            stream.read_exact(&mut first).await.unwrap();
            assert_eq!(first, payload[..7]);
            control.read_direct();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, [payload[7..].to_vec(), tail.to_vec()].concat());
            stream.write_all(&payload).await.unwrap();
            control.write_direct();
            stream.write_all(tail).await.unwrap();
            stream.flush().await.unwrap();
            assert_eq!(*output.lock().unwrap(), [wire(v), tail.to_vec()].concat());
            assert_eq!(stats.bytes(), (tail.len() as u64, tail.len() as u64));
        }
    }

    #[test]
    fn random_direct_headers_match_go_with_every_fragment_boundary() {
        let v = vectors();
        let key = bytes(&v["ctr_key"]);
        let iv: [u8; 16] = bytes(&v["ctr_context"]).try_into().unwrap();
        for decrypt in [false, true] {
            let (input, expected) = if decrypt {
                (
                    bytes(&v["headers_ciphertext"]),
                    bytes(&v["headers_plaintext"]),
                )
            } else {
                (
                    bytes(&v["headers_plaintext"]),
                    bytes(&v["headers_ciphertext"]),
                )
            };
            for cut in 0..=input.len() {
                let mut actual = input.clone();
                let mut state = HeaderXor::default();
                let mut ctr = Ctr::new(&key, &iv).unwrap();
                state.apply(&mut ctr, &mut actual[..cut], decrypt).unwrap();
                for byte in &mut actual[cut..] {
                    state
                        .apply(&mut ctr, std::slice::from_mut(byte), decrypt)
                        .unwrap();
                }
                assert_eq!(actual, expected);
            }
        }
    }

    #[tokio::test]
    async fn close_preserves_read_direction_only_for_replaceable_vision_transport() {
        let vectors = vectors();
        let v = &vectors["records"][0];
        for direct in [0, 1, 2] {
            for random in [false, true] {
                let dropped = Arc::new(AtomicBool::new(false));
                let control = SpliceControl::default();
                let mut stream = fixture(v, b"tail".to_vec(), Arc::default(), dropped.clone())
                    .with_vision(Some((control.clone(), Arc::default())));
                stream.reading = Reading::Header;
                stream.input = vec![0; 5];
                if random {
                    stream.tx_ctr = Some(Ctr::new(&[1; 96], &[2; 16]).unwrap());
                }
                if direct == 1 {
                    control.write_direct();
                } else if direct == 2 {
                    control.read_direct();
                }
                stream.shutdown().await.unwrap();
                stream.shutdown().await.unwrap();
                let retain = direct != 0 && !random;
                assert_eq!(!dropped.load(Ordering::SeqCst), retain);
                if retain {
                    control.read_direct();
                    let mut tail = Vec::new();
                    stream.read_to_end(&mut tail).await.unwrap();
                    assert_eq!(tail, b"tail");
                }
                assert!(stream.write_all(b"forbidden").await.is_err());
                drop(stream);
                assert!(dropped.load(Ordering::SeqCst));
            }
        }
    }

    #[tokio::test]
    async fn fragmented_io_and_cancelled_reads_preserve_independent_go_records() {
        for records in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
            let v = &records[0];
            let expected = [wire(v), wire(&records[1])].concat();
            let input = [bytes(&v["context"]), expected.clone()].concat();
            let output = Arc::new(Mutex::new(Vec::new()));
            let mut stream = fixture(v, input, output.clone(), Arc::default());
            let payload = bytes(&v["plaintext"]);
            for _ in 0..2 {
                stream.write_all(&payload).await.unwrap();
            }
            stream.flush().await.unwrap();
            assert_eq!(
                *output.lock().unwrap(),
                expected,
                "partial writes must not reseal or reuse a nonce"
            );
            let mut buffer = [0; 1];
            let mut cx = Context::from_waker(std::task::Waker::noop());
            for _ in 0..23 {
                let mut read = ReadBuf::new(&mut buffer);
                assert!(
                    Pin::new(&mut stream)
                        .poll_read(&mut cx, &mut read)
                        .is_pending()
                );
                assert!(
                    read.filled().is_empty(),
                    "unauthenticated fragments must stay private"
                );
            }
            let mut actual = Vec::new();
            stream.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, payload.repeat(2));
        }
    }

    #[tokio::test]
    async fn corrupt_truncated_or_replayed_records_fail_closed_without_plaintext() {
        for records in vectors()["records"].as_array().unwrap().as_chunks::<3>().0 {
            let v = &records[0];
            let good = wire(v);
            let variants = [
                {
                    let mut data = good.clone();
                    data[0] = 22;
                    data
                },
                {
                    let mut data = good.clone();
                    data[3..5].copy_from_slice(&17001u16.to_be_bytes());
                    data
                },
                {
                    let mut data = good.clone();
                    *data.last_mut().unwrap() ^= 1;
                    data
                },
                good[..4].to_vec(),
                good[..good.len() - 1].to_vec(),
                wire(&records[1]),
            ];
            for bad in variants {
                let dropped = Arc::new(AtomicBool::new(false));
                let mut stream = fixture(
                    v,
                    [bytes(&v["context"]), bad].concat(),
                    Arc::default(),
                    dropped.clone(),
                );
                let mut actual = Vec::new();
                assert!(stream.read_to_end(&mut actual).await.is_err());
                assert!(actual.is_empty());
                assert!(dropped.load(Ordering::SeqCst));
                assert!(stream.write_all(b"must not escape").await.is_err());
            }
            let mut stream = fixture(
                v,
                [bytes(&v["context"]), good.clone(), good].concat(),
                Arc::default(),
                Arc::default(),
            );
            let mut actual = Vec::new();
            assert!(stream.read_to_end(&mut actual).await.is_err());
            assert_eq!(
                actual,
                bytes(&v["plaintext"]),
                "only the first authenticated record is delivered"
            );
        }
    }

    include!("records_duplex_memory_tests.rs");

    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl AsyncRead for DropProbe {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            panic!("stopped node must not read IO");
        }
    }
    impl AsyncWrite for DropProbe {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            panic!("stopped node must not write IO");
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("stopped node must not flush IO");
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("stopped node must not shutdown IO");
        }
    }

    #[tokio::test]
    async fn stopped_node_fails_writes_and_releases_owned_io_immediately() {
        let dropped = Arc::new(AtomicBool::new(false));
        let cache = Arc::new(Cache::default());
        let key = Zeroizing::new([0; 96]);
        let mut stream = Records::new(
            Box::new(DropProbe(dropped.clone())),
            key,
            Suite::Aes,
            Aead::new(&[0; 16], &[0; 96], Suite::Aes).unwrap(),
            Aead::new(&[0; 16], &[0; 96], Suite::Aes).unwrap(),
            None,
            None,
            17,
            cache.clone(),
            None,
        );
        cache.close();
        assert_eq!(
            stream.write(b"business").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "Stop error must release the underlying IO before returning"
        );
    }
}
