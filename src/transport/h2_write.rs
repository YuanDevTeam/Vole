//! Per-write completion at the supplied IO's flush boundary, not H1/H2 enqueue.
//! Each logical writer keeps at most one outstanding payload/receipt. No extra
//! driver, protocol decoder, socket, or connection-wide admission limit.
use crate::dispatch::BoxStream;
use bytes::{Buf, Bytes};
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

#[derive(Default, Debug)]
struct State {
    closed: bool,
    encoded: Vec<Completion>,
}

impl Writes {
    pub fn wrap(raw: BoxStream) -> (impl AsyncRead + AsyncWrite + Unpin + Send, Self) {
        let writes = Self::default();
        (
            FlushIo {
                raw,
                writes: writes.clone(),
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
                done: Some(done),
                writes: self.clone(),
            },
            receipt,
        )
    }
}

pub(super) struct Payload {
    bytes: Bytes,
    done: Option<Completion>,
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
            let mut state = self.writes.0.lock().unwrap();
            if !state.closed {
                // Encoding may only have copied into h2's own buffer. The IO
                // wrapper acknowledges this after that buffer reaches raw.flush.
                state.encoded.push(done);
            }
        }
    }
}

struct FlushIo {
    raw: BoxStream,
    writes: Writes,
}

impl Drop for FlushIo {
    fn drop(&mut self) {
        let mut state = self.writes.0.lock().unwrap();
        state.closed = true;
        state.encoded.clear();
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
        Pin::new(&mut self.raw).poll_write(cx, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = std::task::ready!(Pin::new(&mut self.raw).poll_flush(cx));
        let encoded = std::mem::take(&mut self.writes.0.lock().unwrap().encoded);
        for done in encoded {
            let _ = done.send(
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| io::Error::from(e.kind())),
            );
        }
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
}
