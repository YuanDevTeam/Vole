//! Complete VMess HTTP-cover ownership; keep independent caller wake slots.
use crate::{dispatch::BoxStream, outbound::owned_stream::OwnedStream};
use futures_util::task::AtomicWaker;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

// The stable proxy is the only wake stored by the existing inner cancellation
// future and IO. It does not own the stream, cancellation token or a task.
struct Callers {
    reader: AtomicWaker,
    writer: AtomicWaker,
}
impl Callers {
    fn wake_all(&self) {
        self.reader.wake();
        self.writer.wake();
    }
}
impl Wake for Callers {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

pub(super) struct HttpCoverReuseOwner {
    inner: OwnedStream,
    callers: Arc<Callers>,
}
impl HttpCoverReuseOwner {
    pub(super) fn new(stream: BoxStream, child: CancellationToken) -> Self {
        Self {
            inner: OwnedStream::new(stream, child),
            callers: Arc::new(Callers {
                reader: AtomicWaker::new(),
                writer: AtomicWaker::new(),
            }),
        }
    }
    fn poll_io<T>(
        &mut self,
        cx: &mut Context<'_>,
        reading: bool,
        operation: impl FnOnce(Pin<&mut OwnedStream>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let slot = if reading {
            &self.callers.reader
        } else {
            &self.callers.writer
        };
        slot.register(cx.waker());
        let proxy = Waker::from(self.callers.clone());
        let result = operation(Pin::new(&mut self.inner), &mut Context::from_waker(&proxy));
        if result.is_ready() {
            drop(slot.take());
        }
        result
    }
}
impl AsyncRead for HttpCoverReuseOwner {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_io(cx, true, |mut inner, proxy| {
            match inner.as_mut().poll_read(proxy, out) {
                ready @ Poll::Ready(_) => ready,
                Poll::Pending => {
                    // A partial HTTP upload can wait for its response after
                    // VMess accepted the last small frame into its output.
                    // Drive that acknowledged output without holding ready RX
                    // behind a blocked writer or replacing its caller slot.
                    match inner.poll_flush(proxy) {
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) | Poll::Pending => Poll::Pending,
                    }
                }
            }
        })
    }
}
impl AsyncWrite for HttpCoverReuseOwner {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = this.poll_io(cx, false, |inner, proxy| inner.poll_write(proxy, bytes));
        if matches!(&result, Poll::Ready(Ok(amount)) if *amount > 0) {
            // The response reader may already be parked while a partial
            // upload accepts its final small frame and waits for more input.
            // Let that reader drive the acknowledged output on its next poll.
            this.callers.reader.wake();
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |inner, proxy| inner.poll_flush(proxy))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |inner, proxy| inner.poll_shutdown(proxy))
    }
}
impl Drop for HttpCoverReuseOwner {
    fn drop(&mut self) {
        self.callers.wake_all();
    }
}
