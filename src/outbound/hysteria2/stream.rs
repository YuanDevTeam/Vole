//! Consume the response on the first read without blocking client-first writes.
//! Mihomo can combine the successful response header with the origin's first
//! bytes. Waiting for that header in connect_stream deadlocks request/response IO.
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type Response<R> = Pin<Box<dyn Future<Output = io::Result<R>> + Send>>;

#[derive(Default)]
struct ResponseWakeups {
    reader: futures_util::task::AtomicWaker,
    writer: futures_util::task::AtomicWaker,
}
impl Wake for ResponseWakeups {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.reader.wake();
        self.writer.wake();
    }
}

pub(super) struct TcpStream<R, W> {
    response: Option<Response<R>>,
    reader: Option<R>,
    writer: Option<W>,
    closing: bool,
    wakeups: Arc<ResponseWakeups>,
}

impl<R: AsyncRead + Unpin + Send + 'static, W> TcpStream<R, W> {
    pub fn new(mut reader: R, writer: W) -> Self {
        Self {
            response: Some(Box::pin(async move {
                // Setup has already committed the request. A peer can defer
                // success until origin data arrives, beyond the setup budget.
                super::wire::tcp_response(&mut reader).await?;
                Ok(reader)
            })),
            reader: None,
            writer: Some(writer),
            closing: false,
            wakeups: Arc::default(),
        }
    }
}

impl<R, W> TcpStream<R, W> {
    fn poll_response(&mut self) -> Poll<io::Result<()>> {
        if self.closing || self.writer.is_none() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let Some(response) = self.response.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        // Reads and opportunistic writes poll the same response future. Its
        // underlying reader has one wake slot; fan it out to both callers.
        let waker = Waker::from(self.wakeups.clone());
        match response.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(Ok(reader)) => {
                self.reader = Some(reader);
                self.response = None;
                self.wakeups.reader.wake();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.response = None;
                self.writer = None;
                self.wakeups.wake_by_ref();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for TcpStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.wakeups.reader.register(cx.waker());
        std::task::ready!(self.poll_response())?;
        Pin::new(self.reader.as_mut().unwrap()).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for TcpStream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Consume an available response/failure without blocking client-first
        // upload or imposing a setup deadline on an established stream.
        self.wakeups.writer.register(cx.waker());
        if let Poll::Ready(Err(error)) = self.poll_response() {
            return Poll::Ready(Err(error));
        }
        Pin::new(self.writer.as_mut().unwrap()).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wakeups.writer.register(cx.waker());
        if let Poll::Ready(Err(error)) = self.poll_response() {
            return Poll::Ready(Err(error));
        }
        Pin::new(self.writer.as_mut().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Mihomo cancels QUIC reads and closes its write side on application
        // EOF. This closes the logical stream, never the shared connection.
        self.closing = true;
        self.response.take();
        self.reader.take();
        self.wakeups.wake_by_ref();
        let Some(writer) = self.writer.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = Pin::new(writer).poll_shutdown(cx);
        if result.is_ready() {
            self.writer.take();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn admitted_upload_survives_setup_deadline_before_delayed_response() {
        let (client, mut peer) = tokio::io::duplex(128);
        let (reader, writer) = tokio::io::split(client);
        let stream = TcpStream::new(reader, writer);
        let (mut reader, mut writer) = tokio::io::split(stream);
        let reading = tokio::spawn(async move {
            let mut reply = [0; 5];
            reader.read_exact(&mut reply).await.unwrap();
            reply
        });
        writer.write_all(b"start").await.unwrap();
        let mut request = [0; 5];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"start");
        // A Mihomo peer may defer success until the origin has response data.
        // Established upload must remain writable beyond its setup budget.
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        writer.write_all(b"tail!").await.unwrap();
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"tail!");
        peer.write_all(b"\0\0\0reply").await.unwrap();
        assert_eq!(&reading.await.unwrap(), b"reply");
        writer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_client_first_write_does_not_steal_a_pending_read_wakeup() {
        let (client, mut peer) = tokio::io::duplex(128);
        let (reader, writer) = tokio::io::split(client);
        let stream = TcpStream::new(reader, writer);
        let (mut reader, mut writer) = tokio::io::split(stream);
        let reading = tokio::spawn(async move { reader.read_u8().await });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        writer.write_all(b"q").await.unwrap();
        assert_eq!(peer.read_u8().await.unwrap(), b'q');
        peer.write_all(b"\0\0\0r").await.unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(100), reading)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            b'r'
        );
    }

    #[tokio::test]
    async fn application_eof_closes_both_directions_without_consuming_a_tail() {
        let (client, mut peer) = tokio::io::duplex(128);
        let (reader, writer) = tokio::io::split(client);
        let mut stream = TcpStream::new(reader, writer);
        peer.write_all(b"\0\0\0hello").await.unwrap();
        let mut hello = [0; 5];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        stream.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        // Even without any peer response, upload EOF must wake a pending read.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_wakes_an_already_pending_logical_reader() {
        let (client, mut peer) = tokio::io::duplex(128);
        let (reader, writer) = tokio::io::split(client);
        let mut stream = TcpStream::new(reader, writer);
        peer.write_all(b"\0\0\0a").await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'a');
        let (mut reader, mut writer) = tokio::io::split(stream);
        let reading = tokio::spawn(async move { reader.read_u8().await });
        tokio::task::yield_now().await;
        assert!(!reading.is_finished());
        writer.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), reading)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
}
