//! Exercise the production HTTP/1 encoder over scalar, partially writable IO.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

struct BodyIo {
    inner: tokio::io::DuplexStream,
    body: Bytes,
    original_bytes_written: Arc<AtomicUsize>,
    largest_body_write: Arc<AtomicUsize>,
}

impl AsyncRead for BodyIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for BodyIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, input))?;
        let start = input.as_ptr() as usize;
        let original = self.body.as_ptr() as usize;
        if start >= original && start + written <= original + self.body.len() {
            self.original_bytes_written
                .fetch_add(written, Ordering::Relaxed);
            self.largest_body_write
                .fetch_max(input.len(), Ordering::Relaxed);
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn http1_body_reaches_scalar_io_in_bounded_slices_without_copying() {
    let body = Bytes::from(vec![0xa5; crate::limits::XHTTP_PACKET_BATCH_BYTES]);
    let (client, server) = tokio::io::duplex(1024);
    let original_bytes_written = Arc::<AtomicUsize>::default();
    let largest_body_write = Arc::<AtomicUsize>::default();
    let io = BodyIo {
        inner: client,
        body: body.clone(),
        original_bytes_written: original_bytes_written.clone(),
        largest_body_write: largest_body_write.clone(),
    };
    // Leave vectored IO at its scalar default, as required by TLS wrappers.
    assert!(!io.is_write_vectored());
    let expected = body.clone();
    let peer = tokio::spawn(async move {
        let mut server = tokio::io::BufReader::new(server);
        let mut line = String::new();
        loop {
            line.clear();
            assert!(server.read_line(&mut line).await.unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        // Production packet-up streams use chunked bodies, not Content-Length.
        let mut received = Vec::new();
        loop {
            line.clear();
            assert!(server.read_line(&mut line).await.unwrap() > 0);
            let size = usize::from_str_radix(line.trim_end(), 16).unwrap();
            assert!(received.len() + size <= expected.len());
            let start = received.len();
            received.resize(start + size, 0);
            server.read_exact(&mut received[start..]).await.unwrap();
            let mut delimiter = [0; 2];
            server.read_exact(&mut delimiter).await.unwrap();
            assert_eq!(&delimiter, b"\r\n");
            if size == 0 {
                break;
            }
        }
        assert_eq!(received, expected);
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tokio::io::copy(&mut server, &mut tokio::io::sink())
            .await
            .unwrap();
    });
    let owner = DriverOwner::default();
    let (sender, connection) = http1(Box::new(io), &owner).await.unwrap();
    let request = Request::post("http://example.com/x").body(()).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        super::super::post_packet(sender, request, body.clone()),
    )
    .await
    .expect("memory HTTP/1 POST stalled")
    .unwrap();
    owner.cancellation.cancel();
    owner.tasks.close();
    owner.tasks.wait().await;
    peer.await.unwrap();
    assert!(owner.tasks.is_empty());
    drop(connection);
    assert_eq!(
        original_bytes_written.load(Ordering::Relaxed),
        body.len(),
        "HTTP/1 copied the payload before reaching the supplied scalar IO"
    );
    assert!(
        largest_body_write.load(Ordering::Relaxed) <= crate::limits::XHTTP_BODY_CHUNK,
        "HTTP/1 presented {} plaintext bytes to one scalar write",
        largest_body_write.load(Ordering::Relaxed),
    );
}
