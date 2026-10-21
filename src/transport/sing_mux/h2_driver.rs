//! Caller-owned h2mux with Mihomo's 30-second read-idle PING policy.
use super::*;
use crate::transport::h2_write::{Sender, Writes};
use std::time::Duration;

pub(super) async fn new(raw: BoxStream) -> io::Result<(Sender, impl Future<Output = ()> + Send)> {
    let last_read = Arc::new(Mutex::new(Instant::now()));
    let (raw, writes) = Writes::wrap(raw);
    let (sender, mut connection) = h2::client::Builder::new()
        .enable_push(false)
        .initial_window_size(65536)
        // Leave bounded connection credit for other streams when a few TCP
        // consumers hold their individual receive windows.
        .initial_connection_window_size(524288)
        .max_frame_size(16384)
        .max_header_list_size(16384)
        .max_concurrent_streams(0)
        .max_send_buffer_size(16384)
        .handshake(ActivityIo {
            raw: Box::new(raw),
            last_read: last_read.clone(),
        })
        .await
        .map_err(|_| io::ErrorKind::ConnectionAborted)?;
    let mut ping = connection.ping_pong().expect("single sing-mux PING owner");
    Ok((
        Sender {
            request: sender,
            writes,
        },
        async move {
            let interval = Duration::from_secs(30);
            loop {
                let at = *last_read.lock().unwrap() + interval;
                tokio::select! {
                    _ = &mut connection => break,
                    () = tokio::time::sleep_until(at) => {
                        if Instant::now() < *last_read.lock().unwrap() + interval {continue;}
                        tokio::select! {
                            _ = &mut connection => break,
                            result = tokio::time::timeout(Duration::from_secs(15), ping.ping(h2::Ping::opaque())) => {
                                if !matches!(result, Ok(Ok(_))) {break;}
                            }
                        }
                    }
                }
            }
        },
    ))
}

struct ActivityIo {
    raw: BoxStream,
    last_read: Arc<Mutex<Instant>>,
}
impl AsyncRead for ActivityIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        let result = Pin::new(&mut self.raw).poll_read(cx, out);
        if out.filled().len() > before {
            *self.last_read.lock().unwrap() = Instant::now();
        }
        result
    }
}
impl AsyncWrite for ActivityIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}
