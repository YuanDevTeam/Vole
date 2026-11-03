//! HTTP/2 idle PING ownership over an already protected byte stream.
use super::{BoxStream, ConnectionGuard, DriverOwner, SendRequest, io_other};
use crate::transport::h2_write::{Sender, Writes};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

pub(super) async fn connect(
    raw: BoxStream,
    send_buffer: usize,
    period: i32,
    owner: &DriverOwner,
    private_active_h2: bool,
) -> io::Result<(SendRequest, Arc<ConnectionGuard>)> {
    let last_read = Arc::new(Mutex::new(Instant::now()));
    let (raw, writes) = Writes::wrap(raw);
    let mut builder = h2::client::Builder::new();
    builder
        .max_header_list_size(super::MAX_H2_HEADER_LIST_SIZE)
        .max_send_buffer_size(send_buffer)
        .enable_push(false);
    if private_active_h2 {
        // Until the first peer SETTINGS is processed, do not borrow four
        // logical streams against an unknown remote concurrency limit.
        builder.initial_max_send_streams(1);
    }
    let (sender, mut connection) = builder
        .handshake(ActivityIo {
            raw: Box::new(raw),
            last_read: last_read.clone(),
        })
        .await
        .map_err(io_other)?;
    let mut ping = connection.ping_pong().expect("single XHTTP PING owner");
    let driver = owner.spawn(async move {
        if period < 0 {let _ = connection.await; return;}
        let interval = Duration::from_secs(if period == 0 {45} else {period as u64});
        loop {
            let idle_at = *last_read.lock().unwrap() + interval;
            tokio::select! {
                _ = &mut connection => break,
                () = tokio::time::sleep_until(idle_at) => {
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
    })?;
    Ok((
        SendRequest::H2(Sender {
            request: sender,
            writes,
        }),
        Arc::new(driver),
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
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.raw).poll_read(cx, buf);
        if buf.filled().len() > before {
            *self.last_read.lock().unwrap() = Instant::now();
        }
        result
    }
}
impl AsyncWrite for ActivityIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}
