//! One native frame at a time, with credit returned after bounded forwarding.
use super::h2_headers;
use bytes::Bytes;
use http::HeaderMap;
use std::io;
use tokio::time::{Duration, timeout};
pub(super) const IDLE: Duration = Duration::from_secs(30);
fn failed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP stream failed")
}
pub(super) struct Length(Option<u64>);
impl Length {
    pub(super) fn new(length: Option<u64>) -> Self {
        Self(length)
    }
    pub(super) fn remaining(&self) -> Option<u64> {
        self.0
    }
    pub(super) fn consume(&mut self, count: usize) -> io::Result<()> {
        if let Some(remaining) = self.0 {
            self.0 = Some(remaining.checked_sub(count as u64).ok_or_else(failed)?);
        }
        Ok(())
    }
    pub(super) fn finish(&self) -> io::Result<()> {
        if self.0.is_some_and(|remaining| remaining != 0) {
            Err(failed())
        } else {
            Ok(())
        }
    }
}
pub(super) async fn send_data(
    target: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
) -> io::Result<()> {
    while !data.is_empty() {
        target.reserve_capacity(data.len().min(16 * 1024));
        let available = timeout(
            IDLE,
            futures_util::future::poll_fn(|cx| target.poll_capacity(cx)),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .ok_or_else(failed)?
        .map_err(|_| failed())?;
        if available == 0 {
            continue;
        }
        let count = data.len().min(available).min(16 * 1024);
        target
            .send_data(data.split_to(count), false)
            .map_err(|_| failed())?;
    }
    Ok(())
}
pub(super) fn finish(
    target: &mut h2::SendStream<Bytes>,
    trailers: Option<HeaderMap>,
    strip_credentials: bool,
) -> io::Result<()> {
    if let Some(trailers) = trailers {
        target
            .send_trailers(h2_headers::trailers(trailers, strip_credentials)?)
            .map_err(|_| failed())
    } else {
        target.send_data(Bytes::new(), true).map_err(|_| failed())
    }
}
pub(super) async fn relay(
    mut source: h2::RecvStream,
    mut target: h2::SendStream<Bytes>,
    expected: Option<u64>,
    strip_credentials: bool,
) -> io::Result<()> {
    let mut length = Length::new(expected);
    loop {
        let frame = timeout(IDLE, source.data())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?;
        let Some(frame) = frame else {
            break;
        };
        let data = frame.map_err(|_| failed())?;
        let count = data.len();
        length.consume(count)?;
        send_data(&mut target, data).await?;
        source
            .flow_control()
            .release_capacity(count)
            .map_err(|_| failed())?;
    }
    length.finish()?;
    let trailers = timeout(IDLE, source.trailers())
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(|_| failed())?;
    finish(&mut target, trailers, strip_credentials)
}
