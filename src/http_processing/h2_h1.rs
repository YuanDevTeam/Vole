//! Hyper HTTP/1 bodies over an existing dispatcher stream, with native H2 credit.
use super::{
    h2_body::{self, IDLE, Length},
    h2_headers,
};
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep, sleep};

pub(super) struct Upload {
    source: h2::RecvStream,
    length: Length,
    release: usize,
    trailers: bool,
    done: bool,
    strip_credentials: bool,
    idle: Pin<Box<Sleep>>,
}
impl Upload {
    pub(super) fn new(
        source: h2::RecvStream,
        length: Option<u64>,
        strip_credentials: bool,
    ) -> Self {
        Self {
            source,
            length: Length::new(length),
            release: 0,
            trailers: false,
            done: false,
            strip_credentials,
            idle: Box::pin(sleep(IDLE)),
        }
    }
    fn stop(&mut self) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.done = true;
        Poll::Ready(Some(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP upload failed",
        ))))
    }
}
impl Drop for Upload {
    fn drop(&mut self) {
        // Hyper may stop polling upload after an early final response. Return
        // the last handed-off frame's credit before the response owner ends.
        if self.release != 0 {
            let _ = self.source.flow_control().release_capacity(self.release);
        }
    }
}
impl Body for Upload {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.release != 0 {
            let count = std::mem::take(&mut self.release);
            if self.source.flow_control().release_capacity(count).is_err() {
                return self.stop();
            }
        }
        if self.idle.as_mut().poll(cx).is_ready() {
            return self.stop();
        }
        if !self.trailers {
            match self.source.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(data))) => {
                    if self.length.consume(data.len()).is_err() {
                        return self.stop();
                    }
                    self.release = data.len();
                    self.idle.as_mut().reset(Instant::now() + IDLE);
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Poll::Ready(Some(Err(_))) => return self.stop(),
                Poll::Ready(None) => {
                    if self.length.finish().is_err() {
                        return self.stop();
                    }
                    self.trailers = true;
                }
            }
        }
        match self.source.poll_trailers(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(headers)) => {
                self.done = true;
                match headers {
                    Some(headers) => Poll::Ready(Some(
                        h2_headers::trailers(headers, self.strip_credentials).map(Frame::trailers),
                    )),
                    None => Poll::Ready(None),
                }
            }
            Poll::Ready(Err(_)) => self.stop(),
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
            || (self.source.is_end_stream()
                && self
                    .length
                    .remaining()
                    .is_none_or(|remaining| remaining == 0))
    }
    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        if let Some(length) = self.length.remaining() {
            hint.set_exact(length);
        }
        hint
    }
}
pub(super) async fn download(
    mut body: hyper::body::Incoming,
    mut target: h2::SendStream<Bytes>,
    expected: Option<u64>,
) -> io::Result<()> {
    let mut length = Length::new(expected);
    while let Some(frame) = tokio::time::timeout(
        IDLE,
        futures_util::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)),
    )
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
    {
        let frame = frame.map_err(|_| io::Error::other("HTTP response body failed"))?;
        match frame.into_data() {
            Ok(data) => {
                length.consume(data.len())?;
                h2_body::send_data(&mut target, data).await?;
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    length.finish()?;
                    return h2_body::finish(&mut target, Some(trailers), false);
                }
            }
        }
    }
    length.finish()?;
    h2_body::finish(&mut target, None, false)
}
