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
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep, sleep};

#[derive(Clone)]
pub(super) struct UploadIdle(Arc<Mutex<UploadIdleState>>);
struct UploadIdleState {
    sleep: Pin<Box<Sleep>>,
    finished: bool,
}
impl UploadIdle {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(UploadIdleState {
            sleep: Box::pin(sleep(IDLE)),
            finished: false,
        })))
    }
    fn progress(&self) {
        if let Ok(mut state) = self.0.lock()
            && !state.finished
        {
            state.sleep.as_mut().reset(Instant::now() + IDLE);
        }
    }
    fn finish(&self) {
        if let Ok(mut state) = self.0.lock()
            && !state.finished
        {
            state.finished = true;
            state.sleep.as_mut().reset(Instant::now() + IDLE);
        }
    }
    fn poll_expired(&self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let Ok(mut state) = self.0.lock() else {
            return Poll::Ready(io::Error::other("HTTP upload clock failed"));
        };
        state
            .sleep
            .as_mut()
            .poll(cx)
            .map(|()| io::ErrorKind::TimedOut.into())
    }
    pub(super) async fn wait_response<F, T, E>(&self, response: F) -> io::Result<T>
    where
        F: Future<Output = Result<T, E>>,
    {
        tokio::pin!(response);
        // Both polls belong to the existing inline driver owner. Never hold
        // the clock lock while polling Hyper, which can also poll Upload.
        futures_util::future::poll_fn(|cx| {
            if let Poll::Ready(result) = response.as_mut().poll(cx) {
                return Poll::Ready(result.map_err(|_| {
                    io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP proxy stream failed")
                }));
            }
            self.poll_expired(cx).map(Err)
        })
        .await
    }
}

pub(super) struct Upload {
    source: h2::RecvStream,
    length: Length,
    release: usize,
    trailers: bool,
    done: bool,
    strip_credentials: bool,
    idle: UploadIdle,
}
impl Upload {
    pub(super) fn new(
        source: h2::RecvStream,
        length: Option<u64>,
        strip_credentials: bool,
        idle: UploadIdle,
    ) -> Self {
        Self {
            source,
            length: Length::new(length),
            release: 0,
            trailers: false,
            done: false,
            strip_credentials,
            idle,
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
        if self.idle.poll_expired(cx).is_ready() {
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
                    if !data.is_empty() {
                        self.idle.progress();
                    }
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
                let frame = match headers {
                    Some(headers) => h2_headers::trailers(headers, self.strip_credentials)
                        .map(Frame::trailers)
                        .map(Some),
                    None => Ok(None),
                };
                match frame {
                    Ok(frame) => {
                        self.idle.finish();
                        Poll::Ready(frame.map(Ok))
                    }
                    Err(error) => Poll::Ready(Some(Err(error))),
                }
            }
            Poll::Ready(Err(_)) => self.stop(),
        }
    }
    fn is_end_stream(&self) -> bool {
        let finished = self.source.is_end_stream()
            && self
                .length
                .remaining()
                .is_none_or(|remaining| remaining == 0);
        // Hyper may omit the final poll_frame when this reports EOS. Errors
        // also set done, and must not refresh the clock as normal completion.
        if !self.done && finished {
            self.idle.finish();
        }
        self.done || finished
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
