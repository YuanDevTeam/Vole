//! Logical Mieru byte streams and the lazy SOCKS business handshake.
use super::tcp::{Carrier, WriterCommand};
use crate::{
    resources::observation::{self, ResourceKind},
    session::Destination,
    socks5,
};
use bytes::Bytes;
use futures_util::{future::BoxFuture, task::AtomicWaker};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll, Wake, Waker, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

pub(super) fn closed() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}
#[derive(Default)]
struct Input {
    queue: VecDeque<ReceivedChunk>,
    failure: bool,
    finished: bool,
}
pub(super) struct ReceivedChunk {
    pub bytes: Bytes,
    pub permit: OwnedSemaphorePermit,
}
pub(super) struct State {
    pub id: u32,
    pub opened: AtomicBool,
    pub sequence: AtomicU32,
    pub next_receive: AtomicU32,
    pub local_closed: AtomicBool,
    pub remote_closed: AtomicBool,
    pub close_response: AtomicBool,
    pub cancel: CancellationToken,
    input: Mutex<Input>,
    read: AtomicWaker,
    pub write: AtomicWaker,
    space: Notify,
    pub activity: Arc<Notify>,
    capacity: usize,
    pub receive_bytes: Arc<Semaphore>,
    _observation: observation::Guard,
}
impl State {
    pub fn new(
        id: u32,
        capacity: usize,
        cancellation: &CancellationToken,
        activity: Arc<Notify>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            opened: AtomicBool::new(false),
            sequence: AtomicU32::new(0),
            next_receive: AtomicU32::new(0),
            local_closed: AtomicBool::new(false),
            remote_closed: AtomicBool::new(false),
            close_response: AtomicBool::new(false),
            cancel: cancellation.child_token(),
            input: Mutex::new(Input::default()),
            read: AtomicWaker::new(),
            write: AtomicWaker::new(),
            space: Notify::new(),
            activity,
            capacity,
            receive_bytes: Arc::new(Semaphore::new(capacity)),
            _observation: observation::track(ResourceKind::Session),
        })
    }
    pub fn close(&self) {
        self.local_closed.store(true, Ordering::Release);
        self.cancel.cancel();
        let mut input = self.input.lock().unwrap();
        input.queue.clear();
        drop(input);
        self.read.wake();
        self.write.wake();
        self.space.notify_one();
        self.activity.notify_one();
    }
    pub fn finish(&self, failure: bool) {
        self.remote_closed.store(true, Ordering::Release);
        let mut input = self.input.lock().unwrap();
        input.failure |= failure;
        input.finished = true;
        drop(input);
        self.cancel.cancel();
        self.read.wake();
        self.write.wake();
        self.space.notify_one();
        self.activity.notify_one();
    }
    pub fn unread_segments(&self) -> usize {
        self.input.lock().unwrap().queue.len()
    }
    #[cfg(test)]
    pub(super) fn unread_bytes(&self) -> usize {
        self.input
            .lock()
            .unwrap()
            .queue
            .iter()
            .map(|chunk| chunk.bytes.len())
            .sum()
    }
    pub(super) fn receive_capacity(&self) -> usize {
        self.capacity
    }
    pub fn deliver_reserved(&self, chunk: ReceivedChunk) {
        if chunk.bytes.is_empty() {
            return;
        }
        let mut input = self.input.lock().unwrap();
        if self.cancel.is_cancelled() {
            return;
        }
        input.queue.push_back(chunk);
        drop(input);
        self.read.wake();
    }
    pub(super) fn try_deliver_reserved(&self, chunk: ReceivedChunk) -> bool {
        let mut input = self.input.lock().unwrap();
        if input.finished || self.cancel.is_cancelled() {
            return false;
        }
        if chunk.bytes.is_empty() {
            return true;
        }
        input.queue.push_back(chunk);
        drop(input);
        self.read.wake();
        true
    }
    pub async fn deliver(&self, mut data: Bytes) -> io::Result<()> {
        while !data.is_empty() {
            let count = data.len().min(self.capacity);
            let permit = tokio::select! { biased;
                ()=self.cancel.cancelled()=>return Err(closed()),
                result=self.receive_bytes.clone().acquire_many_owned(count as u32)=>result.map_err(|_|closed())?,
            };
            self.deliver_reserved(ReceivedChunk {
                bytes: data.split_to(count),
                permit,
            });
        }
        Ok(())
    }
    pub(super) fn poll_read(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read.register(cx.waker());
        let mut input = self.input.lock().unwrap();
        if let Some(mut chunk) = input.queue.pop_front() {
            let count = chunk.bytes.len().min(buffer.remaining());
            buffer.put_slice(&chunk.bytes[..count]);
            drop(chunk.permit.split(count).unwrap());
            if count < chunk.bytes.len() {
                chunk.bytes = chunk.bytes.slice(count..);
                input.queue.push_front(chunk);
            }
            drop(input);
            self.space.notify_one();
            self.activity.notify_one();
            return Poll::Ready(Ok(()));
        }
        if input.failure {
            Poll::Ready(Err(closed()))
        } else if input.finished || self.local_closed.load(Ordering::Acquire) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
pub(super) struct RawStream {
    pub state: Arc<State>,
    carrier: Arc<Carrier>,
    pending: Option<BoxFuture<'static, io::Result<usize>>>,
    chunk: usize,
    ended: bool,
}
impl RawStream {
    pub fn new(carrier: Arc<Carrier>, state: Arc<State>, capacity: usize) -> Self {
        let chunk = capacity.min(32768).min(carrier.maximum_write());
        Self {
            state,
            carrier,
            pending: None,
            chunk,
            ended: false,
        }
    }
    fn end(&mut self) {
        self.ended = true;
        self.state.close();
        self.pending = None;
    }
}
impl Drop for RawStream {
    fn drop(&mut self) {
        self.end();
    }
}
impl AsyncRead for RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.state.poll_read(cx, buffer)
    }
}
impl AsyncWrite for RawStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.state.write.register(cx.waker());
        if self.ended || self.state.cancel.is_cancelled() {
            return Poll::Ready(Err(closed()));
        }
        if self.pending.is_none() {
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let count = bytes.len().min(self.chunk);
            let data = Bytes::copy_from_slice(&bytes[..count]);
            let piggyback = bytes.len() <= 1024;
            let carrier = self.carrier.clone();
            let state = self.state.clone();
            self.pending = Some(Box::pin(async move {
                let operation = async {
                    let permit = carrier
                        .bytes
                        .clone()
                        .acquire_many_owned(count as u32)
                        .await
                        .map_err(|_| closed())?;
                    let (done, response) = oneshot::channel();
                    carrier
                        .writer
                        .send(WriterCommand {
                            state: state.clone(),
                            data,
                            piggyback,
                            done,
                            _bytes: permit,
                        })
                        .await
                        .map_err(|_| closed())?;
                    response.await.map_err(|_| closed())??;
                    Ok(count)
                };
                tokio::select! {biased;()=state.cancel.cancelled()=>Err(closed()),result=operation=>result}
            }));
        }
        let result = ready!(self.pending.as_mut().unwrap().as_mut().poll(cx));
        self.pending = None;
        Poll::Ready(result)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(pending) = self.pending.as_mut() {
            ready!(pending.as_mut().poll(cx))?;
            self.pending = None;
        }
        if self.state.cancel.is_cancelled() {
            return Poll::Ready(Err(closed()));
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ended {
            return Poll::Ready(Ok(()));
        }
        ready!(self.as_mut().poll_flush(cx))?;
        self.end();
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct HandshakeWake {
    read: AtomicWaker,
    write: AtomicWaker,
}
impl Wake for HandshakeWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.read.wake();
        self.write.wake();
    }
}
type Handshake = BoxFuture<'static, (RawStream, io::Result<usize>)>;
pub(super) struct Stream {
    raw: Option<RawStream>,
    request: Option<Bytes>,
    pending: Option<Handshake>,
    completed_write: Option<io::Result<usize>>,
    wake: Arc<HandshakeWake>,
    state: Arc<State>,
    chunk: usize,
}
impl Stream {
    pub async fn standard(
        mut raw: RawStream,
        target: &Destination,
        command: u8,
        deadline: Instant,
    ) -> io::Result<Self> {
        let request = request(target, command)?;
        let _guard = observation::track(ResourceKind::Handshake);
        timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(10)),
            async {
                raw.write_all(&request).await?;
                read_response(&mut raw).await
            },
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        Ok(Self::ready(raw))
    }
    fn ready(raw: RawStream) -> Self {
        let state = raw.state.clone();
        let chunk = raw.chunk;
        Self {
            raw: Some(raw),
            request: None,
            pending: None,
            completed_write: None,
            wake: Arc::default(),
            state,
            chunk,
        }
    }
    pub fn no_wait(raw: RawStream, target: &Destination, command: u8) -> io::Result<Self> {
        let request = request(target, command)?;
        let mut stream = Self::ready(raw);
        stream.request = Some(request);
        Ok(stream)
    }
    fn progress(&mut self) -> Poll<io::Result<()>> {
        if let Some(pending) = self.pending.as_mut() {
            let waker = Waker::from(self.wake.clone());
            let mut context = Context::from_waker(&waker);
            let (raw, result) = ready!(pending.as_mut().poll(&mut context));
            self.raw = Some(raw);
            self.pending = None;
            if result.is_err() {
                self.state.close();
            }
            self.completed_write = Some(result);
            self.wake.wake_by_ref();
        }
        if self.state.local_closed.load(Ordering::Acquire) {
            Poll::Ready(Err(closed()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.state.close();
        self.pending = None;
        self.raw = None;
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.wake.read.register(cx.waker());
        self.state.read.register(cx.waker());
        if self.state.cancel.is_cancelled() && self.request.is_some() {
            return Poll::Ready(Err(closed()));
        }
        if self.state.local_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        if self.request.is_some() {
            return Poll::Pending;
        }
        ready!(self.progress())?;
        Pin::new(self.raw.as_mut().unwrap()).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.wake.write.register(cx.waker());
        if self.state.local_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(closed()));
        }
        if let Some(request) = self.request.take() {
            let count = bytes.len().min(self.chunk);
            let mut combined = Vec::with_capacity(request.len() + count);
            combined.extend_from_slice(&request);
            combined.extend_from_slice(&bytes[..count]);
            let mut raw = self.raw.take().unwrap();
            self.pending = Some(Box::pin(async move {
                let _guard = observation::track(ResourceKind::Handshake);
                let result = timeout_at(Instant::now() + Duration::from_secs(10), async {
                    raw.write_all(&combined).await?;
                    read_response(&mut raw).await?;
                    Ok(count)
                })
                .await
                .map_err(|_| io::ErrorKind::TimedOut.into())
                .and_then(|result| result);
                (raw, result)
            }));
            self.wake.read.wake();
        }
        ready!(self.progress())?;
        if let Some(result) = self.completed_write.take() {
            return Poll::Ready(result);
        }
        Pin::new(self.raw.as_mut().unwrap()).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wake.write.register(cx.waker());
        if self.request.is_some() {
            return Poll::Ready(Ok(()));
        }
        ready!(self.progress())?;
        if self.completed_write.as_ref().is_some_and(Result::is_err) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(self.raw.as_mut().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.close();
        self.pending = None;
        self.raw = None;
        Poll::Ready(Ok(()))
    }
}
fn request(target: &Destination, command: u8) -> io::Result<Bytes> {
    let mut request = vec![socks5::VERSION, command, 0];
    socks5::encode_address(target, &mut request)?;
    Ok(Bytes::from(request))
}
async fn read_response(raw: &mut RawStream) -> io::Result<()> {
    let mut header = [0; 3];
    raw.read_exact(&mut header).await?;
    if header[0] != socks5::VERSION || header[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Mieru business handshake rejected",
        ));
    }
    // The bind endpoint is metadata only. Port zero is valid in a SOCKS reply.
    socks5::read_destination(raw, true).await?;
    Ok(())
}
