use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use h2::{RecvStream, SendStream, client::ResponseFuture};
#[cfg(feature = "outbound-trusttunnel")]
use tokio::sync::oneshot;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::{AbortHandle, JoinHandle},
    time::{Instant, timeout_at},
};

use super::h2_write::{Payload, Receipt, Sender, Writes};
use super::{STREAM_BUFFER_BYTES as LIMIT, STREAM_CHUNK_BYTES as CHUNK};
use crate::dispatch::BoxStream;

enum PendingResponse {
    Direct(ResponseFuture),
    #[cfg(feature = "outbound-trusttunnel")]
    Observed(oneshot::Receiver<io::Result<http::Response<RecvStream>>>),
}
impl Future for PendingResponse {
    type Output = io::Result<http::Response<RecvStream>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Direct(response) => Pin::new(response)
                .poll(cx)
                .map(|result| result.map_err(|_| invalid())),
            #[cfg(feature = "outbound-trusttunnel")]
            Self::Observed(response) => Pin::new(response).poll(cx).map(|result| {
                result.unwrap_or_else(|_| Err(io::ErrorKind::ConnectionAborted.into()))
            }),
        }
    }
}

#[derive(Default)]
struct Close {
    stopped: AtomicBool,
    failed: AtomicBool,
    reader: AtomicWaker,
    writer: AtomicWaker,
    #[cfg(feature = "outbound-trusttunnel")]
    response_cancel: Option<tokio_util::sync::CancellationToken>,
}

impl Close {
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.reader.wake();
        self.writer.wake();
        #[cfg(feature = "outbound-trusttunnel")]
        if let Some(cancel) = &self.response_cancel {
            cancel.cancel();
        }
    }
}

/// Owns one supplied HTTP/2 connection (not a multiplexing pool). Stop
/// owns the join barrier; Drop is cancellation fallback, never a PASS barrier.
pub struct Driver {
    task: Option<JoinHandle<Result<(), h2::Error>>>,
    close: Arc<Close>,
}

impl Driver {
    pub async fn stop(mut self) -> io::Result<()> {
        self.close.stop();
        if let Some(task) = self.task.take() {
            task.abort();
            if task.await.is_err_and(|error| !error.is_cancelled()) {
                return Err(io::ErrorKind::Other.into());
            }
        }
        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.close.stop();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub async fn grpc(
    stream: BoxStream,
    uri: &str,
    deadline: Instant,
) -> io::Result<(BoxStream, Driver)> {
    connect(stream, uri, deadline, Framing::Gun, false).await
}

/// A protocol carrying a bidirectional TCP stream needs upload END_STREAM,
/// not RST_STREAM, when its application half-closes. The read half and driver
/// remain owned until the session is dropped or its owner explicitly stops.
/// This does not change the whole-close contract of `grpc` or legacy H2.
pub async fn grpc_duplex(
    stream: BoxStream,
    uri: &str,
    deadline: Instant,
) -> io::Result<(BoxStream, Driver)> {
    connect(stream, uri, deadline, Framing::Gun, true).await
}

/// Legacy VMess/VLESS H2: PUT with an unframed byte stream, not gRPC.
pub async fn legacy_h2(
    stream: BoxStream,
    uri: &str,
    deadline: Instant,
) -> io::Result<(BoxStream, Driver)> {
    connect(stream, uri, deadline, Framing::Plain, false).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    Gun,
    Plain,
}

async fn connect(
    stream: BoxStream,
    uri: &str,
    deadline: Instant,
    framing: Framing,
    half_close: bool,
) -> io::Result<(BoxStream, Driver)> {
    let uri: http::Uri = uri
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri
            .authority()
            .is_none_or(|value| value.as_str().contains('@'))
        || uri.to_string().len() > super::HTTP_HEAD_BYTES - 256
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let request = http::Request::builder()
        .method(if framing == Framing::Gun {
            "POST"
        } else {
            "PUT"
        })
        .uri(uri);
    let request = match framing {
        Framing::Gun => request
            .header("content-type", "application/grpc")
            .header("te", "trailers"),
        Framing::Plain => request.header("accept-encoding", "identity"),
    };
    let request = request
        .body(())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let (stream, writes) = Writes::wrap(stream);
    let (sender, connection) = timeout_at(
        deadline,
        h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(LIMIT as u32)
            .initial_connection_window_size((2 * LIMIT) as u32)
            .max_frame_size(CHUNK as u32)
            .max_header_list_size(CHUNK as u32)
            .max_concurrent_streams(1)
            .max_send_buffer_size(CHUNK)
            .handshake(stream),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    let close = Arc::new(Close::default());
    let task = crate::resources::observation::spawn(connection);
    let abort = task.abort_handle();
    // Immediately own the task, including cancellation during ready().
    let owner = Driver {
        task: Some(task),
        close: close.clone(),
    };
    let sender = timeout_at(deadline, sender.ready()).await;
    let mut sender = match sender {
        Ok(Ok(sender)) => sender,
        result => {
            owner.stop().await?;
            return Err(if result.is_err() {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::ConnectionAborted
            }
            .into());
        }
    };
    let (response, send) = match sender.send_request(request, false) {
        Ok(stream) => stream,
        Err(_) => {
            owner.stop().await?;
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
    };
    // Do not await response headers here: Mihomo may only flush them after the
    // first VLESS bytes. Request writing and response reading must be independent.
    Ok((
        Box::new(Grpc::new(
            response,
            send,
            framing,
            half_close,
            deadline,
            close,
            Some(abort),
            None,
            writes,
        )),
        owner,
    ))
}

struct Grpc {
    _observation: crate::resources::observation::Guard,
    framing: Framing,
    half_close: bool,
    upload_closed: bool,
    response: Option<PendingResponse>,
    response_deadline: bool,
    receive: Option<RecvStream>,
    send: SendStream<Payload>,
    writes: Writes,
    pending: Option<Receipt>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    frame: Bytes,
    wire: BytesMut,
    payload: Bytes,
    queued: Bytes,
    eof: bool,
    data_eof: bool,
    close: Arc<Close>,
    abort: Option<AbortHandle>,
    _lease: Option<super::grpc_pool::Lease>,
}

pub(super) async fn pooled_stream(
    sender: Sender,
    uri: &str,
    user_agent: &str,
    half_close: bool,
    deadline: Instant,
    lease: super::grpc_pool::Lease,
) -> io::Result<BoxStream> {
    let request = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", user_agent)
        .body(())
        .map_err(|_| invalid())?;
    let writes = sender.writes;
    let mut sender = timeout_at(deadline, sender.request.ready())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    Ok(Box::new(Grpc::new(
        response,
        send,
        Framing::Gun,
        half_close,
        deadline,
        Arc::default(),
        None,
        Some(lease),
        writes,
    )))
}

impl Drop for Grpc {
    fn drop(&mut self) {
        self.close.stop();
        self.send.send_reset(h2::Reason::CANCEL);
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }
}

#[cfg(feature = "outbound-trusttunnel")]
pub(super) async fn pooled_connect(
    sender: Sender,
    request: http::Request<()>,
    deadline: Instant,
    lease: super::grpc_pool::Lease,
    observer: Option<Arc<dyn Fn() + Send + Sync>>,
) -> io::Result<(BoxStream, impl Future<Output = ()> + Send + 'static)> {
    let writes = sender.writes;
    let mut sender = timeout_at(deadline, sender.request.ready())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    let (response, send) = sender.send_request(request, false).map_err(|_| invalid())?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let close = Arc::new(Close {
        response_cancel: Some(cancel.clone()),
        ..Default::default()
    });
    let (ready, receiver) = oneshot::channel();
    let mut stream = Grpc::new(
        response,
        send,
        Framing::Plain,
        false,
        deadline,
        close.clone(),
        None,
        Some(lease),
        writes,
    );
    let response = match stream.response.take().unwrap() {
        PendingResponse::Direct(response) => response,
        _ => unreachable!(),
    };
    stream.response = Some(PendingResponse::Observed(receiver));
    // Physical establishment ends setup, as in Mihomo. A CONNECT peer may
    // defer headers until client-first data; no expired setup timer is applied
    // to an already established logical stream's later first read.
    stream.response_deadline = false;
    let headers = async move {
        let result = tokio::select! {biased;
            ()=cancel.cancelled()=>return,
            result=response=>result.map_err(|_| invalid()).and_then(|response| {
                if response.status() == 200 { Ok(response) } else { Err(invalid()) }
            }),
        };
        if result.is_ok() {
            if let Some(observer) = observer {
                observer();
            }
        } else {
            close.failed.store(true, Ordering::SeqCst);
            close.stop();
        }
        let _ = ready.send(result);
    };
    Ok((Box::new(stream), headers))
}

#[cfg(feature = "outbound-trusttunnel")]
pub(super) async fn connect_probe(
    sender: Sender,
    request: http::Request<()>,
    deadline: Instant,
    _lease: super::grpc_pool::Lease,
) -> io::Result<()> {
    let mut sender = timeout_at(deadline, sender.request.ready())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| invalid())?;
    let (response, _send) = sender.send_request(request, true).map_err(|_| invalid())?;
    let response = timeout_at(deadline, response)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| invalid())?;
    if response.status() == 200 {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// sing-mux uses plain HTTP/2 CONNECT streams, not gRPC records.
#[cfg(feature = "sing-mux")]
pub(super) async fn mux_stream(sender: Sender, deadline: Instant) -> io::Result<BoxStream> {
    let writes = sender.writes;
    let mut sender = sender.request.ready().await.map_err(|_| invalid())?;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://localhost")
        .body(())
        .map_err(|_| invalid())?;
    let (response, send) = sender.send_request(request, false).map_err(|_| invalid())?;
    Ok(Box::new(Grpc::new(
        response,
        send,
        Framing::Plain,
        true,
        deadline,
        Arc::default(),
        None,
        None,
        writes,
    )))
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

impl Grpc {
    fn stopped(&self) -> bool {
        self.close.stopped.load(Ordering::SeqCst)
            || self._lease.as_ref().is_some_and(|lease| lease.stopped())
    }
    #[allow(clippy::too_many_arguments)]
    fn new(
        response: ResponseFuture,
        send: SendStream<Payload>,
        framing: Framing,
        half_close: bool,
        deadline: Instant,
        close: Arc<Close>,
        abort: Option<AbortHandle>,
        lease: Option<super::grpc_pool::Lease>,
        writes: Writes,
    ) -> Self {
        Self {
            _observation: crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Session,
            ),
            framing,
            half_close,
            upload_closed: false,
            response: Some(PendingResponse::Direct(response)),
            response_deadline: true,
            receive: None,
            send,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            writes,
            pending: None,
            frame: Bytes::new(),
            wire: BytesMut::new(),
            payload: Bytes::new(),
            queued: Bytes::new(),
            eof: false,
            data_eof: false,
            close,
            abort,
            _lease: lease,
        }
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close.writer.register(cx.waker());
        if self.stopped() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // Register for connection failure even while waiting on a write receipt:
        // queued DATA can remain owned by a SendStream after its driver stops.
        if self.send.poll_reset(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if let Some(pending) = &mut self.pending {
                ready!(Pin::new(pending).poll(cx)).map_err(|_| io::ErrorKind::BrokenPipe)??;
                self.pending = None;
            }
            if self.queued.is_empty() {
                self.send.reserve_capacity(0);
                return Poll::Ready(Ok(()));
            }
            self.send.reserve_capacity(self.queued.len());
            let count = ready!(self.send.poll_capacity(cx))
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            if count == 0 {
                continue;
            }
            let count = count.min(self.queued.len());
            let (payload, receipt) = self.writes.payload(self.queued.split_to(count));
            self.send
                .send_data(payload, false)
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            self.pending = Some(receipt);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn record(&mut self) -> io::Result<bool> {
        if self.wire.len() < 5 {
            return Ok(false);
        }
        let length = u32::from_be_bytes(self.wire[1..5].try_into().unwrap()) as usize;
        if self.wire[0] != 0 || !(2..=LIMIT + 4).contains(&length) {
            return Err(invalid());
        }
        if self.wire.len() < length + 5 {
            return Ok(false);
        }
        if self.wire[5] != 0x0a {
            return Err(invalid());
        }
        let mut value = 0;
        let mut start = None;
        for index in 0..3 {
            let byte = *self.wire.get(6 + index).ok_or_else(invalid)?;
            value |= usize::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                start = Some(7 + index);
                break;
            }
        }
        let start = start.ok_or_else(invalid)?;
        if value > LIMIT || start + value != length + 5 {
            return Err(invalid());
        }
        self.payload = self.wire.split().freeze().slice(start..);
        Ok(true)
    }
}

impl AsyncRead for Grpc {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.close.reader.register(cx.waker());
        if this.close.failed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(invalid()));
        }
        if this.stopped() || this.eof {
            return Poll::Ready(Ok(()));
        }
        if let Some(response) = &mut this.response {
            // Lazy setup still uses the original deadline, even when headers
            // are already queued. Established reads are not setup operations.
            if this.response_deadline && this.deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
            match Pin::new(response).poll(cx) {
                Poll::Ready(result) => {
                    let response = result?;
                    if response.status() != 200
                        || (this.framing == Framing::Gun
                            && !response.headers().get("content-type").is_some_and(|value| {
                                matches!(
                                    value
                                        .as_bytes()
                                        .split(|byte| matches!(byte, b';' | b'+'))
                                        .next(),
                                    Some(b"application/grpc")
                                )
                            }))
                    {
                        return Poll::Ready(Err(invalid()));
                    }
                    this.response = None;
                    this.receive = Some(response.into_body());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if this.framing == Framing::Plain {
            let receive = this.receive.as_mut().unwrap();
            for _ in 0..crate::limits::IO_POLL_BUDGET {
                if !this.frame.is_empty() {
                    let count = this.frame.len().min(output.remaining());
                    output.put_slice(&this.frame[..count]);
                    this.frame.advance(count);
                    receive
                        .flow_control()
                        .release_capacity(count)
                        .map_err(|_| invalid())?;
                    return Poll::Ready(Ok(()));
                }
                match ready!(receive.poll_data(cx)) {
                    Some(Ok(frame)) => this.frame = frame,
                    Some(Err(_)) => return Poll::Ready(Err(invalid())),
                    None => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if !this.payload.is_empty() {
                let count = this.payload.len().min(output.remaining());
                output.put_slice(&this.payload[..count]);
                this.payload.advance(count);
                return Poll::Ready(Ok(()));
            }
            if this.record()? {
                continue;
            }
            let receive = this.receive.as_mut().unwrap();
            if !this.frame.is_empty() {
                let needed = if this.wire.len() < 5 {
                    5
                } else {
                    5 + u32::from_be_bytes(this.wire[1..5].try_into().unwrap()) as usize
                };
                let count = (needed - this.wire.len()).min(this.frame.len());
                this.wire.extend_from_slice(&this.frame[..count]);
                this.frame.advance(count);
                // Only consumed bytes replenish the peer's window.
                receive
                    .flow_control()
                    .release_capacity(count)
                    .map_err(|_| invalid())?;
                continue;
            }
            if !this.data_eof {
                match ready!(receive.poll_data(cx)) {
                    Some(Ok(frame)) => {
                        this.frame = frame;
                        continue;
                    }
                    Some(Err(_)) => return Poll::Ready(Err(invalid())),
                    None => this.data_eof = true,
                }
            }
            if !this.wire.is_empty() {
                return Poll::Ready(Err(invalid()));
            }
            let trailers = ready!(receive.poll_trailers(cx)).map_err(|_| invalid())?;
            if trailers
                .as_ref()
                .and_then(|headers| headers.get("grpc-status"))
                .is_some_and(|status| status != "0")
            {
                return Poll::Ready(Err(invalid()));
            }
            this.eof = true;
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for Grpc {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.close.writer.register(cx.waker());
        if self.stopped() || self.upload_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(self.drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(CHUNK);
        if self.framing == Framing::Plain {
            self.queued = Bytes::copy_from_slice(&input[..count]);
            return Poll::Ready(Ok(count));
        }
        let mut wire = Vec::with_capacity(count + 9);
        wire.extend_from_slice(&[0; 5]);
        wire.push(0x0a);
        let mut length = count;
        while length > 127 {
            wire.push((length as u8 & 0x7f) | 0x80);
            length >>= 7;
        }
        wire.push(length as u8);
        wire.extend_from_slice(&input[..count]);
        let total = (wire.len() - 5) as u32;
        wire[1..5].copy_from_slice(&total.to_be_bytes());
        self.queued = wire.into();
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drain(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.upload_closed {
            return Poll::Ready(Ok(()));
        }
        if self.half_close {
            ready!(self.drain(cx))?;
            self.send
                .send_data(Payload::empty(), true)
                .map_err(|_| invalid())?;
            self.upload_closed = true;
            return Poll::Ready(Ok(()));
        }
        // Close the logical byte stream. A pooled physical connection belongs
        // to the node and must survive another stream's RST_STREAM.
        ready!(self.drain(cx))?;
        self.upload_closed = true;
        self.close.stop();
        self.send.send_reset(h2::Reason::CANCEL);
        self.response = None;
        self.receive = None;
        self.queued = Bytes::new();
        self._lease.take();
        if let Some(abort) = &self.abort {
            abort.abort();
        }
        Poll::Ready(Ok(()))
    }
}
