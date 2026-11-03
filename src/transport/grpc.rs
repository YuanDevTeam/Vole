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

use super::h2_empty::Send as H2Send;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use h2::{RecvStream, client::ResponseFuture};
#[cfg(feature = "outbound-trusttunnel")]
use tokio::sync::oneshot;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::{AbortHandle, JoinHandle},
    time::{Instant, timeout_at},
};

#[cfg(feature = "sing-mux")]
use super::h2_write::CoalescedAck;
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
    send: H2Send,
    writes: Writes,
    pending: Option<Receipt>,
    #[cfg(feature = "sing-mux")]
    coalesced: Option<Arc<CoalescedAck>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    frame: Bytes,
    wire: BytesMut,
    remaining_payload: usize,
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
    policy: super::grpc_pool::ResponsePolicy,
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
    let mut stream = Grpc::new(
        response,
        send,
        Framing::Gun,
        half_close,
        deadline,
        Arc::default(),
        None,
        Some(lease),
        writes,
    );
    // Client-first protocol owners bound complete request submission separately.
    // Waiting for HTTP response headers must not reuse that setup deadline.
    stream.response_deadline = matches!(policy, super::grpc_pool::ResponsePolicy::SetupDeadline);
    Ok(Box::new(stream))
}

impl Drop for Grpc {
    fn drop(&mut self) {
        #[cfg(feature = "sing-mux")]
        if let Some(ack) = &self.coalesced {
            ack.fail(io::ErrorKind::BrokenPipe);
        }
        self.close.stop();
        if let Some(lease) = &self._lease {
            lease.close_stream();
        }
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
    mut lease: super::grpc_pool::Lease,
    observer: Option<Arc<dyn Fn() + Send + Sync>>,
) -> io::Result<(BoxStream, impl Future<Output = ()> + Send + 'static)> {
    let writes = sender.writes;
    let mut sender = timeout_at(deadline, sender.request.ready())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    let (response, send) = lease
        .request(&mut sender, request, false)
        .map_err(|_| invalid())?;
    let admission = lease.admission();
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
            if let Some(admission) = admission {
                admission.activate();
            }
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

/// CONNECT-IP is usable only after the peer has accepted its request. Keep
/// the logical stream owned while awaiting headers so cancellation resets only
/// this request, and leave its first DATA frame for the caller.
#[cfg(feature = "outbound-masque")]
pub(super) async fn pooled_connect_admitted(
    sender: Sender,
    request: http::Request<()>,
    deadline: Instant,
    lease: super::grpc_pool::Lease,
) -> io::Result<BoxStream> {
    let writes = sender.writes;
    let mut sender = timeout_at(deadline, sender.request.ready())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
    let (response, send) = sender.send_request(request, false).map_err(|_| invalid())?;
    let mut stream = Grpc::new(
        response,
        send,
        Framing::Plain,
        false,
        deadline,
        Arc::default(),
        None,
        Some(lease),
        writes,
    );
    let response = match stream.response.take().unwrap() {
        PendingResponse::Direct(response) => response,
        #[cfg(feature = "outbound-trusttunnel")]
        PendingResponse::Observed(_) => unreachable!(),
    };
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let response = timeout_at(deadline, response)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| invalid())?;
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if response.status() != http::StatusCode::OK {
        return Err(invalid());
    }
    stream.receive = Some(response.into_body());
    stream.response_deadline = false;
    Ok(Box::new(stream))
}

/// sing-mux uses plain HTTP/2 CONNECT streams, not gRPC records.
#[cfg(feature = "sing-mux")]
pub(super) async fn mux_stream(
    sender: Sender,
    deadline: Instant,
    autonomous: bool,
) -> io::Result<BoxStream> {
    let writes = sender.writes;
    let mut sender = sender.request.ready().await.map_err(|_| invalid())?;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://localhost")
        .body(())
        .map_err(|_| invalid())?;
    let (response, send) = sender.send_request(request, false).map_err(|_| invalid())?;
    let mut stream = Grpc::new(
        response,
        send,
        Framing::Plain,
        true,
        deadline,
        Arc::default(),
        None,
        None,
        writes,
    );
    stream.coalesced = autonomous.then(|| Arc::new(CoalescedAck::default()));
    // sing-mux owns the logical setup deadline, including metadata and the
    // optional Brutal exchange. A valid upload can outlive delayed H2 headers;
    // do not hide a second response timer beneath its business-write boundary.
    stream.response_deadline = false;
    Ok(Box::new(stream))
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
        send: impl Into<H2Send>,
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
            send: send.into(),
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            writes,
            pending: None,
            #[cfg(feature = "sing-mux")]
            coalesced: None,
            frame: Bytes::new(),
            wire: BytesMut::new(),
            remaining_payload: 0,
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
        #[cfg(feature = "sing-mux")]
        if let Some(ack) = &self.coalesced {
            self.send.reserve_capacity(0);
            return ack.poll_flushed(cx);
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

    #[cfg(feature = "sing-mux")]
    fn poll_coalesced_write(
        &mut self,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let ack = self.coalesced.as_ref().expect("private h2mux writer");
        ack.check(cx)?;
        if self.send.poll_reset(cx).is_ready() {
            ack.fail(io::ErrorKind::BrokenPipe);
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = input.len().min(CHUNK);
        self.send.reserve_capacity(wanted);
        let count = ready!(self.send.poll_capacity(cx))
            .ok_or(io::ErrorKind::BrokenPipe)?
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let count = wanted.min(count);
        if count == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let payload = self
            .writes
            .coalesced_payload(Bytes::copy_from_slice(&input[..count]), ack)?;
        if self.send.send_data(payload, false).is_err() {
            ack.fail(io::ErrorKind::BrokenPipe);
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // Retain demand for accepted buffered DATA, not the caller's unaccepted tail.
        self.send.reserve_capacity(0);
        // The existing h2 capacity includes max_send_buffer_size. No private
        // tail/oneshot remains; its Connection owns every accepted byte.
        Poll::Ready(Ok(count))
    }

    // Validate the complete bounded header before exposing any payload. A
    // later truncated body remains an error after its valid prefix was read.
    fn record(&mut self) -> io::Result<bool> {
        if self.wire.len() < 5 {
            return Ok(false);
        }
        let length = u32::from_be_bytes(self.wire[1..5].try_into().unwrap()) as usize;
        if self.wire[0] != 0 || !(2..=LIMIT + 4).contains(&length) {
            return Err(invalid());
        }
        if self.wire.len() < 7 {
            return Ok(false);
        }
        if self.wire[5] != 0x0a {
            return Err(invalid());
        }
        let mut value = 0;
        for index in 0..3 {
            let Some(&byte) = self.wire.get(6 + index) else {
                return Ok(false);
            };
            value |= usize::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                if value > LIMIT || 7 + index + value != length + 5 {
                    return Err(invalid());
                }
                self.remaining_payload = value;
                self.wire.clear();
                return Ok(true);
            }
        }
        Err(invalid())
    }
    fn poll_gun_read(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if this.remaining_payload != 0 && !this.frame.is_empty() {
                let count = this
                    .remaining_payload
                    .min(this.frame.len())
                    .min(output.remaining());
                output.put_slice(&this.frame[..count]);
                this.frame.advance(count);
                this.remaining_payload -= count;
                this.receive
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(count)
                    .map_err(|_| invalid())?;
                return Poll::Ready(Ok(()));
            }
            if this.remaining_payload == 0 {
                if this.record()? {
                    continue;
                }
                if !this.frame.is_empty() {
                    // Only the five-byte gRPC prefix, tag and <=3 varint bytes
                    // are staged; the declared payload stays in its h2 frame.
                    let needed = match this.wire.len() {
                        0..5 => 5,
                        5..7 => 7,
                        length => length + 1,
                    };
                    let count = (needed - this.wire.len()).min(this.frame.len());
                    this.wire.extend_from_slice(&this.frame[..count]);
                    this.frame.advance(count);
                    this.receive
                        .as_mut()
                        .unwrap()
                        .flow_control()
                        .release_capacity(count)
                        .map_err(|_| invalid())?;
                    continue;
                }
            }
            let receive = this.receive.as_mut().unwrap();
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
            if this.remaining_payload != 0 || !this.wire.is_empty() {
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
        this.poll_gun_read(cx, output)
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
        #[cfg(feature = "sing-mux")]
        if self.coalesced.is_some() {
            return self.poll_coalesced_write(cx, input);
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
        if let Some(lease) = &self._lease {
            lease.close_stream();
        }
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

#[cfg(all(test, feature = "sing-mux"))]
mod coalesced_partial_memory_tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn private_h2mux_partial_write_releases_unaccepted_reservation() {
        let (raw, peer) = tokio::io::duplex(65536);
        let (raw, writes) = Writes::wrap(Box::new(raw));
        let (mut sender, connection) = h2::client::Builder::new()
            .enable_push(false)
            .max_send_buffer_size(CHUNK)
            .handshake::<_, Payload>(raw)
            .await
            .unwrap();
        let client = tokio::spawn(connection);
        let (ready, ready_rx) = tokio::sync::oneshot::channel();
        let (grown, grown_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(1)
                .handshake::<_, Bytes>(peer)
                .await
                .unwrap();
            let (request, mut reply) = connection.accept().await.unwrap().unwrap();
            let output = reply.send_response(http::Response::new(()), false).unwrap();
            drop(reply);
            let mut input = request.into_body();
            let mut ping = connection.ping_pong().unwrap();
            macro_rules! drive {
                ($future:expr) => {{
                    let future = $future;
                    tokio::pin!(future);
                    loop {
                        tokio::select! { biased;
                            result = &mut future => break result,
                            next = connection.accept() => {
                                assert!(matches!(next, Some(Ok(_))), "peer closed before fixture release");
                            }
                        }
                    }
                }};
            }
            drive!(ping.ping(h2::Ping::opaque())).unwrap();
            drive!(ping.ping(h2::Ping::opaque())).unwrap();
            ready.send(()).unwrap();
            let prefix = drive!(input.data()).unwrap().unwrap().to_vec();
            // Keep this one received byte's flow credit until cleanup. The
            // new stream window adds CHUNK-1 genuine peer credit, no payload.
            connection.set_initial_window_size(CHUNK as u32).unwrap();
            // h2 polls pending user PING before local SETTINGS. The second
            // PING is ordered after SETTINGS, making its ACK a real barrier.
            drive!(ping.ping(h2::Ping::opaque())).unwrap();
            drive!(ping.ping(h2::Ping::opaque())).unwrap();
            grown.send(prefix).unwrap();
            drive!(release_rx).unwrap();
            drop((input, output, ping));
            while let Some(result) = connection.accept().await {
                result.unwrap();
            }
        });
        let request = http::Request::builder()
            .method("CONNECT")
            .uri("https://fixture.invalid")
            .body(())
            .unwrap();
        let (response, send) = sender.send_request(request, false).unwrap();
        let mut stream = Grpc::new(
            response,
            send,
            Framing::Plain,
            true,
            Instant::now() + Duration::from_secs(3),
            Arc::default(),
            None,
            None,
            writes,
        );
        stream.coalesced = Some(Arc::new(CoalescedAck::default()));
        stream.response_deadline = false;
        tokio::time::timeout(Duration::from_secs(1), ready_rx)
            .await
            .unwrap()
            .unwrap();
        let payload = [b'p'; CHUNK];
        let accepted = tokio::time::timeout(Duration::from_secs(1), stream.write(&payload))
            .await
            .unwrap()
            .unwrap();
        // Caller stays idle: no second write, flush or capacity reservation.
        let prefix = tokio::time::timeout(Duration::from_secs(1), grown_rx)
            .await
            .unwrap()
            .unwrap();
        let unused = match &stream.send {
            H2Send::Direct(native) => Some(native.capacity()),
            H2Send::Shared(_) => None,
        };
        release.send(()).unwrap();
        drop((stream, sender));
        let client_result = tokio::time::timeout(Duration::from_secs(1), client)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        // Both drivers naturally joined before the behavioral assertions.
        assert!(
            client_result.is_ok(),
            "client cleanup failed: {client_result:?}"
        );
        assert_eq!(accepted, 1, "peer stream-window fixture failed");
        assert_eq!(
            prefix, b"p",
            "the idle caller delivered an unaccepted suffix"
        );
        assert_eq!(
            unused,
            Some(0),
            "private h2mux must return unaccepted partial-write credit before caller idle"
        );
    }
}

#[cfg(test)]
#[path = "grpc_gun_streaming_read_memory_tests.rs"]
mod streaming_read_memory_tests;
