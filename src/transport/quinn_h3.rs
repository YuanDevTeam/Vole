//! HTTP/3 over an already established, caller-owned Quinn connection.
//!
//! TLS admission, protected datagram IO, deadlines, pools and task joins remain
//! with the caller. The control driver must be polled for the entire connection
//! lifetime. Request FIN does not wait for a transport ACK.

use bytes::Bytes;
use h3::{
    ConnectionState,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

#[path = "quinn_h3_budget.rs"]
mod budget;

pub(crate) type RequestStream = h3::client::RequestStream<BidiStream, Bytes>;
pub(crate) type SendStream = h3::client::RequestStream<GuardedSend, Bytes>;
pub(crate) type RecvStream = h3::client::RequestStream<GuardedRecv, Bytes>;
pub(crate) type ControlDriver = h3::client::Connection<Backend, Bytes>;

#[derive(Clone)]
pub(crate) struct Client {
    sender: h3::client::SendRequest<Streams, Bytes>,
    retiring: Arc<AtomicBool>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuinnH3Client")
            .field("can_open_request", &self.can_open_request())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A pool admission snapshot; send_request also checks the shared H3 state.
    pub(crate) fn can_open_request(&self) -> bool {
        !self.retiring.load(Ordering::Acquire)
            && self.sender.get_conn_error().is_none()
            && !self.sender.is_closing()
    }

    pub(crate) fn retire(&self) {
        self.retiring.store(true, Ordering::Release);
    }

    pub(crate) async fn send_request(
        &mut self,
        request: http::Request<()>,
    ) -> Result<RequestStream, h3::error::StreamError> {
        if self.retiring.load(Ordering::Acquire) {
            return Err(h3::error::StreamError::RemoteClosing);
        }
        self.sender.send_request(request).await
    }
}

pub(crate) async fn attach(
    connection: quinn::Connection,
    header_limit: u64,
) -> Result<(Client, ControlDriver), h3::error::ConnectionError> {
    let (control, sender) = h3::client::builder()
        .max_field_section_size(header_limit)
        .build(Backend {
            inner: h3_quinn::Connection::new(connection.clone()),
            connection,
            header_limit,
        })
        .await?;
    Ok((
        Client {
            sender,
            retiring: Arc::new(AtomicBool::new(false)),
        },
        control,
    ))
}

/// The official backend keeps QUIC I/O, framing and buffering. These delegates
/// bound retained non-DATA frames and preserve request-half cancellation,
/// including HEADERS still being written before h3 returns a RequestStream.
pub(crate) struct Backend {
    inner: h3_quinn::Connection,
    connection: quinn::Connection,
    header_limit: u64,
}

impl quic::Connection<Bytes> for Backend {
    type RecvStream = GuardedRecv;
    type OpenStreams = Streams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<Bytes>::poll_accept_recv(&mut self.inner, cx).map(|result| {
            result.map(|stream| {
                GuardedRecv::new(
                    stream,
                    self.header_limit,
                    true,
                    Some(self.connection.clone()),
                )
            })
        })
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        quic::Connection::<Bytes>::poll_accept_bidi(&mut self.inner, cx)
            .map(|result| result.map(|stream| BidiStream::new(stream, self.header_limit)))
    }

    fn opener(&self) -> Self::OpenStreams {
        Streams {
            inner: quic::Connection::<Bytes>::opener(&self.inner),
            header_limit: self.header_limit,
        }
    }
}

pub(crate) struct Streams {
    inner: h3_quinn::OpenStreams,
    header_limit: u64,
}

impl Clone for Streams {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            header_limit: self.header_limit,
        }
    }
}

impl quic::OpenStreams<Bytes> for Backend {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type BidiStream = BidiStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx)
            .map(|result| result.map(|stream| BidiStream::new(stream, self.header_limit)))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

impl quic::OpenStreams<Bytes> for Streams {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type BidiStream = BidiStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx)
            .map(|result| result.map(|stream| BidiStream::new(stream, self.header_limit)))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

pub(crate) struct BidiStream {
    send: GuardedSend,
    receive: GuardedRecv,
}

impl BidiStream {
    fn new(stream: h3_quinn::BidiStream<Bytes>, header_limit: u64) -> Self {
        let (send, receive) = quic::BidiStream::<Bytes>::split(stream);
        Self {
            send: GuardedSend {
                inner: send,
                finished: false,
            },
            receive: GuardedRecv::new(receive, header_limit, false, None),
        }
    }
}

impl quic::BidiStream<Bytes> for BidiStream {
    type SendStream = GuardedSend;
    type RecvStream = GuardedRecv;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.receive)
    }
}

impl quic::SendStream<Bytes> for BidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::<Bytes>::poll_ready(&mut self.send, cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        quic::SendStream::<Bytes>::send_data(&mut self.send, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::<Bytes>::poll_finish(&mut self.send, cx)
    }

    fn reset(&mut self, code: u64) {
        quic::SendStream::<Bytes>::reset(&mut self.send, code);
    }

    fn send_id(&self) -> StreamId {
        quic::SendStream::<Bytes>::send_id(&self.send)
    }
}

impl quic::RecvStream for BidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        quic::RecvStream::poll_data(&mut self.receive, cx)
    }

    fn stop_sending(&mut self, code: u64) {
        quic::RecvStream::stop_sending(&mut self.receive, code);
    }

    fn recv_id(&self) -> StreamId {
        quic::RecvStream::recv_id(&self.receive)
    }
}

pub(crate) struct GuardedSend {
    inner: h3_quinn::SendStream<Bytes>,
    finished: bool,
}

impl quic::SendStream<Bytes> for GuardedSend {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::<Bytes>::poll_ready(&mut self.inner, cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        quic::SendStream::<Bytes>::send_data(&mut self.inner, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let result = quic::SendStream::<Bytes>::poll_finish(&mut self.inner, cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.finished = true;
        }
        result
    }

    fn reset(&mut self, code: u64) {
        quic::SendStream::<Bytes>::reset(&mut self.inner, code);
        self.finished = true;
    }

    fn send_id(&self) -> StreamId {
        quic::SendStream::<Bytes>::send_id(&self.inner)
    }
}

impl Drop for GuardedSend {
    fn drop(&mut self) {
        if !self.finished {
            quic::SendStream::<Bytes>::reset(
                &mut self.inner,
                h3::error::Code::H3_REQUEST_CANCELLED.value(),
            );
        }
    }
}

pub(crate) struct GuardedRecv {
    inner: Option<h3_quinn::RecvStream>,
    id: StreamId,
    pending: bool,
    stopped: Option<u64>,
    budget: budget::Budget,
    connection: Option<quinn::Connection>,
}

impl GuardedRecv {
    fn new(
        stream: h3_quinn::RecvStream,
        header_limit: u64,
        unidirectional: bool,
        connection: Option<quinn::Connection>,
    ) -> Self {
        let id = quic::RecvStream::recv_id(&stream);
        Self {
            inner: Some(stream),
            id,
            pending: false,
            stopped: None,
            budget: budget::Budget::new(header_limit, unidirectional),
            connection,
        }
    }
}

impl quic::RecvStream for GuardedRecv {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(error_code) = self.stopped {
            return Poll::Ready(Err(StreamErrorIncoming::StreamTerminated { error_code }));
        }
        let result = quic::RecvStream::poll_data(self.inner.as_mut().unwrap(), cx);
        self.pending = result.is_pending();
        if let Poll::Ready(Ok(Some(bytes))) = &result
            && let Err(code) = self.budget.check(bytes)
        {
            self.stop_sending(code.value());
            if self.budget.is_control() {
                // A prefix can already include the control stream type. If
                // rejected before h3 sees that type, a plain reset would be
                // tolerated as an unclassified uni stream ending early.
                self.connection
                    .as_ref()
                    .unwrap()
                    .close(quinn::VarInt::from_u64(code.value()).unwrap(), b"");
                return Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: ConnectionErrorIncoming::ApplicationClose {
                        error_code: code.value(),
                    },
                }));
            }
            return Poll::Ready(Err(StreamErrorIncoming::StreamTerminated {
                error_code: code.value(),
            }));
        }
        result
    }

    fn stop_sending(&mut self, code: u64) {
        if self.stopped.is_some() {
            return;
        }
        if self.pending {
            // h3-quinn 0.0.10 has moved its raw stream into a private future.
            // Ownership Drop is safe and sends the native default STOP(0);
            // it cannot preserve a requested wire code in this Pending state.
            self.inner.take();
        } else {
            quic::RecvStream::stop_sending(self.inner.as_mut().unwrap(), code);
        }
        self.stopped = Some(code);
    }

    fn recv_id(&self) -> StreamId {
        self.id
    }
}

#[cfg(test)]
#[path = "quinn_h3_tests.rs"]
pub(crate) mod tests;
