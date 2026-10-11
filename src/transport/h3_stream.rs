//! Request-stream adapter for acknowledged QUIC upload completion. h3-quinn
//! still owns the HTTP/3 control streams; h3 owns all HTTP encoding. Quinn's
//! finish only queues FIN, so a logical close must also wait for stopped(None)
//! before its last lease can close the physical connection. Each protocol
//! wrapper owns its close deadline and node Stop can cancel every wait.
use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, ReadBuf};

type Operation<T> = Pin<Box<dyn Future<Output = Result<T, StreamErrorIncoming>> + Send>>;

pub(crate) struct Connection {
    control: h3_quinn::Connection,
    open: OpenStreams,
}

impl Connection {
    pub fn new(connection: quinn::Connection) -> Self {
        let control = h3_quinn::Connection::new(connection.clone());
        let open = OpenStreams {
            control: <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&control),
            connection,
            pending: None,
        };
        Self { control, open }
    }
}

impl quic::Connection<Bytes> for Connection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.control, cx)
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream, ConnectionErrorIncoming>> {
        // Clients advertise a zero incoming-bidirectional-stream limit. Keep
        // upstream's connection-error handling if the peer violates it.
        let _unexpected = ready!(
            <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_bidi(
                &mut self.control,
                cx
            )
        )?;
        Poll::Ready(Err(ConnectionErrorIncoming::InternalError(
            "unexpected HTTP/3 request stream".into(),
        )))
    }
    fn opener(&self) -> OpenStreams {
        self.open.clone()
    }
}

pub(crate) struct OpenStreams {
    control: h3_quinn::OpenStreams,
    connection: quinn::Connection,
    pending: Option<Operation<(quinn::SendStream, quinn::RecvStream)>>,
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            control: self.control.clone(),
            connection: self.connection.clone(),
            pending: None,
        }
    }
}

impl quic::OpenStreams<Bytes> for OpenStreams {
    type BidiStream = BidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream, StreamErrorIncoming>> {
        let pending = self.pending.get_or_insert_with(|| {
            let connection = self.connection.clone();
            Box::pin(async move {
                connection.open_bi().await.map_err(|error| {
                    StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error: ConnectionErrorIncoming::Undefined(Arc::new(error)),
                    }
                })
            })
        });
        let result = ready!(pending.as_mut().poll(cx));
        self.pending = None;
        let (send, recv) = result?;
        Poll::Ready(Ok(BidiStream {
            send: SendStream {
                raw: send,
                queued: None,
                completion: None,
                finished: false,
            },
            recv: RecvStream(recv),
        }))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.control.poll_open_send(cx)
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::close(&mut self.control, code, reason);
    }
}

impl quic::OpenStreams<Bytes> for Connection {
    type BidiStream = BidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream, StreamErrorIncoming>> {
        self.open.poll_open_bidi(cx)
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.open.poll_open_send(cx)
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.open.close(code, reason);
    }
}

pub(crate) struct BidiStream {
    send: SendStream,
    recv: RecvStream,
}
pub(crate) struct SendStream {
    raw: quinn::SendStream,
    queued: Option<WriteBuf<Bytes>>,
    completion: Option<Operation<()>>,
    finished: bool,
}
pub(crate) struct RecvStream(quinn::RecvStream);

fn stream_error(error: impl std::error::Error + Send + Sync + 'static) -> StreamErrorIncoming {
    StreamErrorIncoming::Unknown(Box::new(error))
}

impl quic::SendStream<Bytes> for SendStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(data) = &mut self.queued {
            while data.has_remaining() {
                let count = ready!(Pin::new(&mut self.raw).poll_write(cx, data.chunk()))
                    .map_err(stream_error)?;
                data.advance(count);
            }
        }
        self.queued = None;
        Poll::Ready(Ok(()))
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_ready(cx))?;
        if self.completion.is_none() {
            self.raw.finish().map_err(stream_error)?;
            let stopped = self.raw.stopped();
            self.completion = Some(Box::pin(async move {
                match stopped.await.map_err(stream_error)? {
                    None => Ok(()),
                    Some(code) => Err(StreamErrorIncoming::StreamTerminated {
                        error_code: code.into_inner(),
                    }),
                }
            }));
        }
        let result = ready!(self.completion.as_mut().unwrap().as_mut().poll(cx));
        self.completion = None;
        self.finished = result.is_ok();
        Poll::Ready(result)
    }
    fn send_data<D: Into<WriteBuf<Bytes>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        if self.queued.is_some() || self.completion.is_some() || self.finished {
            return Err(stream_error(std::io::Error::other(
                "HTTP/3 upload is not writable",
            )));
        }
        self.queued = Some(data.into());
        Ok(())
    }
    fn reset(&mut self, code: u64) {
        let _ = self
            .raw
            .reset(quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX));
    }
    fn send_id(&self) -> StreamId {
        u64::from(self.raw.id()).try_into().expect("QUIC stream ID")
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let mut bytes = [0; 16384];
        let mut output = ReadBuf::new(&mut bytes);
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut output)).map_err(stream_error)?;
        Poll::Ready(Ok(
            (!output.filled().is_empty()).then(|| Bytes::copy_from_slice(output.filled()))
        ))
    }
    fn stop_sending(&mut self, code: u64) {
        let _ = self
            .0
            .stop(quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX));
    }
    fn recv_id(&self) -> StreamId {
        u64::from(self.0.id()).try_into().expect("QUIC stream ID")
    }
}

impl quic::SendStream<Bytes> for BidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }
    fn send_data<D: Into<WriteBuf<Bytes>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }
    fn reset(&mut self, code: u64) {
        self.send.reset(code);
    }
    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}
impl quic::RecvStream for BidiStream {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }
    fn stop_sending(&mut self, code: u64) {
        self.recv.stop_sending(code);
    }
    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}
impl quic::BidiStream<Bytes> for BidiStream {
    type SendStream = SendStream;
    type RecvStream = RecvStream;
    fn split(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }
}
