//! Vole regressions over bounded in-memory QUIC streams, without UDP endpoints.

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use crate::quic::{RecvStream as _, SendStream as _};
use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use http::{Request, Response};

use crate::{
    error::Code,
    ext::Protocol,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};

const PIPE_BYTES: usize = 16 * 1024;
const MAX_STREAMS: usize = 16;

#[derive(Default)]
struct Pipe {
    buffers: VecDeque<Bytes>,
    bytes: usize,
    ended: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

struct Send {
    id: StreamId,
    pipe: Arc<Mutex<Pipe>>,
}

struct Recv {
    id: StreamId,
    pipe: Arc<Mutex<Pipe>>,
}

fn stream(id: u64) -> (Send, Recv) {
    let pipe = Arc::new(Mutex::new(Pipe::default()));
    (
        Send {
            id: StreamId(id),
            pipe: pipe.clone(),
        },
        Recv {
            id: StreamId(id),
            pipe,
        },
    )
}

fn stream_error() -> StreamErrorIncoming {
    StreamErrorIncoming::Unknown(Box::new(io::Error::other("memory stream capacity")))
}

impl quic::SendStream<Bytes> for Send {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let mut pipe = self.pipe.lock().unwrap();
        if pipe.ended {
            return Poll::Ready(Err(stream_error()));
        }
        if pipe.bytes == PIPE_BYTES {
            pipe.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        let mut data = data.into();
        let len = data.remaining();
        let mut pipe = self.pipe.lock().unwrap();
        if pipe.ended || len > PIPE_BYTES - pipe.bytes {
            return Err(stream_error());
        }
        if len != 0 {
            let mut bytes = Vec::with_capacity(len);
            while data.has_remaining() {
                let chunk = data.chunk();
                bytes.extend_from_slice(chunk);
                let len = chunk.len();
                data.advance(len);
            }
            pipe.bytes += len;
            pipe.buffers.push_back(Bytes::from(bytes));
            if let Some(reader) = pipe.reader.take() {
                reader.wake();
            }
        }
        Ok(())
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.end();
        Poll::Ready(Ok(()))
    }

    fn reset(&mut self, _reset_code: u64) {
        self.end();
    }
    fn send_id(&self) -> StreamId {
        self.id
    }
}

impl Send {
    fn end(&self) {
        let mut pipe = self.pipe.lock().unwrap();
        pipe.ended = true;
        if let Some(reader) = pipe.reader.take() {
            reader.wake();
        }
        if let Some(writer) = pipe.writer.take() {
            writer.wake();
        }
    }
}

impl Drop for Send {
    fn drop(&mut self) {
        self.end();
    }
}

impl quic::RecvStream for Recv {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let mut pipe = self.pipe.lock().unwrap();
        if let Some(data) = pipe.buffers.pop_front() {
            pipe.bytes -= data.len();
            if let Some(writer) = pipe.writer.take() {
                writer.wake();
            }
            return Poll::Ready(Ok(Some(data)));
        }
        if pipe.ended {
            return Poll::Ready(Ok(None));
        }
        pipe.reader = Some(cx.waker().clone());
        Poll::Pending
    }

    fn stop_sending(&mut self, _error_code: u64) {
        let mut pipe = self.pipe.lock().unwrap();
        pipe.ended = true;
        if let Some(writer) = pipe.writer.take() {
            writer.wake();
        }
    }

    fn recv_id(&self) -> StreamId {
        self.id
    }
}

struct Bidi {
    send: Send,
    recv: Recv,
}

impl quic::SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }
    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }
    fn send_id(&self) -> StreamId {
        self.send.id
    }
}

impl quic::RecvStream for Bidi {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }
    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }
    fn recv_id(&self) -> StreamId {
        self.recv.id
    }
}

impl quic::BidiStream<Bytes> for Bidi {
    type SendStream = Send;
    type RecvStream = Recv;
    fn split(self) -> (Send, Recv) {
        (self.send, self.recv)
    }
}

struct Endpoint {
    recv: VecDeque<Recv>,
    bidi: VecDeque<Bidi>,
    next_uni: u64,
    next_bidi: u64,
    accept_recv: Option<Waker>,
    accept_bidi: Option<Waker>,
    closed: Option<u64>,
}

#[derive(Clone)]
struct Memory {
    local: Arc<Mutex<Endpoint>>,
    peer: Arc<Mutex<Endpoint>>,
}

fn pair() -> (Memory, Memory) {
    let endpoint = |side: u64| {
        Arc::new(Mutex::new(Endpoint {
            recv: VecDeque::new(),
            bidi: VecDeque::new(),
            next_uni: 2 + side,
            next_bidi: side,
            accept_recv: None,
            accept_bidi: None,
            closed: None,
        }))
    };
    let client = endpoint(0);
    let server = endpoint(1);
    (
        Memory {
            local: client.clone(),
            peer: server.clone(),
        },
        Memory {
            local: server,
            peer: client,
        },
    )
}

impl quic::OpenStreams<Bytes> for Memory {
    type BidiStream = Bidi;
    type SendStream = Send;

    fn poll_open_bidi(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        let mut local = self.local.lock().unwrap();
        let mut peer = self.peer.lock().unwrap();
        if local.closed.is_some() || peer.closed.is_some() || peer.bidi.len() == MAX_STREAMS {
            return Poll::Ready(Err(stream_error()));
        }
        let id = local.next_bidi;
        local.next_bidi += 4;
        let (send, peer_recv) = stream(id);
        let (peer_send, recv) = stream(id);
        peer.bidi.push_back(Bidi {
            send: peer_send,
            recv: peer_recv,
        });
        if let Some(waker) = peer.accept_bidi.take() {
            waker.wake();
        }
        Poll::Ready(Ok(Bidi { send, recv }))
    }

    fn poll_open_send(&mut self, _cx: &mut Context<'_>) -> Poll<Result<Send, StreamErrorIncoming>> {
        let mut local = self.local.lock().unwrap();
        let mut peer = self.peer.lock().unwrap();
        if local.closed.is_some() || peer.closed.is_some() || peer.recv.len() == MAX_STREAMS {
            return Poll::Ready(Err(stream_error()));
        }
        let id = local.next_uni;
        local.next_uni += 4;
        let (send, recv) = stream(id);
        peer.recv.push_back(recv);
        if let Some(waker) = peer.accept_recv.take() {
            waker.wake();
        }
        Poll::Ready(Ok(send))
    }

    fn close(&mut self, code: Code, _reason: &[u8]) {
        for endpoint in [&self.local, &self.peer] {
            let mut endpoint = endpoint.lock().unwrap();
            endpoint.closed = Some(code.value());
            if let Some(waker) = endpoint.accept_recv.take() {
                waker.wake();
            }
            if let Some(waker) = endpoint.accept_bidi.take() {
                waker.wake();
            }
        }
    }
}

impl quic::Connection<Bytes> for Memory {
    type RecvStream = Recv;
    type OpenStreams = Self;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Recv, ConnectionErrorIncoming>> {
        let mut local = self.local.lock().unwrap();
        if let Some(error_code) = local.closed {
            return Poll::Ready(Err(ConnectionErrorIncoming::ApplicationClose {
                error_code,
            }));
        }
        if let Some(recv) = local.recv.pop_front() {
            return Poll::Ready(Ok(recv));
        }
        local.accept_recv = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi, ConnectionErrorIncoming>> {
        let mut local = self.local.lock().unwrap();
        if let Some(error_code) = local.closed {
            return Poll::Ready(Err(ConnectionErrorIncoming::ApplicationClose {
                error_code,
            }));
        }
        if let Some(bidi) = local.bidi.pop_front() {
            return Poll::Ready(Ok(bidi));
        }
        local.accept_bidi = Some(cx.waker().clone());
        Poll::Pending
    }

    fn opener(&self) -> Self {
        self.clone()
    }
}

#[tokio::test]
async fn vole_peer_settings_wait_for_real_control_frame_and_preserve_presence() {
    for modern in [false, true] {
        let (raw_client, raw_server) = pair();
        let mut client_builder = crate::client::builder();
        client_builder.send_grease(false);
        let (mut client, sender) = client_builder.build(raw_client).await.unwrap();
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(client.poll_peer_settings(&mut cx).is_pending());

        let mut server_builder = crate::server::builder();
        server_builder
            .send_grease(false)
            .enable_extended_connect(true)
            .enable_datagram(modern);
        server_builder.config.settings.legacy_datagram = Some(true);
        let _server = server_builder.build(raw_server).await.unwrap();
        let settings = poll_fn(|cx| client.poll_peer_settings(cx)).await.unwrap();
        assert_eq!(settings.modern_datagram_setting(), Some(modern));
        assert_eq!(settings.legacy_datagram_setting(), Some(true));
        assert_eq!(settings.enable_datagram(), modern);
        assert!(settings.enable_extended_connect());
        drop(sender);
    }
}

#[tokio::test]
async fn vole_cf_connect_ip_headers_roundtrip_over_actual_h3_request_stream() {
    let (raw_client, raw_server) = pair();
    let mut client_builder = crate::client::builder();
    client_builder.send_grease(false).enable_datagram(true);
    let (mut client, mut sender) = client_builder.build(raw_client).await.unwrap();
    let mut server_builder = crate::server::builder();
    server_builder
        .send_grease(false)
        .enable_extended_connect(true)
        .enable_datagram(true);
    let mut server = server_builder.build(raw_server).await.unwrap();
    poll_fn(|cx| client.poll_peer_settings(cx)).await.unwrap();

    let request = Request::builder()
        .method("CONNECT")
        .uri("https://proxy.example/cf-connect-ip")
        .extension(Protocol::CF_CONNECT_IP)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    let resolver = server.accept().await.unwrap().unwrap();
    let (request, mut peer) = resolver.resolve_request().await.unwrap();
    assert_eq!(request.method(), "CONNECT");
    assert_eq!(request.uri().authority().unwrap().as_str(), "proxy.example");
    assert_eq!(request.uri().path(), "/cf-connect-ip");
    assert_eq!(
        request.extensions().get::<Protocol>(),
        Some(&Protocol::CF_CONNECT_IP)
    );
    assert_eq!(request.headers()["capsule-protocol"], "?1");
    peer.send_response(
        Response::builder()
            .status(200)
            .header("capsule-protocol", "?1")
            .body(())
            .unwrap(),
    )
    .await
    .unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["capsule-protocol"], "?1");
}
