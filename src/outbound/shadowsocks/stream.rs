use crate::dispatch::BoxStream;
use shadowsocks::{
    ServerConfig,
    context::SharedContext,
    relay::{
        socks5::Address,
        tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
    },
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::limits::SHADOWSOCKS_WRITE_CHUNK as WRITE_CHUNK;

const MAX_PADDING: usize = 900;

enum Start {
    Fresh(Address),
    EmptyPending,
    EmptyFlushing,
    Started,
}

pub(super) struct SsStream {
    inner: CryptoStream<BoxStream>,
    context: SharedContext,
    start: Start,
    pending: Option<Vec<u8>>,
    response_checked: bool,
}

impl SsStream {
    pub(super) fn new(
        context: SharedContext,
        io: BoxStream,
        config: &ServerConfig,
        target: Address,
    ) -> Self {
        Self {
            inner: CryptoStream::from_stream_with_identity(
                &context,
                io,
                StreamType::Client,
                config.method(),
                config.key(),
                config.identity_keys(),
                None,
            ),
            context,
            start: Start::Fresh(target),
            pending: None,
            response_checked: false,
        }
    }

    fn first_packet(&mut self, payload: &[u8]) -> Vec<u8> {
        let Start::Fresh(target) = std::mem::replace(&mut self.start, Start::Started) else {
            unreachable!("Shadowsocks target header was already consumed");
        };
        let padding = if payload.is_empty() {
            rand::random_range(1..=MAX_PADDING)
        } else {
            0
        };
        request_packet(&target, payload, padding)
    }

    fn begin_empty(&mut self) {
        self.pending = Some(self.first_packet(&[]));
        self.start = Start::EmptyPending;
    }

    fn finish_empty(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.start, Start::EmptyPending) {
            ready!(self.finish_write(cx))?;
            self.start = Start::EmptyFlushing;
        }
        if matches!(self.start, Start::EmptyFlushing) {
            // Buffered carriers need a flush when no application payload can
            // make the target header reach the server.
            ready!(self.inner.poll_flush(cx)).map_err(|error| super::safe_io(error.into()))?;
            self.start = Start::Started;
        }
        Poll::Ready(Ok(()))
    }

    fn finish_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(bytes) = &self.pending {
            // The official writer reports the retry slice's length after
            // draining its frame, so retain the original input across Pending.
            let written = ready!(Pin::new(&mut self.inner).poll_write_encrypted(cx, bytes))
                .map_err(|error| super::safe_io(error.into()))?;
            if written != bytes.len() {
                return Poll::Ready(Err(io::Error::other(
                    "Shadowsocks buffered write was incomplete",
                )));
            }
            self.pending = None;
        }
        Poll::Ready(Ok(()))
    }
}

// Only the request prelude is assembled here. The official CryptoStream owns
// salts, EIH, AEAD framing and authentication. Initialize before randomizing so
// every byte is defined even when an allocator reuses old storage.
fn request_packet(target: &Address, payload: &[u8], padding: usize) -> Vec<u8> {
    let mut packet = Vec::with_capacity(target.serialized_len() + 2 + padding + payload.len());
    target.write_to_buf(&mut packet);
    packet.extend_from_slice(&(padding as u16).to_be_bytes());
    let start = packet.len();
    packet.resize(start + padding, 0);
    rand::fill(&mut packet[start..]);
    packet.extend_from_slice(payload);
    packet
}

impl AsyncRead for SsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if matches!(this.start, Start::Fresh(_)) {
            this.begin_empty();
        }
        ready!(this.finish_empty(cx))?;
        // Advance accepted writes without blocking reads on a full write side.
        if let Poll::Ready(result) = this.finish_write(cx) {
            result?;
        }
        let result = Pin::new(&mut this.inner)
            .poll_read_decrypted(cx, &this.context, buf)
            .map_err(|error| super::safe_io(error.into()));
        if !this.response_checked
            && let Some(request_nonce) = this.inner.received_request_nonce()
        {
            // This nonce is exposed only after authenticating the response
            // header. Bind it before returning plaintext, even when the body
            // remains pending.
            if request_nonce != this.inner.sent_nonce() {
                return Poll::Ready(Err(super::safe_io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks response did not match its request",
                ))));
            }
            this.response_checked = true;
        }
        result
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.finish_empty(cx))?;
        ready!(this.finish_write(cx))?;
        if buf.is_empty() {
            if matches!(this.start, Start::Fresh(_)) {
                this.begin_empty();
                ready!(this.finish_empty(cx))?;
            }
            return Poll::Ready(Ok(0));
        }
        let payload = &buf[..buf.len().min(WRITE_CHUNK)];
        if matches!(this.start, Start::Fresh(_)) {
            this.pending = Some(this.first_packet(payload));
            // Accept one bounded payload while keeping the complete first
            // frame stable for reads, flush and later writes under backpressure.
            if let Poll::Ready(result) = this.finish_write(cx) {
                result?;
            }
            return Poll::Ready(Ok(payload.len()));
        }
        match Pin::new(&mut this.inner).poll_write_encrypted(cx, payload) {
            Poll::Pending => {
                this.pending = Some(payload.to_vec());
                Poll::Ready(Ok(payload.len()))
            }
            Poll::Ready(result) => {
                Poll::Ready(result.map_err(|error| super::safe_io(error.into())))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.finish_empty(cx))?;
        ready!(this.finish_write(cx))?;
        this.inner
            .poll_flush(cx)
            .map_err(|error| super::safe_io(error.into()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Write-half EOF can still receive a response to an empty upload.
        // Drop/cancellation never calls this or creates a target header.
        if matches!(this.start, Start::Fresh(_)) {
            this.begin_empty();
        }
        ready!(this.finish_empty(cx))?;
        ready!(this.finish_write(cx))?;
        this.inner
            .poll_shutdown(cx)
            .map_err(|error| super::safe_io(error.into()))
    }
}
