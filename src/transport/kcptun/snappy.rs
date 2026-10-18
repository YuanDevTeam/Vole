//! Snappy framed stream below smux, with fixed 64-KiB chunks and CRC32C.
use crate::dispatch::BoxStream;
use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
const MAGIC: &[u8] = b"\xff\x06\0\0sNaPpY";
const CHUNK: usize = 65536;
const WRITE: usize = 16 * 1024;
pub(super) fn wrap(raw: BoxStream) -> BoxStream {
    Box::new(Snappy {
        raw,
        first_write: true,
        first_read: true,
        pending: Bytes::new(),
        input: Vec::new(),
        decoded: Bytes::new(),
        encoder: snap::raw::Encoder::new(),
        decoder: snap::raw::Decoder::new(),
    })
}
struct Snappy {
    raw: BoxStream,
    first_write: bool,
    first_read: bool,
    pending: Bytes,
    input: Vec<u8>,
    decoded: Bytes,
    encoder: snap::raw::Encoder,
    decoder: snap::raw::Decoder,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid kcptun Snappy frame")
}
fn checksum(bytes: &[u8]) -> u32 {
    crc32c::crc32c(bytes)
        .rotate_right(15)
        .wrapping_add(0xa282ead8)
}
impl Snappy {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.pending.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = ready!(Pin::new(&mut self.raw).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(n);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn exact(&mut self, cx: &mut Context<'_>, target: usize) -> Poll<io::Result<bool>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.input.len() >= target {
                return Poll::Ready(Ok(true));
            }
            let mut scratch = [0; 4096];
            let count = (target - self.input.len()).min(scratch.len());
            let mut buf = ReadBuf::new(&mut scratch[..count]);
            ready!(Pin::new(&mut self.raw).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return if self.input.is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            self.input.extend_from_slice(buf.filled());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !ready!(self.exact(cx, 4))? {
            return Poll::Ready(Ok(false));
        }
        let kind = self.input[0];
        let size = u32::from_le_bytes([self.input[1], self.input[2], self.input[3], 0]) as usize;
        if size > snap::raw::max_compress_len(CHUNK) + 4 || self.first_read && kind != 255 {
            return Poll::Ready(Err(invalid()));
        }
        if !ready!(self.exact(cx, 4 + size))? {
            return Poll::Ready(Err(invalid()));
        }
        if kind == 255 {
            if self.input.as_slice() != MAGIC {
                return Poll::Ready(Err(invalid()));
            }
            self.first_read = false;
        } else if kind == 0 || kind == 1 {
            if size < 4 {
                return Poll::Ready(Err(invalid()));
            }
            let wanted = u32::from_le_bytes(self.input[4..8].try_into().unwrap());
            let payload = &self.input[8..];
            let decoded = if kind == 1 {
                if payload.len() > CHUNK {
                    return Poll::Ready(Err(invalid()));
                }
                payload.to_vec()
            } else {
                let size = snap::raw::decompress_len(payload).map_err(|_| invalid())?;
                if size > CHUNK {
                    return Poll::Ready(Err(invalid()));
                }
                let mut output = vec![0; size];
                self.decoder
                    .decompress(payload, &mut output)
                    .map_err(|_| invalid())?;
                output
            };
            if checksum(&decoded) != wanted {
                return Poll::Ready(Err(invalid()));
            }
            self.decoded = decoded.into();
        } else if kind < 128 {
            return Poll::Ready(Err(invalid()));
        }
        self.input.clear();
        Poll::Ready(Ok(true))
    }
}
impl AsyncRead for Snappy {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(result) = this.drain(cx) {
            result?;
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if !this.decoded.is_empty() {
                let n = output.remaining().min(this.decoded.len());
                output.put_slice(&this.decoded[..n]);
                this.decoded.advance(n);
                return Poll::Ready(Ok(()));
            }
            if !ready!(this.frame(cx))? {
                return Poll::Ready(Ok(()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Snappy {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = input.len().min(WRITE);
        let input = &input[..n];
        let mut compressed = vec![0; snap::raw::max_compress_len(n)];
        let count = this
            .encoder
            .compress(input, &mut compressed)
            .map_err(|_| invalid())?;
        let (kind, payload) = if count < n {
            (0, &compressed[..count])
        } else {
            (1, input)
        };
        let mut wire = Vec::with_capacity(payload.len() + 18);
        if this.first_write {
            wire.extend_from_slice(MAGIC);
            this.first_write = false;
        }
        wire.push(kind);
        wire.extend_from_slice(&((payload.len() + 4) as u32).to_le_bytes()[..3]);
        wire.extend_from_slice(&checksum(input).to_le_bytes());
        wire.extend_from_slice(payload);
        this.pending = wire.into();
        if let Poll::Ready(result) = this.drain(cx) {
            result?;
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.raw).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.raw).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn official_snappy_framing_interoperates_across_partial_io() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let payload = vec![7; 40000];
            let (raw, mut peer) = tokio::io::duplex(37);
            let mut client = wrap(Box::new(raw));
            let expected = payload.clone();
            let peer = tokio::spawn(async move {
                let mut wire = Vec::new();
                peer.read_to_end(&mut wire).await.unwrap();
                let mut decoded = Vec::new();
                snap::read::FrameDecoder::new(wire.as_slice())
                    .read_to_end(&mut decoded)
                    .unwrap();
                assert_eq!(decoded, expected);
                let mut encoder = snap::write::FrameEncoder::new(Vec::new());
                encoder.write_all(b"peer-reply").unwrap();
                let wire = encoder.into_inner().unwrap();
                for chunk in wire.chunks(3) {
                    peer.write_all(chunk).await.unwrap();
                }
            });
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(&response, b"peer-reply");
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn oversized_compressed_input_is_rejected_before_body_allocation() {
        let (raw, mut peer) = tokio::io::duplex(64);
        let mut client = wrap(Box::new(raw));
        peer.write_all(MAGIC).await.unwrap();
        peer.write_all(&[0, 255, 255, 255]).await.unwrap();
        assert!(client.read(&mut [0; 1]).await.is_err());
    }
}
