//! Vision framing over authenticated VLESS. Wire constants follow the public
//! XTLS/Mihomo protocol; state, bounds and async ownership are Vole-owned.
use super::vision_filter::Filter;
use crate::{dispatch::BoxStream, security::vision::SpliceControl};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CONTENT_LIMIT: usize = crate::limits::VISION_CONTENT_BYTES;
pub(super) struct VisionStream {
    io: Option<BoxStream>,
    control: SpliceControl,
    uuid: [u8; 16],
    filter: Filter,
    header: [u8; 21],
    header_read: usize,
    first_read: bool,
    need_header: bool,
    content_left: usize,
    padding_left: usize,
    command: u8,
    read_done: bool,
    first_write: bool,
    write_done: bool,
    queued: Bytes,
    queued_command: u8,
}
impl VisionStream {
    pub(super) fn new(io: BoxStream, id: uuid::Uuid, control: SpliceControl) -> Self {
        Self {
            io: Some(io),
            control,
            uuid: id.into_bytes(),
            filter: Filter::default(),
            header: [0; 21],
            header_read: 0,
            first_read: true,
            need_header: true,
            content_left: 0,
            padding_left: 0,
            command: 0,
            read_done: false,
            first_write: true,
            write_done: false,
            queued: Bytes::new(),
            queued_command: 0,
        }
    }
    fn open(&mut self) -> io::Result<&mut BoxStream> {
        self.io
            .as_mut()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
    fn finish<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if matches!(result, Poll::Ready(Err(_))) {
            self.io.take();
            self.queued = Bytes::new();
        }
        result
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.queued.is_empty() {
                if self.queued_command != 0 {
                    self.write_done = true;
                    if self.queued_command == 2 {
                        self.control.write_direct();
                    }
                    self.queued_command = 0;
                }
                return Poll::Ready(Ok(()));
            }
            let io = self
                .io
                .as_mut()
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
            let count = ready!(Pin::new(io).poll_write(cx, &self.queued))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.queued.advance(count);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn read(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.queued.is_empty() || self.queued_command != 0 {
            ready!(self.drain(cx))?;
            ready!(Pin::new(self.open()?).poll_flush(cx))?;
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.read_done {
                return Pin::new(self.open()?).poll_read(cx, out);
            }
            if self.need_header {
                let size = if self.first_read { 21 } else { 5 };
                if self.header_read < size {
                    let mut part = ReadBuf::new(&mut self.header[self.header_read..size]);
                    ready!(
                        Pin::new(self.io.as_mut().ok_or(io::ErrorKind::BrokenPipe)?)
                            .poll_read(cx, &mut part)
                    )?;
                    let count = part.filled().len();
                    if count == 0 {
                        if self.header_read == 0 && !self.first_read {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.header_read += count;
                    if self.header_read < size {
                        continue;
                    }
                }
                let start = if self.first_read {
                    if self.header[..16] != self.uuid {
                        return Poll::Ready(Err(invalid()));
                    }
                    self.first_read = false;
                    16
                } else {
                    0
                };
                let frame = &self.header[start..];
                self.command = frame[0];
                if self.command > 2 {
                    return Poll::Ready(Err(invalid()));
                }
                self.content_left = u16::from_be_bytes([frame[1], frame[2]]) as usize;
                self.padding_left = u16::from_be_bytes([frame[3], frame[4]]) as usize;
                self.need_header = false;
                self.header_read = 0;
            }
            if self.content_left > 0 {
                let count = out.remaining().min(self.content_left);
                let mut part = ReadBuf::new(&mut out.initialize_unfilled()[..count]);
                ready!(
                    Pin::new(self.io.as_mut().ok_or(io::ErrorKind::BrokenPipe)?)
                        .poll_read(cx, &mut part)
                )?;
                let count = part.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                self.filter.received(part.filled());
                self.content_left -= count;
                out.advance(count);
                return Poll::Ready(Ok(()));
            }
            if self.padding_left > 0 {
                let mut discard = [0; 1024];
                let count = self.padding_left.min(discard.len());
                let mut part = ReadBuf::new(&mut discard[..count]);
                ready!(Pin::new(self.open()?).poll_read(cx, &mut part))?;
                let count = part.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                self.padding_left -= count;
                if self.padding_left > 0 {
                    continue;
                }
            }
            match self.command {
                0 => self.need_header = true,
                1 => self.read_done = true,
                2 => {
                    self.control.read_direct();
                    self.read_done = true;
                }
                _ => unreachable!(),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn write(&mut self, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        self.open()?;
        ready!(self.drain(cx))?;
        if self.write_done {
            return Pin::new(self.open()?).poll_write(cx, input);
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = input.len().min(CONTENT_LIMIT);
        let command = self.filter.command(&input[..count]);
        let padding = if count < 900 {
            if self.filter.is_tls() {
                900 - count + rand::random_range(0..500)
            } else {
                rand::random_range(0..256)
            }
        } else {
            0
        };
        let mut frame = BytesMut::with_capacity(count + padding + 21);
        if self.first_write {
            frame.extend_from_slice(&self.uuid);
            self.first_write = false;
        }
        frame.put_u8(command);
        frame.put_u16(count as u16);
        frame.put_u16(padding as u16);
        frame.extend_from_slice(&input[..count]);
        for _ in 0..padding {
            frame.put_u8(rand::random());
        }
        self.queued = frame.freeze();
        self.queued_command = command;
        Poll::Ready(Ok(count))
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Vision frame")
}
impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let result = self.read(cx, out);
        self.finish(result)
    }
}
impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = self.write(cx, buf);
        self.finish(result)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = (|| {
            ready!(self.drain(cx))?;
            Pin::new(self.open()?).poll_flush(cx)
        })();
        self.finish(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = (|| {
            ready!(self.drain(cx))?;
            ready!(Pin::new(self.open()?).poll_flush(cx))?;
            Pin::new(self.open()?).poll_shutdown(cx)
        })();
        self.finish(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn frame(first: bool, command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let mut wire = if first { vec![7; 16] } else { Vec::new() };
        wire.push(command);
        wire.extend((content.len() as u16).to_be_bytes());
        wire.extend((padding as u16).to_be_bytes());
        wire.extend(content);
        wire.extend(vec![0; padding]);
        wire
    }

    #[tokio::test]
    async fn vision_fragmented_headers_content_padding_and_cancelled_reads_keep_raw_tail() {
        let mut wire = frame(true, 0, b"abc", 7);
        wire.extend(frame(false, 2, b"def", 3));
        wire.extend(b"raw-tail");
        for cut in 0..wire.len() {
            let (io, mut peer) = tokio::io::duplex(4096);
            let mut stream = VisionStream::new(
                Box::new(io),
                uuid::Uuid::from_bytes([7; 16]),
                SpliceControl::default(),
            );
            peer.write_all(&wire[..cut]).await.unwrap();
            let mut received = Vec::new();
            assert!(
                tokio::time::timeout(Duration::from_millis(1), stream.read_to_end(&mut received))
                    .await
                    .is_err()
            );
            peer.write_all(&wire[cut..]).await.unwrap();
            peer.shutdown().await.unwrap();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"abcdefraw-tail");
        }
    }

    #[tokio::test]
    async fn vision_invalid_uuid_command_and_truncation_poison_the_stream() {
        let good = frame(true, 0, b"content", 4);
        let mut invalid_uuid = good.clone();
        invalid_uuid[0] ^= 1;
        let mut invalid_command = good.clone();
        invalid_command[16] = 3;
        for wire in (0..good.len())
            .map(|n| good[..n].to_vec())
            .chain([invalid_uuid, invalid_command])
        {
            let (io, mut peer) = tokio::io::duplex(4096);
            let mut stream = VisionStream::new(
                Box::new(io),
                uuid::Uuid::from_bytes([7; 16]),
                SpliceControl::default(),
            );
            peer.write_all(&wire).await.unwrap();
            peer.shutdown().await.unwrap();
            assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
            assert!(stream.write_all(b"not-replayed").await.is_err());
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn vision_bounded_partial_writes_flush_and_close_preserve_all_plaintext() {
        let (io, mut peer) = tokio::io::duplex(31);
        let mut stream = VisionStream::new(
            Box::new(io),
            uuid::Uuid::from_bytes([7; 16]),
            SpliceControl::default(),
        );
        let reader = tokio::spawn(async move {
            let mut uuid = [0; 16];
            peer.read_exact(&mut uuid).await.unwrap();
            assert_eq!(uuid, [7; 16]);
            let mut data = Vec::new();
            loop {
                let command = peer.read_u8().await.unwrap();
                let content = peer.read_u16().await.unwrap() as usize;
                let padding = peer.read_u16().await.unwrap() as usize;
                assert!(content <= CONTENT_LIMIT && padding <= 1399);
                let mut part = vec![0; content + padding];
                peer.read_exact(&mut part).await.unwrap();
                data.extend(&part[..content]);
                if command == 1 {
                    break;
                }
                assert_eq!(command, 0);
            }
            peer.read_to_end(&mut data).await.unwrap();
            data
        });
        let payload = vec![0x5a; 128 * 1024];
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), payload);
    }
}
