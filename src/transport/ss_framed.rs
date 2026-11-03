//! Bounded adapters for simple-obfs and v2ray-plugin's single mux channel.
//! These are protocol encoders, not full TLS or a general V2Ray multiplexer.
use crate::dispatch::BoxStream;
use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
const CHUNK: usize = 16 * 1024;

pub(crate) enum Kind {
    Http { host: String, port: u16 },
    Tls { host: String },
    V2rayMux,
}
pub(crate) fn wrap(raw: BoxStream, kind: Kind) -> BoxStream {
    Box::new(Framed {
        raw,
        kind,
        first_write: true,
        first_read: true,
        write: Bytes::new(),
        head: Vec::new(),
        remaining: 0,
        eof: false,
        closing: false,
    })
}
struct Framed {
    raw: BoxStream,
    kind: Kind,
    first_write: bool,
    first_read: bool,
    write: Bytes,
    head: Vec<u8>,
    remaining: usize,
    eof: bool,
    closing: bool,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Shadowsocks plugin frame",
    )
}
impl Framed {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.write.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = ready!(Pin::new(&mut self.raw).poll_write(cx, &self.write))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write.advance(n);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn encode(&mut self, input: &[u8]) -> io::Result<usize> {
        let n = input.len().min(CHUNK);
        let input = &input[..n];
        let mut wire = Vec::with_capacity(n + 512);
        match &self.kind {
            Kind::Http { host, port } if self.first_write => {
                use base64::Engine;
                let mut nonce = [0; 16];
                rand::fill(&mut nonce);
                let authority = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.clone()
                };
                let authority = if *port == 80 {
                    authority
                } else {
                    format!("{authority}:{port}")
                };
                let key = base64::engine::general_purpose::URL_SAFE.encode(nonce);
                wire.extend_from_slice(format!("GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nContent-Length: {n}\r\n\r\n").as_bytes());
            }
            Kind::Http { .. } => {}
            Kind::Tls { host } if self.first_write => {
                wire = client_hello(input, host)?;
            }
            Kind::Tls { .. } => {
                wire.extend_from_slice(&[23, 3, 3]);
                wire.extend_from_slice(&(n as u16).to_be_bytes());
            }
            Kind::V2rayMux => {
                if self.first_write {
                    wire.extend_from_slice(&[0, 12, 0, 0, 1, 0, 1, 0, 0, 1, 127, 0, 0, 1]);
                }
                wire.extend_from_slice(&[0, 4, 0, 0, 2, 1]);
                wire.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        if !matches!(self.kind, Kind::Tls { .. }) || !self.first_write {
            wire.extend_from_slice(input);
        }
        self.first_write = false;
        self.write = wire.into();
        Ok(n)
    }
    fn read_head(&mut self, cx: &mut Context<'_>, target: usize) -> Poll<io::Result<bool>> {
        if target > 16 * 1024 {
            return Poll::Ready(Err(invalid()));
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if self.head.len() >= target {
                return Poll::Ready(Ok(true));
            }
            let mut scratch = [0; 512];
            let count = (target - self.head.len()).min(scratch.len());
            let mut output = ReadBuf::new(&mut scratch[..count]);
            ready!(Pin::new(&mut self.raw).poll_read(cx, &mut output))?;
            if output.filled().is_empty() {
                return if self.head.is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            self.head.extend_from_slice(output.filled());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn next_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &self.kind {
            Kind::Http { .. } => {
                if !self.first_read {
                    self.remaining = usize::MAX;
                    return Poll::Ready(Ok(()));
                }
                for _ in 0..crate::limits::IO_POLL_BUDGET {
                    let target = self.head.len() + 1;
                    if !ready!(self.read_head(cx, target))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    if self.head.ends_with(b"\r\n\r\n") {
                        let prefix = &self.head[..self.head.len().min(13)];
                        if !prefix.starts_with(b"HTTP/1.1 101 ")
                            && !prefix.starts_with(b"HTTP/1.0 101 ")
                        {
                            return Poll::Ready(Err(invalid()));
                        }
                        self.head.clear();
                        self.first_read = false;
                        self.remaining = usize::MAX;
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            Kind::Tls { .. } => {
                let target = if self.first_read { 107 } else { 5 };
                if !ready!(self.read_head(cx, target))? {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                let h = &self.head;
                if self.first_read {
                    if h[..3] != [22, 3, 1]
                        || h[96..102] != [20, 3, 3, 0, 1, 1]
                        || h[102..105] != [22, 3, 3]
                    {
                        return Poll::Ready(Err(invalid()));
                    }
                } else if h[..3] != [23, 3, 3] {
                    return Poll::Ready(Err(invalid()));
                }
                self.remaining =
                    usize::from(u16::from_be_bytes(h[target - 2..].try_into().unwrap()));
                if self.remaining > CHUNK {
                    return Poll::Ready(Err(invalid()));
                }
                self.head.clear();
                self.first_read = false;
                return Poll::Ready(Ok(()));
            }
            Kind::V2rayMux => {
                if !ready!(self.read_head(cx, 2))? {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                let metadata = usize::from(u16::from_be_bytes(self.head[..2].try_into().unwrap()));
                if !(4..=512).contains(&metadata) {
                    return Poll::Ready(Err(invalid()));
                }
                if !ready!(self.read_head(cx, 2 + metadata))? {
                    return Poll::Ready(Err(invalid()));
                }
                if self.head[2..4] != [0, 0]
                    || !matches!(self.head[4], 1..=4)
                    || self.head[5] & !3 != 0
                {
                    return Poll::Ready(Err(invalid()));
                }
                let end = self.head[4] == 3;
                let error = self.head[5] & 2 != 0;
                if self.head[5] & 1 != 0 {
                    if !ready!(self.read_head(cx, 4 + metadata))? {
                        return Poll::Ready(Err(invalid()));
                    }
                    self.remaining = usize::from(u16::from_be_bytes(
                        self.head[2 + metadata..4 + metadata].try_into().unwrap(),
                    ));
                }
                self.head.clear();
                if error {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
                }
                self.eof = end;
                return Poll::Ready(Ok(()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncRead for Framed {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // An accepted buffered write must progress when the peer waits for it;
        // its backpressure never prevents consuming an already available reply.
        if let Poll::Ready(result) = this.drain(cx) {
            result?;
        }
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            if this.remaining == 0 && !this.eof {
                ready!(this.next_frame(cx))?;
            }
            if this.eof && this.remaining == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.remaining == 0 {
                continue;
            }
            let count = output.remaining().min(this.remaining);
            let mut limited = ReadBuf::new(output.initialize_unfilled_to(count));
            ready!(Pin::new(&mut this.raw).poll_read(cx, &mut limited))?;
            let n = limited.filled().len();
            if n == 0 && this.remaining != usize::MAX {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            output.advance(n);
            if this.remaining != usize::MAX {
                this.remaining -= n;
            }
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Framed {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = this.encode(input)?;
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
        if !this.closing {
            this.closing = true;
            if matches!(this.kind, Kind::V2rayMux) {
                this.write = Bytes::from_static(&[0, 4, 0, 0, 3, 0]);
            }
        }
        ready!(this.drain(cx))?;
        Pin::new(&mut this.raw).poll_shutdown(cx)
    }
}
fn client_hello(data: &[u8], host: &str) -> io::Result<Vec<u8>> {
    if host.len() > 255 || data.len() > CHUNK {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut hello = vec![1, 0, 0, 0, 3, 3];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs() as u32;
    hello.extend_from_slice(&timestamp.to_be_bytes());
    let mut random = [0; 60];
    rand::fill(&mut random);
    hello.extend_from_slice(&random[..28]);
    hello.push(32);
    hello.extend_from_slice(&random[28..]);
    // The simple-obfs server's first ticket starts at byte 142 of this fixed
    // TLS-shaped envelope. All cipher/group/signature IDs are public IANA values.
    hello.extend_from_slice(&56u16.to_be_bytes());
    for _ in 0..2 {
        for cipher in [
            0xc02cu16, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028,
            0x006b, 0xc023, 0xc027, 0x0067,
        ] {
            hello.extend_from_slice(&cipher.to_be_bytes());
        }
    }
    hello.extend_from_slice(&[1, 0]);
    let mut extensions = Vec::new();
    let mut extension = |id: u16, value: &[u8]| {
        extensions.extend_from_slice(&id.to_be_bytes());
        extensions.extend_from_slice(&(value.len() as u16).to_be_bytes());
        extensions.extend_from_slice(value);
    };
    extension(35, data);
    let mut sni = Vec::with_capacity(host.len() + 5);
    sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    extension(0, &sni);
    extension(11, &[3, 1, 0, 2]);
    extension(10, &[0, 8, 0, 29, 0, 23, 0, 25, 0, 24]);
    let mut signatures = vec![0, 30];
    for pair in [
        (6, 1),
        (6, 2),
        (6, 3),
        (5, 1),
        (5, 2),
        (5, 3),
        (4, 1),
        (4, 2),
        (4, 3),
        (3, 1),
        (3, 2),
        (3, 3),
        (2, 1),
        (2, 2),
        (2, 3),
    ] {
        signatures.extend_from_slice(&[pair.0, pair.1]);
    }
    extension(13, &signatures);
    extension(22, &[]);
    extension(23, &[]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let size = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&size.to_be_bytes()[1..]);
    let mut wire = vec![22, 3, 1];
    wire.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    wire.extend_from_slice(&hello);
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn http_obfs_preserves_fragmented_head_tail_and_half_close() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (raw, mut peer) = tokio::io::duplex(23);
            let mut client = wrap(
                Box::new(raw),
                Kind::Http {
                    host: "cover.invalid".into(),
                    port: 443,
                },
            );
            let peer = tokio::spawn(async move {
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(peer.read_u8().await.unwrap());
                }
                let head = String::from_utf8(header).unwrap();
                assert!(head.contains("Content-Length: 7\r\n"));
                let mut body = [0; 7];
                peer.read_exact(&mut body).await.unwrap();
                assert_eq!(&body, b"payload");
                for chunk in b"HTTP/1.1 101 Switching Protocols\r\n\r\nreply".chunks(3) {
                    peer.write_all(chunk).await.unwrap();
                }
                let mut rest = Vec::new();
                peer.read_to_end(&mut rest).await.unwrap();
                assert_eq!(&rest, b"tail");
                peer.write_all(b"after-fin").await.unwrap();
            });
            assert_eq!(client.write(&[]).await.unwrap(), 0);
            client.write_all(b"payload").await.unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
            client.write_all(b"tail").await.unwrap();
            client.shutdown().await.unwrap();
            let mut tail = Vec::new();
            client.read_to_end(&mut tail).await.unwrap();
            assert_eq!(&tail, b"after-fin");
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn v2ray_mux_metadata_and_final_frame_keep_payload_boundaries() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (raw, mut peer) = tokio::io::duplex(31);
            let mut client = wrap(Box::new(raw), Kind::V2rayMux);
            let peer = tokio::spawn(async move {
                let mut header = [0; 22];
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(
                    &header[..14],
                    &[0, 12, 0, 0, 1, 0, 1, 0, 0, 1, 127, 0, 0, 1]
                );
                assert_eq!(&header[14..], &[0, 4, 0, 0, 2, 1, 0, 4]);
                let mut payload = [0; 4];
                peer.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"data");
                peer.write_all(&[0, 4, 0, 0, 4, 0, 0, 4, 0, 0, 2, 1, 0, 5])
                    .await
                    .unwrap();
                peer.write_all(b"reply").await.unwrap();
                let mut end = [0; 6];
                peer.read_exact(&mut end).await.unwrap();
                assert_eq!(end, [0, 4, 0, 0, 3, 0]);
            });
            client.write_all(b"data").await.unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
            client.shutdown().await.unwrap();
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }
    #[test]
    fn tls_obfs_ticket_layout_is_fixed_but_nonces_are_fresh() {
        let first = client_hello(b"payload", "cover.invalid").unwrap();
        let second = client_hello(b"payload", "cover.invalid").unwrap();
        assert_eq!(&first[..3], &[22, 3, 1]);
        assert_eq!(&first[138..142], &[0, 35, 0, 7]);
        assert_eq!(&first[142..149], b"payload");
        assert_ne!(first, second);
        assert_eq!(
            usize::from(u16::from_be_bytes(first[3..5].try_into().unwrap())),
            first.len() - 5
        );
    }
}
