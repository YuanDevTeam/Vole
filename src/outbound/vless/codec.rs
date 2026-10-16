use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut as _, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::outbound::address::encode_port_first as encode_destination;
use crate::{dispatch::BoxStream, session::Destination};

const VLESS_VERSION: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp,
    Udp,
    Mux,
}

impl VlessCommand {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
            Self::Mux => 3,
        }
    }
}

pub fn encode_request_header(
    uuid: Uuid,
    command: VlessCommand,
    destination: Option<&Destination>,
) -> io::Result<Bytes> {
    encode_header(uuid, command, destination, false)
}

pub(super) fn encode_header(
    uuid: Uuid,
    command: VlessCommand,
    destination: Option<&Destination>,
    vision: bool,
) -> io::Result<Bytes> {
    if (command != VlessCommand::Mux) != destination.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS TCP/UDP requires a destination and mux must omit it",
        ));
    }

    let mut output = BytesMut::with_capacity(64);
    output.put_u8(VLESS_VERSION);
    output.extend_from_slice(uuid.as_bytes());
    if vision {
        output.put_u8(18);
        output.extend_from_slice(b"\x0a\x10xtls-rprx-vision");
    } else {
        output.put_u8(0);
    }
    output.put_u8(command.wire_value());
    if let Some(destination) = destination {
        encode_destination(destination, &mut output)?;
    }
    Ok(output.freeze())
}

pub async fn read_response_header<T>(stream: &mut T) -> io::Result<()>
where
    T: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != VLESS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected VLESS response version",
        ));
    }
    if header[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VLESS response addons are unsupported when flow is empty",
        ));
    }
    Ok(())
}

/// A VLESS TCP stream that emits the request header before the first operation
/// and consumes the response header immediately before the first payload read.
///
/// VLESS servers are allowed to delay their response header until target data
/// is available. Keeping both handshakes lazy avoids waiting for that response
/// before the caller has had a chance to send its first request payload.
pub struct VlessStream {
    inner: Option<BoxStream>,
    request_header: Bytes,
    request_header_written: usize,
    request_header_flushed: bool,
    response_header: [u8; 2],
    response_header_read: usize,
    response_header_done: bool,
    whole_close: bool,
    closed: bool,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl VlessStream {
    #[must_use]
    pub const fn new(inner: BoxStream, request_header: Bytes) -> Self {
        Self {
            inner: Some(inner),
            request_header,
            request_header_written: 0,
            request_header_flushed: false,
            response_header: [0; 2],
            response_header_read: 0,
            response_header_done: false,
            whole_close: false,
            closed: false,
            deadline: None,
        }
    }

    pub fn with_deadline(
        inner: BoxStream,
        request_header: Bytes,
        deadline: tokio::time::Instant,
    ) -> Self {
        let mut stream = Self::new(inner, request_header);
        stream.deadline = Some(Box::pin(tokio::time::sleep_until(deadline)));
        stream
    }

    pub(super) fn with_whole_close(mut self) -> Self {
        self.whole_close = true;
        self
    }

    fn check_setup(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.inner.is_none() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if !self.request_header_flushed
            && self
                .deadline
                .as_mut()
                .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
        {
            self.inner.take();
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    fn finish<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if matches!(result, Poll::Ready(Err(_))) {
            self.inner.take();
        }
        result
    }

    fn poll_request_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_setup(cx)?;
        while self.request_header_written < self.request_header.len() {
            let written = match Pin::new(self.inner.as_mut().expect("checked open"))
                .poll_write(cx, &self.request_header[self.request_header_written..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(written)) => written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            };
            if written == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.request_header_written += written;
        }
        // Complete the handshake's write ownership before handing the supplied
        // transport to payload writes or reads. A read-side flush must never
        // consume the completion of a concurrently pending packet-up write:
        // its writer would then replay bytes whose acknowledgement was lost.
        if !self.request_header_flushed {
            std::task::ready!(Pin::new(self.inner.as_mut().expect("checked open")).poll_flush(cx))?;
            self.request_header_flushed = true;
            // The authenticated transport and VLESS request are established.
            // A valid upload-only target may send its response header much
            // later; its silence must not expire ongoing payload writes.
            self.deadline = None;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_response_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.response_header_done {
            return Poll::Ready(Ok(()));
        }

        while self.response_header_read < self.response_header.len() {
            let mut buffer = ReadBuf::new(&mut self.response_header[self.response_header_read..]);
            match Pin::new(self.inner.as_mut().expect("checked open")).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                Poll::Ready(Ok(())) => self.response_header_read += buffer.filled().len(),
            }
        }

        if self.response_header[0] != VLESS_VERSION {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected VLESS response version",
            )));
        }
        if self.response_header[1] != 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS response addons are unsupported when flow is empty",
            )));
        }

        self.response_header_done = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 || self.closed {
            return Poll::Ready(Ok(()));
        }
        let result = (|| {
            match self.poll_request_header(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            match self.poll_response_header(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            Pin::new(self.inner.as_mut().expect("checked open")).poll_read(cx, buffer)
        })();
        self.finish(result)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let result = (|| {
            match self.poll_request_header(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            Pin::new(self.inner.as_mut().expect("checked open")).poll_write(cx, buffer)
        })();
        self.finish(result)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let result = (|| {
            match self.poll_request_header(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            Pin::new(self.inner.as_mut().expect("checked open")).poll_flush(cx)
        })();
        self.finish(result)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.whole_close {
            std::task::ready!(self.as_mut().poll_flush(cx))?;
            self.closed = true;
            // HTTP camouflage has no Mihomo CloseWrite. Drop the supplied
            // OwnedStream, which also wakes reads via its shared session token.
            self.inner.take();
            self.deadline.take();
            return Poll::Ready(Ok(()));
        }
        let result = (|| {
            match self.poll_request_header(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            Pin::new(self.inner.as_mut().expect("checked open")).poll_shutdown(cx)
        })();
        self.finish(result)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;

    use super::*;

    fn uuid() -> Uuid {
        Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap()
    }

    #[test]
    fn tcp_header_matches_vless_wire_format() {
        let destination = Destination::domain("example.com", 443).unwrap();
        let header = encode_request_header(uuid(), VlessCommand::Tcp, Some(&destination)).unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(uuid().as_bytes());
        expected.extend_from_slice(&[
            0, // addons
            1, // TCP
            0x01, 0xbb, // port 443
            2, 11, // domain + length
        ]);
        expected.extend_from_slice(b"example.com");
        assert_eq!(header.as_ref(), expected);
    }

    #[test]
    fn xudp_starts_with_a_destinationless_mux_header() {
        let header = encode_request_header(uuid(), VlessCommand::Mux, None).unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(uuid().as_bytes());
        expected.extend_from_slice(&[0, 3]);
        assert_eq!(header.as_ref(), expected);
    }

    #[tokio::test]
    async fn rejects_response_addons_when_flow_is_empty() {
        let mut stream = std::io::Cursor::new([0, 3, 1, 2, 3]);
        let error = read_response_header(&mut stream).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn lazy_stream_does_not_wait_for_response_before_request_payload() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let destination = Destination::domain("example.com", 80).unwrap();
            let header =
                encode_request_header(uuid(), VlessCommand::Tcp, Some(&destination)).unwrap();
            let header_for_server = header.clone();
            let (client, mut server) = tokio::io::duplex(256);
            let mut stream = VlessStream::new(Box::new(client), header);

            let server_task = async move {
                let mut received_header = vec![0_u8; header_for_server.len()];
                server.read_exact(&mut received_header).await.unwrap();
                assert_eq!(received_header, header_for_server);

                let mut request = [0_u8; 4];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                server.write_all(&[0, 0]).await.unwrap();
                server.write_all(b"pong").await.unwrap();
            };
            let client_task = async move {
                stream.write_all(b"ping").await.unwrap();
                stream.flush().await.unwrap();
                let mut response = [0_u8; 4];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"pong");
            };

            tokio::join!(server_task, client_task);
        })
        .await
        .expect("lazy VLESS exchange timed out");
    }

    #[tokio::test(start_paused = true)]
    async fn upload_survives_setup_deadline_when_response_is_delayed() {
        let header = encode_request_header(
            uuid(),
            VlessCommand::Tcp,
            Some(&Destination::domain("example.com", 80).unwrap()),
        )
        .unwrap();
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream = VlessStream::with_deadline(
            Box::new(client),
            header.clone(),
            tokio::time::Instant::now() + Duration::from_secs(10),
        );
        stream.write_all(b"before").await.unwrap();
        tokio::time::advance(Duration::from_secs(11)).await;
        stream
            .write_all(b"after")
            .await
            .expect("active upload must outlive setup");
        let mut request = vec![0; header.len() + 11];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..header.len()], header.as_ref());
        assert_eq!(&request[header.len()..], b"beforeafter");
        server.write_all(&[0, 0, 42]).await.unwrap();
        let mut response = [0];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [42]);
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_request_header_still_obeys_setup_deadline() {
        let header = encode_request_header(uuid(), VlessCommand::Mux, None).unwrap();
        let (client, _server) = tokio::io::duplex(1);
        let mut stream = VlessStream::with_deadline(
            Box::new(client),
            header,
            tokio::time::Instant::now() + Duration::from_secs(10),
        );
        let error = stream.write_all(b"payload").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
