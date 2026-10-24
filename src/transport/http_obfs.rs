//! One HTTP/1 request/response header followed by unframed bytes. The supplied
//! protocol prefix is the first request body; later writes are never re-framed.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use futures_util::future::BoxFuture;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    time::{Instant, timeout_at},
};

use super::http_head::{HTTP_HEAD_BYTES, HTTP_HEADER_COUNT, read_response};
use crate::dispatch::BoxStream;

#[derive(Clone)]
pub struct HttpObfsOptions {
    head: Vec<u8>,
}

impl std::fmt::Debug for HttpObfsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpObfsOptions").finish_non_exhaustive()
    }
}

impl HttpObfsOptions {
    /// A caller selects one configured path/Host before constructing options.
    /// Framing headers are reserved, so configuration cannot inject a second body.
    pub fn new(method: http::Method, uri: &str, headers: http::HeaderMap) -> io::Result<Self> {
        let uri: http::Uri = uri.parse().map_err(|_| invalid())?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || headers.len() > HTTP_HEADER_COUNT - 2
        {
            return Err(invalid());
        }
        let authority = uri
            .authority()
            .filter(|value| !value.as_str().contains('@'))
            .ok_or_else(invalid)?;
        let host = match headers.get("host") {
            Some(value) => {
                let value: http::uri::Authority = value
                    .to_str()
                    .map_err(|_| invalid())?
                    .parse()
                    .map_err(|_| invalid())?;
                if value.as_str().contains('@') {
                    return Err(invalid());
                }
                value.to_string()
            }
            None => authority.to_string(),
        };
        let path = uri.path_and_query().map_or("/", |path| path.as_str());
        if !path.starts_with('/') {
            return Err(invalid());
        }
        let mut head = format!("{method} {path} HTTP/1.1\r\nhost: {host}\r\n").into_bytes();
        for (name, value) in &headers {
            if matches!(name.as_str(), "content-length" | "transfer-encoding")
                || headers.get_all(name).iter().count() != 1
            {
                return Err(invalid());
            }
            if name == "host" {
                continue;
            }
            head.extend_from_slice(name.as_str().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        // Reserve the maximum usize decimal length and final framing headers.
        if head.len() + 42 > HTTP_HEAD_BYTES {
            return Err(invalid());
        }
        Ok(Self { head })
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid HTTP transport options",
    )
}

pub async fn http_obfs(
    mut stream: BoxStream,
    options: &HttpObfsOptions,
    prefix: &[u8],
    deadline: Instant,
) -> io::Result<BoxStream> {
    timeout_at(deadline, async {
        stream.write_all(&options.head).await?;
        stream
            .write_all(format!("content-length: {}\r\n\r\n", prefix.len()).as_bytes())
            .await?;
        stream.write_all(prefix).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let (mut reader, writer) = tokio::io::split(stream);
    // The complete request prefix was submitted within the setup deadline.
    // An official peer can wait for application output before its first reply.
    // No task or socket: the caller's first read drives the response header.
    let response = Box::pin(async move {
        let (_, tail) = read_response(&mut reader).await?;
        Ok((reader, Bytes::from(tail)))
    });
    Ok(Box::new(HttpStream {
        _observation: crate::resources::observation::track(
            crate::resources::observation::ResourceKind::Session,
        ),
        response: Some(response),
        reader: None,
        writer,
        tail: Bytes::new(),
        failed: false,
    }))
}

type Response = BoxFuture<'static, io::Result<(ReadHalf<BoxStream>, Bytes)>>;

struct HttpStream {
    _observation: crate::resources::observation::Guard,
    response: Option<Response>,
    reader: Option<ReadHalf<BoxStream>>,
    writer: WriteHalf<BoxStream>,
    tail: Bytes,
    failed: bool,
}

impl AsyncRead for HttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        if let Some(response) = &mut this.response {
            let result = ready!(response.as_mut().poll(cx));
            this.response = None;
            match result {
                Ok((reader, tail)) => {
                    this.reader = Some(reader);
                    this.tail = tail;
                }
                Err(error) => {
                    this.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
        if !this.tail.is_empty() {
            let count = output.remaining().min(this.tail.len());
            output.put_slice(&this.tail[..count]);
            this.tail.advance(count);
            return Poll::Ready(Ok(()));
        }
        Pin::new(this.reader.as_mut().unwrap()).poll_read(cx, output)
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut self.writer).poll_write(cx, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
