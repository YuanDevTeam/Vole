use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{CONTROLLER_BODY_TIMEOUT, CONTROLLER_HEADER_TIMEOUT, RequestContext};

pub(super) trait ControllerIo: AsyncRead + Unpin + Send {
    fn respond(
        &mut self,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> impl Future<Output = io::Result<()>> + Send;
}

pub(super) struct H1Io<T>(pub T);
impl<T: AsyncRead + Unpin> AsyncRead for H1Io<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ControllerIo for H1Io<T> {
    async fn respond(
        &mut self,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> io::Result<()> {
        let reason = http::StatusCode::from_u16(status)
            .ok()
            .and_then(|s| s.canonical_reason())
            .unwrap_or("Error");
        let mut head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
            body.len()
        );
        for (name, value) in headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        tokio::time::timeout(CONTROLLER_BODY_TIMEOUT, async {
            self.0.write_all(head.as_bytes()).await?;
            self.0.write_all(body).await?;
            self.0.shutdown().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "controller response timed out"))?
    }
}

pub(super) struct CorsIo<T> {
    inner: T,
    headers: Vec<(String, String)>,
}
impl<T> CorsIo<T> {
    pub fn new(inner: T, headers: Vec<(String, String)>) -> Self {
        Self { inner, headers }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for CorsIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: ControllerIo> ControllerIo for CorsIo<T> {
    async fn respond(
        &mut self,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> io::Result<()> {
        let mut all = Vec::with_capacity(headers.len() + self.headers.len());
        all.extend_from_slice(headers);
        all.extend(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        self.inner.respond(status, &all, body).await
    }
}

struct H2Io {
    body: h2::RecvStream,
    buffered: Bytes,
    response: h2::server::SendResponse<Bytes>,
}
impl AsyncRead for H2Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if target.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let count = target.remaining().min(self.buffered.len());
                target.put_slice(&self.buffered.split_to(count));
                return Poll::Ready(
                    self.body
                        .flow_control()
                        .release_capacity(count)
                        .map_err(io::Error::other),
                );
            }
            match self.body.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Ready(Some(Ok(data))) => self.buffered = data,
            }
        }
    }
}
impl ControllerIo for H2Io {
    async fn respond(
        &mut self,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> io::Result<()> {
        let mut head = http::Response::builder()
            .status(status)
            .header("cache-control", "no-store")
            .header("content-length", body.len());
        for (name, value) in headers {
            head = head.header(*name, *value);
        }
        let mut send = self
            .response
            .send_response(head.body(()).map_err(io::Error::other)?, body.is_empty())
            .map_err(io::Error::other)?;
        tokio::time::timeout(CONTROLLER_BODY_TIMEOUT, async {
            let mut position = 0;
            while position < body.len() {
                send.reserve_capacity((body.len() - position).min(16 * 1024));
                let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                    .await
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "controller stream closed")
                    })?
                    .map_err(io::Error::other)?;
                let count = capacity.min(body.len() - position).min(16 * 1024);
                if count == 0 {
                    continue;
                }
                let end = position + count;
                send.send_data(
                    Bytes::copy_from_slice(&body[position..end]),
                    end == body.len(),
                )
                .map_err(io::Error::other)?;
                position = end;
            }
            Ok(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "controller response timed out"))?
    }
}

pub(super) async fn serve_tls<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: T,
    tls: std::sync::Arc<super::tls::ServerTls>,
    context: RequestContext,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let stream = tokio::select! { biased;
        () = cancellation.cancelled() => return Ok(()),
        result = tokio::time::timeout(CONTROLLER_HEADER_TIMEOUT, tokio_rustls::TlsAcceptor::from(tls.config.clone()).accept(stream)) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "controller TLS handshake timed out"))??,
    };
    if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        serve_h2(stream, context, cancellation).await
    } else {
        super::handle_connection(H1Io(stream), context, cancellation).await
    }
}

pub(super) async fn serve_h2<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: T,
    context: RequestContext,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(8)
        .initial_window_size(1024)
        .initial_connection_window_size(8 * 1024)
        .max_header_list_size(crate::inbound::DEFAULT_HEADER_LIMIT as u32)
        .max_send_buffer_size(16 * 1024);
    let mut connection = tokio::select! { biased;
        () = cancellation.cancelled() => return Ok(()),
        result = tokio::time::timeout(CONTROLLER_HEADER_TIMEOUT, builder.handshake::<_, Bytes>(stream)) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "controller H2 handshake timed out"))?.map_err(io::Error::other)?,
    };
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! { biased;
            () = cancellation.cancelled() => break Ok(()),
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined { break Err(io::Error::other(error)); }
            }
            accepted = connection.accept() => {
                let Some(accepted) = accepted else { break Ok(()); };
                let (request, mut response) = match accepted { Ok(value) => value, Err(error) => break Err(io::Error::other(error)) };
                if tasks.len() >= 8 { response.send_reset(h2::Reason::REFUSED_STREAM); continue; }
                let target = request.uri().path_and_query().map_or("/", |value| value.as_str()).to_owned();
                if target.len() > 8 * 1024 || request.headers().len() > crate::inbound::DEFAULT_HEADER_COUNT_LIMIT {
                    response.send_reset(h2::Reason::PROTOCOL_ERROR); continue;
                }
                let mut headers = Vec::with_capacity(request.headers().len());
                let mut valid = true;
                for (name, value) in request.headers() {
                    match value.to_str() { Ok(value) => headers.push((name.as_str().into(), value.into())), Err(_) => { valid = false; break; } }
                }
                if !valid { response.send_reset(h2::Reason::PROTOCOL_ERROR); continue; }
                let head = crate::inbound::http::RequestHead { method: request.method().as_str().into(), target,
                    version: "HTTP/2".into(), headers, buffered: Vec::new() };
                let io = H2Io { body: request.into_body(), buffered: Bytes::new(), response };
                let context = context.clone(); let child = cancellation.clone();
                let tracking = context.requests.clone();
                tasks.spawn(tracking.track_future(crate::resources::observation::task(async move {
                    let _ = super::handle_request(io, head, context, child).await;
                })));
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
