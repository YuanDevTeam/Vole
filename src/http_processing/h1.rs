//! URL actions reuse the existing streaming HTTP/1 framing and body relay.
use super::{HttpContext, Intercept, Scheme, config::checked_url, io::Replay, request::Decision};
use crate::{
    inbound::http::{
        HttpServerConfig, RequestHead,
        framing::{self, RequestPlan},
        server,
    },
    security::{StandardTlsClient, TlsClientOptions},
    session::StreamSession,
};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use url::Url;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid intercepted HTTP request",
    )
}

impl HttpContext {
    /// No read occurs for a noncandidate port. A transparent result returns all
    /// consumed bytes; the caller keeps the same IO and replays that prefix.
    pub(crate) async fn try_intercept<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        stream: &mut S,
        session: StreamSession,
        cancellation: CancellationToken,
    ) -> io::Result<Intercept> {
        if !self.candidate_port(session.destination.port()) {
            return Ok(Intercept::Transparent { prefix: Vec::new() });
        }
        let mut prefix = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let recognized = tokio::select! {biased;
            ()=cancellation.cancelled()=>return Err(io::Error::new(io::ErrorKind::Interrupted,"HTTP processing stopped")),
            result=timeout_at(deadline,async {
                for _ in 0..32 {
                    let byte=stream.read_u8().await?;prefix.push(byte);
                    if byte==b' ' {return Ok(prefix.len()>1);}
                    if !byte.is_ascii_uppercase() && byte!=b'-' {return Ok(false);}
                }
                Ok::<_,io::Error>(false)
            })=>match result {Ok(Ok(value))=>value,Ok(Err(error)) if error.kind()==io::ErrorKind::UnexpectedEof=>false,Ok(Err(error))=>return Err(error),Err(_)=>false},
        };
        if !recognized || prefix == b"CONNECT " {
            return Ok(Intercept::Transparent { prefix });
        }
        let mut replay = Replay::new(prefix, stream);
        self.serve_h1(&mut replay, session, Scheme::Http, cancellation)
            .await?;
        Ok(Intercept::Handled)
    }

    /// Also serves HTTP/1 after selective TLS termination. HTTPS callers must
    /// authorize each original authority before this request is forwarded.
    pub(crate) async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        stream: &mut S,
        session: StreamSession,
        scheme: Scheme,
        cancellation: CancellationToken,
    ) -> io::Result<()> {
        let operation = async {
            let (read, mut write) = tokio::io::split(stream);
            let mut reader = BufReader::with_capacity(framing::COPY_BUFFER, read);
            let config = HttpServerConfig::processing();
            loop {
                let request = timeout(config.header_timeout, async {
                    if reader.fill_buf().await?.is_empty() {
                        return Ok(None);
                    }
                    let bytes = framing::read_head(&mut reader, config.header_limit).await?;
                    crate::inbound::http::parser::parse_request_head(&bytes, Vec::new()).map(Some)
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))??;
                let Some(request) = request else {
                    return Ok(());
                };
                if request.is_connect() {
                    return Err(invalid());
                }
                if !self
                    .forward_h1(
                        &mut reader,
                        &mut write,
                        &request,
                        session.clone(),
                        scheme,
                        &config,
                    )
                    .await?
                {
                    return Ok(());
                }
            }
        };
        tokio::select! {biased;
            ()=cancellation.cancelled()=>Ok(()),
            result=operation=>result,
        }
    }

    pub(crate) async fn forward_h1<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        reader: &mut R,
        writer: &mut W,
        request: &RequestHead,
        session: StreamSession,
        scheme: Scheme,
        config: &HttpServerConfig,
    ) -> io::Result<bool> {
        let original = request_url(request, scheme)?;
        let asterisk = request.method == "OPTIONS" && request.target == "*";
        let target = match self.plan(original, session, scheme, !asterisk)? {
            Decision::Reject => {
                framing::write_timed(
                    writer,
                    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    config.header_timeout,
                )
                .await?;
                return Ok(false);
            }
            Decision::Redirect { status, url } => {
                let reason = if status == 302 {
                    "Found"
                } else {
                    "Temporary Redirect"
                };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nLocation: {url}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                );
                framing::write_timed(writer, head.as_bytes(), config.header_timeout).await?;
                return Ok(false);
            }
            Decision::Forward(target) => target,
        };
        let mut origin = if asterisk {
            "*".to_owned()
        } else {
            target.url.path().to_owned()
        };
        if let Some(query) = target.url.query() {
            origin.push('?');
            origin.push_str(query);
        }
        let plan = RequestPlan::for_target(
            request,
            target.logical_destination.clone(),
            origin,
            target.strip_origin_credentials,
        )?;
        let deadline = Instant::now() + config.connect_timeout;
        let mut outbound = timeout_at(deadline, self.dispatcher.connect_tcp(target.session))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP outbound timed out"))?
            .map_err(|_| io::Error::other("HTTP outbound failed"))?;
        if target.url.scheme() == "https" {
            let tls = StandardTlsClient::with_options(
                self.security(),
                target
                    .url
                    .host_str()
                    .ok_or_else(invalid)?
                    .trim_matches(['[', ']']),
                TlsClientOptions {
                    alpn: vec![b"http/1.1".to_vec()],
                    ..Default::default()
                },
                0,
                64 * 1024,
            )?;
            outbound = timeout_at(deadline, tls.connect(outbound))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "HTTP upstream TLS timed out")
                })?
                .map_err(|_| io::Error::other("HTTP upstream TLS failed"))?;
        }
        server::forward_request(reader, writer, outbound, request, plan, config).await
    }
}
fn request_url(request: &RequestHead, scheme: Scheme) -> io::Result<Url> {
    let mut hosts = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"));
    let host = hosts.next().map(|(_, value)| value);
    if hosts.next().is_some() || (request.version == "HTTP/1.1" && host.is_none()) {
        return Err(invalid());
    }
    if request.method == "OPTIONS" && request.target == "*" {
        let host = host.ok_or_else(invalid)?;
        return checked_url(&format!("{}://{host}/", scheme.name())).map_err(|_| invalid());
    }
    if request.target.starts_with('/') {
        let host = host.ok_or_else(invalid)?;
        if request.target.starts_with("//") {
            return Err(invalid());
        }
        checked_url(&format!("{}://{host}{}", scheme.name(), request.target)).map_err(|_| invalid())
    } else {
        let url = checked_url(&request.target).map_err(|_| invalid())?;
        if url.scheme() != scheme.name() {
            return Err(invalid());
        }
        Ok(url)
    }
}
