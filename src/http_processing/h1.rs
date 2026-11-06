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
        if self
            .policy()
            .mitm()
            .is_some_and(|policy| policy.candidate_port(session.destination.port()))
        {
            return self.intercept_tls(stream, session, cancellation).await;
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
        // Allocate H1's larger streaming state only on the selected path;
        // otherwise it also enlarges every TLS/H2 connection future.
        let mut replay = Replay::new(prefix, stream);
        Box::pin(self.serve_h1(&mut replay, session, Scheme::Http, cancellation)).await?;
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
            let mut upstream = None;
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
                        (&config, &cancellation),
                        &mut upstream,
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward_h1<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        reader: &mut R,
        writer: &mut W,
        request: &RequestHead,
        mut session: StreamSession,
        scheme: Scheme,
        scope: (&HttpServerConfig, &CancellationToken),
        upstream: &mut Option<server::UpstreamSlot>,
    ) -> io::Result<bool> {
        let (config, cancellation) = scope;
        let original = request_url(request, scheme)?;
        if scheme == Scheme::Http
            && let Some(plan) = self
                .dispatcher()
                .sniff_plan(session.source, &session.destination)
                .await
                .map_err(|_| io::Error::other("sniffer rule evaluation failed"))?
        {
            plan.with_cancellation(cancellation.clone())
                .observe_http_host(original.host_str().ok_or_else(invalid)?, &mut session)
                .map_err(|_| io::Error::other("sniffer rule evaluation failed"))?;
        }
        let base_session = session.clone();
        let asterisk = request.method == "OPTIONS" && request.target == "*";
        let decision = match self.plan(original, session, scheme, !asterisk) {
            Ok(decision) => decision,
            Err(error) if error.kind() != io::ErrorKind::PermissionDenied => {
                framing::write_timed(
                    writer,
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    config.header_timeout,
                )
                .await?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let mut target = match decision {
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
            Decision::Forward(target) => *target,
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
        // Validate framing before any editable fields enter the pipeline.
        RequestPlan::for_target(
            request,
            target.logical_destination.clone(),
            origin.clone(),
            false,
        )?;
        let original_url = target.original.clone();
        let original_meta =
            super::body::OriginalRequestMeta::new(&request.method, &request.headers);
        let mut continued = false;
        let mut prepared_upload = None;
        let mut script_context = None;
        let mut outgoing = request.clone();
        if target.strip_origin_credentials {
            super::headers::strip_origin_credentials(&mut outgoing.headers);
        }
        super::headers::apply(
            self.policy().rules(),
            &target.original,
            super::rules::Phase::Request,
            &mut outgoing.headers,
        );
        let mut plan =
            RequestPlan::for_target(&outgoing, target.logical_destination.clone(), origin, false)?;
        let active_scripts = plan.upgrade.is_empty()
            && self
                .policy()
                .scripts()
                .iter()
                .any(|s| s.matches(&original_url));
        if active_scripts {
            use super::{
                body::{Transaction, WireBodyMeta},
                script_config::BodyMode,
                script_message::{self, OriginalSnapshot, Outcome, RequestSnapshot},
            };
            let wants_body = self.policy().scripts().iter().any(|s| {
                s.phase == super::rules::Phase::Request
                    && s.body != BodyMode::None
                    && s.matches(&original_url)
            });
            let length = match plan.body {
                framing::Body::Empty => Some(0),
                framing::Body::Length(n) => Some(n),
                _ => None,
            };
            let wire = WireBodyMeta::new(
                &request.headers,
                &original_meta,
                super::rules::Phase::Request,
                None,
                length,
                false,
            );
            let transaction = Transaction::begin_shared(
                self.policy().body_budget(),
                self.policy().rules(),
                &original_url,
                super::rules::Phase::Request,
                &wire,
                wants_body && !asterisk,
            )
            .ok();
            if transaction.is_some()
                && request
                    .headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("expect"))
            {
                framing::write_timed(
                    writer,
                    b"HTTP/1.1 100 Continue\r\n\r\n",
                    config.header_timeout,
                )
                .await?;
                framing::timeout_io(
                    config.header_timeout,
                    tokio::io::AsyncWriteExt::flush(writer),
                )
                .await?;
                continued = true;
                outgoing
                    .headers
                    .retain(|(name, _)| !name.eq_ignore_ascii_case("expect"));
            }
            if target.strip_origin_credentials {
                plan.trailer_blocklist.insert("cookie".into());
            }
            let (mut prepared, entity) = super::h1_body::prepare_shared(
                reader,
                plan.body,
                &plan.trailer_blocklist,
                config.body_idle_timeout,
                transaction,
                &mut outgoing.headers,
            )
            .await?;
            let original = OriginalSnapshot {
                url: original_url.clone(),
                method: request.method.clone(),
                identity_allowed: original_meta.identity_allowed,
                asterisk,
            };
            let mut message = script_message::Message::request(
                original.clone(),
                RequestSnapshot {
                    url: target.url.clone(),
                    method: outgoing.method.clone(),
                    headers: outgoing.headers.clone(),
                },
                entity,
                &request.headers,
                target.strip_origin_credentials,
            );
            let outcome =
                match script_message::run(self.policy(), &original_url, &mut message, cancellation)
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error)
                        if cancellation.is_cancelled()
                            || error.kind() == io::ErrorKind::Interrupted =>
                    {
                        return Err(error);
                    }
                    Err(_) => {
                        return write_local(
                            writer,
                            script_message::LocalResponse {
                                status: 502,
                                headers: vec![("Content-Length".into(), "0".into())],
                                body: bytes::Bytes::new(),
                            },
                            config.header_timeout,
                        )
                        .await;
                    }
                };
            match outcome {
                Outcome::Abort => return Ok(false),
                Outcome::Respond(local) => {
                    drop(message);
                    drop(prepared);
                    return write_local(writer, local, config.header_timeout).await;
                }
                Outcome::Forward => {}
            }
            if let Some(entity) = message.body.take() {
                prepared.install_entity(entity);
            }
            outgoing.method = message.request.method.clone();
            outgoing.headers = message.request.headers.clone();
            target = self.final_target(
                original_url.clone(),
                message.request.url.clone(),
                base_session,
                scheme,
            )?;
            let mut final_origin = if asterisk {
                "*".to_owned()
            } else {
                target.url.path().to_owned()
            };
            if let Some(query) = target.url.query() {
                final_origin.push('?');
                final_origin.push_str(query);
            }
            plan = RequestPlan::for_target(
                &outgoing,
                target.logical_destination.clone(),
                final_origin,
                false,
            )?;
            if message.crossed_origin {
                plan.trailer_blocklist.insert("cookie".into());
            }
            prepared_upload = Some(prepared);
            script_context = Some(super::h1_body::ScriptContext {
                original,
                request: message.request,
                cancellation: cancellation.clone(),
            });
        }
        if target.strip_origin_credentials {
            plan.trailer_blocklist.insert("cookie".into());
        }
        let message = super::h1_body::Message {
            policy: self.policy(),
            original: &original_url,
            request,
            meta: original_meta,
            continued: std::sync::atomic::AtomicBool::new(continued),
            prepared: std::sync::Mutex::new(prepared_upload),
            scripts: script_context,
        };
        // Request scripts have finished. Native request-body rules remain on
        // the original path, including rules whose empty GET becomes nonempty.
        let request_body_rules = self.policy().rules().iter().any(|r| {
            matches!(
                r.action,
                super::rules::RuleAction::Body {
                    phase: super::rules::Phase::Request,
                    ..
                }
            )
        });
        let eligible = scheme == Scheme::Http
            && target.url.scheme() == "http"
            && outgoing.method == "GET"
            && request.version == "HTTP/1.1"
            && plan.keep_alive
            && plan.upgrade.is_empty()
            && matches!(plan.body, framing::Body::Empty | framing::Body::Length(0))
            && !request_body_rules
            && !outgoing
                .headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("expect"));
        let deadline = Instant::now() + config.connect_timeout;
        let prepared = if eligible {
            timeout_at(
                deadline,
                self.dispatcher.prepare_http_tcp(target.session.clone()),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "HTTP outbound planning timed out")
            })?
            .map_err(|_| io::Error::other("HTTP outbound planning failed"))?
        } else {
            None
        };
        let key = prepared.as_ref().and_then(|p| p.reuse_key()).cloned();
        let authority = target.url.origin().ascii_serialization();
        // Taking removes the slot even on errors/panic. No old IO can survive
        // an uncertain exchange or be used for a rejected new route.
        if let Some(mut previous) = upstream.take()
            && key.as_ref().is_some_and(|k| previous.key.same(k))
            && previous.authority == authority
            && previous.io.idle_healthy().await
        {
            drop(prepared);
            let outcome = server::forward_processed_reusable(
                reader,
                writer,
                &mut previous.io,
                request,
                plan,
                config,
                &message,
            )
            .await?;
            if outcome.upstream_reusable {
                *upstream = Some(previous);
            }
            return Ok(outcome.downstream_keep_alive);
        }
        let mut outbound = timeout_at(deadline, async {
            if let Some(prepared) = prepared {
                prepared.connect().await
            } else {
                self.dispatcher.connect_tcp(target.session).await
            }
        })
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
        if let Some(key) = key {
            let mut io = server::UpstreamIo::new(outbound);
            let outcome = server::forward_processed_reusable(
                reader, writer, &mut io, request, plan, config, &message,
            )
            .await?;
            if outcome.upstream_reusable {
                *upstream = Some(server::UpstreamSlot { authority, key, io });
            }
            Ok(outcome.downstream_keep_alive)
        } else {
            server::forward_processed(reader, writer, outbound, request, plan, config, &message)
                .await
        }
    }
}
async fn write_local<W: AsyncWrite + Unpin>(
    writer: &mut W,
    local: super::script_message::LocalResponse,
    idle: Duration,
) -> io::Result<bool> {
    let reason = http::StatusCode::from_u16(local.status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Response");
    let mut head = format!("HTTP/1.1 {} {}\r\n", local.status, reason);
    for (name, value) in &local.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    framing::write_timed(writer, head.as_bytes(), idle).await?;
    framing::write_timed(writer, &local.body, idle).await?;
    framing::timeout_io(idle, tokio::io::AsyncWriteExt::flush(writer)).await?;
    Ok(false)
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
