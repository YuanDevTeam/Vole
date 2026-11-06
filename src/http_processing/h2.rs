//! HTTP/2 downstream owner. Every request and upstream driver is polled inline.
use super::{
    HttpContext, Scheme,
    body::{Entity, OriginalRequestMeta, Transaction, WireBodyMeta},
    config::checked_url,
    h2_body::{self, IDLE},
    h2_h1, h2_headers, headers,
    request::{Decision, Target},
    rules::Phase,
    script_config::BodyMode,
    script_message::{
        self, LocalResponse, Message, OriginalSnapshot, Outcome, RequestSnapshot, ResponseSnapshot,
    },
};
use crate::{
    dispatch::BoxStream,
    security::{StandardTlsClient, TlsClientOptions},
    session::StreamSession,
};
use bytes::Bytes;
use futures_util::{StreamExt, future::poll_fn, stream::FuturesUnordered};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
const STREAMS: usize = 8;
const SETUP: Duration = Duration::from_secs(10);
struct MessageMeta {
    original: OriginalRequestMeta,
    length: Option<u64>,
    asterisk: bool,
    script: Option<ScriptExchange>,
}
struct ScriptExchange {
    original: OriginalSnapshot,
    request: Option<RequestSnapshot>,
    cancellation: CancellationToken,
}
struct BodyMessage {
    phase: Phase,
    wire: Option<WireBodyMeta>,
    expected: Option<u64>,
    strip_credentials: bool,
    scripts: bool,
    asterisk: bool,
}
fn failed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP proxy stream failed")
}

impl HttpContext {
    pub(in crate::http_processing) async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        stream: &mut S,
        session: StreamSession,
        cancellation: CancellationToken,
    ) -> io::Result<()> {
        let operation = async {
            let mut builder = h2::server::Builder::new();
            builder
                .initial_window_size(32 * 1024)
                .initial_connection_window_size(64 * 1024)
                .header_table_size(0)
                .max_header_list_size(32 * 1024)
                .max_frame_size(16 * 1024)
                .max_send_buffer_size(16 * 1024)
                .max_concurrent_streams(STREAMS as u32)
                .max_concurrent_reset_streams(16)
                .max_local_error_reset_streams(Some(16));
            let mut connection = timeout(SETUP, builder.handshake::<_, Bytes>(stream))
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?
                .map_err(|_| failed())?;
            let mut requests = FuturesUnordered::new();
            let idle = tokio::time::sleep(IDLE);
            tokio::pin!(idle);
            loop {
                // accept also drives DATA, SETTINGS, WINDOW_UPDATE and resets.
                // It stays polled while all eight request slots are occupied.
                tokio::select! {biased;
                    ()=&mut idle,if requests.is_empty()=>return Ok(()),
                    result=requests.next(),if !requests.is_empty()=>{
                        let _=result;idle.as_mut().reset(Instant::now()+IDLE);
                    },
                    accepted=connection.accept()=>match accepted {
                        Some(Ok((request,mut response)))=>{
                            idle.as_mut().reset(Instant::now()+IDLE);
                            if requests.len()>=STREAMS {response.send_reset(h2::Reason::REFUSED_STREAM);} else {
                                // The ready queue also owns an empty sentinel
                                // with the same future type. Keep its storage
                                // small on every downstream connection.
                                requests.push(Box::pin(self.h2_request(request,response,session.clone(),cancellation.clone())));
                            }
                        },
                        Some(Err(_))=>return Err(failed()),
                        None=>return Ok(()),
                    }
                }
            }
        };
        tokio::select! {biased;()=cancellation.cancelled()=>Ok(()),result=operation=>result}
    }

    async fn h2_request(
        &self,
        request: Request<h2::RecvStream>,
        response: h2::server::SendResponse<Bytes>,
        session: StreamSession,
        cancellation: CancellationToken,
    ) {
        let response = ResponseSlot(Arc::new(Mutex::new(ResponseState {
            response,
            infos: 0,
            final_started: false,
            upstream_final_received: false,
        })));
        if self
            .h2_forward(request, &response, session, cancellation)
            .await
            .is_err()
        {
            response.reset();
        }
    }
    async fn h2_forward(
        &self,
        request: Request<h2::RecvStream>,
        response: &ResponseSlot,
        session: StreamSession,
        cancellation: CancellationToken,
    ) -> io::Result<()> {
        if request.method() == Method::CONNECT {
            return local(response, StatusCode::METHOD_NOT_ALLOWED, None);
        }
        let length = match h2_headers::request(request.headers()) {
            Ok(length) => length,
            Err(_) => return local(response, StatusCode::BAD_REQUEST, None),
        };
        let original_fields = headers::from_map(request.headers());
        let mut original_meta = OriginalRequestMeta::new(
            request.method().as_str(),
            original_fields.as_ref().unwrap_or(&Vec::new()),
        );
        if original_fields.is_none() {
            original_meta.identity_allowed = false;
        }
        let wire = original_fields.as_ref().map(|fields| {
            WireBodyMeta::new(fields, &original_meta, Phase::Request, None, length, false)
        });
        let (original, asterisk) = match original_url(&request) {
            Ok(value) => value,
            Err(_) => return local(response, StatusCode::BAD_REQUEST, None),
        };
        let scripts_selected = self.has_scripts(&original, Phase::Request)
            || self.has_scripts(&original, Phase::Response);
        let original_snapshot = scripts_selected.then(|| OriginalSnapshot {
            url: original.clone(),
            method: request.method().as_str().to_owned(),
            identity_allowed: original_meta.identity_allowed,
            asterisk,
        });
        let base_session = session.clone();
        let mut target = match self.plan(original, session, Scheme::Https, !asterisk) {
            Ok(Decision::Reject) => return local(response, StatusCode::FORBIDDEN, None),
            Ok(Decision::Redirect { status, url }) => {
                return local(
                    response,
                    StatusCode::from_u16(status).map_err(|_| failed())?,
                    Some(url.as_str()),
                );
            }
            Ok(Decision::Forward(target)) => *target,
            Err(error) => {
                return local(
                    response,
                    if error.kind() == io::ErrorKind::PermissionDenied {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::BAD_GATEWAY
                    },
                    None,
                );
            }
        };
        if request.headers().contains_key("expect") && !request.body().is_end_stream() {
            response.continue_upload()?;
        }
        let (mut parts, body) = request.into_parts();
        parts.headers = h2_headers::clean(parts.headers, target.strip_origin_credentials, true)?;
        headers::apply_map(
            self.policy().rules(),
            &target.original,
            Phase::Request,
            &mut parts.headers,
        );
        let (mut body, mut length, entity) = self
            .prepare_body(
                h2_body::Source::h2(body),
                &target.original,
                &mut parts.headers,
                BodyMessage {
                    phase: Phase::Request,
                    wire,
                    expected: length,
                    strip_credentials: target.strip_origin_credentials,
                    scripts: original_fields.is_some(),
                    asterisk,
                },
            )
            .await?;
        let mut final_request = scripts_selected
            .then(|| headers::from_map(&parts.headers))
            .flatten()
            .map(|fields| RequestSnapshot {
                url: target.url.clone(),
                method: parts.method.as_str().to_owned(),
                headers: fields,
            });
        if self.has_scripts(&target.original, Phase::Request) {
            if let Some(request_snapshot) = final_request.take() {
                let mut message = Message::request(
                    original_snapshot
                        .as_ref()
                        .expect("selected script context")
                        .clone(),
                    request_snapshot,
                    entity,
                    original_fields.as_ref().unwrap_or(&Vec::new()),
                    target.strip_origin_credentials,
                );
                match script_message::run(
                    self.policy(),
                    &target.original,
                    &mut message,
                    &cancellation,
                )
                .await
                {
                    Ok(Outcome::Forward) => {
                        if let Some(entity) = message.body.take().filter(Entity::changed) {
                            length = Some(entity.wire().len() as u64);
                            body = h2_body::Source::buffered(entity.into_wire(), None);
                        }
                        parts.method = Method::from_bytes(message.request.method.as_bytes())
                            .map_err(|_| failed())?;
                        parts.headers =
                            headers::to_map(message.request.headers.clone()).ok_or_else(failed)?;
                        let sticky = message.crossed_origin;
                        target = self.final_target(
                            target.original.clone(),
                            message.request.url.clone(),
                            base_session,
                            Scheme::Https,
                        )?;
                        // This flag is used for trailers, never a second ordinary
                        // credential cleanup after explicit script operations.
                        target.strip_origin_credentials |= sticky;
                        final_request = Some(message.request);
                    }
                    Ok(Outcome::Respond(local_response)) => {
                        let fully_collected = message.body.is_some();
                        drop(message);
                        if fully_collected {
                            // The collector already returned the receive owner;
                            // only obsolete buffered wire bytes remain here.
                            drop(body);
                            return send_local(response, local_response).await;
                        }
                        // Keep the receive half alive until the final response
                        // has been committed; dropping it first can reset the
                        // stream before the client receives its local result.
                        let result = send_local(response, local_response).await;
                        drop(body);
                        return result;
                    }
                    Ok(Outcome::Abort) => return Err(failed()),
                    Err(error) if cancellation.is_cancelled() => return Err(error),
                    Err(_) => return local(response, StatusCode::BAD_GATEWAY, None),
                }
            } else {
                self.skip_unrepresentable(&target.original, Phase::Request);
            }
        }
        let request = Request::from_parts(parts, body);
        let metadata = MessageMeta {
            original: original_meta,
            length,
            asterisk,
            script: original_snapshot.map(|original| ScriptExchange {
                original,
                request: final_request,
                cancellation,
            }),
        };
        let (io, protocol) = self.http_upstream(&target).await?;
        if protocol.as_deref() == Some(b"h2") {
            self.h2_upstream(io, request, response, target, metadata)
                .await
        } else {
            self.h1_upstream(io, request, response, target, metadata)
                .await
        }
    }
    async fn prepare_body(
        &self,
        source: h2_body::Source,
        original: &url::Url,
        headers: &mut http::HeaderMap,
        message: BodyMessage,
    ) -> io::Result<(h2_body::Source, Option<u64>, Option<Entity>)> {
        let Some(wire) = message.wire else {
            return Ok((source, message.expected, None));
        };
        if message.scripts && self.has_scripts(original, message.phase) {
            let Some(mut fields) = headers::from_map(headers) else {
                return Ok((source, message.expected, None));
            };
            let script_body = !message.asterisk
                && self.policy().scripts().iter().any(|script| {
                    script.phase == message.phase
                        && script.matches(original)
                        && script.body != BodyMode::None
                });
            let Ok(transaction) = Transaction::begin_shared(
                self.policy().body_budget(),
                self.policy().rules(),
                original,
                message.phase,
                &wire,
                script_body,
            ) else {
                return Ok((source, message.expected, None));
            };
            let prepared = h2_body::prepare_shared(
                source,
                transaction,
                message.expected,
                message.strip_credentials,
                &mut fields,
            )
            .await?;
            *headers = headers::to_map(fields).ok_or_else(failed)?;
            return Ok((prepared.source, prepared.expected, prepared.entity));
        }
        let Ok(transaction) = Transaction::begin(
            self.policy().body_budget(),
            self.policy().rules(),
            original,
            message.phase,
            &wire,
        ) else {
            return Ok((source, message.expected, None));
        };
        let prepared = h2_body::prepare(
            source,
            transaction,
            message.expected,
            message.strip_credentials,
            headers,
        )
        .await?;
        Ok((prepared.source, prepared.expected, None))
    }
    fn has_scripts(&self, original: &url::Url, phase: Phase) -> bool {
        self.policy()
            .scripts()
            .iter()
            .any(|script| script.phase == phase && script.matches(original))
    }

    fn skip_unrepresentable(&self, original: &url::Url, phase: Phase) {
        for script in self
            .policy()
            .scripts()
            .iter()
            .filter(|script| script.phase == phase && script.matches(original))
        {
            tracing::debug!(target: "vole::http_processing::script", script = %script.name, phase = ?phase,
                reason="input-unrepresentable", "HTTP script skipped");
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_response(
        &self,
        mut parts: http::response::Parts,
        source: h2_body::Source,
        method: &Method,
        target: &Target,
        original_meta: &OriginalRequestMeta,
        script: Option<&ScriptExchange>,
        response: &ResponseSlot,
    ) -> io::Result<()> {
        response.received_final()?;
        let expected = h2_headers::response_body(&parts.headers, parts.status, method)?;
        let wire_fields = headers::from_map(&parts.headers);
        let wire = wire_fields.as_ref().map(|fields| {
            WireBodyMeta::new(
                fields,
                original_meta,
                Phase::Response,
                Some(parts.status.as_u16()),
                expected,
                false,
            )
        });
        headers::apply_map(
            self.policy().rules(),
            &target.original,
            Phase::Response,
            &mut parts.headers,
        );
        parts.headers = h2_headers::clean(parts.headers, false, false)?;
        let (mut source, mut expected, entity) = self
            .prepare_body(
                source,
                &target.original,
                &mut parts.headers,
                BodyMessage {
                    phase: Phase::Response,
                    wire,
                    expected,
                    strip_credentials: false,
                    scripts: script.is_some_and(|script| script.request.is_some())
                        && wire_fields.is_some(),
                    asterisk: false,
                },
            )
            .await?;
        if self.has_scripts(&target.original, Phase::Response) {
            let script = script.ok_or_else(failed)?;
            if let (Some(request), Some(fields), Some(original_fields)) = (
                script.request.as_ref(),
                headers::from_map(&parts.headers),
                wire_fields.as_ref(),
            ) {
                let mut message = Message::response(
                    script.original.clone(),
                    request.clone(),
                    ResponseSnapshot {
                        status: parts.status.as_u16(),
                        headers: fields,
                    },
                    entity,
                    original_fields,
                );
                match script_message::run(
                    self.policy(),
                    &target.original,
                    &mut message,
                    &script.cancellation,
                )
                .await
                {
                    Ok(Outcome::Forward) => {
                        if let Some(entity) = message.body.take().filter(Entity::changed) {
                            expected = Some(entity.wire().len() as u64);
                            source = h2_body::Source::buffered(entity.into_wire(), None);
                        }
                        let result = message.response.take().ok_or_else(failed)?;
                        parts.status = StatusCode::from_u16(result.status).map_err(|_| failed())?;
                        parts.headers = headers::to_map(result.headers).ok_or_else(failed)?;
                    }
                    Ok(Outcome::Respond(local_response)) => {
                        drop(message);
                        drop(source);
                        return send_local(response, local_response).await;
                    }
                    Ok(Outcome::Abort) => return Err(failed()),
                    Err(error) if script.cancellation.is_cancelled() => return Err(error),
                    Err(_) => return local(response, StatusCode::BAD_GATEWAY, None),
                }
            } else {
                self.skip_unrepresentable(&target.original, Phase::Response);
            }
        }
        parts.version = Version::HTTP_2;
        h2_headers::check(&parts.headers)?;
        let downstream = response.final_response(Response::from_parts(parts, ()), false)?;
        h2_body::relay(source, downstream, expected, false).await
    }
    async fn http_upstream(&self, target: &Target) -> io::Result<(BoxStream, Option<Vec<u8>>)> {
        let deadline = Instant::now() + SETUP;
        let stream = timeout_at(
            deadline,
            self.dispatcher().connect_tcp(target.session.clone()),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(|_| failed())?;
        if target.url.scheme() == "http" {
            return Ok((stream, None));
        }
        let tls = StandardTlsClient::with_options(
            self.security(),
            target
                .url
                .host_str()
                .ok_or_else(failed)?
                .trim_matches(['[', ']']),
            TlsClientOptions {
                alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                ..Default::default()
            },
            0,
            32 * 1024,
        )?;
        timeout_at(deadline, tls.connect_negotiated(stream))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(|_| failed())
    }
    async fn h2_upstream(
        &self,
        io: BoxStream,
        request: Request<h2_body::Source>,
        response: &ResponseSlot,
        target: Target,
        metadata: MessageMeta,
    ) -> io::Result<()> {
        let MessageMeta {
            original: original_meta,
            length,
            asterisk,
            script,
        } = metadata;
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(32 * 1024)
            .initial_connection_window_size(64 * 1024)
            .header_table_size(0)
            .max_header_list_size(32 * 1024)
            .max_frame_size(16 * 1024)
            .max_send_buffer_size(16 * 1024)
            .enable_push(false)
            .max_concurrent_streams(1);
        let (sender, driver) = timeout(SETUP, builder.handshake::<_, Bytes>(io))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
            .map_err(|_| failed())?;
        let exchange = Box::pin(async {
            let (parts, body) = request.into_parts();
            let method = parts.method.clone();
            // Original credentials were removed before request-header actions.
            // A second origin cleanup must not erase explicitly supplied ones.
            let mut headers = h2_headers::clean(parts.headers, false, true)?;
            headers.remove("expect");
            let uri = if asterisk {
                http::Uri::builder()
                    .scheme("https")
                    .authority(target.logical_destination.authority())
                    .path_and_query("*")
                    .build()
                    .map_err(|_| failed())?
            } else {
                target.url.as_str().parse().map_err(|_| failed())?
            };
            let mut outgoing = Request::builder()
                .method(parts.method)
                .uri(uri)
                .version(Version::HTTP_2)
                .body(())
                .map_err(|_| failed())?;
            *outgoing.headers_mut() = headers;
            let mut sender = sender.ready().await.map_err(|_| failed())?;
            let (mut incoming, upload) =
                sender.send_request(outgoing, false).map_err(|_| failed())?;
            let (upload_finished, uploaded) = tokio::sync::oneshot::channel();
            let upload = async move {
                let result =
                    h2_body::relay(body, upload, length, target.strip_origin_credentials).await;
                if result.is_ok() {
                    let _ = upload_finished.send(());
                }
                result
            };
            let download = async {
                let incoming = response_after_upload(uploaded, async {
                    let mut infos = 0;
                    loop {
                        let event = poll_fn(|cx| {
                            if let Poll::Ready(Some(info)) = incoming.poll_informational(cx) {
                                return Poll::Ready(info.map(Head::Informational));
                            }
                            Pin::new(&mut incoming)
                                .poll(cx)
                                .map(|value| value.map(Head::Final))
                        })
                        .await
                        .map_err(|_| failed())?;
                        match event {
                            Head::Informational(info) => {
                                infos += 1;
                                if infos > 16 {
                                    return Err(failed());
                                }
                                if info.status() != StatusCode::CONTINUE {
                                    let (mut parts, ()) = info.into_parts();
                                    parts.headers = h2_headers::clean(parts.headers, false, false)?;
                                    response
                                        .informational(Response::from_parts(parts, ()))
                                        .map_err(|_| failed())?;
                                }
                            }
                            Head::Final(incoming) => {
                                response.received_final()?;
                                break Ok(incoming);
                            }
                        }
                    }
                })
                .await?;
                let (parts, body) = incoming.into_parts();
                self.forward_response(
                    parts,
                    h2_body::Source::h2(body),
                    &method,
                    &target,
                    &original_meta,
                    script.as_ref(),
                    response,
                )
                .await
            };
            // A complete final response ends this exchange even when the
            // client has not finished uploading. Dropping the inline upload
            // returns its receive owner; h2 closes that half with NO_ERROR
            // after the final response, without blocking sibling streams.
            tokio::pin!(upload);
            tokio::pin!(download);
            tokio::select! {biased;
                result=&mut download=>result,
                result=&mut upload=>{
                    // An early final response may reset the upstream's input
                    // before its nonempty response has crossed the downstream
                    // window. Once headers were committed, finish that bounded
                    // response rather than replacing it with a reset.
                    if result.is_err() && !response.upstream_final_received() { result?; }
                    download.await
                }
            }
        });
        inline_driver(driver, exchange).await
    }
    async fn h1_upstream(
        &self,
        io: BoxStream,
        request: Request<h2_body::Source>,
        response: &ResponseSlot,
        target: Target,
        metadata: MessageMeta,
    ) -> io::Result<()> {
        let MessageMeta {
            original: original_meta,
            length,
            asterisk,
            script,
        } = metadata;
        let (mut sender, driver) = timeout(
            SETUP,
            hyper::client::conn::http1::Builder::new()
                .max_headers(100)
                .max_buf_size(32 * 1024)
                .writev(true)
                .handshake::<_, h2_h1::Upload>(hyper_util::rt::TokioIo::new(io)),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(|_| failed())?;
        // Hyper requires a static informational callback. Only this bounded
        // request handle is shared; no body queue or extra task is introduced.
        let state = response.clone();
        let info_cancel = CancellationToken::new();
        let upload_idle = h2_h1::UploadIdle::new();
        let exchange = Box::pin(async {
            let (parts, body) = request.into_parts();
            let method = parts.method.clone();
            let mut headers = h2_headers::clean(parts.headers, false, true)?;
            headers.remove("expect");
            headers.remove("te");
            headers.insert(
                "host",
                HeaderValue::from_str(&target.logical_destination.authority())
                    .map_err(|_| failed())?,
            );
            let mut path = if asterisk {
                "*".to_owned()
            } else {
                target.url.path().to_owned()
            };
            if !asterisk && let Some(query) = target.url.query() {
                path.push('?');
                path.push_str(query);
            }
            let mut request = Request::builder()
                .method(parts.method)
                .uri(path)
                .version(Version::HTTP_11)
                .body(h2_h1::Upload::new(
                    body,
                    length,
                    target.strip_origin_credentials,
                    upload_idle.clone(),
                ))
                .map_err(|_| failed())?;
            *request.headers_mut() = headers;
            let info = state.clone();
            let cancel_info = info_cancel.clone();
            hyper::ext::on_informational(&mut request, move |response| {
                let outcome = (|| {
                    // Check before cloning Hyper's borrowed response head.
                    h2_headers::check(response.headers())?;
                    let headers = h2_headers::clean(response.headers().clone(), false, false)?;
                    let mut message = Response::builder()
                        .status(response.status())
                        .version(Version::HTTP_2)
                        .body(())
                        .map_err(|_| failed())?;
                    *message.headers_mut() = headers;
                    info.informational(message)
                })();
                if outcome.is_err() {
                    cancel_info.cancel();
                }
            });
            sender.ready().await.map_err(|_| failed())?;
            let incoming = upload_idle
                .wait_response(sender.send_request(request))
                .await?;
            if incoming.status() == StatusCode::SWITCHING_PROTOCOLS {
                return Err(failed());
            }
            let (parts, body) = incoming.into_parts();
            self.forward_response(
                parts,
                h2_body::Source::h1(body),
                &method,
                &target,
                &original_meta,
                script.as_ref(),
                &state,
            )
            .await
        });
        tokio::select! {biased;()=info_cancel.cancelled()=>Err(failed()),result=inline_driver(driver,exchange)=>result}
    }
}
async fn response_after_upload<F, T>(
    uploaded: tokio::sync::oneshot::Receiver<()>,
    response: F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::pin!(response);
    // Keep accepting early responses while the separately bounded upload is
    // active. A response head gets its own idle budget only after upload EOS.
    tokio::select! {biased;
        result=&mut response=>result,
        result=uploaded=>{
            result.map_err(|_|failed())?;
            timeout(IDLE,response).await.map_err(|_|io::ErrorKind::TimedOut)?
        }
    }
}
enum Head {
    Informational(Response<()>),
    Final(Response<h2::RecvStream>),
}
#[derive(Clone)]
struct ResponseSlot(Arc<Mutex<ResponseState>>);
struct ResponseState {
    response: h2::server::SendResponse<Bytes>,
    infos: usize,
    final_started: bool,
    upstream_final_received: bool,
}
impl ResponseSlot {
    fn received_final(&self) -> io::Result<()> {
        self.0.lock().map_err(|_| failed())?.upstream_final_received = true;
        Ok(())
    }
    fn upstream_final_received(&self) -> bool {
        self.0
            .lock()
            .is_ok_and(|state| state.upstream_final_received)
    }
    fn informational(&self, response: Response<()>) -> io::Result<()> {
        let mut state = self.0.lock().map_err(|_| failed())?;
        state.infos += 1;
        if state.infos > 16 {
            return Err(failed());
        }
        // 100 Continue is acknowledged locally, once, before upload forwarding.
        if response.status() == StatusCode::CONTINUE {
            return Ok(());
        }
        state
            .response
            .send_informational(response)
            .map_err(|_| failed())
    }
    fn continue_upload(&self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| failed())?
            .response
            .send_informational(
                Response::builder()
                    .status(StatusCode::CONTINUE)
                    .body(())
                    .map_err(|_| failed())?,
            )
            .map_err(|_| failed())
    }
    fn final_response(
        &self,
        response: Response<()>,
        end: bool,
    ) -> io::Result<h2::SendStream<Bytes>> {
        let mut state = self.0.lock().map_err(|_| failed())?;
        let stream = state
            .response
            .send_response(response, end)
            .map_err(|_| failed())?;
        state.final_started = true;
        Ok(stream)
    }
    fn final_started(&self) -> bool {
        self.0.lock().is_ok_and(|state| state.final_started)
    }
    fn reset(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.response.send_reset(h2::Reason::INTERNAL_ERROR);
        }
    }
}
async fn send_local(response: &ResponseSlot, result: LocalResponse) -> io::Result<()> {
    if response.final_started() {
        return Err(failed());
    }
    let length = result.body.len() as u64;
    let mut message = Response::builder()
        .status(result.status)
        .body(())
        .map_err(|_| failed())?;
    *message.headers_mut() = headers::to_map(result.headers).ok_or_else(failed)?;
    let downstream = response.final_response(message, length == 0)?;
    if length != 0 {
        h2_body::relay(
            h2_body::Source::buffered(result.body, None),
            downstream,
            Some(length),
            false,
        )
        .await?;
    }
    Ok(())
}
async fn inline_driver<D, E, T, X>(driver: D, exchange: E) -> io::Result<T>
where
    D: Future<Output = Result<(), X>>,
    E: Future<Output = io::Result<T>>,
{
    tokio::pin!(exchange);
    // Driver shutdown can fail after a complete response was delivered (for
    // example a peer closes before TLS close_notify is flushed). The response
    // and body futures own message integrity, including errors on truncation;
    // do not replace buffered valid data with the driver's shutdown result.
    {
        tokio::pin!(driver);
        tokio::select! {biased;result=&mut exchange=>return result,_=&mut driver=>{}}
    }
    // Drop a completed driver before waiting, so its remaining senders cannot
    // keep a failed ResponseFuture or body channel artificially alive.
    exchange.await
}
fn local(response: &ResponseSlot, status: StatusCode, location: Option<&str>) -> io::Result<()> {
    let mut message = Response::builder()
        .status(status)
        .header("content-length", "0");
    if let Some(location) = location {
        message = message.header("location", location);
    }
    response
        .final_response(message.body(()).map_err(|_| failed())?, true)
        .map_err(|_| failed())?;
    Ok(())
}
fn original_url(request: &Request<h2::RecvStream>) -> io::Result<(url::Url, bool)> {
    let uri = request.uri();
    if uri.scheme_str() != Some("https") {
        return Err(failed());
    }
    let authority = uri.authority().ok_or_else(failed)?.as_str();
    let path = uri.path_and_query().map_or("/", |path| path.as_str());
    let asterisk = path == "*" && request.method() == Method::OPTIONS;
    if path.len() > 8192 || (!asterisk && (!path.starts_with('/') || path.starts_with("//"))) {
        return Err(failed());
    }
    let url = checked_url(&format!(
        "https://{authority}{}",
        if asterisk { "/" } else { path }
    ))?;
    let mut hosts = request.headers().get_all("host").iter();
    if let Some(host) = hosts.next() {
        if hosts.next().is_some() {
            return Err(failed());
        }
        let host = checked_url(&format!(
            "https://{}/",
            host.to_str().map_err(|_| failed())?
        ))?;
        if host.host() != url.host() || host.port_or_known_default() != url.port_or_known_default()
        {
            return Err(failed());
        }
    }
    Ok((url, asterisk))
}
