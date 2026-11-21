//! Optional HTTP/1 entity probing. Unselected messages retain the old relay.
use super::{
    Policy,
    body::{self, BudgetedBytes, OriginalRequestMeta, Transaction, WireBodyMeta},
    headers::Fields,
    rules::{HeaderView, Phase, RequestMatch},
};
use super::{
    script_config::BodyMode,
    script_message::{self, OriginalSnapshot, Outcome, RequestSnapshot, ResponseSnapshot},
};
use crate::inbound::http::{
    HttpServerConfig, RequestHead,
    framing::{self, Body, RequestPlan, ResponseHead},
};
use bytes::Bytes;
use std::{
    collections::HashSet,
    io,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use url::Url;

pub(crate) struct ScriptContext {
    pub(crate) original: OriginalSnapshot,
    pub(crate) request: RequestSnapshot,
    pub(crate) cancellation: CancellationToken,
}

pub(crate) struct Message<'a> {
    pub(crate) policy: &'a Policy,
    pub(crate) original: &'a Url,
    pub(crate) request: &'a RequestHead,
    pub(crate) request_conditions: u64,
    pub(crate) meta: OriginalRequestMeta,
    pub(crate) continued: AtomicBool,
    pub(crate) prepared: std::sync::Mutex<Option<PreparedBody>>,
    pub(crate) scripts: Option<ScriptContext>,
}

impl Message<'_> {
    fn selection(&self, response_conditions: u64) -> RequestMatch<'_> {
        RequestMatch::from((self.original, self.request.method.as_str()))
            .with_conditions(self.request_conditions, response_conditions)
    }

    pub(crate) fn suppress_continue(&self) -> bool {
        self.continued.load(Ordering::Relaxed)
    }
    pub(crate) async fn request<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        reader: &mut R,
        writer: &mut W,
        plan: &mut RequestPlan,
        config: &HttpServerConfig,
    ) -> io::Result<PreparedBody> {
        if let Some(prepared) = self
            .prepared
            .lock()
            .map_err(|_| io::Error::other("HTTP upload owner poisoned"))?
            .take()
        {
            return Ok(prepared);
        }
        let wire = WireBodyMeta::new(
            &self.request.headers,
            &self.meta,
            Phase::Request,
            None,
            length(plan.body),
            !plan.upgrade.is_empty(),
        );
        let transaction = Transaction::begin(
            self.policy.body_budget(),
            self.policy.rules(),
            self.selection(0),
            Phase::Request,
            &wire,
        )
        .ok();
        if transaction.is_some()
            && self
                .request
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
            framing::timeout_io(config.header_timeout, writer.flush()).await?;
            self.continued.store(true, Ordering::Relaxed);
            plan.edit_headers(|fields| {
                fields.retain(|(name, _)| !name.eq_ignore_ascii_case("expect"))
            })?;
        }
        let mut prepared = probe(
            reader,
            plan.body,
            &plan.trailer_blocklist,
            config.body_idle_timeout,
            transaction,
        )
        .await?;
        if prepared.result.is_some() {
            plan.edit_headers(|fields| prepared.finalize_headers(fields))?;
        }
        Ok(prepared)
    }

    pub(crate) async fn response<R: AsyncBufRead + Unpin>(
        &self,
        reader: &mut R,
        response: &mut ResponseHead,
        config: &HttpServerConfig,
    ) -> io::Result<PreparedBody> {
        let body = response.body(&self.request.method);
        let response_conditions = self
            .policy
            .response_conditions(response.status, HeaderView::Fields(response.headers()));
        let selection = self.selection(response_conditions);
        let wire = WireBodyMeta::new(
            response.headers(),
            &self.meta,
            Phase::Response,
            Some(response.status),
            length(body),
            response.status == 101,
        );
        let scripts = self.scripts.as_ref().filter(|_| {
            self.policy
                .scripts()
                .iter()
                .any(|script| script.phase == Phase::Response && script.matches(selection))
        });
        let original_fields = scripts.map(|_| response.headers().clone());
        self.apply_response_headers(response, selection)?;
        if let Some(script) = scripts {
            let wants_body = self.policy.scripts().iter().any(|s| {
                s.phase == Phase::Response && s.body != BodyMode::None && s.matches(selection)
            });
            let transaction = Transaction::begin_shared(
                self.policy.body_budget(),
                self.policy.rules(),
                selection,
                Phase::Response,
                &wire,
                wants_body,
            )
            .ok();
            let mut fields = response.headers().clone();
            let (mut prepared, entity) = prepare_shared(
                reader,
                body,
                response.trailer_blocklist(),
                config.body_idle_timeout,
                transaction,
                &mut fields,
            )
            .await?;
            let mut message = script_message::Message::response(
                script.original.clone(),
                script.request.clone(),
                ResponseSnapshot {
                    status: response.status,
                    headers: fields,
                },
                entity,
                original_fields.as_ref().expect("script wire headers"),
            )
            .with_conditions(self.request_conditions, response_conditions);
            let outcome = match script_message::run(
                self.policy,
                self.original,
                &mut message,
                &script.cancellation,
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(error)
                    if script.cancellation.is_cancelled()
                        || error.kind() == io::ErrorKind::Interrupted =>
                {
                    return Err(error);
                }
                Err(_) => {
                    response.replace(502, vec![("Content-Length".into(), "0".into())])?;
                    return Ok(PreparedBody::from_bytes(Bytes::new()));
                }
            };
            match outcome {
                Outcome::Forward => {
                    let current = message.response.take().expect("response message");
                    response.replace(current.status, current.headers)?;
                    if let Some(entity) = message.body {
                        prepared.install_entity(entity);
                    }
                    return Ok(prepared);
                }
                Outcome::Respond(local) => {
                    drop(message);
                    drop(prepared);
                    response.replace(local.status, local.headers)?;
                    return Ok(PreparedBody::from_bytes(local.body));
                }
                Outcome::Abort => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "HTTP script aborted exchange",
                    ));
                }
            }
        }
        let transaction = Transaction::begin(
            self.policy.body_budget(),
            self.policy.rules(),
            selection,
            Phase::Response,
            &wire,
        )
        .ok();
        let mut prepared = probe(
            reader,
            body,
            response.trailer_blocklist(),
            config.body_idle_timeout,
            transaction,
        )
        .await?;
        if prepared.result.is_some() {
            response.edit_headers(|fields| prepared.finalize_headers(fields))?;
        }
        Ok(prepared)
    }

    /// Informational responses and successful upgrades have no body stage,
    /// but their ordinary fields still participate in the response pipeline.
    pub(crate) fn response_headers(&self, response: &mut ResponseHead) -> io::Result<()> {
        self.apply_response_headers(response, self.selection(0))
    }

    fn apply_response_headers(
        &self,
        response: &mut ResponseHead,
        selection: RequestMatch<'_>,
    ) -> io::Result<()> {
        response.edit_headers(|fields| {
            super::headers::apply(self.policy.rules(), selection, Phase::Response, fields);
        })
    }
}

fn length(body: Body) -> Option<u64> {
    match body {
        Body::Empty => Some(0),
        Body::Length(length) => Some(length),
        _ => None,
    }
}

// This wrapper belongs only to PreparedBody's body transfer, never the head.
// Both transfer paths call flush only after successful source/framing reads
// and all body/framing writes. Keep that invariant if intermediate flushes are added.
struct FinalFlushProbe<'a, W> {
    writer: &'a mut W,
    observed: &'a AtomicBool,
    eligible: bool,
}
impl<W: AsyncWrite + Unpin> AsyncWrite for FinalFlushProbe<'_, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.writer).poll_write(cx, bytes)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.writer).poll_write_vectored(cx, bytes)
    }
    fn is_write_vectored(&self) -> bool {
        self.writer.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.eligible {
            self.observed.store(true, Ordering::Release);
        }
        Pin::new(&mut *self.writer).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.writer).poll_shutdown(cx)
    }
}

pub(crate) struct PreparedBody {
    framing: Body,
    cursor: Option<Cursor>,
    prefix: Option<BudgetedBytes>,
    result: Option<body::ResultBody>,
    buffered: Option<Bytes>,
    origin_replaced: bool,
}
impl PreparedBody {
    pub(crate) fn from_bytes(bytes: Bytes) -> Self {
        Self {
            framing: Body::Length(bytes.len() as u64),
            cursor: Some(Cursor::new(Body::Empty)),
            prefix: None,
            result: None,
            buffered: Some(bytes),
            origin_replaced: true,
        }
    }
    pub(crate) fn install_entity(&mut self, entity: body::Entity) {
        if entity.changed() {
            self.framing = Body::Length(entity.wire().len() as u64);
        }
        self.buffered = Some(entity.into_wire());
    }
    fn finalize_headers(&mut self, fields: &mut Fields) {
        if let Some(mut result) = self.result.take() {
            result.finalize_headers(fields);
            if result.changed {
                self.framing = Body::Length(result.body.as_ref().len() as u64);
            }
            self.prefix = Some(result.body);
        }
    }
    pub(crate) fn original(body: Body) -> Self {
        Self {
            framing: body,
            cursor: None,
            prefix: None,
            result: None,
            buffered: None,
            origin_replaced: false,
        }
    }
    pub(crate) async fn transfer_observing_final_flush<
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    >(
        self,
        reader: &mut R,
        writer: &mut W,
        idle: Duration,
        blocklist: &HashSet<String>,
        dechunk: bool,
        observed: &AtomicBool,
    ) -> io::Result<()> {
        // Cursor framing is the real source, not the rewritten output length.
        // Unknown/generated sources and chunked/trailer paths gain no proof.
        let fixed_source = match self.cursor.as_ref() {
            Some(cursor) => matches!(cursor.body, Body::Empty | Body::Length(_)),
            None => self.buffered.is_none() && self.prefix.is_none() && self.result.is_none(),
        };
        let eligible = fixed_source
            && !self.origin_replaced
            && !dechunk
            && matches!(self.framing, Body::Empty | Body::Length(_));
        let mut writer = FinalFlushProbe {
            writer,
            observed,
            eligible,
        };
        self.transfer(reader, &mut writer, idle, blocklist, dechunk)
            .await
    }

    pub(crate) async fn transfer<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        self,
        reader: &mut R,
        writer: &mut W,
        idle: Duration,
        blocklist: &HashSet<String>,
        dechunk: bool,
    ) -> io::Result<()> {
        self.transfer_with_origin(reader, writer, idle, blocklist, dechunk)
            .await
            .map(|_| ())
    }
    pub(crate) async fn transfer_with_origin<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        self,
        reader: &mut R,
        writer: &mut W,
        idle: Duration,
        blocklist: &HashSet<String>,
        dechunk: bool,
    ) -> io::Result<bool> {
        let Some(mut cursor) = self.cursor else {
            framing::transfer_body(reader, writer, self.framing, idle, blocklist, dechunk).await?;
            return Ok(!self.origin_replaced && matches!(self.framing, Body::Length(_)));
        };
        // A later request script may have changed origin after collection.
        // Recheck against the final credential blocklist before any replay.
        for (name, _) in &cursor.trailers {
            if framing::forbidden_trailer(name, blocklist) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP trailer became forbidden after rewriting",
                ));
            }
        }
        let chunked = self.framing == Body::Chunked && !dechunk;
        if let Some(bytes) = self.buffered {
            send(writer, &bytes, chunked, idle).await?;
        }
        if let Some(prefix) = self.prefix {
            send(writer, prefix.as_ref(), chunked, idle).await?;
            // Keep the reservation until write_all actually completes.
            drop(prefix);
        }
        let mut bytes = [0u8; framing::COPY_BUFFER];
        loop {
            let count = cursor.read(reader, &mut bytes, idle, blocklist).await?;
            if count == 0 {
                break;
            }
            send(writer, &bytes[..count], chunked, idle).await?;
        }
        let consumed =
            !self.origin_replaced && cursor.done && matches!(cursor.body, Body::Length(0));
        if chunked {
            framing::write_timed(writer, b"0\r\n", idle).await?;
            for (name, value) in cursor.trailers {
                if framing::forbidden_trailer(&name, blocklist) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "forbidden HTTP trailer",
                    ));
                }
                framing::write_timed(writer, format!("{name}: {value}\r\n").as_bytes(), idle)
                    .await?;
            }
            framing::write_timed(writer, b"\r\n", idle).await?;
        }
        framing::timeout_io(idle, writer.flush()).await?;
        Ok(consumed)
    }
}

/// The cursor reads the wire once and keeps every over-limit prefix for replay.
pub(crate) async fn prepare_shared<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    framing: Body,
    blocklist: &HashSet<String>,
    idle: Duration,
    transaction: Option<Transaction<'_>>,
    fields: &mut Fields,
) -> io::Result<(PreparedBody, Option<body::Entity>)> {
    let Some(mut transaction) = transaction else {
        return Ok((PreparedBody::original(framing), None));
    };
    let mut cursor = Cursor::new(framing);
    let mut bytes = [0u8; framing::COPY_BUFFER];
    loop {
        if cursor.done || matches!(cursor.body, Body::Empty | Body::Length(0)) {
            let entity = transaction.finish_shared(!cursor.trailers.is_empty(), fields);
            let mut prepared = PreparedBody {
                framing,
                cursor: Some(cursor),
                prefix: None,
                result: None,
                buffered: None,
                origin_replaced: false,
            };
            prepared.install_entity(entity.clone());
            return Ok((prepared, Some(entity)));
        }
        let available = transaction.remaining().min(bytes.len());
        if available == 0 {
            super::diagnostics::body_bypass(
                super::diagnostics::BodyPoint::Collection,
                body::Bypass::Size,
            );
            return Ok((
                PreparedBody {
                    framing,
                    cursor: Some(cursor),
                    prefix: Some(transaction.into_raw()),
                    result: None,
                    buffered: None,
                    origin_replaced: false,
                },
                None,
            ));
        }
        let count = cursor
            .read(reader, &mut bytes[..available], idle, blocklist)
            .await?;
        if count == 0 {
            let entity = transaction.finish_shared(!cursor.trailers.is_empty(), fields);
            let mut prepared = PreparedBody {
                framing,
                cursor: Some(cursor),
                prefix: None,
                result: None,
                buffered: None,
                origin_replaced: false,
            };
            prepared.install_entity(entity.clone());
            return Ok((prepared, Some(entity)));
        }
        if transaction.push(&bytes[..count]).is_err() {
            return Ok((
                PreparedBody {
                    framing,
                    cursor: Some(cursor),
                    prefix: Some(transaction.into_raw()),
                    result: None,
                    buffered: None,
                    origin_replaced: false,
                },
                None,
            ));
        }
    }
}

async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    chunked: bool,
    idle: Duration,
) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    if chunked {
        framing::write_timed(writer, format!("{:x}\r\n", bytes.len()).as_bytes(), idle).await?;
    }
    framing::write_timed(writer, bytes, idle).await?;
    if chunked {
        framing::write_timed(writer, b"\r\n", idle).await?;
    }
    Ok(())
}

async fn probe<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    body: Body,
    blocklist: &HashSet<String>,
    idle: Duration,
    transaction: Option<Transaction<'_>>,
) -> io::Result<PreparedBody> {
    let Some(mut transaction) = transaction else {
        return Ok(PreparedBody::original(body));
    };
    let mut cursor = Cursor::new(body);
    let mut bytes = [0u8; framing::COPY_BUFFER];
    loop {
        if cursor.done || matches!(cursor.body, Body::Empty | Body::Length(0)) {
            let result = transaction.finish(!cursor.trailers.is_empty());
            return Ok(PreparedBody {
                framing: body,
                cursor: Some(cursor),
                prefix: None,
                result: Some(result),
                buffered: None,
                origin_replaced: false,
            });
        }
        let available = transaction.remaining().min(bytes.len());
        if available == 0 {
            super::diagnostics::body_bypass(
                super::diagnostics::BodyPoint::Collection,
                body::Bypass::Size,
            );
            return Ok(PreparedBody {
                framing: body,
                cursor: Some(cursor),
                prefix: Some(transaction.into_raw()),
                result: None,
                buffered: None,
                origin_replaced: false,
            });
        }
        let count = cursor
            .read(reader, &mut bytes[..available], idle, blocklist)
            .await?;
        if count == 0 {
            let result = transaction.finish(!cursor.trailers.is_empty());
            return Ok(PreparedBody {
                framing: body,
                cursor: Some(cursor),
                prefix: None,
                result: Some(result),
                buffered: None,
                origin_replaced: false,
            });
        }
        if transaction.push(&bytes[..count]).is_err() {
            return Ok(PreparedBody {
                framing: body,
                cursor: Some(cursor),
                prefix: Some(transaction.into_raw()),
                result: None,
                buffered: None,
                origin_replaced: false,
            });
        }
    }
}

struct Cursor {
    body: Body,
    chunk_remaining: u64,
    chunk_crlf: bool,
    done: bool,
    trailers: Fields,
}
impl Cursor {
    fn new(body: Body) -> Self {
        Self {
            body,
            chunk_remaining: 0,
            chunk_crlf: false,
            done: false,
            trailers: vec![],
        }
    }
    async fn read<R: AsyncBufRead + Unpin>(
        &mut self,
        reader: &mut R,
        output: &mut [u8],
        idle: Duration,
        blocklist: &HashSet<String>,
    ) -> io::Result<usize> {
        if self.done || matches!(self.body, Body::Empty | Body::Length(0)) {
            self.done = true;
            return Ok(0);
        }
        if self.body == Body::Chunked && self.chunk_remaining == 0 {
            if self.chunk_crlf {
                let mut crlf = [0; 2];
                framing::timeout_io(idle, reader.read_exact(&mut crlf)).await?;
                if crlf != *b"\r\n" {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
            let line = framing::timeout_io(idle, framing::read_line(reader, 1024)).await?;
            self.chunk_remaining = framing::chunk_size(&line)?;
            self.chunk_crlf = true;
            if self.chunk_remaining == 0 {
                let mut bytes = 0;
                loop {
                    let line = framing::timeout_io(
                        idle,
                        framing::read_line(reader, 8192usize.saturating_sub(bytes)),
                    )
                    .await?;
                    bytes += line.len();
                    if line == b"\r\n" {
                        break;
                    }
                    if self.trailers.len() >= 100 {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    let text = std::str::from_utf8(&line[..line.len() - 2])
                        .map_err(|_| io::ErrorKind::InvalidData)?;
                    let mut fields =
                        crate::inbound::http::parser::parse_headers(std::iter::once(text))?;
                    if framing::forbidden_trailer(&fields[0].0, blocklist) {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    self.trailers.append(&mut fields);
                }
                self.done = true;
                return Ok(0);
            }
        }
        let limit = match self.body {
            Body::Length(remaining) => remaining.min(output.len() as u64) as usize,
            Body::Chunked => self.chunk_remaining.min(output.len() as u64) as usize,
            _ => output.len(),
        };
        let count = framing::timeout_io(idle, reader.read(&mut output[..limit])).await?;
        if count == 0 {
            if self.body != Body::UntilEof {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.done = true;
        }
        match &mut self.body {
            Body::Length(remaining) => *remaining -= count as u64,
            Body::Chunked => self.chunk_remaining -= count as u64,
            _ => {}
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(unix, feature = "inbound-http"))]
    #[forbid(unsafe_code)]
    mod shared_collector_mapping_tests {
        include!("shared_collector_h1_memory_tests.rs");
    }

    #[cfg(all(unix, feature = "inbound-http"))]
    #[forbid(unsafe_code)]
    mod shared_collector_c15_gap_tests {
        include!("shared_collector_c15_cancel_metadata_memory_tests.rs");
    }
    #[tokio::test]
    async fn collected_cookie_trailer_cannot_cross_a_later_script_origin_change() {
        let budget = body::Budget::default();
        let original = Url::parse("http://a.example/").unwrap();
        let meta = OriginalRequestMeta::new("POST", &vec![]);
        let wire = WireBodyMeta::new(&vec![], &meta, Phase::Request, None, None, false);
        let transaction =
            Transaction::begin_shared(&budget, &[], &original, Phase::Request, &wire, true)
                .unwrap();
        let mut reader = b"3\r\nold\r\n0\r\nCookie: old-secret\r\n\r\n".as_slice();
        let mut fields = vec![];
        let (prepared, entity) = prepare_shared(
            &mut reader,
            Body::Chunked,
            &HashSet::new(),
            Duration::from_secs(1),
            Some(transaction),
            &mut fields,
        )
        .await
        .unwrap();
        assert!(
            entity
                .as_ref()
                .is_some_and(|entity| entity.logical().is_none())
        );
        let mut final_blocklist = HashSet::new();
        final_blocklist.insert("cookie".into());
        let mut sent = Vec::new();
        let error = prepared
            .transfer(
                &mut reader,
                &mut sent,
                Duration::from_secs(1),
                &final_blocklist,
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(sent.is_empty());
        drop(entity);
        assert_eq!(budget.used(), 0);
    }
    fn rules() -> Vec<super::super::rules::Rule> {
        let value: serde_yaml_ng::Value =
            serde_yaml_ng::from_str("{url: '.', action: response-body-set, value: changed}")
                .unwrap();
        vec![
            super::super::rules::Rule::compile(serde_yaml_ng::from_value(value).unwrap(), &mut 0)
                .unwrap(),
        ]
    }
    #[tokio::test]
    async fn entity_probe_preserves_overflow_and_late_trailers() {
        let rules = rules();
        let url = Url::parse("http://example.com/").unwrap();
        let meta = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(200), None, false);
        let budget = body::Budget::default();
        let payload = vec![b'x'; body::MAX_BODY + 123];
        let mut input = format!("{:x}\r\n", payload.len()).into_bytes();
        input.extend_from_slice(&payload);
        input.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut reader = input.as_slice();
        let transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        let prepared = probe(
            &mut reader,
            Body::Chunked,
            &HashSet::new(),
            Duration::from_secs(1),
            Some(transaction),
        )
        .await
        .unwrap();
        let mut output = vec![];
        prepared
            .transfer(
                &mut reader,
                &mut output,
                Duration::from_secs(1),
                &HashSet::new(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(output, payload);
        assert!(reader.is_empty());
        assert_eq!(budget.used(), 0);

        let mut reader = b"3\r\nold\r\n0\r\nX-End: present\r\n\r\n".as_slice();
        let transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        let mut prepared = probe(
            &mut reader,
            Body::Chunked,
            &HashSet::new(),
            Duration::from_secs(1),
            Some(transaction),
        )
        .await
        .unwrap();
        prepared.finalize_headers(&mut vec![]);
        let mut output = vec![];
        prepared
            .transfer(
                &mut reader,
                &mut output,
                Duration::from_secs(1),
                &HashSet::new(),
                false,
            )
            .await
            .unwrap();
        assert_eq!(output, b"3\r\nold\r\n0\r\nX-End: present\r\n\r\n");
    }
    #[tokio::test]
    async fn known_length_commits_only_complete_entities() {
        let rules = rules();
        let url = Url::parse("http://example.com/").unwrap();
        let budget = body::Budget::default();
        let meta = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(200), Some(3), false);
        let transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        let mut reader = b"old".as_slice();
        let mut prepared = probe(
            &mut reader,
            Body::Length(3),
            &HashSet::new(),
            Duration::from_secs(1),
            Some(transaction),
        )
        .await
        .unwrap();
        let mut fields = vec![("Content-Length".into(), "3".into())];
        prepared.finalize_headers(&mut fields);
        let mut output = vec![];
        prepared
            .transfer(
                &mut reader,
                &mut output,
                Duration::from_secs(1),
                &HashSet::new(),
                false,
            )
            .await
            .unwrap();
        assert_eq!(output, b"changed");
        assert_eq!(fields, vec![("Content-Length".into(), "7".into())]);
        let wire = WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(200), Some(4), false);
        let transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        assert!(
            probe(
                &mut b"old".as_slice(),
                Body::Length(4),
                &HashSet::new(),
                Duration::from_secs(1),
                Some(transaction)
            )
            .await
            .is_err()
        );
    }
}
