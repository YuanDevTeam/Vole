//! Optional HTTP/1 entity probing. Unselected messages retain the old relay.
use super::{
    Policy,
    body::{self, BudgetedBytes, OriginalRequestMeta, Transaction, WireBodyMeta},
    headers::Fields,
    rules::Phase,
};
use crate::inbound::http::{
    HttpServerConfig, RequestHead,
    framing::{self, Body, RequestPlan, ResponseHead},
};
use std::{
    collections::HashSet,
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

pub(crate) struct Message<'a> {
    pub(crate) policy: &'a Policy,
    pub(crate) original: &'a Url,
    pub(crate) request: &'a RequestHead,
    pub(crate) meta: OriginalRequestMeta,
    pub(crate) continued: AtomicBool,
}

impl Message<'_> {
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
            self.original,
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
        let wire = WireBodyMeta::new(
            response.headers(),
            &self.meta,
            Phase::Response,
            Some(response.status),
            length(body),
            response.status == 101,
        );
        self.response_headers(response)?;
        let transaction = Transaction::begin(
            self.policy.body_budget(),
            self.policy.rules(),
            self.original,
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
        response.edit_headers(|fields| {
            super::headers::apply(self.policy.rules(), self.original, Phase::Response, fields);
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

pub(crate) struct PreparedBody {
    framing: Body,
    cursor: Option<Cursor>,
    prefix: Option<BudgetedBytes>,
    result: Option<body::ResultBody>,
}
impl PreparedBody {
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
        }
    }
    pub(crate) async fn transfer<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        self,
        reader: &mut R,
        writer: &mut W,
        idle: Duration,
        blocklist: &HashSet<String>,
        dechunk: bool,
    ) -> io::Result<()> {
        let Some(mut cursor) = self.cursor else {
            return framing::transfer_body(reader, writer, self.framing, idle, blocklist, dechunk)
                .await;
        };
        let chunked = self.framing == Body::Chunked && !dechunk;
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
        if chunked {
            framing::write_timed(writer, b"0\r\n", idle).await?;
            for (name, value) in cursor.trailers {
                framing::write_timed(writer, format!("{name}: {value}\r\n").as_bytes(), idle)
                    .await?;
            }
            framing::write_timed(writer, b"\r\n", idle).await?;
        }
        framing::timeout_io(idle, writer.flush()).await
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
            });
        }
        let available = transaction.remaining().min(bytes.len());
        if available == 0 {
            return Ok(PreparedBody {
                framing: body,
                cursor: Some(cursor),
                prefix: Some(transaction.into_raw()),
                result: None,
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
            });
        }
        if transaction.push(&bytes[..count]).is_err() {
            return Ok(PreparedBody {
                framing: body,
                cursor: Some(cursor),
                prefix: Some(transaction.into_raw()),
                result: None,
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
