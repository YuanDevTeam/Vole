//! Shared streaming resource transport. Callers own content validation and
//! publication; every HTTP hop uses the supplied Core dispatcher.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::BytesMut;
use rustls::{ClientConfig, RootCertStore, client::Resumption, pki_types::ServerName};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use super::subscription::SubscriptionInfo;
use crate::{
    dispatch::{BoxStream, DispatchError, Dispatcher},
    session::{Destination, InboundKind, StreamSession},
};

pub(crate) const DEFAULT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(90);

const MAX_REDIRECTS: usize = 5;
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_REQUEST_ETAG_BYTES: usize = 1024;
const MAX_RESPONSE_HEAD_BYTES: usize = 32 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_INFORMATIONAL_RESPONSES: usize = 4;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_TRAILER_BYTES: usize = 8 * 1024;
const MAX_TRAILER_HEADERS: usize = 32;
const IO_BUFFER_BYTES: usize = 16 * 1024;

pub(crate) struct DownloadRequest {
    pub dispatcher: Arc<dyn Dispatcher>,
    pub url: String,
    pub etag: Option<String>,
    /// A new temporary file. The downloader refuses to replace an existing
    /// path; publishing the completed file is the manager's responsibility.
    pub temporary_path: PathBuf,
    pub timeout: Duration,
    pub cancellation: CancellationToken,
    pub options: HttpOptions,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpOptions {
    pub user_agent: String,
    pub headers: Vec<(String, String)>,
    pub size_limit: Option<u64>,
    pub allow_http: bool,
    pub allow_ip: bool,
}
impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            user_agent: concat!("Vole/", env!("CARGO_PKG_VERSION")).into(),
            headers: Vec::new(),
            size_limit: None,
            allow_http: cfg!(feature = "benchmark-geodata-http"),
            allow_ip: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DownloadOutcome {
    NotModified {
        subscription_info: Option<SubscriptionInfo>,
    },
    Downloaded {
        etag: Option<String>,
        sha256: [u8; 32],
        size: u64,
        final_url: String,
        subscription_info: Option<SubscriptionInfo>,
    },
}

#[derive(Debug, Error)]
pub(crate) enum DownloadError {
    #[error("invalid resource URL: {0}")]
    InvalidUrl(String),
    #[error("resource download URL must use HTTPS")]
    HttpsRequired,
    #[error("resource download URL must contain a domain host")]
    DomainRequired,
    #[error("resource download URL must not contain credentials")]
    CredentialsNotAllowed,
    #[error("resource download ETag is not a bounded HTTP header value")]
    InvalidEtag,
    #[error("resource proxy dispatch failed: {0}")]
    Dispatch(#[source] DispatchError),
    #[error("resource TLS setup failed: {0}")]
    TlsSetup(String),
    #[error("resource TLS handshake failed: {0}")]
    TlsHandshake(String),
    #[error("resource HTTP protocol error: {0}")]
    Protocol(String),
    #[error("resource server returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("resource download followed more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
    #[error("resource download timed out after {0:?}")]
    TimedOut(Duration),
    #[error("resource download was cancelled")]
    Cancelled,
    #[error("failed to {operation} resource temporary file {path}: {source}")]
    File {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("resource network I/O failed: {0}")]
    NetworkIo(#[source] io::Error),
}

/// Downloads one resource asset exclusively through `request.dispatcher`.
///
/// The successful `Downloaded` result leaves a fully flushed temporary file at
/// `request.temporary_path`. All other outcomes remove the temporary file.
pub(crate) async fn download(request: DownloadRequest) -> Result<DownloadOutcome, DownloadError> {
    let connector = WebPkiHttpsConnector::new()?;
    download_with_connector(request, &connector).await
}

#[async_trait]
trait HttpsConnector: Send + Sync {
    async fn connect(
        &self,
        server_name: &str,
        stream: BoxStream,
    ) -> Result<BoxStream, DownloadError>;
}

struct WebPkiHttpsConnector {
    connector: TlsConnector,
}

impl WebPkiHttpsConnector {
    fn new() -> Result<Self, DownloadError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| DownloadError::TlsSetup(error.to_string()))?
            .with_root_certificates(Arc::new(roots))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = Resumption::disabled();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

#[async_trait]
impl HttpsConnector for WebPkiHttpsConnector {
    async fn connect(
        &self,
        server_name: &str,
        stream: BoxStream,
    ) -> Result<BoxStream, DownloadError> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|error| DownloadError::TlsSetup(error.to_string()))?;
        self.connector
            .connect(server_name, stream)
            .await
            .map(|stream| Box::new(stream) as BoxStream)
            .map_err(|error| DownloadError::TlsHandshake(error.to_string()))
    }
}

async fn download_with_connector(
    request: DownloadRequest,
    connector: &dyn HttpsConnector,
) -> Result<DownloadOutcome, DownloadError> {
    let initial_url = parse_url(&request.url, &request.options)?;
    validate_options(&request.options)?;
    validate_etag(request.etag.as_deref())?;

    let temporary_path = request.temporary_path.clone();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|source| DownloadError::File {
            operation: "create",
            path: temporary_path.clone(),
            source,
        })?;

    let mut cleanup = TemporaryDownload(Some(temporary_path.clone()));
    let cancellation = request.cancellation.clone();
    let timeout = request.timeout;
    let result = {
        let operation = download_inner(request, connector, initial_url, file);
        tokio::pin!(operation);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(DownloadError::Cancelled),
            timed = tokio::time::timeout(timeout, &mut operation) => {
                match timed {
                    Ok(result) => result,
                    Err(_) => Err(DownloadError::TimedOut(timeout)),
                }
            }
        }
    };

    if matches!(result, Ok(DownloadOutcome::Downloaded { .. })) {
        cleanup.0 = None;
    }
    result
}

async fn download_inner(
    request: DownloadRequest,
    connector: &dyn HttpsConnector,
    mut current_url: Url,
    file: File,
) -> Result<DownloadOutcome, DownloadError> {
    let mut file = Some(file);
    let initial_origin = current_url.origin();

    for redirects_followed in 0..=MAX_REDIRECTS {
        let endpoint = DownloadEndpoint::from_url(&current_url)?;
        let session = StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::InternalGeoData,
            source: SocketAddr::from(([0, 0, 0, 0], 0)),
            destination: match endpoint.host.parse() {
                Ok(ip) => Destination::Ip(SocketAddr::new(ip, endpoint.port)),
                Err(_) => Destination::domain(endpoint.host.clone(), endpoint.port)
                    .map_err(|error| DownloadError::InvalidUrl(error.to_string()))?,
            },
            sniffed_domain: None,
        };
        let stream = request
            .dispatcher
            .connect_tcp(session)
            .await
            .map_err(DownloadError::Dispatch)?;
        let stream = if current_url.scheme() == "http" {
            stream
        } else {
            connector.connect(&endpoint.host, stream).await?
        };
        let mut response = HttpReader::new(stream);

        response
            .stream
            .write_all(&build_request(
                &endpoint,
                request.etag.as_deref(),
                &request.options,
                current_url.origin() == initial_origin,
            ))
            .await
            .map_err(DownloadError::NetworkIo)?;
        response
            .stream
            .flush()
            .await
            .map_err(DownloadError::NetworkIo)?;

        let head = response.read_final_head().await?;
        if is_redirect(head.status) {
            if redirects_followed == MAX_REDIRECTS {
                return Err(DownloadError::TooManyRedirects);
            }
            let location = head.location.ok_or_else(|| {
                DownloadError::Protocol("redirect response does not contain Location".to_owned())
            })?;
            current_url = redirect(&current_url, &location, &request.options)?;
            continue;
        }

        match head.status {
            304 if request.etag.is_some() => {
                return Ok(DownloadOutcome::NotModified {
                    subscription_info: head.subscription_info,
                });
            }
            304 => {
                return Err(DownloadError::Protocol(
                    "received 304 without sending If-None-Match".to_owned(),
                ));
            }
            200 => {}
            status => return Err(DownloadError::HttpStatus(status)),
        }

        validate_content_encoding(head.content_encoding.as_deref())?;
        let framing = body_framing(&head)?;
        let target = file
            .take()
            .expect("temporary file must be consumed by one final response");
        let mut sink = BodySink::new(target, request.options.size_limit);
        match framing {
            BodyFraming::ContentLength(length) => {
                if request
                    .options
                    .size_limit
                    .is_some_and(|limit| length > limit)
                {
                    return Err(DownloadError::Protocol(
                        "resource exceeds size-limit".into(),
                    ));
                }
                response.copy_exact_body(length, &mut sink).await?;
            }
            BodyFraming::Chunked => {
                response.copy_chunked_body(&mut sink).await?;
            }
            BodyFraming::UntilEof => {
                response.copy_body_until_eof(&mut sink).await?;
            }
        }
        let (sha256, size) = sink.finish(&request.temporary_path)?;
        return Ok(DownloadOutcome::Downloaded {
            etag: head.etag,
            sha256,
            size,
            final_url: current_url.to_string(),
            subscription_info: head.subscription_info,
        });
    }

    Err(DownloadError::TooManyRedirects)
}

#[derive(Debug)]
struct DownloadEndpoint {
    host: String,
    port: u16,
    authority: String,
    origin_form: String,
}

impl DownloadEndpoint {
    fn from_url(url: &Url) -> Result<Self, DownloadError> {
        let host = match url.host() {
            Some(host) => match host {
                Host::Domain(host) => host.to_owned(),
                Host::Ipv4(ip) => ip.to_string(),
                Host::Ipv6(ip) => ip.to_string(),
            },
            None => return Err(DownloadError::DomainRequired),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| DownloadError::InvalidUrl("missing HTTP(S) port".to_owned()))?;
        let default_port = if url.scheme() == "http" { 80 } else { 443 };
        let authority_host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let authority = if port == default_port {
            authority_host
        } else {
            format!("{authority_host}:{port}")
        };
        let mut origin_form = if url.path().is_empty() {
            "/".to_owned()
        } else {
            url.path().to_owned()
        };
        if let Some(query) = url.query() {
            origin_form.push('?');
            origin_form.push_str(query);
        }
        Ok(Self {
            host,
            port,
            authority,
            origin_form,
        })
    }
}

#[cfg(test)]
fn parse_resource_url(raw: &str) -> Result<Url, DownloadError> {
    parse_url(raw, &HttpOptions::default())
}

pub(crate) fn parse_url(raw: &str, options: &HttpOptions) -> Result<Url, DownloadError> {
    if raw.len() > MAX_URL_BYTES {
        return Err(DownloadError::InvalidUrl(format!(
            "URL exceeds {MAX_URL_BYTES} bytes"
        )));
    }
    let mut url = Url::parse(raw).map_err(|error| DownloadError::InvalidUrl(error.to_string()))?;
    let allowed_scheme = url.scheme() == "https" || options.allow_http && url.scheme() == "http";
    if !allowed_scheme {
        return Err(DownloadError::HttpsRequired);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DownloadError::CredentialsNotAllowed);
    }
    if url.host().is_none() || (!options.allow_ip && !matches!(url.host(), Some(Host::Domain(_)))) {
        return Err(DownloadError::DomainRequired);
    }
    if url.scheme() == "http" {
        let authority = raw
            .split_once("://")
            .map(|(_, suffix)| suffix)
            .and_then(|suffix| suffix.split(['/', '?', '#']).next())
            .unwrap_or_default();
        if authority.contains('@') {
            return Err(DownloadError::CredentialsNotAllowed);
        }
        if url.fragment().is_some() {
            return Err(DownloadError::InvalidUrl(
                "URL must not contain a fragment".to_owned(),
            ));
        }
    }
    url.set_fragment(None);
    Ok(url)
}

#[cfg(test)]
fn resolve_redirect(base: &Url, location: &str) -> Result<Url, DownloadError> {
    redirect(base, location, &HttpOptions::default())
}

fn redirect(base: &Url, location: &str, options: &HttpOptions) -> Result<Url, DownloadError> {
    if location.len() > MAX_URL_BYTES || !is_header_value(location.as_bytes()) {
        return Err(DownloadError::InvalidUrl(
            "redirect Location is not a bounded HTTP header value".to_owned(),
        ));
    }
    let joined = base
        .join(location)
        .map_err(|error| DownloadError::InvalidUrl(error.to_string()))?;
    if base.scheme() == "https" && joined.scheme() != "https" {
        return Err(DownloadError::HttpsRequired);
    }
    parse_url(joined.as_str(), options)
}

fn validate_etag(etag: Option<&str>) -> Result<(), DownloadError> {
    if let Some(etag) = etag
        && (etag.len() > MAX_REQUEST_ETAG_BYTES || !is_header_value(etag.as_bytes()))
    {
        return Err(DownloadError::InvalidEtag);
    }
    Ok(())
}

pub(crate) fn validate_options(options: &HttpOptions) -> Result<(), DownloadError> {
    if options.user_agent.len() > 1024 || !is_header_value(options.user_agent.as_bytes()) {
        return Err(DownloadError::Protocol("invalid User-Agent".into()));
    }
    let mut size = 0usize;
    for (name, value) in &options.headers {
        size = size.saturating_add(name.len()).saturating_add(value.len());
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !is_header_value(value.as_bytes())
            || size > MAX_RESPONSE_HEAD_BYTES
            || [
                "host",
                "connection",
                "content-length",
                "transfer-encoding",
                "if-none-match",
                "accept-encoding",
            ]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(DownloadError::Protocol(
                "invalid resource request header".into(),
            ));
        }
    }
    Ok(())
}

fn build_request(
    endpoint: &DownloadEndpoint,
    etag: Option<&str>,
    options: &HttpOptions,
    same_origin: bool,
) -> Vec<u8> {
    let conditional = etag.map_or_else(String::new, |etag| format!("If-None-Match: {etag}\r\n"));
    let mut headers = String::new();
    for (name, value) in &options.headers {
        if !same_origin
            && ["authorization", "cookie", "proxy-authorization"]
                .iter()
                .any(|s| name.eq_ignore_ascii_case(s))
        {
            continue;
        }
        headers.push_str(&format!("{name}: {value}\r\n"));
    }
    let user_agent = if options
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
    {
        String::new()
    } else {
        format!("User-Agent: {}\r\n", options.user_agent)
    };
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\n{}Connection: close\r\n{}{}\r\n",
        endpoint.origin_form, endpoint.authority, user_agent, conditional, headers
    ).into_bytes()
}

struct TemporaryDownload(Option<PathBuf>);
impl Drop for TemporaryDownload {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[derive(Debug)]
struct ResponseHead {
    status: u16,
    content_length: Option<u64>,
    transfer_encoding: Option<String>,
    content_encoding: Option<String>,
    etag: Option<String>,
    location: Option<String>,
    subscription_info: Option<SubscriptionInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    ContentLength(u64),
    Chunked,
    UntilEof,
}

fn body_framing(head: &ResponseHead) -> Result<BodyFraming, DownloadError> {
    if head.transfer_encoding.is_some() && head.content_length.is_some() {
        return Err(DownloadError::Protocol(
            "response contains both Transfer-Encoding and Content-Length".to_owned(),
        ));
    }
    if let Some(encoding) = &head.transfer_encoding {
        if !encoding.eq_ignore_ascii_case("chunked") {
            return Err(DownloadError::Protocol(format!(
                "unsupported Transfer-Encoding `{encoding}`"
            )));
        }
        return Ok(BodyFraming::Chunked);
    }
    if let Some(length) = head.content_length {
        return Ok(BodyFraming::ContentLength(length));
    }
    Ok(BodyFraming::UntilEof)
}

fn validate_content_encoding(encoding: Option<&str>) -> Result<(), DownloadError> {
    if let Some(encoding) = encoding
        && !encoding
            .split(',')
            .all(|value| value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(DownloadError::Protocol(format!(
            "unsupported Content-Encoding `{encoding}`"
        )));
    }
    Ok(())
}

struct HttpReader {
    stream: BoxStream,
    buffered: BytesMut,
}

impl HttpReader {
    fn new(stream: BoxStream) -> Self {
        Self {
            stream,
            buffered: BytesMut::with_capacity(4 * 1024),
        }
    }

    async fn read_final_head(&mut self) -> Result<ResponseHead, DownloadError> {
        for informational_count in 0..=MAX_INFORMATIONAL_RESPONSES {
            let block = self.read_head_block().await?;
            let head = parse_response_head(&block)?;
            if !(100..200).contains(&head.status) {
                return Ok(head);
            }
            if head.status == 101 {
                return Err(DownloadError::Protocol(
                    "HTTP protocol switching is not supported".to_owned(),
                ));
            }
            if informational_count == MAX_INFORMATIONAL_RESPONSES {
                return Err(DownloadError::Protocol(
                    "too many informational responses".to_owned(),
                ));
            }
        }
        unreachable!("informational response loop always returns");
    }

    async fn read_head_block(&mut self) -> Result<Vec<u8>, DownloadError> {
        loop {
            if let Some(end) = find_bytes(&self.buffered, b"\r\n\r\n") {
                if end + 4 > MAX_RESPONSE_HEAD_BYTES {
                    return Err(DownloadError::Protocol(format!(
                        "response head exceeds {MAX_RESPONSE_HEAD_BYTES} bytes"
                    )));
                }
                let mut block = self.buffered.split_to(end + 4).to_vec();
                block.truncate(end);
                return Ok(block);
            }
            if self.buffered.len() >= MAX_RESPONSE_HEAD_BYTES {
                return Err(DownloadError::Protocol(format!(
                    "response head exceeds {MAX_RESPONSE_HEAD_BYTES} bytes"
                )));
            }
            let mut scratch = [0_u8; 4 * 1024];
            let read = self
                .stream
                .read(&mut scratch)
                .await
                .map_err(DownloadError::NetworkIo)?;
            if read == 0 {
                return Err(DownloadError::Protocol(
                    "response ended before its HTTP head".to_owned(),
                ));
            }
            self.buffered.extend_from_slice(&scratch[..read]);
        }
    }

    async fn copy_exact_body(
        &mut self,
        mut remaining: u64,
        sink: &mut BodySink,
    ) -> Result<(), DownloadError> {
        let mut scratch = [0_u8; IO_BUFFER_BYTES];
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(IO_BUFFER_BYTES as u64))
                .expect("bounded read size fits usize");
            let read = self.read_some(&mut scratch[..wanted]).await?;
            if read == 0 {
                return Err(DownloadError::Protocol(format!(
                    "response body ended with {remaining} bytes missing"
                )));
            }
            sink.write(&scratch[..read])?;
            remaining -= read as u64;
        }
        Ok(())
    }

    async fn copy_body_until_eof(&mut self, sink: &mut BodySink) -> Result<(), DownloadError> {
        let mut scratch = [0_u8; IO_BUFFER_BYTES];
        loop {
            let read = self.read_some(&mut scratch).await?;
            if read == 0 {
                return Ok(());
            }
            sink.write(&scratch[..read])?;
        }
    }

    async fn copy_chunked_body(&mut self, sink: &mut BodySink) -> Result<(), DownloadError> {
        loop {
            let line = self.read_line(MAX_CHUNK_LINE_BYTES).await?;
            if !is_header_value(&line) {
                return Err(DownloadError::Protocol(
                    "chunk-size line contains invalid bytes".to_owned(),
                ));
            }
            let size_text = line
                .split(|byte| *byte == b';')
                .next()
                .expect("split always returns one value");
            let size_text = trim_ascii_whitespace(size_text);
            if size_text.is_empty() || size_text.len() > 16 {
                return Err(DownloadError::Protocol("invalid chunk size".to_owned()));
            }
            let size_text = std::str::from_utf8(size_text)
                .map_err(|_| DownloadError::Protocol("chunk size is not ASCII".to_owned()))?;
            let size = u64::from_str_radix(size_text, 16).map_err(|_| {
                DownloadError::Protocol("invalid hexadecimal chunk size".to_owned())
            })?;
            if size == 0 {
                self.read_trailers().await?;
                return Ok(());
            }
            self.copy_exact_body(size, sink).await?;
            let terminator = self.read_exact_small(2).await?;
            if terminator != b"\r\n" {
                return Err(DownloadError::Protocol(
                    "chunk data is not followed by CRLF".to_owned(),
                ));
            }
        }
    }

    async fn read_trailers(&mut self) -> Result<(), DownloadError> {
        let mut total = 0_usize;
        for count in 0..=MAX_TRAILER_HEADERS {
            let line = self.read_line(MAX_TRAILER_BYTES).await?;
            total = total
                .checked_add(line.len() + 2)
                .ok_or_else(|| DownloadError::Protocol("trailer size overflow".to_owned()))?;
            if total > MAX_TRAILER_BYTES {
                return Err(DownloadError::Protocol(format!(
                    "trailers exceed {MAX_TRAILER_BYTES} bytes"
                )));
            }
            if line.is_empty() {
                return Ok(());
            }
            if count == MAX_TRAILER_HEADERS {
                return Err(DownloadError::Protocol(format!(
                    "trailers contain more than {MAX_TRAILER_HEADERS} fields"
                )));
            }
            validate_trailer_line(&line)?;
        }
        unreachable!("trailer loop always returns");
    }

    async fn read_line(&mut self, maximum: usize) -> Result<Vec<u8>, DownloadError> {
        loop {
            if let Some(end) = find_bytes(&self.buffered, b"\r\n") {
                if end > maximum {
                    return Err(DownloadError::Protocol(format!(
                        "HTTP line exceeds {maximum} bytes"
                    )));
                }
                let mut line = self.buffered.split_to(end + 2).to_vec();
                line.truncate(end);
                return Ok(line);
            }
            if self.buffered.len() > maximum {
                return Err(DownloadError::Protocol(format!(
                    "HTTP line exceeds {maximum} bytes"
                )));
            }
            let mut scratch = [0_u8; 4 * 1024];
            let read = self
                .stream
                .read(&mut scratch)
                .await
                .map_err(DownloadError::NetworkIo)?;
            if read == 0 {
                return Err(DownloadError::Protocol(
                    "response ended in the middle of an HTTP line".to_owned(),
                ));
            }
            self.buffered.extend_from_slice(&scratch[..read]);
        }
    }

    async fn read_exact_small(&mut self, length: usize) -> Result<Vec<u8>, DownloadError> {
        let mut output = vec![0_u8; length];
        let mut written = 0;
        while written < length {
            if self.buffered.is_empty() {
                let mut scratch = [0_u8; 4 * 1024];
                let read = self
                    .stream
                    .read(&mut scratch)
                    .await
                    .map_err(DownloadError::NetworkIo)?;
                if read == 0 {
                    return Err(DownloadError::Protocol(
                        "response body ended unexpectedly".to_owned(),
                    ));
                }
                self.buffered.extend_from_slice(&scratch[..read]);
            }
            let take = (length - written).min(self.buffered.len());
            let bytes = self.buffered.split_to(take);
            output[written..written + take].copy_from_slice(&bytes);
            written += take;
        }
        Ok(output)
    }

    async fn read_some(&mut self, output: &mut [u8]) -> Result<usize, DownloadError> {
        if !self.buffered.is_empty() {
            let take = output.len().min(self.buffered.len());
            let bytes = self.buffered.split_to(take);
            output[..take].copy_from_slice(&bytes);
            return Ok(take);
        }
        self.stream
            .read(output)
            .await
            .map_err(DownloadError::NetworkIo)
    }
}

fn parse_response_head(block: &[u8]) -> Result<ResponseHead, DownloadError> {
    if !block.is_ascii() {
        return Err(DownloadError::Protocol(
            "response head contains non-ASCII bytes".to_owned(),
        ));
    }
    let text = std::str::from_utf8(block)
        .map_err(|_| DownloadError::Protocol("invalid response head".to_owned()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| DownloadError::Protocol("missing HTTP status line".to_owned()))?;
    let mut status_parts = status_line.splitn(3, ' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(DownloadError::Protocol(
            "server did not respond with HTTP/1.1".to_owned(),
        ));
    }
    let status_text = status_parts
        .next()
        .ok_or_else(|| DownloadError::Protocol("missing HTTP status".to_owned()))?;
    if status_text.len() != 3 || !status_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DownloadError::Protocol("invalid HTTP status".to_owned()));
    }
    let status = status_text
        .parse::<u16>()
        .map_err(|_| DownloadError::Protocol("invalid HTTP status".to_owned()))?;

    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut content_encoding = None;
    let mut etag = None;
    let mut location = None;
    let mut subscription_info = None;
    let mut subscription_seen = false;
    let mut header_count = 0_usize;

    for line in lines {
        header_count += 1;
        if header_count > MAX_RESPONSE_HEADERS {
            return Err(DownloadError::Protocol(format!(
                "response contains more than {MAX_RESPONSE_HEADERS} headers"
            )));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(DownloadError::Protocol(
                "obsolete folded headers are not supported".to_owned(),
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| DownloadError::Protocol("malformed HTTP response header".to_owned()))?;
        if !is_header_name(name.as_bytes()) {
            return Err(DownloadError::Protocol(
                "invalid HTTP response header name".to_owned(),
            ));
        }
        let value = value.trim_matches([' ', '\t']);
        if !is_header_value(value.as_bytes()) {
            return Err(DownloadError::Protocol(
                "invalid HTTP response header value".to_owned(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            set_once(&mut content_length, "Content-Length")?;
            content_length = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| DownloadError::Protocol("invalid Content-Length".to_owned()))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            set_string_once(&mut transfer_encoding, value, "Transfer-Encoding")?;
        } else if name.eq_ignore_ascii_case("content-encoding") {
            set_string_once(&mut content_encoding, value, "Content-Encoding")?;
        } else if name.eq_ignore_ascii_case("etag") {
            set_string_once(&mut etag, value, "ETag")?;
        } else if name.eq_ignore_ascii_case("location") {
            set_string_once(&mut location, value, "Location")?;
        } else if name.eq_ignore_ascii_case("subscription-userinfo") && !subscription_seen {
            subscription_seen = true;
            subscription_info = SubscriptionInfo::parse(value);
        }
    }

    Ok(ResponseHead {
        status,
        content_length,
        transfer_encoding,
        content_encoding,
        etag,
        location,
        subscription_info,
    })
}

fn set_once<T>(slot: &mut Option<T>, header_name: &'static str) -> Result<(), DownloadError> {
    if slot.is_some() {
        return Err(DownloadError::Protocol(format!(
            "duplicate {header_name} header"
        )));
    }
    Ok(())
}

fn set_string_once(
    slot: &mut Option<String>,
    value: &str,
    header_name: &'static str,
) -> Result<(), DownloadError> {
    set_once(slot, header_name)?;
    *slot = Some(value.to_owned());
    Ok(())
}

fn validate_trailer_line(line: &[u8]) -> Result<(), DownloadError> {
    if !line.is_ascii()
        || line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        return Err(DownloadError::Protocol("invalid HTTP trailer".to_owned()));
    }
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(DownloadError::Protocol("malformed HTTP trailer".to_owned()));
    };
    let name = &line[..colon];
    let value = trim_ascii_whitespace(&line[colon + 1..]);
    if !is_header_name(name) || !is_header_value(value) {
        return Err(DownloadError::Protocol("invalid HTTP trailer".to_owned()));
    }
    if name.eq_ignore_ascii_case(b"content-length")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"content-encoding")
        || name.eq_ignore_ascii_case(b"location")
    {
        return Err(DownloadError::Protocol(
            "forbidden framing field in HTTP trailer".to_owned(),
        ));
    }
    Ok(())
}

fn is_header_name(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_header_value(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct BodySink {
    file: File,
    hasher: Sha256,
    size: u64,
    limit: Option<u64>,
}

impl BodySink {
    fn new(file: File, limit: Option<u64>) -> Self {
        Self {
            file,
            hasher: Sha256::new(),
            limit,
            size: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), DownloadError> {
        let added = u64::try_from(bytes.len()).expect("buffer length fits u64");
        let next = self
            .size
            .checked_add(added)
            .ok_or_else(|| DownloadError::Protocol("body size overflows u64".to_owned()))?;
        if self.limit.is_some_and(|limit| next > limit) {
            return Err(DownloadError::Protocol(
                "resource exceeds size-limit".into(),
            ));
        }
        self.file
            .write_all(bytes)
            .map_err(DownloadError::NetworkIo)?;
        self.hasher.update(bytes);
        self.size = next;
        Ok(())
    }

    fn finish(mut self, path: &std::path::Path) -> Result<([u8; 32], u64), DownloadError> {
        self.file
            .flush()
            .and_then(|()| self.file.sync_all())
            .map_err(|source| DownloadError::File {
                operation: "flush",
                path: path.to_path_buf(),
                source,
            })?;
        let sha256 = self.hasher.finalize().into();
        Ok((sha256, self.size))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        dispatch::{DatagramTransport, DispatchError},
        session::{DatagramSession, Destination},
    };

    #[test]
    fn subscription_header_uses_first_value_including_an_empty_one() {
        let head = parse_response_head(
            b"HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=7\r\nsubscription-userinfo: upload=99",
        )
        .unwrap();
        assert_eq!(head.subscription_info.unwrap().upload, 7);
        let head = parse_response_head(
            b"HTTP/1.1 304 Not Modified\r\nSubscription-Userinfo: \r\nsubscription-userinfo: upload=99",
        )
        .unwrap();
        assert_eq!(head.subscription_info, None);
    }

    struct PlainHttpsConnector;

    #[async_trait]
    impl HttpsConnector for PlainHttpsConnector {
        async fn connect(
            &self,
            _server_name: &str,
            stream: BoxStream,
        ) -> Result<BoxStream, DownloadError> {
            Ok(stream)
        }
    }

    #[cfg(feature = "benchmark-geodata-http")]
    #[derive(Default)]
    struct RecordingHttpsConnector(Mutex<Vec<String>>);

    #[cfg(feature = "benchmark-geodata-http")]
    #[async_trait]
    impl HttpsConnector for RecordingHttpsConnector {
        async fn connect(
            &self,
            server_name: &str,
            stream: BoxStream,
        ) -> Result<BoxStream, DownloadError> {
            self.0.lock().unwrap().push(server_name.to_owned());
            Ok(stream)
        }
    }

    struct ScriptedDispatcher {
        responses: Mutex<VecDeque<Vec<u8>>>,
        sessions: Mutex<Vec<StreamSession>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    struct HangingDispatcher;

    #[async_trait]
    impl Dispatcher for HangingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            std::future::pending().await
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }

    impl ScriptedDispatcher {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                sessions: Mutex::new(Vec::new()),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn sessions(&self) -> Vec<StreamSession> {
            self.sessions.lock().expect("sessions lock").clone()
        }

        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    #[async_trait]
    impl Dispatcher for ScriptedDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.sessions.lock().expect("sessions lock").push(session);
            let response = self
                .responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .ok_or_else(|| DispatchError::Other("no scripted response".to_owned()))?;
            let requests = Arc::clone(&self.requests);
            let (client, mut server) = tokio::io::duplex(128 * 1024);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut scratch = [0_u8; 1024];
                loop {
                    let read = server.read(&mut scratch).await.expect("read request");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&scratch[..read]);
                    if find_bytes(&request, b"\r\n\r\n").is_some() {
                        break;
                    }
                }
                requests.lock().expect("requests lock").push(request);
                server.write_all(&response).await.expect("write response");
                server.shutdown().await.expect("shutdown response");
            });
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }

    fn request(
        dispatcher: Arc<dyn Dispatcher>,
        url: &str,
        temporary_path: PathBuf,
    ) -> DownloadRequest {
        DownloadRequest {
            dispatcher,
            url: url.to_owned(),
            etag: Some("\"old\"".to_owned()),
            temporary_path,
            timeout: Duration::from_secs(2),
            cancellation: CancellationToken::new(),
            options: HttpOptions::default(),
        }
    }

    #[cfg(feature = "benchmark-geodata-http")]
    #[tokio::test]
    async fn benchmark_http_uses_the_raw_stream_and_existing_download_outcomes() {
        for (name, response) in [
            (
                "download",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n"
                    .as_slice(),
            ),
            (
                "not-modified",
                b"HTTP/1.1 304 Not Modified\r\n\r\n".as_slice(),
            ),
            (
                "truncated",
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort".as_slice(),
            ),
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("fixture.new");
            let dispatcher = Arc::new(ScriptedDispatcher::new([response.to_vec()]));
            // The real connector would reject this plaintext in-memory peer if
            // HTTP accidentally attempted a TLS handshake.
            let outcome = download(request(
                dispatcher.clone(),
                "http://rules.example.test/geoip.dat",
                path.clone(),
            ))
            .await;
            match name {
                "download" => {
                    assert!(matches!(
                        outcome,
                        Ok(DownloadOutcome::Downloaded { size: 4, .. })
                    ));
                    assert_eq!(fs::read(&path).unwrap(), b"data");
                }
                "not-modified" => {
                    assert_eq!(
                        outcome.unwrap(),
                        DownloadOutcome::NotModified {
                            subscription_info: None
                        }
                    );
                    assert!(!path.exists());
                }
                "truncated" => {
                    assert!(matches!(outcome, Err(DownloadError::Protocol(_))));
                    assert!(!path.exists());
                }
                _ => unreachable!(),
            }
            let sessions = dispatcher.sessions();
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].inbound, InboundKind::InternalGeoData);
            assert_eq!(
                sessions[0].destination,
                Destination::domain("rules.example.test", 80).unwrap()
            );
            assert!(
                std::str::from_utf8(&dispatcher.requests()[0])
                    .unwrap()
                    .contains("\r\nHost: rules.example.test\r\n")
            );
        }
    }

    #[cfg(feature = "benchmark-geodata-http")]
    #[tokio::test]
    async fn benchmark_http_redirects_allow_plaintext_hops_and_https_upgrade() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("redirect.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 302 Found\r\nLocation: http://cdn.example.test:8080/next.dat\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: https://secure.example.test/final.dat\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata".to_vec(),
        ]));
        let connector = RecordingHttpsConnector::default();
        let outcome = download_with_connector(
            request(
                dispatcher.clone(),
                "http://rules.example.test/start.dat",
                path,
            ),
            &connector,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, DownloadOutcome::Downloaded { final_url, .. } if final_url == "https://secure.example.test/final.dat")
        );
        assert_eq!(*connector.0.lock().unwrap(), ["secure.example.test"]);
        let destinations: Vec<_> = dispatcher
            .sessions()
            .into_iter()
            .map(|session| session.destination)
            .collect();
        assert_eq!(
            destinations,
            [
                Destination::domain("rules.example.test", 80).unwrap(),
                Destination::domain("cdn.example.test", 8080).unwrap(),
                Destination::domain("secure.example.test", 443).unwrap(),
            ]
        );
        assert!(
            std::str::from_utf8(&dispatcher.requests()[1])
                .unwrap()
                .contains("\r\nHost: cdn.example.test:8080\r\n")
        );
    }

    #[cfg(not(feature = "benchmark-geodata-http"))]
    #[tokio::test]
    async fn plaintext_geodata_is_rejected_before_dispatch() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("http.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([]));
        let error = download(request(
            dispatcher.clone(),
            "http://rules.example.test/geoip.dat",
            path.clone(),
        ))
        .await
        .unwrap_err();
        assert!(matches!(error, DownloadError::HttpsRequired));
        assert!(dispatcher.sessions().is_empty());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn follows_https_redirect_and_streams_chunked_body_through_raw_proxy() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("geosite.dat.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example.test/final.dat?version=2\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: identity\r\nETag: \"new\"\r\n\r\n4\r\ngeo-\r\n4\r\ndata\r\n0\r\nX-Checksum: present\r\n\r\n".to_vec(),
        ]));
        let outcome = download_with_connector(
            request(
                dispatcher.clone(),
                "https://rules.example.test/geosite.dat",
                temporary_path.clone(),
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("download succeeds");

        let expected_sha256: [u8; 32] = Sha256::digest(b"geo-data").into();
        assert_eq!(
            outcome,
            DownloadOutcome::Downloaded {
                etag: Some("\"new\"".to_owned()),
                sha256: expected_sha256,
                size: 8,
                final_url: "https://cdn.example.test/final.dat?version=2".to_owned(),
                subscription_info: None,
            }
        );
        assert_eq!(
            fs::read(&temporary_path).expect("temporary data"),
            b"geo-data"
        );

        let sessions = dispatcher.sessions();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|session| {
            session.inbound == InboundKind::InternalGeoData
                && session.source == SocketAddr::from(([0, 0, 0, 0], 0))
                && session.sniffed_domain.is_none()
        }));
        assert_eq!(
            sessions[0].destination,
            Destination::Domain {
                host: "rules.example.test".to_owned(),
                port: 443,
            }
        );
        assert_eq!(
            sessions[1].destination,
            Destination::Domain {
                host: "cdn.example.test".to_owned(),
                port: 443,
            }
        );

        let requests = dispatcher.requests();
        assert_eq!(requests.len(), 2);
        let first = std::str::from_utf8(&requests[0]).expect("request is ASCII");
        assert!(first.starts_with("GET /geosite.dat HTTP/1.1\r\n"));
        assert!(first.contains("\r\nHost: rules.example.test\r\n"));
        assert!(first.contains("\r\nAccept-Encoding: identity\r\n"));
        assert!(first.contains("\r\nIf-None-Match: \"old\"\r\n"));
    }

    #[tokio::test]
    async fn not_modified_removes_the_unused_temporary_file() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("geoip.dat.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 304 Not Modified\r\nETag: \"old\"\r\n\r\n".to_vec(),
        ]));
        let outcome = download_with_connector(
            request(
                dispatcher,
                "https://rules.example.test/geoip.dat",
                temporary_path.clone(),
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("conditional request succeeds");

        assert_eq!(
            outcome,
            DownloadOutcome::NotModified {
                subscription_info: None
            }
        );
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn supports_content_length_and_eof_delimited_bodies() {
        let directory = tempdir().expect("tempdir");
        let content_length_path = directory.path().join("content-length.new");
        let content_length_dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345ignored".to_vec(),
        ]));
        let content_length = download_with_connector(
            request(
                content_length_dispatcher,
                "https://rules.example.test/content-length",
                content_length_path.clone(),
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("content-length body");
        assert!(matches!(
            content_length,
            DownloadOutcome::Downloaded { size: 5, .. }
        ));
        assert_eq!(
            fs::read(content_length_path).expect("length file"),
            b"12345"
        );

        let eof_path = directory.path().join("eof.new");
        let eof_dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\neof-body".to_vec(),
        ]));
        let eof = download_with_connector(
            request(
                eof_dispatcher,
                "https://rules.example.test/eof",
                eof_path.clone(),
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("EOF body");
        assert!(matches!(eof, DownloadOutcome::Downloaded { size: 8, .. }));
        assert_eq!(fs::read(eof_path).expect("EOF file"), b"eof-body");
    }

    #[tokio::test]
    async fn streams_body_beyond_former_file_size_limits() {
        let directory = tempdir().unwrap();
        let temporary_path = directory.path().join("large.new");
        let length = 32 * 1024 * 1024 + 1;
        let mut response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n").into_bytes();
        response.resize(response.len() + length, b'x');
        let dispatcher = Arc::new(ScriptedDispatcher::new([response]));
        let mut request = request(
            dispatcher,
            "https://rules.example.test/geoip.dat",
            temporary_path.clone(),
        );
        request.timeout = Duration::from_secs(15);
        let outcome = download_with_connector(request, &PlainHttpsConnector)
            .await
            .unwrap();
        assert!(
            matches!(outcome, DownloadOutcome::Downloaded { size, .. } if size == length as u64)
        );
        assert_eq!(fs::metadata(temporary_path).unwrap().len(), length as u64);
    }

    #[tokio::test]
    async fn truncated_body_still_removes_partial_file() {
        let directory = tempdir().unwrap();
        let temporary_path = directory.path().join("truncated.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort".to_vec(),
        ]));
        let error = download_with_connector(
            request(
                dispatcher,
                "https://rules.example.test/geoip.dat",
                temporary_path.clone(),
            ),
            &PlainHttpsConnector,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, DownloadError::Protocol(_)));
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn rejects_redirect_to_http_without_dispatching_the_second_hop() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("redirect.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 302 Found\r\nLocation: http://unsafe.example.test/file\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ]));
        let error = download_with_connector(
            request(
                dispatcher.clone(),
                "https://rules.example.test/geoip.dat",
                temporary_path.clone(),
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect_err("HTTP redirect must be rejected");

        assert!(matches!(error, DownloadError::HttpsRequired));
        assert_eq!(dispatcher.sessions().len(), 1);
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn cancellation_wins_before_proxy_dispatch() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("cancelled.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ]));
        let request = request(
            dispatcher.clone(),
            "https://rules.example.test/geoip.dat",
            temporary_path.clone(),
        );
        request.cancellation.cancel();
        let error = download_with_connector(request, &PlainHttpsConnector)
            .await
            .expect_err("cancelled request");

        assert!(matches!(error, DownloadError::Cancelled));
        assert!(dispatcher.sessions().is_empty());
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn timeout_covers_proxy_connection_and_removes_temporary_file() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("timeout.new");
        let mut request = request(
            Arc::new(HangingDispatcher),
            "https://rules.example.test/geoip.dat",
            temporary_path.clone(),
        );
        request.timeout = Duration::from_millis(10);
        let error = download_with_connector(request, &PlainHttpsConnector)
            .await
            .expect_err("request must time out");

        assert!(matches!(
            error,
            DownloadError::TimedOut(duration)
                if duration == Duration::from_millis(10)
        ));
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn shared_transport_applies_headers_size_limit_and_drop_cleanup() {
        let root = tempdir().unwrap();
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata".to_vec(),
        ]));
        let path = root.path().join("candidate");
        let mut input = request(
            dispatcher.clone(),
            "http://192.0.2.1/provider",
            path.clone(),
        );
        input.etag = None;
        input.options = HttpOptions {
            user_agent: "shared-fixture".into(),
            headers: vec![("X-Fixture".into(), "enabled".into())],
            size_limit: Some(3),
            allow_http: true,
            allow_ip: true,
        };
        assert!(
            download_with_connector(input, &PlainHttpsConnector)
                .await
                .is_err()
        );
        assert!(!path.exists());
        let requests = dispatcher.requests.lock().unwrap();
        let headers = String::from_utf8_lossy(&requests[0]);
        assert!(headers.contains("User-Agent: shared-fixture\r\n"));
        assert!(headers.contains("X-Fixture: enabled\r\n"));
        assert!(!headers.contains("If-None-Match"));
        drop(requests);
        let mut future = Box::pin(download_with_connector(
            request(
                Arc::new(HangingDispatcher),
                "https://rules.example.test/resource",
                path.clone(),
            ),
            &PlainHttpsConnector,
        ));
        assert!(futures_util::poll!(&mut future).is_pending());
        assert!(path.exists());
        drop(future);
        assert!(!path.exists());
    }

    #[test]
    fn parser_rejects_ambiguous_or_unbounded_framing() {
        let both = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked",
        )
        .expect("head parses");
        assert!(matches!(
            body_framing(&both),
            Err(DownloadError::Protocol(_))
        ));

        let length = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 33554433")
            .expect("head parses");
        assert_eq!(
            body_framing(&length).unwrap(),
            BodyFraming::ContentLength(33_554_433)
        );
        assert!(
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616")
                .is_err()
        );
    }

    #[test]
    fn url_and_etag_validation_preserve_the_geodata_contract() {
        #[cfg(not(feature = "benchmark-geodata-http"))]
        assert!(matches!(
            parse_resource_url("http://example.test/file"),
            Err(DownloadError::HttpsRequired)
        ));
        assert!(matches!(
            parse_resource_url("https://127.0.0.1/file"),
            Err(DownloadError::DomainRequired)
        ));
        assert!(matches!(
            parse_resource_url("https://user@example.test/file"),
            Err(DownloadError::CredentialsNotAllowed)
        ));
        assert_eq!(
            parse_resource_url("https://example.test/file#fragment")
                .unwrap()
                .as_str(),
            "https://example.test/file"
        );
        assert!(parse_resource_url("ftp://example.test/file").is_err());
        assert!(matches!(
            validate_etag(Some("\"ok\"\r\nX-Evil: yes")),
            Err(DownloadError::InvalidEtag)
        ));
    }

    #[test]
    fn download_endpoints_use_scheme_specific_ports_and_authorities() {
        for (raw, port, authority) in [
            ("https://example.test/file", 443, "example.test"),
            ("https://example.test:80/file", 80, "example.test:80"),
            ("https://example.test:8443/file", 8443, "example.test:8443"),
        ] {
            let endpoint = DownloadEndpoint::from_url(&parse_resource_url(raw).unwrap()).unwrap();
            assert_eq!(endpoint.port, port);
            assert_eq!(endpoint.authority, authority);
        }
        #[cfg(feature = "benchmark-geodata-http")]
        {
            for (raw, port, authority) in [
                ("http://example.test/file", 80, "example.test"),
                ("http://example.test:443/file", 443, "example.test:443"),
            ] {
                let endpoint =
                    DownloadEndpoint::from_url(&parse_resource_url(raw).unwrap()).unwrap();
                assert_eq!(endpoint.port, port);
                assert_eq!(endpoint.authority, authority);
            }
            for raw in [
                "http://127.0.0.1/file",
                "http://[::1]/file",
                "http://user@example.test/file",
                "http://@example.test/file",
                "http://example.test/file#fragment",
            ] {
                assert!(parse_resource_url(raw).is_err());
            }
            let base = parse_resource_url("http://example.test/start").unwrap();
            assert_eq!(
                resolve_redirect(&base, "/next").unwrap().as_str(),
                "http://example.test/next"
            );
            for location in [
                "ftp://example.test/file",
                "http://127.0.0.1/file",
                "http://user@example.test/file",
                "/file#fragment",
            ] {
                assert!(resolve_redirect(&base, location).is_err());
            }
        }
    }
}
