//! Bounded HTTP/1 message framing. Ambiguous lengths fail closed (RFC 9112 §6.3).
use std::{collections::HashSet, io, time::Duration};

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use tokio::time::timeout;

use super::parser::{RequestHead, is_token_byte, parse_headers};
use crate::session::Destination;

pub(crate) const COPY_BUFFER: usize = 8 * 1024;
const MAX_CHUNK_LINE: usize = 1024;
const MAX_TRAILERS: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Body {
    Empty,
    Length(u64),
    Chunked,
    UntilEof,
}

pub(crate) struct RequestPlan {
    pub destination: Destination,
    pub head: Vec<u8>,
    pub body: Body,
    pub keep_alive: bool,
    pub upgrade: Vec<String>,
    pub trailer_blocklist: HashSet<String>,
}

impl RequestPlan {
    pub fn new(request: &RequestHead) -> io::Result<Self> {
        let (destination, origin) = request.forward_target()?;
        Self::for_target(request, destination, origin, false)
    }
    pub(crate) fn for_target(
        request: &RequestHead,
        destination: Destination,
        origin: String,
        strip_origin_credentials: bool,
    ) -> io::Result<Self> {
        let mut framing = Framing::parse(&request.headers)?;
        if strip_origin_credentials {
            framing.connection.insert("cookie".into());
            framing
                .trailers
                .retain(|name| !name.eq_ignore_ascii_case("cookie"));
        }
        let body = framing.body.unwrap_or(Body::Empty);
        if request.version == "HTTP/1.0" && body == Body::Chunked {
            return Err(invalid("HTTP/1.0 cannot use chunked framing"));
        }
        let hosts = values(&request.headers, "host").count();
        if hosts > 1 || (request.version == "HTTP/1.1" && hosts != 1) {
            return Err(invalid("HTTP/1.1 requires one Host field"));
        }
        let upgrade = upgrade_protocols(&request.headers, &framing.connection)?;
        if !upgrade.is_empty()
            && (!matches!(body, Body::Empty | Body::Length(0)) || request.version != "HTTP/1.1")
        {
            return Err(invalid(
                "Upgrade requires an HTTP/1.1 request without a body",
            ));
        }
        let expectations = values(&request.headers, "expect").collect::<Vec<_>>();
        if expectations.len() > 1
            || expectations
                .first()
                .is_some_and(|value| !value.eq_ignore_ascii_case("100-continue"))
        {
            return Err(invalid("unsupported HTTP expectation"));
        }
        let mut head = format!("{} {} HTTP/1.1\r\n", request.method, origin).into_bytes();
        append_headers(
            &mut head,
            &request.headers,
            &framing.connection,
            strip_origin_credentials,
        );
        append(&mut head, "Host", &destination.authority());
        append_framing(&mut head, &framing);
        if upgrade.is_empty() {
            append(&mut head, "Connection", "close");
        } else {
            append(&mut head, "Connection", "Upgrade");
            append(&mut head, "Upgrade", &upgrade.join(", "));
        }
        head.extend_from_slice(b"\r\n");
        let keep_alive = !framing.connection.contains("close")
            && (request.version == "HTTP/1.1" || framing.connection.contains("keep-alive"));
        Ok(Self {
            destination,
            head,
            body,
            keep_alive,
            upgrade,
            trailer_blocklist: framing.connection,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ResponseHead {
    pub status: u16,
    line: String,
    headers: Vec<(String, String)>,
    framing: Framing,
}

impl ResponseHead {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| invalid("invalid response head encoding"))?;
        let mut lines = text.split("\r\n");
        let line = lines
            .next()
            .ok_or_else(|| invalid("missing HTTP response line"))?;
        let mut parts = line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let status = parts.next().unwrap_or_default();
        let reason = parts
            .next()
            .ok_or_else(|| invalid("invalid HTTP response line"))?;
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
            || status.len() != 3
            || !status.bytes().all(|byte| byte.is_ascii_digit())
            || reason
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid("invalid HTTP response line"));
        }
        let status = status
            .parse::<u16>()
            .map_err(|_| invalid("invalid status code"))?;
        if !(100..=599).contains(&status) {
            return Err(invalid("invalid status code"));
        }
        let headers = parse_headers(lines)?;
        let framing = Framing::parse(&headers)?;
        if version == "HTTP/1.0" && framing.body == Some(Body::Chunked) {
            return Err(invalid("HTTP/1.0 cannot use chunked framing"));
        }
        if (status < 200 || status == 204) && framing.body.is_some() {
            return Err(invalid("body framing is forbidden for this response"));
        }
        Ok(Self {
            status,
            line: format!("HTTP/1.1 {} {}", status, reason),
            headers,
            framing,
        })
    }

    pub fn body(&self, method: &str) -> Body {
        if method == "HEAD" || self.status < 200 || matches!(self.status, 204 | 304) {
            Body::Empty
        } else {
            self.framing.body.unwrap_or(Body::UntilEof)
        }
    }

    pub fn valid_upgrade(&self, requested: &[String]) -> io::Result<bool> {
        let protocols = upgrade_protocols(&self.headers, &self.framing.connection)?;
        Ok(self.status == 101
            && !requested.is_empty()
            && !protocols.is_empty()
            && protocols
                .iter()
                .all(|protocol| requested.contains(protocol)))
    }

    pub fn trailer_blocklist(&self) -> &HashSet<String> {
        &self.framing.connection
    }

    pub fn encode(&self, keep_alive: bool, upgraded: bool, legacy: bool) -> Vec<u8> {
        let line = if legacy {
            self.line.replacen("HTTP/1.1", "HTTP/1.0", 1)
        } else {
            self.line.clone()
        };
        let mut head = format!("{line}\r\n").into_bytes();
        append_headers(&mut head, &self.headers, &self.framing.connection, false);
        if !legacy || self.framing.body != Some(Body::Chunked) {
            append_framing(&mut head, &self.framing);
        }
        if upgraded {
            append(&mut head, "Connection", "Upgrade");
            if let Some(protocol) = values(&self.headers, "upgrade").next() {
                append(&mut head, "Upgrade", protocol);
            }
        } else if self.status >= 200 {
            append(
                &mut head,
                "Connection",
                if keep_alive { "keep-alive" } else { "close" },
            );
        }
        head.extend_from_slice(b"\r\n");
        head
    }
}

#[derive(Debug)]
struct Framing {
    body: Option<Body>,
    connection: HashSet<String>,
    trailers: Vec<String>,
}

impl Framing {
    fn parse(headers: &[(String, String)]) -> io::Result<Self> {
        let lengths = values(headers, "content-length").collect::<Vec<_>>();
        let transfers = values(headers, "transfer-encoding").collect::<Vec<_>>();
        if lengths.len() > 1
            || transfers.len() > 1
            || (!lengths.is_empty() && !transfers.is_empty())
        {
            return Err(invalid("ambiguous HTTP message length"));
        }
        let body = if let Some(length) = lengths.first() {
            if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("invalid Content-Length"));
            }
            Some(Body::Length(
                length
                    .parse()
                    .map_err(|_| invalid("Content-Length overflow"))?,
            ))
        } else if let Some(transfer) = transfers.first() {
            if !transfer.eq_ignore_ascii_case("chunked") {
                return Err(invalid("unsupported Transfer-Encoding"));
            }
            Some(Body::Chunked)
        } else {
            None
        };
        let mut connection = HashSet::new();
        for value in values(headers, "connection").chain(values(headers, "proxy-connection")) {
            for token in value.split(',') {
                let token = token.trim_matches([' ', '\t']);
                if token.is_empty() || !token.bytes().all(is_token_byte) {
                    return Err(invalid("invalid Connection token"));
                }
                let token = token.to_ascii_lowercase();
                if [
                    "content-length",
                    "transfer-encoding",
                    "host",
                    "trailer",
                    "expect",
                ]
                .contains(&token.as_str())
                {
                    return Err(invalid(
                        "Connection cannot remove message framing or routing fields",
                    ));
                }
                connection.insert(token);
            }
        }
        let mut trailers = Vec::new();
        for value in values(headers, "trailer") {
            if body != Some(Body::Chunked) {
                return Err(invalid("Trailer requires chunked framing"));
            }
            for name in value.split(',') {
                let name = name.trim_matches([' ', '\t']);
                if name.is_empty()
                    || !name.bytes().all(is_token_byte)
                    || forbidden_trailer(name, &connection)
                {
                    return Err(invalid("invalid Trailer declaration"));
                }
                trailers.push(name.to_owned());
            }
        }
        Ok(Self {
            body,
            connection,
            trailers,
        })
    }
}

pub(crate) fn validate_connect(request: &RequestHead) -> io::Result<()> {
    let framing = Framing::parse(&request.headers)?;
    let hosts = values(&request.headers, "host").count();
    if !matches!(framing.body, None | Some(Body::Length(0)))
        || values(&request.headers, "upgrade").next().is_some()
        || framing.connection.contains("upgrade")
        || values(&request.headers, "expect").next().is_some()
        || hosts > 1
        || (request.version == "HTTP/1.1" && hosts != 1)
    {
        return Err(invalid("CONNECT must not carry an HTTP body or Upgrade"));
    }
    Ok(())
}

fn upgrade_protocols(
    headers: &[(String, String)],
    connection: &HashSet<String>,
) -> io::Result<Vec<String>> {
    let upgrades = values(headers, "upgrade").collect::<Vec<_>>();
    if upgrades.len() > 1 || upgrades.is_empty() != !connection.contains("upgrade") {
        return Err(invalid("Upgrade and Connection must agree"));
    }
    let Some(value) = upgrades.first() else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(|protocol| {
            let protocol = protocol.trim_matches([' ', '\t']);
            let parts = protocol.split('/').collect::<Vec<_>>();
            if parts.len() > 2
                || parts
                    .iter()
                    .any(|part| part.is_empty() || !part.bytes().all(is_token_byte))
            {
                return Err(invalid("invalid Upgrade protocol"));
            }
            Ok(protocol.to_owned())
        })
        .collect()
}

fn values<'a>(headers: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn append(output: &mut Vec<u8>, name: &str, value: &str) {
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(b"\r\n");
}

fn stripped(name: &str, connection: &HashSet<String>) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "host",
        "content-length",
        "transfer-encoding",
    ]
    .contains(&name.as_str())
        || name.starts_with("x-vole-")
        || connection.contains(&name)
}

fn append_headers(
    output: &mut Vec<u8>,
    headers: &[(String, String)],
    connection: &HashSet<String>,
    strip_origin_credentials: bool,
) {
    for (name, value) in headers {
        if strip_origin_credentials
            && (name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie"))
        {
            continue;
        }

        if !stripped(name, connection) {
            append(output, name, value);
        }
    }
}

fn append_framing(output: &mut Vec<u8>, framing: &Framing) {
    match framing.body {
        Some(Body::Length(length)) => append(output, "Content-Length", &length.to_string()),
        Some(Body::Chunked) => {
            append(output, "Transfer-Encoding", "chunked");
            if !framing.trailers.is_empty() {
                append(output, "Trailer", &framing.trailers.join(", "));
            }
        }
        _ => {}
    }
}

/// Consume exactly one head; BufReader retains any body or pipelined request.
pub(crate) async fn read_head<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(maximum.min(4096));
    loop {
        let line = read_line(reader, maximum.saturating_sub(head.len())).await?;
        if line == b"\r\n" {
            if head.len() < 2 {
                return Err(invalid("empty HTTP head"));
            }
            head.truncate(head.len() - 2);
            return Ok(head);
        }
        head.extend_from_slice(&line);
    }
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, maximum: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(maximum.min(128));
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete HTTP message",
            ));
        }
        let end = buffer
            .iter()
            .position(|&byte| byte == b'\n')
            .map(|index| index + 1);
        let length = end.unwrap_or(buffer.len());
        if line.len().saturating_add(length) > maximum {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "HTTP line or head exceeds its limit",
            ));
        }
        line.extend_from_slice(&buffer[..length]);
        reader.consume(length);
        if end.is_some() {
            if !line.ends_with(b"\r\n") {
                return Err(invalid("HTTP lines require CRLF"));
            }
            return Ok(line);
        }
    }
}

pub(crate) async fn transfer_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    body: Body,
    idle: Duration,
    trailer_blocklist: &HashSet<String>,
    dechunk: bool,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        Body::Empty => {}
        Body::Length(length) => copy_length(reader, writer, Some(length), idle).await?,
        Body::UntilEof => copy_length(reader, writer, None, idle).await?,
        Body::Chunked => loop {
            let line = timeout_io(idle, read_line(reader, MAX_CHUNK_LINE)).await?;
            let size = chunk_size(&line)?;
            // Re-encode rather than forward extension syntax to the next parser.
            if !dechunk {
                write_timed(writer, format!("{size:x}\r\n").as_bytes(), idle).await?;
            }
            if size == 0 {
                let mut bytes = 0;
                let mut fields = 0;
                loop {
                    let line = timeout_io(idle, read_line(reader, MAX_TRAILERS - bytes)).await?;
                    bytes += line.len();
                    if line == b"\r\n" {
                        break;
                    }
                    fields += 1;
                    if fields > 100 {
                        return Err(invalid("too many HTTP trailers"));
                    }
                    let text = std::str::from_utf8(&line[..line.len() - 2])
                        .map_err(|_| invalid("invalid trailer encoding"))?;
                    let header = parse_headers(std::iter::once(text))?;
                    let (name, _) = &header[0];
                    if forbidden_trailer(name, trailer_blocklist) {
                        return Err(invalid("forbidden HTTP trailer"));
                    }
                    if !dechunk {
                        write_timed(writer, &line, idle).await?;
                    }
                }
                if !dechunk {
                    write_timed(writer, b"\r\n", idle).await?;
                }
                break;
            }
            copy_length(reader, writer, Some(size), idle).await?;
            let mut crlf = [0; 2];
            timeout_io(idle, reader.read_exact(&mut crlf)).await?;
            if crlf != *b"\r\n" {
                return Err(invalid("invalid chunk terminator"));
            }
            if !dechunk {
                write_timed(writer, b"\r\n", idle).await?;
            }
        },
    }
    timeout_io(idle, writer.flush()).await
}

fn forbidden_trailer(name: &str, connection: &HashSet<String>) -> bool {
    stripped(name, connection)
        || [
            "authorization",
            "expect",
            "content-type",
            "content-encoding",
            "content-range",
        ]
        .iter()
        .any(|field| name.eq_ignore_ascii_case(field))
}

fn chunk_size(line: &[u8]) -> io::Result<u64> {
    let text = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| invalid("invalid chunk line"))?;
    let end = text
        .iter()
        .take_while(|byte| byte.is_ascii_hexdigit())
        .count();
    if end == 0 || end > 16 {
        return Err(invalid("invalid chunk size"));
    }
    let size = u64::from_str_radix(std::str::from_utf8(&text[..end]).unwrap(), 16)
        .map_err(|_| invalid("chunk size overflow"))?;
    let mut rest = &text[end..];
    while !rest.is_empty() {
        rest = trim_bws(rest);
        rest = rest
            .strip_prefix(b";")
            .ok_or_else(|| invalid("invalid chunk extension"))?;
        rest = trim_bws(rest);
        let token = rest.iter().take_while(|&&byte| is_token_byte(byte)).count();
        if token == 0 {
            return Err(invalid("invalid chunk extension name"));
        }
        rest = &rest[token..];
        let after_space = trim_bws(rest);
        if let Some(value) = after_space.strip_prefix(b"=") {
            rest = trim_bws(value);
            if let Some(value) = rest.strip_prefix(b"\"") {
                rest = value;
                loop {
                    let (&byte, tail) = rest
                        .split_first()
                        .ok_or_else(|| invalid("unclosed chunk extension"))?;
                    rest = tail;
                    if byte == b'"' {
                        break;
                    }
                    if byte == b'\\' {
                        let (&escaped, tail) = rest
                            .split_first()
                            .ok_or_else(|| invalid("invalid quoted pair"))?;
                        if escaped != b'\t' && !(b' '..=b'~').contains(&escaped) && escaped < 128 {
                            return Err(invalid("invalid quoted pair"));
                        }
                        rest = tail;
                    } else if byte != b'\t' && !(b' '..=b'~').contains(&byte) && byte < 128 {
                        return Err(invalid("invalid quoted extension"));
                    }
                }
            } else {
                let token = rest.iter().take_while(|&&byte| is_token_byte(byte)).count();
                if token == 0 {
                    return Err(invalid("invalid chunk extension value"));
                }
                rest = &rest[token..];
            }
        }
    }
    Ok(size)
}

fn trim_bws(bytes: &[u8]) -> &[u8] {
    &bytes[bytes
        .iter()
        .take_while(|&&byte| byte == b' ' || byte == b'\t')
        .count()..]
}

async fn copy_length<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: Option<u64>,
    idle: Duration,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0; COPY_BUFFER];
    while remaining != Some(0) {
        let maximum = remaining.map_or(buffer.len(), |left| left.min(buffer.len() as u64) as usize);
        let read = timeout_io(idle, reader.read(&mut buffer[..maximum])).await?;
        if read == 0 {
            return if remaining.is_none() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated HTTP body",
                ))
            };
        }
        write_timed(writer, &buffer[..read], idle).await?;
        if let Some(left) = &mut remaining {
            *left -= read as u64;
        }
    }
    Ok(())
}

pub(crate) async fn timeout_io<T>(
    duration: Duration,
    future: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout(duration, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP I/O timed out"))?
}

pub(crate) async fn write_timed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    idle: Duration,
) -> io::Result<()> {
    timeout_io(idle, writer.write_all(bytes)).await
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn chunk_extensions_follow_token_and_quoted_string_grammar() {
        for line in [
            "a\r\n",
            "A;foo=bar\r\n",
            "a ; foo = \"a;\\\"b\";empty=\"\";flag\r\n",
            "ffffffffffffffff\r\n",
        ] {
            assert!(chunk_size(line.as_bytes()).is_ok(), "{line:?}");
        }
        for line in [
            "",
            "-1\r\n",
            "1g\r\n",
            "1 \r\n",
            "1;\r\n",
            "1;=x\r\n",
            "1;name=\r\n",
            "1;name=x y\r\n",
            "1;name=\"x\"y\r\n",
            "1;name=\"unterminated\r\n",
            "1;name=\"\u{7f}\"\r\n",
            "10000000000000000\r\n",
        ] {
            assert!(chunk_size(line.as_bytes()).is_err(), "{line:?}");
        }
    }

    #[tokio::test]
    async fn malformed_chunks_truncated_lengths_and_sensitive_trailers_fail_closed() {
        for (body, wire) in [
            (Body::Length(u64::MAX), "short"),
            (Body::Chunked, "3\r\nxy"),
            (Body::Chunked, "3\r\nabcXX"),
            (Body::Chunked, "z\r\n"),
            (Body::Chunked, "0\r\nProxy-Authorization: secret\r\n\r\n"),
            (Body::Chunked, "0\r\nX-Vole-Measure-Diagnostic: v1\r\n\r\n"),
            (Body::Chunked, "0\r\nContent-Length: 9\r\n\r\n"),
            (Body::Chunked, "0\r\nX-Hop: removed\r\n\r\n"),
        ] {
            let mut reader = BufReader::with_capacity(3, wire.as_bytes());
            let mut output = Vec::new();
            assert!(
                transfer_body(
                    &mut reader,
                    &mut output,
                    body,
                    Duration::from_secs(1),
                    &HashSet::from(["x-hop".to_owned()]),
                    false
                )
                .await
                .is_err(),
                "{wire:?}"
            );
            let output = String::from_utf8(output).unwrap();
            for secret in ["secret", "v1", "Content-Length", "removed"] {
                assert!(!output.contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn trailers_chunks_and_heads_have_explicit_parser_limits() {
        for wire in [
            format!("1;{}\r\nx\r\n0\r\n\r\n", "a".repeat(MAX_CHUNK_LINE)),
            format!("0\r\nX-Long: {}\r\n\r\n", "a".repeat(MAX_TRAILERS)),
        ] {
            let mut reader = BufReader::new(wire.as_bytes());
            assert!(
                transfer_body(
                    &mut reader,
                    &mut tokio::io::sink(),
                    Body::Chunked,
                    Duration::from_secs(1),
                    &HashSet::new(),
                    false
                )
                .await
                .is_err()
            );
        }
        let mut reader =
            BufReader::with_capacity(5, b"GET / HTTP/1.1\r\nHost: a\r\n\r\nNEXT".as_slice());
        assert_eq!(
            read_head(&mut reader, 1024).await.unwrap(),
            b"GET / HTTP/1.1\r\nHost: a"
        );
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"NEXT");
    }

    #[tokio::test]
    async fn body_idle_timeout_bounds_stalled_reads_and_writes() {
        let (read, _held) = tokio::io::duplex(8);
        let mut reader = BufReader::new(read);
        let error = transfer_body(
            &mut reader,
            &mut tokio::io::sink(),
            Body::Length(1),
            Duration::from_millis(20),
            &HashSet::new(),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let (mut writer, _held) = tokio::io::duplex(1);
        let mut reader = BufReader::new(b"abcd".as_slice());
        let error = transfer_body(
            &mut reader,
            &mut writer,
            Body::Length(4),
            Duration::from_millis(20),
            &HashSet::new(),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
