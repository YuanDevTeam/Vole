//! Bounded TCP first-payload sniffing for the TUN inbound.
//!
//! The inbound applies the configured destination-override policy. All bytes read
//! here remain available to the caller for replay after the outbound has been
//! selected.

use std::{io, net::IpAddr, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    time::{Instant, timeout_at},
};

use crate::routing::normalize_domain_name;

#[path = "tcp_sniffer/http2.rs"]
mod http2;

pub(crate) const TCP_SNIFF_MAX_BYTES: usize = 64 * 1024;
pub(crate) const TCP_SNIFF_TIMEOUT: Duration = Duration::from_secs(1);

const READ_CHUNK_BYTES: usize = 2 * 1024;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_CLIENT_HELLO_TYPE: u8 = 0x01;
const TLS_SERVER_NAME_EXTENSION: u16 = 0;
const TLS_ENCRYPTED_CLIENT_HELLO_EXTENSION: u16 = 0xfe0d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SniffProtocol {
    Http,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SniffOutcome {
    Matched {
        protocol: SniffProtocol,
        domain: String,
    },
    EchExtensionPresent,
    NotMatched,
    TimedOut,
    LimitReached,
    EndOfStream,
}

/// Result shared by TLS-over-TCP and QUIC CRYPTO ClientHello parsing.
///
/// `NeedMoreData` is used only by the record-oriented TCP parser. A complete
/// QUIC CRYPTO handshake passed to [`parse_client_hello`] resolves to one of
/// the other variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseOutcome {
    Matched(String),
    EchExtensionPresent,
    NeedMoreData,
    NotMatched,
}

/// Stateful bounded sniffer which retains every byte consumed from the
/// intercepted stream until the caller takes the prefix for replay.
pub(crate) struct TcpSniffer {
    protocols: Vec<SniffProtocol>,
    buffered: Vec<u8>,
}

impl TcpSniffer {
    /// Creates a bounded parser selected by the normalized runtime
    /// configuration. Port selection remains outside the parser so the same
    /// HTTP/TLS implementation can serve every configured TCP port.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn new(protocol: SniffProtocol) -> Self {
        Self::with_protocols(vec![protocol])
    }
    pub(crate) fn with_protocols(protocols: Vec<SniffProtocol>) -> Self {
        Self {
            protocols,
            buffered: Vec::with_capacity(READ_CHUNK_BYTES),
        }
    }

    /// Reads until the selected parser reaches a decision, the fixed deadline
    /// expires, EOF is observed, or the retained-prefix ceiling is reached.
    ///
    /// A caller cancelling this future still owns `self`, including all bytes
    /// already consumed from `reader`.
    pub(crate) async fn sniff<R>(&mut self, reader: &mut R) -> io::Result<SniffOutcome>
    where
        R: AsyncRead + Unpin,
    {
        let mut deadline = Instant::now() + TCP_SNIFF_TIMEOUT;
        loop {
            let mut active = Vec::with_capacity(self.protocols.len());
            let mut ech = false;
            for protocol in &self.protocols {
                match parse(*protocol, &self.buffered) {
                    ParseOutcome::Matched(domain) => {
                        return Ok(SniffOutcome::Matched {
                            protocol: *protocol,
                            domain,
                        });
                    }
                    ParseOutcome::NeedMoreData => active.push(*protocol),
                    ParseOutcome::EchExtensionPresent => ech = true,
                    ParseOutcome::NotMatched => {}
                }
            }
            self.protocols = active;
            if self.protocols.is_empty() {
                return Ok(if ech {
                    SniffOutcome::EchExtensionPresent
                } else {
                    SniffOutcome::NotMatched
                });
            }

            let remaining = TCP_SNIFF_MAX_BYTES.saturating_sub(self.buffered.len());
            if remaining == 0 {
                return Ok(SniffOutcome::LimitReached);
            }

            let mut chunk = [0_u8; READ_CHUNK_BYTES];
            let chunk_length = remaining.min(chunk.len());
            let read = timeout_at(deadline, reader.read(&mut chunk[..chunk_length])).await;
            let count = match read {
                Err(_) => return Ok(SniffOutcome::TimedOut),
                Ok(Ok(0)) => return Ok(SniffOutcome::EndOfStream),
                Ok(Ok(count)) => count,
                Ok(Err(error)) => return Err(error),
            };
            if self.buffered.is_empty() {
                deadline = Instant::now() + TCP_SNIFF_TIMEOUT;
            }
            self.buffered.extend_from_slice(&chunk[..count]);
        }
    }

    #[must_use]
    pub(crate) fn into_buffered(self) -> Vec<u8> {
        self.buffered
    }
}

fn parse(protocol: SniffProtocol, input: &[u8]) -> ParseOutcome {
    match protocol {
        SniffProtocol::Http => sniff_http_host(input),
        SniffProtocol::Tls => sniff_tls_sni(input),
    }
}

fn sniff_http_host(input: &[u8]) -> ParseOutcome {
    if http2::PREFACE.starts_with(input) {
        return ParseOutcome::NeedMoreData;
    }
    if input.starts_with(http2::PREFACE) {
        return http2::sniff(input);
    }
    sniff_http1_host(input)
}

fn sniff_http1_host(input: &[u8]) -> ParseOutcome {
    let Some(headers_end) = find_bytes(input, b"\r\n\r\n") else {
        return if input.len() == TCP_SNIFF_MAX_BYTES {
            ParseOutcome::NotMatched
        } else {
            early_http_decision(input)
        };
    };
    let headers = &input[..headers_end];
    let request_line_end = find_bytes(headers, b"\r\n").unwrap_or(headers.len());
    if !is_http_request_line(&headers[..request_line_end]) {
        return ParseOutcome::NotMatched;
    }

    let target_host = request_target_host(&headers[..request_line_end]);
    let mut host = None;
    let mut saw_host = false;
    let mut cursor = request_line_end + 2;
    while cursor < headers.len() {
        let line_end =
            find_bytes(&headers[cursor..], b"\r\n").map_or(headers.len(), |offset| cursor + offset);
        let line = &headers[cursor..line_end];
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return ParseOutcome::NotMatched;
        };
        if line[..colon].eq_ignore_ascii_case(b"host") {
            // Multiple Host fields are invalid for the routing hint even when
            // they happen to contain the same text.
            if saw_host {
                return ParseOutcome::NotMatched;
            }
            saw_host = true;
            host = normalize_host_header(&line[colon + 1..]);
            if host.is_none() && target_host.is_none() {
                return ParseOutcome::NotMatched;
            }
        }
        cursor = line_end.saturating_add(2);
    }

    target_host
        .or(host)
        .map_or(ParseOutcome::NotMatched, ParseOutcome::Matched)
}

fn request_target_host(line: &[u8]) -> Option<String> {
    let mut fields = line.split(|byte| *byte == b' ');
    let method = fields.next()?;
    let target = std::str::from_utf8(fields.next()?).ok()?;
    if method.eq_ignore_ascii_case(b"CONNECT") {
        return match crate::session::Destination::from_authority(target).ok()? {
            crate::session::Destination::Domain { host, .. } => normalize_domain(&host),
            crate::session::Destination::Ip(_) => None,
        };
    }
    if target.starts_with('/') || target == "*" {
        return None;
    }
    let url = url::Url::parse(target).ok()?;
    normalize_domain(url.host_str()?)
}

fn early_http_decision(input: &[u8]) -> ParseOutcome {
    let request_line = find_bytes(input, b"\r\n").map_or(input, |end| &input[..end]);
    let Some(space) = request_line.iter().position(|byte| *byte == b' ') else {
        return if HTTP_METHODS.iter().any(|method| {
            method.len() >= request_line.len()
                && method[..request_line.len()].eq_ignore_ascii_case(request_line)
        }) {
            ParseOutcome::NeedMoreData
        } else {
            ParseOutcome::NotMatched
        };
    };
    if is_http_method(&request_line[..space]) {
        ParseOutcome::NeedMoreData
    } else {
        ParseOutcome::NotMatched
    }
}

const HTTP_METHODS: [&[u8]; 9] = [
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"PATCH", b"TRACE",
];

fn is_http_method(candidate: &[u8]) -> bool {
    HTTP_METHODS
        .iter()
        .any(|method| candidate.eq_ignore_ascii_case(method))
}

fn is_http_request_line(line: &[u8]) -> bool {
    let mut fields = line.split(|byte| *byte == b' ');
    let Some(method) = fields.next() else {
        return false;
    };
    let Some(target) = fields.next() else {
        return false;
    };
    let Some(version) = fields.next() else {
        return false;
    };
    fields.next().is_none()
        && is_http_method(method)
        && !target.is_empty()
        && matches!(version, b"HTTP/1.0" | b"HTTP/1.1")
}

fn normalize_host_header(raw: &[u8]) -> Option<String> {
    let raw = trim_ascii_whitespace(raw);
    let raw = std::str::from_utf8(raw).ok()?;
    let host = if raw.starts_with('[') {
        // Bracketed Host values are IP literals and carry no domain routing
        // information.
        return None;
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        if host.contains(':') || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
            return None;
        }
        host
    } else {
        raw
    };
    normalize_domain(host)
}

fn sniff_tls_sni(input: &[u8]) -> ParseOutcome {
    if input.is_empty() {
        return ParseOutcome::NeedMoreData;
    }
    if input[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return ParseOutcome::NotMatched;
    }
    if input.len() < 3 {
        return ParseOutcome::NeedMoreData;
    }
    if input[1] != 3 {
        return ParseOutcome::NotMatched;
    }

    let first_payload = match tls_record_payload(input, 0) {
        RecordPayload::Complete { payload, next } => (payload, next),
        RecordPayload::NeedMoreData => return ParseOutcome::NeedMoreData,
        RecordPayload::Invalid => return ParseOutcome::NotMatched,
    };
    if first_payload.0.len() >= 4 {
        if first_payload.0[0] != TLS_CLIENT_HELLO_TYPE {
            return ParseOutcome::NotMatched;
        }
        let handshake_length = read_u24(&first_payload.0[1..4]);
        let total_length = match handshake_length.checked_add(4) {
            Some(length) if length <= TCP_SNIFF_MAX_BYTES => length,
            _ => return ParseOutcome::NotMatched,
        };
        if first_payload.0.len() >= total_length {
            return parse_client_hello(&first_payload.0[..total_length]);
        }
    }

    // ClientHello fragmentation across TLS records is uncommon but valid.
    // Allocate the reassembly buffer only for that slow path.
    let mut handshake = Vec::with_capacity(first_payload.0.len().max(4));
    handshake.extend_from_slice(first_payload.0);
    let mut cursor = first_payload.1;
    while handshake.len() < 4 {
        let payload = match tls_record_payload(input, cursor) {
            RecordPayload::Complete { payload, next } => {
                cursor = next;
                payload
            }
            RecordPayload::NeedMoreData => return ParseOutcome::NeedMoreData,
            RecordPayload::Invalid => return ParseOutcome::NotMatched,
        };
        handshake.extend_from_slice(payload);
    }
    if handshake[0] != TLS_CLIENT_HELLO_TYPE {
        return ParseOutcome::NotMatched;
    }
    let total_length = match read_u24(&handshake[1..4]).checked_add(4) {
        Some(length) if length <= TCP_SNIFF_MAX_BYTES => length,
        _ => return ParseOutcome::NotMatched,
    };
    if handshake.capacity() < total_length {
        handshake.reserve(total_length - handshake.len());
    }
    while handshake.len() < total_length {
        let payload = match tls_record_payload(input, cursor) {
            RecordPayload::Complete { payload, next } => {
                cursor = next;
                payload
            }
            RecordPayload::NeedMoreData => return ParseOutcome::NeedMoreData,
            RecordPayload::Invalid => return ParseOutcome::NotMatched,
        };
        let needed = total_length - handshake.len();
        handshake.extend_from_slice(&payload[..payload.len().min(needed)]);
    }
    parse_client_hello(&handshake[..total_length])
}

enum RecordPayload<'a> {
    Complete { payload: &'a [u8], next: usize },
    NeedMoreData,
    Invalid,
}

fn tls_record_payload(input: &[u8], offset: usize) -> RecordPayload<'_> {
    let Some(header_end) = offset.checked_add(5) else {
        return RecordPayload::Invalid;
    };
    if input.len() < header_end {
        return RecordPayload::NeedMoreData;
    }
    if input[offset] != TLS_HANDSHAKE_CONTENT_TYPE || input[offset + 1] != 3 {
        return RecordPayload::Invalid;
    }
    let length = usize::from(u16::from_be_bytes([input[offset + 3], input[offset + 4]]));
    if length == 0 {
        return RecordPayload::Invalid;
    }
    let Some(record_end) = header_end.checked_add(length) else {
        return RecordPayload::Invalid;
    };
    if record_end > TCP_SNIFF_MAX_BYTES {
        return RecordPayload::Invalid;
    }
    if input.len() < record_end {
        return RecordPayload::NeedMoreData;
    }
    RecordPayload::Complete {
        payload: &input[header_end..record_end],
        next: record_end,
    }
}

pub(crate) fn parse_client_hello(handshake: &[u8]) -> ParseOutcome {
    if handshake.len() < 4 || handshake[0] != TLS_CLIENT_HELLO_TYPE {
        return ParseOutcome::NotMatched;
    }
    let declared_length = read_u24(&handshake[1..4]);
    if declared_length != handshake.len().saturating_sub(4) {
        return ParseOutcome::NotMatched;
    }

    let body = &handshake[4..];
    // legacy_version + random + session_id length
    if body.len() < 35 {
        return ParseOutcome::NotMatched;
    }
    let session_id_length = usize::from(body[34]);
    if session_id_length > 32 {
        return ParseOutcome::NotMatched;
    }
    let mut cursor = 35;
    if !advance(&mut cursor, session_id_length, body.len()) {
        return ParseOutcome::NotMatched;
    }

    let Some(cipher_suites_length) = take_u16(body, &mut cursor) else {
        return ParseOutcome::NotMatched;
    };
    if cipher_suites_length == 0
        || cipher_suites_length % 2 != 0
        || !advance(&mut cursor, cipher_suites_length, body.len())
    {
        return ParseOutcome::NotMatched;
    }

    let Some(compression_length) = body.get(cursor).copied().map(usize::from) else {
        return ParseOutcome::NotMatched;
    };
    cursor += 1;
    if compression_length == 0 || !advance(&mut cursor, compression_length, body.len()) {
        return ParseOutcome::NotMatched;
    }
    let Some(extensions_length) = take_u16(body, &mut cursor) else {
        return ParseOutcome::NotMatched;
    };
    let Some(extensions_end) = cursor.checked_add(extensions_length) else {
        return ParseOutcome::NotMatched;
    };
    if extensions_end != body.len() {
        return ParseOutcome::NotMatched;
    }

    let mut server_name = None;
    let mut saw_server_name_extension = false;
    let mut saw_encrypted_client_hello = false;
    while cursor < extensions_end {
        let Some(extension_type) = take_u16_value(body, &mut cursor) else {
            return ParseOutcome::NotMatched;
        };
        let Some(extension_length) = take_u16(body, &mut cursor) else {
            return ParseOutcome::NotMatched;
        };
        let Some(extension_end) = cursor.checked_add(extension_length) else {
            return ParseOutcome::NotMatched;
        };
        if extension_end > extensions_end {
            return ParseOutcome::NotMatched;
        }
        match extension_type {
            TLS_SERVER_NAME_EXTENSION => {
                // TLS forbids duplicate extensions. More importantly, an
                // ambiguous name must never become a routing hint.
                if saw_server_name_extension {
                    return ParseOutcome::NotMatched;
                }
                saw_server_name_extension = true;
                server_name = match parse_server_name_extension(&body[cursor..extension_end]) {
                    ParseOutcome::Matched(domain) => Some(domain),
                    ParseOutcome::EchExtensionPresent
                    | ParseOutcome::NeedMoreData
                    | ParseOutcome::NotMatched => {
                        return ParseOutcome::NotMatched;
                    }
                };
            }
            TLS_ENCRYPTED_CLIENT_HELLO_EXTENSION => {
                // A passive sniffer cannot reliably distinguish a genuine ECH
                // offer from ECH GREASE. Genuine ECH exposes only an outer
                // public name, so conservatively treat the plaintext SNI as
                // untrusted whenever this extension is present.
                saw_encrypted_client_hello = true;
            }
            _ => {}
        }
        cursor = extension_end;
    }
    if saw_encrypted_client_hello {
        ParseOutcome::EchExtensionPresent
    } else {
        server_name.map_or(ParseOutcome::NotMatched, ParseOutcome::Matched)
    }
}

fn parse_server_name_extension(extension: &[u8]) -> ParseOutcome {
    if extension.len() < 2 {
        return ParseOutcome::NotMatched;
    }
    let names_length = usize::from(u16::from_be_bytes([extension[0], extension[1]]));
    if names_length != extension.len() - 2 {
        return ParseOutcome::NotMatched;
    }
    let mut cursor = 2;
    let mut server_name = None;
    while cursor < extension.len() {
        let Some(name_type) = extension.get(cursor).copied() else {
            return ParseOutcome::NotMatched;
        };
        cursor += 1;
        let Some(name_length) = take_u16(extension, &mut cursor) else {
            return ParseOutcome::NotMatched;
        };
        let Some(name_end) = cursor.checked_add(name_length) else {
            return ParseOutcome::NotMatched;
        };
        if name_end > extension.len() {
            return ParseOutcome::NotMatched;
        }
        if name_type == 0 {
            if server_name.is_some() {
                return ParseOutcome::NotMatched;
            }
            let Ok(host) = std::str::from_utf8(&extension[cursor..name_end]) else {
                return ParseOutcome::NotMatched;
            };
            // RFC 6066 forbids a trailing root dot in host_name.
            if host.ends_with('.') {
                return ParseOutcome::NotMatched;
            }
            let Some(domain) = normalize_domain(host) else {
                return ParseOutcome::NotMatched;
            };
            server_name = Some(domain);
        }
        cursor = name_end;
    }
    server_name.map_or(ParseOutcome::NotMatched, ParseOutcome::Matched)
}

fn normalize_domain(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    normalize_domain_name(host).ok()
}

fn trim_ascii_whitespace(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_u24(input: &[u8]) -> usize {
    (usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2])
}

fn take_u16(input: &[u8], cursor: &mut usize) -> Option<usize> {
    take_u16_value(input, cursor).map(usize::from)
}

fn take_u16_value(input: &[u8], cursor: &mut usize) -> Option<u16> {
    let end = cursor.checked_add(2)?;
    let bytes: [u8; 2] = input.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(u16::from_be_bytes(bytes))
}

fn advance(cursor: &mut usize, count: usize, length: usize) -> bool {
    let Some(end) = cursor.checked_add(count) else {
        return false;
    };
    if end > length {
        return false;
    }
    *cursor = end;
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use tokio::io::{AsyncWriteExt as _, duplex};

    use super::*;

    fn http_request(host: &str) -> Vec<u8> {
        format!("GET / HTTP/1.1\r\nUser-Agent: test\r\nHost: {host}\r\n\r\n").into_bytes()
    }

    #[test]
    fn http_target_authority_precedes_host_and_connect_needs_no_host_header() {
        for request in [
            b"GET http://Target.Example:8080/path HTTP/1.1\r\nHost: other.example\r\n\r\n"
                .as_slice(),
            b"CONNECT target.example:443 HTTP/1.1\r\n\r\n",
            b"GET https://target.example/path HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                sniff_http_host(request),
                ParseOutcome::Matched("target.example".into())
            );
        }
        assert_eq!(
            sniff_http_host(b"GET http://target.example/ HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"),
            ParseOutcome::NotMatched
        );
        assert_eq!(
            sniff_http_host(b"CONNECT target.example:0 HTTP/1.1\r\n\r\n"),
            ParseOutcome::NotMatched
        );
    }

    pub(crate) fn tls_client_hello(host: &str) -> Vec<u8> {
        tls_client_hello_with_extensions(&tls_server_name_extension(host))
    }

    fn tls_server_name_extension(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&u16::try_from(host.len() + 3).unwrap().to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
        server_name.extend_from_slice(host);
        tls_extension(TLS_SERVER_NAME_EXTENSION, &server_name)
    }

    fn tls_extension(extension_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut extension = Vec::new();
        extension.extend_from_slice(&extension_type.to_be_bytes());
        extension.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        extension.extend_from_slice(payload);
        extension
    }

    fn tls_client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_CLIENT_HELLO_TYPE);
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        handshake.extend_from_slice(&length[1..]);
        handshake.extend_from_slice(&body);

        tls_record(&handshake)
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x01];
        record.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn http_host_is_normalized_and_optional_port_is_removed() {
        assert_eq!(
            sniff_http_host(&http_request("ExAmPlE.COM:8080")),
            ParseOutcome::Matched("example.com".to_owned())
        );
        assert_eq!(
            sniff_http_host(&http_request("例子.中国")),
            ParseOutcome::Matched("xn--fsqu00a.xn--fiqs8s".to_owned())
        );
    }

    #[test]
    fn http_requires_a_complete_valid_request_and_one_domain_host() {
        assert_eq!(
            sniff_http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            ParseOutcome::NeedMoreData
        );
        assert_eq!(sniff_http_host(b"g"), ParseOutcome::NeedMoreData);
        assert_eq!(
            sniff_http_host(b"GETTING / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            ParseOutcome::NotMatched
        );
        assert_eq!(
            sniff_http_host(b"GET / HTTP/2\r\nHost: example.com\r\n\r\n"),
            ParseOutcome::NotMatched
        );
        assert_eq!(
            sniff_http_host(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n"),
            ParseOutcome::NotMatched
        );
        assert_eq!(
            sniff_http_host(b"GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n"),
            ParseOutcome::NotMatched
        );
    }

    #[test]
    fn tls_extracts_and_normalizes_sni() {
        assert_eq!(
            sniff_tls_sni(&tls_client_hello("ExAmPlE.COM")),
            ParseOutcome::Matched("example.com".to_owned())
        );
        assert_eq!(
            sniff_tls_sni(&tls_client_hello("192.0.2.1")),
            ParseOutcome::NotMatched
        );
    }

    #[test]
    fn tls_ech_suppresses_outer_sni_regardless_of_extension_order() {
        let server_name = tls_server_name_extension("outer.example");
        // A passive parser must handle genuine ECH and deliberately
        // indistinguishable GREASE payloads the same way.
        let encrypted_client_hello =
            tls_extension(TLS_ENCRYPTED_CLIENT_HELLO_EXTENSION, &[0x00, 0xaa, 0xbb]);

        for extensions in [
            [server_name.as_slice(), encrypted_client_hello.as_slice()].concat(),
            [encrypted_client_hello.as_slice(), server_name.as_slice()].concat(),
        ] {
            assert_eq!(
                sniff_tls_sni(&tls_client_hello_with_extensions(&extensions)),
                ParseOutcome::EchExtensionPresent
            );
        }
        assert_eq!(
            sniff_tls_sni(&tls_client_hello_with_extensions(&encrypted_client_hello)),
            ParseOutcome::EchExtensionPresent
        );
    }

    #[test]
    fn tls_unknown_extension_does_not_suppress_sni() {
        let server_name = tls_server_name_extension("visible.example");
        let unknown = tls_extension(42, &[0xde, 0xad, 0xbe, 0xef]);

        for extensions in [
            [unknown.as_slice(), server_name.as_slice()].concat(),
            [server_name.as_slice(), unknown.as_slice()].concat(),
        ] {
            assert_eq!(
                sniff_tls_sni(&tls_client_hello_with_extensions(&extensions)),
                ParseOutcome::Matched("visible.example".to_owned())
            );
        }
    }

    #[test]
    fn tls_duplicate_sni_extensions_are_not_used_as_a_hint() {
        let server_name = tls_server_name_extension("duplicate.example");
        let extensions = [server_name.as_slice(), server_name.as_slice()].concat();
        assert_eq!(
            sniff_tls_sni(&tls_client_hello_with_extensions(&extensions)),
            ParseOutcome::NotMatched
        );
    }

    #[test]
    fn tls_client_hello_may_span_two_records() {
        let record = tls_client_hello("fragmented.example");
        let payload = &record[5..];
        for split in [2, 17] {
            let mut fragmented = tls_record(&payload[..split]);
            fragmented.extend_from_slice(&tls_record(&payload[split..]));
            assert_eq!(
                sniff_tls_sni(&fragmented),
                ParseOutcome::Matched("fragmented.example".to_owned())
            );
        }
    }

    #[test]
    fn tls_ech_may_span_multiple_records_without_exposing_outer_sni() {
        let server_name = tls_server_name_extension("outer.example");
        let encrypted_client_hello = tls_extension(
            TLS_ENCRYPTED_CLIENT_HELLO_EXTENSION,
            &[0x00, 0xaa, 0xbb, 0xcc],
        );
        let extensions = [server_name.as_slice(), encrypted_client_hello.as_slice()].concat();
        let record = tls_client_hello_with_extensions(&extensions);
        let payload = &record[5..];
        let ech_offset = payload
            .windows(2)
            .position(|window| window == TLS_ENCRYPTED_CLIENT_HELLO_EXTENSION.to_be_bytes())
            .unwrap();

        for split in [2, ech_offset + 1, ech_offset + 5] {
            let mut fragmented = tls_record(&payload[..split]);
            fragmented.extend_from_slice(&tls_record(&payload[split..]));
            assert_eq!(
                sniff_tls_sni(&fragmented),
                ParseOutcome::EchExtensionPresent
            );
        }
    }

    #[test]
    fn tls_parser_distinguishes_incomplete_and_invalid_inputs() {
        let hello = tls_client_hello("example.com");
        assert_eq!(
            sniff_tls_sni(&hello[..hello.len() - 1]),
            ParseOutcome::NeedMoreData
        );
        assert_eq!(
            sniff_tls_sni(b"\x17\x03\x03\x00\x01\x00"),
            ParseOutcome::NotMatched
        );
        let mut no_sni = tls_client_hello("example.com");
        let extension_type = no_sni.len() - "example.com".len() - 9;
        no_sni[extension_type..extension_type + 2].copy_from_slice(&42_u16.to_be_bytes());
        assert_eq!(sniff_tls_sni(&no_sni), ParseOutcome::NotMatched);
    }

    #[tokio::test]
    async fn async_sniffer_retains_exact_fragmented_prefix_for_replay() {
        let request = http_request("example.com");
        let (mut writer, mut reader) = duplex(TCP_SNIFF_MAX_BYTES);
        let expected = request.clone();
        let writer_task = tokio::spawn(async move {
            for chunk in request.chunks(3) {
                writer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut sniffer = TcpSniffer::new(SniffProtocol::Http);
        assert_eq!(
            sniffer.sniff(&mut reader).await.unwrap(),
            SniffOutcome::Matched {
                protocol: SniffProtocol::Http,
                domain: "example.com".to_owned(),
            }
        );
        writer_task.await.unwrap();
        assert_eq!(sniffer.into_buffered(), expected);
    }

    #[tokio::test]
    async fn async_ech_sniffer_retains_exact_fragmented_prefix_for_replay() {
        let server_name = tls_server_name_extension("outer.example");
        let encrypted_client_hello =
            tls_extension(TLS_ENCRYPTED_CLIENT_HELLO_EXTENSION, &[0x00, 0xaa, 0xbb]);
        let extensions = [server_name.as_slice(), encrypted_client_hello.as_slice()].concat();
        let hello = tls_client_hello_with_extensions(&extensions);
        let (mut writer, mut reader) = duplex(TCP_SNIFF_MAX_BYTES);
        let expected = hello.clone();
        let writer_task = tokio::spawn(async move {
            for chunk in hello.chunks(3) {
                writer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut sniffer = TcpSniffer::new(SniffProtocol::Tls);
        assert_eq!(
            sniffer.sniff(&mut reader).await.unwrap(),
            SniffOutcome::EchExtensionPresent
        );
        writer_task.await.unwrap();
        assert_eq!(sniffer.into_buffered(), expected);
    }

    #[tokio::test]
    async fn timeout_is_fail_open_and_keeps_received_bytes() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(b"GET /").await.unwrap();
        let mut sniffer = TcpSniffer::new(SniffProtocol::Http);
        assert_eq!(
            sniffer.sniff(&mut reader).await.unwrap(),
            SniffOutcome::TimedOut
        );
        assert_eq!(sniffer.into_buffered(), b"GET /");
    }

    #[tokio::test]
    async fn unsupported_protocol_stops_without_waiting_for_deadline() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        let mut sniffer = TcpSniffer::new(SniffProtocol::Tls);
        assert_eq!(
            sniffer.sniff(&mut reader).await.unwrap(),
            SniffOutcome::NotMatched
        );
        assert_eq!(sniffer.into_buffered(), b"SSH-2.0-test\r\n");
    }
}
