use std::{io, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};
use url::{Host, Url};

use crate::session::Destination;

use super::super::DEFAULT_HEADER_COUNT_LIMIT;

#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub buffered: Vec<u8>,
}

impl RequestHead {
    pub fn is_connect(&self) -> bool {
        self.method == "CONNECT"
    }

    pub fn connect_destination(&self) -> io::Result<Destination> {
        Destination::from_authority(&self.target)
    }

    pub(super) fn forward_target(&self) -> io::Result<(Destination, String)> {
        if self.target.len() > 8 * 1024 {
            return Err(invalid("HTTP request target is too long"));
        }
        let (_, authority) = self
            .target
            .split_once("://")
            .ok_or_else(|| invalid("absolute-form URL requires an authority"))?;
        if self.target.contains('\\')
            || authority
                .split(['/', '?', '#'])
                .next()
                .is_some_and(|value| value.contains('@'))
        {
            return Err(invalid("invalid absolute-form authority"));
        }
        let url = Url::parse(&self.target).map_err(|_| invalid("invalid absolute-form URL"))?;
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid("only absolute-form http:// URLs are supported"));
        }
        let host = url
            .host()
            .ok_or_else(|| invalid("absolute URL has no host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| invalid("URL has no port"))?;
        if port == 0 {
            return Err(invalid("URL port must be nonzero"));
        }
        let destination = match host {
            Host::Ipv4(address) => Destination::Ip(SocketAddr::from((address, port))),
            Host::Ipv6(address) => Destination::Ip(SocketAddr::from((address, port))),
            Host::Domain(domain) => Destination::domain(domain, port)?,
        };
        let mut origin = url.path().to_owned();
        if origin.is_empty() {
            origin.push('/');
        }
        if let Some(query) = url.query() {
            origin.push('?');
            origin.push_str(query);
        }

        Ok((destination, origin))
    }
}

pub async fn read_request_head<R>(reader: &mut R, max_bytes: usize) -> io::Result<RequestHead>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut input = Vec::with_capacity(max_bytes.min(4 * 1024));
    let header_end = loop {
        if let Some(end) = find_header_end(&input) {
            break end;
        }
        if input.len() >= max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "HTTP request head exceeds its limit",
            ));
        }
        let mut chunk = [0_u8; 1024];
        let remaining = max_bytes - input.len();
        let max_read = remaining.min(chunk.len());
        let length = reader.read(&mut chunk[..max_read]).await?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP connection closed before the request head",
            ));
        }
        input.extend_from_slice(&chunk[..length]);
    };

    let buffered = input.split_off(header_end + 4);
    input.truncate(header_end);
    parse_request_head(&input, buffered)
}

pub(crate) fn parse_request_head(input: &[u8], buffered: Vec<u8>) -> io::Result<RequestHead> {
    let head =
        std::str::from_utf8(input).map_err(|_| invalid("HTTP request head is not valid UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid("missing HTTP request line"))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || method.is_empty()
        || target.is_empty()
        || target.bytes().any(|byte| byte <= b' ' || byte == 127)
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !method.bytes().all(is_token_byte)
    {
        return Err(invalid("invalid HTTP request line"));
    }

    let headers = parse_headers(lines)?;

    Ok(RequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        buffered,
    })
}

pub(crate) fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> io::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(invalid("obsolete folded HTTP header"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed HTTP header"))?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(invalid("invalid HTTP header name"));
        }
        let value = value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid("invalid HTTP header value"));
        }
        headers.push((name.to_owned(), value.to_owned()));
        if headers.len() > DEFAULT_HEADER_COUNT_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "too many HTTP headers",
            ));
        }
    }

    Ok(headers)
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

pub(super) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    #[cfg(feature = "inbound-http")]
    async fn parser_preserves_early_data_and_rewrites_absolute_form() {
        let (mut writer, mut reader) = tokio::io::duplex(2048);
        writer
            .write_all(
                b"POST http://example.com/a?q=1 HTTP/1.1\r\nHost: old\r\nProxy-Authorization: secret\r\nX-Vole-Measure-Diagnostic: v1\r\nConnection: X-Remove\r\nX-Remove: yes\r\nContent-Length: 3\r\n\r\nabc",
            )
            .await
            .unwrap();
        let request = read_request_head(&mut reader, 1024).await.unwrap();
        let plan = super::super::framing::RequestPlan::new(&request).unwrap();
        let destination = plan.destination;
        let rewritten = plan.head;
        let buffered = request.buffered;
        let rewritten = String::from_utf8(rewritten).unwrap();
        assert_eq!(destination, Destination::domain("example.com", 80).unwrap());
        assert!(rewritten.starts_with("POST /a?q=1 HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: example.com:80\r\n"));
        assert!(!rewritten.contains("Proxy-Authorization"));
        assert!(!rewritten.contains("X-Vole-Measure-Diagnostic"));
        assert!(!rewritten.contains("X-Remove"));
        assert_eq!(buffered, b"abc");
    }

    #[tokio::test]
    async fn parser_enforces_the_header_limit() {
        let (mut writer, mut reader) = tokio::io::duplex(2048);
        writer.write_all(&[b'a'; 128]).await.unwrap();
        assert_eq!(
            read_request_head(&mut reader, 64).await.unwrap_err().kind(),
            io::ErrorKind::FileTooLarge
        );
    }

    #[test]
    fn connect_requires_authority_form_with_an_explicit_port() {
        let request = RequestHead {
            method: "CONNECT".to_owned(),
            target: "example.com".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            buffered: Vec::new(),
        };
        assert!(request.connect_destination().is_err());
    }
}
