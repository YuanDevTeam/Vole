//! Shared DoH GET construction and HTTP/1.1 framing over caller-owned IO.
use super::{MAX_HTTP_HEADER_BYTES, MAX_MESSAGE_SIZE};
use crate::{config::DnsNameserver, dispatch::BoxStream};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn request(server: &DnsNameserver, query: &[u8]) -> io::Result<http::Request<()>> {
    if query.len() < 12 || query.len() > MAX_MESSAGE_SIZE {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut wire = query.to_vec();
    wire[..2].fill(0);
    let host = match &server.address {
        crate::config::DnsAddress::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        other => other.to_string(),
    };
    let authority = format!("{host}:{}", server.port);
    let target = format!(
        "{}?dns={}",
        server.path.as_deref().unwrap_or("/dns-query"),
        URL_SAFE_NO_PAD.encode(wire)
    );
    let size = authority.len()
        + target.len()
        + server.http_auth.as_ref().map_or(0, |auth| auth.0.len())
        // Covers HTTP/1 framing and the HTTP/2 pseudo/header names with
        // RFC 7540's 32-byte accounting per field.
        + 512;
    if size > MAX_HTTP_HEADER_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let uri = http::Uri::builder()
        .scheme(if server.transport == crate::config::DnsTransport::Http {
            "http"
        } else {
            "https"
        })
        .authority(authority)
        .path_and_query(target)
        .build()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut builder = http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("accept", "application/dns-message");
    if let Some(auth) = &server.http_auth {
        let mut value =
            http::HeaderValue::from_str(&auth.0).map_err(|_| io::ErrorKind::InvalidInput)?;
        value.set_sensitive(true);
        builder = builder.header("authorization", value);
    }
    builder
        .body(())
        .map_err(|_| io::ErrorKind::InvalidInput.into())
}

pub(super) fn restore_id(query: &[u8], response: &mut [u8]) -> io::Result<()> {
    if response.len() < 12 || response[..2] != [0, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response ID is not zero",
        ));
    }
    response[..2].copy_from_slice(&query[..2]);
    Ok(())
}

#[cfg(feature = "dns-quic")]
pub(super) fn validate_headers(
    status: http::StatusCode,
    headers: &http::HeaderMap,
) -> io::Result<Option<usize>> {
    if status != http::StatusCode::OK
        || !headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(';').next().is_some_and(|value| {
                    value.trim().eq_ignore_ascii_case("application/dns-message")
                })
            })
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    headers
        .get(http::header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|length| *length <= MAX_MESSAGE_SIZE)
                .ok_or_else(|| io::ErrorKind::InvalidData.into())
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_get_uses_id_zero_unpadded_dns_and_sensitive_basic() {
        let config = crate::config::Config::parse_yaml(b"mixed-port: 1080\ndns:\n  enable: true\n  nameserver: ['http://alice:password@[2001:db8::1]:8080/dns%2Fquery?old=value#ecs=192.0.2.1']\n").unwrap();
        let query =
            crate::dns::build_query(0x1234, "example.com", crate::dns::QueryType::A).unwrap();
        let request = request(&config.dns.nameservers[0], &query).unwrap();
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().authority().unwrap(), "[2001:db8::1]:8080");
        assert_eq!(request.uri().path(), "/dns/query");
        let encoded = request.uri().query().unwrap().strip_prefix("dns=").unwrap();
        assert!(!encoded.contains('='));
        let mut decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        assert_eq!(&decoded[..2], &[0, 0]);
        assert_eq!(&decoded[2..], &query[2..]);
        assert_eq!(
            request.headers()["authorization"],
            "Basic YWxpY2U6cGFzc3dvcmQ="
        );
        assert!(request.headers()["authorization"].is_sensitive());
        assert_eq!(request.headers()["accept"], "application/dns-message");
        for name in ["content-type", "content-length", "user-agent"] {
            assert!(!request.headers().contains_key(name));
        }
        restore_id(&query, &mut decoded).unwrap();
        assert_eq!(decoded, query);
        assert!(restore_id(&query, &mut decoded).is_err());
    }
}

async fn line(stream: &mut BoxStream, remaining: &mut usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    loop {
        *remaining = remaining.checked_sub(1).ok_or(io::ErrorKind::InvalidData)?;
        let byte = stream.read_u8().await?;
        bytes.push(byte);
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            break;
        }
    }
    String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into())
}

pub(super) async fn exchange(
    stream: &mut BoxStream,
    server: &DnsNameserver,
    query: &[u8],
) -> io::Result<(Vec<u8>, bool)> {
    let request = request(server, query)?;
    let mut head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n",
        request.uri().path_and_query().expect("DoH has a path"),
        request.uri().authority().expect("DoH has an authority")
    );
    for (name, value) in request.headers() {
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(value.to_str().map_err(|_| io::ErrorKind::InvalidInput)?);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    let mut budget = MAX_HTTP_HEADER_BYTES;
    let status = line(stream, &mut budget).await?;
    let mut parts = status.split_ascii_whitespace();
    let version = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next() != Some("200") {
        return Err(io::Error::other("DNS HTTP response status is not 200"));
    }
    let mut reusable = version == "HTTP/1.1";
    let mut length = None;
    let mut chunked = false;
    let mut content_type = false;
    loop {
        let header = line(stream, &mut budget).await?;
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').ok_or(io::ErrorKind::InvalidData)?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| io::ErrorKind::InvalidData)?,
                );
            }
            "transfer-encoding" => {
                if chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                chunked = true;
            }
            "content-type" => {
                content_type = value.split(';').next().is_some_and(|value| {
                    value.trim().eq_ignore_ascii_case("application/dns-message")
                })
            }
            "connection"
                if value
                    .split(',')
                    .any(|value| value.trim().eq_ignore_ascii_case("close")) =>
            {
                reusable = false
            }
            _ => {}
        }
    }
    if !content_type || (chunked && length.is_some()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let size = line(stream, &mut budget).await?;
            let size = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| io::ErrorKind::InvalidData)?;
            if size == 0 {
                while !line(stream, &mut budget).await?.is_empty() {}
                break;
            }
            let end = body
                .len()
                .checked_add(size)
                .filter(|size| *size <= MAX_MESSAGE_SIZE)
                .ok_or(io::ErrorKind::InvalidData)?;
            let start = body.len();
            body.resize(end, 0);
            stream.read_exact(&mut body[start..]).await?;
            if stream.read_u16().await? != 0x0d0a {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
    } else if let Some(length) = length {
        if length > MAX_MESSAGE_SIZE {
            return Err(io::ErrorKind::InvalidData.into());
        }
        body.resize(length, 0);
        stream.read_exact(&mut body).await?;
    } else {
        reusable = false;
        stream
            .take(MAX_MESSAGE_SIZE as u64 + 1)
            .read_to_end(&mut body)
            .await?;
        if body.len() > MAX_MESSAGE_SIZE {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    restore_id(query, &mut body)?;
    Ok((body, reusable))
}
