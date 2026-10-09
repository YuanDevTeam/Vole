//! DNS-over-HTTP/1.1 on a caller-owned authenticated stream. No socket factory
//! or detached connection driver; cancellation discards the current lease.
use super::MAX_MESSAGE_SIZE;
use crate::{config::DnsNameserver, dispatch::BoxStream};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HEADER_LIMIT: usize = 16 * 1024;

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
    let host = match &server.address {
        crate::config::DnsAddress::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        other => other.to_string(),
    };
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {host}:{}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        server.path.as_deref().unwrap_or("/dns-query"),
        server.port,
        query.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let mut budget = HEADER_LIMIT;
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
    Ok((body, reusable))
}
