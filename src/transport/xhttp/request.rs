use std::io;

use http::{HeaderValue, Request, Uri};
use rand::RngExt as _;

use crate::config::xhttp::{DataPlacement, MetaPlacement, PaddingPlacement, XHttpPadding};

pub(super) const MAX_REQUEST_BYTES: usize = crate::limits::XHTTP_REQUEST_BYTES;
pub(super) const MAX_REQUEST_HEADERS: usize = crate::limits::XHTTP_REQUEST_HEADERS;

pub(super) fn request_size(request: &Request<()>) -> usize {
    request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 32)
        .sum::<usize>()
        + request.uri().to_string().len()
        + 128
}

pub(super) fn check_size(request: &Request<()>) -> io::Result<()> {
    if request_size(request) > MAX_REQUEST_BYTES || request.headers().len() > MAX_REQUEST_HEADERS {
        Err(invalid_request())
    } else {
        Ok(())
    }
}

pub(super) fn packet_payload(
    mut request: Request<()>,
    data: &bytes::Bytes,
    placement: &DataPlacement,
) -> io::Result<(Request<()>, bytes::Bytes, usize)> {
    use base64::Engine as _;
    let DataPlacement::Chunks { key, cookie, size } = placement else {
        return Ok((request, data.clone(), data.len()));
    };
    let base = request_size(&request);
    let fits = |raw: usize| {
        let encoded = (raw * 4).div_ceil(3);
        let chunks = encoded.div_ceil(size.min);
        let extra = encoded + chunks * (key.len() + 10 + if *cookie { 0 } else { 32 }) + 32;
        let fields = if *cookie { 1 } else { chunks };
        base + extra <= MAX_REQUEST_BYTES && request.headers().len() + fields <= MAX_REQUEST_HEADERS
    };
    let (mut low, mut high) = (0, data.len());
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if fits(mid) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    if low == 0 {
        return Err(invalid_request());
    }
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data[..low]);
    let mut remaining = encoded.as_str();
    let mut index = 0;
    while !remaining.is_empty() {
        let count = size.sample().min(remaining.len());
        let (chunk, rest) = remaining.split_at(count);
        remaining = rest;
        if *cookie {
            append_cookie(&mut request, &format!("{key}_{index}"), chunk)?;
        } else {
            let name = format!("{key}-{index}")
                .parse::<http::HeaderName>()
                .map_err(|_| invalid_request())?;
            request.headers_mut().insert(name, header_value(chunk)?);
        }
        index += 1;
    }
    check_size(&request)?;
    Ok((request, bytes::Bytes::new(), low))
}

pub(super) fn apply_metadata(
    request: &mut Request<()>,
    placement: &MetaPlacement,
    value: &str,
) -> io::Result<()> {
    match placement {
        MetaPlacement::Path => {
            let path = request.uri().path();
            let path = format!(
                "{}{value}{}",
                if path.ends_with('/') {
                    path.to_owned()
                } else {
                    format!("{path}/")
                },
                request
                    .uri()
                    .query()
                    .map_or(String::new(), |query| format!("?{query}"))
            );
            let mut parts = request.uri().clone().into_parts();
            parts.path_and_query = Some(path.parse().map_err(|_| invalid_request())?);
            *request.uri_mut() = Uri::from_parts(parts).map_err(|_| invalid_request())?;
        }
        MetaPlacement::Query(key) => append_query(request, key, value)?,
        MetaPlacement::Header(key) => {
            request
                .headers_mut()
                .insert(key.clone(), header_value(value)?);
        }
        MetaPlacement::Cookie(key) => append_cookie(request, key, value)?,
    }
    Ok(())
}

fn append_query(request: &mut Request<()>, key: &str, value: &str) -> io::Result<()> {
    let mut parts = request.uri().clone().into_parts();
    let path = request.uri().path_and_query().unwrap().as_str();
    let separator = if request.uri().query().is_some() {
        '&'
    } else {
        '?'
    };
    parts.path_and_query = Some(
        format!("{path}{separator}{key}={value}")
            .parse()
            .map_err(|_| invalid_request())?,
    );
    *request.uri_mut() = Uri::from_parts(parts).map_err(|_| invalid_request())?;
    Ok(())
}

pub(super) fn apply_padding(
    request: &mut Request<()>,
    base: &Uri,
    padding: &XHttpPadding,
) -> io::Result<()> {
    let length = padding.bytes.sample();
    let value = if padding.tokenish {
        tokenish(length)
    } else {
        "X".repeat(length)
    };
    match padding.placement {
        PaddingPlacement::Header => {
            request
                .headers_mut()
                .insert(padding.header.clone(), header_value(&value)?);
        }
        PaddingPlacement::QueryInHeader => {
            let url = format!(
                "{}://{}{}?{}={}",
                base.scheme_str().unwrap_or("https"),
                base.authority().unwrap(),
                base.path(),
                padding.key,
                value
            );
            request
                .headers_mut()
                .insert(padding.header.clone(), header_value(&url)?);
        }
        PaddingPlacement::Query => {
            append_query(request, &padding.key, &value)?;
        }
        PaddingPlacement::Cookie => append_cookie(request, &padding.key, &value)?,
    }
    Ok(())
}

pub(super) fn append_cookie(request: &mut Request<()>, key: &str, value: &str) -> io::Result<()> {
    let prefix = request
        .headers()
        .get(http::header::COOKIE)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|_| invalid_request())?;
    let cookie = prefix.map_or_else(
        || format!("{key}={value}"),
        |prefix| format!("{prefix}; {key}={value}"),
    );
    request
        .headers_mut()
        .insert(http::header::COOKIE, header_value(&cookie)?);
    Ok(())
}

pub(super) fn header_value(value: &str) -> io::Result<HeaderValue> {
    let mut value = HeaderValue::from_str(value).map_err(|_| invalid_request())?;
    value.set_sensitive(true);
    Ok(value)
}

pub(super) fn invalid_request() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid or oversized XHTTP request",
    )
}

fn tokenish(target: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    let mut result = String::with_capacity(target * 8 / 5 + 1);
    let mut bits: usize = 0;
    while bits.div_ceil(8) < target {
        let ch = ALPHABET[rng.random_range(0..ALPHABET.len())];
        // Code widths for ASCII alphanumerics from RFC 7541 Appendix B.
        // Incrementally target the encoded byte count; no HTTP encoder fork.
        bits += match ch {
            b'0'..=b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
            b'3'..=b'9'
            | b'A'
            | b'b'
            | b'd'
            | b'f'
            | b'g'
            | b'h'
            | b'l'
            | b'm'
            | b'n'
            | b'p'
            | b'r'
            | b'u' => 6,
            b'X' | b'Z' => 8,
            _ => 7,
        };
        result.push(char::from(ch));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_body_shares_the_frozen_batch_without_a_second_payload_allocation() {
        let batch = bytes::Bytes::from(vec![7; crate::limits::XHTTP_PACKET_BATCH_BYTES]);
        let (request, payload, count) =
            packet_payload(Request::new(()), &batch, &DataPlacement::Body).unwrap();
        assert_eq!(count, batch.len());
        assert!(request.headers().is_empty());
        assert_eq!(payload.as_ptr(), batch.as_ptr());
        drop(batch);
        assert_eq!(payload.len(), count);
        assert!(payload.iter().all(|byte| *byte == 7));
    }
}
