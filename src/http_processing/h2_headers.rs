//! Shared bounded HTTP/2 header validation and HTTP/1 hop-field conversion.
use http::{HeaderMap, HeaderName, Method, StatusCode};
use std::{collections::HashSet, io};
const MAX_BYTES: usize = 32 * 1024;
const MAX_FIELDS: usize = 100;
pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP headers")
}
pub(super) fn check(headers: &HeaderMap) -> io::Result<()> {
    if headers.len() > MAX_FIELDS {
        return Err(invalid());
    }
    let mut total = 0usize;
    for (name, value) in headers {
        total = total
            .checked_add(name.as_str().len() + value.as_bytes().len() + 32)
            .filter(|size| *size <= MAX_BYTES)
            .ok_or_else(invalid)?;
    }
    Ok(())
}
pub(super) fn request(headers: &HeaderMap) -> io::Result<Option<u64>> {
    check(headers)?;
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ] {
        if headers.contains_key(name) {
            return Err(invalid());
        }
    }
    for value in headers.get_all("te") {
        if !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
            return Err(invalid());
        }
    }
    let mut expect = headers.get_all("expect").iter();
    if let Some(value) = expect.next()
        && (!value.as_bytes().eq_ignore_ascii_case(b"100-continue") || expect.next().is_some())
    {
        return Err(invalid());
    }
    length(headers)
}
pub(super) fn length(headers: &HeaderMap) -> io::Result<Option<u64>> {
    let mut values = headers.get_all("content-length").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some()
        || value.is_empty()
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(invalid());
    }
    let text = value.to_str().map_err(|_| invalid())?;
    Ok(Some(text.parse().map_err(|_| invalid())?))
}
pub(super) fn response_body(
    headers: &HeaderMap,
    status: StatusCode,
    method: &Method,
) -> io::Result<Option<u64>> {
    check(headers)?;
    let length = length(headers)?;
    if (status.is_informational() || status == StatusCode::NO_CONTENT) && length.is_some() {
        return Err(invalid());
    }
    if method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        Ok(Some(0))
    } else {
        Ok(length)
    }
}
pub(super) fn clean(
    mut headers: HeaderMap,
    strip_origin_credentials: bool,
    request: bool,
) -> io::Result<HeaderMap> {
    check(&headers)?;
    let mut connection = HashSet::new();
    for value in headers.get_all("connection") {
        for token in value.to_str().map_err(|_| invalid())?.split(',') {
            let token = HeaderName::from_bytes(token.trim().as_bytes()).map_err(|_| invalid())?;
            connection.insert(token);
        }
    }
    for name in connection {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "transfer-encoding",
        "trailer",
        "upgrade",
        "host",
    ] {
        headers.remove(name);
    }
    if !request {
        headers.remove("te");
    }
    if strip_origin_credentials {
        headers.remove("authorization");
        headers.remove("cookie");
    }
    let internal = headers
        .keys()
        .filter(|name| name.as_str().starts_with("x-vole-"))
        .cloned()
        .collect::<Vec<_>>();
    for name in internal {
        headers.remove(name);
    }
    Ok(headers)
}
pub(super) fn trailers(
    headers: HeaderMap,
    strip_origin_credentials: bool,
) -> io::Result<HeaderMap> {
    check(&headers)?;
    if headers.keys().any(|name| {
        matches!(
            name.as_str(),
            "authorization"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "trailer"
                | "expect"
                | "content-type"
                | "content-encoding"
                | "content-range"
        ) || name.as_str().starts_with("x-vole-")
    }) {
        return Err(invalid());
    }
    if strip_origin_credentials && headers.contains_key("cookie") {
        return Err(invalid());
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn h2_headers_and_trailers_are_bounded_before_conversion() {
        let mut headers = HeaderMap::new();
        for _ in 0..101 {
            headers.append("x-test", "a".parse().unwrap());
        }
        assert!(request(&headers).is_err());
        headers.clear();
        headers.insert(
            "x-test",
            http::HeaderValue::from_bytes(&vec![b'x'; 32 * 1024]).unwrap(),
        );
        assert!(check(&headers).is_err());
        headers.clear();
        headers.insert("content-length", "2".parse().unwrap());
        headers.append("content-length", "2".parse().unwrap());
        assert!(request(&headers).is_err());
        headers.clear();
        headers.insert("cookie", "secret".parse().unwrap());
        assert!(trailers(headers, true).is_err());
    }
}
