//! Validated, bounded XHTTP request options shared by configuration and transport.
use std::collections::BTreeMap;

use http::{HeaderMap, HeaderName, HeaderValue};

use super::{Result, invalid};

pub const MAX_CUSTOM_HEADER_BYTES: usize = crate::limits::XHTTP_CUSTOM_HEADER_BYTES;
pub const MAX_CUSTOM_HEADERS: usize = crate::limits::XHTTP_CUSTOM_HEADERS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum XHttpVersion {
    Http1,
    #[default]
    Http2,
    Http3,
}

impl XHttpVersion {
    pub(crate) fn from_alpn(protocols: &[String]) -> Result<Self> {
        if protocols == ["h3"] {
            return Ok(Self::Http3);
        }
        if protocols
            .iter()
            .any(|p| !matches!(p.as_str(), "http/1.1" | "h2"))
        {
            return invalid("XHTTP ALPN must select a supported HTTP version");
        }
        Ok(if protocols == ["http/1.1"] {
            Self::Http1
        } else {
            Self::Http2
        })
    }
    pub(crate) fn alpn(self) -> &'static [u8] {
        match self {
            Self::Http1 => b"http/1.1",
            Self::Http2 => b"h2",
            Self::Http3 => b"h3",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XHttpRequestOptions {
    pub no_grpc_header: bool,
    pub(crate) padding: XHttpPadding,
    pub(crate) uplink_method: http::Method,
    pub(crate) session: MetaPlacement,
    pub(crate) sequence: MetaPlacement,
    pub(crate) session_id: SessionId,
    pub(crate) data: DataPlacement,
    pub(crate) post_bytes: IntegerRange,
    pub(crate) post_interval_ms: IntegerRange,
}

impl Default for XHttpRequestOptions {
    fn default() -> Self {
        Self {
            no_grpc_header: false,
            padding: Default::default(),
            uplink_method: http::Method::POST,
            session: MetaPlacement::Path,
            sequence: MetaPlacement::Path,
            session_id: SessionId::Hex,
            data: DataPlacement::Body,
            post_bytes: IntegerRange {
                min: 1_000_000,
                max: 1_000_000,
            },
            post_interval_ms: IntegerRange { min: 10, max: 10 },
        }
    }
}

impl XHttpRequestOptions {
    pub(super) fn normalize(
        raw: &super::RawXHttpSettings,
        headers: &XHttpHeaders,
        mode: super::XHttpMode,
    ) -> Result<Self> {
        if mode == super::XHttpMode::PacketUp && raw.no_grpc_header {
            return invalid("xhttp-opts.no-grpc-header is only effective for streaming modes");
        }
        if mode != super::XHttpMode::PacketUp
            && !raw.no_grpc_header
            && headers.as_map().contains_key(http::header::CONTENT_TYPE)
        {
            return invalid("XHTTP generated content type conflicts with custom headers");
        }
        if mode != super::XHttpMode::PacketUp
            && (nonempty(raw.seq_key.as_deref()).is_some()
                || nonempty(raw.seq_placement.as_deref()).is_some())
        {
            return invalid("XHTTP sequence overrides require packet-up");
        }
        let data = DataPlacement::normalize(raw)?;
        if mode != super::XHttpMode::PacketUp
            && (data != DataPlacement::Body
                || range_value(raw.sc_max_each_post_bytes.as_deref()).is_some()
                || range_value(raw.sc_min_posts_interval_ms.as_deref()).is_some())
        {
            return invalid("XHTTP packet upload fields require packet-up");
        }
        let post_bytes = IntegerRange::parse_with_default(
            raw.sc_max_each_post_bytes.as_deref(),
            "1000000",
            1,
            crate::limits::XHTTP_POST_BYTES,
        )?;
        let post_interval_ms = IntegerRange::parse_with_default(
            raw.sc_min_posts_interval_ms.as_deref(),
            "10",
            0,
            60_000,
        )?;
        if post_interval_ms.max == 0 {
            return invalid("XHTTP post interval must have a positive maximum");
        }
        let uplink_method = nonempty(raw.uplink_http_method.as_deref())
            .unwrap_or("POST")
            .parse::<http::Method>()
            .map_err(|_| crate::VoleError::InvalidConfig("invalid XHTTP uplink method".into()))?;
        if matches!(uplink_method, http::Method::GET | http::Method::OPTIONS) {
            return invalid("XHTTP download and preflight methods cannot carry upload data");
        }
        let options = Self {
            no_grpc_header: raw.no_grpc_header,
            padding: XHttpPadding::normalize(raw, headers)?,
            uplink_method,
            session: MetaPlacement::normalize(
                raw.session_placement.as_deref(),
                raw.session_key.as_deref(),
                "X-Session",
                "x_session",
            )?,
            sequence: MetaPlacement::normalize(
                raw.seq_placement.as_deref(),
                raw.seq_key.as_deref(),
                "X-Seq",
                "x_seq",
            )?,
            session_id: SessionId::normalize(
                raw.session_table.as_deref().unwrap_or(""),
                raw.session_length.as_deref(),
            )?,
            data,
            post_bytes,
            post_interval_ms,
        };
        options.validate_headers(headers, &raw.path)?;
        Ok(options)
    }

    pub(super) fn validate_headers(&self, headers: &XHttpHeaders, path: &str) -> Result<()> {
        let padding_conflict = match self.padding.placement {
            PaddingPlacement::Header | PaddingPlacement::QueryInHeader => {
                headers.as_map().contains_key(&self.padding.header)
            }
            PaddingPlacement::Cookie => headers.as_map().contains_key(http::header::COOKIE),
            PaddingPlacement::Query => path.split_once('?').is_some_and(|(_, q)| {
                url::form_urlencoded::parse(q.as_bytes()).any(|(key, _)| key == self.padding.key)
            }),
        };
        if padding_conflict {
            return invalid("XHTTP padding conflicts with configured headers or query");
        }
        if self.session != MetaPlacement::Path && self.session == self.sequence {
            return invalid("XHTTP session and sequence keys must not collide");
        }
        for meta in [&self.session, &self.sequence] {
            let padding_conflict = match meta {
                MetaPlacement::Header(name) => {
                    if headers.as_map().contains_key(name) {
                        return invalid("XHTTP metadata conflicts with custom headers");
                    }
                    matches!(
                        self.padding.placement,
                        PaddingPlacement::Header | PaddingPlacement::QueryInHeader
                    ) && self.padding.header == *name
                }
                MetaPlacement::Query(key) => {
                    if path.split_once('?').is_some_and(|(_, q)| {
                        url::form_urlencoded::parse(q.as_bytes()).any(|(k, _)| k == key.as_str())
                    }) {
                        return invalid("XHTTP metadata conflicts with the configured query");
                    }
                    self.padding.placement == PaddingPlacement::Query && self.padding.key == *key
                }
                MetaPlacement::Cookie(key) => {
                    if headers.as_map().contains_key(http::header::COOKIE) {
                        return invalid(
                            "XHTTP cookie metadata conflicts with a custom Cookie header",
                        );
                    }
                    self.padding.placement == PaddingPlacement::Cookie && self.padding.key == *key
                }
                MetaPlacement::Path => false,
            };
            if padding_conflict {
                return invalid("XHTTP metadata conflicts with padding");
            }
        }
        if let DataPlacement::Chunks { key, cookie, .. } = &self.data {
            let prefix = format!("{key}{}", if *cookie { '_' } else { '-' });
            for meta in [&self.session, &self.sequence] {
                let collides = match meta {
                    MetaPlacement::Header(name) if !cookie => {
                        name.as_str().starts_with(&prefix.to_ascii_lowercase())
                    }
                    MetaPlacement::Cookie(name) if *cookie => name.starts_with(&prefix),
                    _ => false,
                };
                if collides {
                    return invalid("XHTTP payload key conflicts with metadata");
                }
            }
            if *cookie && headers.as_map().contains_key(http::header::COOKIE)
                || !cookie
                    && headers
                        .as_map()
                        .keys()
                        .any(|name| name.as_str().starts_with(&prefix.to_ascii_lowercase()))
                || *cookie
                    && self.padding.placement == PaddingPlacement::Cookie
                    && self.padding.key.starts_with(&prefix)
                || !cookie
                    && matches!(
                        self.padding.placement,
                        PaddingPlacement::Header | PaddingPlacement::QueryInHeader
                    )
                    && self
                        .padding
                        .header
                        .as_str()
                        .starts_with(&prefix.to_ascii_lowercase())
            {
                return invalid("XHTTP payload key conflicts with request headers or padding");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DataPlacement {
    Body,
    Chunks {
        key: String,
        cookie: bool,
        size: IntegerRange,
    },
}

impl DataPlacement {
    fn normalize(raw: &super::RawXHttpSettings) -> Result<Self> {
        let placement = nonempty(raw.uplink_data_placement.as_deref()).unwrap_or("body");
        if matches!(placement, "body" | "auto") {
            if nonempty(raw.uplink_data_key.as_deref()).is_some()
                || range_value(raw.uplink_chunk_size.as_deref()).is_some()
            {
                return invalid(
                    "XHTTP body upload does not use payload keys or header chunk sizes",
                );
            }
            return Ok(Self::Body);
        }
        if !matches!(placement, "header" | "cookie") {
            return invalid("unsupported XHTTP payload placement");
        }
        let Some(key) = &raw.uplink_data_key else {
            return invalid("XHTTP header/cookie upload requires a payload key");
        };
        validate_key(key)?;
        let mut size =
            IntegerRange::parse_with_default(raw.uplink_chunk_size.as_deref(), "0", 0, 8192)?;
        if size.max == 0 {
            size = if placement == "cookie" {
                IntegerRange {
                    min: 2048,
                    max: 3072,
                }
            } else {
                IntegerRange {
                    min: 3072,
                    max: 4096,
                }
            };
        }
        size.min = size.min.max(64);
        size.max = size.max.max(size.min);
        Ok(Self::Chunks {
            key: key.clone(),
            cookie: placement == "cookie",
            size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MetaPlacement {
    Path,
    Query(String),
    Header(HeaderName),
    Cookie(String),
}

impl MetaPlacement {
    fn normalize(
        placement: Option<&str>,
        key: Option<&str>,
        header_default: &str,
        other_default: &str,
    ) -> Result<Self> {
        let placement = nonempty(placement);
        let key = nonempty(key);
        match placement.unwrap_or("path") {
            "path" if key.is_none() => Ok(Self::Path),
            "query" | "cookie" => {
                let key = key.unwrap_or(other_default);
                validate_key(key)?;
                Ok(if placement == Some("query") {
                    Self::Query(key.into())
                } else {
                    Self::Cookie(key.into())
                })
            }
            "header" => {
                let key = key.unwrap_or(header_default);
                validate_key(key)?;
                let Ok(key) = key.parse::<HeaderName>() else {
                    return invalid("invalid XHTTP metadata header");
                };
                if reserved_header(&key) || key == http::header::COOKIE {
                    return invalid("reserved XHTTP metadata header");
                }
                Ok(Self::Header(key))
            }
            _ => invalid("invalid XHTTP metadata placement or unused key"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SessionId {
    Hex,
    Uuid,
    Alphabet {
        bytes: Vec<u8>,
        length: IntegerRange,
    },
}

impl SessionId {
    fn normalize(table: &str, length: Option<&str>) -> Result<Self> {
        let length = range_value(length);
        if table.is_empty() || table == "uuid" {
            if length.is_some() {
                return invalid("XHTTP session-length requires a character table");
            }
            return Ok(if table.is_empty() {
                Self::Hex
            } else {
                Self::Uuid
            });
        }
        let table = match table {
            "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "HEX" => "0123456789ABCDEF",
            "alphabet" => "abcdefghijklmnopqrstuvwxyz",
            "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
            "hex" => "0123456789abcdef",
            "number" => "0123456789",
            other => other,
        };
        validate_key(table)?;
        let mut bytes = Vec::new();
        for byte in table.bytes() {
            if !bytes.contains(&byte) {
                bytes.push(byte);
            }
        }
        let length = IntegerRange::parse_with_default(length, "16-32", 1, 128)?;
        let mut possibilities = 0u64;
        for n in length.min..=length.max {
            possibilities =
                possibilities.saturating_add((bytes.len() as u64).saturating_pow(n as u32));
        }
        if possibilities < 1 << 31 {
            return invalid("XHTTP session ID namespace must contain at least 2^31 values");
        }
        Ok(Self::Alphabet { bytes, length })
    }

    pub(crate) fn generate(&self) -> String {
        use rand::RngExt as _;
        match self {
            Self::Hex => uuid::Uuid::from_bytes(rand::random()).simple().to_string(),
            Self::Uuid => {
                let mut bytes: [u8; 16] = rand::random();
                bytes[6] = (bytes[6] & 15) | 64;
                bytes[8] = (bytes[8] & 63) | 128;
                uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
            }
            Self::Alphabet { bytes, length } => {
                let mut rng = rand::rng();
                (0..length.sample())
                    .map(|_| char::from(bytes[rng.random_range(0..bytes.len())]))
                    .collect()
            }
        }
    }
}

pub const MAX_PADDING_BYTES: usize = crate::limits::XHTTP_PADDING_BYTES;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IntegerRange {
    pub min: usize,
    pub max: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XHttpReuseConfig {
    pub(crate) concurrency: IntegerRange,
    pub(crate) connections: IntegerRange,
    pub(crate) reuse_times: IntegerRange,
    pub(crate) requests: IntegerRange,
    pub(crate) age_seconds: IntegerRange,
    pub(crate) keep_alive_seconds: i32,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawReuseConfig {
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    max_concurrency: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    max_connections: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    c_max_reuse_times: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    h_max_request_times: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_present_option")]
    h_max_reusable_secs: Option<String>,
    #[serde(default)]
    h_keep_alive_period: i32,
}

impl RawReuseConfig {
    pub(super) fn normalize(self, version: XHttpVersion) -> Result<XHttpReuseConfig> {
        let range = |value: Option<String>| {
            IntegerRange::parse_with_default(value.as_deref(), "0", 0, i32::MAX as usize)
        };
        if version == XHttpVersion::Http1 && self.h_keep_alive_period != 0 {
            return invalid("XHTTP HTTP/1 does not support a keepalive period override");
        }
        Ok(XHttpReuseConfig {
            concurrency: range(self.max_concurrency)?,
            connections: range(self.max_connections)?,
            reuse_times: range(self.c_max_reuse_times)?,
            requests: range(self.h_max_request_times)?,
            age_seconds: range(self.h_max_reusable_secs)?,
            keep_alive_seconds: self.h_keep_alive_period,
        })
    }
}

impl IntegerRange {
    fn parse_with_default(
        value: Option<&str>,
        fallback: &str,
        minimum: usize,
        maximum: usize,
    ) -> Result<Self> {
        Self::parse(range_value(value).unwrap_or(fallback), minimum, maximum)
    }

    pub(super) fn parse(value: &str, minimum: usize, maximum: usize) -> Result<Self> {
        let value = value.trim();
        let (left, right) = value.split_once('-').unwrap_or((value, value));
        let (left, right) = (left.trim(), right.trim());
        if [left, right].iter().any(|part| {
            let decimal = part.strip_prefix('+').unwrap_or(part);
            decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit())
        }) {
            return invalid("XHTTP range must be decimal N or N-M");
        }
        let (Ok(min), Ok(max)) = (left.parse::<usize>(), right.parse::<usize>()) else {
            return invalid("XHTTP range exceeds its numeric limit");
        };
        if min < minimum || max < min || max > maximum {
            return invalid("XHTTP range is outside its field bounds");
        }
        Ok(Self { min, max })
    }
    pub(crate) fn sample(self) -> usize {
        use rand::RngExt as _;
        rand::rng().random_range(self.min..=self.max)
    }
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn range_value(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaddingPlacement {
    QueryInHeader,
    Header,
    Query,
    Cookie,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XHttpPadding {
    pub bytes: IntegerRange,
    pub placement: PaddingPlacement,
    pub key: String,
    pub header: HeaderName,
    pub tokenish: bool,
}

impl Default for XHttpPadding {
    fn default() -> Self {
        Self {
            bytes: IntegerRange {
                min: 100,
                max: 1000,
            },
            placement: PaddingPlacement::QueryInHeader,
            key: "x_padding".into(),
            header: http::header::REFERER,
            tokenish: false,
        }
    }
}

impl XHttpPadding {
    pub(super) fn normalize(raw: &super::RawXHttpSettings, headers: &XHttpHeaders) -> Result<Self> {
        let mut padding = Self {
            bytes: IntegerRange::parse_with_default(
                raw.x_padding_bytes.as_deref(),
                "100-1000",
                1,
                MAX_PADDING_BYTES,
            )?,
            ..Self::default()
        };
        if !raw.x_padding_obfs_mode {
            if nonempty(raw.x_padding_key.as_deref()).is_some_and(|value| value != "x_padding")
                || nonempty(raw.x_padding_header.as_deref())
                    .is_some_and(|value| !value.eq_ignore_ascii_case("referer"))
                || nonempty(raw.x_padding_placement.as_deref())
                    .is_some_and(|value| value != "queryInHeader")
                || nonempty(raw.x_padding_method.as_deref())
                    .is_some_and(|value| value != "repeat-x")
            {
                return invalid(
                    "XHTTP non-obfuscated padding requires its default placement and method",
                );
            }
            return Ok(padding);
        }
        padding.placement = match raw.x_padding_placement.as_deref() {
            Some("queryInHeader") => PaddingPlacement::QueryInHeader,
            Some("header") => PaddingPlacement::Header,
            Some("query") => PaddingPlacement::Query,
            Some("cookie") => PaddingPlacement::Cookie,
            _ => return invalid("XHTTP obfuscated padding requires a supported placement"),
        };
        padding.tokenish = match nonempty(raw.x_padding_method.as_deref()).unwrap_or("repeat-x") {
            "repeat-x" => false,
            "tokenish" => true,
            _ => return invalid("unsupported XHTTP padding method"),
        };
        if padding.placement == PaddingPlacement::Header {
            if raw.x_padding_key.is_some() {
                return invalid("XHTTP header padding does not use a key");
            }
        } else {
            let Some(key) = &raw.x_padding_key else {
                return invalid("XHTTP padding requires a key");
            };
            validate_key(key)?;
            padding.key = key.clone();
        }
        if matches!(
            padding.placement,
            PaddingPlacement::Header | PaddingPlacement::QueryInHeader
        ) {
            let Some(header) = &raw.x_padding_header else {
                return invalid("XHTTP padding requires a header name");
            };
            let Ok(header) = header.parse::<HeaderName>() else {
                return invalid("invalid XHTTP padding header name");
            };
            if reserved_header(&header) && header != http::header::REFERER
                || header == http::header::COOKIE
                || headers.as_map().contains_key(&header)
            {
                return invalid("XHTTP padding header conflicts with another request field");
            }
            padding.header = header;
        } else if raw.x_padding_header.is_some() {
            return invalid("XHTTP padding placement does not use a header name");
        }
        Ok(padding)
    }
}

pub(super) fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
    {
        return invalid("XHTTP placement key must be a bounded HTTP-safe token");
    }
    Ok(())
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct XHttpHeaders(HeaderMap);

impl std::fmt::Debug for XHttpHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XHttpHeaders")
            .field("count", &self.0.len())
            .finish()
    }
}

impl XHttpHeaders {
    pub fn as_map(&self) -> &HeaderMap {
        &self.0
    }

    pub(super) fn normalize(raw: BTreeMap<String, String>) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let mut bytes = 0usize;
        for (name, value) in raw {
            let (Ok(name), Ok(mut value)) =
                (name.parse::<HeaderName>(), value.parse::<HeaderValue>())
            else {
                return invalid("invalid XHTTP request header");
            };
            if headers.contains_key(&name)
                || reserved_header(&name)
                    && name != http::header::CONTENT_TYPE
                    && name != http::header::REFERER
            {
                return invalid("duplicate or reserved XHTTP request header");
            }
            bytes += name.as_str().len() + value.len() + 4;
            if bytes > MAX_CUSTOM_HEADER_BYTES || headers.len() >= MAX_CUSTOM_HEADERS {
                return invalid("XHTTP custom headers exceed their byte or field limit");
            }
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        Ok(Self(headers))
    }
}

pub(super) fn reserved_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "upgrade"
            | "trailer"
            | "te"
            | "keep-alive"
            | "proxy-connection"
            | "content-type"
            | "referer"
    )
}

#[cfg(test)]
mod request_compatibility_tests {
    use super::*;

    #[test]
    fn custom_upload_method_and_small_chunks_keep_bounded_request_options() {
        let raw = serde_json::from_value(serde_json::json!({
            "uplink-http-method":"PROPFIND",
            "uplink-data-placement":"header",
            "uplink-data-key":"X-Payload",
            "uplink-chunk-size":1
        }))
        .unwrap();
        let options = XHttpRequestOptions::normalize(
            &raw,
            &XHttpHeaders::default(),
            super::super::XHttpMode::PacketUp,
        )
        .unwrap();
        assert_eq!(options.uplink_method.as_str(), "PROPFIND");
        let DataPlacement::Chunks { size, .. } = options.data else {
            panic!("chunks")
        };
        assert_eq!((size.min, size.max), (64, 64));
    }
}
