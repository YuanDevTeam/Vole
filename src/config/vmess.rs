use super::grpc::RawGrpc;
use super::{
    GrpcOptions, ProxyProtocol, deserialize_present_option, invalid, parse_standard_uuid,
    validate_host, validate_port,
};
use crate::Result;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Default)]
pub enum VmessPacketEncoding {
    #[default]
    #[serde(rename = "")]
    Raw,
    #[serde(rename = "xudp")]
    Xudp,
    #[serde(rename = "packetaddr")]
    PacketAddr,
}

#[derive(Clone, PartialEq, Eq)]
pub enum StreamTransport {
    Tcp,
    WebSocket {
        uri: String,
        headers: BTreeMap<String, String>,
        max_early_data: u16,
        early_data_header_name: String,
        handshake: super::WebSocketHandshake,
    },
    Grpc {
        uri: String,
        options: GrpcOptions,
    },
    Http {
        method: String,
        uris: Vec<String>,
        headers: BTreeMap<String, Vec<String>>,
    },
    H2 {
        uris: Vec<String>,
    },
}
impl std::fmt::Debug for StreamTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "Tcp",
            Self::WebSocket { .. } => "WebSocket",
            Self::Grpc { .. } => "Grpc",
            Self::Http { .. } => "Http",
            Self::H2 { .. } => "H2",
        })
    }
}
impl StreamTransport {
    pub fn required_alpn(&self) -> Option<&'static [u8]> {
        match self {
            Self::WebSocket { .. } => Some(b"http/1.1"),
            Self::Grpc { .. } | Self::H2 { .. } => Some(b"h2"),
            _ => None,
        }
    }
    #[cfg(feature = "stream-transport")]
    pub fn websocket_options(&self) -> std::io::Result<Option<crate::transport::WebSocketOptions>> {
        let Self::WebSocket {
            uri,
            headers,
            max_early_data,
            early_data_header_name,
            handshake,
        } = self
        else {
            return Ok(None);
        };
        super::trojan::websocket_options(
            uri,
            headers,
            *max_early_data,
            early_data_header_name,
            *handshake,
        )
        .map(Some)
    }
    #[cfg(feature = "stream-transport")]
    pub fn http_options(&self) -> std::io::Result<Option<crate::transport::HttpObfsOptions>> {
        let Self::Http {
            method,
            uris,
            headers,
        } = self
        else {
            return Ok(None);
        };
        let choose = |values: &[String]| values[rand::random_range(0..values.len())].clone();
        http_options(
            method,
            &choose(uris),
            headers.iter().map(|(key, values)| (key, choose(values))),
        )
        .map(Some)
    }
}

#[cfg(feature = "stream-transport")]
fn http_options<'a>(
    method: &str,
    uri: &str,
    headers: impl Iterator<Item = (&'a String, String)>,
) -> std::io::Result<crate::transport::HttpObfsOptions> {
    let error = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let mut map = http::HeaderMap::new();
    for (name, value) in headers {
        let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| error())?;
        if map
            .insert(name, value.parse().map_err(|_| error())?)
            .is_some()
        {
            return Err(error());
        }
    }
    crate::transport::HttpObfsOptions::new(method.parse().map_err(|_| error())?, uri, map)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawWs {
    #[serde(rename = "v2ray-http-upgrade", default)]
    pub(super) http_upgrade: bool,
    #[serde(rename = "v2ray-http-upgrade-fast-open", default)]
    pub(super) fast_open: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) headers: BTreeMap<String, String>,
    #[serde(rename = "max-early-data", default)]
    pub(super) max_early_data: u16,
    #[serde(
        rename = "early-data-header-name",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    pub(super) early_data_header_name: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHttp {
    #[serde(default, deserialize_with = "deserialize_present_option")]
    method: Option<String>,
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    headers: BTreeMap<String, Vec<String>>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawH2 {
    #[serde(default)]
    host: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    path: Option<String>,
}

fn uri(scheme: &str, authority: &str, path: &str) -> Result<String> {
    if !path.starts_with('/') || path.contains(['\r', '\n', '#']) {
        return invalid("invalid stream transport path");
    }
    let uri = http::Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|_| crate::VoleError::InvalidConfig("invalid stream transport URI".into()))?;
    if uri.to_string().len() > 16 * 1024 - 256 {
        return invalid("VMess transport URI exceeds limit");
    }
    Ok(uri.to_string())
}
fn authority_host(value: &str) -> Result<String> {
    let authority: http::uri::Authority = value
        .parse()
        .map_err(|_| crate::VoleError::InvalidConfig("invalid VMess Host".into()))?;
    let has_port = value.len() > authority.host().len();
    if value.contains('@') || (has_port && !authority.port_u16().is_some_and(|port| port > 0)) {
        return invalid("invalid VMess Host");
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    validate_host(host, "VMess Host")?;
    Ok(host.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Default)]
pub enum VmessCipher {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
    #[serde(rename = "none", alias = "zero")]
    None,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VmessOutboundConfig {
    pub address: String,
    pub port: u16,
    pub id: uuid::Uuid,
    pub cipher: VmessCipher,
    pub global_padding: bool,
    pub authenticated_length: bool,
    pub packet_encoding: VmessPacketEncoding,
    pub server_name: String,
    pub tls: Option<super::TlsClientPolicy>,
    pub transport: StreamTransport,
}
impl std::fmt::Debug for VmessOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessOutboundConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawVmess {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    #[serde(rename = "alterId", default)]
    alter_id: u16,
    #[serde(default)]
    cipher: VmessCipher,
    #[serde(default)]
    udp: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    network: Option<String>,
    #[serde(default)]
    tls: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    servername: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(
        rename = "skip-cert-verify",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    skip_cert_verify: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(
        rename = "name-cert-verify",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    name_cert_verify: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    certificate: Option<String>,
    #[serde(
        rename = "private-key",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    private_key: Option<String>,
    #[serde(
        rename = "client-fingerprint",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    client_fingerprint: Option<String>,
    #[serde(rename = "global-padding", default)]
    global_padding: bool,
    #[serde(rename = "authenticated-length", default)]
    authenticated_length: bool,
    #[serde(rename = "packet-encoding", default)]
    packet_encoding: VmessPacketEncoding,
    #[serde(
        rename = "ws-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    ws: Option<RawWs>,
    #[serde(
        rename = "grpc-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    grpc: Option<RawGrpc>,
    #[serde(
        rename = "http-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    http: Option<RawHttp>,
    #[serde(
        rename = "h2-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    h2: Option<RawH2>,
    #[serde(
        rename = "dialer-proxy",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    dialer_proxy: Option<String>,
}
impl std::fmt::Debug for RawVmess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawVmess").finish_non_exhaustive()
    }
}
impl RawVmess {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-vmess") {
            return invalid("VMess outbound support is disabled at build time");
        }
        validate_host(&self.server, "VMess server")?;
        validate_port(self.port, "VMess")?;
        if self.alter_id != 0 {
            return invalid("VMess requires AEAD alterId=0");
        }
        if self.cipher == VmessCipher::None && (self.global_padding || self.authenticated_length) {
            return invalid("VMess none cannot enable padding or authenticated length");
        }
        if !self.tls
            && (self.servername.is_some()
                || self.alpn.is_some()
                || self.skip_cert_verify.is_some()
                || self.fingerprint.is_some()
                || self.name_cert_verify.is_some()
                || self.certificate.is_some()
                || self.private_key.is_some()
                || self.client_fingerprint.is_some())
        {
            return invalid("VMess TLS options require tls=true");
        }
        let (transport, fallback_name) = normalize_transport(
            &self.server,
            self.port,
            self.tls,
            self.network
                .as_deref()
                .filter(|network| !network.is_empty())
                .unwrap_or("tcp"),
            self.ws,
            self.grpc,
            self.http,
            self.h2,
            self.servername.as_deref().filter(|name| !name.is_empty()),
        )?;
        let server_name = self
            .servername
            .filter(|name| !name.is_empty())
            .unwrap_or(fallback_name);
        validate_host(&server_name, "VMess servername")?;
        let tls = if self.tls {
            let alpn: Vec<Vec<u8>> = self
                .alpn
                .unwrap_or_else(|| {
                    transport
                        .required_alpn()
                        .map(|p| vec![String::from_utf8(p.to_vec()).unwrap()])
                        .unwrap_or_default()
                })
                .into_iter()
                .map(String::into_bytes)
                .collect();
            if alpn.iter().any(|p| p.is_empty() || p.len() > 255)
                || alpn.iter().map(|p| p.len() + 1).sum::<usize>() > 65533
                || transport
                    .required_alpn()
                    .is_some_and(|required| !alpn.iter().any(|p| p == required))
            {
                return invalid("invalid VMess ALPN");
            }
            let fingerprint =
                super::normalize_certificate_fingerprint(self.fingerprint.as_deref())?;
            Some(super::TlsClientPolicy {
                client_fingerprint: super::parse_client_fingerprint(
                    self.client_fingerprint.as_deref(),
                )?,
                alpn,
                certificate: super::TlsCertificatePolicy {
                    fingerprint,
                    skip_cert_verify: self.skip_cert_verify.unwrap_or(false),
                    verification_name: super::normalize_verification_name(self.name_cert_verify)?,
                },
                identity: super::normalize_client_identity(self.certificate, self.private_key)?,
            })
        } else {
            None
        };
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::Vmess(VmessOutboundConfig {
                address: self.server,
                port: self.port,
                id: parse_standard_uuid(&self.uuid)?,
                cipher: self.cipher,
                global_padding: self.global_padding,
                authenticated_length: self.authenticated_length,
                packet_encoding: self.packet_encoding,
                server_name,
                tls,
                transport,
            }),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn normalize_transport(
    server: &str,
    port: u16,
    tls: bool,
    network: &str,
    ws: Option<RawWs>,
    grpc: Option<RawGrpc>,
    http: Option<RawHttp>,
    h2: Option<RawH2>,
    grpc_authority: Option<&str>,
) -> Result<(StreamTransport, String)> {
    let authority = if server.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", server, port)
    } else {
        format!("{}:{}", server, port)
    };
    let scheme = if tls { "https" } else { "http" };
    let mut fallback_name = server.to_owned();
    let transport = match (network, ws, grpc, http, h2) {
        ("tcp", None, None, None, None) => StreamTransport::Tcp,
        ("ws", ws, None, None, None) => {
            let ws = ws.unwrap_or_default();
            if ws.max_early_data > 2048
                || (ws.max_early_data == 0 && ws.early_data_header_name.is_some())
            {
                return invalid("invalid VMess early-data options");
            }
            for (key, value) in &ws.headers {
                if key.eq_ignore_ascii_case("host") {
                    fallback_name = authority_host(value)?;
                }
            }
            let transport = StreamTransport::WebSocket {
                handshake: super::trojan::websocket_handshake(
                    ws.http_upgrade,
                    ws.fast_open,
                    ws.early_data_header_name.as_deref(),
                )?,
                uri: uri(
                    if tls { "wss" } else { "ws" },
                    &authority,
                    ws.path
                        .as_deref()
                        .filter(|path| !path.is_empty())
                        .unwrap_or("/"),
                )?,
                headers: ws.headers,
                max_early_data: ws.max_early_data,
                early_data_header_name: ws
                    .early_data_header_name
                    .unwrap_or_else(|| "Sec-WebSocket-Protocol".into()),
            };
            #[cfg(feature = "stream-transport")]
            if transport.websocket_options().is_err() {
                return invalid("invalid VMess WebSocket options");
            }
            transport
        }
        ("grpc", None, grpc, None, None) => {
            let (path, options) = grpc.unwrap_or_default().normalize()?;
            let grpc_authority = grpc_authority.map(|name| {
                if name.parse::<std::net::Ipv6Addr>().is_ok() {
                    format!("[{name}]")
                } else {
                    name.to_owned()
                }
            });
            StreamTransport::Grpc {
                uri: uri(
                    scheme,
                    grpc_authority.as_deref().unwrap_or(&authority),
                    &path,
                )?,
                options,
            }
        }
        ("http", None, None, http, None) => {
            let mut http = http.unwrap_or_default();
            if http.path.is_empty() {
                http.path.push("/".into());
            }
            let method = http
                .method
                .filter(|method| !method.is_empty())
                .unwrap_or_else(|| "GET".into());
            if method.parse::<http::Method>().is_err() || http.headers.values().any(Vec::is_empty) {
                return invalid("invalid HTTP transport options");
            }
            for (key, values) in &http.headers {
                let name: http::HeaderName = key.parse().map_err(|_| {
                    crate::VoleError::InvalidConfig("invalid HTTP transport header".into())
                })?;
                for value in values {
                    if value.parse::<http::HeaderValue>().is_err() {
                        return invalid("invalid HTTP transport value");
                    }
                    if name == "host" {
                        authority_host(value)?;
                    }
                }
            }
            let uris = http
                .path
                .iter()
                .map(|path| {
                    if (!path.is_empty() && !path.starts_with('/')) || path.contains(['\r', '\n']) {
                        return invalid("invalid HTTP transport path");
                    }
                    let mut url =
                        url::Url::parse(&format!("{scheme}://{authority}/")).map_err(|_| {
                            crate::VoleError::InvalidConfig("invalid HTTP transport URI".into())
                        })?;
                    url.set_path(path);
                    Ok(url.to_string())
                })
                .collect::<Result<Vec<_>>>()?;
            #[cfg(feature = "stream-transport")]
            for uri in &uris {
                if http_options(
                    &method,
                    uri,
                    http.headers.iter().map(|(key, values)| {
                        (key, values.iter().max_by_key(|v| v.len()).unwrap().clone())
                    }),
                )
                .is_err()
                {
                    return invalid("invalid HTTP transport options");
                }
            }
            StreamTransport::Http {
                method,
                uris,
                headers: http.headers,
            }
        }
        ("h2", None, None, None, h2) => {
            let mut h2 = h2.unwrap_or_default();
            if h2.host.is_empty() {
                h2.host.push("www.example.com".into());
            }
            let mut uris = Vec::new();
            for host in h2.host {
                authority_host(&host)?;
                uris.push(uri(
                    scheme,
                    &host,
                    h2.path
                        .as_deref()
                        .filter(|path| !path.is_empty())
                        .unwrap_or("/"),
                )?);
            }
            StreamTransport::H2 { uris }
        }
        _ => return invalid("stream transport options do not match network"),
    };
    Ok((transport, fallback_name))
}
