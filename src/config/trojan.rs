use super::grpc::RawGrpc;
use serde::Deserialize;
use std::collections::BTreeMap;

use super::{
    GrpcOptions, ProxyProtocol, deserialize_present_option, invalid, validate_host, validate_port,
};
use crate::Result;

#[derive(Clone, PartialEq, Eq)]
pub struct TrojanOutboundConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub server_name: String,
    pub security: super::SecurityConfig,
    pub transport: TrojanTransport,
}

#[derive(Clone, PartialEq, Eq)]
pub enum TrojanTransport {
    Tcp,
    WebSocket {
        uri: String,
        headers: BTreeMap<String, String>,
        max_early_data: u16,
        early_data_header_name: String,
        handshake: WebSocketHandshake,
    },
    Grpc {
        uri: String,
        options: GrpcOptions,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WebSocketHandshake {
    #[default]
    WebSocket,
    HttpUpgrade {
        fast_open: bool,
    },
}

pub(super) fn websocket_handshake(
    upgrade: bool,
    fast_open: bool,
    early_header: Option<&str>,
) -> Result<WebSocketHandshake> {
    if (fast_open && !upgrade)
        || (upgrade
            && early_header
                .is_some_and(|name| !name.eq_ignore_ascii_case("Sec-WebSocket-Protocol")))
    {
        return invalid("invalid HTTPUpgrade options");
    }
    Ok(if upgrade {
        WebSocketHandshake::HttpUpgrade { fast_open }
    } else {
        WebSocketHandshake::WebSocket
    })
}

impl std::fmt::Debug for TrojanTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "Tcp",
            Self::WebSocket { .. } => "WebSocket",
            Self::Grpc { .. } => "Grpc",
        })
    }
}

impl TrojanTransport {
    pub fn required_alpn(&self) -> Option<&'static [u8]> {
        match self {
            Self::Tcp => None,
            Self::WebSocket { .. } => Some(b"http/1.1"),
            Self::Grpc { .. } => Some(b"h2"),
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
        websocket_options(
            uri,
            headers,
            *max_early_data,
            early_data_header_name,
            *handshake,
        )
        .map(Some)
    }
}

#[cfg(feature = "stream-transport")]
pub(super) fn websocket_options(
    uri: &str,
    headers: &BTreeMap<String, String>,
    max_early_data: u16,
    early_data_header_name: &str,
    handshake: WebSocketHandshake,
) -> std::io::Result<crate::transport::WebSocketOptions> {
    use crate::transport::{WebSocketEarlyData, WebSocketOptions};
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid WebSocket options",
        )
    };
    let mut map = http::HeaderMap::new();
    for (name, value) in headers {
        let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
        if map
            .insert(name, value.parse().map_err(|_| invalid())?)
            .is_some()
        {
            return Err(invalid());
        }
    }
    let early = if max_early_data == 0 {
        None
    } else if early_data_header_name.is_empty() {
        Some(WebSocketEarlyData::Path {
            max_bytes: usize::from(max_early_data),
        })
    } else {
        Some(WebSocketEarlyData::Header {
            name: early_data_header_name.parse().map_err(|_| invalid())?,
            max_bytes: usize::from(max_early_data),
        })
    };
    let options = WebSocketOptions::new(uri, map, early)?;
    match handshake {
        WebSocketHandshake::WebSocket => Ok(options),
        WebSocketHandshake::HttpUpgrade { fast_open } => options.with_http_upgrade(fast_open),
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWebSocket {
    #[serde(rename = "v2ray-http-upgrade", default)]
    http_upgrade: bool,
    #[serde(rename = "v2ray-http-upgrade-fast-open", default)]
    fast_open: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    path: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(rename = "max-early-data", default)]
    max_early_data: u16,
    #[serde(
        rename = "early-data-header-name",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    early_data_header_name: Option<String>,
}

fn uri(scheme: &str, server: &str, path: &str) -> Result<String> {
    if !path.starts_with('/') || path.contains(['\r', '\n', '#']) {
        return invalid("invalid Trojan transport path");
    }
    let authority = if server.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{server}]")
    } else {
        server.to_owned()
    };
    let uri = http::Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|_| crate::VoleError::InvalidConfig("invalid Trojan transport URI".into()))?;
    // Same bounded HTTP head envelope as the shared stream adapters.
    if uri.to_string().len() > 16 * 1024 - 256 {
        return invalid("Trojan transport URI exceeds HTTP head limit");
    }
    Ok(uri.to_string())
}

impl std::fmt::Debug for TrojanOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanOutboundConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTrojan {
    name: String,
    server: String,
    port: u16,
    password: String,
    #[serde(default)]
    udp: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    network: Option<String>,
    #[serde(
        rename = "ws-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    ws: Option<RawWebSocket>,
    #[serde(
        rename = "grpc-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    grpc: Option<RawGrpc>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sni: Option<String>,
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
    #[serde(
        rename = "ech-opts",
        default,
        deserialize_with = "super::ech::deserialize"
    )]
    ech_opts: Option<super::ech::RawEch>,
    #[serde(
        rename = "shadow-tls-opts",
        default,
        deserialize_with = "super::security::deserialize_shadow_tls"
    )]
    shadow_tls_opts: Option<super::security::RawShadowTlsMode>,
    #[serde(
        rename = "jls-opts",
        default,
        deserialize_with = "super::jls::deserialize"
    )]
    jls_opts: Option<super::jls::RawJls>,
    #[serde(
        rename = "reality-opts",
        default,
        deserialize_with = "super::deserialize_present_map"
    )]
    reality_opts: Option<super::RawRealitySettings>,
    #[serde(
        rename = "dialer-proxy",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    dialer_proxy: Option<String>,
}

impl std::fmt::Debug for RawTrojan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTrojan").finish_non_exhaustive()
    }
}

impl RawTrojan {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-trojan") {
            return invalid("Trojan outbound support is disabled at build time");
        }
        validate_host(&self.server, "Trojan server")?;
        validate_port(self.port, "Trojan")?;
        if self.password.is_empty() {
            return invalid("Trojan password must not be empty");
        }
        let server_name = self
            .sni
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| self.server.clone());
        validate_host(&server_name, "Trojan sni")?;
        let transport = match (
            self.network
                .as_deref()
                .filter(|network| !network.is_empty())
                .unwrap_or("tcp"),
            self.ws,
            self.grpc,
        ) {
            ("tcp", None, None) => TrojanTransport::Tcp,
            ("ws", ws, None) => {
                let ws = ws.unwrap_or_default();
                if ws.max_early_data > 2048
                    || (ws.max_early_data == 0 && ws.early_data_header_name.is_some())
                {
                    return invalid("invalid Trojan WebSocket early-data options");
                }
                let transport = TrojanTransport::WebSocket {
                    handshake: websocket_handshake(
                        ws.http_upgrade,
                        ws.fast_open,
                        ws.early_data_header_name.as_deref(),
                    )?,
                    uri: uri(
                        "wss",
                        &server_name,
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
                    return invalid("invalid Trojan WebSocket options");
                }
                transport
            }
            ("grpc", None, grpc) => {
                let (path, options) = grpc.unwrap_or_default().normalize()?;
                TrojanTransport::Grpc {
                    uri: uri("https", &server_name, &path)?,
                    options,
                }
            }
            _ => return invalid("Trojan requires tcp, ws with ws-opts, or grpc with grpc-opts"),
        };
        let alpn: Vec<Vec<u8>> = self
            .alpn
            .unwrap_or_else(|| {
                transport
                    .required_alpn()
                    .map(|value| vec![String::from_utf8(value.to_vec()).unwrap()])
                    .unwrap_or_default()
            })
            .into_iter()
            .map(String::into_bytes)
            .collect();
        if alpn
            .iter()
            .any(|value| value.is_empty() || value.len() > 255)
            || alpn.iter().map(|value| value.len() + 1).sum::<usize>() > 65_533
        {
            return invalid("invalid Trojan ALPN list");
        }
        if transport
            .required_alpn()
            .is_some_and(|required| !alpn.iter().any(|value| value == required))
        {
            return invalid("Trojan ALPN does not include the selected transport");
        }
        let certificate_options = self.skip_cert_verify.is_some()
            || self.fingerprint.is_some()
            || self.name_cert_verify.is_some()
            || self.certificate.is_some()
            || self.private_key.is_some();
        let fingerprint = super::normalize_certificate_fingerprint(self.fingerprint.as_deref())?;
        let client_fingerprint =
            super::parse_client_fingerprint(self.client_fingerprint.as_deref())?;
        let ech = self
            .ech_opts
            .map(|raw| raw.normalize(client_fingerprint.is_some()))
            .transpose()?
            .flatten();
        if ech.is_some() && server_name.parse::<std::net::IpAddr>().is_ok() {
            return invalid("Trojan ECH requires DNS sni");
        }
        if self.reality_opts.is_some() && matches!(transport, TrojanTransport::WebSocket { .. }) {
            return invalid("Trojan REALITY requires a stream TLS transport");
        }
        if self.reality_opts.is_some() && client_fingerprint.is_none() {
            return invalid("Trojan REALITY requires a named client-fingerprint");
        }
        let security = super::security::RawSecurityModes {
            reality: self.reality_opts,
            jls: self.jls_opts,
            shadow_tls: self.shadow_tls_opts,
        }
        .normalize(
            super::TlsConfig {
                server_name: server_name.clone(),
                required_alpn: transport.required_alpn().map(<[u8]>::to_vec),
                tls13_only: ech.is_some(),
                ech,
                client_fingerprint,
                alpn,
                certificate: super::TlsCertificatePolicy {
                    skip_cert_verify: self.skip_cert_verify.unwrap_or(false),
                    fingerprint,
                    verification_name: super::normalize_verification_name(self.name_cert_verify)?,
                },
                identity: super::normalize_client_identity(self.certificate, self.private_key)?,
            },
            certificate_options,
        )?;
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::Trojan(TrojanOutboundConfig {
                address: self.server,
                port: self.port,
                password: self.password,
                server_name,
                transport,
                security,
            }),
        ))
    }
}
