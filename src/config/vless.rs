//! VLESS public normalization. Transport options share the common stream adapters;
//! security and VLESS-specific behavior remain independent of VMess.
use super::vmess::{RawGrpc, RawH2, RawHttp, RawWs};
use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VlessStreamOptions {
    pub http_upgrade: bool,
    pub fast_open: bool,
    pub grpc: GrpcOptions,
    pub sing_mux: Option<SingMuxConfig>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SingMuxProtocol {
    #[default]
    H2Mux,
    Smux,
    Yamux,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SingMuxConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: SingMuxProtocol,
    #[serde(default)]
    pub max_connections: u32,
    #[serde(default)]
    pub min_streams: u32,
    #[serde(default)]
    pub max_streams: u32,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub only_tcp: bool,
}
#[derive(Clone, PartialEq, Eq)]
pub struct GrpcOptions {
    pub user_agent: String,
    pub ping_interval: u64,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
}
impl std::fmt::Debug for GrpcOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcOptions").finish_non_exhaustive()
    }
}
impl Default for GrpcOptions {
    fn default() -> Self {
        Self {
            user_agent: "grpc-go/1.36.0".into(),
            ping_interval: 0,
            max_connections: 1,
            min_streams: 0,
            max_streams: 0,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVlessWs {
    #[serde(default, deserialize_with = "deserialize_present_option")]
    path: Option<String>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(rename = "max-early-data", default)]
    max_early_data: u16,
    #[serde(
        rename = "early-data-header-name",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    early_data_header_name: Option<String>,
    #[serde(rename = "v2ray-http-upgrade", default)]
    http_upgrade: bool,
    #[serde(rename = "v2ray-http-upgrade-fast-open", default)]
    fast_open: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVlessGrpc {
    #[serde(rename = "grpc-service-name")]
    service: String,
    #[serde(
        rename = "grpc-user-agent",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    user_agent: Option<String>,
    #[serde(rename = "ping-interval", default)]
    ping_interval: u64,
    #[serde(rename = "max-connections", default)]
    max_connections: usize,
    #[serde(rename = "min-streams", default)]
    min_streams: usize,
    #[serde(rename = "max-streams", default)]
    max_streams: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawVless {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    #[serde(default)]
    udp: bool,
    #[serde(default)]
    tls: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    network: Option<String>,
    #[serde(rename = "packet-encoding", default)]
    packet_encoding: VlessPacketEncoding,
    #[serde(default)]
    encryption: String,
    #[serde(default)]
    flow: String,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    servername: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
    #[serde(
        rename = "dialer-proxy",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    dialer_proxy: Option<String>,
    #[serde(
        rename = "reality-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    reality_opts: Option<RawRealitySettings>,
    #[serde(
        rename = "jls-opts",
        default,
        deserialize_with = "super::jls::deserialize"
    )]
    jls_opts: Option<super::jls::RawJls>,
    #[serde(
        rename = "ech-opts",
        default,
        deserialize_with = "super::ech::deserialize"
    )]
    ech_opts: Option<super::ech::RawEch>,
    #[serde(
        rename = "xhttp-opts",
        default,
        deserialize_with = "deserialize_present_map"
    )]
    xhttp_opts: Option<RawXHttpSettings>,

    #[serde(default, deserialize_with = "deserialize_present_map")]
    smux: Option<SingMuxConfig>,

    #[serde(
        rename = "ws-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    ws: Option<RawVlessWs>,
    #[serde(
        rename = "grpc-opts",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    grpc: Option<RawVlessGrpc>,
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
        rename = "skip-cert-verify",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    skip_cert_verify: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(
        rename = "client-fingerprint",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    client_fingerprint: Option<String>,
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
}

impl std::fmt::Debug for RawVless {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawVless").finish_non_exhaustive()
    }
}

impl RawVless {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-vless") {
            return invalid("VLESS support is disabled in this build");
        }
        validate_host(&self.server, "VLESS server")?;
        validate_port(self.port, "VLESS")?;
        let id = parse_standard_uuid(&self.uuid)?;
        let encryption = if matches!(self.encryption.as_str(), "" | "none") {
            VlessEncryption::None
        } else {
            #[cfg(feature = "outbound-vless")]
            crate::outbound::validate_vless_encryption(&self.encryption).map_err(|_| {
                VoleError::InvalidConfig("invalid VLESS Encryption configuration".into())
            })?;
            VlessEncryption::MlKem768X25519Plus(self.encryption)
        };
        let network = self.network.as_deref().unwrap_or("tcp");
        let vision = self.flow == "xtls-rprx-vision";
        if self.jls_opts.is_some() && (vision || self.reality_opts.is_some()) {
            return invalid("JLS cannot be combined with REALITY or Vision");
        }
        if (!self.flow.is_empty() && !vision)
            || (vision
                && (network != "tcp"
                    || (!self.tls && matches!(&encryption, VlessEncryption::None))
                    || self.packet_encoding != VlessPacketEncoding::Xudp))
        {
            return invalid("VLESS Vision requires TCP, TLS or Encryption, and XUDP");
        }
        let mut stream_options = VlessStreamOptions::default();
        if let Some(mut mux) = self.smux {
            if (mux.max_connections > 0 && mux.max_streams > 0)
                || [mux.max_connections, mux.min_streams, mux.max_streams]
                    .iter()
                    .any(|value| *value > i32::MAX as u32)
                || (mux.enabled && vision)
            {
                return invalid("invalid VLESS sing-mux options");
            }
            if mux.max_connections == 0 && mux.max_streams == 0 {
                mux.min_streams = 8;
            }
            stream_options.sing_mux = mux.enabled.then_some(mux);
        }
        let ws = self
            .ws
            .map(|ws| {
                if (ws.fast_open && !ws.http_upgrade)
                    || (ws.http_upgrade
                        && ws.early_data_header_name.as_ref().is_some_and(|name| {
                            !name.eq_ignore_ascii_case("Sec-WebSocket-Protocol")
                        }))
                {
                    return invalid("invalid VLESS HTTPUpgrade options");
                }
                stream_options.http_upgrade = ws.http_upgrade;
                stream_options.fast_open = ws.fast_open;
                Ok(RawWs {
                    // VLESS also carries the mode alongside Encryption's
                    // initial-data choice; keep that existing ownership path.
                    http_upgrade: false,
                    fast_open: false,
                    path: ws.path,
                    headers: ws.headers,
                    max_early_data: ws.max_early_data,
                    early_data_header_name: ws.early_data_header_name,
                })
            })
            .transpose()?;
        let grpc = self
            .grpc
            .map(|grpc| {
                let user_agent = grpc.user_agent.unwrap_or_else(|| "grpc-go/1.36.0".into());
                if user_agent.len() > 8192
                    || user_agent.parse::<http::HeaderValue>().is_err()
                    || (grpc.max_connections > 0 && grpc.max_streams > 0)
                    || std::time::Instant::now()
                        .checked_add(std::time::Duration::from_secs(grpc.ping_interval))
                        .is_none()
                {
                    return invalid("invalid VLESS gRPC options");
                }
                stream_options.grpc = GrpcOptions {
                    user_agent,
                    ping_interval: grpc.ping_interval,
                    max_connections: if grpc.max_connections == 0
                        && grpc.min_streams == 0
                        && grpc.max_streams == 0
                    {
                        1
                    } else {
                        grpc.max_connections
                    },
                    min_streams: grpc.min_streams,
                    max_streams: grpc.max_streams,
                };
                Ok(RawGrpc {
                    service: grpc.service,
                })
            })
            .transpose()?;
        if (network != "xhttp" && self.xhttp_opts.is_some())
            || (network == "xhttp"
                && (ws.is_some() || grpc.is_some() || self.http.is_some() || self.h2.is_some()))
        {
            return invalid("VLESS transport options do not match network");
        }
        let (stream, fallback_name) = if network == "xhttp" {
            (StreamTransport::Tcp, self.server.clone())
        } else {
            vmess::normalize_transport(
                &self.server,
                self.port,
                self.tls,
                network,
                ws,
                grpc,
                self.http,
                self.h2,
            )?
        };
        let standard_options = self.skip_cert_verify.is_some()
            || self.fingerprint.is_some()
            || self.name_cert_verify.is_some()
            || self.certificate.is_some()
            || self.private_key.is_some();
        if !self.tls
            && (self.servername.is_some()
                || (network != "xhttp" && self.alpn.is_some())
                || self.reality_opts.is_some()
                || self.jls_opts.is_some()
                || self.ech_opts.is_some()
                || self.client_fingerprint.is_some()
                || standard_options)
        {
            return invalid("VLESS TLS options require tls=true");
        }
        if self.reality_opts.is_some() && standard_options {
            return invalid("standard certificate options cannot be used with REALITY");
        }
        if self.jls_opts.is_some() && standard_options {
            return invalid("standard certificate options cannot be used with JLS");
        }
        let ech = self
            .ech_opts
            .map(super::ech::RawEch::normalize)
            .transpose()?
            .flatten();
        if ech.is_some() && (self.reality_opts.is_some() || self.jls_opts.is_some() || vision) {
            return invalid("ECH requires standard TLS without REALITY, JLS or Vision");
        }
        let xhttp_version = if network == "xhttp" {
            super::XHttpVersion::from_alpn(self.alpn.as_deref().unwrap_or_default())?
        } else {
            super::XHttpVersion::default()
        };
        let default_alpn = if network == "xhttp" {
            Some(xhttp_version.alpn())
        } else {
            stream.required_alpn()
        };
        let client_fingerprint = parse_client_fingerprint(self.client_fingerprint.as_deref())?;
        if network == "xhttp"
            && xhttp_version == super::XHttpVersion::Http3
            && client_fingerprint.is_some()
        {
            return invalid("client-fingerprint is not supported on HTTP/3");
        }
        let alpn: Vec<Vec<u8>> = if network == "xhttp" {
            vec![xhttp_version.alpn().to_vec()]
        } else {
            self.alpn
                .map(|values| values.into_iter().map(String::into_bytes).collect())
                .unwrap_or_else(|| default_alpn.into_iter().map(<[u8]>::to_vec).collect())
        };
        if alpn.iter().any(|p| p.is_empty() || p.len() > 255)
            || alpn.iter().map(|p| 1 + p.len()).sum::<usize>() > 65533
            || default_alpn.is_some_and(|p| !alpn.iter().any(|v| v == p))
        {
            return invalid("invalid VLESS ALPN");
        }
        let explicit_name = self.servername.is_some();
        let server_name = self.servername.unwrap_or(fallback_name);
        validate_host(&server_name, "VLESS servername")?;
        if ech.is_some() && server_name.parse::<std::net::IpAddr>().is_ok() {
            return invalid("ECH requires a DNS servername");
        }
        if let Some(name) = &self.name_cert_verify {
            validate_host(name, "VLESS certificate verification name")?;
        }
        let identity = match (self.certificate, self.private_key) {
            (None, None) => None,
            (Some(certificate), Some(private_key)) => {
                validate_client_identity(&certificate, &private_key)?;
                Some(TlsIdentityPem {
                    certificate,
                    private_key,
                })
            }
            _ => return invalid("VLESS certificate and private-key must be provided together"),
        };
        let security = match (self.reality_opts, self.jls_opts) {
            (Some(raw), None) => {
                let mut config = raw.normalize(server_name)?;
                config.alpn = alpn;
                config.client_fingerprint = client_fingerprint;
                config.validate_fingerprint()?;
                SecurityConfig::Reality(config)
            }
            (None, Some(raw)) => SecurityConfig::Jls(raw.normalize(TlsConfig {
                ech: None,
                client_fingerprint,
                server_name,
                alpn,
                tls13_only: true,
                required_alpn: default_alpn.map(<[u8]>::to_vec),
                certificate: Default::default(),
                identity: None,
            })?),
            (None, None) if self.tls => SecurityConfig::Tls(TlsConfig {
                tls13_only: ech.is_some()
                    || network == "xhttp"
                    || (vision && matches!(&encryption, VlessEncryption::None)),
                ech,
                client_fingerprint,
                server_name,
                alpn,
                required_alpn: default_alpn.map(<[u8]>::to_vec),
                certificate: TlsCertificatePolicy {
                    verification_name: self.name_cert_verify,
                    skip_cert_verify: self.skip_cert_verify.unwrap_or(false),
                    fingerprint: self
                        .fingerprint
                        .map(|value| parse_pin(&value))
                        .transpose()?,
                },
                identity,
            }),
            (None, None) => SecurityConfig::None,
            (Some(_), Some(_)) => return invalid("JLS and REALITY are mutually exclusive"),
        };
        let transport = if network == "xhttp" {
            VlessTransport::Xhttp(Box::new(self.xhttp_opts.unwrap_or_default().normalize(
                &self.server,
                self.port,
                explicit_name.then_some(security.server_name()),
                if matches!(security, SecurityConfig::None) {
                    &self.server
                } else {
                    security.server_name()
                },
                &security,
                xhttp_version,
            )?))
        } else {
            VlessTransport::Stream(stream)
        };
        Ok((
            self.name,
            self.dialer_proxy,
            self.udp,
            ProxyProtocol::Vless(VlessOutboundConfig {
                address: self.server,
                port: self.port,
                id,
                encryption,
                flow: self.flow,
                security,
                transport,
                packet_encoding: self.packet_encoding,
                stream_options,
            }),
        ))
    }
}
#[cfg(feature = "outbound-vless")]
pub(super) fn validate_client_identity(certificate: &str, private_key: &str) -> Result<()> {
    crate::security::TlsClientIdentity::from_pem(certificate, private_key)
        .map(|_| ())
        .map_err(|_| VoleError::InvalidConfig("invalid VLESS client identity".into()))
}

#[cfg(not(feature = "outbound-vless"))]
pub(super) fn validate_client_identity(_certificate: &str, _private_key: &str) -> Result<()> {
    invalid("VLESS support is disabled in this build")
}

pub(super) fn parse_pin(value: &str) -> Result<[u8; 32]> {
    let hex = value
        .trim()
        .bytes()
        .filter(|byte| *byte != b':')
        .collect::<Vec<_>>();
    if hex.len() != 64 || hex.iter().any(|byte| !byte.is_ascii_hexdigit()) {
        return invalid("fingerprint must be a SHA-256 certificate digest");
    }
    let mut pin = [0; 32];
    for (index, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        pin[index] = ((pair[0] as char).to_digit(16).unwrap() * 16
            + (pair[1] as char).to_digit(16).unwrap()) as u8;
    }
    Ok(pin)
}
