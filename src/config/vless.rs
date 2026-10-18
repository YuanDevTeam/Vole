//! VLESS public normalization. Transport options share the common stream adapters;
//! security and VLESS-specific behavior remain independent of VMess.
use super::grpc::RawGrpc;
use super::vmess::{RawH2, RawHttp, RawWs};
use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VlessStreamOptions {
    pub http_upgrade: bool,
    pub fast_open: bool,
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
    flow: Option<String>,
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
        rename = "shadow-tls-opts",
        default,
        deserialize_with = "super::security::deserialize_shadow_tls"
    )]
    shadow_tls_opts: Option<super::security::RawShadowTlsMode>,
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
        let network = self
            .network
            .as_deref()
            .filter(|network| !network.is_empty())
            .unwrap_or("tcp");
        let flow = self.flow.unwrap_or_default();
        let vision = flow == "xtls-rprx-vision";
        if self.shadow_tls_opts.is_some() && vision {
            return invalid("ShadowTLS cannot be combined with Vision");
        }
        if self.jls_opts.is_some() && (vision || self.reality_opts.is_some()) {
            return invalid("JLS cannot be combined with REALITY or Vision");
        }
        if (!flow.is_empty() && !vision)
            || (vision
                && (network != "tcp"
                    || (!self.tls && matches!(&encryption, VlessEncryption::None))
                    || self.packet_encoding != VlessPacketEncoding::Xudp))
        {
            return invalid("VLESS Vision requires TCP, TLS or Encryption, and XUDP");
        }
        let mut stream_options = VlessStreamOptions::default();
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
        let grpc = self.grpc;
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
                self.servername.as_deref().filter(|name| !name.is_empty()),
            )?
        };
        if self.reality_opts.is_some() && matches!(stream, StreamTransport::WebSocket { .. }) {
            return invalid("VLESS REALITY requires a stream TLS transport");
        }
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
                || self.shadow_tls_opts.is_some()
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
        let client_fingerprint = parse_client_fingerprint(self.client_fingerprint.as_deref())?;
        let ech = self
            .ech_opts
            .map(|raw| raw.normalize(client_fingerprint.is_some()))
            .transpose()?
            .flatten();
        if ech.is_some()
            && (self.reality_opts.is_some()
                || self.jls_opts.is_some()
                || self.shadow_tls_opts.is_some()
                || vision)
        {
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
        let servername = self.servername.filter(|name| !name.is_empty());
        let explicit_name = servername.is_some();
        let server_name = servername.unwrap_or(fallback_name);
        validate_host(&server_name, "VLESS servername")?;
        if ech.is_some() && server_name.parse::<std::net::IpAddr>().is_ok() {
            return invalid("ECH requires a DNS servername");
        }
        let verification_name = normalize_verification_name(self.name_cert_verify)?;
        let identity = normalize_client_identity(self.certificate, self.private_key)?;
        let security = if self.tls {
            super::security::RawSecurityModes {
                reality: self.reality_opts,
                jls: self.jls_opts,
                shadow_tls: self.shadow_tls_opts,
            }
            .normalize(
                TlsConfig {
                    tls13_only: ech.is_some()
                        || network == "xhttp"
                        || (vision && matches!(&encryption, VlessEncryption::None)),
                    ech,
                    client_fingerprint,
                    server_name,
                    alpn,
                    required_alpn: default_alpn.map(<[u8]>::to_vec),
                    certificate: TlsCertificatePolicy {
                        verification_name,
                        skip_cert_verify: self.skip_cert_verify.unwrap_or(false),
                        fingerprint: normalize_certificate_fingerprint(
                            self.fingerprint.as_deref(),
                        )?,
                    },
                    identity,
                },
                standard_options,
            )?
        } else {
            SecurityConfig::None
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
                flow,
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
