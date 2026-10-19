//! One strict transport plugin below the official Shadowsocks 2022 codec.
use super::*;
use serde::de::DeserializeOwned;
use serde_yaml_ng::Value;
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq)]
pub enum ShadowsocksPlugin {
    ShadowTls(ShadowTlsConfig),
    Jls(JlsConfig),
    Obfs {
        tls: bool,
        host: String,
    },
    WebSocket {
        gost: bool,
        mux: bool,
        transport: StreamTransport,
        tls: Option<TlsConfig>,
    },
}
impl std::fmt::Debug for ShadowsocksPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ShadowTls(_) => "ShadowTls",
            Self::Jls(_) => "Jls",
            Self::Obfs { .. } => "Obfs",
            Self::WebSocket { .. } => "WebSocket",
        })
    }
}
impl ShadowsocksPlugin {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::ShadowTls(options) => options.validate(),
            Self::Jls(options) => options.validate(),
            Self::Obfs { host, .. } => validate_host(host, "Shadowsocks obfs host"),
            Self::WebSocket {
                transport: StreamTransport::WebSocket { .. },
                ..
            } => Ok(()),
            Self::WebSocket { .. } => invalid("invalid Shadowsocks WebSocket transport"),
        }
    }
    pub(crate) fn tls_sessions(&self) -> usize {
        usize::from(matches!(self, Self::WebSocket { tls: Some(_), .. }))
    }
}

pub(super) fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_present_map(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid Shadowsocks plugin options"))
}
fn decode<T: DeserializeOwned>(value: Value) -> Result<T> {
    serde_yaml_ng::from_value(value)
        .map_err(|_| VoleError::InvalidConfig("invalid Shadowsocks plugin options".into()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Obfs {
    mode: String,
    #[serde(default = "default_host")]
    host: String,
}
fn default_host() -> String {
    "bing.com".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jls {
    host: String,
    username: String,
    password: String,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WebSocket {
    mode: String,
    #[serde(default = "default_host")]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    tls: bool,
    #[serde(default = "enabled")]
    mux: bool,
    #[serde(default)]
    v2ray_http_upgrade: bool,
    #[serde(default)]
    v2ray_http_upgrade_fast_open: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    skip_cert_verify: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    name_cert_verify: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    certificate: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    private_key: Option<String>,
    #[serde(default, deserialize_with = "ech::deserialize")]
    ech_opts: Option<ech::RawEch>,
}
fn enabled() -> bool {
    true
}

pub(super) fn normalize(
    name: Option<String>,
    options: Option<Value>,
    fingerprint: Option<String>,
    port: u16,
) -> Result<Option<ShadowsocksPlugin>> {
    let (name, options) = match (name.filter(|name| !name.is_empty()), options) {
        (None, None) if fingerprint.is_none() => return Ok(None),
        (Some(name), Some(options)) => (name, options),
        _ => return invalid("Shadowsocks plugin and options must be provided together"),
    };
    if fingerprint.is_some() && !matches!(name.as_str(), "shadow-tls" | "jls") {
        return invalid("Shadowsocks client-fingerprint requires a consuming identity plugin");
    }
    let plugin = match name.as_str() {
        "shadow-tls" => ShadowsocksPlugin::ShadowTls(
            shadowsocks::plugin(Some(name), Some(decode(options)?), fingerprint)?.unwrap(),
        ),
        "jls" => {
            if !cfg!(feature = "stream-security") {
                return invalid("JLS is not compiled in");
            }
            let raw: Jls = decode(options)?;
            validate_host(&raw.host, "JLS host")?;
            let mut tls = TlsConfig::xhttp(raw.host);
            tls.required_alpn = None;
            tls.alpn = normalize_alpn(
                raw.alpn
                    .unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()]),
            )?;
            tls.tls13_only = true;
            tls.client_fingerprint = parse_client_fingerprint(fingerprint.as_deref())?;
            ShadowsocksPlugin::Jls(JlsConfig {
                tls,
                username: raw.username,
                password: raw.password,
            })
        }
        "obfs" => {
            let raw: Obfs = decode(options)?;
            if !matches!(raw.mode.as_str(), "http" | "tls") {
                return invalid("invalid Shadowsocks obfs mode");
            }
            ShadowsocksPlugin::Obfs {
                tls: raw.mode == "tls",
                host: raw.host,
            }
        }
        "v2ray-plugin" | "gost-plugin" => {
            let raw: WebSocket = decode(options)?;
            let gost = name == "gost-plugin";
            if raw.mode != "websocket"
                || (gost && (raw.v2ray_http_upgrade || raw.v2ray_http_upgrade_fast_open))
            {
                return invalid("invalid Shadowsocks WebSocket plugin mode");
            }
            if !raw.tls
                && (raw.skip_cert_verify.is_some()
                    || raw.name_cert_verify.is_some()
                    || raw.fingerprint.is_some()
                    || raw.certificate.is_some()
                    || raw.private_key.is_some()
                    || raw.ech_opts.is_some())
            {
                return invalid("Shadowsocks plugin TLS options require tls=true");
            }
            validate_host(&raw.host, "Shadowsocks plugin host")?;
            let (transport, server_name) = vmess::normalize_transport(
                &raw.host,
                port,
                raw.tls,
                "ws",
                Some(vmess::RawWs {
                    path: Some(if raw.path.is_empty() {
                        "/".into()
                    } else {
                        raw.path
                    }),
                    headers: raw.headers,
                    http_upgrade: raw.v2ray_http_upgrade,
                    fast_open: raw.v2ray_http_upgrade_fast_open,
                    ..Default::default()
                }),
                None,
                None,
                None,
                None,
            )?;
            let tls = if raw.tls {
                let ech = raw
                    .ech_opts
                    .map(|raw| raw.normalize(false))
                    .transpose()?
                    .flatten();
                Some(TlsConfig {
                    server_name,
                    client_fingerprint: None,
                    alpn: vec![b"http/1.1".to_vec()],
                    required_alpn: Some(b"http/1.1".to_vec()),
                    tls13_only: ech.is_some(),
                    ech,
                    certificate: TlsCertificatePolicy {
                        fingerprint: normalize_certificate_fingerprint(raw.fingerprint.as_deref())?,
                        skip_cert_verify: raw.skip_cert_verify.unwrap_or(false),
                        verification_name: normalize_verification_name(raw.name_cert_verify)?,
                    },
                    identity: normalize_client_identity(raw.certificate, raw.private_key)?,
                })
            } else {
                None
            };
            ShadowsocksPlugin::WebSocket {
                gost,
                mux: raw.mux,
                transport,
                tls,
            }
        }
        _ => return invalid("unsupported Shadowsocks plugin"),
    };
    plugin.validate()?;
    Ok(Some(plugin))
}
fn normalize_alpn(values: Vec<String>) -> Result<Vec<Vec<u8>>> {
    if values.iter().any(|v| v.is_empty() || v.len() > 255)
        || values.iter().map(|v| v.len() + 1).sum::<usize>() > 65533
    {
        return invalid("invalid Shadowsocks plugin ALPN");
    }
    Ok(values.into_iter().map(String::into_bytes).collect())
}

#[cfg(all(test, feature = "outbound-shadowsocks"))]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;
    fn parse(plugin: &str, options: serde_json::Value) -> Result<Config> {
        Config::parse_yaml(&serde_json::to_vec(&json!({"proxies":[{"name":"edge","type":"ss","server":"proxy.invalid","port":443,"cipher":"2022-blake3-aes-128-gcm","password":base64::engine::general_purpose::STANDARD.encode([7;16]),"udp":true,"plugin":plugin,"plugin-opts":options}],"rules":["MATCH,edge"]})).unwrap())
    }
    #[test]
    fn strict_plugins_construct_their_actual_transport() {
        for (plugin, options) in [
            ("obfs", json!({"mode":"http"})),
            ("obfs", json!({"mode":"tls","host":"cover.invalid"})),
            (
                "v2ray-plugin",
                json!({"mode":"websocket","mux":true,"tls":true,"host":"cover.invalid","headers":{"Host":"identity.invalid"},"v2ray-http-upgrade":true,"v2ray-http-upgrade-fast-open":true}),
            ),
            ("gost-plugin", json!({"mode":"websocket","mux":true})),
            (
                "jls",
                json!({"host":"cover.invalid","username":"synthetic-user","password":"synthetic-password"}),
            ),
        ] {
            let config = parse(plugin, options).unwrap();
            let ProxyProtocol::Shadowsocks(ss) = &config.proxies[0].protocol else {
                panic!("expected SS")
            };
            assert!(!ss.udp_over_tcp);
            if let Some(ShadowsocksPlugin::WebSocket { tls: Some(tls), .. }) = &ss.plugin {
                assert_eq!(tls.server_name, "identity.invalid");
                assert_eq!(tls.required_alpn.as_deref(), Some(b"http/1.1".as_slice()));
            }
            let debug = format!("{config:?}");
            assert!(!debug.contains("synthetic-user"));
            assert!(!debug.contains("synthetic-password"));
        }
    }
    #[test]
    fn unused_security_flags_and_unbounded_options_fail_before_io() {
        for (plugin, options) in [
            ("obfs", json!({"mode":"http","tls":true})),
            (
                "v2ray-plugin",
                json!({"mode":"websocket","tls":false,"skip-cert-verify":false}),
            ),
            (
                "gost-plugin",
                json!({"mode":"websocket","v2ray-http-upgrade":true}),
            ),
            (
                "jls",
                json!({"host":"cover.invalid","username":"synthetic-user","password":"synthetic-password","certificate":"unused"}),
            ),
        ] {
            let error = parse(plugin, options).unwrap_err().to_string();
            assert!(!error.contains("synthetic-user"));
            assert!(!error.contains("synthetic-password"));
        }
    }
}
