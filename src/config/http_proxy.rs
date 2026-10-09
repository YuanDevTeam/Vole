use super::*;
use std::collections::BTreeMap;
#[derive(Clone, PartialEq, Eq)]
pub struct HttpOutboundConfig {
    pub address: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
    pub auth: Option<ProxyCredentials>,
    pub headers: BTreeMap<String, String>,
}
impl std::fmt::Debug for HttpOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOutboundConfig")
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawHttp {
    name: String,
    server: String,
    port: u16,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    tls: bool,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default)]
    name_cert_verify: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    dialer_proxy: Option<String>,
}
impl std::fmt::Debug for RawHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawHttp").finish_non_exhaustive()
    }
}
impl RawHttp {
    pub(super) fn normalize(self) -> Result<(String, Option<String>, bool, ProxyProtocol)> {
        if !cfg!(feature = "outbound-http") {
            return invalid("HTTP outbound support is disabled at build time");
        }
        validate_host(&self.server, "HTTP server")?;
        validate_port(self.port, "HTTP")?;
        let auth = if !self.username.is_empty() && !self.password.is_empty() {
            Some(
                ProxyCredentials::new(self.username, self.password).map_err(|_| {
                    VoleError::InvalidConfig("invalid HTTP proxy credentials".into())
                })?,
            )
        } else {
            None
        };
        let mut header_bytes = 0usize;
        for (name, value) in &self.headers {
            header_bytes = header_bytes
                .saturating_add(name.len())
                .saturating_add(value.len());
            if http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                || http::HeaderValue::from_str(value).is_err()
                || header_bytes > 32 * 1024
            {
                return invalid("invalid HTTP proxy headers");
            }
        }
        if self.headers.keys().any(|key| {
            ["content-length", "transfer-encoding"]
                .iter()
                .any(|reserved| key.eq_ignore_ascii_case(reserved))
        }) {
            return invalid("HTTP CONNECT does not carry a request body");
        }
        let tls = if self.tls {
            let name = self.sni.unwrap_or_else(|| self.server.clone());
            validate_host(&name, "HTTP sni")?;
            if let Some(verify) = &self.name_cert_verify {
                validate_host(verify, "HTTP verification name")?;
            }
            let identity = match (self.certificate, self.private_key) {
                (Some(certificate), Some(private_key)) => {
                    crate::security::TlsClientIdentity::from_pem(&certificate, &private_key)
                        .map_err(|_| {
                            VoleError::InvalidConfig("invalid HTTP client identity".into())
                        })?;
                    Some(TlsIdentityPem {
                        certificate,
                        private_key,
                    })
                }
                (None, None) => None,
                _ => return invalid("HTTP certificate and private-key must be paired"),
            };
            Some(TlsConfig {
                server_name: name,
                alpn: vec![b"http/1.1".to_vec()],
                tls13_only: false,
                required_alpn: None,
                ech: None,
                client_fingerprint: None,
                identity,
                certificate: TlsCertificatePolicy {
                    skip_cert_verify: self.skip_cert_verify,
                    verification_name: self.name_cert_verify,
                    fingerprint: self
                        .fingerprint
                        .as_deref()
                        .map(vless::parse_pin)
                        .transpose()?,
                },
            })
        } else {
            if self.sni.is_some()
                || self.skip_cert_verify
                || self.name_cert_verify.is_some()
                || self.fingerprint.is_some()
                || self.certificate.is_some()
                || self.private_key.is_some()
            {
                return invalid("HTTP TLS options require tls: true");
            }
            None
        };
        Ok((
            self.name,
            self.dialer_proxy,
            false,
            ProxyProtocol::Http(HttpOutboundConfig {
                address: self.server,
                port: self.port,
                tls,
                auth,
                headers: self.headers,
            }),
        ))
    }
}

#[cfg(all(test, feature = "outbound-http"))]
mod tests {
    use super::*;
    #[test]
    fn http_tls_and_common_node_options_normalize() {
        let config = Config::parse_yaml(
            br#"mixed-port: 1080
proxies:
  - name: web
    type: http
    server: proxy.example.com
    port: 443
    tls: true
    username: u
    password: p
    ip-version: ipv4-prefer
    headers: {Host: custom.example.com}
"#,
        )
        .unwrap();
        assert_eq!(config.proxies[0].ip_version, IpVersion::Ipv4Prefer);
        let ProxyProtocol::Http(http) = &config.proxies[0].protocol else {
            panic!()
        };
        assert_eq!(http.tls.as_ref().unwrap().server_name, "proxy.example.com");
        assert!(http.auth.as_ref().unwrap().matches(b"u", b"p"));
        assert!(!config.proxies[0].udp);
    }
}
