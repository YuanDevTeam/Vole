//! Hysteria Realm control options; no server-side registration or event stream.
use super::{
    TlsCertificatePolicy, TlsConfig, deserialize_present_option, invalid,
    normalize_certificate_fingerprint, normalize_client_identity, normalize_verification_name,
    validate_host,
};
use crate::{Result, session::Destination};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, PartialEq, Eq)]
pub struct Hysteria2Realm {
    pub server_url: String,
    pub token: String,
    pub realm_id: String,
    pub stun_servers: Vec<Destination>,
    pub tls: Option<TlsConfig>,
}
impl std::fmt::Debug for Hysteria2Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Realm").finish_non_exhaustive()
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawRealm {
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    server_url: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    realm_id: String,
    #[serde(default)]
    stun_servers: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    sni: Option<String>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    name_cert_verify: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    fingerprint: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    certificate: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    private_key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    alpn: Option<Vec<String>>,
}
fn bad() -> crate::VoleError {
    crate::VoleError::InvalidConfig("invalid Hysteria2 Realm endpoint".into())
}
fn stun(value: &str) -> Result<Destination> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(bad());
        }
        return Ok(Destination::Ip(address));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(Destination::Ip(SocketAddr::new(ip, 3478)));
    }
    let (host, port) = value
        .rsplit_once(':')
        .map_or(Ok((value, 3478)), |(host, port)| {
            port.parse::<u16>()
                .map(|port| (host, port))
                .map_err(|_| bad())
        })?;
    validate_host(host, "Hysteria2 Realm STUN host")?;
    if port == 0 {
        return Err(bad());
    }
    Destination::domain(host, port).map_err(|_| bad())
}
impl RawRealm {
    pub(super) fn normalize(self) -> Result<Option<Hysteria2Realm>> {
        if !self.enable {
            return Ok(None);
        }
        let url = url::Url::parse(&self.server_url).map_err(|_| bad())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.server_url.len() > 8192
            || self.realm_id.is_empty()
            || matches!(self.realm_id.as_str(), "." | "..")
            || self.realm_id.len() > 1024
            || self.realm_id.contains('\0')
            || self.stun_servers.is_empty()
            || self.stun_servers.len() > 16
            || self.token.len() > 8192
            || http::HeaderValue::from_str(&format!("Bearer {}", self.token)).is_err()
        {
            return Err(bad());
        }
        let stun_servers = self
            .stun_servers
            .iter()
            .map(|server| stun(server))
            .collect::<Result<Vec<_>>>()?;
        let tls = if url.scheme() == "https" {
            let name = self
                .sni
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| url.host_str().unwrap().trim_matches(['[', ']']).to_owned());
            validate_host(&name, "Hysteria2 Realm sni")?;
            let alpn = self
                .alpn
                .unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()]);
            if alpn.iter().any(|name| name.is_empty() || name.len() > 255)
                || alpn.iter().map(|name| name.len() + 1).sum::<usize>() > 65533
            {
                return invalid("invalid Hysteria2 Realm ALPN");
            }
            Some(TlsConfig {
                server_name: name,
                alpn: alpn.into_iter().map(String::into_bytes).collect(),
                tls13_only: false,
                required_alpn: None,
                ech: None,
                client_fingerprint: None,
                certificate: TlsCertificatePolicy {
                    skip_cert_verify: self.skip_cert_verify,
                    verification_name: normalize_verification_name(self.name_cert_verify)?,
                    fingerprint: normalize_certificate_fingerprint(self.fingerprint.as_deref())?,
                },
                identity: normalize_client_identity(self.certificate, self.private_key)?,
            })
        } else {
            if self.sni.is_some()
                || self.skip_cert_verify
                || self.name_cert_verify.is_some()
                || self.fingerprint.is_some()
                || self.certificate.is_some()
                || self.private_key.is_some()
                || self.alpn.is_some()
            {
                return invalid("Hysteria2 Realm TLS options require HTTPS");
            }
            None
        };
        Ok(Some(Hysteria2Realm {
            server_url: url.as_str().trim_end_matches('/').to_owned(),
            token: self.token,
            realm_id: self.realm_id,
            stun_servers,
            tls,
        }))
    }
}
#[cfg(all(test, feature = "outbound-hysteria2"))]
mod tests {
    use super::*;
    #[test]
    fn realm_options_bind_control_tls_and_bounded_stun_endpoints() {
        let raw:RawRealm=serde_json::from_value(serde_json::json!({"enable":true,"server-url":"https://control.example/base/","token":"private","realm-id":"zone","stun-servers":["192.0.2.1","[2001:db8::1]:3479","stun.example"],"name-cert-verify":"identity.example","sni":"cover.example"})).unwrap();
        let config = raw.normalize().unwrap().unwrap();
        assert_eq!(config.stun_servers.len(), 3);
        assert_eq!(config.server_url, "https://control.example/base");
        assert_eq!(config.tls.as_ref().unwrap().server_name, "cover.example");
        assert_eq!(
            config
                .tls
                .as_ref()
                .unwrap()
                .certificate
                .verification_name
                .as_deref(),
            Some("identity.example")
        );
        assert!(!format!("{config:?}").contains("private"));
    }
}
