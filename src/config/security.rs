//! Shared normalized identities for caller-owned TCP transport legs.
use super::*;

#[derive(Default)]
pub(super) struct RawSecurityModes {
    pub reality: Option<RawRealitySettings>,
    pub jls: Option<jls::RawJls>,
    pub shadow_tls: Option<RawShadowTlsMode>,
}

impl RawSecurityModes {
    pub(super) fn normalize(
        self,
        mut tls: TlsConfig,
        certificate_options: bool,
    ) -> Result<SecurityConfig> {
        tls.tls13_only |= tls.ech.is_some();
        if tls.tls13_only
            || self.reality.is_some()
            || self.jls.is_some()
            || self.shadow_tls.is_some()
        {
            validate_tls13_fingerprint(tls.client_fingerprint)?;
        }
        if usize::from(self.reality.is_some())
            + usize::from(self.jls.is_some())
            + usize::from(self.shadow_tls.is_some())
            > 1
        {
            return invalid("transport security identities are mutually exclusive");
        }
        if (self.reality.is_some() || self.jls.is_some()) && certificate_options {
            return invalid("certificate options cannot be used with this transport identity");
        }
        if (self.reality.is_some() || self.jls.is_some() || self.shadow_tls.is_some())
            && tls.ech.is_some()
        {
            return invalid("ECH requires standard TLS");
        }
        if let Some(raw) = self.reality {
            if !cfg!(feature = "stream-security") {
                return invalid("REALITY is not compiled in");
            }
            let mut config = raw.normalize(tls.server_name)?;
            config.alpn = tls.alpn;
            config.client_fingerprint = tls.client_fingerprint;
            config.validate_fingerprint()?;
            return Ok(SecurityConfig::Reality(config));
        }
        if let Some(raw) = self.jls {
            if !cfg!(feature = "stream-security") {
                return invalid("JLS is not compiled in");
            }
            tls.tls13_only = true;
            return Ok(SecurityConfig::Jls(raw.normalize(tls)?));
        }
        if let Some(raw) = self.shadow_tls {
            return raw.normalize(tls).map(SecurityConfig::ShadowTls);
        }
        Ok(SecurityConfig::Tls(tls))
    }
}

/// Generic ShadowTLS options take the cover name/policy from their TLS node.
/// SS plugins have their own `host` and policy fields and use a separate decoder.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawShadowTlsMode {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    password: String,
}

impl std::fmt::Debug for RawShadowTlsMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawShadowTlsMode")
            .finish_non_exhaustive()
    }
}

impl RawShadowTlsMode {
    pub(super) fn is_empty(&self) -> bool {
        self.version == 0 && self.password.is_empty()
    }

    pub(super) fn normalize(self, tls: TlsConfig) -> Result<ShadowTlsConfig> {
        if self.version != 3 {
            return invalid("ShadowTLS requires explicit version 3");
        }
        let config = ShadowTlsConfig {
            server_name: tls.server_name,
            password: self.password,
            alpn: tls.alpn,
            required_alpn: tls.required_alpn,
            certificate: tls.certificate,
            identity: tls.identity,
            client_fingerprint: tls.client_fingerprint,
        };
        config.validate()?;
        Ok(config)
    }
}

pub(super) fn deserialize_shadow_tls<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<RawShadowTlsMode>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_present_map(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid ShadowTLS identity object"))
}

#[cfg(all(
    test,
    feature = "stream-security",
    feature = "shadow-tls-v3",
    feature = "outbound-vmess",
    feature = "outbound-vless",
    feature = "outbound-trojan",
    feature = "outbound-anytls",
    feature = "outbound-shadowsocks"
))]
#[path = "security_tests.rs"]
mod tests;
