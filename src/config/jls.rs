use super::*;

/// JLS identity is independent of WebPKI; the native TLS handshake still verifies
/// CertificateVerify and Finished. Each transport leg owns its credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct JlsConfig {
    pub tls: TlsConfig,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for JlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JlsConfig")
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

impl JlsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_tls13_fingerprint(self.tls.client_fingerprint)?;
        for value in [&self.username, &self.password] {
            if value.is_empty() || value.len() > 65_535 {
                return invalid("JLS credentials must each contain 1..65535 bytes");
            }
        }
        if self.tls.certificate != TlsCertificatePolicy::default()
            || self.tls.identity.is_some()
            || self.tls.ech.is_some()
        {
            return invalid("JLS cannot use standard certificate policy or client identity");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawJls {
    #[serde(default, deserialize_with = "deserialize_present_option")]
    username: Option<String>,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    password: Option<String>,
}

impl std::fmt::Debug for RawJls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawJls").finish_non_exhaustive()
    }
}

impl RawJls {
    pub(super) fn is_empty(&self) -> bool {
        self.username.is_none() && self.password.is_none()
    }

    pub(super) fn normalize(self, tls: TlsConfig) -> Result<JlsConfig> {
        let (Some(username), Some(password)) = (self.username, self.password) else {
            return invalid("JLS requires both username and password");
        };
        let config = JlsConfig {
            tls,
            username,
            password,
        };
        config.validate()?;
        Ok(config)
    }
}

pub(super) fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<RawJls>, D::Error>
where
    D: Deserializer<'de>,
{
    // Serde's type/unknown-field errors can echo a supplied numeric secret or
    // an entire malformed credential object. Keep the strict map decoder but
    // do not expose its input-bearing error through Config or Invoke.
    deserialize_present_map(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid JLS credential object"))
}
