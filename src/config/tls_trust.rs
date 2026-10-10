use std::sync::Arc;

use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use serde::Deserialize;

use crate::{Result, VoleError};

/// Client trust only. Certificates are decoded once; resource generations share them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TlsTrustConfig {
    pub(crate) certificates: Arc<[CertificateDer<'static>]>,
}

impl std::fmt::Debug for TlsTrustConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTrustConfig")
            .field("certificate_count", &self.certificates.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrust {
    #[serde(rename = "custom-certifactes", default)]
    certificates: Vec<String>,
}

impl<'de> Deserialize<'de> for TlsTrustConfig {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = RawTrust::deserialize(deserializer)
            .map_err(|_| serde::de::Error::custom("invalid TLS trust fields"))?;
        Self::parse(raw.certificates)
            .map_err(|_| serde::de::Error::custom("invalid TLS trust certificate"))
    }
}

impl TlsTrustConfig {
    fn parse(values: Vec<String>) -> Result<Self> {
        let invalid = || VoleError::InvalidConfig("invalid TLS trust certificate".into());
        let mut certificates = Vec::new();
        for value in values {
            if value.is_empty() {
                return Err(invalid());
            }
            let mut parsed = CertificateDer::pem_slice_iter(value.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| invalid())?;
            if parsed.is_empty() {
                parsed.push(CertificateDer::from(value.into_bytes()));
            }
            let mut validator = RootCertStore::empty();
            for certificate in &parsed {
                validator.add(certificate.clone()).map_err(|_| invalid())?;
            }
            certificates.extend(parsed);
        }
        certificates.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        certificates.dedup_by(|a, b| a.as_ref() == b.as_ref());
        Ok(Self {
            certificates: certificates.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_roots_decode_once_and_remain_redacted() {
        let certificate = rcgen::generate_simple_self_signed(vec!["trust.example".into()])
            .unwrap()
            .cert;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(certificate.der())
        );
        let config = TlsTrustConfig::parse(vec![pem.clone(), pem]).unwrap();
        assert_eq!(config.certificates.len(), 1);
        assert!(Arc::ptr_eq(
            &config.certificates,
            &config.clone().certificates
        ));
        assert!(!format!("{config:?}").contains("CERTIFICATE"));
    }

    #[test]
    fn trust_is_strict_certificate_content_not_a_path_or_alias() {
        for value in [
            "custom-certificates: []",
            "custom-certifactes: [./ca.pem]",
            "certificate: ca",
            "custom-certifactes: [null]",
        ] {
            assert!(serde_yaml_ng::from_str::<TlsTrustConfig>(value).is_err());
        }
        assert!(serde_yaml_ng::from_str::<TlsTrustConfig>("custom-certifactes: []").is_ok());
    }
}
