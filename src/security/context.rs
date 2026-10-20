use std::sync::Arc;

use rustls::RootCertStore;

/// Shared immutable roots/provider and the runtime's client-identity publisher.
///
/// Protocol-specific clients still own their small `ClientConfig`, while the
/// crypto provider and WebPKI roots are constructed only once.
#[derive(Clone)]
pub struct SecurityContext {
    pub(super) provider: Arc<rustls::crypto::CryptoProvider>,
    pub(super) tls_roots: Arc<RootCertStore>,
    pub(crate) identities: Arc<super::identity::IdentityRegistry>,
}

impl std::fmt::Debug for SecurityContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecurityContext")
            .field("tls_root_count", &self.tls_roots.len())
            .finish_non_exhaustive()
    }
}

impl SecurityContext {
    #[cfg(test)]
    pub(crate) fn shares_roots_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tls_roots, &other.tls_roots)
    }
    /// Read available platform roots once during preparation, retaining the
    /// approved built-in roots when a platform store is unavailable.
    #[cfg(any(test, feature = "invoke"))]
    pub(crate) fn load(trust: &crate::config::TlsTrustConfig) -> Self {
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            tracing::debug!("some platform TLS trust roots were unavailable");
        }
        Self::with_certificates(trust, native.certs)
    }

    #[cfg(any(test, feature = "invoke"))]
    pub(crate) fn with_certificates(
        trust: &crate::config::TlsTrustConfig,
        mut native: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        native.extend(trust.certificates.iter().cloned());
        native.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        native.dedup_by(|a, b| a.as_ref() == b.as_ref());
        let mut roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
        roots.add_parsable_certificates(native);
        // Native and embedded sources may contain the same trust anchor.
        let mut unique = std::collections::HashSet::new();
        roots.roots.retain(|root| unique.insert(root.clone()));
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            tls_roots: Arc::new(roots),
            identities: Arc::default(),
        }
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            tls_roots: Arc::new(webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect()),
            identities: Arc::default(),
        }
    }

    #[cfg(any(test, feature = "interop-test"))]
    pub(crate) fn with_tls_roots(tls_roots: RootCertStore) -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            tls_roots: Arc::new(tls_roots),
            identities: Arc::default(),
        }
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_runtime_context_shares_provider_and_root_store() {
        let context = SecurityContext::new();
        let clone = context.clone();
        assert!(Arc::ptr_eq(&context.provider, &clone.provider));
        assert!(Arc::ptr_eq(&context.tls_roots, &clone.tls_roots));
        assert!(!context.tls_roots.is_empty());
    }

    #[test]
    fn configured_and_native_roots_merge_once_without_removing_embedded_roots() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let certificate = rcgen::generate_simple_self_signed(vec!["trust.example".into()])
            .unwrap()
            .cert;
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(certificate.der())
        );
        let trust = serde_yaml_ng::from_value::<crate::config::TlsTrustConfig>(
            serde_yaml_ng::to_value(serde_json::json!({"custom-certifactes": [pem]})).unwrap(),
        )
        .unwrap();
        let context = SecurityContext::with_certificates(&trust, vec![certificate.der().clone()]);
        assert_eq!(
            context.tls_roots.len(),
            SecurityContext::new().tls_roots.len() + 1
        );
        assert!(context.shares_roots_with(&context.clone()));
        assert!(!context.shares_roots_with(&SecurityContext::new()));
    }
}
