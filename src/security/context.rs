use std::sync::Arc;

use rustls::RootCertStore;

/// Immutable cryptographic material shared by every TLS client in one runtime.
///
/// Protocol-specific clients still own their small `ClientConfig`, while the
/// crypto provider and WebPKI roots are constructed only once.
#[derive(Clone)]
pub struct SecurityContext {
    pub(super) provider: Arc<rustls::crypto::CryptoProvider>,
    pub(super) tls_roots: Arc<RootCertStore>,
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            tls_roots: Arc::new(webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect()),
        }
    }

    #[cfg(any(test, feature = "interop-test"))]
    pub(crate) fn with_tls_roots(tls_roots: RootCertStore) -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            tls_roots: Arc::new(tls_roots),
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
}
