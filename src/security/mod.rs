//! TLS and REALITY security layers used by outbound transports.

#[cfg(feature = "tls-fingerprint")]
mod boring;
#[cfg(feature = "tls-fingerprint")]
mod boring_resumption;
#[cfg(feature = "tls-fingerprint")]
mod boring_stream;
#[cfg(feature = "outbound-vless")]
mod client;
mod context;
#[cfg(feature = "ech")]
pub(crate) mod ech;
mod resumption;
#[cfg(feature = "shadow-tls-v3")]
mod shadow_tls;
#[cfg(all(test, feature = "shadow-tls-v3"))]
mod shadow_tls_tests;
mod stream;
mod tls;
mod verifier;
#[cfg(feature = "shadow-tls-v3")]
pub use shadow_tls::ShadowTlsClient;
#[cfg(feature = "outbound-vless")]
pub(crate) mod vision;

#[cfg(feature = "outbound-vless")]
pub use client::{REALITY_CLIENT_VERSION, SecurityClient};
pub use context::SecurityContext;
pub use stream::CLOSE_NOTIFY_TIMEOUT;
pub use tls::{
    StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET, TlsCertificatePolicy, TlsClientIdentity,
    TlsClientOptions, TlsVersions,
};

#[cfg(test)]
fn test_profiles() -> &'static [Option<crate::config::ClientFingerprint>] {
    #[cfg(feature = "tls-fingerprint")]
    {
        use crate::config::ClientFingerprint::*;
        &[
            None,
            Some(Chrome133),
            Some(Firefox120),
            Some(Safari16),
            Some(Ios14),
        ]
    }
    #[cfg(not(feature = "tls-fingerprint"))]
    {
        &[None]
    }
}

#[cfg(all(test, feature = "outbound-vless", feature = "tls-fingerprint"))]
#[path = "ech_dynamic_tests.rs"]
mod ech_dynamic_tests;
