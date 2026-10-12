use std::{io, sync::Arc};

#[cfg(feature = "interop-test")]
use rustls::RootCertStore;

use crate::{
    config::{SecurityConfig, VlessOutboundConfig},
    dispatch::BoxStream,
};

use super::{
    SecurityContext,
    tls::{
        DEFAULT_TLS_BUFFER_LIMIT, StandardTlsClient, TLS_RESUMPTION_SESSION_BUDGET,
        TlsClientOptions, TlsVersions,
    },
};

/// Current Xray compatibility version carried in the encrypted REALITY session ID.
///
/// Xray-core 26.7.11 defaults `minClientVer` to 26.3.27. Vole pins the wire
/// version here rather than exposing another profile field.
pub const REALITY_CLIENT_VERSION: [u8; 3] = [26, 7, 11];

#[derive(Clone)]
enum SecurityBackend {
    Plain,
    Standard(StandardTlsClient),
    Reality {
        client: super::boring::BoringTlsClient,
        buffer_limit: usize,
    },
    Jls {
        client: super::boring::BoringTlsClient,
        buffer_limit: usize,
    },
}

#[derive(Clone)]
pub struct SecurityClient {
    backend: SecurityBackend,
}

impl std::fmt::Debug for SecurityClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.backend {
            SecurityBackend::Plain => formatter.write_str("SecurityClient::Plain"),
            SecurityBackend::Standard(client) => formatter
                .debug_tuple("SecurityClient::Standard")
                .field(client)
                .finish(),
            SecurityBackend::Reality { buffer_limit, .. } => formatter
                .debug_struct("SecurityClient::Reality")
                .field("buffer_limit", buffer_limit)
                .finish_non_exhaustive(),
            SecurityBackend::Jls { buffer_limit, .. } => formatter
                .debug_struct("SecurityClient::Jls")
                .field("buffer_limit", buffer_limit)
                .finish_non_exhaustive(),
        }
    }
}

impl SecurityClient {
    #[cfg(feature = "h3-transport")]
    pub(crate) async fn quiche_config_with_context(
        &self,
        context: &crate::outbound::EstablishContext,
    ) -> io::Result<super::QuicheTls> {
        match &self.backend {
            SecurityBackend::Standard(client) => client.quiche_config_with_context(context).await,
            _ => Err(io::Error::other("HTTP/3 requires standard TLS")),
        }
    }

    pub(crate) async fn connect_with_context(
        &self,
        stream: BoxStream,
        context: &crate::outbound::EstablishContext,
    ) -> io::Result<BoxStream> {
        match &self.backend {
            SecurityBackend::Standard(client) => client.connect_with_context(stream, context).await,
            _ => self.connect(stream).await,
        }
    }

    /// Builds one TLS, REALITY or JLS transport leg from its normalized security
    /// configuration. A VLESS XHTTP download leg may use security settings
    /// distinct from the enclosing proxy's primary leg.
    pub fn from_security(config: &SecurityConfig) -> io::Result<Self> {
        Self::from_security_with_context(
            config,
            &SecurityContext::new(),
            TLS_RESUMPTION_SESSION_BUDGET,
            DEFAULT_TLS_BUFFER_LIMIT,
        )
    }

    /// Backwards-compatible primary-leg constructor.
    pub fn from_proxy(config: &VlessOutboundConfig) -> io::Result<Self> {
        Self::from_security(&config.security)
    }

    /// Builds one node from instance-shared cryptographic material. The
    /// caller allocates the aggregate TLS resumption budget across standard-TLS
    /// nodes; zero disables resumption when the fixed four-session runtime
    /// budget cannot provide a slot for every node. REALITY and JLS ignore the
    /// budget because their resumption policies are disabled.
    pub(crate) fn from_proxy_with_context(
        config: &VlessOutboundConfig,
        context: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        Self::from_security_with_context(
            &config.security,
            context,
            resumption_sessions,
            buffer_limit,
        )
    }

    pub(crate) fn from_security_with_context(
        config: &SecurityConfig,
        context: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        Self::from_security_with_security_context(
            config,
            context,
            resumption_sessions,
            buffer_limit,
        )
    }

    /// Builds a standard-TLS client with explicit local-test trust anchors.
    ///
    /// This entry point does not exist unless the `interop-test` feature is
    /// enabled. Production builds always use the bundled WebPKI roots.
    #[cfg(feature = "interop-test")]
    pub(crate) fn from_proxy_with_test_tls_roots(
        config: &VlessOutboundConfig,
        roots_der: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<Self> {
        Self::from_security_with_test_tls_roots(&config.security, roots_der)
    }

    #[cfg(feature = "interop-test")]
    pub(crate) fn from_security_with_test_tls_roots(
        config: &SecurityConfig,
        roots_der: impl IntoIterator<Item = Vec<u8>>,
    ) -> io::Result<Self> {
        if !matches!(config, SecurityConfig::Tls(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "test TLS roots can only be used with standard TLS",
            ));
        }
        let mut roots = RootCertStore::empty();
        for root in roots_der {
            roots
                .add(rustls::pki_types::CertificateDer::from(root))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        }
        if roots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one test TLS root is required",
            ));
        }
        Self::from_security_with_security_context(
            config,
            &SecurityContext::with_tls_roots(roots),
            TLS_RESUMPTION_SESSION_BUDGET,
            DEFAULT_TLS_BUFFER_LIMIT,
        )
    }

    fn from_security_with_security_context(
        config: &SecurityConfig,
        context: &SecurityContext,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        if buffer_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS buffer limit must be greater than zero",
            ));
        }
        let backend = match config {
            SecurityConfig::None => SecurityBackend::Plain,
            SecurityConfig::Tls(tls) => SecurityBackend::Standard(StandardTlsClient::with_options(
                context,
                &tls.server_name,
                TlsClientOptions {
                    ech: tls.ech.clone(),
                    client_fingerprint: tls.client_fingerprint,
                    versions: if tls.tls13_only {
                        TlsVersions::Tls13
                    } else {
                        TlsVersions::Tls12And13
                    },
                    alpn: tls.alpn.clone(),
                    required_alpn: tls.required_alpn.clone(),
                    certificate: tls.certificate.clone(),
                    identity: tls
                        .identity
                        .as_ref()
                        .map(|identity| {
                            super::TlsClientIdentity::from_pem(
                                &identity.certificate,
                                &identity.private_key,
                            )
                        })
                        .transpose()?,
                },
                resumption_sessions,
                buffer_limit,
            )?),
            SecurityConfig::Reality(reality) => SecurityBackend::Reality {
                client: super::boring::BoringTlsClient::reality(reality)?,
                buffer_limit,
            },
            SecurityConfig::Jls(jls) => SecurityBackend::Jls {
                client: super::boring::BoringTlsClient::jls(jls)?,
                buffer_limit,
            },
        };

        Ok(Self { backend })
    }

    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        match &self.backend {
            SecurityBackend::Plain => Ok(stream),
            SecurityBackend::Standard(client) => client.connect(stream).await,
            SecurityBackend::Reality {
                client,
                buffer_limit,
            }
            | SecurityBackend::Jls {
                client,
                buffer_limit,
            } => client.connect(stream, *buffer_limit).await,
        }
    }

    pub(crate) async fn connect_vision(
        &self,
        stream: BoxStream,
        stats: Arc<super::vision::SpliceStats>,
    ) -> io::Result<(BoxStream, super::vision::SpliceControl)> {
        match &self.backend {
            SecurityBackend::Plain => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Vision requires TLS",
            )),
            SecurityBackend::Jls { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Vision cannot use JLS",
            )),
            SecurityBackend::Standard(client) => client.connect_vision(stream, stats).await,
            SecurityBackend::Reality {
                client,
                buffer_limit,
            } => client.connect_vision(stream, stats, *buffer_limit).await,
        }
    }

    #[cfg(test)]
    const fn buffer_limit(&self) -> usize {
        match &self.backend {
            SecurityBackend::Plain => 0,
            SecurityBackend::Standard(client) => client.buffer_limit(),
            SecurityBackend::Reality { buffer_limit, .. }
            | SecurityBackend::Jls { buffer_limit, .. } => *buffer_limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SecurityConfig, TlsConfig, VlessEncryption, XHttpConfig, XHttpMode};

    fn tls_proxy() -> VlessOutboundConfig {
        VlessOutboundConfig {
            address: "example.com".to_owned(),
            port: 443,
            id: uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
            encryption: VlessEncryption::None,
            flow: String::new(),
            security: SecurityConfig::Tls(TlsConfig::xhttp("example.com".to_owned())),
            transport: crate::config::VlessTransport::Xhttp(Box::new(XHttpConfig {
                path: "/xhttp".to_owned(),
                host: "example.com".to_owned(),
                mode: XHttpMode::StreamOne,
                http_version: Default::default(),
                reuse: None,
                headers: Default::default(),
                request: Default::default(),
                download: None,
            })),
            packet_encoding: crate::config::VlessPacketEncoding::Xudp,
            stream_options: Default::default(),
        }
    }

    #[test]
    fn default_and_shared_clients_keep_distinct_tls_buffer_limits() {
        let config = tls_proxy();
        let default = SecurityClient::from_proxy(&config).unwrap();
        assert_eq!(default.buffer_limit(), 64 * 1024);

        let context = SecurityContext::new();
        let limited =
            SecurityClient::from_proxy_with_context(&config, &context, 4, 16 * 1024).unwrap();
        assert_eq!(limited.buffer_limit(), 16 * 1024);
        let without_resumption =
            SecurityClient::from_proxy_with_context(&config, &context, 0, 16 * 1024).unwrap();
        assert_eq!(without_resumption.buffer_limit(), 16 * 1024);
        assert!(SecurityClient::from_proxy_with_context(&config, &context, 4, 0).is_err());
    }

    #[test]
    fn security_level_constructor_matches_the_proxy_wrapper() {
        let config = tls_proxy();
        let direct = SecurityClient::from_security(&config.security).unwrap();
        let wrapped = SecurityClient::from_proxy(&config).unwrap();
        assert_eq!(direct.buffer_limit(), wrapped.buffer_limit());

        let context = SecurityContext::new();
        let direct =
            SecurityClient::from_security_with_context(&config.security, &context, 1, 8 * 1024)
                .unwrap();
        assert_eq!(direct.buffer_limit(), 8 * 1024);
    }

    #[test]
    fn security_level_constructor_keeps_an_independent_reality_identity() {
        let security = SecurityConfig::Reality(crate::config::RealityConfig {
            support_x25519mlkem768: false,
            client_fingerprint: None,
            server_name: "download.example.com".to_owned(),
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            alpn: vec![b"h2".to_vec()],
        });
        let client = SecurityClient::from_security_with_context(
            &security,
            &SecurityContext::new(),
            4,
            12 * 1024,
        )
        .unwrap();
        let SecurityBackend::Reality { buffer_limit, .. } = &client.backend else {
            panic!("REALITY security must build the REALITY backend")
        };
        assert_eq!(*buffer_limit, 12 * 1024);
        assert!(!format!("{client:?}").contains("download.example.com"));
    }
}
