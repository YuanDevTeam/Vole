use std::{io, sync::Arc};

use rustls::{
    ClientConfig,
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    version::{TLS12, TLS13},
};
use tokio_rustls::TlsConnector;

use crate::dispatch::BoxStream;

use super::SecurityContext;

pub(crate) const DEFAULT_TLS_BUFFER_LIMIT: usize = 64 * 1024;

/// Aggregate per-runtime cache budget shared across standard TLS nodes.
/// REALITY disables resumption and does not consume this budget.
pub const TLS_RESUMPTION_SESSION_BUDGET: usize = 4;

pub use crate::config::TlsCertificatePolicy;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TlsVersions {
    #[default]
    Tls12And13,
    Tls13,
}

/// Immutable per-node, per-transport TLS options. Constructing another client
/// always creates an independent resumption store, even for the same SNI.
#[derive(Default)]
pub struct TlsClientOptions {
    pub ech: Option<crate::config::StaticEchConfig>,
    pub client_fingerprint: Option<crate::config::ClientFingerprint>,
    pub versions: TlsVersions,
    pub alpn: Vec<Vec<u8>>,
    pub required_alpn: Option<Vec<u8>>,
    pub certificate: TlsCertificatePolicy,
    pub identity: Option<TlsClientIdentity>,
}

impl std::fmt::Debug for TlsClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientOptions")
            .field("client_fingerprint", &self.client_fingerprint)
            .field("versions", &self.versions)
            .field("alpn_count", &self.alpn.len())
            .field("requires_alpn", &self.required_alpn.is_some())
            .field("certificate", &self.certificate)
            .field("client_identity", &self.identity.is_some())
            .field("ech", &self.ech.is_some())
            .finish()
    }
}

impl TlsClientOptions {
    #[cfg(any(
        test,
        feature = "outbound-anytls",
        feature = "outbound-trojan",
        feature = "outbound-vmess",
        feature = "outbound-socks5"
    ))]
    pub(crate) fn from_policy(
        policy: &crate::config::TlsClientPolicy,
        required_alpn: Option<&[u8]>,
    ) -> io::Result<Self> {
        Ok(Self {
            client_fingerprint: policy.client_fingerprint,
            alpn: policy.alpn.clone(),
            required_alpn: required_alpn.map(<[u8]>::to_vec),
            certificate: policy.certificate.clone(),
            identity: policy
                .identity
                .as_ref()
                .map(|identity| {
                    TlsClientIdentity::from_pem(&identity.certificate, &identity.private_key)
                })
                .transpose()?,
            ..Default::default()
        })
    }
}

/// A node-owned certificate chain and matching key. The provider validates the
/// key pair while constructing the client, before any supplied stream is used.
/// No file loading, environment key logging or dynamic identity reload occurs.
pub struct TlsClientIdentity {
    pub(super) certificates: Vec<CertificateDer<'static>>,
    pub(super) key: PrivateKeyDer<'static>,
}

impl TlsClientIdentity {
    pub fn from_pem(certificate: &str, private_key: &str) -> io::Result<Self> {
        use rustls::pki_types::pem::PemObject;
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS client identity");
        if certificate.len().saturating_add(private_key.len()) > crate::config::MAX_CONFIG_BYTES {
            return Err(invalid());
        }
        let certificates = CertificateDer::pem_slice_iter(certificate.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        let mut keys = PrivateKeyDer::pem_slice_iter(private_key.as_bytes());
        let key = keys.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
        if keys.next().is_some() || certificates.is_empty() {
            return Err(invalid());
        }
        rustls::sign::CertifiedKey::from_der(
            certificates.clone(),
            key.clone_key(),
            &rustls::crypto::ring::default_provider(),
        )
        .map_err(|_| invalid())?;
        Ok(Self { certificates, key })
    }

    pub fn from_der(
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        Self { certificates, key }
    }
}

impl std::fmt::Debug for TlsClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientIdentity").finish_non_exhaustive()
    }
}

/// TLS protocol policy for a standard WebPKI client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum StandardTlsProfile {
    /// VLESS XHTTP is TLS 1.3 and HTTP/2 only.
    VlessXhttp,
}

/// Reusable standard TLS client shared by protocol-specific outbound code.
///
/// REALITY remains in [`super::SecurityClient`] with a distinct authentication
/// and session policy. Ordinary unprofiled TLS and QUIC continue to use rustls.
#[derive(Clone)]
pub struct StandardTlsClient {
    connector: StandardConnector,
    server_name: String,
    required_alpn: Option<Vec<u8>>,
    buffer_limit: usize,
    require_ech: bool,
}

#[derive(Clone)]
enum StandardConnector {
    Rustls(TlsConnector),
    #[cfg(feature = "tls-fingerprint")]
    Boring(super::boring::BoringTlsClient),
}

impl std::fmt::Debug for StandardTlsClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StandardTlsClient")
            .field("requires_alpn", &self.required_alpn.is_some())
            .field("buffer_limit", &self.buffer_limit)
            .finish_non_exhaustive()
    }
}

impl StandardTlsClient {
    #[cfg(any(
        feature = "outbound-vless",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic"
    ))]
    pub(crate) fn quic_config(&self) -> io::Result<(Arc<ClientConfig>, String)> {
        match &self.connector {
            StandardConnector::Rustls(connector) => {
                // XHTTP validates its exclusive h3 policy before construction.
                // Hysteria2 also uses H3 but permits a custom negotiated ALPN.
                if connector.config().alpn_protocols.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "QUIC requires ALPN",
                    ));
                }
                Ok((connector.config().clone(), self.server_name.clone()))
            }
            #[cfg(feature = "tls-fingerprint")]
            StandardConnector::Boring(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client-fingerprint is not supported on QUIC",
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        context: &SecurityContext,
        server_name: impl Into<String>,
        profile: StandardTlsProfile,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let options = match profile {
            StandardTlsProfile::VlessXhttp => TlsClientOptions {
                versions: TlsVersions::Tls13,
                alpn: vec![b"h2".to_vec()],
                required_alpn: Some(b"h2".to_vec()),
                ..Default::default()
            },
        };
        Self::with_options(
            context,
            server_name,
            options,
            resumption_sessions,
            buffer_limit,
        )
    }

    /// Wraps caller-supplied streams only: no socket, resolver, background task
    /// or unbounded shared cache is created here. The graph allocates ticket
    /// capacity from its existing aggregate budget; zero disables resumption.
    pub fn with_options(
        context: &SecurityContext,
        server_name: impl Into<String>,
        options: TlsClientOptions,
        resumption_sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let server_name = server_name.into();
        let name = ServerName::try_from(server_name.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let require_ech = options.ech.is_some();
        if require_ech && !matches!(name, ServerName::DnsName(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ECH requires a DNS server name",
            ));
        }
        #[cfg(not(feature = "outbound-vless"))]
        if require_ech {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ECH is not compiled in",
            ));
        }
        if buffer_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS buffer limit must be greater than zero",
            ));
        }
        if resumption_sessions > TLS_RESUMPTION_SESSION_BUDGET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS ticket capacity exceeds the runtime budget",
            ));
        }
        let alpn_size = options.alpn.iter().try_fold(0_usize, |size, protocol| {
            if !(1..=255).contains(&protocol.len()) {
                return None;
            }
            size.checked_add(1 + protocol.len())
                .filter(|total| *total <= 65_533)
        });
        if alpn_size.is_none()
            || options
                .required_alpn
                .as_ref()
                .is_some_and(|required| !options.alpn.contains(required))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TLS ALPN policy",
            ));
        }

        if options.client_fingerprint.is_some() {
            #[cfg(not(feature = "tls-fingerprint"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "client-fingerprint is not compiled in",
            ));
            #[cfg(feature = "tls-fingerprint")]
            {
                let client = super::boring::BoringTlsClient::standard(
                    context,
                    &server_name,
                    &options,
                    resumption_sessions,
                )?;
                return Ok(Self {
                    connector: StandardConnector::Boring(client),
                    server_name,
                    required_alpn: options.required_alpn,
                    buffer_limit,
                    require_ech,
                });
            }
        }

        let protocol_versions: &[&'static rustls::SupportedProtocolVersion] = match options.versions
        {
            TlsVersions::Tls13 => &[&TLS13],
            TlsVersions::Tls12And13 => &[&TLS13, &TLS12],
        };
        let builder = ClientConfig::builder_with_provider(context.provider.clone());
        #[cfg(feature = "outbound-vless")]
        let builder = if let Some(ech) = &options.ech {
            let ech = rustls::client::EchConfig::new(ech.as_bytes().into(), super::ech::SUITES)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid static ECH config")
                })?;
            builder.with_ech(ech.into()).map_err(io_other)?
        } else {
            builder
                .with_protocol_versions(protocol_versions)
                .map_err(io_other)?
        };
        #[cfg(not(feature = "outbound-vless"))]
        let builder = builder
            .with_protocol_versions(protocol_versions)
            .map_err(io_other)?;
        let builder = builder.with_root_certificates(context.tls_roots.clone());
        let mut config = if let Some(identity) = options.identity {
            let identity_size = identity
                .certificates
                .iter()
                .try_fold(identity.key.secret_der().len(), |size, cert| {
                    size.checked_add(cert.len())
                });
            if identity_size.is_none_or(|size| size > crate::config::MAX_CONFIG_BYTES) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS client identity exceeds the configuration bound",
                ));
            }
            builder
                .with_client_auth_cert(identity.certificates, identity.key)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS client identity")
                })?
        } else {
            builder.with_no_client_auth()
        };
        config.resumption = if resumption_sessions == 0 || require_ech {
            Resumption::disabled()
        } else {
            Resumption::store(Arc::new(super::resumption::NodeSessionStore::new(
                name,
                resumption_sessions,
            )))
        };

        config.alpn_protocols = options.alpn;
        config.dangerous().set_certificate_verifier(Arc::new(
            super::verifier::CertificateVerifier::new(context, options.certificate)?,
        ));

        Ok(Self {
            connector: StandardConnector::Rustls(TlsConnector::from(Arc::new(config))),
            server_name,
            required_alpn: options.required_alpn,
            buffer_limit,
            require_ech,
        })
    }

    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        let connector = match &self.connector {
            StandardConnector::Rustls(connector) => connector,
            #[cfg(feature = "tls-fingerprint")]
            StandardConnector::Boring(client) => {
                return client.connect(stream, self.buffer_limit).await;
            }
        };
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let tls = connector
            .connect_with(server_name, stream, |connection| {
                connection.set_buffer_limit(Some(self.buffer_limit));
            })
            .await
            .map_err(|error| io::Error::new(error.kind(), "TLS handshake failed"))?;

        if self.require_ech && tls.get_ref().1.ech_status() != rustls::client::EchStatus::Accepted {
            return Err(io::Error::other("TLS ECH was not accepted"));
        }

        if let Some(required_alpn) = self.required_alpn.as_deref()
            && tls.get_ref().1.alpn_protocol() != Some(required_alpn)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS server did not negotiate the required ALPN",
            ));
        }

        Ok(Box::new(super::stream::TlsStream::new(tls)))
    }

    #[cfg(feature = "outbound-vless")]
    pub(crate) async fn connect_vision(
        &self,
        stream: BoxStream,
        stats: Arc<super::vision::SpliceStats>,
    ) -> io::Result<(BoxStream, super::vision::SpliceControl)> {
        if self.require_ech {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Vision with ECH is not supported",
            ));
        }
        let connector = match &self.connector {
            StandardConnector::Rustls(connector) => connector,
            StandardConnector::Boring(client) => {
                return client
                    .connect_vision(stream, stats, self.buffer_limit)
                    .await;
            }
        };
        let name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let tls = connector
            .connect_with(name, super::vision::RecordIo::new(stream), |connection| {
                connection.set_buffer_limit(Some(self.buffer_limit))
            })
            .await
            .map_err(|error| io::Error::new(error.kind(), "Vision TLS handshake failed"))?;
        if self
            .required_alpn
            .as_deref()
            .is_some_and(|required| tls.get_ref().1.alpn_protocol() != Some(required))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS server did not negotiate the required ALPN",
            ));
        }
        super::vision::SpliceTls::wrap(tls, stats)
    }

    #[cfg(test)]
    pub(super) const fn buffer_limit(&self) -> usize {
        self.buffer_limit
    }
}

fn io_other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
