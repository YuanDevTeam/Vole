use std::{
    io,
    sync::{Arc, Mutex},
};

use rustls::{
    ClientConfig,
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    version::{TLS12, TLS13},
};
use tokio_rustls::TlsConnector;

use crate::dispatch::BoxStream;

use super::SecurityContext;
use super::identity::{ClientIdentitySource, IdentityEpoch, IdentityMaterial, IdentitySnapshot};

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
#[derive(Default, Clone)]
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
        context: &SecurityContext,
    ) -> io::Result<Self> {
        Ok(Self {
            ech: policy.ech.clone(),
            client_fingerprint: policy.client_fingerprint,
            alpn: policy.alpn.clone(),
            required_alpn: required_alpn.map(<[u8]>::to_vec),
            certificate: policy.certificate.clone(),
            identity: policy
                .identity
                .as_ref()
                .map(|identity| TlsClientIdentity::from_config(identity, context))
                .transpose()?,
            ..Default::default()
        })
    }
}

/// Parsed inline material or an explicitly registered file-backed identity.
/// Handshakes only snapshot published material; they never read a file.
#[derive(Clone)]
pub struct TlsClientIdentity {
    storage: IdentityStorage,
    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    native: Option<Arc<NativeIdentityClient>>,
}

#[derive(Clone)]
enum IdentityStorage {
    Inline(Arc<IdentityMaterial>),
    Files(Arc<ClientIdentitySource>),
}

#[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
struct NativeIdentityClient {
    identity: TlsClientIdentity,
    current: Mutex<Option<(u64, Arc<super::identity::NativeIdentity>)>>,
    _lease: Option<Arc<()>>,
}

#[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
impl NativeIdentityClient {
    fn snapshot(&self) -> io::Result<IdentitySnapshot> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("TLS identity unavailable"))?;
        let mut snapshot = self.identity.snapshot();
        let native = match current.as_ref() {
            Some((generation, native)) if *generation == snapshot.epoch.generation() => {
                native.clone()
            }
            _ => {
                let native = snapshot.material.native()?;
                *current = Some((snapshot.epoch.generation(), native.clone()));
                native
            }
        };
        snapshot.native = Some(native);
        Ok(snapshot)
    }
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
        let identity = Self::from_der(certificates, key);
        identity.snapshot().material.validate()?;
        Ok(identity)
    }

    pub fn from_der(
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            storage: IdentityStorage::Inline(Arc::new(IdentityMaterial::new(certificates, key))),
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            native: None,
        }
    }

    pub(crate) fn from_config(
        identity: &crate::config::TlsIdentityPem,
        context: &SecurityContext,
    ) -> io::Result<Self> {
        let initial = Self::from_pem(&identity.certificate, &identity.private_key)?;
        let Some(origin) = &identity.origin else {
            return Ok(initial);
        };
        let material = initial.snapshot().material;
        material.validate()?;
        let source = context.identities.register(
            origin,
            material,
            identity
                .certificate
                .len()
                .saturating_add(identity.private_key.len()),
        )?;
        Ok(Self {
            storage: IdentityStorage::Files(source),
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            native: None,
        })
    }

    pub(super) fn snapshot(&self) -> IdentitySnapshot {
        match &self.storage {
            IdentityStorage::Inline(material) => IdentitySnapshot {
                material: material.clone(),
                epoch: IdentityEpoch::default(),
                #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
                native: None,
            },
            IdentityStorage::Files(source) => source.snapshot(),
        }
    }

    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    pub(super) fn native_snapshot(&self) -> io::Result<IdentitySnapshot> {
        self.for_native()?.native.as_ref().unwrap().snapshot()
    }

    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    pub(super) fn for_native(&self) -> io::Result<Self> {
        if self.native.is_some() {
            return Ok(self.clone());
        }
        let lease = match &self.storage {
            IdentityStorage::Files(source) => Some(source.native_lease()?),
            IdentityStorage::Inline(_) => None,
        };
        let client = Arc::new(NativeIdentityClient {
            identity: self.clone(),
            current: Mutex::new(None),
            _lease: lease,
        });
        client.snapshot()?;
        Ok(Self {
            storage: self.storage.clone(),
            native: Some(client),
        })
    }

    fn reloadable(&self) -> bool {
        matches!(self.storage, IdentityStorage::Files(_))
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
/// and session policy. Unprofiled stream TLS and Quinn continue to use rustls.
#[derive(Clone)]
pub struct StandardTlsClient {
    connector: Option<StandardConnector>,
    rustls_identity: Option<Arc<RustlsIdentityClient>>,
    server_name: String,
    required_alpn: Option<Vec<u8>>,
    buffer_limit: usize,
    require_ech: bool,
    dynamic_ech: Option<Arc<DynamicEchTls>>,
    #[cfg(feature = "quiche-h3-transport")]
    quiche_source: Option<Arc<QuicheSource>>,
}

struct RustlsIdentityClient {
    identity: TlsClientIdentity,
    current: Mutex<(u64, Arc<ClientConfig>)>,
    sessions: Option<Arc<super::resumption::NodeSessionStore>>,
}

impl RustlsIdentityClient {
    fn connector(&self) -> io::Result<TlsConnector> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("TLS identity unavailable"))?;
        let snapshot = self.identity.snapshot();
        if current.0 != snapshot.epoch.generation() {
            let mut config = (*current.1).clone();
            config.client_auth_cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(
                snapshot.material.certified_key()?,
            ));
            config.resumption = self
                .sessions
                .as_ref()
                .map_or_else(Resumption::disabled, |store| {
                    Resumption::store(store.for_epoch(snapshot.epoch.clone()))
                });
            *current = (snapshot.epoch.generation(), Arc::new(config));
        }
        Ok(TlsConnector::from(current.1.clone()))
    }
}

#[cfg(feature = "quiche-h3-transport")]
struct QuicheSource {
    context: SecurityContext,
    options: Mutex<TlsClientOptions>,
}

struct DynamicEchTls {
    context: SecurityContext,
    options: TlsClientOptions,
}

#[derive(Clone)]
enum StandardConnector {
    Rustls(TlsConnector),
    #[cfg(feature = "tls-fingerprint")]
    Boring(Arc<super::boring::BoringTlsClient>),
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
    #[cfg(feature = "quiche-h3-transport")]
    pub(crate) fn prepare_quiche_identity(&self) -> io::Result<()> {
        if let Some(source) = &self.quiche_source {
            let mut options = source
                .options
                .lock()
                .map_err(|_| io::Error::other("TLS identity unavailable"))?;
            options.identity = options
                .identity
                .as_ref()
                .map(TlsClientIdentity::for_native)
                .transpose()?;
        }
        Ok(())
    }

    #[cfg(feature = "quiche-h3-transport")]
    pub(crate) fn quiche_config(&self) -> io::Result<super::QuicheTls> {
        if self.dynamic_ech.is_some() {
            return Err(io::Error::other(
                "dynamic ECH requires a node resolution context",
            ));
        }
        let source = self
            .quiche_source
            .as_ref()
            .ok_or_else(|| io::Error::other("HTTP/3 requires H3 ALPN"))?;
        self.prepare_quiche_identity()?;
        let options = source
            .options
            .lock()
            .map_err(|_| io::Error::other("TLS identity unavailable"))?
            .clone();
        super::QuicheTls::standard(&source.context, &self.server_name, &options)
    }

    #[cfg(feature = "quiche-h3-transport")]
    pub(crate) async fn quiche_config_with_context(
        &self,
        context: &crate::outbound::EstablishContext,
    ) -> io::Result<super::QuicheTls> {
        let Some(dynamic) = &self.dynamic_ech else {
            return self.quiche_config();
        };
        self.prepare_quiche_identity()?;
        let source = self
            .quiche_source
            .as_ref()
            .ok_or_else(|| io::Error::other("HTTP/3 requires H3 ALPN"))?;
        let mut options = source
            .options
            .lock()
            .map_err(|_| io::Error::other("TLS identity unavailable"))?
            .clone();
        options.ech = Some(
            dynamic
                .options
                .ech
                .as_ref()
                .expect("dynamic ECH source")
                .for_backend(true)
                .map_err(|_| io::Error::other("ECH has no compatible QUIC configuration"))?
                .resolve(&self.server_name, context)
                .await?,
        );
        super::QuicheTls::standard(&dynamic.context, &self.server_name, &options)
    }

    #[cfg(feature = "quic-transport")]
    pub(crate) fn quic_config(&self) -> io::Result<(Arc<ClientConfig>, String)> {
        if self.dynamic_ech.is_some() {
            return Err(io::Error::other(
                "dynamic ECH requires a node resolution context",
            ));
        }
        match &self.current_connector()? {
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
        let mut options = options;
        if let Some(identity) = &options.identity {
            identity.snapshot().material.validate()?;
        }
        options.ech = options
            .ech
            .as_ref()
            .map(|ech| ech.for_backend(options.client_fingerprint.is_some()))
            .transpose()
            .map_err(|_| io::Error::other("ECH has no compatible configuration"))?;
        let require_ech = options.ech.is_some();
        if require_ech && !matches!(name, ServerName::DnsName(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ECH requires a DNS server name",
            ));
        }
        #[cfg(not(feature = "ech"))]
        if require_ech {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ECH is not compiled in",
            ));
        }
        if options
            .ech
            .as_ref()
            .is_some_and(crate::config::StaticEchConfig::is_dynamic)
        {
            #[cfg(feature = "tls-fingerprint")]
            if options.client_fingerprint.is_some() {
                // DNS resolution rebuilds only ECH's physical TLS context.
                // The node's native identity owner/cache survives those builds.
                options.identity = options
                    .identity
                    .as_ref()
                    .map(TlsClientIdentity::for_native)
                    .transpose()?;
            }
            let mut plain = options.clone();
            plain.ech = None;
            plain.versions = TlsVersions::Tls13;
            let mut client = Self::with_options(context, server_name, plain, 0, buffer_limit)?;
            client.require_ech = true;
            client.dynamic_ech = Some(Arc::new(DynamicEchTls {
                context: context.clone(),
                options,
            }));
            return Ok(client);
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

        #[cfg(feature = "quiche-h3-transport")]
        let quiche_source = options
            .alpn
            .iter()
            .any(|protocol| protocol == b"h3")
            .then(|| {
                Arc::new(QuicheSource {
                    context: context.clone(),
                    options: Mutex::new(options.clone()),
                })
            });

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
                    connector: Some(StandardConnector::Boring(Arc::new(client))),
                    rustls_identity: None,
                    server_name,
                    required_alpn: options.required_alpn,
                    buffer_limit,
                    require_ech,
                    dynamic_ech: None,
                    #[cfg(feature = "quiche-h3-transport")]
                    quiche_source,
                });
            }
        }

        let protocol_versions: &[&'static rustls::SupportedProtocolVersion] = match options.versions
        {
            TlsVersions::Tls13 => &[&TLS13],
            TlsVersions::Tls12And13 => &[&TLS13, &TLS12],
        };
        let builder = ClientConfig::builder_with_provider(context.provider.clone());
        #[cfg(feature = "ech")]
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
        #[cfg(not(feature = "ech"))]
        let builder = builder
            .with_protocol_versions(protocol_versions)
            .map_err(io_other)?;
        let builder = builder.with_root_certificates(context.tls_roots.clone());
        let identity_snapshot = options.identity.as_ref().map(TlsClientIdentity::snapshot);
        let mut config = if let Some(identity) = &identity_snapshot {
            builder.with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                identity.material.certified_key()?,
            )))
        } else {
            builder.with_no_client_auth()
        };
        let sessions = (resumption_sessions != 0 && !require_ech).then(|| {
            Arc::new(super::resumption::NodeSessionStore::new(
                name,
                resumption_sessions,
            ))
        });
        config.resumption = sessions
            .as_ref()
            .map_or_else(Resumption::disabled, |store| {
                Resumption::store(
                    store.for_epoch(
                        identity_snapshot
                            .as_ref()
                            .map(|identity| identity.epoch.clone())
                            .unwrap_or_default(),
                    ),
                )
            });

        config.alpn_protocols = options.alpn;
        config.dangerous().set_certificate_verifier(Arc::new(
            super::verifier::CertificateVerifier::new(context, options.certificate)?,
        ));

        let config = Arc::new(config);
        let rustls_identity =
            options
                .identity
                .filter(TlsClientIdentity::reloadable)
                .map(|identity| {
                    Arc::new(RustlsIdentityClient {
                        identity,
                        current: Mutex::new((
                            identity_snapshot.as_ref().unwrap().epoch.generation(),
                            config.clone(),
                        )),
                        sessions,
                    })
                });
        Ok(Self {
            connector: rustls_identity
                .is_none()
                .then(|| StandardConnector::Rustls(TlsConnector::from(config))),
            rustls_identity,
            server_name,
            required_alpn: options.required_alpn,
            buffer_limit,
            require_ech,
            dynamic_ech: None,
            #[cfg(feature = "quiche-h3-transport")]
            quiche_source,
        })
    }

    fn current_connector(&self) -> io::Result<StandardConnector> {
        self.rustls_identity.as_ref().map_or_else(
            || {
                self.connector
                    .clone()
                    .ok_or_else(|| io::Error::other("TLS connector unavailable"))
            },
            |identity| identity.connector().map(StandardConnector::Rustls),
        )
    }

    async fn resolved(&self, context: &crate::outbound::EstablishContext) -> io::Result<Self> {
        let Some(dynamic) = &self.dynamic_ech else {
            return Ok(self.clone());
        };
        let mut options = dynamic.options.clone();
        options.ech = Some(
            options
                .ech
                .as_ref()
                .expect("dynamic ECH source")
                .resolve(&self.server_name, context)
                .await?,
        );
        Self::with_options(
            &dynamic.context,
            &self.server_name,
            options,
            0,
            self.buffer_limit,
        )
    }

    pub(crate) async fn connect_with_context(
        &self,
        stream: BoxStream,
        context: &crate::outbound::EstablishContext,
    ) -> io::Result<BoxStream> {
        self.resolved(context).await?.connect(stream).await
    }

    #[cfg(any(
        feature = "outbound-vless",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "outbound-trusttunnel"
    ))]
    pub(crate) async fn quic_config_with_context(
        &self,
        context: &crate::outbound::EstablishContext,
    ) -> io::Result<(Arc<ClientConfig>, String)> {
        self.resolved(context).await?.quic_config()
    }

    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        self.connect_negotiated(stream)
            .await
            .map(|(stream, _)| stream)
    }

    /// Returns the authenticated stream and the server's actual ALPN choice.
    /// Existing required-ALPN/ECH checks apply before either becomes visible.
    pub async fn connect_negotiated(
        &self,
        stream: BoxStream,
    ) -> io::Result<(BoxStream, Option<Vec<u8>>)> {
        if self.dynamic_ech.is_some() {
            return Err(io::Error::other(
                "dynamic ECH requires a node resolution context",
            ));
        }
        let current = self.current_connector()?;
        let connector = match &current {
            StandardConnector::Rustls(connector) => connector,
            #[cfg(feature = "tls-fingerprint")]
            StandardConnector::Boring(client) => {
                return client.connect_negotiated(stream, self.buffer_limit).await;
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

        let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        Ok((Box::new(super::stream::TlsStream::new(tls)), alpn))
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
        let current = self.current_connector()?;
        let connector = match &current {
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
