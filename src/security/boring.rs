//! Named TLS profiles over caller-supplied IO. Certificate policy is shared with
//! rustls, not a second OpenSSL trust policy. This module never resolves or dials.
use super::boring_stream::{BoringStream, KeepOpen};
use super::{SecurityContext, TlsClientIdentity, TlsClientOptions, TlsVersions};
use crate::dispatch::BoxStream;
use boring::ssl::{
    ClientFingerprint, ConnectConfiguration, FingerprintConnector, SslAlert, SslConnector,
    SslMethod, SslVerifyError, SslVerifyMode, SslVersion,
};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone)]
pub(super) struct BoringTlsClient {
    connector: Connector,
    server_name: String,
    alpn: Vec<u8>,
    required_alpn: Option<Vec<u8>>,
    sessions: super::boring_resumption::Sessions,
    identity: Option<TlsClientIdentity>,
    ech: Option<crate::config::StaticEchConfig>,
    #[cfg(feature = "stream-security")]
    reality: Option<boring::ssl::RealityClientConfig>,
    #[cfg(feature = "stream-security")]
    jls: Option<Arc<JlsCredentials>>,
}

#[cfg(feature = "stream-security")]
struct JlsCredentials {
    username: zeroize::Zeroizing<Vec<u8>>,
    password: zeroize::Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
enum Connector {
    Default(SslConnector),
    Named(FingerprintConnector),
}
impl Connector {
    fn configure(&self, alpn: &[u8]) -> Result<ConnectConfiguration, boring::error::ErrorStack> {
        match self {
            Self::Default(connector) => {
                let mut config = connector.configure()?;
                config.set_alpn_protos(alpn)?;
                Ok(config)
            }
            Self::Named(connector) => connector.configure_with_application_settings(alpn, false),
        }
    }
}

impl BoringTlsClient {
    pub(super) fn standard(
        context: &SecurityContext,
        server_name: &str,
        options: &TlsClientOptions,
        capacity: usize,
    ) -> io::Result<Self> {
        let identity = options
            .identity
            .as_ref()
            .map(TlsClientIdentity::for_native)
            .transpose()?;
        if let Some(identity) = &identity {
            identity.native_snapshot()?.material.validate()?;
        }
        if (options.ech.is_some() || options.versions == TlsVersions::Tls13)
            && options
                .client_fingerprint
                .is_some_and(|profile| !profile.supports_tls13())
        {
            return Err(invalid());
        }
        let name = ServerName::try_from(server_name.to_owned()).map_err(|_| invalid())?;
        let verifier = Arc::new(super::verifier::CertificateVerifier::new(
            context,
            options.certificate.clone(),
        )?);
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| invalid())?;
        builder
            .set_min_proto_version(Some(
                match if options.ech.is_some() {
                    TlsVersions::Tls13
                } else {
                    options.versions
                } {
                    TlsVersions::Tls13 => SslVersion::TLS1_3,
                    TlsVersions::Tls12And13 => SslVersion::TLS1_2,
                },
            ))
            .map_err(|_| invalid())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| invalid())?;
        let sessions = super::boring_resumption::Sessions::new(
            &mut builder,
            if options.ech.is_some() { 0 } else { capacity },
        )?;
        let rejection_verifier =
            super::verifier::CertificateVerifier::new(context, Default::default())?;
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let reject = || SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE);
            let chain = ssl.peer_cert_chain().ok_or_else(reject)?;
            let certificates = chain
                .iter()
                .map(|cert| cert.to_der().map(CertificateDer::from))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| reject())?;
            let (leaf, rest) = certificates.split_first().ok_or_else(reject)?;
            let outer_name = ssl.get_ech_name_override().map(|bytes| {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|name| ServerName::try_from(name.to_owned()).ok())
            });
            let (verifier, name): (&dyn ServerCertVerifier, _) = match outer_name {
                Some(Some(outer)) => (&rejection_verifier, outer),
                Some(None) => return Err(reject()),
                None => (verifier.as_ref(), name.clone()),
            };
            verifier
                .verify_server_cert(
                    leaf,
                    rest,
                    &name,
                    ssl.ocsp_status().unwrap_or_default(),
                    UnixTime::now(),
                )
                .map(|_| ())
                .map_err(|_| reject())
        });
        let connector = match options.client_fingerprint {
            Some(value) => Connector::Named(
                FingerprintConnector::new(builder, profile(value)).map_err(|_| invalid())?,
            ),
            None => Connector::Default(builder.build()),
        };
        let alpn = wire_alpn(&options.alpn)?;
        Ok(Self {
            connector,
            server_name: server_name.to_owned(),
            alpn,
            required_alpn: options.required_alpn.clone(),
            sessions,
            identity,
            ech: options.ech.clone(),
            #[cfg(feature = "stream-security")]
            reality: None,
            #[cfg(feature = "stream-security")]
            jls: None,
        })
    }

    #[cfg(feature = "stream-security")]
    pub(super) fn reality(config: &crate::config::RealityConfig) -> io::Result<Self> {
        config.validate_fingerprint().map_err(|_| invalid())?;
        ServerName::try_from(config.server_name.to_owned()).map_err(|_| invalid())?;
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| invalid())?;
        builder
            // A named REALITY hello preserves the template's TLS1.2 fields,
            // as Mihomo does. Native REALITY independently rejects every
            // pre-TLS1.3 ServerHello before certificate/application processing.
            .set_min_proto_version(Some(if config.client_fingerprint.is_some() {
                SslVersion::TLS1_2
            } else {
                SslVersion::TLS1_3
            }))
            .map_err(|_| invalid())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| invalid())?;
        builder
            .set_curves_list(if config.support_x25519mlkem768 {
                "X25519MLKEM768:X25519"
            } else {
                "X25519"
            })
            .map_err(|_| invalid())?;
        let sessions = super::boring_resumption::Sessions::new(&mut builder, 0)?;
        let connector = match config.client_fingerprint {
            Some(value) => Connector::Named(
                FingerprintConnector::new(builder, profile(value)).map_err(|_| invalid())?,
            ),
            None => Connector::Default(builder.build()),
        };
        let reality = boring::ssl::RealityClientConfig::new(
            config.public_key,
            &config.short_id,
            super::REALITY_CLIENT_VERSION,
        )
        .map_err(|_| invalid())?;
        let reality = if config.support_x25519mlkem768 {
            reality.allow_x25519mlkem768()
        } else {
            reality
        };
        Ok(Self {
            connector,
            server_name: config.server_name.clone(),
            alpn: wire_alpn(&config.alpn)?,
            // REALITY peers can omit negotiated ALPN. XHTTP retains the
            // configured HTTP version; no ordinary PKI fallback is permitted.
            required_alpn: None,
            sessions,
            identity: None,
            ech: None,
            reality: Some(reality),
            jls: None,
        })
    }

    #[cfg(feature = "stream-security")]
    pub(super) fn jls(config: &crate::config::JlsConfig) -> io::Result<Self> {
        config.validate().map_err(|_| invalid())?;
        ServerName::try_from(config.tls.server_name.to_owned()).map_err(|_| invalid())?;
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| invalid())?;
        // Retain the advertised template floor. Native JLS independently
        // requires an authenticated TLS 1.3 result, including CV and Finished.
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|_| invalid())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| invalid())?;
        let sessions = super::boring_resumption::Sessions::new(&mut builder, 0)?;
        let connector = match config.tls.client_fingerprint {
            Some(value) => Connector::Named(
                FingerprintConnector::new(builder, profile(value)).map_err(|_| invalid())?,
            ),
            None => Connector::Default(builder.build()),
        };
        Ok(Self {
            connector,
            server_name: config.tls.server_name.clone(),
            alpn: wire_alpn(&config.tls.alpn)?,
            required_alpn: config.tls.required_alpn.clone(),
            sessions,
            identity: None,
            ech: None,
            reality: None,
            jls: Some(Arc::new(JlsCredentials {
                username: config.username.as_bytes().to_vec().into(),
                password: config.password.as_bytes().to_vec().into(),
            })),
        })
    }

    pub(super) async fn connect(
        &self,
        stream: BoxStream,
        buffer_limit: usize,
    ) -> io::Result<BoxStream> {
        self.connect_negotiated(stream, buffer_limit)
            .await
            .map(|(stream, _)| stream)
    }

    pub(super) async fn connect_negotiated(
        &self,
        stream: BoxStream,
        buffer_limit: usize,
    ) -> io::Result<(BoxStream, Option<Vec<u8>>)> {
        self.connect_negotiated_with_policy(stream, buffer_limit, false)
            .await
    }

    pub(super) async fn connect_negotiated_with_policy(
        &self,
        stream: BoxStream,
        buffer_limit: usize,
        allow_missing_alpn: bool,
    ) -> io::Result<(BoxStream, Option<Vec<u8>>)> {
        let tls = self
            .handshake_configured_with_policy(stream, |_| Ok(()), allow_missing_alpn)
            .await?;
        let alpn = tls.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
        Ok((Box::new(BoringStream::new(tls, buffer_limit)), alpn))
    }

    #[cfg(feature = "outbound-vless")]
    pub(super) async fn connect_vision(
        &self,
        stream: BoxStream,
        stats: Arc<super::vision::SpliceStats>,
        buffer_limit: usize,
    ) -> io::Result<(BoxStream, super::vision::SpliceControl)> {
        let tls = self.handshake(super::vision::RecordIo::new(stream)).await?;
        super::vision::BoringSplice::wrap(tls, stats, buffer_limit)
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> io::Result<tokio_boring::SslStream<KeepOpen<S>>> {
        self.handshake_configured(stream, |_| Ok(())).await
    }

    pub(super) async fn handshake_configured<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        configure: impl FnOnce(&mut ConnectConfiguration) -> io::Result<()>,
    ) -> io::Result<tokio_boring::SslStream<KeepOpen<S>>> {
        self.handshake_configured_with_policy(stream, configure, false)
            .await
    }

    async fn handshake_configured_with_policy<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        configure: impl FnOnce(&mut ConnectConfiguration) -> io::Result<()>,
        allow_missing_alpn: bool,
    ) -> io::Result<tokio_boring::SslStream<KeepOpen<S>>> {
        let mut config = self
            .connector
            .configure(&self.alpn)
            .map_err(|_| invalid())?;
        // The shared WebPKI verifier owns name checking, including independent
        // verification names and pin precedence; wire SNI still uses server_name.
        config.set_verify_hostname(false);
        // Read one identity generation for this physical handshake. The SSL
        // object owns its certificate/key references after installation; a
        // later rotation cannot rewrite a handshake already in progress.
        let identity = self
            .identity
            .as_ref()
            .map(TlsClientIdentity::native_snapshot)
            .transpose()?;
        if let Some(identity) = &identity {
            let material = &identity.material;
            let size = material
                .certificates
                .iter()
                .try_fold(material.key.secret_der().len(), |size, cert| {
                    size.checked_add(cert.len())
                });
            if size.is_none_or(|n| n > crate::config::MAX_CONFIG_BYTES) {
                return Err(invalid());
            }
            let native = identity.native.as_ref().ok_or_else(invalid)?;
            let (leaf, rest) = native.certificates.split_first().ok_or_else(invalid)?;
            config.set_certificate(leaf).map_err(|_| invalid())?;
            for cert in rest {
                config.add_chain_cert(cert).map_err(|_| invalid())?;
            }
            config.set_private_key(&native.key).map_err(|_| invalid())?;
        }
        let epoch = identity.map(|snapshot| snapshot.epoch).unwrap_or_default();
        let sink = self.sessions.configure(&mut config, epoch)?;
        if let Some(ech) = &self.ech {
            config
                .set_ech_config_list(ech.as_bytes())
                .map_err(|_| invalid())?;
        }
        #[cfg(feature = "stream-security")]
        if let Some(reality) = &self.reality {
            config.set_reality_client(reality).map_err(|_| invalid())?;
        }
        #[cfg(feature = "stream-security")]
        if let Some(jls) = &self.jls {
            config
                .set_jls_client(&jls.username, &jls.password)
                .map_err(|_| invalid())?;
        }
        configure(&mut config)?;
        let tls = tokio_boring::connect(config, &self.server_name, KeepOpen(stream))
            .await
            .map_err(|_| io::Error::other("TLS handshake failed"))?;
        if self.ech.is_some() && !tls.ssl().ech_accepted() {
            return Err(io::Error::other("TLS ECH was not accepted"));
        }
        super::tls::validate_alpn(
            self.required_alpn.as_deref(),
            tls.ssl().selected_alpn_protocol(),
            allow_missing_alpn,
        )?;
        // The HTTP drivers use on-wire SETTINGS and do not import ALPS into
        // their initial state. Never silently accept nonempty peer settings.
        if tls
            .ssl()
            .peer_application_settings()
            .is_some_and(|settings| !settings.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "nonempty TLS ALPS settings are not supported",
            ));
        }
        sink.accept()?;
        Ok(tls)
    }
}

fn profile(value: crate::config::ClientFingerprint) -> ClientFingerprint {
    match value {
        crate::config::ClientFingerprint::Chrome133 => ClientFingerprint::Chrome133,
        crate::config::ClientFingerprint::Firefox120 => ClientFingerprint::Firefox120,
        crate::config::ClientFingerprint::Safari16 => ClientFingerprint::Safari16,
        crate::config::ClientFingerprint::Ios14 => ClientFingerprint::Ios14,
        crate::config::ClientFingerprint::Android11 => ClientFingerprint::Android11,
        crate::config::ClientFingerprint::Edge85 => ClientFingerprint::Edge85,
        crate::config::ClientFingerprint::ThreeSixty75 => ClientFingerprint::ThreeSixty75,
        crate::config::ClientFingerprint::Qq111 => ClientFingerprint::Qq111,
    }
}

fn wire_alpn(protocols: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let mut wire = Vec::new();
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > 255 || wire.len() + 1 + protocol.len() > 65_533 {
            return Err(invalid());
        }
        wire.push(protocol.len() as u8);
        wire.extend_from_slice(protocol);
    }
    Ok(wire)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid fingerprinted TLS policy",
    )
}
