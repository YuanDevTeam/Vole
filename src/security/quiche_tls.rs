//! QUIC TLS over the shared certificate policy and immutable identity material.
//! The native backend owns handshake signatures; WebPKI still owns trust.
use std::{io, sync::Arc};

use boring::{
    pkey::PKey,
    ssl::{
        SslAlert, SslContextBuilder, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyError,
        SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};

use super::{SecurityContext, TlsClientOptions};

const CERTIFICATE_BOUND: usize = 128 * 1024;

/// A single physical connection's immutable policy and one-use TLS builder.
/// Configure the connection before sending its first packet, then check the
/// negotiated policy before publishing any application stream.
pub(crate) struct QuicheTls {
    builder: Option<SslContextBuilder>,
    server_name: String,
    alpn: Vec<Vec<u8>>,
    required_alpn: Option<Vec<u8>>,
    ech: Option<crate::config::StaticEchConfig>,
}

impl std::fmt::Debug for QuicheTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicheTls")
            .field("requires_ech", &self.ech.is_some())
            .field("requires_alpn", &self.required_alpn.is_some())
            .finish_non_exhaustive()
    }
}

impl QuicheTls {
    pub(super) fn standard(
        context: &SecurityContext,
        server_name: &str,
        options: &TlsClientOptions,
    ) -> io::Result<Self> {
        let name = ServerName::try_from(server_name.to_owned()).map_err(|_| invalid())?;
        if options.client_fingerprint.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client-fingerprint is not supported on QUIC",
            ));
        }
        let ech = options
            .ech
            .as_ref()
            .map(|ech| ech.for_backend(true))
            .transpose()
            .map_err(|_| io::Error::other("ECH has no compatible QUIC configuration"))?;
        #[cfg(not(feature = "ech"))]
        if ech.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ECH is not compiled in",
            ));
        }
        if ech.as_ref().is_some_and(|ech| ech.is_dynamic()) {
            return Err(io::Error::other(
                "dynamic ECH requires a node resolution context",
            ));
        }
        if ech.is_some() && !matches!(name, ServerName::DnsName(_)) {
            return Err(invalid());
        }
        let verifier = Arc::new(super::verifier::CertificateVerifier::new(
            context,
            options.certificate.clone(),
        )?);
        let rejection_verifier =
            super::verifier::CertificateVerifier::new(context, Default::default())?;
        let mut builder = Self::builder()?;
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let reject = || SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE);
            let certificates = peer_certificates(ssl).map_err(|_| reject())?;
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
        if let Some(identity) = &options.identity {
            let size = identity
                .certificates
                .iter()
                .try_fold(identity.key.secret_der().len(), |size, cert| {
                    size.checked_add(cert.len())
                });
            if size.is_none_or(|size| size > crate::config::MAX_CONFIG_BYTES) {
                return Err(invalid());
            }
            let (leaf, rest) = identity.certificates.split_first().ok_or_else(invalid)?;
            let leaf = X509::from_der(leaf).map_err(|_| invalid())?;
            builder.set_certificate(&leaf).map_err(|_| invalid())?;
            for cert in rest {
                builder
                    .add_extra_chain_cert(X509::from_der(cert).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
            }
            let key =
                PKey::private_key_from_der(identity.key.secret_der()).map_err(|_| invalid())?;
            builder.set_private_key(&key).map_err(|_| invalid())?;
            builder.check_private_key().map_err(|_| invalid())?;
        }
        Self::from_builder(
            builder,
            server_name.to_owned(),
            options.alpn.clone(),
            options.required_alpn.clone(),
            ech,
        )
    }

    pub(super) fn builder() -> io::Result<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(|_| invalid())?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| invalid())?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|_| invalid())?;
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        builder.set_options(SslOptions::NO_TICKET);
        Ok(builder)
    }

    pub(super) fn from_builder(
        builder: SslContextBuilder,
        server_name: String,
        alpn: Vec<Vec<u8>>,
        required_alpn: Option<Vec<u8>>,
        ech: Option<crate::config::StaticEchConfig>,
    ) -> io::Result<Self> {
        ServerName::try_from(server_name.clone()).map_err(|_| invalid())?;
        if alpn.is_empty()
            || alpn
                .iter()
                .any(|protocol| !(1..=255).contains(&protocol.len()))
            || required_alpn
                .as_ref()
                .is_some_and(|required| !alpn.contains(required))
        {
            return Err(invalid());
        }
        Ok(Self {
            builder: Some(builder),
            server_name,
            alpn,
            required_alpn,
            ech,
        })
    }

    pub(crate) fn server_name(&self) -> &str {
        &self.server_name
    }

    pub(crate) fn build_config(&mut self) -> io::Result<quiche::Config> {
        let builder = self
            .builder
            .take()
            .ok_or_else(|| io::Error::other("QUIC TLS configuration was already consumed"))?;
        let mut config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
                .map_err(|_| invalid())?;
        let alpn = self.alpn.iter().map(Vec::as_slice).collect::<Vec<_>>();
        config
            .set_application_protos(&alpn)
            .map_err(|_| invalid())?;
        Ok(config)
    }

    pub(crate) fn prepare_connection<F: quiche::BufFactory>(
        &self,
        connection: &mut quiche::Connection<F>,
    ) -> io::Result<()> {
        #[cfg(feature = "ech")]
        if let Some(ech) = &self.ech {
            connection
                .as_mut()
                .set_ech_config_list(ech.as_bytes())
                .map_err(|_| invalid())?;
        }
        #[cfg(not(feature = "ech"))]
        let _ = connection;
        Ok(())
    }

    pub(crate) fn check_handshake<F: quiche::BufFactory>(
        &self,
        connection: &mut quiche::Connection<F>,
    ) -> io::Result<()> {
        if !connection.is_established() {
            return Err(io::Error::other("QUIC TLS handshake is incomplete"));
        }
        if self.ech.is_some() && !connection.as_mut().ech_accepted() {
            return Err(io::Error::other("TLS ECH was not accepted"));
        }
        if self
            .required_alpn
            .as_ref()
            .is_some_and(|required| connection.application_proto() != required.as_slice())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS server did not negotiate the required ALPN",
            ));
        }
        Ok(())
    }
}

pub(super) fn peer_certificates(
    ssl: &boring::ssl::SslRef,
) -> io::Result<Vec<CertificateDer<'static>>> {
    let chain = ssl.peer_cert_chain().ok_or_else(invalid)?;
    let mut size = 0_usize;
    chain
        .iter()
        .map(|certificate| {
            let der = certificate.to_der().map_err(|_| invalid())?;
            size = size.checked_add(der.len()).ok_or_else(invalid)?;
            if size > CERTIFICATE_BOUND {
                return Err(invalid());
            }
            Ok(CertificateDer::from(der))
        })
        .collect()
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid QUIC TLS configuration",
    )
}
