use std::{
    fs::OpenOptions,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use rsa::pkcs8::EncodePrivateKey;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime, pem::PemObject},
    server::{
        ClientHello, ResolvesServerCert, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};
use tokio_util::sync::CancellationToken;

use crate::config::ControllerTls;

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;

struct Resolver(RwLock<Arc<CertifiedKey>>);
impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerCertificateResolver")
            .finish_non_exhaustive()
    }
}
impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().unwrap().clone())
    }
}

pub(super) struct ServerTls {
    pub config: Arc<rustls::ServerConfig>,
    resolver: Arc<Resolver>,
    files: Option<(PathBuf, PathBuf)>,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid controller TLS material",
    )
}

fn pair(certificate: &[u8], private_key: &[u8]) -> io::Result<Arc<CertifiedKey>> {
    if certificate.len().saturating_add(private_key.len()) > crate::config::MAX_CONFIG_BYTES {
        return Err(invalid());
    }
    let certs = CertificateDer::pem_slice_iter(certificate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    let mut keys = PrivateKeyDer::pem_slice_iter(private_key);
    let key = keys.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
    if keys.next().is_some() || certs.is_empty() {
        return Err(invalid());
    }
    CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider())
        .map(Arc::new)
        .map_err(|_| invalid())
}

fn read_regular(path: &Path, remaining: &mut usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| invalid())?;
    if !file.metadata().map_err(|_| invalid())?.is_file() {
        return Err(invalid());
    }
    let mut data = Vec::new();
    file.take(*remaining as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| invalid())?;
    if data.len() > *remaining {
        return Err(invalid());
    }
    *remaining -= data.len();
    Ok(data)
}

fn read_pair(files: &(PathBuf, PathBuf)) -> io::Result<Arc<CertifiedKey>> {
    let mut remaining = crate::config::MAX_CONFIG_BYTES;
    let certificate = read_regular(&files.0, &mut remaining)?;
    let key = read_regular(&files.1, &mut remaining)?;
    pair(&certificate, &key)
}

struct OsRandom;
impl rsa::rand_core::CryptoRng for OsRandom {}
impl rsa::rand_core::RngCore for OsRandom {
    fn next_u32(&mut self) -> u32 {
        rand::random()
    }
    fn next_u64(&mut self) -> u64 {
        rand::random()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn generated_pair() -> io::Result<Arc<CertifiedKey>> {
    let key = rsa::RsaPrivateKey::new(&mut OsRandom, 2048).map_err(|_| invalid())?;
    let der = key.to_pkcs8_der().map_err(|_| invalid())?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.as_bytes()));
    let key_pair = rcgen::KeyPair::from_der_and_sign_algo(&key_der, &rcgen::PKCS_RSA_SHA256)
        .map_err(|_| invalid())?;
    let mut params = rcgen::CertificateParams::default();
    let now = SystemTime::now();
    let year = Duration::from_secs(365 * 24 * 3600);
    params.not_before = (now - year).into();
    params.not_after = (now + year).into();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(1u64.into());
    let certificate = params.self_signed(&key_pair).map_err(|_| invalid())?;
    CertifiedKey::from_der(
        vec![certificate.der().clone()],
        key_der.clone_key(),
        &rustls::crypto::ring::default_provider(),
    )
    .map(Arc::new)
    .map_err(|_| invalid())
}

#[derive(Debug)]
struct ProofVerifier {
    mandatory: bool,
}
impl ClientCertVerifier for ProofVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        rustls::server::ParsedCertificate::try_from(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn verifier(options: &ControllerTls, root: &Path) -> io::Result<Arc<dyn ClientCertVerifier>> {
    let mut mode = options.client_auth_type.as_ref();
    if !matches!(
        mode,
        "request" | "require-any" | "verify-if-given" | "require-and-verify"
    ) {
        mode = if options.client_auth_cert.is_empty() {
            ""
        } else {
            "require-and-verify"
        };
    }
    match mode {
        "request" | "require-any" => Ok(Arc::new(ProofVerifier {
            mandatory: mode == "require-any",
        })),
        "verify-if-given" | "require-and-verify" => {
            let inline = CertificateDer::pem_slice_iter(options.client_auth_cert.as_bytes())
                .collect::<Result<Vec<_>, _>>();
            let certs = match inline {
                Ok(certs) if !certs.is_empty() => certs,
                _ => {
                    let path = crate::resource::cache::resource_path(
                        root,
                        &options.client_auth_cert,
                        false,
                    )
                    .map_err(|_| invalid())?;
                    let mut remaining = crate::config::MAX_CONFIG_BYTES;
                    let bytes = read_regular(&path, &mut remaining)?;
                    CertificateDer::pem_slice_iter(&bytes)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| invalid())?
                }
            };
            let mut roots = rustls::RootCertStore::empty();
            for certificate in certs {
                roots.add(certificate).map_err(|_| invalid())?;
            }
            let mut builder = WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(rustls::crypto::ring::default_provider()),
            );
            if mode == "verify-if-given" {
                builder = builder.allow_unauthenticated();
            }
            builder.build().map_err(|_| invalid())
        }
        _ => Ok(Arc::new(rustls::server::NoClientAuth)),
    }
}

impl ServerTls {
    pub fn load(options: &ControllerTls, root: &Path) -> io::Result<Self> {
        let (key, files) = if options.certificate.is_empty() && options.private_key.is_empty() {
            (generated_pair()?, None)
        } else if let Ok(key) = pair(
            options.certificate.as_bytes(),
            options.private_key.as_bytes(),
        ) {
            (key, None)
        } else {
            let files = (
                crate::resource::cache::resource_path(root, &options.certificate, false)
                    .map_err(|_| invalid())?,
                crate::resource::cache::resource_path(root, &options.private_key, false)
                    .map_err(|_| invalid())?,
            );
            (read_pair(&files)?, Some(files))
        };
        let resolver = Arc::new(Resolver(RwLock::new(key)));
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .with_client_cert_verifier(verifier(options, root)?)
        .with_cert_resolver(resolver.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
            resolver,
            files,
        })
    }

    pub fn watches_files(&self) -> bool {
        self.files.is_some()
    }

    pub async fn watch(self: Arc<Self>, cancellation: CancellationToken) {
        let Some(files) = self.files.clone() else {
            return;
        };
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! { biased; () = cancellation.cancelled() => break, _ = interval.tick() => {} }
            let files = files.clone();
            // Await every blocking read, including during cancellation. Stop
            // cannot return while a certificate candidate is still running.
            let candidate = tokio::task::spawn_blocking(move || read_pair(&files)).await;
            if cancellation.is_cancelled() {
                break;
            }
            if let Ok(Ok(candidate)) = candidate {
                let mut current = self.resolver.0.write().unwrap();
                if current.cert != candidate.cert {
                    *current = candidate;
                }
            }
        }
    }
}
