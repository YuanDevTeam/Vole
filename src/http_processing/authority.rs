//! Host-owned CA identity and a small generation-owned leaf certificate cache.
//! No files, trust installation, global issuer, detached task or private-key log.
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fmt, io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use x509_parser::{parse_x509_certificate, time::ASN1Time};

const MAX_IDENTITY: usize = 32 * 1024;
const MAX_LEAVES: usize = 32;
const MAX_LEAF_BYTES: usize = 256 * 1024;
const IDLE: Duration = Duration::from_secs(600);
const LEAF_LIFETIME: i64 = 24 * 3600;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid HTTP certificate authority",
    )
}
struct Entry {
    name: Box<str>,
    config: Arc<ServerConfig>,
    bytes: usize,
    used: Instant,
    expires: i64,
}
struct State {
    leaves: VecDeque<Entry>,
    bytes: usize,
}
pub(super) struct Authority {
    issuer: Issuer<'static, KeyPair>,
    certificate: CertificateDer<'static>,
    not_before: i64,
    not_after: i64,
    provider: Arc<rustls::crypto::CryptoProvider>,
    // One synchronous ECDSA issuance at a time, with lookup and insertion in
    // the same short section. Concurrent same-name requests share the result.
    // No queued signing jobs can outlive cancellation or the Stop barrier.
    state: Mutex<State>,
}
impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAuthority").finish_non_exhaustive()
    }
}
impl Authority {
    pub(super) fn load(certificate_pem: &str, key_pem: &str) -> io::Result<Arc<Self>> {
        if certificate_pem.len() > MAX_IDENTITY || key_pem.len() > MAX_IDENTITY {
            return Err(invalid());
        }
        let mut certificates = CertificateDer::pem_slice_iter(certificate_pem.as_bytes());
        let certificate = certificates
            .next()
            .ok_or_else(invalid)?
            .map_err(|_| invalid())?;
        if certificates.next().is_some() {
            return Err(invalid());
        }
        let (remaining, parsed) =
            parse_x509_certificate(certificate.as_ref()).map_err(|_| invalid())?;
        if !remaining.is_empty()
            || !parsed.validity().is_valid()
            || !parsed
                .basic_constraints()
                .map_err(|_| invalid())?
                .is_some_and(|ext| ext.value.ca)
            || parsed
                .key_usage()
                .map_err(|_| invalid())?
                .is_some_and(|ext| !ext.value.key_cert_sign())
        {
            return Err(invalid());
        }
        let private = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| invalid())?;
        let key = KeyPair::try_from(&private).map_err(|_| invalid())?;
        if key.subject_public_key_info() != parsed.public_key().raw {
            return Err(invalid());
        }
        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();
        let issuer = Issuer::from_ca_cert_der(&certificate, key).map_err(|_| invalid())?;
        Ok(Arc::new(Self {
            issuer,
            certificate,
            not_before,
            not_after,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            state: Mutex::new(State {
                leaves: VecDeque::new(),
                bytes: 0,
            }),
        }))
    }
    /// Public certificate identity; private-key spelling never affects a token.
    pub(super) fn identity(&self) -> [u8; 32] {
        Sha256::digest(self.certificate.as_ref()).into()
    }
    pub(super) fn server_config(&self, name: &str) -> io::Result<Arc<ServerConfig>> {
        // Validate before a key is generated and never put IP literals or an
        // unbounded untrusted SNI in the leaf cache.
        if name.len() > 253
            || name.parse::<std::net::IpAddr>().is_ok()
            || !matches!(
                rustls::pki_types::ServerName::try_from(name),
                Ok(rustls::pki_types::ServerName::DnsName(_))
            )
        {
            return Err(invalid());
        }
        let now = Instant::now();
        let unix = ASN1Time::now().timestamp();
        if unix < self.not_before || unix >= self.not_after {
            return Err(invalid());
        }
        let mut state = self.state.lock().map_err(|_| invalid())?;
        let mut index = 0;
        while index < state.leaves.len() {
            let entry = &state.leaves[index];
            if now.saturating_duration_since(entry.used) >= IDLE || entry.expires <= unix {
                let expired = state.leaves.remove(index).unwrap();
                state.bytes -= expired.bytes;
            } else {
                index += 1;
            }
        }
        if let Some(entry) = state
            .leaves
            .iter_mut()
            .find(|entry| entry.name.as_ref() == name)
        {
            entry.used = now;
            return Ok(entry.config.clone());
        }
        let key = KeyPair::generate().map_err(|_| invalid())?;
        let mut params = CertificateParams::new(vec![name.into()]).map_err(|_| invalid())?;
        params.not_before = ASN1Time::from_timestamp((unix - 300).max(self.not_before))
            .map_err(|_| invalid())?
            .to_datetime();
        let expires = (unix + LEAF_LIFETIME).min(self.not_after);
        params.not_after = ASN1Time::from_timestamp(expires)
            .map_err(|_| invalid())?
            .to_datetime();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let leaf = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| invalid())?;
        let private = key.serialize_der();
        // Include a conservative fixed cost for the rustls config and signer.
        let bytes = leaf.der().len() + self.certificate.len() + private.len() + name.len() + 4096;
        if bytes > MAX_LEAF_BYTES {
            return Err(invalid());
        }
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid())?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), self.certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private)),
            )
            .map_err(|_| invalid())?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let config = Arc::new(config);
        while state.leaves.len() >= MAX_LEAVES || state.bytes + bytes > MAX_LEAF_BYTES {
            let oldest = state
                .leaves
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(i, _)| i)
                .ok_or_else(invalid)?;
            let evicted = state.leaves.remove(oldest).unwrap();
            state.bytes -= evicted.bytes;
        }
        state.bytes += bytes;
        state.leaves.push_back(Entry {
            name: name.into(),
            config: config.clone(),
            bytes,
            used: now,
            expires,
        });
        Ok(config)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa};
    fn pem(label: &str, bytes: &[u8]) -> String {
        use base64::Engine as _;
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    }
    fn identity() -> (String, String) {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (
            pem("CERTIFICATE", cert.der()),
            pem("PRIVATE KEY", &key.serialize_der()),
        )
    }
    #[test]
    fn authority_checks_ca_identity_and_bounds_generation_owned_leaves() {
        let (cert, key) = identity();
        let authority = Authority::load(&cert, &key).unwrap();
        let first = authority.server_config("one.example").unwrap();
        assert!(Arc::ptr_eq(
            &first,
            &authority.server_config("one.example").unwrap()
        ));
        for index in 0..MAX_LEAVES * 2 {
            authority
                .server_config(&format!("{index}.example"))
                .unwrap();
        }
        let state = authority.state.lock().unwrap();
        assert!(state.leaves.len() <= MAX_LEAVES);
        assert!(state.bytes <= MAX_LEAF_BYTES);
        drop(state);
        let (_, other) = identity();
        assert!(Authority::load(&cert, &other).is_err());
        assert!(authority.server_config("127.0.0.1").is_err());
        let leaf = rcgen::generate_simple_self_signed(vec!["leaf.example".into()]).unwrap();
        assert!(
            Authority::load(
                &pem("CERTIFICATE", leaf.cert.der()),
                &pem("PRIVATE KEY", &leaf.signing_key.serialize_der())
            )
            .is_err()
        );
    }
    #[test]
    fn ca_chain_bytes_are_charged_to_each_retained_leaf() {
        let names = (0..96)
            .map(|index| format!("{index}.{}.example", "a".repeat(48)))
            .collect::<Vec<_>>();
        let mut params = CertificateParams::new(names).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        assert!(cert.der().len() > 4096);
        let authority = Authority::load(
            &pem("CERTIFICATE", cert.der()),
            &pem("PRIVATE KEY", &key.serialize_der()),
        )
        .unwrap();
        for index in 0..64 {
            authority
                .server_config(&format!("{index}.example"))
                .unwrap();
        }
        let state = authority.state.lock().unwrap();
        assert!(state.bytes <= MAX_LEAF_BYTES);
        assert!(state.bytes >= state.leaves.len() * (cert.der().len() + 4096));
    }
    #[tokio::test]
    async fn issued_leaf_identifies_its_authority_in_a_memory_tls_handshake() {
        let (cert, key) = identity();
        let authority = Authority::load(&cert, &key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(authority.certificate.clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(authority.provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let acceptor =
            tokio_rustls::TlsAcceptor::from(authority.server_config("one.example").unwrap());
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (server, client) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect("one.example".try_into().unwrap(), client_io)
        );
        let _server = server.unwrap();
        let client = client.unwrap();
        let certificates = client.get_ref().1.peer_certificates().unwrap();
        let (_, leaf) = parse_x509_certificate(certificates[0].as_ref()).unwrap();
        use x509_parser::extensions::ParsedExtension;
        let leaf_id =
            leaf.extensions()
                .iter()
                .find_map(|extension| match extension.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(id) => id.key_identifier.as_ref(),
                    _ => None,
                });
        let (_, ca) = parse_x509_certificate(authority.certificate.as_ref()).unwrap();
        let ca_id =
            ca.extensions()
                .iter()
                .find_map(|extension| match extension.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(id) => Some(id),
                    _ => None,
                });
        assert!(leaf_id.is_some());
        assert_eq!(leaf_id, ca_id);
    }
}
