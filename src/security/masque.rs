//! MASQUE uses an ECDSA identity and a peer public-key pin, without WebPKI.
//! HTTP/2 uses rustls/ring; HTTP/3 uses the shared Boring QUIC backend. Boring
//! also supplies P-224/P-521 and TLS 1.2's curve-independent hash selection.
use std::{
    fmt, io,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, alphabet, engine::general_purpose};
use boring::{
    asn1::Asn1Time,
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer as NativeSigner, Verifier},
    x509::{X509, X509Name},
};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureAlgorithm,
    SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
    version::{TLS12, TLS13},
};
use zeroize::Zeroizing;

use super::SecurityContext;

const UNKNOWN_VERSION: u8 = 0;
const VERSION_12: u8 = 12;
const VERSION_13: u8 = 13;
const VERIFY_SCHEMES: [SignatureScheme; 10] = [
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
];

/// Immutable keys/certificate; call `config` once for each physical connection.
#[derive(Clone)]
pub(crate) struct MasqueTls {
    identity: Arc<Identity>,
    peer: PKey<Public>,
    skip_pin: bool,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for MasqueTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueTls")
            .field("skip_pin", &self.skip_pin)
            .finish_non_exhaustive()
    }
}

impl MasqueTls {
    #[cfg(feature = "quiche-h3-transport")]
    pub(crate) fn quiche_config(
        &self,
        server_name: impl Into<String>,
    ) -> io::Result<super::QuicheTls> {
        use boring::ssl::{SslAlert, SslVerifyError, SslVerifyMode};

        let mut builder = super::QuicheTls::builder()?;
        let certificate = parsed_certificate(&self.identity.certificate)
            .map_err(|_| io::Error::other("cannot create MASQUE QUIC TLS configuration"))?;
        builder
            .set_certificate(&certificate)
            .map_err(|_| io::Error::other("cannot set MASQUE QUIC certificate"))?;
        builder
            .set_private_key(&self.identity.key)
            .map_err(|_| io::Error::other("cannot set MASQUE QUIC identity"))?;
        builder
            .check_private_key()
            .map_err(|_| io::Error::other("invalid MASQUE QUIC identity"))?;
        let verifier = MasqueVerifier {
            peer: self.peer.clone(),
            skip_pin: self.skip_pin,
            version: Arc::new(AtomicU8::new(VERSION_13)),
        };
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let reject = || SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE);
            let certificates = super::quiche_tls::peer_certificates(ssl).map_err(|_| reject())?;
            let (leaf, rest) = certificates.split_first().ok_or_else(reject)?;
            verifier.verify_chain(leaf, rest).map_err(|_| reject())
        });
        super::QuicheTls::from_builder(
            builder,
            server_name.into(),
            vec![b"h3".to_vec()],
            Some(b"h3".to_vec()),
            None,
        )
    }

    pub(crate) fn new(
        private_b64: &str,
        public_b64: &str,
        skip: bool,
        context: &SecurityContext,
    ) -> io::Result<Self> {
        let (key, identity_curve, peer) = keys(private_b64, public_b64)?;
        let spki = key
            .public_key_to_der()
            .map_err(|_| invalid("invalid MASQUE ECDSA private key"))?;
        let certificate = certificate(&key, identity_curve)?;

        Ok(Self {
            identity: Arc::new(Identity {
                key,
                curve: identity_curve,
                spki,
                certificate,
            }),
            peer,
            skip_pin: skip,
            provider: context.provider.clone(),
        })
    }

    /// QUIC is TLS 1.3 only. HTTP/2 can negotiate either version, so its
    /// signer and verifier share state unique to this returned configuration.
    pub(crate) fn config(&self, quic: bool) -> io::Result<Arc<ClientConfig>> {
        let version = Arc::new(AtomicU8::new(if quic {
            VERSION_13
        } else {
            UNKNOWN_VERSION
        }));
        let verifier = Arc::new(MasqueVerifier {
            peer: self.peer.clone(),
            skip_pin: self.skip_pin,
            version: version.clone(),
        });
        let key = CertifiedKey::new(
            vec![self.identity.certificate.clone()],
            Arc::new(IdentityKey {
                identity: self.identity.clone(),
                version,
            }),
        );
        let versions: &[&'static rustls::SupportedProtocolVersion] =
            if quic { &[&TLS13] } else { &[&TLS13, &TLS12] };
        let mut config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(versions)
            .map_err(|_| io::Error::other("cannot create MASQUE TLS configuration"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
        config.alpn_protocols = vec![if quic { b"h3".to_vec() } else { b"h2".to_vec() }];
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        Ok(Arc::new(config))
    }
}

/// Configuration validation parses the immutable material without reading
/// time, generating a certificate, or acquiring runtime resources.
pub(crate) fn validate_keys(private_b64: &str, public_b64: &str) -> io::Result<()> {
    keys(private_b64, public_b64).map(|_| ())
}

fn keys(private_b64: &str, public_b64: &str) -> io::Result<(PKey<Private>, Curve, PKey<Public>)> {
    let private_der = decode_key(private_b64)?;
    let ec = sec1_private_key(&private_der)?;
    let key = PKey::from_ec_key(ec).map_err(|_| invalid("invalid MASQUE ECDSA private key"))?;
    let identity_curve = curve(&key)?;
    let public_der = decode_key(public_b64)?;
    complete_der_sequence(&public_der).map_err(|_| invalid("invalid MASQUE SPKI public key"))?;
    let peer = PKey::public_key_from_der(&public_der)
        .map_err(|_| invalid("invalid MASQUE SPKI public key"))?;
    curve(&peer)?;
    Ok((key, identity_curve, peer))
}

struct Identity {
    key: PKey<Private>,
    curve: Curve,
    spki: Vec<u8>,
    certificate: CertificateDer<'static>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Curve {
    P224,
    P256,
    P384,
    P521,
}

impl Curve {
    fn tls13_scheme(self) -> Option<SignatureScheme> {
        match self {
            Self::P224 => None,
            Self::P256 => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
            Self::P384 => Some(SignatureScheme::ECDSA_NISTP384_SHA384),
            Self::P521 => Some(SignatureScheme::ECDSA_NISTP521_SHA512),
        }
    }
    fn certificate_digest(self) -> MessageDigest {
        match self {
            Self::P224 | Self::P256 => MessageDigest::sha256(),
            Self::P384 => MessageDigest::sha384(),
            Self::P521 => MessageDigest::sha512(),
        }
    }
}

fn curve<T: HasPublic>(key: &PKeyRef<T>) -> io::Result<Curve> {
    let ec = key
        .ec_key()
        .map_err(|_| invalid("MASQUE key must be ECDSA"))?;
    match ec.group().curve_name() {
        Some(Nid::SECP224R1) => Ok(Curve::P224),
        Some(Nid::X9_62_PRIME256V1) => Ok(Curve::P256),
        Some(Nid::SECP384R1) => Ok(Curve::P384),
        Some(Nid::SECP521R1) => Ok(Curve::P521),
        _ => Err(invalid("unsupported MASQUE ECDSA curve")),
    }
}

fn decode_key(encoded: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if encoded.len() > crate::config::MAX_CONFIG_BYTES {
        return Err(invalid("MASQUE key exceeds configuration bound"));
    }
    let cleaned = Zeroizing::new(
        encoded
            .bytes()
            .filter(|b| !matches!(b, b'\r' | b'\n'))
            .collect::<Vec<_>>(),
    );
    let engine = general_purpose::GeneralPurpose::new(
        &alphabet::STANDARD,
        general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    engine
        .decode(cleaned.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| invalid("invalid MASQUE key base64"))
}

fn named_curve(oid: &[u8]) -> Option<Nid> {
    match oid {
        [0x2b, 0x81, 0x04, 0, 0x21] => Some(Nid::SECP224R1),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7] => Some(Nid::X9_62_PRIME256V1),
        [0x2b, 0x81, 0x04, 0, 0x22] => Some(Nid::SECP384R1),
        [0x2b, 0x81, 0x04, 0, 0x23] => Some(Nid::SECP521R1),
        _ => None,
    }
}

/// Go's SEC1 consumer derives the public point from the scalar, ignoring the
/// optional encoded point. It also tolerates scalar zero padding and a suffix.
fn sec1_private_key(der: &[u8]) -> io::Result<EcKey<Private>> {
    let parse = || -> Result<EcKey<Private>, Error> {
        let mut der = der;
        let mut fields = der_value(&mut der, 0x30)?;
        if der_value(&mut fields, 2)? != [1] {
            return Err(bad_encoding());
        }
        let mut scalar = der_value(&mut fields, 4)?;
        let mut parameters = der_value(&mut fields, 0xa0)?;
        let nid = named_curve(der_value(&mut parameters, 6)?).ok_or_else(bad_encoding)?;
        if fields.first() == Some(&0xa1) {
            let mut public = der_value(&mut fields, 0xa1)?;
            let bits = der_value(&mut public, 3)?;
            let unused = *bits.first().ok_or_else(bad_encoding)?;
            if unused > 7
                || (bits.len() == 1 && unused != 0)
                || (unused != 0 && bits.last().copied().unwrap_or(0) & ((1 << unused) - 1) != 0)
            {
                return Err(bad_encoding());
            }
        }
        let group = EcGroup::from_curve_name(nid).map_err(|_| bad_encoding())?;
        let size = (group.order_bits() as usize).div_ceil(8);
        while scalar.len() > size && scalar.first() == Some(&0) {
            scalar = &scalar[1..];
        }
        if scalar.len() > size {
            return Err(bad_encoding());
        }
        let scalar = BigNum::from_slice(scalar).map_err(|_| bad_encoding())?;
        let mut context = BigNumContext::new().map_err(|_| bad_encoding())?;
        let mut order = BigNum::new().map_err(|_| bad_encoding())?;
        group
            .order(&mut order, &mut context)
            .map_err(|_| bad_encoding())?;
        if scalar.num_bits() == 0 || scalar.ucmp(&order) != std::cmp::Ordering::Less {
            return Err(bad_encoding());
        }
        let mut point = EcPoint::new(&group).map_err(|_| bad_encoding())?;
        point
            .mul_generator(&group, &scalar, &mut context)
            .map_err(|_| bad_encoding())?;
        let key =
            EcKey::from_private_components(&group, &scalar, &point).map_err(|_| bad_encoding())?;
        key.check_key().map_err(|_| bad_encoding())?;
        Ok(key)
    };
    parse().map_err(|_| invalid("invalid MASQUE SEC1 private key"))
}

fn certificate(key: &PKeyRef<Private>, curve: Curve) -> io::Result<CertificateDer<'static>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("cannot read MASQUE certificate time"))?
        .as_secs();
    let not_before =
        i64::try_from(now).map_err(|_| io::Error::other("invalid MASQUE certificate time"))?;
    let not_after = not_before
        .checked_add(24 * 60 * 60)
        .ok_or_else(|| io::Error::other("invalid MASQUE certificate time"))?;
    let build = || -> Result<Vec<u8>, boring::error::ErrorStack> {
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let serial = BigNum::from_u32(0)?.to_asn1_integer()?;
        cert.set_serial_number(&serial)?;
        let name = X509Name::builder()?.build();
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        let not_before = Asn1Time::from_unix(not_before)?;
        let not_after = Asn1Time::from_unix(not_after)?;
        cert.set_not_before(&not_before)?;
        cert.set_not_after(&not_after)?;
        cert.set_pubkey(key)?;
        cert.sign(key, curve.certificate_digest())?;
        cert.build().to_der()
    };
    build()
        .map(CertificateDer::from)
        .map_err(|_| io::Error::other("cannot create MASQUE client certificate"))
}

/// The safe Boring decoders permit a suffix. Go's SPKI/certificate parsers
/// consume one complete DER value; SEC1 deliberately retains its own parser.
fn der_value<'a>(der: &mut &'a [u8], tag: u8) -> Result<&'a [u8], Error> {
    let input = *der;
    if der.first() != Some(&tag) {
        return Err(bad_encoding());
    }
    let first = *der.get(1).ok_or_else(bad_encoding)?;
    let (header, length) = if first < 128 {
        (2, first as usize)
    } else {
        let count = (first & 127) as usize;
        if count == 0 || count > size_of::<usize>() {
            return Err(bad_encoding());
        }
        let bytes = der.get(2..2 + count).ok_or_else(bad_encoding)?;
        if bytes.first() == Some(&0) {
            return Err(bad_encoding());
        }
        let length = bytes
            .iter()
            .try_fold(0usize, |v, b| v.checked_mul(256)?.checked_add(*b as usize))
            .ok_or_else(bad_encoding)?;
        if length < 128 {
            return Err(bad_encoding());
        }
        (2 + count, length)
    };
    let end = header.checked_add(length).ok_or_else(bad_encoding)?;
    let value = input.get(header..end).ok_or_else(bad_encoding)?;
    *der = &input[end..];
    Ok(value)
}

fn complete_der_sequence(mut der: &[u8]) -> Result<(), Error> {
    der_value(&mut der, 0x30)?;
    if !der.is_empty() {
        return Err(bad_encoding());
    }
    Ok(())
}

fn parsed_certificate(der: &CertificateDer<'_>) -> Result<X509, Error> {
    complete_der_sequence(der.as_ref())?;
    X509::from_der(der.as_ref()).map_err(|_| bad_encoding())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn bad_encoding() -> Error {
    Error::InvalidCertificate(CertificateError::BadEncoding)
}
fn bad_signature() -> Error {
    Error::InvalidCertificate(CertificateError::BadSignature)
}
fn unsupported_signature() -> Error {
    Error::General("unsupported MASQUE handshake signature".into())
}

struct MasqueVerifier {
    peer: PKey<Public>,
    skip_pin: bool,
    version: Arc<AtomicU8>,
}

impl fmt::Debug for MasqueVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueVerifier")
            .field("skip_pin", &self.skip_pin)
            .finish_non_exhaustive()
    }
}

impl MasqueVerifier {
    fn verify_chain(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
    ) -> Result<(), Error> {
        for der in std::iter::once(leaf).chain(chain) {
            let cert = parsed_certificate(der)?;
            if !self.skip_pin {
                let key = cert.public_key().map_err(|_| bad_encoding())?;
                if key.id() != Id::EC || !key.public_eq(&self.peer) {
                    return Err(Error::General(
                        "MASQUE peer certificate public key does not match".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn verify_and_publish(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
        version: u8,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signature(message, cert, dss.scheme, dss.signature(), version)?;
        match self.version.compare_exchange(
            UNKNOWN_VERSION,
            version,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(previous) if previous == version => {}
            Err(_) => {
                return Err(Error::General(
                    "MASQUE TLS version changed during handshake".into(),
                ));
            }
        }
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ServerCertVerifier for MasqueVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verify_chain(leaf, chain)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_and_publish(message, cert, dss, VERSION_12)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_and_publish(message, cert, dss, VERSION_13)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        VERIFY_SCHEMES
            .into_iter()
            .filter(|scheme| {
                self.version.load(Ordering::Acquire) != VERSION_13 || !rsa_pkcs1(*scheme)
            })
            .collect()
    }
}

fn ecdsa_digest(scheme: SignatureScheme) -> Option<MessageDigest> {
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Some(MessageDigest::sha256()),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Some(MessageDigest::sha384()),
        SignatureScheme::ECDSA_NISTP521_SHA512 => Some(MessageDigest::sha512()),
        _ => None,
    }
}

fn rsa_pkcs1(scheme: SignatureScheme) -> bool {
    matches!(
        scheme,
        SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
    )
}

fn rsa_digest(scheme: SignatureScheme) -> Option<MessageDigest> {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 | SignatureScheme::RSA_PKCS1_SHA256 => {
            Some(MessageDigest::sha256())
        }
        SignatureScheme::RSA_PSS_SHA384 | SignatureScheme::RSA_PKCS1_SHA384 => {
            Some(MessageDigest::sha384())
        }
        SignatureScheme::RSA_PSS_SHA512 | SignatureScheme::RSA_PKCS1_SHA512 => {
            Some(MessageDigest::sha512())
        }
        _ => None,
    }
}

fn verify_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    scheme: SignatureScheme,
    signature: &[u8],
    version: u8,
) -> Result<(), Error> {
    if !matches!(version, VERSION_12 | VERSION_13) {
        return Err(unsupported_signature());
    }
    let key = parsed_certificate(cert)?
        .public_key()
        .map_err(|_| bad_encoding())?;
    let native = match key.id() {
        Id::EC => {
            let digest = ecdsa_digest(scheme).ok_or_else(unsupported_signature)?;
            let key_curve = curve(&key).map_err(|_| unsupported_signature())?;
            if version == VERSION_13 && key_curve.tls13_scheme() != Some(scheme) {
                return Err(unsupported_signature());
            }
            Verifier::new(digest, &key).map_err(|_| bad_signature())?
        }
        Id::RSA => {
            let digest = rsa_digest(scheme).ok_or_else(unsupported_signature)?;
            if version == VERSION_13 && rsa_pkcs1(scheme) {
                return Err(unsupported_signature());
            }
            let mut verifier = Verifier::new(digest, &key).map_err(|_| bad_signature())?;
            if rsa_pkcs1(scheme) {
                verifier
                    .set_rsa_padding(Padding::PKCS1)
                    .map_err(|_| bad_signature())?;
            } else {
                verifier
                    .set_rsa_padding(Padding::PKCS1_PSS)
                    .map_err(|_| bad_signature())?;
                verifier
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .map_err(|_| bad_signature())?;
                verifier
                    .set_rsa_mgf1_md(digest)
                    .map_err(|_| bad_signature())?;
            }
            verifier
        }
        Id::ED25519 if scheme == SignatureScheme::ED25519 => {
            Verifier::new_without_digest(&key).map_err(|_| bad_signature())?
        }
        _ => return Err(unsupported_signature()),
    };
    let mut native = native;
    if native
        .verify_oneshot(signature, message)
        .map_err(|_| bad_signature())?
    {
        Ok(())
    } else {
        Err(bad_signature())
    }
}

struct IdentityKey {
    identity: Arc<Identity>,
    version: Arc<AtomicU8>,
}
impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueIdentityKey").finish_non_exhaustive()
    }
}

impl SigningKey for IdentityKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let version = self.version.load(Ordering::Acquire);
        let mut candidates = [None; 3];
        let mut count = 0;
        for scheme in offered.iter().copied() {
            if ecdsa_digest(scheme).is_none() || candidates.contains(&Some(scheme)) {
                continue;
            }
            if version == VERSION_13 && self.identity.curve.tls13_scheme() != Some(scheme) {
                continue;
            }
            candidates[count] = Some(scheme);
            count += 1;
        }
        if count == 0 {
            return None;
        }
        Some(Box::new(DeferredSigner {
            identity: self.identity.clone(),
            version: self.version.clone(),
            candidates,
            selected: OnceLock::new(),
        }))
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.identity.spki.as_slice().into())
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct DeferredSigner {
    identity: Arc<Identity>,
    version: Arc<AtomicU8>,
    candidates: [Option<SignatureScheme>; 3],
    selected: OnceLock<Result<SignatureScheme, ()>>,
}
impl fmt::Debug for DeferredSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueDeferredSigner")
            .finish_non_exhaustive()
    }
}
impl DeferredSigner {
    fn selection(&self) -> Result<SignatureScheme, ()> {
        *self.selected.get_or_init(|| {
            let version = self.version.load(Ordering::Acquire);
            if !matches!(version, VERSION_12 | VERSION_13) {
                return Err(());
            }
            self.candidates
                .iter()
                .copied()
                .flatten()
                .find(|scheme| {
                    version == VERSION_12 || self.identity.curve.tls13_scheme() == Some(*scheme)
                })
                .ok_or(())
        })
    }
}
impl Signer for DeferredSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let scheme = self.selection().map_err(|_| unsupported_signature())?;
        let digest = ecdsa_digest(scheme).ok_or_else(unsupported_signature)?;
        let mut signer =
            NativeSigner::new(digest, &self.identity.key).map_err(|_| bad_signature())?;
        signer
            .sign_oneshot_to_vec(message)
            .map_err(|_| bad_signature())
    }
    fn scheme(&self) -> SignatureScheme {
        // rustls asks for the scheme before `sign`. A premature/unsupported
        // selection seals an error; `sign` fails before rustls emits a message.
        self.selection()
            .unwrap_or(SignatureScheme::ECDSA_NISTP256_SHA256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use boring::{ec::EcGroup, rsa::Rsa};
    use rustls::{
        DistinguishedName, ProtocolVersion, ServerConfig,
        pki_types::PrivateKeyDer,
        server::danger::{ClientCertVerified, ClientCertVerifier},
    };
    use std::{sync::Mutex, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn ec_key(nid: Nid) -> PKey<Private> {
        PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(nid).unwrap()).unwrap())
            .unwrap()
    }

    fn factory(client: &PKey<Private>, peer: &PKey<Private>, skip: bool) -> MasqueTls {
        MasqueTls::new(
            &STANDARD.encode(client.ec_key().unwrap().private_key_to_der().unwrap()),
            &STANDARD.encode(peer.public_key_to_der().unwrap()),
            skip,
            &SecurityContext::new(),
        )
        .unwrap()
    }

    fn verifier(peer: &PKey<Private>, skip: bool, version: u8) -> MasqueVerifier {
        MasqueVerifier {
            peer: PKey::public_key_from_der(&peer.public_key_to_der().unwrap()).unwrap(),
            skip_pin: skip,
            version: Arc::new(AtomicU8::new(version)),
        }
    }

    fn identity_key(factory: &MasqueTls, version: u8) -> IdentityKey {
        IdentityKey {
            identity: factory.identity.clone(),
            version: Arc::new(AtomicU8::new(version)),
        }
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if content.len() < 128 {
            output.push(content.len() as u8);
        } else if content.len() < 256 {
            output.extend_from_slice(&[0x81, content.len() as u8]);
        } else {
            output.push(0x82);
            output.extend_from_slice(&(content.len() as u16).to_be_bytes());
        }
        output.extend_from_slice(content);
        output
    }

    #[test]
    fn sec1_spki_curves_and_certificate_contract() {
        for nid in [
            Nid::SECP224R1,
            Nid::X9_62_PRIME256V1,
            Nid::SECP384R1,
            Nid::SECP521R1,
        ] {
            let key = ec_key(nid);
            let mut private = key.ec_key().unwrap().private_key_to_der().unwrap();
            // Go's SEC1 parser ignores a suffix, unlike its public-key parser.
            private.push(0);
            let private = STANDARD.encode(private);
            let public = STANDARD.encode(key.public_key_to_der().unwrap());
            let client = MasqueTls::new(
                &format!("\r\n{private}\n"),
                &public,
                true,
                &SecurityContext::new(),
            )
            .unwrap();
            let cert = parsed_certificate(&client.identity.certificate).unwrap();
            assert_eq!(
                cert.serial_number()
                    .to_bn()
                    .unwrap()
                    .to_dec_str()
                    .unwrap()
                    .to_string(),
                "0"
            );
            assert_eq!(cert.subject_name().entries().count(), 0);
            assert_eq!(cert.issuer_name().entries().count(), 0);
            let validity = cert.not_before().diff(cert.not_after()).unwrap();
            assert_eq!((validity.days, validity.secs), (1, 0));
            assert!(cert.public_key().unwrap().public_eq(&key));
            assert!(!format!("{client:?}").contains(&private));

            let encoded = key.ec_key().unwrap().private_key_to_der().unwrap();
            let mut input = encoded.as_slice();
            let mut fields = der_value(&mut input, 0x30).unwrap();
            der_value(&mut fields, 2).unwrap();
            let scalar = der_value(&mut fields, 4).unwrap();
            let parameters = der_value(&mut fields, 0xa0).unwrap();
            let mut padded = vec![0, 0];
            padded.extend_from_slice(scalar);
            let mut rewritten = der(2, &[1]);
            rewritten.extend(der(4, &padded));
            rewritten.extend(der(0xa0, parameters));
            // A syntactically valid bitstring need not contain the scalar's
            // actual point: the reference derives that point independently.
            rewritten.extend(der(0xa1, &der(3, &[0, 0xff])));
            let imported = sec1_private_key(&der(0x30, &rewritten)).unwrap();
            assert!(PKey::from_ec_key(imported).unwrap().public_eq(&key));

            let pkcs8 = STANDARD.encode(key.private_key_to_der_pkcs8().unwrap());
            assert!(MasqueTls::new(&pkcs8, &public, false, &SecurityContext::new()).is_err());
            let mut extra = key.public_key_to_der().unwrap();
            extra.push(0);
            assert!(
                MasqueTls::new(
                    &private,
                    &STANDARD.encode(extra),
                    true,
                    &SecurityContext::new()
                )
                .is_err()
            );
        }
        let ec = ec_key(Nid::X9_62_PRIME256V1);
        let rsa = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let private = STANDARD.encode(ec.ec_key().unwrap().private_key_to_der().unwrap());
        assert!(
            MasqueTls::new(
                &private,
                &STANDARD.encode(rsa.public_key_to_der().unwrap()),
                true,
                &SecurityContext::new()
            )
            .is_err()
        );
        assert_eq!(decode_key("Zh==\r\n").unwrap().as_slice(), b"f");
        assert!(decode_key("Zg== ").is_err());
        assert!(decode_key("Zg").is_err());
    }

    #[test]
    fn pin_requires_every_chain_key_and_skip_still_parses_der() {
        let peer = ec_key(Nid::SECP521R1);
        let other = ec_key(Nid::X9_62_PRIME256V1);
        let rsa = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let leaf = certificate(&peer, Curve::P521).unwrap();
        let same = certificate(&peer, Curve::P521).unwrap();
        let different = certificate(&other, Curve::P256).unwrap();
        let rsa_cert = certificate(&rsa, Curve::P256).unwrap();
        let pinned = verifier(&peer, false, UNKNOWN_VERSION);
        assert!(pinned.verify_chain(&leaf, &[same]).is_ok());
        assert!(pinned.verify_chain(&leaf, &[different.clone()]).is_err());
        assert!(pinned.verify_chain(&leaf, &[rsa_cert.clone()]).is_err());
        assert!(pinned.verify_chain(&different, &[]).is_err());
        let skipped = verifier(&peer, true, UNKNOWN_VERSION);
        assert!(skipped.verify_chain(&rsa_cert, &[different]).is_ok());
        assert!(
            skipped
                .verify_chain(&leaf, &[CertificateDer::from(vec![0x30, 0])])
                .is_err()
        );
        let mut trailing = leaf.as_ref().to_vec();
        trailing.push(0);
        assert!(
            skipped
                .verify_chain(&CertificateDer::from(trailing), &[])
                .is_err()
        );
        // No DNS-name, CA, or time policy is applied to a matching key.
        assert!(
            pinned
                .verify_server_cert(
                    &leaf,
                    &[],
                    &ServerName::try_from("different.invalid").unwrap(),
                    &[],
                    UnixTime::since_unix_epoch(Duration::ZERO)
                )
                .is_ok()
        );
    }

    #[test]
    fn tls12_cross_curve_hashes_and_tls13_curve_binding() {
        let schemes = [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ];
        for nid in [
            Nid::SECP224R1,
            Nid::X9_62_PRIME256V1,
            Nid::SECP384R1,
            Nid::SECP521R1,
        ] {
            let key = ec_key(nid);
            let client = factory(&key, &key, false);
            for scheme in schemes {
                let signer = identity_key(&client, VERSION_12)
                    .choose_scheme(&[scheme])
                    .unwrap();
                let signature = signer.sign(b"actual transcript").unwrap();
                assert_eq!(signer.scheme(), scheme);
                assert!(
                    verify_signature(
                        b"actual transcript",
                        &client.identity.certificate,
                        scheme,
                        &signature,
                        VERSION_12
                    )
                    .is_ok()
                );
                assert!(
                    verify_signature(
                        b"changed transcript",
                        &client.identity.certificate,
                        scheme,
                        &signature,
                        VERSION_12
                    )
                    .is_err()
                );
                assert_eq!(
                    verify_signature(
                        b"actual transcript",
                        &client.identity.certificate,
                        scheme,
                        &signature,
                        VERSION_13
                    )
                    .is_ok(),
                    client.identity.curve.tls13_scheme() == Some(scheme)
                );
                assert_eq!(
                    identity_key(&client, VERSION_13)
                        .choose_scheme(&[scheme])
                        .is_some(),
                    client.identity.curve.tls13_scheme() == Some(scheme)
                );
            }
            assert!(
                identity_key(&client, VERSION_12)
                    .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                    .is_none()
            );
        }
    }

    #[test]
    fn deferred_selection_seals_errors_and_obeys_peer_order() {
        let key = ec_key(Nid::SECP521R1);
        let client = factory(&key, &key, false);
        let identity = identity_key(&client, UNKNOWN_VERSION);
        let offered = [
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ];
        let early = identity.choose_scheme(&offered).unwrap();
        let _ = early.scheme();
        identity.version.store(VERSION_12, Ordering::Release);
        assert!(early.sign(b"transcript").is_err());
        let valid = identity.choose_scheme(&offered).unwrap();
        assert_eq!(valid.scheme(), offered[0]);
        assert!(valid.sign(b"transcript").is_ok());
        let second = identity_key(&client, UNKNOWN_VERSION);
        let deferred = second.choose_scheme(&offered).unwrap();
        second.version.store(VERSION_13, Ordering::Release);
        assert_eq!(deferred.scheme(), SignatureScheme::ECDSA_NISTP521_SHA512);
        let invalid = identity_key(&client, UNKNOWN_VERSION);
        let deferred = invalid.choose_scheme(&offered[..2]).unwrap();
        invalid.version.store(VERSION_13, Ordering::Release);
        assert!(deferred.sign(b"transcript").is_err());
        let config1 = client.config(false).unwrap();
        let config2 = client.config(false).unwrap();
        assert!(!Arc::ptr_eq(&config1, &config2));
        assert!(!Arc::ptr_eq(
            &config1.client_auth_cert_resolver,
            &config2.client_auth_cert_resolver
        ));
        assert_eq!(
            client.config(true).unwrap().alpn_protocols,
            [b"h3".to_vec()]
        );
    }

    #[test]
    fn skip_pin_preserves_rsa_and_ed25519_signature_checks() {
        let rsa = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let cert = certificate(&rsa, Curve::P256).unwrap();
        for scheme in [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ] {
            let digest = rsa_digest(scheme).unwrap();
            let mut signer = NativeSigner::new(digest, &rsa).unwrap();
            if rsa_pkcs1(scheme) {
                signer.set_rsa_padding(Padding::PKCS1).unwrap();
            } else {
                signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                signer
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .unwrap();
                signer.set_rsa_mgf1_md(digest).unwrap();
            }
            let signature = signer.sign_oneshot_to_vec(b"transcript").unwrap();
            assert!(verify_signature(b"transcript", &cert, scheme, &signature, VERSION_12).is_ok());
            assert_eq!(
                verify_signature(b"transcript", &cert, scheme, &signature, VERSION_13).is_ok(),
                !rsa_pkcs1(scheme)
            );
            assert!(verify_signature(b"other", &cert, scheme, &signature, VERSION_12).is_err());
        }
        let key = PKey::generate(Id::ED25519).unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(0).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        let name = X509Name::builder().unwrap().build();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        let before = Asn1Time::from_unix(0).unwrap();
        let after = Asn1Time::from_unix(1).unwrap();
        builder.set_not_before(&before).unwrap();
        builder.set_not_after(&after).unwrap();
        builder.set_pubkey(&key).unwrap();
        // Certificate issuer trust is intentionally unrelated to the leaf's
        // handshake key when pin verification is skipped.
        builder.sign(&rsa, MessageDigest::sha256()).unwrap();
        let cert = CertificateDer::from(builder.build().to_der().unwrap());
        let signature = NativeSigner::new_without_digest(&key)
            .unwrap()
            .sign_oneshot_to_vec(b"transcript")
            .unwrap();
        assert!(
            verify_signature(
                b"transcript",
                &cert,
                SignatureScheme::ED25519,
                &signature,
                VERSION_13
            )
            .is_ok()
        );
        assert!(
            verify_signature(
                b"other",
                &cert,
                SignatureScheme::ED25519,
                &signature,
                VERSION_13
            )
            .is_err()
        );
    }

    #[derive(Debug)]
    struct ClientVerifier {
        verifier: MasqueVerifier,
        scheme: SignatureScheme,
        seen: Arc<Mutex<Option<SignatureScheme>>>,
    }
    impl ClientCertVerifier for ClientVerifier {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }
        fn verify_client_cert(
            &self,
            cert: &CertificateDer<'_>,
            chain: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, Error> {
            self.verifier.verify_chain(cert, chain)?;
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            *self.seen.lock().unwrap() = Some(dss.scheme);
            self.verifier
                .verify_and_publish(message, cert, dss, VERSION_12)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            *self.seen.lock().unwrap() = Some(dss.scheme);
            self.verifier
                .verify_and_publish(message, cert, dss, VERSION_13)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![self.scheme]
        }
    }

    async fn memory_handshake(version: u8, client_scheme: SignatureScheme, rsa_peer: bool) {
        let client_key = ec_key(Nid::SECP521R1);
        let server_key = if rsa_peer {
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
        } else {
            ec_key(Nid::SECP521R1)
        };
        let pin = if rsa_peer {
            client_key.clone()
        } else {
            server_key.clone()
        };
        let client = factory(&client_key, &pin, rsa_peer);
        let mut config = (*client.config(version == VERSION_13).unwrap()).clone();
        if version == VERSION_12 {
            // Restrict the memory peer instead of changing the production config.
            config.alpn_protocols = vec![b"h2".to_vec()];
        }
        let server_cert = certificate(&server_key, Curve::P521).unwrap();
        let server_signer: Arc<dyn SigningKey> = if rsa_peer {
            rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
                server_key.private_key_to_der_pkcs8().unwrap().into(),
            ))
            .unwrap()
        } else {
            let server_factory = factory(&server_key, &client_key, false);
            Arc::new(identity_key(&server_factory, version))
        };
        let seen = Arc::new(Mutex::new(None));
        let server = ServerConfig::builder_with_provider(client.provider.clone())
            .with_protocol_versions(&[if version == VERSION_12 {
                &TLS12
            } else {
                &TLS13
            }])
            .unwrap()
            .with_client_cert_verifier(Arc::new(ClientVerifier {
                verifier: verifier(&client_key, false, version),
                scheme: client_scheme,
                seen: seen.clone(),
            }))
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(CertifiedKey::new(
                vec![server_cert],
                server_signer,
            ))));
        let mut server = server;
        server.alpn_protocols = config.alpn_protocols.clone();
        let (client_io, server_io) = tokio::io::duplex(1024);
        tokio::time::timeout(Duration::from_secs(3), async {
            let consume = async {
                let mut tls = TlsConnector::from(Arc::new(config))
                    .connect(ServerName::try_from("masque.invalid").unwrap(), client_io)
                    .await
                    .unwrap();
                assert_eq!(
                    tls.get_ref().1.protocol_version(),
                    Some(if version == VERSION_12 {
                        ProtocolVersion::TLSv1_2
                    } else {
                        ProtocolVersion::TLSv1_3
                    })
                );
                tls.write_all(b"ping").await.unwrap();
                let mut reply = [0; 4];
                tls.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"pong");
            };
            let serve = async {
                let mut tls = TlsAcceptor::from(Arc::new(server))
                    .accept(server_io)
                    .await
                    .unwrap();
                let mut request = [0; 4];
                tls.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                tls.write_all(b"pong").await.unwrap();
            };
            tokio::join!(consume, serve);
        })
        .await
        .unwrap();
        assert_eq!(*seen.lock().unwrap(), Some(client_scheme));
    }

    #[tokio::test]
    async fn duplex_tls12_p521_sha256_and_tls13_p521_with_client_auth() {
        memory_handshake(VERSION_12, SignatureScheme::ECDSA_NISTP256_SHA256, false).await;
        memory_handshake(VERSION_13, SignatureScheme::ECDSA_NISTP521_SHA512, false).await;
        memory_handshake(VERSION_13, SignatureScheme::ECDSA_NISTP521_SHA512, true).await;
    }
}
