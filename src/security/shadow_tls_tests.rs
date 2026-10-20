//! Public wrapper behavior with native TLS over bounded memory IO. The scripted
//! relay is only a fault fixture; official server interoperability is separate.
use super::{SecurityContext, ShadowTlsClient};
use crate::config::ShadowTlsConfig;
use rustls::{RootCertStore, ServerConfig, ServerConnection, pki_types::PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const PASSWORD: &[u8] = b"synthetic-memory-relay";

struct Material {
    server: Arc<ServerConfig>,
    context: SecurityContext,
    options: ShadowTlsConfig,
    pin: [u8; 32],
}

fn material() -> Material {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["cover.invalid".into()]).unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(signing_key.serialize_der().into()),
        )
        .unwrap();
    server.send_tls13_tickets = 0;
    Material {
        pin: Sha256::digest(cert.der()).into(),
        server: Arc::new(server),
        context: SecurityContext {
            provider,
            tls_roots: Arc::new(roots),
            identities: Arc::default(),
        },
        options: ShadowTlsConfig {
            server_name: "cover.invalid".into(),
            password: String::from_utf8(PASSWORD.to_vec()).unwrap(),
            alpn: vec![],
            required_alpn: None,
            identity: None,
            certificate: Default::default(),
            client_fingerprint: None,
        },
    }
}

#[derive(Debug)]
struct ForgedResolver(Arc<dyn rustls::server::ResolvesServerCert>);
impl rustls::server::ResolvesServerCert for ForgedResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let genuine = self.0.resolve(hello)?;
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            genuine.cert.clone(),
            Arc::new(ForgedKey),
        )))
    }
}
#[derive(Debug)]
struct ForgedKey;
impl rustls::sign::SigningKey for ForgedKey {
    fn choose_scheme(
        &self,
        schemes: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        schemes
            .contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(Self) as Box<dyn rustls::sign::Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}
impl rustls::sign::Signer for ForgedKey {
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(vec![0; 64])
    }
    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[tokio::test]
async fn certificate_policy_and_native_signature_must_succeed_before_a_shadowtls_stream_exists() {
    let _case = crate::resources::case_events::Case::new("SHADOWTLS-UNIT", "native_signature");
    for profile in super::test_profiles() {
        for failure in [
            "name",
            "untrusted",
            "pin",
            "signature",
            "signature-skip",
            "signature-pin",
        ] {
            let mut material = material();
            material.options.client_fingerprint = *profile;
            match failure {
                "name" => {
                    material.options.certificate.verification_name = Some("wrong.invalid".into())
                }
                "untrusted" => material.context = SecurityContext::new(),
                "pin" => material.options.certificate.fingerprint = Some([0; 32]),
                "signature-skip" => material.options.certificate.skip_cert_verify = true,
                "signature-pin" => material.options.certificate.fingerprint = Some(material.pin),
                _ => {}
            }
            if failure.starts_with("signature") {
                let server = Arc::make_mut(&mut material.server);
                server.cert_resolver = Arc::new(ForgedResolver(server.cert_resolver.clone()));
            }
            let client = ShadowTlsClient::new(&material.context, &material.options).unwrap();
            let (raw, mut peer) = tokio::io::duplex(73);
            tokio::time::timeout(Duration::from_secs(3), async {
                let (consumer, native) = tokio::join!(
                    client.connect(Box::new(raw)),
                    handshake(&mut peer, material.server)
                );
                assert!(consumer.is_err(), "{failure} / {profile:?}");
                assert!(
                    native.is_err(),
                    "native TLS did not authenticate the client Finished"
                );
            })
            .await
            .unwrap();
        }
    }
}

// Test oracle deliberately uses boring's one-shot HMAC and a bounded transcript,
// not the production ring context or record implementation.
struct Transcript(Vec<u8>);
impl Transcript {
    fn new(seed: &[u8], direction: &[u8]) -> Self {
        Self([seed, direction].concat())
    }
    fn tag(&mut self, payload: &[u8], chain: bool) -> [u8; 4] {
        self.0.extend_from_slice(payload);
        assert!(self.0.len() <= 1024 * 1024, "memory oracle bound");
        let tag: [u8; 4] = boring::hash::hmac_sha1(PASSWORD, &self.0).unwrap()[..4]
            .try_into()
            .unwrap();
        if chain {
            self.0.extend_from_slice(&tag);
        }
        tag
    }
    fn seal(&mut self, payload: &[u8], chain: bool) -> Vec<u8> {
        let mut output = vec![23, 3, 3];
        output.extend_from_slice(&u16::try_from(payload.len() + 4).unwrap().to_be_bytes());
        output.extend_from_slice(&self.tag(payload, chain));
        output.extend_from_slice(payload);
        output
    }
}

async fn record(raw: &mut DuplexStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 5];
    raw.read_exact(&mut header).await?;
    let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
    assert!((1..=18436).contains(&size));
    let mut bytes = header.to_vec();
    bytes.resize(5 + size, 0);
    raw.read_exact(&mut bytes[5..]).await?;
    Ok(bytes)
}

struct Flight {
    seed: Option<[u8; 32]>,
    cover: Option<Transcript>,
    mask: [u8; 32],
    finished_fault: Option<FinishedFault>,
}
impl Flight {
    fn new() -> Self {
        Self {
            seed: None,
            cover: None,
            mask: [0; 32],
            finished_fault: None,
        }
    }
    fn transform(&mut self, records: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut at = 0;
        while at < records.len() {
            let size = usize::from(u16::from_be_bytes([records[at + 3], records[at + 4]]));
            let mut wire = records[at..at + 5 + size].to_vec();
            if wire[0] == 23
                && let Some(fault) = &mut self.finished_fault
            {
                fault.mutate(&mut wire);
            }
            let record = wire.as_slice();
            if record[0] == 22 && self.seed.is_none() {
                assert_eq!(record[5], 2);
                let seed: [u8; 32] = record[11..43].try_into().unwrap();
                self.cover = Some(Transcript::new(&seed, b""));
                self.mask = Sha256::digest([PASSWORD, &seed].concat()).into();
                self.seed = Some(seed);
            }
            if record[0] == 23 {
                let payload: Vec<_> = record[5..]
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ self.mask[i % 32])
                    .collect();
                output.extend(self.cover.as_mut().unwrap().seal(&payload, false));
            } else {
                output.extend_from_slice(record);
            }
            at += 5 + size;
        }
        output
    }
    async fn flush(
        &mut self,
        tls: &mut ServerConnection,
        raw: &mut DuplexStream,
    ) -> io::Result<()> {
        let mut records = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut records)?;
        }
        let transformed = self.transform(&records);
        for chunk in transformed.chunks(7) {
            raw.write_all(chunk).await?;
        }
        raw.flush().await
    }
}

async fn handshake(
    raw: &mut DuplexStream,
    config: Arc<ServerConfig>,
) -> io::Result<(ServerConnection, Flight)> {
    handshake_with_flight(raw, config, Flight::new()).await
}

async fn handshake_with_flight(
    raw: &mut DuplexStream,
    config: Arc<ServerConfig>,
    mut flight: Flight,
) -> io::Result<(ServerConnection, Flight)> {
    let mut tls = ServerConnection::new(config).unwrap();
    while tls.is_handshaking() {
        let wire = record(raw).await?;
        tls.read_tls(&mut io::Cursor::new(wire))?;
        tls.process_new_packets().map_err(io::Error::other)?;
        flight.flush(&mut tls, raw).await?;
    }
    Ok((tls, flight))
}

// Fault injection uses only the public native TLS key-log seam, retained in
// memory for this synthetic connection. Native rustls creates the entire TLS
// flight. We alter Finished verify_data and reseal that one record with ring,
// so its AEAD and outer ShadowTLS MAC remain valid. No test TLS engine, key log
// file, production hook or copied third-party implementation is involved.
#[derive(Default)]
struct Secret(Mutex<zeroize::Zeroizing<Vec<u8>>>);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntheticHandshakeSecret")
            .finish_non_exhaustive()
    }
}
impl rustls::KeyLog for Secret {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
            self.0.lock().unwrap().extend_from_slice(secret);
        }
    }
}
struct FinishedFault {
    secret: Arc<Secret>,
    sequence: u64,
    applied: Arc<AtomicBool>,
}
impl FinishedFault {
    fn mutate(&mut self, record: &mut [u8]) {
        use ring::{aead, hkdf};
        struct Size(usize);
        impl hkdf::KeyType for Size {
            fn len(&self) -> usize {
                self.0
            }
        }
        let derive = |label: &[u8], size: usize| {
            let secret = self.secret.0.lock().unwrap();
            assert_eq!(secret.len(), 32);
            let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &secret);
            let label = [b"tls13 ", label].concat();
            let mut info = (size as u16).to_be_bytes().to_vec();
            info.push(label.len() as u8);
            info.extend_from_slice(&label);
            info.push(0);
            let mut output = zeroize::Zeroizing::new(vec![0; size]);
            prk.expand(&[&info], Size(size))
                .unwrap()
                .fill(&mut output)
                .unwrap();
            output
        };
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &derive(b"key", 16)).unwrap(),
        );
        let mut nonce: [u8; 12] = derive(b"iv", 12).as_slice().try_into().unwrap();
        for (index, byte) in self.sequence.to_be_bytes().iter().enumerate() {
            nonce[index + 4] ^= byte;
        }
        self.sequence += 1;
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let mut plain = record[5..].to_vec();
        let len = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(header),
                &mut plain,
            )
            .unwrap()
            .len();
        plain.truncate(len);
        assert_eq!(plain.last(), Some(&22));
        let mut at = 0;
        while at + 1 < plain.len() {
            let len = u32::from_be_bytes([0, plain[at + 1], plain[at + 2], plain[at + 3]]) as usize;
            assert!(at + 4 + len < plain.len());
            if plain[at] == 20 {
                assert_eq!(len, 32);
                assert!(!self.applied.swap(true, Ordering::SeqCst));
                plain[at + 4] ^= 1;
            }
            at += 4 + len;
        }
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(header),
            &mut plain,
        )
        .unwrap();
        record[5..].copy_from_slice(&plain);
    }
}

#[tokio::test]
async fn a_forged_finished_is_rejected_even_when_record_aead_relay_mac_and_pin_are_valid() {
    let _case = crate::resources::case_events::Case::new("SHADOWTLS-UNIT", "native_finished");
    for profile in super::test_profiles() {
        for policy in ["webpki", "skip", "pin"] {
            let mut material = material();
            material.options.client_fingerprint = *profile;
            if policy == "skip" {
                material.options.certificate.skip_cert_verify = true;
            }
            if policy == "pin" {
                material.options.certificate.fingerprint = Some(material.pin);
            }
            let secret = Arc::new(Secret::default());
            Arc::make_mut(&mut material.server).key_log = secret.clone();
            let applied = Arc::new(AtomicBool::new(false));
            let mut flight = Flight::new();
            flight.finished_fault = Some(FinishedFault {
                secret,
                sequence: 0,
                applied: applied.clone(),
            });
            let client = ShadowTlsClient::new(&material.context, &material.options).unwrap();
            let (raw, mut peer) = tokio::io::duplex(73);
            tokio::time::timeout(Duration::from_secs(3), async {
                let (consumer, native) = tokio::join!(
                    client.connect(Box::new(raw)),
                    handshake_with_flight(&mut peer, material.server, flight)
                );
                assert!(applied.load(Ordering::SeqCst));
                assert!(consumer.is_err(), "{profile:?} / {policy}");
                assert!(native.is_err());
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn authenticated_stream_ignores_residual_cover_and_preserves_partial_io_flush_and_eof() {
    let _case = crate::resources::case_events::Case::new("SHADOWTLS-UNIT", "stream_io");
    for profile in super::test_profiles() {
        let mut material = material();
        material.options.client_fingerprint = *profile;
        let client = ShadowTlsClient::new(&material.context, &material.options).unwrap();
        let (raw, mut peer) = tokio::io::duplex(73);
        tokio::time::timeout(Duration::from_secs(10), async {
            let server = async {
                let (mut tls, mut flight) = handshake(&mut peer, material.server).await.unwrap();
                // More than one poll's record quota, from real native TLS.
                for _ in 0..40 {
                    io::Write::write_all(&mut tls.writer(), b"residual-cover").unwrap();
                    flight.flush(&mut tls, &mut peer).await.unwrap();
                }
                let seed = flight.seed.unwrap();
                let mut transmit = Transcript::new(&seed, b"S");
                peer.write_all(&transmit.seal(b"server-first", true))
                    .await
                    .unwrap();
                let mut receive = Transcript::new(&seed, b"C");
                let mut input = Vec::new();
                while input.len() < 131_072 {
                    let bytes = record(&mut peer).await.unwrap();
                    assert_eq!(&bytes[..3], &[23, 3, 3]);
                    assert_eq!(receive.tag(&bytes[9..], true), bytes[5..9]);
                    input.extend_from_slice(&bytes[9..]);
                }
                assert_eq!(input, vec![0x5a; 131_072]);
                assert_eq!(
                    peer.read(&mut [0; 1]).await.unwrap(),
                    0,
                    "only raw FIN after flush; no TLS close_notify as SS bytes"
                );
                peer.write_all(&transmit.seal(b"tail", true)).await.unwrap();
                peer.shutdown().await.unwrap();
            };
            let consumer = async {
                let mut stream = client.connect(Box::new(raw)).await.unwrap();
                let mut hello = [0; 12];
                for byte in &mut hello {
                    stream.read_exact(std::slice::from_mut(byte)).await.unwrap();
                }
                assert_eq!(&hello, b"server-first");
                stream.write_all(&vec![0x5a; 131_072]).await.unwrap();
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
                let mut tail = Vec::new();
                stream.read_to_end(&mut tail).await.unwrap();
                assert_eq!(tail, b"tail");
            };
            tokio::join!(server, consumer);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn cancelling_a_partial_authenticated_record_read_preserves_it_for_the_next_reader() {
    let _case = crate::resources::case_events::Case::new("SHADOWTLS-UNIT", "read_cancel");
    let material = material();
    let client = ShadowTlsClient::new(&material.context, &material.options).unwrap();
    let (raw, mut peer) = tokio::io::duplex(73);
    let (sent, seen) = tokio::sync::oneshot::channel();
    let (resume, ready) = tokio::sync::oneshot::channel();
    tokio::time::timeout(Duration::from_secs(3), async {
        let server = async {
            let (_, flight) = handshake(&mut peer, material.server).await.unwrap();
            let mut transmit = Transcript::new(&flight.seed.unwrap(), b"S");
            let wire = transmit.seal(b"one-intact-response", true);
            peer.write_all(&wire[..8]).await.unwrap();
            sent.send(()).unwrap();
            ready.await.unwrap();
            peer.write_all(&wire[8..]).await.unwrap();
            peer.shutdown().await.unwrap();
        };
        let consumer = async {
            let mut stream = client.connect(Box::new(raw)).await.unwrap();
            seen.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(10), stream.read(&mut [0; 1]))
                    .await
                    .is_err()
            );
            resume.send(()).unwrap();
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"one-intact-response");
        };
        tokio::join!(server, consumer);
    })
    .await
    .unwrap();
}

struct WriteGate {
    io: DuplexStream,
    blocked: Arc<AtomicBool>,
}
impl tokio::io::AsyncRead for WriteGate {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, out)
    }
}
impl tokio::io::AsyncWrite for WriteGate {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if self.blocked.load(Ordering::SeqCst) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_has_a_five_second_bound_even_when_the_caller_transport_never_becomes_writable() {
    let _case = crate::resources::case_events::Case::new("SHADOWTLS-UNIT", "close_deadline");
    let material = material();
    let client = ShadowTlsClient::new(&material.context, &material.options).unwrap();
    let (raw, mut peer) = tokio::io::duplex(73);
    let blocked = Arc::new(AtomicBool::new(false));
    let io = WriteGate {
        io: raw,
        blocked: blocked.clone(),
    };
    let server = async {
        handshake(&mut peer, material.server).await.unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    };
    let consumer = async {
        let mut stream = client.connect(Box::new(io)).await.unwrap();
        blocked.store(true, Ordering::SeqCst);
        stream
            .write_all(b"accepted-but-backpressured")
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        let error = stream.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert!(stream.write_all(b"must-not-retry").await.is_err());
        drop(stream);
    };
    tokio::time::timeout(Duration::from_secs(6), async {
        tokio::join!(server, consumer);
    })
    .await
    .unwrap();
}
