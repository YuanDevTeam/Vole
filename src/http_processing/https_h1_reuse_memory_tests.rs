//! Real upstream TLS over duplex IO, entered after downstream TLS decryption.
//! These tests exercise `serve_h1(Scheme::Https)`, not the full MITM handshake.
//! All identities are generated in memory; no sockets, DNS or files are used.
#[cfg(feature = "sing-mux")]
#[path = "https_h1_sing_mux_reuse_memory_tests.rs"]
mod sing_mux_reuse;

#[cfg(feature = "outbound-shadowsocks")]
#[path = "https_h1_ss_obfs_reuse_memory_tests.rs"]
mod ss_obfs_reuse;

#[cfg(feature = "outbound-shadowsocks")]
#[path = "https_h1_ss_v2ray_mux_reuse_memory_tests.rs"]
mod ss_v2ray_mux_reuse;

#[cfg(feature = "outbound-vmess")]
#[path = "https_h1_vmess_http_cover_reuse_memory_tests.rs"]
mod vmess_http_cover_reuse;

use crate::{
    dispatch::{
        BoxStream, DatagramTransport, DispatchError, Dispatcher, HttpTcpPlan, HttpTcpReuseKey,
        observe_handshakes_with_stats, observe_sessions_with_stats,
    },
    http_processing::{
        HttpContext, Scheme, authority::Authority, config::Document, private_context::CaMaterial,
    },
    inbound::http::{framing, parser::parse_request_head},
    resources::RuntimeResourceStats,
    security::SecurityContext,
    session::{DatagramSession, Destination, InboundKind, InboundMetadata, StreamSession},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(feature = "outbound-vmess")]
use futures_util::FutureExt;
#[cfg(feature = "outbound-vmess")]
use std::panic::AssertUnwindSafe;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
enum Reply {
    Persistent,
    Close,
    Http10,
    Extra,
    Chunked,
    Trailer,
    ContentRange,
    FailSecond,
    Partial,
    EarlyPost,
    WaitPost,
}

struct State {
    authority: Arc<Authority>,
    scope: Arc<()>,
    alpn: Option<&'static [u8]>,
    reply: Reply,
    reject: AtomicBool,
    prepares: AtomicUsize,
    opens: AtomicUsize,
    accepts: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<String>>>,
    uploads: Arc<Mutex<Vec<Vec<u8>>>>,
    sni: Arc<Mutex<Vec<String>>>,
    negotiated: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    sessions: Mutex<Vec<StreamSession>>,
    peers: Mutex<Vec<JoinHandle<()>>>,
    partial: Arc<tokio::sync::Notify>,
    #[cfg(feature = "outbound-shadowsocks")]
    obfs: Mutex<Option<Arc<crate::outbound::MemoryObfsFactory>>>,
    #[cfg(feature = "outbound-vmess")]
    vmess_http_cover: Mutex<Option<Arc<crate::outbound::MemoryVmessHttpCoverFactory>>>,
}

#[derive(Clone)]
struct MemoryTls(Arc<State>);

// Equality evidence owns its scope, rather than comparing a borrowed address.
// Routing and physical-DIRECT proofs are covered by upstream_memory_tests;
// this fixture deliberately supplies one immutable physical in-memory leaf.
struct Identity {
    scope: Arc<()>,
    session: StreamSession,
}
impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope) && self.session == other.session
    }
}
impl Eq for Identity {}

struct Plan {
    origin: MemoryTls,
    session: StreamSession,
    key: HttpTcpReuseKey,
}
#[async_trait]
impl HttpTcpPlan for Plan {
    fn reuse_key(&self) -> Option<&HttpTcpReuseKey> {
        Some(&self.key)
    }
    async fn connect(self: Box<Self>) -> Result<BoxStream, DispatchError> {
        let Self {
            origin, session, ..
        } = *self;
        origin.open(session).await
    }
}

struct OwnedClient {
    io: BoxStream,
    live: Arc<AtomicUsize>,
}
impl Drop for OwnedClient {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl AsyncRead for OwnedClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}
impl AsyncWrite for OwnedClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[async_trait]
impl Dispatcher for MemoryTls {
    async fn prepare_http_tcp(
        &self,
        session: StreamSession,
    ) -> Result<Option<Box<dyn HttpTcpPlan>>, DispatchError> {
        self.0.prepares.fetch_add(1, Ordering::SeqCst);
        if self.0.reject.load(Ordering::SeqCst) {
            return Err(DispatchError::NotAllowed);
        }
        let key = HttpTcpReuseKey::new(Identity {
            scope: self.0.scope.clone(),
            session: session.clone(),
        });
        Ok(Some(Box::new(Plan {
            origin: self.clone(),
            session,
            key,
        })))
    }
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.open(session).await
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

type AcceptedMemoryPeer = Pin<Box<dyn std::future::Future<Output = io::Result<BoxStream>> + Send>>;

fn plain_memory_pair() -> (BoxStream, AcceptedMemoryPeer) {
    let (client, peer) = tokio::io::duplex(8192);
    (
        Box::new(client),
        Box::pin(async move { Ok(Box::new(peer) as BoxStream) }),
    )
}

impl MemoryTls {
    async fn open(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let name = match &session.destination {
            Destination::Domain { host, .. } => host.clone(),
            Destination::Ip(_) => session
                .sniffed_domain
                .clone()
                .expect("the selected original IP must retain its own SNI"),
        };
        // This fixture maps only rewritten port 80 to cleartext; 443 and 444
        // are real TLS peers. It never resolves the symbolic destination.
        let secure = session.destination.port() != 80;
        let config = if secure {
            let mut config = (*self.0.authority.server_config(&name).unwrap()).clone();
            config.alpn_protocols = self.0.alpn.map_or_else(Vec::new, |p| vec![p.to_vec()]);
            Some(Arc::new(config))
        } else {
            None
        };
        self.0.sessions.lock().unwrap().push(session.clone());
        self.0.opens.fetch_add(1, Ordering::SeqCst);
        #[cfg(feature = "outbound-shadowsocks")]
        let factory = self.0.obfs.lock().unwrap().clone();
        #[cfg(feature = "outbound-vmess")]
        let vmess = self.0.vmess_http_cover.lock().unwrap().clone();
        #[cfg(all(feature = "outbound-shadowsocks", feature = "outbound-vmess"))]
        if factory.is_some() && vmess.is_some() {
            return Err(DispatchError::NotAllowed);
        }
        let fallback = async {
            #[cfg(feature = "outbound-shadowsocks")]
            if let Some(factory) = factory {
                return factory.open(session.destination.clone()).await;
            }
            Ok::<_, io::Error>(plain_memory_pair())
        };
        #[cfg(feature = "outbound-vmess")]
        let (client, peer) = match vmess {
            Some(factory) => factory.open(session.destination.clone()).await?,
            None => fallback.await?,
        };
        #[cfg(not(feature = "outbound-vmess"))]
        let (client, peer) = fallback.await?;
        self.0.live.fetch_add(1, Ordering::SeqCst);
        let accepts = self.0.accepts.clone();
        let sni = self.0.sni.clone();
        let negotiated = self.0.negotiated.clone();
        let heads = self.0.heads.clone();
        let uploads = self.0.uploads.clone();
        let partial = self.0.partial.clone();
        let reply = self.0.reply;
        self.0.peers.lock().unwrap().push(tokio::spawn(async move {
            // The real SS handshake must await client TLS bytes, after open returns.
            let peer = peer.await.expect("memory carrier handshake and exact target");
            let stream: BoxStream = if let Some(config) = config {
                let tls = tokio_rustls::TlsAcceptor::from(config)
                    .accept(peer)
                    .await
                    .expect("the in-memory upstream TLS handshake must really succeed");
                accepts.fetch_add(1, Ordering::SeqCst);
                sni.lock()
                    .unwrap()
                    .push(tls.get_ref().1.server_name().unwrap().to_owned());
                negotiated
                    .lock()
                    .unwrap()
                    .push(tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
                Box::new(tls)
            } else {
                peer
            };
            let mut reader = BufReader::new(stream);
            let mut sequence = 0;
            loop {
                let bytes = match framing::read_head(&mut reader, 32768).await {
                    Ok(bytes) => bytes,
                    Err(_) => break, // EOF/cancellation releases this real peer.
                };
                let request = parse_request_head(&bytes, Vec::new()).unwrap();
                assert!(matches!(request.method.as_str(), "GET" | "POST"));
                let text = String::from_utf8(bytes).unwrap();
                heads.lock().unwrap().push(text.clone());
                sequence += 1;
                if matches!(reply, Reply::FailSecond) && sequence == 2 {
                    break; // The second request head was received, never replay it.
                }
                if request.method == "POST" {
                    let expected = request.headers.iter().find_map(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.parse::<usize>().unwrap())
                    }).expect("the fixed POST fixture requires Content-Length");
                    assert!(expected <= 65536);
                    let mut body = vec![0; if matches!(reply, Reply::EarlyPost | Reply::WaitPost) {
                        expected.min(1)
                    } else { expected }];
                    if reader.read_exact(&mut body).await.is_err() {
                        break;
                    }
                    uploads.lock().unwrap().push(body);
                    if matches!(reply, Reply::EarlyPost | Reply::WaitPost) {
                        partial.notify_one();
                    }
                    if matches!(reply, Reply::WaitPost) {
                        // An unfinished upload is released by Core cancellation,
                        // rather than by a fixture-side timer or detached task.
                        let mut tail = Vec::new();
                        let _ = reader.read_to_end(&mut tail).await;
                        break;
                    }
                }
                let wire: &[u8] = match reply {
                    Reply::Close => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
                    Reply::Http10 => b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\norigin",
                    Reply::Extra => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\noriginunsolicited",
                    Reply::Chunked => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n6\r\norigin\r\n0\r\n\r\n",
                    Reply::Trailer => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nTrailer: X-Safe\r\n\r\n6\r\norigin\r\n0\r\nX-Safe: value\r\n\r\n",
                    Reply::ContentRange => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nContent-Range: bytes 0-5/12\r\n\r\norigin",
                    Reply::Partial => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\norigin",
                    _ => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\norigin",
                };
                if reader.get_mut().write_all(wire).await.is_err()
                    || reader.get_mut().flush().await.is_err()
                {
                    break;
                }
                if matches!(reply, Reply::Partial) {
                    partial.notify_one();
                }
                if matches!(reply, Reply::EarlyPost) {
                    let mut tail = Vec::new();
                    let _ = reader.read_to_end(&mut tail).await;
                    break;
                }
                if matches!(reply, Reply::Close | Reply::Http10)
                    || text.to_ascii_lowercase().contains("connection: close")
                {
                    break;
                }
            }
        }));
        Ok(Box::new(OwnedClient {
            io: client,
            live: self.0.live.clone(),
        }))
    }
    fn count(&self, value: &AtomicUsize) -> usize {
        value.load(Ordering::SeqCst)
    }
}

struct Fixture {
    context: HttpContext,
    origin: MemoryTls,
    stats: RuntimeResourceStats,
}
fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
}
fn fixture(alpn: Option<&'static [u8]>, reply: Reply, rewrite_body: bool, extra: &str) -> Fixture {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let certificate = pem("CERTIFICATE", cert.der());
    let private_key = pem("PRIVATE KEY", &key.serialize_der());
    let authority = Authority::load(&certificate, &private_key).unwrap();
    let body = if rewrite_body {
        "          body:\n            - {set: changed}\n"
    } else {
        ""
    };
    let source = format!(
        "targets:\n  - origins: [https://a.test, https://b.test]\n    rules:\n      - response:\n          headers:\n            - {{set: {{X-Native-Proof: memory-tls}}}}\n{body}{extra}"
    );
    let candidate = Document::parse(&source).unwrap().compile().unwrap();
    let policy = candidate
        .bind_settings(
            &crate::http_processing::config::HttpSettings {
                mitm_enabled: true,
                ..Default::default()
            },
            Some(&CaMaterial {
                certificate,
                private_key: zeroize::Zeroizing::new(private_key),
            }),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let origin = MemoryTls(Arc::new(State {
        authority,
        scope: Arc::new(()),
        alpn,
        reply,
        reject: AtomicBool::new(false),
        prepares: AtomicUsize::new(0),
        opens: AtomicUsize::new(0),
        accepts: Arc::new(AtomicUsize::new(0)),
        live: Arc::new(AtomicUsize::new(0)),
        heads: Arc::default(),
        uploads: Arc::default(),
        sni: Arc::default(),
        negotiated: Arc::default(),
        sessions: Mutex::new(Vec::new()),
        peers: Mutex::new(Vec::new()),
        partial: Arc::new(tokio::sync::Notify::new()),
        #[cfg(feature = "outbound-shadowsocks")]
        obfs: Mutex::new(None),
        #[cfg(feature = "outbound-vmess")]
        vmess_http_cover: Mutex::new(None),
    }));
    let stats = RuntimeResourceStats::new("https_h1_reuse_memory");
    let dispatcher = observe_sessions_with_stats(
        observe_handshakes_with_stats(Arc::new(origin.clone()), stats.clone()),
        stats.clone(),
    );
    Fixture {
        context: HttpContext::new(policy, dispatcher, SecurityContext::with_tls_roots(roots)),
        origin,
        stats,
    }
}

struct Running {
    client: BufReader<tokio::io::DuplexStream>,
    cancellation: CancellationToken,
    serving: JoinHandle<io::Result<()>>,
}
fn start(fixture: &Fixture) -> Running {
    let (client, mut peer) = tokio::io::duplex(8192);
    let cancellation = CancellationToken::new();
    let stop = cancellation.clone();
    let context = fixture.context.clone();
    let serving = tokio::spawn(async move {
        context
            .serve_h1(
                &mut peer,
                StreamSession {
                    metadata: InboundMetadata::new(443),
                    inbound: InboundKind::Tun,
                    source: "198.18.0.2:30000".parse().unwrap(),
                    destination: Destination::Ip("203.0.113.1:443".parse().unwrap()),
                    sniffed_domain: Some("a.test".into()),
                },
                Scheme::Https,
                stop,
            )
            .await
    });
    Running {
        client: BufReader::new(client),
        cancellation,
        serving,
    }
}
async fn joined<T>(mut task: JoinHandle<T>) -> Result<T, String> {
    match timeout(WAIT, &mut task).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err("the real memory task did not join before the deadline".into())
        }
    }
}
async fn finish(running: Running, fixture: &Fixture) -> io::Result<()> {
    // Keep the downstream open until serving has actually joined. EOF must not
    // be the only reason an idle or partly consumed TLS owner gets released.
    running.cancellation.cancel();
    let result = joined(running.serving).await;
    let mut failures = Vec::new();
    if let Err(error) = &result {
        failures.push(error.clone());
    }
    #[cfg(feature = "outbound-vmess")]
    {
        let factory = fixture
            .origin
            .0
            .vmess_http_cover
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if let Some(factory) = factory {
            if AssertUnwindSafe(factory.shutdown())
                .catch_unwind()
                .await
                .is_err()
            {
                failures.push("actual VMess HTTP-cover owner shutdown panicked".into());
            }
        }
    }
    let peers = std::mem::take(&mut *fixture.origin.0.peers.lock().unwrap());
    for peer in peers {
        if let Err(error) = joined(peer).await {
            failures.push(error);
        }
    }
    drop(running.client);
    assert!(
        failures.is_empty(),
        "all real owners must join: {failures:?}"
    );
    assert_eq!(fixture.origin.count(&fixture.origin.0.live), 0);
    assert_eq!(fixture.stats.snapshot().tcp_current, 0);
    assert_eq!(fixture.stats.snapshot().handshake_current, 0);
    result.unwrap()
}
async fn request(
    running: &mut Running,
    authority: &str,
    path: &str,
) -> io::Result<(String, Vec<u8>)> {
    request_fields(running, authority, path, "").await
}
async fn request_fields(
    running: &mut Running,
    authority: &str,
    path: &str,
    fields: &str,
) -> io::Result<(String, Vec<u8>)> {
    timeout(WAIT, async {
        running
            .client
            .get_mut()
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n{fields}\r\n").as_bytes(),
            )
            .await?;
        let head = framing::read_head(&mut running.client, 32768).await?;
        let response = framing::ResponseHead::parse(&head)?;
        let mut body = Vec::new();
        framing::transfer_body(
            &mut running.client,
            &mut body,
            response.body("GET"),
            WAIT,
            response.trailer_blocklist(),
            true,
        )
        .await?;
        Ok((String::from_utf8(head).unwrap(), body))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "memory response timed out"))?
}
fn native_response(result: io::Result<(String, Vec<u8>)>, body: &[u8]) {
    let (head, actual) = result.unwrap();
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(
        head.to_ascii_lowercase()
            .contains("x-native-proof: memory-tls")
    );
    assert_eq!(actual, body);
}

async fn fixed_post(
    running: &mut Running,
    path: &str,
    body: &[u8],
) -> io::Result<(String, Vec<u8>)> {
    timeout(WAIT, async {
        running.client.get_mut().write_all(format!(
            "POST {path} HTTP/1.1\r\nHost: a.test\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n", body.len()
        ).as_bytes()).await?;
        running.client.get_mut().write_all(body).await?;
        running.client.get_mut().flush().await?;
        let head = framing::read_head(&mut running.client, 32768).await?;
        let response = framing::ResponseHead::parse(&head)?;
        let mut received = Vec::new();
        framing::transfer_body(&mut running.client, &mut received, response.body("POST"), WAIT, response.trailer_blocklist(), true).await?;
        Ok((String::from_utf8(head).unwrap(), received))
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixed POST response timed out"))?
}

#[tokio::test]
async fn completed_post_h1_reuses_only_after_full_fixed_upload_and_response() {
    for native in [false, true] {
        let extra = if native {
            "      - request:\n          body:\n            - {set: transformed}\n"
        } else {
            ""
        };
        let fixture = fixture(Some(b"http/1.1"), Reply::Persistent, false, extra);
        let mut running = start(&fixture);
        let first = fixed_post(&mut running, "/one", b"original").await;
        let second = fixed_post(&mut running, "/two", b"original").await;
        let finished = finish(running, &fixture).await;
        native_response(first, b"origin");
        native_response(second, b"origin");
        finished.unwrap();
        assert_eq!(fixture.origin.count(&fixture.origin.0.prepares), 2);
        assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 1);
        assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), 1);
        let expected = if native {
            b"transformed".as_slice()
        } else {
            b"original".as_slice()
        };
        assert_eq!(
            *fixture.origin.0.uploads.lock().unwrap(),
            vec![expected.to_vec(), expected.to_vec()]
        );
        assert!(
            fixture
                .origin
                .0
                .heads
                .lock()
                .unwrap()
                .iter()
                .all(|head| head.to_ascii_lowercase().contains("connection: keep-alive"))
        );
    }
}

#[tokio::test]
async fn completed_post_h1_sent_second_request_is_never_replayed() {
    let fixture = fixture(Some(b"http/1.1"), Reply::FailSecond, false, "");
    let mut running = start(&fixture);
    let first = fixed_post(&mut running, "/one", b"original").await;
    let second = fixed_post(&mut running, "/two", b"original").await;
    let finished = finish(running, &fixture).await;
    native_response(first, b"origin");
    if let Ok((head, body)) = second {
        // The ordinary H1 forwarder can frame the upstream failure before
        // propagating its IO error. A gateway error is not a replayed response.
        let response = framing::ResponseHead::parse(head.as_bytes()).unwrap();
        assert!(matches!(response.status, 400 | 502));
        assert!(body.is_empty());
    }
    assert!(finished.is_err());
    assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 1);
    assert_eq!(fixture.origin.0.heads.lock().unwrap().len(), 2);
    assert_eq!(fixture.origin.0.uploads.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn completed_post_h1_partial_upload_early_final_closes_both_owners() {
    let fixture = fixture(Some(b"http/1.1"), Reply::EarlyPost, false, "");
    let mut running = start(&fixture);
    let result = timeout(WAIT, async {
        running
            .client
            .get_mut()
            .write_all(b"POST /early HTTP/1.1\r\nHost: a.test\r\nContent-Length: 65536\r\n\r\nx")
            .await?;
        let head = framing::read_head(&mut running.client, 32768).await?;
        let response = framing::ResponseHead::parse(&head)?;
        let mut body = Vec::new();
        framing::transfer_body(
            &mut running.client,
            &mut body,
            response.body("POST"),
            WAIT,
            response.trailer_blocklist(),
            false,
        )
        .await?;
        let mut tail = [0; 1];
        let eof = running.client.read(&mut tail).await?;
        Ok::<_, io::Error>((head, body, eof))
    })
    .await;
    let finished = finish(running, &fixture).await;
    let (head, body, eof) = result.unwrap().unwrap();
    finished.unwrap();
    assert!(
        String::from_utf8(head)
            .unwrap()
            .to_ascii_lowercase()
            .contains("connection: close")
    );
    assert_eq!(body, b"origin");
    assert_eq!(eof, 0);
    assert_eq!(
        *fixture.origin.0.uploads.lock().unwrap(),
        vec![b"x".to_vec()]
    );
    assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 1);
}

#[tokio::test]
async fn completed_post_h1_cancellation_joins_an_unfinished_upload() {
    let fixture = fixture(Some(b"http/1.1"), Reply::WaitPost, false, "");
    let mut running = start(&fixture);
    let started = timeout(WAIT, async {
        running
            .client
            .get_mut()
            .write_all(b"POST /cancel HTTP/1.1\r\nHost: a.test\r\nContent-Length: 65536\r\n\r\nx")
            .await?;
        fixture.origin.0.partial.notified().await;
        Ok::<_, io::Error>(())
    })
    .await;
    let finished = finish(running, &fixture).await;
    started.unwrap().unwrap();
    finished.unwrap();
    assert_eq!(
        *fixture.origin.0.uploads.lock().unwrap(),
        vec![b"x".to_vec()]
    );
    assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 1);
}

#[tokio::test]
async fn https_h1_actual_h1_or_no_alpn_reuses_one_tls_owner_for_two_native_responses() {
    for alpn in [Some(b"http/1.1".as_slice()), None] {
        let fixture = fixture(alpn, Reply::Persistent, true, "");
        let mut running = start(&fixture);
        let first = request(&mut running, "a.test", "/one").await;
        let second = request(&mut running, "a.test", "/two").await;
        let active = fixture.stats.snapshot();
        finish(running, &fixture).await.unwrap();
        native_response(first, b"changed");
        native_response(second, b"changed");
        assert_eq!(fixture.origin.count(&fixture.origin.0.prepares), 2);
        assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 1);
        assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), 1);
        assert_eq!(fixture.origin.0.heads.lock().unwrap().len(), 2);
        assert_eq!(
            *fixture.origin.0.sni.lock().unwrap(),
            vec!["a.test".to_owned()]
        );
        assert_eq!(
            *fixture.origin.0.negotiated.lock().unwrap(),
            vec![alpn.map(<[u8]>::to_vec)]
        );
        assert_eq!(active.tcp_current, 1);
        assert_eq!(active.handshake_current, 0);
    }
}

#[tokio::test]
async fn https_h1_request_close_retires_a_previously_cached_tls_owner() {
    let fixture = fixture(Some(b"http/1.1"), Reply::Persistent, false, "");
    let mut running = start(&fixture);
    let first = request(&mut running, "a.test", "/one").await;
    let second = request_fields(&mut running, "a.test", "/closing", "Connection: close\r\n").await;
    let serving = finish(running, &fixture).await;
    native_response(first, b"origin");
    native_response(second, b"origin");
    serving.unwrap();
    assert_eq!(fixture.origin.count(&fixture.origin.0.prepares), 1);
    assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 2);
    assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), 2);
    let heads = fixture.origin.0.heads.lock().unwrap();
    assert_eq!(heads.len(), 2);
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("connection: keep-alive")
    );
    assert!(heads[1].to_ascii_lowercase().contains("connection: close"));
}

#[tokio::test]
async fn https_h1_original_wire_retirement_cases_require_two_real_tls_accepts() {
    for reply in [
        Reply::Close,
        Reply::Http10,
        Reply::Extra,
        Reply::Chunked,
        Reply::Trailer,
        Reply::ContentRange,
    ] {
        let fixture = fixture(Some(b"http/1.1"), reply, false, "");
        let mut running = start(&fixture);
        let first = request(&mut running, "a.test", "/one").await;
        let second = request(&mut running, "a.test", "/two").await;
        finish(running, &fixture).await.unwrap();
        native_response(first, b"origin");
        native_response(second, b"origin");
        assert_eq!(fixture.origin.count(&fixture.origin.0.prepares), 2);
        assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 2);
        assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), 2);
        assert_eq!(fixture.origin.0.heads.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn https_h1_host_port_and_scheme_rewrites_keep_one_shot_and_final_sni() {
    for (replacement, name, port, accepts) in [
        ("https://b.test/final", "b.test", 443, 2),
        ("https://a.test:444/final", "a.test", 444, 2),
        ("http://a.test/final", "a.test", 80, 0),
    ] {
        let extra = format!(
            "      - match: {{url-regex: '^https://a\\.test/rewrite'}}\n        request:\n          url: {{replace: '{replacement}'}}\n"
        );
        let fixture = fixture(Some(b"http/1.1"), Reply::Persistent, false, &extra);
        let mut running = start(&fixture);
        let first = request(&mut running, "a.test", "/rewrite-one").await;
        let second = request(&mut running, "a.test", "/rewrite-two").await;
        finish(running, &fixture).await.unwrap();
        native_response(first, b"origin");
        native_response(second, b"origin");
        assert_eq!(fixture.origin.count(&fixture.origin.0.prepares), 0);
        assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 2);
        assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), accepts);
        let sessions = fixture.origin.0.sessions.lock().unwrap();
        assert!(sessions.iter().all(|s| {
            s.destination == Destination::domain(name, port).unwrap() && s.sniffed_domain.is_none()
        }));
        let expected: Vec<String> = (0..accepts).map(|_| name.to_owned()).collect();
        assert_eq!(*fixture.origin.0.sni.lock().unwrap(), expected);
        assert!(fixture.origin.0.heads.lock().unwrap().iter().all(|head| {
            head.starts_with("GET /final HTTP/1.1\r\n")
                && head.to_ascii_lowercase().contains("connection: close")
        }));
    }
}

#[tokio::test]
async fn https_h1_unauthorized_original_authority_is_rejected_before_rewrite_or_reuse() {
    let fixture = fixture(Some(b"http/1.1"), Reply::Persistent, false, "");
    let mut running = start(&fixture);
    let first = request(&mut running, "a.test", "/one").await;
    let (head, body) = request(&mut running, "denied.test", "/two").await.unwrap();
    finish(running, &fixture).await.unwrap();
    native_response(first, b"origin");
    assert!(head.starts_with("HTTP/1.1 403 Forbidden"));
    assert!(body.is_empty());
    assert_eq!(fixture.origin.count(&fixture.origin.0.prepares), 1);
    assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 1);
    assert_eq!(fixture.origin.0.heads.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn https_h1_idle_and_partial_response_cancel_join_actual_tls_owners() {
    for reply in [Reply::Persistent, Reply::Partial] {
        let fixture = fixture(Some(b"http/1.1"), reply, false, "");
        let mut running = start(&fixture);
        let initial = async {
            if matches!(reply, Reply::Partial) {
                running
                    .client
                    .get_mut()
                    .write_all(b"GET /partial HTTP/1.1\r\nHost: a.test\r\n\r\n")
                    .await?;
                timeout(WAIT, fixture.origin.0.partial.notified())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "missing partial TLS response")
                    })?;
                Ok::<_, io::Error>(None)
            } else {
                request(&mut running, "a.test", "/idle").await.map(Some)
            }
        }
        .await;
        let live = fixture.origin.count(&fixture.origin.0.live);
        let active = fixture.stats.snapshot().tcp_current;
        let finished = finish(running, &fixture).await;
        if let Some(response) = initial.unwrap() {
            native_response(Ok(response), b"origin");
        }
        finished.unwrap();
        assert_eq!(live, 1);
        assert_eq!(active, 1);
        assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), 1);
    }
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn https_h1_native_then_real_js_a_b_a_does_not_recover_reuse_eligibility() {
    let extra = r#"      - match: {url-regex: '^https://a\.test/'}
        request:
          url: {replace: https://b.test/middle}
      - name: return-to-original
        match: {url-regex: '^https://a\.test/'}
        request:
          js:
            source: |
              function rewrite(input) {
                if (input.request.url !== "https://b.test/middle") return {type:"abort"};
                return {type:"modify",url:"https://a.test/final",headers:[{op:"set",name:"X-Round-Trip",values:["real-jsc"]}]};
              }
"#;
    let fixture = fixture(Some(b"http/1.1"), Reply::Persistent, false, extra);
    let mut running = start(&fixture);
    let first = request(&mut running, "a.test", "/one").await;
    let second = request(&mut running, "a.test", "/two").await;
    finish(running, &fixture).await.unwrap();
    native_response(first, b"origin");
    native_response(second, b"origin");
    assert_eq!(fixture.origin.count(&fixture.origin.0.prepares), 0);
    assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 2);
    assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), 2);
    assert_eq!(
        *fixture.origin.0.sni.lock().unwrap(),
        vec!["a.test".to_owned(), "a.test".to_owned()]
    );
    let heads = fixture.origin.0.heads.lock().unwrap();
    assert_eq!(heads.len(), 2);
    assert!(heads.iter().all(|head| {
        let lower = head.to_ascii_lowercase();
        head.starts_with("GET /final HTTP/1.1\r\n")
            && lower.contains("x-round-trip: real-jsc")
            && lower.contains("connection: close")
    }));
}
