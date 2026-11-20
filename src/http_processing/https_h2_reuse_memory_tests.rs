//! Real TLS/H2 and ALPN-H1 over duplex; no listener, DNS or file material.
#[cfg(feature = "outbound-shadowsocks")]
#[path = "https_h2_ss_obfs_reuse_memory_tests.rs"]
mod ss_obfs_reuse;

#[cfg(feature = "outbound-shadowsocks")]
#[path = "https_h2_ss_v2ray_mux_reuse_memory_tests.rs"]
mod ss_v2ray_mux_reuse;

#[cfg(feature = "outbound-vmess")]
#[path = "https_h2_vmess_http_cover_reuse_memory_tests.rs"]
mod vmess_http_cover_reuse;

use crate::{
    dispatch::{
        BoxStream, DatagramTransport, DispatchError, Dispatcher, HttpTcpPlan, HttpTcpReuseKey,
    },
    http_processing::{
        HttpContext, authority::Authority, config::Document, private_context::CaMaterial,
    },
    security::SecurityContext,
    session::{DatagramSession, Destination, InboundKind, InboundMetadata, StreamSession},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use http::{Request, Response, StatusCode};
use std::panic::AssertUnwindSafe;
use std::{
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    task::JoinHandle,
    time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(3);
const PAYLOAD: &[u8] = b"from-origin";
#[derive(Clone, Copy, Default)]
enum PostReply {
    #[default]
    Complete,
    Early,
    Wait,
    FailSecond,
}
#[derive(Default)]
struct GoAwayProbe {
    observed: CancellationToken,
    release_response: CancellationToken,
    requests: Mutex<Vec<(usize, String)>>,
}

#[derive(Clone)]
struct Origin(Arc<Inner>);
struct Inner {
    authority: Arc<Authority>,
    h2: bool,
    scope: Arc<()>,
    key: AtomicUsize,
    reusable: AtomicBool,
    prepares: AtomicUsize,
    opens: AtomicUsize,
    accepts: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    sni: Arc<Mutex<Vec<String>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    post_reply: PostReply,
    uploads: Arc<Mutex<Vec<Vec<u8>>>>,
    post_heads: Arc<AtomicUsize>,
    post_started: Arc<tokio::sync::Notify>,
    go_away: Option<Arc<GoAwayProbe>>,
    #[cfg(feature = "outbound-shadowsocks")]
    obfs: Mutex<Option<Arc<crate::outbound::MemoryObfsFactory>>>,
    #[cfg(feature = "outbound-vmess")]
    vmess_http_cover: Mutex<Option<Arc<crate::outbound::MemoryVmessHttpCoverFactory>>>,
}
struct Key {
    scope: Arc<()>,
    version: usize,
    session: StreamSession,
}
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope)
            && self.version == other.version
            && self.session == other.session
    }
}
impl Eq for Key {}
struct Plan {
    origin: Origin,
    session: StreamSession,
    key: Option<HttpTcpReuseKey>,
}
#[async_trait]
impl HttpTcpPlan for Plan {
    fn reuse_key(&self) -> Option<&HttpTcpReuseKey> {
        self.key.as_ref()
    }
    async fn connect(self: Box<Self>) -> Result<BoxStream, DispatchError> {
        self.origin.open(self.session).await
    }
}
struct Io<T> {
    io: T,
    live: Arc<AtomicUsize>,
}
impl<T> Io<T> {
    fn new(io: T, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::AcqRel);
        Self {
            io,
            live: live.clone(),
        }
    }
}
impl<T> Drop for Io<T> {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Io<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Io<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
#[async_trait]
impl Dispatcher for Origin {
    async fn prepare_http_tcp(
        &self,
        session: StreamSession,
    ) -> Result<Option<Box<dyn HttpTcpPlan>>, DispatchError> {
        self.0.prepares.fetch_add(1, Ordering::AcqRel);
        let key = self.0.reusable.load(Ordering::Acquire).then(|| {
            HttpTcpReuseKey::new(Key {
                scope: self.0.scope.clone(),
                version: self.0.key.load(Ordering::Acquire),
                session: session.clone(),
            })
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
type AcceptedMemoryPeer =
    Pin<Box<dyn std::future::Future<Output = std::io::Result<BoxStream>> + Send>>;

fn plain_memory_pair(live: &Arc<AtomicUsize>) -> (BoxStream, AcceptedMemoryPeer) {
    let (client, peer) = tokio::io::duplex(8192);
    let peer = Io::new(peer, live);
    (
        Box::new(client),
        Box::pin(async move { Ok(Box::new(peer) as BoxStream) }),
    )
}

impl Origin {
    async fn open(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let connection_index = self.0.opens.fetch_add(1, Ordering::AcqRel) + 1;
        let name = match &session.destination {
            Destination::Domain { host, .. } => host.clone(),
            _ => session.sniffed_domain.clone().unwrap(),
        };
        let mut config = (*self.0.authority.server_config(&name).unwrap()).clone();
        config.alpn_protocols = vec![if self.0.h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
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
                let (client, peer) = factory.open(session.destination.clone()).await?;
                let live = self.0.live.clone();
                return Ok::<_, std::io::Error>((
                    client,
                    Box::pin(async move {
                        peer.await
                            .map(|io| Box::new(Io::new(io, &live)) as BoxStream)
                    }) as AcceptedMemoryPeer,
                ));
            }
            Ok::<_, std::io::Error>(plain_memory_pair(&self.0.live))
        };
        #[cfg(feature = "outbound-vmess")]
        let (client, peer): (BoxStream, AcceptedMemoryPeer) = match vmess {
            Some(factory) => {
                let (client, peer) = factory.open(session.destination.clone()).await?;
                let live = self.0.live.clone();
                (
                    client,
                    Box::pin(async move {
                        peer.await
                            .map(|io| Box::new(Io::new(io, &live)) as BoxStream)
                    }),
                )
            }
            None => fallback.await?,
        };
        #[cfg(not(feature = "outbound-vmess"))]
        let (client, peer) = fallback.await?;
        let accepts = self.0.accepts.clone();
        let sni = self.0.sni.clone();
        let h2 = self.0.h2;
        let post_reply = self.0.post_reply;
        let uploads = self.0.uploads.clone();
        let post_heads = self.0.post_heads.clone();
        let post_started = self.0.post_started.clone();
        let go_away = self.0.go_away.clone();
        let task = tokio::spawn(async move {
            let peer = peer
                .await
                .expect("memory carrier handshake and exact target");
            let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(peer)
                .await
            else {
                return;
            };
            accepts.fetch_add(1, Ordering::AcqRel);
            sni.lock()
                .unwrap()
                .push(tls.get_ref().1.server_name().unwrap_or_default().to_owned());
            if h2 {
                let mut connection = h2::server::Builder::new()
                    .handshake::<_, Bytes>(tls)
                    .await
                    .unwrap();
                let mut exchanges = FuturesUnordered::new();
                let mut sequence = 0;
                let mut go_away_ping: Option<h2::PingPong> = None;
                loop {
                    tokio::select! {biased;
                        _=exchanges.next(),if !exchanges.is_empty()=>{},
                        pong=std::future::poll_fn(|cx| {
                            go_away_ping.as_mut().unwrap().poll_pong(cx)
                        }),if go_away_ping.is_some()=>{
                            pong.expect("upstream PING after GOAWAY acknowledged");
                            go_away_ping = None;
                            go_away.as_ref().unwrap().observed.cancel();
                        },
                        accepted=connection.accept()=>{
                            let Some(Ok((request, mut response))) = accepted else { break; };
                            sequence += 1;
                            assert_eq!(request.headers()["x-request"], "native");
                            if let Some(probe) = &go_away {
                                probe.requests.lock().unwrap().push((connection_index, request.uri().path().to_owned()));
                            }
                            let held = go_away.clone().filter(|_| connection_index == 1 && sequence == 1);
                            if held.is_some() {
                                connection.graceful_shutdown();
                                // h2 queues its NO_ERROR GOAWAY before sending PING.
                                // The peer's PONG proves the ordered frame was processed.
                                let mut ping = connection.ping_pong().unwrap();
                                ping.send_ping(h2::Ping::opaque()).unwrap();
                                go_away_ping = Some(ping);
                            }
                            let uploads = uploads.clone();
                            let post_heads = post_heads.clone();
                            let post_started = post_started.clone();
                            exchanges.push(async move {
                                if request.method() == http::Method::POST {
                                    post_heads.fetch_add(1, Ordering::AcqRel);
                                    if matches!(post_reply, PostReply::FailSecond) && sequence == 2 {
                                        response.send_reset(h2::Reason::INTERNAL_ERROR);
                                        return;
                                    }
                                    let expected = request.headers()["content-length"].to_str().unwrap().parse::<usize>().unwrap();
                                    assert!(expected <= 65536);
                                    let mut input = request.into_body();
                                    let mut bytes = Vec::new();
                                    while let Some(frame) = input.data().await {
                                        let Ok(frame) = frame else { return; };
                                        bytes.extend_from_slice(&frame);
                                        assert!(bytes.len() <= expected);
                                        if input.flow_control().release_capacity(frame.len()).is_err() { return; }
                                        if matches!(post_reply, PostReply::Early | PostReply::Wait) {
                                            uploads.lock().unwrap().push(bytes);
                                            post_started.notify_one();
                                            if matches!(post_reply, PostReply::Wait) {
                                                while input.data().await.is_some() {}
                                                return;
                                            }
                                            let Ok(mut body) = response.send_response(Response::builder().header("content-length", PAYLOAD.len()).header("content-type", "text/plain").body(()).unwrap(), false) else { return; };
                                            let _ = body.send_data(Bytes::from_static(PAYLOAD), true);
                                            // Return the unread receive owner only after committing
                                            // a complete final response on the same real stream.
                                            return;
                                        }
                                    }
                                    assert_eq!(bytes.len(), expected);
                                    assert!(input.trailers().await.unwrap().is_none());
                                    uploads.lock().unwrap().push(bytes);
                                } else {
                                    assert!(request.body().is_end_stream());
                                }
                                if let Some(probe) = held {
                                    probe.release_response.cancelled().await;
                                }
                                let Ok(mut body) = response.send_response(Response::builder().header("content-length", PAYLOAD.len()).header("content-type", "text/plain").body(()).unwrap(), false) else { return; };
                                let _ = body.send_data(Bytes::from_static(PAYLOAD), true);
                            });
                        }
                    }
                }
            } else {
                let mut head = Vec::new();
                while head.len() < 32768 && !head.ends_with(b"\r\n\r\n") {
                    let Ok(byte) = tls.read_u8().await else {
                        return;
                    };
                    head.push(byte);
                }
                assert!(
                    String::from_utf8(head)
                        .unwrap()
                        .to_ascii_lowercase()
                        .contains("x-request: native\r\n")
                );
                tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",PAYLOAD.len()).as_bytes()).await.unwrap();
                tls.write_all(PAYLOAD).await.unwrap();
                let _ = tls.shutdown().await;
            }
        });
        self.0.tasks.lock().unwrap().push(task);
        Ok(Box::new(Io::new(client, &self.0.live)))
    }
    async fn join(&self) -> Result<(), String> {
        let tasks = std::mem::take(
            &mut *self
                .0
                .tasks
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        );
        let mut errors = Vec::new();
        for task in tasks {
            if let Err(error) = join_owned(task).await {
                errors.push(error);
            }
        }
        if self.0.live.load(Ordering::Acquire) != 0 {
            errors.push("origin I/O owners remain".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}
#[cfg(feature = "outbound-shadowsocks")]
fn begin_obfs_owner_shutdown(origin: &Origin) {
    let factory = origin
        .0
        .obfs
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if let Some(factory) = factory {
        factory.begin_shutdown();
    }
}

#[cfg(feature = "outbound-vmess")]
fn begin_vmess_owner_shutdown(origin: &Origin) {
    let factory = origin
        .0
        .vmess_http_cover
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if let Some(factory) = factory {
        factory.begin_shutdown();
    }
}

#[cfg(feature = "outbound-vmess")]
async fn shutdown_vmess_owner(origin: &Origin) -> Result<(), &'static str> {
    let factory = origin
        .0
        .vmess_http_cover
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    match factory {
        Some(factory) => AssertUnwindSafe(factory.shutdown())
            .catch_unwind()
            .await
            .map_err(|_| "actual VMess HTTP-cover owner shutdown panicked"),
        None => Ok(()),
    }
}

fn pem(label: &str, bytes: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
}
fn fixture(h2: bool, extra: &str) -> (HttpContext, Origin) {
    fixture_post(h2, extra, PostReply::Complete)
}
fn fixture_post(h2: bool, extra: &str, post_reply: PostReply) -> (HttpContext, Origin) {
    fixture_with_probe(h2, extra, post_reply, None)
}

fn fixture_with_probe(
    h2: bool,
    extra: &str,
    post_reply: PostReply,
    go_away: Option<Arc<GoAwayProbe>>,
) -> (HttpContext, Origin) {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = pem("CERTIFICATE", cert.der());
    let key_pem = pem("PRIVATE KEY", &key.serialize_der());
    let authority = Authority::load(&cert_pem, &key_pem).unwrap();
    let document=Document::parse(&format!("mitm:\n  enabled: true\n  domains: [{{pattern: a.test}}, {{pattern: b.test}}]\nrewrite:\n  enabled: true\n  rules:\n    - {{url: 'https://a.test/', match: prefix, action: request-header-set, header: x-request, value: native}}\n    - {{url: 'https://a.test/', match: prefix, action: response-header-set, header: x-proof, value: native}}\n    - {{url: 'https://a.test/', match: prefix, action: response-body-replace, search: '-', replacement: '_'}}\n{extra}")).unwrap();
    let candidate = document
        .compile(&std::collections::BTreeMap::new())
        .unwrap();
    let material = CaMaterial {
        certificate: cert_pem,
        private_key: zeroize::Zeroizing::new(key_pem),
    };
    let policy = candidate.bind_ca(Some(&material)).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let origin = Origin(Arc::new(Inner {
        authority,
        h2,
        scope: Arc::new(()),
        key: AtomicUsize::new(1),
        reusable: AtomicBool::new(true),
        prepares: AtomicUsize::new(0),
        opens: AtomicUsize::new(0),
        accepts: Arc::new(AtomicUsize::new(0)),
        live: Arc::new(AtomicUsize::new(0)),
        sni: Arc::new(Mutex::new(Vec::new())),
        tasks: Mutex::new(Vec::new()),
        post_reply,
        uploads: Arc::default(),
        post_heads: Arc::default(),
        post_started: Arc::new(tokio::sync::Notify::new()),
        go_away,
        #[cfg(feature = "outbound-shadowsocks")]
        obfs: Mutex::new(None),
        #[cfg(feature = "outbound-vmess")]
        vmess_http_cover: Mutex::new(None),
    }));
    (
        HttpContext::new(
            policy,
            Arc::new(origin.clone()),
            SecurityContext::with_tls_roots(roots),
        ),
        origin,
    )
}
fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(443),
        inbound: InboundKind::Tun,
        source: "198.18.0.2:30000".parse().unwrap(),
        destination: Destination::Ip("203.0.113.1:443".parse().unwrap()),
        sniffed_domain: Some("a.test".into()),
    }
}
async fn join_owned<T>(mut task: JoinHandle<T>) -> Result<T, String> {
    match timeout(WAIT, &mut task).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("memory owner join: {error}")),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err("memory owner required abort after join timeout".into())
        }
    }
}
async fn reply(sender: h2::client::SendRequest<Bytes>, path: &str) -> Result<Vec<u8>, String> {
    timeout(WAIT, async {
        let mut sender = sender
            .ready()
            .await
            .map_err(|_| "downstream sender not ready")?;
        let request = Request::builder()
            .uri(format!("https://a.test/{path}"))
            .header("accept-encoding", "identity")
            .body(())
            .map_err(|_| "request construction")?;
        let (response, _) = sender
            .send_request(request, true)
            .map_err(|_| "downstream request failed")?;
        let response = response.await.map_err(|_| "response head failed")?;
        if response.status() != StatusCode::OK
            || response
                .headers()
                .get("x-proof")
                .map(|value| value.as_bytes())
                != Some(b"native".as_slice())
        {
            return Err("rewritten response head differs".into());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.data().await {
            let frame = frame.map_err(|_| "response body failed")?;
            bytes.extend_from_slice(&frame);
            body.flow_control()
                .release_capacity(frame.len())
                .map_err(|_| "receive credit release failed")?;
        }
        Ok::<_, String>(bytes)
    })
    .await
    .map_err(|_| "complete H2 reply deadline".to_owned())?
}
async fn exercise(h2: bool, concurrent: bool, change_key: bool, keyless: bool) {
    let (context, origin) = fixture(h2, "");
    origin.0.reusable.store(!keyless, Ordering::Release);
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let (client, mut server) = tokio::io::duplex(8192);
    let owner = tokio::spawn(async move { context.serve_h2(&mut server, session(), cancel).await });
    let mut sender_owner = None;
    let mut driver_owner = None;
    let result = AssertUnwindSafe(async {
        timeout(WAIT * 3, async {
            let (sender, driver) = h2::client::handshake(client)
                .await
                .map_err(|_| "downstream handshake failed")?;
            sender_owner = Some(sender);
            driver_owner = Some(tokio::spawn(driver));
            let sender = sender_owner.as_ref().ok_or("missing downstream sender")?;
            if concurrent {
                let (a, b) =
                    tokio::join!(reply(sender.clone(), "one"), reply(sender.clone(), "two"));
                if a? != b"from_origin" || b? != b"from_origin" {
                    return Err("concurrent full rewritten bytes differ".into());
                }
            } else {
                if reply(sender.clone(), "one").await? != b"from_origin" {
                    return Err("first full rewritten bytes differ".into());
                }
                if change_key {
                    origin.0.key.store(2, Ordering::Release);
                }
                if reply(sender.clone(), "two").await? != b"from_origin" {
                    return Err("second full rewritten bytes differ".into());
                }
            }
            let expected = if h2 && !change_key && !keyless { 1 } else { 2 };
            if origin.0.prepares.load(Ordering::Acquire) != 2
                || origin.0.opens.load(Ordering::Acquire) != expected
                || origin.0.accepts.load(Ordering::Acquire) != expected
            {
                return Err("fresh-route / physical-open / TLS-accept counts differ".into());
            }
            if !origin
                .0
                .sni
                .lock()
                .map_err(|_| "SNI witness poisoned")?
                .iter()
                .all(|name| name == "a.test")
            {
                return Err("authenticated upstream SNI differs".into());
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|_| "whole memory exchange deadline".to_owned())?
    })
    .catch_unwind()
    .await;
    // Always close and actually await every owned task before propagating any
    // mismatch, timeout or panic. A timeout abort is itself a test failure.
    #[cfg(feature = "outbound-vmess")]
    begin_vmess_owner_shutdown(&origin);
    stop.cancel();
    let owner_join = join_owned(owner).await;
    drop(sender_owner.take());
    let driver_join = if let Some(driver) = driver_owner.take() {
        join_owned(driver).await.map(|_| ())
    } else {
        Ok(())
    };
    #[cfg(feature = "outbound-shadowsocks")]
    let carrier_shutdown = {
        let factory = origin
            .0
            .obfs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        match factory {
            Some(factory) => AssertUnwindSafe(factory.shutdown())
                .catch_unwind()
                .await
                .map_err(|_| "actual obfs owner shutdown panicked"),
            None => Ok(()),
        }
    };
    #[cfg(feature = "outbound-vmess")]
    let vmess_shutdown = shutdown_vmess_owner(&origin).await;
    let peers_join = origin.join().await;
    let result = match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(result.is_ok(), "{result:?}");
    assert!(matches!(&owner_join, Ok(Ok(()))), "{owner_join:?}");
    assert!(driver_join.is_ok(), "{driver_join:?}");
    assert!(peers_join.is_ok(), "{peers_join:?}");
    #[cfg(feature = "outbound-shadowsocks")]
    assert!(carrier_shutdown.is_ok(), "{carrier_shutdown:?}");
    #[cfg(feature = "outbound-vmess")]
    assert!(vmess_shutdown.is_ok(), "{vmess_shutdown:?}");
}
#[tokio::test]
async fn h2_tls_sequential_and_concurrent_gets_reuse_one_authenticated_origin() {
    exercise(true, false, false, false).await;
    exercise(true, true, false, false).await;
}
#[tokio::test]
async fn h2_tls_changed_route_key_and_keyless_plan_do_not_reuse() {
    exercise(true, false, true, false).await;
    exercise(true, false, false, true).await;
}
#[tokio::test]
async fn h2_actual_h1_alpn_uses_original_connected_io_once_per_exchange() {
    exercise(false, false, false, false).await;
}

async fn post_response(
    response: h2::client::ResponseFuture,
    early: bool,
) -> Result<Vec<u8>, String> {
    let response = response
        .await
        .map_err(|error| format!("POST response head: {error}"))?;
    if response.status() != StatusCode::OK
        || response.headers().get("x-proof").map(|h| h.as_bytes()) != Some(b"native".as_slice())
    {
        return Err("POST response head was not fully processed".into());
    }
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(frame) = body.data().await {
        match frame {
            Ok(frame) => {
                received.extend_from_slice(&frame);
                body.flow_control()
                    .release_capacity(frame.len())
                    .map_err(|_| "POST response credit")?;
            }
            // A complete early final may close the unread upload with NO_ERROR;
            // it cannot excuse a single missing or changed response byte.
            Err(error)
                if early
                    && error.reason() == Some(h2::Reason::NO_ERROR)
                    && received == b"from_origin" =>
            {
                break;
            }
            Err(error) => return Err(format!("POST response body: {error}")),
        }
    }
    if received != b"from_origin" {
        return Err("POST final response bytes differ".into());
    }
    Ok(received)
}

async fn send_post(sender: h2::client::SendRequest<Bytes>, path: &str) -> Result<Vec<u8>, String> {
    let mut sender = sender.ready().await.map_err(|_| "POST sender readiness")?;
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://a.test/{path}"))
        .header("content-type", "text/plain")
        .header("content-length", 8)
        .body(())
        .map_err(|_| "POST request construction")?;
    let (response, mut upload) = sender
        .send_request(request, false)
        .map_err(|_| "POST send head")?;
    upload
        .send_data(Bytes::from_static(b"original"), true)
        .map_err(|_| "POST send body")?;
    post_response(response, false).await
}

#[tokio::test]
async fn h2_remote_goaway_moves_unsent_post_to_fresh_origin_without_interrupting_inflight_get() {
    let probe = Arc::new(GoAwayProbe::default());
    let (context, origin) = fixture_with_probe(true, "", PostReply::Complete, Some(probe.clone()));
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let (client, mut server) = tokio::io::duplex(8192);
    let owner = tokio::spawn(async move { context.serve_h2(&mut server, session(), cancel).await });
    let mut driver_owner = None;
    let result = AssertUnwindSafe(timeout(WAIT * 3, async {
        let (sender, driver) = h2::client::handshake(client)
            .await
            .map_err(|error| error.to_string())?;
        driver_owner = Some(tokio::spawn(driver));
        let first = reply(sender.clone(), "held");
        tokio::pin!(first);
        tokio::select! {
            () = probe.observed.cancelled() => {},
            result = &mut first => return Err(format!("first response ended before GOAWAY was acknowledged: {result:?}")),
        }
        if origin.0.live.load(Ordering::Acquire) != 2 {
            return Err("original upstream closed before the replacement request".into());
        }
        send_post(sender, "replacement").await?;
        if origin.0.live.load(Ordering::Acquire) != 4 {
            return Err("original and replacement upstream were not both live".into());
        }
        probe.release_response.cancel();
        if first.await? != b"from_origin" {
            return Err("original response bytes differ after GOAWAY".into());
        }
        Ok::<_, String>(())
    }))
    .catch_unwind()
    .await;
    probe.release_response.cancel();
    stop.cancel();
    let owner_join = join_owned(owner).await;
    let driver_join = match driver_owner {
        Some(driver) => join_owned(driver).await.map(|_| ()),
        None => Err("downstream driver never started".into()),
    };
    let peers_join = origin.join().await;
    match result {
        Ok(result) => result.expect("GOAWAY exchange deadline").unwrap(),
        Err(panic) => std::panic::resume_unwind(panic),
    }
    assert!(matches!(owner_join, Ok(Ok(()))), "{owner_join:?}");
    assert!(driver_join.is_ok(), "{driver_join:?}");
    assert!(peers_join.is_ok(), "{peers_join:?}");
    assert_eq!(origin.0.prepares.load(Ordering::Acquire), 2);
    assert_eq!(origin.0.opens.load(Ordering::Acquire), 2);
    assert_eq!(origin.0.accepts.load(Ordering::Acquire), 2);
    assert_eq!(origin.0.post_heads.load(Ordering::Acquire), 1);
    assert_eq!(*origin.0.uploads.lock().unwrap(), [b"original".to_vec()]);
    assert_eq!(
        *probe.requests.lock().unwrap(),
        [(1, "/held".to_owned()), (2, "/replacement".to_owned())]
    );
}

async fn wait_post_released(origin: &Origin) -> Result<(), String> {
    timeout(WAIT, async {
        while origin.0.live.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "uncertain POST retained its physical owner".to_owned())
}

async fn exercise_post(mode: PostReply, native: bool, change_key: bool) {
    let extra = if native {
        "    - {url: 'https://a.test/', match: prefix, action: request-body-set, value: transformed}\n"
    } else {
        ""
    };
    let (context, origin) = fixture_post(true, extra, mode);
    exercise_post_fixture(mode, native, change_key, context, origin).await;
}

async fn exercise_post_fixture(
    mode: PostReply,
    native: bool,
    change_key: bool,
    context: HttpContext,
    origin: Origin,
) {
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let (client, mut server) = tokio::io::duplex(8192);
    let owner = tokio::spawn(async move { context.serve_h2(&mut server, session(), cancel).await });
    let mut sender_owner = None;
    let mut driver_owner = None;
    let result = AssertUnwindSafe(async {
        timeout(WAIT * 3, async {
            let (sender, driver) = h2::client::handshake(client)
                .await
                .map_err(|_| "POST downstream handshake")?;
            sender_owner = Some(sender);
            driver_owner = Some(tokio::spawn(driver));
            let sender = sender_owner.as_ref().ok_or("missing POST sender")?;
            if matches!(mode, PostReply::Early | PostReply::Wait) {
                let mut ready = sender
                    .clone()
                    .ready()
                    .await
                    .map_err(|_| "partial POST readiness")?;
                let request = Request::builder()
                    .method("POST")
                    .uri("https://a.test/unfinished")
                    .header("content-length", 65536)
                    .body(())
                    .map_err(|_| "partial POST construction")?;
                let (response, mut upload) = ready
                    .send_request(request, false)
                    .map_err(|_| "partial POST send")?;
                upload
                    .send_data(Bytes::from_static(b"x"), false)
                    .map_err(|_| "partial POST prefix")?;
                origin.0.post_started.notified().await;
                if matches!(mode, PostReply::Wait) {
                    // Keep both the downstream upload and response owners alive
                    // while cancelling the actual serve_h2 parent.
                    #[cfg(feature = "outbound-shadowsocks")]
                    begin_obfs_owner_shutdown(&origin);
                    #[cfg(feature = "outbound-vmess")]
                    begin_vmess_owner_shutdown(&origin);
                    stop.cancel();
                    drop((upload, response));
                } else {
                    post_response(response, true).await?;
                    // The physical connection must retire despite a complete
                    // valid final response: its upload never reached EOS.
                    wait_post_released(&origin).await?;
                    drop(upload);
                    if reply(sender.clone(), "after-early").await? != b"from_origin" {
                        return Err("post-retirement GET differs".into());
                    }
                    if origin.0.opens.load(Ordering::Acquire) != 2 {
                        return Err("early POST physical connection was reused".into());
                    }
                }
                if *origin.0.uploads.lock().unwrap() != vec![b"x".to_vec()] {
                    return Err("partial POST input differs".into());
                }
            } else {
                send_post(sender.clone(), "one").await?;
                if change_key {
                    origin.0.key.store(2, Ordering::Release);
                }
                let second = send_post(sender.clone(), "two").await;
                if matches!(mode, PostReply::FailSecond) {
                    if second.is_ok() {
                        return Err(
                            "second submitted POST was replayed or did not reach the fault".into(),
                        );
                    }
                    wait_post_released(&origin).await?;
                } else {
                    second?;
                }
                let expected_opens = if change_key { 2 } else { 1 };
                if origin.0.prepares.load(Ordering::Acquire) != 2
                    || origin.0.opens.load(Ordering::Acquire) != expected_opens
                    || origin.0.accepts.load(Ordering::Acquire) != expected_opens
                    || origin.0.post_heads.load(Ordering::Acquire) != 2
                {
                    return Err("completed POST route/open/TLS/request counts differ".into());
                }
                let body = if native {
                    b"transformed".as_slice()
                } else {
                    b"original".as_slice()
                };
                let count = if matches!(mode, PostReply::FailSecond) {
                    1
                } else {
                    2
                };
                if *origin.0.uploads.lock().unwrap() != vec![body.to_vec(); count] {
                    return Err("fully consumed POST payloads differ".into());
                }
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|_| "whole POST memory exchange deadline".to_owned())?
    })
    .catch_unwind()
    .await;
    // The regression stays red without leaking owners, including on assertion,
    // handshake, content, timeout and early-response failures.
    #[cfg(feature = "outbound-shadowsocks")]
    begin_obfs_owner_shutdown(&origin);
    #[cfg(feature = "outbound-vmess")]
    begin_vmess_owner_shutdown(&origin);
    stop.cancel();
    let owner_join = join_owned(owner).await;
    drop(sender_owner.take());
    let driver_join = if let Some(driver) = driver_owner.take() {
        join_owned(driver).await.map(|_| ())
    } else {
        Ok(())
    };
    #[cfg(feature = "outbound-shadowsocks")]
    let carrier_shutdown = {
        let factory = origin
            .0
            .obfs
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        match factory {
            Some(factory) => AssertUnwindSafe(factory.shutdown())
                .catch_unwind()
                .await
                .map_err(|_| "actual obfs owner shutdown panicked"),
            None => Ok(()),
        }
    };
    #[cfg(feature = "outbound-vmess")]
    let vmess_shutdown = shutdown_vmess_owner(&origin).await;
    let peers_join = origin.join().await;
    let result = match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(result.is_ok(), "{result:?}");
    assert!(matches!(&owner_join, Ok(Ok(()))), "{owner_join:?}");
    assert!(driver_join.is_ok(), "{driver_join:?}");
    assert!(peers_join.is_ok(), "{peers_join:?}");
    #[cfg(feature = "outbound-shadowsocks")]
    assert!(carrier_shutdown.is_ok(), "{carrier_shutdown:?}");
    #[cfg(feature = "outbound-vmess")]
    assert!(vmess_shutdown.is_ok(), "{vmess_shutdown:?}");
}

#[tokio::test]
async fn completed_post_h2_reuses_after_full_body_and_checks_fresh_route() {
    exercise_post(PostReply::Complete, false, false).await;
    exercise_post(PostReply::Complete, true, false).await;
    exercise_post(PostReply::Complete, false, true).await;
}

#[tokio::test]
async fn completed_post_h2_sent_second_stream_is_never_replayed() {
    exercise_post(PostReply::FailSecond, false, false).await;
}

#[tokio::test]
async fn completed_post_h2_partial_upload_early_final_retires_physical_owner() {
    exercise_post(PostReply::Early, false, false).await;
}

#[tokio::test]
async fn completed_post_h2_cancel_joins_partial_upload_and_driver() {
    exercise_post(PostReply::Wait, false, false).await;
}
