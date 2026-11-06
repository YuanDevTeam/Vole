// Real in-memory origins and the production routing/HTTP loops; no sockets.
include!("upstream_connect_memory_tests.rs");
use super::*;
use crate::{
    dispatch::{DatagramTransport, observe_handshakes_with_stats, observe_sessions_with_stats},
    http_processing::{HttpContext, Intercept, Policy},
    routing::{EmptyGeoMatcher, GeoMatcher, ProxyDispatchers, RoutingDispatcher, RuleSet},
    security::SecurityContext,
    session::{DatagramSession, Destination},
};
use async_trait::async_trait;
use std::{
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

#[derive(Clone, Copy)]
enum Reply {
    Persistent,
    Close,
    Http10,
    Extra,
    Chunked,
    Trailer,
    ContentRange,
    BadLength,
    Truncated,
    FailSecond,
    Pending,
}
struct MemoryOrigin {
    reply: Reply,
    opened: AtomicUsize,
    live: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    partial: Arc<tokio::sync::Notify>,
}
struct OwnedMemoryStream {
    io: tokio::io::DuplexStream,
    live: Arc<AtomicUsize>,
}
impl Drop for OwnedMemoryStream {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl AsyncRead for OwnedMemoryStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, b)
    }
}
impl AsyncWrite for OwnedMemoryStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
async fn joined<T>(mut task: tokio::task::JoinHandle<T>) -> Result<T, String> {
    match tokio::time::timeout(Duration::from_secs(1), &mut task).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err("memory peer did not join".into())
        }
    }
}
impl MemoryOrigin {
    fn new(reply: Reply) -> Arc<Self> {
        Arc::new(Self {
            reply,
            opened: AtomicUsize::new(0),
            live: Arc::new(AtomicUsize::new(0)),
            heads: Arc::default(),
            bodies: Arc::default(),
            tasks: Mutex::new(Vec::new()),
            partial: Arc::new(tokio::sync::Notify::new()),
        })
    }
    async fn join(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        let mut failure = None;
        for task in tasks {
            if let Err(error) = joined(task).await {
                failure = Some(error);
            }
        }
        assert_eq!(self.live.load(Ordering::SeqCst), 0);
        assert!(failure.is_none(), "{failure:?}");
    }
}
#[async_trait]
impl Dispatcher for MemoryOrigin {
    fn permits_http_tcp_reuse(&self) -> bool {
        true
    }
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        self.live.fetch_add(1, Ordering::SeqCst);
        let (client, server) = tokio::io::duplex(8192);
        let (reply, heads, bodies, partial) = (
            self.reply,
            self.heads.clone(),
            self.bodies.clone(),
            self.partial.clone(),
        );
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            let mut server = BufReader::new(server);
            let mut sequence=0;
            loop {
                let bytes = match framing::read_head(&mut server,32768).await { Ok(b)=>b, Err(_)=>break };
                let text=String::from_utf8(bytes.clone()).unwrap();
                let request=crate::inbound::http::parser::parse_request_head(&bytes,Vec::new()).unwrap();
                let plan=framing::RequestPlan::for_target(&request,Destination::Ip("203.0.113.1:80".parse().unwrap()),"/".into(),false).unwrap();
                let mut body=Vec::new();
                framing::transfer_body(&mut server,&mut body,plan.body,Duration::from_secs(1),&plan.trailer_blocklist,true).await.unwrap();
                heads.lock().unwrap().push(text.clone()); bodies.lock().unwrap().push(body); sequence+=1;
                if matches!(reply,Reply::FailSecond) && sequence==2 { break; }
                let wire: &[u8] = match reply {
                    Reply::Close => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    Reply::Http10 => b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    Reply::Extra => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokunsolicited",
                    Reply::Chunked => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
                    Reply::Trailer => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Safe\r\n\r\n2\r\nok\r\n0\r\nX-Safe: v\r\n\r\n",
                    Reply::ContentRange => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/4\r\n\r\nok",
                    Reply::BadLength => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
                    Reply::Truncated|Reply::Pending => b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok",
                    _ => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                };
                if server.get_mut().write_all(wire).await.is_err() { break; }
                if matches!(reply,Reply::Pending) { partial.notify_one(); }
                if matches!(reply,Reply::Truncated) { break; }
                if text.to_ascii_lowercase().contains("connection: close") || matches!(reply,Reply::Close|Reply::Http10) { break; }
            }
        }));
        Ok(Box::new(OwnedMemoryStream {
            io: client,
            live: self.live.clone(),
        }))
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn ingress() -> StreamSession {
    StreamSession {
        metadata: crate::session::InboundMetadata::new(80),
        inbound: InboundKind::Tun,
        source: "198.18.0.2:12345".parse().unwrap(),
        destination: Destination::Ip("203.0.113.1:80".parse().unwrap()),
        sniffed_domain: Some("origin.invalid".into()),
    }
}
fn router(origin: Arc<dyn Dispatcher>, geo: Arc<dyn GeoMatcher>) -> Arc<RoutingDispatcher> {
    let config =
        crate::config::Config::parse_yaml(b"rules: [\"GEOSITE,flip,REJECT\",\"MATCH,DIRECT\"]\n")
            .unwrap();
    Arc::new(RoutingDispatcher::new(
        ProxyDispatchers::new(Vec::new()).unwrap(),
        origin,
        None,
        RuleSet::compile(config.rules).unwrap(),
        geo,
    ))
}
fn context(
    origin: Arc<MemoryOrigin>,
    geo: Arc<dyn GeoMatcher>,
    extra: &str,
) -> (HttpContext, crate::resources::RuntimeResourceStats) {
    let stats = crate::resources::RuntimeResourceStats::new("http_upstream_reuse_memory_test");
    let dispatcher = observe_sessions_with_stats(
        observe_handshakes_with_stats(router(origin, geo), stats.clone()),
        stats.clone(),
    );
    let policy=Policy::compile(&format!("http-ports: [80]\nrewrite:\n  enabled: true\n  rules:\n  - {{url: '.', action: response-header-set, header: X-Test, value: value}}\n{extra}")).unwrap();
    (
        HttpContext::new(policy, dispatcher, SecurityContext::new()),
        stats,
    )
}
async fn read_response(client: &mut BufReader<tokio::io::DuplexStream>) -> io::Result<Vec<u8>> {
    let head = framing::read_head(client, 32768).await?;
    let response = framing::ResponseHead::parse(&head)?;
    let mut body = Vec::new();
    framing::transfer_body(
        client,
        &mut body,
        response.body("GET"),
        Duration::from_secs(1),
        response.trailer_blocklist(),
        true,
    )
    .await?;
    Ok(body)
}
async fn send(client: &mut BufReader<tokio::io::DuplexStream>, path: &str) {
    client.get_mut().write_all(format!("GET /{path} HTTP/1.1\r\nHost: origin.invalid\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").as_bytes()).await.unwrap();
}
fn start(
    context: HttpContext,
    cancel: CancellationToken,
) -> (
    BufReader<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<io::Result<Intercept>>,
) {
    let (client, mut stream) = tokio::io::duplex(8192);
    let task =
        tokio::spawn(async move { context.try_intercept(&mut stream, ingress(), cancel).await });
    (BufReader::new(client), task)
}
async fn end(
    mut client: BufReader<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<io::Result<Intercept>>,
    origin: &MemoryOrigin,
) {
    client.get_mut().shutdown().await.unwrap();
    let result = joined(task).await;
    origin.join().await;
    result.unwrap().unwrap();
}

#[tokio::test]
async fn upstream_reuse_two_real_requests_one_connection_and_stop_releases_owners() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let (context, stats) = context(origin.clone(), Arc::new(EmptyGeoMatcher), "");
    let (mut client, task) = start(context, CancellationToken::new());
    for path in ["one", "two"] {
        send(&mut client, path).await;
        assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    }
    let opened = origin.opened.load(Ordering::SeqCst);
    let active = stats.snapshot();
    let heads = origin.heads.lock().unwrap().len();
    end(client, task, &origin).await;
    assert_eq!(opened, 1);
    assert_eq!(active.tcp_current, 1);
    assert_eq!(active.handshake_current, 0);
    assert_eq!(heads, 2);
    assert_eq!(stats.snapshot().tcp_current, 0);
}
#[tokio::test]
async fn upstream_reuse_original_wire_close_version_extra_and_chunks_retire() {
    for reply in [
        Reply::Close,
        Reply::Http10,
        Reply::Extra,
        Reply::Chunked,
        Reply::Trailer,
        Reply::ContentRange,
    ] {
        let origin = MemoryOrigin::new(reply);
        let (context, _) = context(origin.clone(), Arc::new(EmptyGeoMatcher), "");
        let (mut client, task) = start(context, CancellationToken::new());
        for path in ["one", "two"] {
            send(&mut client, path).await;
            assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
        }
        assert_eq!(origin.opened.load(Ordering::SeqCst), 2);
        end(client, task, &origin).await;
    }
}
#[tokio::test]
async fn upstream_reuse_truncated_body_remains_error_and_is_never_replayed() {
    let origin = MemoryOrigin::new(Reply::Truncated);
    let (context, _) = context(origin.clone(), Arc::new(EmptyGeoMatcher), "");
    let (mut client, task) = start(context, CancellationToken::new());
    send(&mut client, "one").await;
    assert!(read_response(&mut client).await.is_err());
    assert!(joined(task).await.unwrap().is_err());
    origin.join().await;
    assert_eq!(origin.opened.load(Ordering::SeqCst), 1);
    assert_eq!(origin.heads.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn upstream_reuse_sent_second_request_failure_does_not_reconnect_or_replay() {
    let origin = MemoryOrigin::new(Reply::FailSecond);
    let (context, _) = context(origin.clone(), Arc::new(EmptyGeoMatcher), "");
    let (mut client, task) = start(context, CancellationToken::new());
    send(&mut client, "one").await;
    assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    send(&mut client, "two").await;
    // The ordinary error may be rendered as a local empty 502, then the owner fails.
    let _ = read_response(&mut client).await;
    assert!(joined(task).await.unwrap().is_err());
    origin.join().await;
    assert_eq!(origin.opened.load(Ordering::SeqCst), 1);
    assert_eq!(origin.heads.lock().unwrap().len(), 2);
}
#[derive(Default)]
struct FlipGeo(AtomicUsize);
impl GeoMatcher for FlipGeo {
    fn matches_geosite(&self, _: &str, _: &str) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst) > 0
    }
    fn matches_geoip(&self, _: &str, _: std::net::IpAddr) -> bool {
        false
    }
}
#[tokio::test]
async fn upstream_reuse_new_request_rechecks_reject_before_using_cached_stream() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let geo = Arc::new(FlipGeo::default());
    let (context, _) = context(origin.clone(), geo.clone(), "");
    let (mut client, task) = start(context, CancellationToken::new());
    send(&mut client, "one").await;
    assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    send(&mut client, "two").await;
    let _ = read_response(&mut client).await;
    assert!(joined(task).await.unwrap().is_err());
    origin.join().await;
    assert_eq!(geo.0.load(Ordering::SeqCst), 2);
    assert_eq!(origin.opened.load(Ordering::SeqCst), 1);
    assert_eq!(origin.heads.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn upstream_reuse_owned_plan_does_not_run_routing_twice() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let geo = Arc::new(FlipGeo::default());
    let router = router(origin.clone(), geo.clone());
    let plan = router.prepare_http_tcp(ingress()).await.unwrap().unwrap();
    let stream = plan.connect().await.unwrap();
    assert_eq!(geo.0.load(Ordering::SeqCst), 1);
    drop(stream);
    origin.join().await;
    let rejected = router.prepare_http_tcp(ingress()).await.unwrap().unwrap();
    assert!(rejected.connect().await.is_err());
    assert_eq!(geo.0.load(Ordering::SeqCst), 2);
    assert_eq!(origin.opened.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn upstream_reuse_idle_and_partial_response_cancellation_drop_actual_streams() {
    for reply in [Reply::Persistent, Reply::Pending] {
        let origin = MemoryOrigin::new(reply);
        let cancel = CancellationToken::new();
        let (context, stats) = context(origin.clone(), Arc::new(EmptyGeoMatcher), "");
        let (mut client, task) = start(context, cancel.clone());
        send(&mut client, "one").await;
        if matches!(reply, Reply::Pending) {
            origin.partial.notified().await;
        } else {
            assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
        }
        cancel.cancel();
        joined(task).await.unwrap().unwrap();
        origin.join().await;
        assert_eq!(stats.snapshot().tcp_current, 0);
        assert_eq!(stats.snapshot().handshake_current, 0);
    }
}

#[tokio::test]
async fn upstream_reuse_same_ip_different_authority_never_coalesces() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let (context, _) = context(origin.clone(), Arc::new(EmptyGeoMatcher), "");
    let (mut client, task) = start(context, CancellationToken::new());
    send(&mut client, "one").await;
    assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    client
        .get_mut()
        .write_all(b"GET /two HTTP/1.1\r\nHost: other.invalid\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    assert_eq!(origin.opened.load(Ordering::SeqCst), 2);
    end(client, task, &origin).await;
}
#[tokio::test]
async fn upstream_reuse_native_request_body_set_retains_the_one_shot_path() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let (context, _) = context(
        origin.clone(),
        Arc::new(EmptyGeoMatcher),
        "  - {url: '.', action: request-body-set, value: x}\n",
    );
    let (mut client, task) = start(context, CancellationToken::new());
    for path in ["one", "two"] {
        send(&mut client, path).await;
        assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    }
    assert_eq!(origin.opened.load(Ordering::SeqCst), 2);
    assert_eq!(
        *origin.bodies.lock().unwrap(),
        vec![b"x".to_vec(), b"x".to_vec()]
    );
    assert!(
        origin
            .heads
            .lock()
            .unwrap()
            .iter()
            .all(|h| h.to_ascii_lowercase().contains("connection: close"))
    );
    end(client, task, &origin).await;
}
#[tokio::test]
async fn upstream_reuse_ambiguous_upstream_framing_remains_failure() {
    let origin = MemoryOrigin::new(Reply::BadLength);
    let (context, _) = context(origin.clone(), Arc::new(EmptyGeoMatcher), "");
    let (mut client, task) = start(context, CancellationToken::new());
    send(&mut client, "one").await;
    let _ = read_response(&mut client).await;
    assert!(joined(task).await.unwrap().is_err());
    origin.join().await;
    assert_eq!(origin.opened.load(Ordering::SeqCst), 1);
}
struct OpaqueDirect(Arc<MemoryOrigin>);
#[async_trait]
impl Dispatcher for OpaqueDirect {
    async fn connect_tcp(&self, s: StreamSession) -> Result<BoxStream, DispatchError> {
        self.0.connect_tcp(s).await
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
#[tokio::test]
async fn upstream_reuse_route_named_direct_is_insufficient_without_physical_proof() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let opaque = Arc::new(OpaqueDirect(origin.clone()));
    let context=HttpContext::new(Policy::compile("http-ports: [80]\nrewrite: {enabled: true, rules: [{url: '.', action: response-header-set, header: X-Test, value: value}]}\n").unwrap(),router(opaque,Arc::new(EmptyGeoMatcher)),SecurityContext::new());
    let (mut client, task) = start(context, CancellationToken::new());
    for path in ["one", "two"] {
        send(&mut client, path).await;
        assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    }
    assert_eq!(origin.opened.load(Ordering::SeqCst), 2);
    end(client, task, &origin).await;
}
#[test]
fn upstream_reuse_builtin_direct_rejects_mutable_or_special_egress() {
    let dialer = crate::dialer::Dialer::default();
    let plain = crate::outbound::DirectOutbound::new(dialer.clone());
    assert!(plain.permits_http_tcp_reuse());
    dialer.begin_shutdown();
    assert!(!plain.permits_http_tcp_reuse());
    let mptcp =
        crate::outbound::DirectOutbound::new(crate::dialer::Dialer::default().with_mptcp(true));
    assert!(!mptcp.permits_http_tcp_reuse());
}
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn upstream_reuse_local_respond_does_not_claim_unread_origin_body() {
    let origin = MemoryOrigin::new(Reply::Truncated);
    let source = "http-scripts:\n  enabled: true\n  scripts:\n  - {name: local, phase: response, body: none, url: '.', source: \"function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:'zz'}};}\"}\n";
    let (context, _) = context(origin.clone(), Arc::new(EmptyGeoMatcher), source);
    let (mut client, task) = start(context, CancellationToken::new());
    for path in ["one", "two"] {
        send(&mut client, path).await;
        assert_eq!(read_response(&mut client).await.unwrap(), b"zz");
    }
    assert_eq!(origin.opened.load(Ordering::SeqCst), 2);
    end(client, task, &origin).await;
}

#[tokio::test]
async fn upstream_reuse_collected_rewritten_body_proves_original_wire_completion() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let (context, _) = context(
        origin.clone(),
        Arc::new(EmptyGeoMatcher),
        "  - {url: '.', action: response-body-set, value: changed}\n",
    );
    let (mut client, task) = start(context, CancellationToken::new());
    for path in ["one", "two"] {
        send(&mut client, path).await;
        assert_eq!(read_response(&mut client).await.unwrap(), b"changed");
    }
    let opened = origin.opened.load(Ordering::SeqCst);
    end(client, task, &origin).await;
    assert_eq!(opened, 1);
}

struct MixedEntry {
    context: HttpContext,
    router: Arc<RoutingDispatcher>,
}
#[async_trait]
impl Dispatcher for MixedEntry {
    fn http_context(&self) -> Option<HttpContext> {
        Some(self.context.clone())
    }
    async fn connect_tcp(&self, s: StreamSession) -> Result<BoxStream, DispatchError> {
        self.router.connect_tcp(s).await
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
#[tokio::test]
async fn upstream_reuse_mixed_connect_releases_the_old_slot_before_tunnel() {
    let origin = MemoryOrigin::new(Reply::Persistent);
    let router = router(origin.clone(), Arc::new(EmptyGeoMatcher));
    let context=HttpContext::new(Policy::compile("http-ports: [80]\nrewrite: {enabled: true, rules: [{url: '.', action: response-header-set, header: X-Test, value: value}]}\n").unwrap(),router.clone(),SecurityContext::new());
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(MixedEntry { context, router });
    let (client, stream) = tokio::io::duplex(8192);
    let task = tokio::spawn(async move {
        let (read, mut write) = tokio::io::split(stream);
        let mut reader = BufReader::new(read);
        let config = HttpServerConfig::processing();
        serve_requests(
            &mut reader,
            &mut write,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
            &dispatcher,
            &config,
            (
                Instant::now() + Duration::from_secs(10),
                &CancellationToken::new(),
            ),
        )
        .await
    });
    let mut client = BufReader::new(client);
    client
        .get_mut()
        .write_all(b"GET http://203.0.113.1/one HTTP/1.1\r\nHost: 203.0.113.1\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut client).await.unwrap(), b"ok");
    assert_eq!(origin.opened.load(Ordering::SeqCst), 1);
    client
        .get_mut()
        .write_all(b"CONNECT 203.0.113.1:443 HTTP/1.1\r\nHost: 203.0.113.1:443\r\n\r\n")
        .await
        .unwrap();
    let head = framing::read_head(&mut client, 32768).await.unwrap();
    let during = origin.live.load(Ordering::SeqCst);
    let opened = origin.opened.load(Ordering::SeqCst);
    client.get_mut().shutdown().await.unwrap();
    let result = joined(task).await;
    origin.join().await;
    result.unwrap().unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    assert_eq!(opened, 2);
    assert_eq!(during, 1);
}
