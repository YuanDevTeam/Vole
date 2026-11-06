//! Real mixed HTTP entry and bounded memory origins; no sockets or VM backend.
use super::*;
use crate::{
    dispatch::{HttpTcpPlan, HttpTcpReuseKey},
    inbound::http::{HttpBasicAuth, HttpServerConfig, framing, server},
    routing::EmptyGeoMatcher,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, DuplexStream, ReadBuf};

#[derive(Default)]
struct Recorded {
    sessions: Mutex<Vec<StreamSession>>,
    heads: Mutex<Vec<String>>,
    live_at_connect: Mutex<Vec<usize>>,
    live: Arc<AtomicUsize>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone, Default)]
struct FixedOrigin {
    recorded: Arc<Recorded>,
    sniff: Option<Arc<crate::sniffing::Policy>>,
}

struct StreamOwner {
    io: DuplexStream,
    live: Arc<AtomicUsize>,
}
impl Drop for StreamOwner {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl AsyncRead for StreamOwner {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for StreamOwner {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct FixedPlan {
    origin: FixedOrigin,
    session: StreamSession,
    key: HttpTcpReuseKey,
}
#[async_trait]
impl HttpTcpPlan for FixedPlan {
    fn reuse_key(&self) -> Option<&HttpTcpReuseKey> {
        Some(&self.key)
    }
    async fn connect(self: Box<Self>) -> Result<BoxStream, DispatchError> {
        self.origin.connect_tcp(self.session).await
    }
}

#[async_trait]
impl Dispatcher for FixedOrigin {
    async fn sniff_plan(
        &self,
        source: SocketAddr,
        destination: &Destination,
    ) -> Result<Option<crate::sniffing::Plan>, DispatchError> {
        let host = match destination {
            Destination::Domain { host, .. } => Some(host.as_str()),
            Destination::Ip(_) => None,
        };
        self.sniff
            .as_ref()
            .map(|policy| policy.plan(source, destination, host, false))
            .transpose()
            .map_err(DispatchError::from)
    }
    async fn prepare_http_tcp(
        &self,
        session: StreamSession,
    ) -> Result<Option<Box<dyn HttpTcpPlan>>, DispatchError> {
        Ok(Some(Box::new(FixedPlan {
            origin: self.clone(),
            session,
            // The test origin has one immutable route. Production's key proof
            // is tested separately; this exercises the actual HTTP slot owner.
            key: HttpTcpReuseKey::new(1_u8),
        })))
    }
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.recorded
            .live_at_connect
            .lock()
            .unwrap()
            .push(self.recorded.live.load(Ordering::SeqCst));
        self.recorded.sessions.lock().unwrap().push(session);
        self.recorded.live.fetch_add(1, Ordering::SeqCst);
        let (client, peer) = tokio::io::duplex(8192);
        let recorded = self.recorded.clone();
        let task = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            loop {
                let Ok(head) = framing::read_head(&mut peer, 32768).await else {
                    break;
                };
                let head = String::from_utf8(head).unwrap();
                let close = head.to_ascii_lowercase().contains("connection: close\r\n");
                recorded.heads.lock().unwrap().push(head);
                if peer
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .is_err()
                {
                    break;
                }
                if close {
                    break;
                }
            }
        });
        self.recorded.tasks.lock().unwrap().push(task);
        Ok(Box::new(StreamOwner {
            io: client,
            live: self.recorded.live.clone(),
        }))
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

async fn join_owned<T>(mut task: tokio::task::JoinHandle<T>) -> Result<T, String> {
    match timeout(Duration::from_secs(5), &mut task).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err("memory owner did not join".into())
        }
    }
}

fn start(
    origin: &FixedOrigin,
    policy: &str,
    auth: bool,
) -> (
    BufReader<DuplexStream>,
    CancellationToken,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    start_with_policy(origin, Policy::compile(policy).unwrap(), auth)
}

fn start_with_policy(
    origin: &FixedOrigin,
    policy: Arc<Policy>,
    auth: bool,
) -> (
    BufReader<DuplexStream>,
    CancellationToken,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let fixed: Arc<dyn Dispatcher> = Arc::new(origin.clone());
    // Entry::connect_tcp deliberately panics: fallback must retain this fixed
    // HttpContext dispatcher rather than return to the outer dynamic entry.
    let entry: Arc<dyn Dispatcher> = Arc::new(Entry(HttpContext::new(
        policy,
        fixed,
        SecurityContext::new(),
    )));
    let (client, peer) = tokio::io::duplex(8192);
    let cancel = CancellationToken::new();
    let child = cancel.clone();
    let mut config = HttpServerConfig::processing();
    if auth {
        config.auth = Some(HttpBasicAuth::new("user", "pass").unwrap());
    }
    let task = tokio::spawn(async move {
        server::handle_connection_with_deadline(
            peer,
            "127.0.0.1:30000".parse().unwrap(),
            "127.0.0.1:1080".parse().unwrap(),
            entry,
            config,
            child,
            Instant::now() + Duration::from_secs(5),
        )
        .await
    });
    (BufReader::new(client), cancel, task)
}

async fn finish(
    client: BufReader<DuplexStream>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    origin: &FixedOrigin,
) {
    cancel.cancel();
    drop(client);
    let server = join_owned(task).await;
    let tasks = std::mem::take(&mut *origin.recorded.tasks.lock().unwrap());
    let mut peers = Vec::new();
    for task in tasks {
        peers.push(join_owned(task).await);
    }
    assert_eq!(origin.recorded.live.load(Ordering::SeqCst), 0);
    server.unwrap().unwrap();
    for peer in peers {
        peer.unwrap();
    }
}

async fn response(client: &mut BufReader<DuplexStream>) -> std::io::Result<String> {
    let head = framing::read_head(client, 32768).await?;
    let mut body = [0; 2];
    client.read_exact(&mut body).await?;
    if body != *b"ok" {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(String::from_utf8(head).unwrap())
}

const REWRITE: &str = "http-ports: [80]\nrewrite:\n  enabled: true\n  rules:\n  - {url: '.', action: response-header-set, header: X-Rewrite, value: active}\n  - {url: '.', action: replace, replacement-mode: url, replacement: 'http://first.invalid/rewritten'}\n";

#[tokio::test]
async fn ordinary_http_on_mitm_only_port_stays_plain_forwarding() {
    let material = super::super::private_context::test_material();
    let yaml = format!(
        "{REWRITE}\nmitm:\n  enabled: true\n  ports: [443]\n  domains: [{{pattern: first.invalid}}]\n"
    );
    let policy = super::super::config::Document::parse(&yaml)
        .unwrap()
        .compile(&Default::default())
        .unwrap()
        .bind_ca(Some(&material))
        .unwrap();
    let origin = FixedOrigin::default();
    let (mut client, cancel, task) = start_with_policy(&origin, policy, false);
    let exchange = timeout(Duration::from_secs(5), async {
        client.get_mut().write_all(b"GET http://first.invalid:443/original HTTP/1.1\r\nHost: first.invalid:443\r\nConnection: close\r\n\r\n").await?;
        response(&mut client).await
    }).await;
    finish(client, cancel, task, &origin).await;
    let response = exchange.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.to_ascii_lowercase().contains("x-rewrite:"));
    let sessions = origin.recorded.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].destination,
        Destination::domain("first.invalid", 443).unwrap()
    );
    assert_eq!(sessions[0].inbound, InboundKind::Http);
    assert!(origin.recorded.heads.lock().unwrap()[0].starts_with("GET /original HTTP/1.1\r\n"));
}

#[tokio::test]
async fn ordinary_noncandidate_port_forwards_without_rewrite_through_fixed_context() {
    let origin = FixedOrigin::default();
    let (mut client, cancel, task) = start(&origin, REWRITE, false);
    let exchange = timeout(Duration::from_secs(5), async {
        client.get_mut().write_all(b"GET http://first.invalid:8081/original HTTP/1.1\r\nHost: first.invalid:8081\r\nConnection: close\r\n\r\n").await?;
        response(&mut client).await
    }).await;
    finish(client, cancel, task, &origin).await;
    let response = exchange.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.to_ascii_lowercase().contains("x-rewrite:"));
    let sessions = origin.recorded.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].destination,
        Destination::domain("first.invalid", 8081).unwrap()
    );
    assert_eq!(sessions[0].inbound, InboundKind::Http);
    assert!(origin.recorded.heads.lock().unwrap()[0].starts_with("GET /original HTTP/1.1\r\n"));
}

#[tokio::test]
async fn candidate_then_noncandidate_retires_cached_upstream_and_keeps_request_identity() {
    let origin = FixedOrigin::default();
    let (mut client, cancel, task) = start(&origin, REWRITE, true);
    let exchange = timeout(Duration::from_secs(5), async {
        let mut responses = Vec::new();
        let mut retained_first_owner = false;
        for (authority, connection) in [("first.invalid", "X-Hop"), ("first.invalid:8081", "close, X-Hop")] {
            client.get_mut().write_all(format!("GET http://{authority}/original HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nProxy-Connection: keep-alive\r\nConnection: {connection}\r\nX-Hop: private\r\n\r\n").as_bytes()).await?;
            responses.push(response(&mut client).await?);
            if responses.len() == 1 {
                retained_first_owner = origin.recorded.live.load(Ordering::SeqCst) == 1;
            }
        }
        Ok::<_, std::io::Error>((responses, retained_first_owner))
    }).await;
    finish(client, cancel, task, &origin).await;
    let (responses, retained_first_owner) = exchange.unwrap().unwrap();
    assert!(
        retained_first_owner,
        "the first persistent response must retain its actual upstream owner"
    );
    assert!(
        responses[0]
            .to_ascii_lowercase()
            .contains("x-rewrite: active\r\n")
    );
    assert!(!responses[1].to_ascii_lowercase().contains("x-rewrite:"));
    let sessions = origin.recorded.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    for (session, port) in sessions.iter().zip([80, 8081]) {
        assert_eq!(
            session.destination,
            Destination::domain("first.invalid", port).unwrap()
        );
        assert_eq!(session.inbound, InboundKind::Http);
        assert_eq!(session.metadata.user.as_deref(), Some("user"));
        assert_eq!(session.metadata.local_port, 1080);
        assert_eq!(
            session.metadata.local_address,
            Some("127.0.0.1:1080".parse().unwrap())
        );
    }
    assert_eq!(
        *origin.recorded.live_at_connect.lock().unwrap(),
        [0, 0],
        "the cached first owner must drop before the second dial"
    );
    let heads = origin.recorded.heads.lock().unwrap();
    assert_eq!(heads.len(), 2);
    assert!(heads[0].starts_with("GET /rewritten HTTP/1.1\r\n"));
    assert!(heads[1].starts_with("GET /original HTTP/1.1\r\n"));
    assert!(
        heads[0]
            .lines()
            .any(|line| line.eq_ignore_ascii_case("connection: keep-alive")),
        "the first response must have qualified for a live upstream slot"
    );
    for head in heads.iter() {
        let lower = head.to_ascii_lowercase();
        for forbidden in ["proxy-authorization:", "proxy-connection:", "x-hop:"] {
            assert!(!lower.contains(forbidden), "{forbidden} leaked");
        }
    }
}

#[tokio::test]
async fn ordinary_http_and_connect_share_force_skip_and_override_false_sniff_policy() {
    let base = "sniffer:\n  enable: true\n  parse-pure-ip: false\n  force-domain: [target.invalid]\n  override-destination: false\n  sniff:\n    HTTP: {ports: [8081]}\n";
    for (main, accepted) in [
        (base.to_owned(), true),
        (
            base.replace("force-domain: [target.invalid]", "force-domain: []"),
            false,
        ),
        (
            base.replace(
                "  sniff:",
                "  skip-domain: [target.invalid, observed.invalid]\n  sniff:",
            ),
            false,
        ),
        (base.replace("ports: [8081]", "ports: [8082]"), false),
    ] {
        for connect in [false, true] {
            let config = crate::config::Config::parse_yaml(main.as_bytes()).unwrap();
            let origin = FixedOrigin {
                recorded: Arc::default(),
                sniff: Some(crate::sniffing::Policy::new(
                    Arc::new(config.sniffer),
                    Arc::new(EmptyGeoMatcher),
                )),
            };
            let (mut client, cancel, task) = start(&origin, REWRITE, false);
            let exchange = timeout(Duration::from_secs(5), async {
                if connect {
                    client.get_mut().write_all(b"CONNECT target.invalid:8081 HTTP/1.1\r\nHost: target.invalid:8081\r\n\r\n").await?;
                    let head = framing::read_head(&mut client, 32768).await?;
                    if !head.starts_with(b"HTTP/1.1 200 ") { return Err(std::io::ErrorKind::InvalidData.into()); }
                    client.get_mut().write_all(b"GET /inside HTTP/1.1\r\nHost: observed.invalid\r\nConnection: close\r\n\r\n").await?;
                } else {
                    client.get_mut().write_all(b"GET http://target.invalid:8081/outside HTTP/1.1\r\nHost: target.invalid:8081\r\nConnection: close\r\n\r\n").await?;
                }
                response(&mut client).await
            }).await;
            finish(client, cancel, task, &origin).await;
            assert!(
                exchange
                    .unwrap()
                    .unwrap()
                    .starts_with("HTTP/1.1 200 OK\r\n")
            );
            let sessions = origin.recorded.sessions.lock().unwrap();
            assert_eq!(sessions.len(), 1);
            assert_eq!(
                sessions[0].destination,
                Destination::domain("target.invalid", 8081).unwrap(),
                "override false must retain the original target"
            );
            assert_eq!(
                sessions[0].inbound,
                if connect {
                    InboundKind::Https
                } else {
                    InboundKind::Http
                }
            );
            let expected = accepted.then_some(if connect {
                "observed.invalid"
            } else {
                "target.invalid"
            });
            assert_eq!(
                sessions[0].sniffed_domain.as_deref(),
                expected,
                "{main}; CONNECT={connect}"
            );
        }
    }
}
