//! Real SOCKS5 handshakes, HTTP framing and TLS over duplex IO; no sockets.
//! Filter: inbound::socks5::server::http_processing_memory_tests::
use super::Socks5Handler;
use crate::{
    config::{ProxyAccess, ProxyCredentials, Socks5InboundConfig},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    http_processing::{HttpContext, Policy, config::Document, private_context::test_material},
    inbound::http::{framing, parser},
    security::SecurityContext,
    session::{DatagramSession, Destination, InboundKind, StreamSession},
};
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream},
    task::JoinHandle,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(5);
const REQUEST: &[u8] = b"POST /path HTTP/1.1\r\nHost: target.test\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nold";
const NATIVE: &str = r#"
http-ports: [80]
rewrite:
  enabled: true
  rules:
  - {url: '.', action: request-header-set, header: X-Request-Native, value: yes}
  - {url: '.', action: request-body-set, value: native-request}
  - {url: '.', action: response-header-set, header: X-Response-Native, value: yes}
  - {url: '.', action: response-body-set, value: native-response}
"#;

#[derive(Clone)]
enum PeerMode {
    Http,
    Echo,
    SniffingEcho,
    BufferedSniffingEcho,
    Tls(Arc<rustls::ServerConfig>),
    Refused,
}
type RequestLog = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;
struct Origin {
    mode: PeerMode,
    sessions: Mutex<Vec<StreamSession>>,
    requests: RequestLog,
    tasks: Mutex<Vec<JoinHandle<io::Result<()>>>>,
    live: Arc<AtomicUsize>,
    cancellation: CancellationToken,
}
struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn http_origin<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    destination: Destination,
    requests: RequestLog,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let head = framing::read_head(&mut reader, 32768).await?;
    let request = parser::parse_request_head(&head, Vec::new())?;
    let plan = framing::RequestPlan::for_target(&request, destination, "/".into(), false)?;
    let mut body = Vec::new();
    framing::transfer_body(
        &mut reader,
        &mut body,
        plan.body,
        WAIT,
        &plan.trailer_blocklist,
        true,
    )
    .await?;
    requests.lock().unwrap().push((head, body));
    reader.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin").await?;
    reader.get_mut().shutdown().await
}

#[async_trait]
impl Dispatcher for Origin {
    async fn sniff_plan(
        &self,
        source: std::net::SocketAddr,
        destination: &Destination,
    ) -> Result<Option<crate::sniffing::Plan>, DispatchError> {
        if !matches!(
            self.mode,
            PeerMode::SniffingEcho | PeerMode::BufferedSniffingEcho
        ) {
            return Ok(None);
        }
        let config = crate::config::Config::parse_yaml(
            b"sniffer:\n  enable: true\n  force-domain: [target.test]\n  sniff:\n    HTTP: {ports: [80]}\n",
        ).unwrap();
        let policy = crate::sniffing::Policy::new(
            Arc::new(config.sniffer),
            Arc::new(crate::routing::EmptyGeoMatcher),
        );
        let host = match destination {
            Destination::Domain { host, .. } => Some(host.as_str()),
            Destination::Ip(_) => None,
        };
        Ok(Some(policy.plan(source, destination, host, false)?))
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.sessions.lock().unwrap().push(session.clone());
        if matches!(self.mode, PeerMode::Refused) {
            return Err(DispatchError::ConnectionRefused);
        }
        let (client, mut peer) = tokio::io::duplex(16384);
        let mode = self.mode.clone();
        let requests = self.requests.clone();
        let cancellation = self.cancellation.clone();
        self.live.fetch_add(1, Ordering::SeqCst);
        let live = Live(self.live.clone());
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            let _live = live;
            let operation = async {
                match mode {
                    PeerMode::Http => http_origin(peer, session.destination, requests).await,
                    PeerMode::Tls(config) => {
                        let tls = tokio_rustls::TlsAcceptor::from(config).accept(peer).await?;
                        http_origin(tls, session.destination, requests).await
                    }
                    PeerMode::Echo | PeerMode::SniffingEcho => {
                        let mut bytes = Vec::new();
                        peer.read_to_end(&mut bytes).await?;
                        requests.lock().unwrap().push((bytes.clone(), Vec::new()));
                        peer.write_all(&bytes).await?;
                        peer.shutdown().await
                    }
                    PeerMode::BufferedSniffingEcho => {
                        let mut bytes = [0_u8; 1024];
                        loop {
                            let count = peer.read(&mut bytes).await?;
                            if count == 0 {
                                return peer.shutdown().await;
                            }
                            peer.write_all(&bytes[..count]).await?;
                        }
                    }
                    PeerMode::Refused => unreachable!(),
                }
            };
            tokio::select! {
                biased;
                () = cancellation.cancelled() => Ok(()),
                result = operation => result,
            }
        }));
        if matches!(self.mode, PeerMode::BufferedSniffingEcho) {
            Ok(Box::new(tokio::io::BufWriter::new(client)))
        } else {
            Ok(Box::new(client))
        }
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
impl Origin {
    fn new(mode: PeerMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            sessions: Mutex::new(Vec::new()),
            requests: Arc::default(),
            tasks: Mutex::new(Vec::new()),
            live: Arc::default(),
            cancellation: CancellationToken::new(),
        })
    }
    async fn join(&self) -> io::Result<()> {
        self.cancellation.cancel();
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        let mut failure = None;
        for task in tasks {
            if let Err(error) = join(task).await {
                failure = Some(error);
            }
        }
        if self.live.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::other("memory origin owner remains alive"));
        }
        failure.map_or(Ok(()), Err)
    }
}

struct Entry {
    context: Option<HttpContext>,
    origin: Arc<Origin>,
    outer_connects: Arc<AtomicUsize>,
}
#[async_trait]
impl Dispatcher for Entry {
    fn http_context(&self) -> Option<HttpContext> {
        self.context.clone()
    }
    async fn sniff_plan(
        &self,
        source: std::net::SocketAddr,
        destination: &Destination,
    ) -> Result<Option<crate::sniffing::Plan>, DispatchError> {
        self.origin.sniff_plan(source, destination).await
    }
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.outer_connects.fetch_add(1, Ordering::SeqCst);
        self.origin.connect_tcp(session).await
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

struct Fixture {
    client: DuplexStream,
    worker: JoinHandle<io::Result<()>>,
    cancellation: CancellationToken,
    outer_connects: Arc<AtomicUsize>,
}
impl Fixture {
    fn new(context: Option<HttpContext>, origin: Arc<Origin>, authenticated: bool) -> Self {
        let outer_connects = Arc::new(AtomicUsize::new(0));
        let entry = Arc::new(Entry {
            context,
            origin,
            outer_connects: outer_connects.clone(),
        });
        let handler = Socks5Handler::new(
            Socks5InboundConfig {
                tag: "memory-socks".into(),
                port: 1080,
                access: ProxyAccess {
                    bind_address: None,
                    allow_lan: false,
                    ipv6: false,
                },
                auth: authenticated.then(|| ProxyCredentials::new("fixture", "password").unwrap()),
            },
            entry,
        );
        let (client, server) = tokio::io::duplex(16384);
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let worker = tokio::spawn(async move {
            // Same cancellation owner as the production accept loop. No test
            // listener, fake HTTP adapter or independently detached relay.
            tokio::select! {
                biased;
                () = stop.cancelled() => Ok(()),
                result = handler.handle_connection(
                    server, "198.51.100.2:34567".parse().unwrap(),
                    "127.0.0.1:1080".parse().unwrap(), None, stop.clone(), Instant::now() + WAIT,
                ) => result,
            }
        });
        Self {
            client,
            worker,
            cancellation,
            outer_connects,
        }
    }
    async fn finish(self, origin: &Origin) -> io::Result<()> {
        self.cancellation.cancel();
        drop(self.client);
        let worker = join(self.worker).await;
        let peers = origin.join().await;
        worker.and(peers)
    }
}
async fn join(mut task: JoinHandle<io::Result<()>>) -> io::Result<()> {
    match timeout(WAIT, &mut task).await {
        Ok(result) => result.map_err(io::Error::other)?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "memory owner did not join",
            ))
        }
    }
}
fn context(yaml: &str, origin: Arc<Origin>) -> HttpContext {
    HttpContext::new(
        Policy::compile(yaml).unwrap(),
        origin,
        SecurityContext::new(),
    )
}
async fn exact(client: &mut DuplexStream, expected: &[u8]) -> io::Result<()> {
    let mut bytes = vec![0; expected.len()];
    client.read_exact(&mut bytes).await?;
    if bytes != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SOCKS reply",
        ));
    }
    Ok(())
}
async fn handshake(client: &mut DuplexStream, port: u16, authenticated: bool) -> io::Result<()> {
    if authenticated {
        client.write_all(&[5, 1, 2]).await?;
        exact(client, &[5, 2]).await?;
        client.write_all(b"\x01\x07fixture\x08password").await?;
        exact(client, &[1, 0]).await?;
    } else {
        client.write_all(&[5, 1, 0]).await?;
        exact(client, &[5, 0]).await?;
    }
    let mut command = vec![5, 1, 0];
    crate::socks5::encode_address(&Destination::domain("target.test", port)?, &mut command)?;
    client.write_all(&command).await?;
    // No HTTP/TLS bytes are sent until the real CONNECT success is received.
    exact(client, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[tokio::test]
async fn socks_http_native_request_response_and_authenticated_identity() {
    let origin = Origin::new(PeerMode::Http);
    let mut fixture = Fixture::new(Some(context(NATIVE, origin.clone())), origin.clone(), true);
    let exchange = timeout(WAIT, async {
        handshake(&mut fixture.client, 80, true).await?;
        fixture.client.write_all(REQUEST).await?;
        let mut response = String::new();
        fixture.client.read_to_string(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await;
    let outer = fixture.outer_connects.load(Ordering::SeqCst);
    let cleanup = fixture.finish(&origin).await;
    cleanup.unwrap();
    let response = exchange.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-response-native: yes\r\n")
    );
    assert!(response.ends_with("\r\n\r\nnative-response"));
    assert_eq!(outer, 0);
    let requests = origin.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        String::from_utf8_lossy(&requests[0].0)
            .to_ascii_lowercase()
            .contains("x-request-native: yes\r\n")
    );
    assert_eq!(requests[0].1, b"native-request");
    let sessions = origin.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].inbound, InboundKind::Socks5);
    assert_eq!(sessions[0].metadata.user.as_deref(), Some("fixture"));
    assert_eq!(sessions[0].metadata.local_port, 1080);
    let original = sessions[0].metadata.original.as_ref().unwrap();
    assert_eq!(original.inbound, InboundKind::Socks5);
    assert_eq!(original.user.as_deref(), Some("fixture"));
    assert_eq!(
        original.destination,
        Destination::domain("target.test", 80).unwrap()
    );
}

#[tokio::test]
async fn socks_http_transparent_boundaries_preserve_bytes_and_fixed_context() {
    for (yaml, port, candidate) in [
        (None, 80, false),
        (
            Some(
                "http-ports: [80]\nrewrite: {enabled: false, rules: [{url: '.', action: response-body-set, value: changed}]}\n",
            ),
            80,
            false,
        ),
        (Some(NATIVE), 81, false),
        (Some(NATIVE), 80, true),
    ] {
        let origin = Origin::new(if candidate {
            PeerMode::SniffingEcho
        } else {
            PeerMode::Echo
        });
        let pinned = yaml.is_some();
        let http = yaml.map(|yaml| context(yaml, origin.clone()));
        let mut fixture = Fixture::new(http, origin.clone(), false);
        let exchange = timeout(WAIT, async {
            handshake(&mut fixture.client, port, false).await?;
            let before_payload = origin.sessions.lock().unwrap().len();
            let payload = b"PING\0opaque\r\n\xfftail";
            fixture.client.write_all(payload).await?;
            fixture.client.shutdown().await?;
            let mut response = Vec::new();
            fixture.client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>((before_payload, response, payload.to_vec()))
        })
        .await;
        let outer = fixture.outer_connects.load(Ordering::SeqCst);
        let cleanup = fixture.finish(&origin).await;
        cleanup.unwrap();
        let (before, response, payload) = exchange.unwrap().unwrap();
        assert_eq!(
            before,
            usize::from(!candidate),
            "raw ports must connect before acknowledging"
        );
        assert_eq!(outer, usize::from(!pinned));
        assert_eq!(
            response, payload,
            "consumed prefix or a duplicate SOCKS reply leaked"
        );
        assert_eq!(origin.requests.lock().unwrap()[0].0, payload);
    }
}

#[tokio::test]
async fn socks_sniffed_prefix_is_flushed_before_the_client_sends_more() {
    let origin = Origin::new(PeerMode::BufferedSniffingEcho);
    let mut fixture = Fixture::new(None, origin.clone(), false);
    let exchange = timeout(WAIT, async {
        handshake(&mut fixture.client, 80, false).await?;
        fixture.client.write_all(REQUEST).await?;
        let mut response = vec![0; REQUEST.len()];
        // The client deliberately keeps its write half open and sends no
        // second flight until the buffered outbound has replied.
        fixture.client.read_exact(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await;
    let cleanup = fixture.finish(&origin).await;
    cleanup.unwrap();
    assert_eq!(exchange.unwrap().unwrap(), REQUEST);
    assert_eq!(
        origin.sessions.lock().unwrap()[0].sniffed_domain.as_deref(),
        Some("target.test")
    );
}

#[tokio::test]
async fn socks_http_transparent_connect_failure_never_sends_a_second_socks_reply() {
    let origin = Origin::new(PeerMode::Refused);
    let mut fixture = Fixture::new(Some(context(NATIVE, origin.clone())), origin.clone(), false);
    let exchange = timeout(WAIT, async {
        handshake(&mut fixture.client, 80, false).await?;
        fixture.client.write_all(b"\0opaque").await?;
        let mut response = Vec::new();
        fixture.client.read_to_end(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await;
    let outer = fixture.outer_connects.load(Ordering::SeqCst);
    let cleanup = fixture.finish(&origin).await;
    assert!(cleanup.is_err());
    assert!(exchange.unwrap().unwrap().is_empty());
    assert_eq!(outer, 0);
    assert_eq!(origin.sessions.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn socks_http_cancel_pending_candidate_joins_without_origin() {
    let origin = Origin::new(PeerMode::Http);
    let mut fixture = Fixture::new(Some(context(NATIVE, origin.clone())), origin.clone(), false);
    let exchange = timeout(WAIT, async {
        handshake(&mut fixture.client, 80, false).await?;
        fixture.client.write_all(b"GE").await
    })
    .await;
    let cleanup = fixture.finish(&origin).await;
    cleanup.unwrap();
    exchange.unwrap().unwrap();
    assert!(origin.sessions.lock().unwrap().is_empty());
    assert_eq!(origin.live.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn socks_https_mitm_allowed_and_excluded_use_real_tls_and_correct_identity() {
    for excluded in [false, true] {
        let material = test_material();
        let identity =
            rcgen::generate_simple_self_signed(vec!["allowed.test".into(), "excluded.test".into()])
                .unwrap();
        let origin_certificate = identity.cert.der().clone();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![origin_certificate.clone()],
            PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
        )
        .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let origin = Origin::new(PeerMode::Tls(Arc::new(server)));
        let yaml = "mitm:\n  enabled: true\n  ports: [443]\n  domains: [{pattern: allowed.test}, {pattern: excluded.test}]\n  exclude-domains: [{pattern: excluded.test}]\nrewrite:\n  enabled: true\n  rules:\n  - {url: '.', action: response-header-set, header: X-Mitm, value: yes}\n  - {url: '.', action: response-body-set, value: decrypted}\n";
        let policy = Document::parse(yaml)
            .unwrap()
            .compile(&Default::default())
            .unwrap()
            .bind_ca(Some(&material))
            .unwrap();
        let mut upstream_roots = rustls::RootCertStore::empty();
        upstream_roots.add(origin_certificate.clone()).unwrap();
        let http = HttpContext::new(
            policy,
            origin.clone(),
            SecurityContext::with_tls_roots(upstream_roots),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(if excluded {
                origin_certificate.clone()
            } else {
                CertificateDer::from_pem_slice(material.certificate.as_bytes()).unwrap()
            })
            .unwrap();
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut fixture = Fixture::new(Some(http), origin.clone(), true);
        let name = if excluded {
            "excluded.test"
        } else {
            "allowed.test"
        };
        let exchange = timeout(WAIT, async {
            handshake(&mut fixture.client, 443, true).await?;
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect(ServerName::try_from(name).unwrap(), &mut fixture.client)
                .await?;
            let certificate = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
            tls.write_all(
                format!("GET /tls HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
            let mut reader = BufReader::new(tls);
            let head = framing::read_head(&mut reader, 32768).await?;
            let parsed = framing::ResponseHead::parse(&head)?;
            let mut body = Vec::new();
            framing::transfer_body(
                &mut reader,
                &mut body,
                parsed.body("GET"),
                WAIT,
                parsed.trailer_blocklist(),
                true,
            )
            .await?;
            let head = String::from_utf8(head).map_err(io::Error::other)?;
            Ok::<_, io::Error>((certificate, head, body))
        })
        .await;
        let outer = fixture.outer_connects.load(Ordering::SeqCst);
        let cleanup = fixture.finish(&origin).await;
        cleanup.unwrap();
        let (certificate, head, body) = exchange.unwrap().unwrap();
        assert_eq!(certificate == origin_certificate, excluded);
        assert!(head.starts_with("HTTP/1.1 200"));
        assert_eq!(
            head.lines()
                .any(|line| line.eq_ignore_ascii_case("x-mitm: yes")),
            !excluded
        );
        assert_eq!(
            body,
            if excluded {
                b"origin".as_slice()
            } else {
                b"decrypted".as_slice()
            }
        );
        assert_eq!(
            outer, 0,
            "transparent TLS must retain the HTTP resource generation"
        );
        let sessions = origin.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].inbound, InboundKind::Socks5);
        assert_eq!(sessions[0].metadata.user.as_deref(), Some("fixture"));
    }
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn socks_http_jsc_request_and_response_follow_native_stages() {
    let yaml = format!(
        "{NATIVE}\nhttp-scripts:\n  enabled: true\n  scripts:\n  - name: request\n    phase: request\n    url: '.'\n    body: text\n    source: 'function rewrite(input) {{return {{type: \"modify\", body: {{kind: \"text\", data: input.body.data + \":js\"}}}};}}'\n  - name: response\n    phase: response\n    url: '.'\n    body: text\n    source: 'function rewrite(input) {{return {{type: \"modify\", body: {{kind: \"text\", data: input.body.data + \":js\"}}}};}}'\n"
    );
    let origin = Origin::new(PeerMode::Http);
    let mut fixture = Fixture::new(Some(context(&yaml, origin.clone())), origin.clone(), false);
    let exchange = timeout(WAIT, async {
        handshake(&mut fixture.client, 80, false).await?;
        fixture.client.write_all(REQUEST).await?;
        let mut response = String::new();
        fixture.client.read_to_string(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await;
    let cleanup = fixture.finish(&origin).await;
    cleanup.unwrap();
    assert!(
        exchange
            .unwrap()
            .unwrap()
            .ends_with("\r\n\r\nnative-response:js")
    );
    assert_eq!(origin.requests.lock().unwrap()[0].1, b"native-request:js");
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn socks_http_jsc_local_response_never_opens_upstream() {
    let origin = Origin::new(PeerMode::Http);
    let yaml = r#"http-ports: [80]
http-scripts:
  enabled: true
  scripts:
  - name: local
    phase: request
    url: '.'
    source: 'function rewrite(input) {return {type:"respond",status:201,body:{kind:"text",data:"local-jsc"}};}'
"#;
    let mut fixture = Fixture::new(Some(context(yaml, origin.clone())), origin.clone(), false);
    let exchange = timeout(WAIT, async {
        handshake(&mut fixture.client, 80, false).await?;
        fixture.client.write_all(REQUEST).await?;
        let mut response = String::new();
        fixture.client.read_to_string(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await;
    let cleanup = fixture.finish(&origin).await;
    cleanup.unwrap();
    let response = exchange.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 201"));
    assert!(response.ends_with("\r\n\r\nlocal-jsc"));
    assert!(origin.sessions.lock().unwrap().is_empty());
}
