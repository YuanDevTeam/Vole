//! TrustTunnel CONNECT over supplied TLS/H2 or controlled QUIC IO. Physical sockets remain owned
//! by the shared Dialer; the node owns the pool and its synchronous stop barrier.
use crate::{
    config::TrustTunnelOutboundConfig,
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        server_destination,
    },
    security::{
        SecurityContext, StandardTlsClient, TlsClientIdentity, TlsClientOptions, TlsVersions,
    },
    session::{DatagramSession, Destination, StreamSession},
    transport::GrpcPool,
};
use async_trait::async_trait;
use base64::Engine;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    task::JoinHandle,
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

mod h3;
mod packet;
const HEALTH_INTERVAL: Duration = Duration::from_secs(7);

struct ConnectionFactory {
    server: Destination,
    upstream: UpstreamPath,
    tls: StandardTlsClient,
    authorization: String,
    quic: bool,
    congestion: Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>,
}
impl ConnectionFactory {
    async fn connect(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<crate::dispatch::BoxStream> {
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await
            .map_err(io::Error::other)?;
        self.tls.connect_with_context(raw.io, context).await
    }
    async fn connect_quic(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<h3::QuicTransport> {
        let (tls, server_name) = self.tls.quic_config_with_context(context).await?;
        let server = self
            .upstream
            .datagram_server(&self.server, context)
            .await
            .map_err(io::Error::other)?;
        let peer = context
            .resolve_ip(&server)
            .await
            .map_err(io::Error::other)?;
        let budget = DatagramBudget::new(1400, 1400);
        let request = DatagramRequest::new(
            DatagramSession::new(session.inbound, session.source).with_metadata(session.metadata),
        )
        .with_budget(budget);
        let transport = self
            .upstream
            .open_datagram(request, context)
            .await
            .map_err(io::Error::other)?;
        Ok(h3::QuicTransport {
            transport,
            peer,
            budget,
            tls,
            server_name,
        })
    }
}

enum ClientTransport {
    H2(GrpcPool),
    H3(h3::Pool),
}
impl ClientTransport {
    async fn open(
        &self,
        request: http::Request<()>,
        context: &EstablishContext,
        observer: Option<Arc<dyn Fn() + Send + Sync>>,
        factory: Arc<ConnectionFactory>,
        session: StreamSession,
    ) -> io::Result<crate::dispatch::BoxStream> {
        match self {
            Self::H2(pool) => match observer {
                Some(observer) => {
                    pool.open_connect_observed(request, context.deadline(), observer, || {
                        factory.connect(session, context)
                    })
                    .await
                }
                None => {
                    pool.open_connect(request, context.deadline(), || {
                        factory.connect(session, context)
                    })
                    .await
                }
            },
            Self::H3(pool) => {
                let setup = context.clone();
                pool.open_connect(request, context.deadline(), observer, move || async move {
                    factory.connect_quic(session, &setup).await
                })
                .await
            }
        }
    }
    async fn probe(
        &self,
        request: http::Request<()>,
        context: &EstablishContext,
        factory: Arc<ConnectionFactory>,
        session: StreamSession,
    ) -> io::Result<()> {
        match self {
            Self::H2(pool) => {
                pool.probe(request, context.deadline(), || {
                    factory.connect(session, context)
                })
                .await
            }
            Self::H3(pool) => {
                let setup = context.clone();
                pool.probe(request, context.deadline(), move || async move {
                    factory.connect_quic(session, &setup).await
                })
                .await
            }
        }
    }
    fn begin_shutdown(&self) {
        match self {
            Self::H2(pool) => pool.begin_shutdown(),
            Self::H3(pool) => pool.begin_shutdown(),
        }
    }
    async fn shutdown(&self) {
        match self {
            Self::H2(pool) => pool.shutdown().await,
            Self::H3(pool) => pool.shutdown().await,
        }
    }
}
struct Client {
    transport: ClientTransport,
    active: AtomicUsize,
    health_started: Mutex<bool>,
    last_success: watch::Sender<Instant>,
}
impl Client {
    fn new(factory: &ConnectionFactory) -> Self {
        let (last_success, _) = watch::channel(Instant::now());
        Self {
            transport: if factory.quic {
                ClientTransport::H3(h3::Pool::new(factory.congestion.clone()))
            } else {
                ClientTransport::H2(GrpcPool::connect_client())
            },
            active: AtomicUsize::new(0),
            health_started: Mutex::new(false),
            last_success,
        }
    }
}
struct ClientLease(Arc<Client>);
impl Drop for ClientLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct OwnedTasks {
    admission: Mutex<()>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
}
impl OwnedTasks {
    fn new() -> Self {
        Self {
            admission: Mutex::new(()),
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }
    fn spawn(
        &self,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<JoinHandle<()>> {
        let _admission = self.admission.lock().unwrap();
        if self.cancellation.is_cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let cancel = self.cancellation.clone();
        Ok(self
            .tasks
            .spawn(crate::resources::observation::task(async move {
                tokio::select! {biased; ()=cancel.cancelled()=>{}, ()=future=>{}}
            })))
    }
    fn close(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancellation.cancel();
        self.tasks.close();
    }
}

pub struct TrustTunnelOutbound {
    connection: Arc<ConnectionFactory>,
    options: crate::config::TrustTunnelPoolOptions,
    udp: bool,
    health_check: bool,
    clients: Mutex<Vec<Arc<Client>>>,
    owned: OwnedTasks,
}

impl TrustTunnelOutbound {
    pub(crate) fn with_shared_security(
        config: &TrustTunnelOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let policy = &config.tls;
        let tls = StandardTlsClient::with_options(
            security,
            &policy.server_name,
            TlsClientOptions {
                ech: policy.ech.clone(),
                client_fingerprint: if config.quic {
                    None
                } else {
                    policy.client_fingerprint
                },
                versions: if policy.tls13_only {
                    TlsVersions::Tls13
                } else {
                    TlsVersions::Tls12And13
                },
                alpn: policy.alpn.clone(),
                required_alpn: policy.required_alpn.clone(),
                certificate: policy.certificate.clone(),
                identity: policy
                    .identity
                    .as_ref()
                    .map(|identity| {
                        TlsClientIdentity::from_pem(&identity.certificate, &identity.private_key)
                    })
                    .transpose()?,
            },
            sessions,
            buffer_limit,
        )?;
        let connection = Arc::new(ConnectionFactory {
            server: server_destination(&config.address, config.port)?,
            upstream,
            tls,
            authorization: format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", config.username, config.password))
            ),
            quic: config.quic,
            congestion: if config.quic {
                crate::transport::quic::congestion_controller(
                    &config.congestion_controller,
                    config.cwnd,
                    &config.bbr_profile,
                )
            } else {
                None
            },
        });
        let first = Arc::new(Client::new(&connection));
        Ok(Self {
            connection,
            options: config.pool.clone(),
            udp: config.udp,
            health_check: config.health_check,
            clients: Mutex::new(vec![first]),
            owned: OwnedTasks::new(),
        })
    }
    fn select_client(&self) -> io::Result<ClientLease> {
        let _admission = self.owned.admission.lock().unwrap();
        if self.owned.cancellation.is_cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let mut clients = self.clients.lock().unwrap();
        let candidate = clients
            .iter()
            .min_by_key(|client| client.active.load(Ordering::Acquire))
            .cloned();
        let client = match candidate {
            Some(client)
                if reuse_client(
                    &self.options,
                    clients.len(),
                    client.active.load(Ordering::Acquire),
                ) =>
            {
                client
            }
            _ => {
                let client = Arc::new(Client::new(&self.connection));
                clients.push(client.clone());
                client
            }
        };
        client
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        Ok(ClientLease(client))
    }
    fn start_health(
        &self,
        client: &Arc<Client>,
        session: &StreamSession,
        context: &EstablishContext,
    ) -> io::Result<()> {
        if !self.health_check {
            return Ok(());
        }
        let mut started = client.health_started.lock().unwrap();
        if *started {
            return Ok(());
        }
        client.last_success.send_replace(Instant::now());
        let mut activity = client.last_success.subscribe();
        let client = Arc::downgrade(client);
        let factory = self.connection.clone();
        let session = session.clone();
        let resolution = context.resolution();
        self.owned.spawn(async move {
            loop {
                let deadline = *activity.borrow_and_update() + HEALTH_INTERVAL;
                tokio::select! {
                    changed=activity.changed()=>{ if changed.is_err() { return; } continue; }
                    ()=tokio::time::sleep_until(deadline)=>{}
                }
                let Some(client) = client.upgrade() else {
                    return;
                };
                let context =
                    EstablishContext::with_resolution(HEALTH_INTERVAL, resolution.clone());
                if let Ok(request) =
                    authority_request("_check", &factory.authorization, std::env::consts::OS)
                {
                    let _ = client
                        .transport
                        .probe(request, &context, factory.clone(), session.clone())
                        .await;
                }
                // Probe failure does not reset physical connections or mutate a
                // policy group's health; the next probe is scheduled normally.
                client.last_success.send_replace(Instant::now());
            }
        })?;
        *started = true;
        Ok(())
    }
    async fn connect(
        &self,
        session: StreamSession,
        authority: &str,
        context: &EstablishContext,
    ) -> io::Result<crate::dispatch::BoxStream> {
        let lease = self.select_client()?;
        self.start_health(&lease.0, &session, context)?;
        let user_agent = if authority == "_udp2" {
            format!("{} _udp2", std::env::consts::OS)
        } else {
            format!(
                "{} Vole/{}",
                std::env::consts::OS,
                env!("CARGO_PKG_VERSION")
            )
        };
        let request = authority_request(authority, &self.connection.authorization, &user_agent)?;
        let observer = if self.health_check {
            let client = Arc::downgrade(&lease.0);
            Some(Arc::new(move || {
                if let Some(client) = client.upgrade() {
                    client.last_success.send_replace(Instant::now());
                }
            }) as Arc<dyn Fn() + Send + Sync>)
        } else {
            None
        };
        let stream = lease
            .0
            .transport
            .open(request, context, observer, self.connection.clone(), session)
            .await?;
        Ok(Box::new(CountedStream {
            io: stream,
            lease: Some(lease),
        }))
    }
}

fn reuse_client(
    options: &crate::config::TrustTunnelPoolOptions,
    count: usize,
    active: usize,
) -> bool {
    let smaller =
        |count: usize, threshold: i64| threshold > 0 && (count as u128) < threshold as u128;
    active == 0
        || if options.max_connections > 0 {
            !smaller(count, options.max_connections) || smaller(active, options.min_streams)
        } else {
            smaller(active, options.max_streams)
        }
}

struct CountedStream {
    io: crate::dispatch::BoxStream,
    lease: Option<ClientLease>,
}
impl AsyncRead for CountedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}
impl AsyncWrite for CountedStream {
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
        let result = Pin::new(&mut self.io).poll_shutdown(cx);
        if result.is_ready() {
            self.lease.take();
        }
        result
    }
}

#[cfg(test)]
fn connect_request(target: &Destination, authorization: &str) -> io::Result<http::Request<()>> {
    let authority = match target {
        Destination::Ip(address) => address.to_string(),
        Destination::Domain { host, port } => format!("{host}:{port}"),
    };
    authority_request(
        &authority,
        authorization,
        &format!(
            "{} Vole/{}",
            std::env::consts::OS,
            env!("CARGO_PKG_VERSION")
        ),
    )
}
fn authority_request(
    authority: &str,
    authorization: &str,
    user_agent: &str,
) -> io::Result<http::Request<()>> {
    // Ordinary CONNECT uses only :authority in both H2 and H3.
    let uri = http::Uri::builder()
        .authority(authority)
        .build()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header("proxy-authorization", authorization)
        .header("user-agent", user_agent)
        .body(())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

#[async_trait]
impl OutboundConnector for TrustTunnelOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let target = session.destination.clone();
        let authority = match &target {
            Destination::Ip(address) => address.to_string(),
            Destination::Domain { host, port } => format!("{host}:{port}"),
        };
        let io = context
            .run_io(
                "TrustTunnel CONNECT",
                self.connect(session, &authority, context),
            )
            .await?;
        Ok(ConnectedStream {
            io,
            effective_peer: target,
        })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        if !self.udp {
            return Err(DispatchError::NotAllowed);
        }
        let session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: self.connection.server.clone(),
            sniffed_domain: None,
        };
        let io = context
            .run_io(
                "TrustTunnel UDP CONNECT",
                self.connect(session, "_udp2", context),
            )
            .await?;
        let transport = packet::PacketTransport::new(
            io,
            &request,
            context,
            self.owned.cancellation.clone(),
            |reader| self.owned.spawn(reader),
        )?;
        Ok(crate::dispatch::bound_datagram(
            Box::new(transport),
            request.budget(),
        ))
    }
    fn begin_shutdown(&self) {
        self.owned.close();
        for client in self.clients.lock().unwrap().iter() {
            client.transport.begin_shutdown();
        }
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.owned.tasks.wait().await;
        let clients = std::mem::take(&mut *self.clients.lock().unwrap());
        for client in clients {
            client.transport.shutdown().await;
        }
    }
}
impl Drop for TrustTunnelOutbound {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GrpcOptions;
    use crate::resources::observation::ResourceProbe;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::task::TaskTracker;

    struct NoNetwork;
    #[async_trait]
    impl OutboundConnector for NoNetwork {
        async fn connect_stream(
            &self,
            _: StreamSession,
            _: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
        async fn open_datagram(
            &self,
            _: DatagramRequest,
            _: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }
    fn make_node(options: &str) -> TrustTunnelOutbound {
        let config = crate::config::Config::parse_yaml(format!("proxies:\n  - name: tunnel\n    type: trusttunnel\n    server: fixture.invalid\n    port: 443\n{options}").as_bytes()).unwrap();
        let crate::config::ProxyProtocol::TrustTunnel(config) = &config.proxies[0].protocol else {
            panic!("TrustTunnel");
        };
        TrustTunnelOutbound::with_shared_security(
            config,
            UpstreamPath::proxy(Arc::new(NoNetwork)),
            &SecurityContext::new(),
            1,
            65536,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn trusttunnel_logical_slots_release_leases_and_keep_threshold_priority() {
        let node = make_node("    max-connections: 2\n    min-streams: 1\n    max-streams: 1\n");
        let first = node.select_client().unwrap();
        let second = node.select_client().unwrap();
        let third = node.select_client().unwrap();
        assert_eq!(node.clients.lock().unwrap().len(), 2);
        assert!(Arc::ptr_eq(&first.0, &third.0));
        assert!(!Arc::ptr_eq(&first.0, &second.0));
        drop(second);
        let fourth = node.select_client().unwrap();
        assert_eq!(fourth.0.active.load(Ordering::Acquire), 1);
        assert!(!Arc::ptr_eq(&first.0, &fourth.0));
        drop((first, third, fourth));
        // A transport can retire independently of its persistent logical slot.
        assert_eq!(node.clients.lock().unwrap().len(), 2);
        node.shutdown().await;
        assert!(node.select_client().is_err());
        assert!(node.owned.spawn(async {}).is_err());

        let node = make_node("    max-connections: -1\n    max-streams: 1\n");
        let first = node.select_client().unwrap();
        let second = node.select_client().unwrap();
        assert_eq!(node.clients.lock().unwrap().len(), 2);
        drop(first);
        let third = node.select_client().unwrap();
        assert_ne!(Arc::as_ptr(&second.0), Arc::as_ptr(&third.0));
        drop((second, third));
        node.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn trusttunnel_health_is_lazy_bodyless_and_does_not_count_business_streams() {
        let observation = ResourceProbe::default();
        observation
            .scope(async {
                let node = make_node("    health-check: true\n");
                assert!(node.owned.tasks.is_empty());
                let lease = node.select_client().unwrap();
                let peers = TaskTracker::new();
                let (checked, mut checks) = tokio::sync::mpsc::channel(1);
                let ready = Arc::new(tokio::sync::Notify::new());
                let (raw, peer) = tokio::io::duplex(65536);
                let streams = peers.clone();
                peers.spawn(async move {
                    let mut connection = h2::server::handshake(peer).await.unwrap();
                    while let Some(Ok((request, mut response))) = connection.accept().await {
                        if request.uri().authority().unwrap().as_str() == "_check" {
                            assert_eq!(request.headers()["user-agent"], std::env::consts::OS);
                            assert_eq!(request.headers()["proxy-authorization"], "Basic Og==");
                            assert!(request.body().is_end_stream());
                            response
                                .send_response(http::Response::new(()), true)
                                .unwrap();
                            checked.send(()).await.unwrap();
                        } else {
                            let send = response
                                .send_response(http::Response::new(()), false)
                                .unwrap();
                            streams.spawn(async move {
                                let _send = send;
                                let mut receive = request.into_body();
                                while let Some(Ok(data)) = receive.data().await {
                                    receive.flow_control().release_capacity(data.len()).unwrap();
                                }
                            });
                        }
                    }
                });
                let session = StreamSession {
                    metadata: Default::default(),
                    inbound: crate::session::InboundKind::Socks5,
                    source: "127.0.0.1:1000".parse().unwrap(),
                    destination: Destination::Domain {
                        host: "target.invalid".into(),
                        port: 443,
                    },
                    sniffed_domain: None,
                };
                let context = EstablishContext::with_timeout(Duration::from_secs(5));
                node.start_health(&lease.0, &session, &context).unwrap();
                let observed_client = Arc::downgrade(&lease.0);
                let observed_ready = ready.clone();
                let ClientTransport::H2(transport) = &lease.0.transport else {
                    unreachable!();
                };
                let mut stream = transport
                    .open_connect_observed(
                        connect_request(&session.destination, &node.connection.authorization)
                            .unwrap(),
                        context.deadline(),
                        Arc::new(move || {
                            if let Some(client) = observed_client.upgrade() {
                                client.last_success.send_replace(Instant::now());
                            }
                            observed_ready.notify_one();
                        }),
                        || async { Ok(Box::new(raw) as crate::dispatch::BoxStream) },
                    )
                    .await
                    .unwrap();
                stream.write_all(b"write-only").await.unwrap();
                stream.flush().await.unwrap();
                ready.notified().await;
                tokio::time::advance(Duration::from_secs(6)).await;
                assert!(checks.try_recv().is_err());
                tokio::time::advance(Duration::from_secs(1)).await;
                checks.recv().await.unwrap();
                assert_eq!(lease.0.active.load(Ordering::Acquire), 1);
                stream.shutdown().await.unwrap();
                drop((stream, lease));
                node.shutdown().await;
                drop(node);
                peers.close();
                peers.wait().await;
            })
            .await;
        assert!(observation.snapshot().is_idle());
    }

    #[tokio::test]
    async fn trusttunnel_h2_connect_is_raw_deferred_pooled_and_stopped() {
        let probe = ResourceProbe::default();
        probe
            .scope(async {
                let peers = TaskTracker::new();
                let connections = Arc::new(AtomicUsize::new(0));
                let pool = GrpcPool::new(GrpcOptions::default());
                let make_connection = || {
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (client, peer) = tokio::io::duplex(64 * 1024);
                    let streams = peers.clone();
                    peers.spawn(async move {
                        let mut connection = h2::server::handshake(peer).await.unwrap();
                        while let Some(Ok((request, mut response))) = connection.accept().await {
                            assert_eq!(request.method(), http::Method::CONNECT);
                            assert_eq!(request.uri().authority().unwrap(), "example.invalid:443");
                            assert_eq!(request.headers()["proxy-authorization"], "Basic dTpw");
                            assert!(!request.headers().contains_key("content-type"));
                            streams.spawn(async move {
                                let mut receive = request.into_body();
                                let data = receive.data().await.unwrap().unwrap();
                                assert_eq!(data.as_ref(), b"unframed-client-first");
                                receive.flow_control().release_capacity(data.len()).unwrap();
                                let mut send = response
                                    .send_response(http::Response::new(()), false)
                                    .unwrap();
                                send.send_data(data, false).unwrap();
                                while receive.data().await.is_some_and(|data| data.is_ok()) {}
                            });
                        }
                    });
                    async move { Ok(Box::new(client) as crate::dispatch::BoxStream) }
                };
                let target = Destination::Domain {
                    host: "example.invalid".into(),
                    port: 443,
                };
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut first = pool
                    .open_connect(
                        connect_request(&target, "Basic dTpw").unwrap(),
                        deadline,
                        make_connection,
                    )
                    .await
                    .unwrap();
                let mut second = pool
                    .open_connect(
                        connect_request(&target, "Basic dTpw").unwrap(),
                        deadline,
                        make_connection,
                    )
                    .await
                    .unwrap();
                assert_eq!(connections.load(Ordering::SeqCst), 1);
                for stream in [&mut first, &mut second] {
                    stream.write_all(b"unframed-client-first").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut response = [0; 21];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"unframed-client-first");
                }
                first.shutdown().await.unwrap();
                pool.shutdown().await;
                assert!(second.write_all(b"after-stop").await.is_err());
                drop((first, second));
                peers.close();
                peers.wait().await;
            })
            .await;
        assert!(probe.snapshot().is_idle());
    }
}
