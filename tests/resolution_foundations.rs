use async_trait::async_trait;
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use vole::{
    dialer::{ResolvedEndpoint, Resolver},
    dns::resolution::ResolutionContext,
    outbound::EstablishContext,
    session::Destination,
};

struct Bootstrap(AtomicUsize);

struct IpBoundary {
    seen: Arc<std::sync::Mutex<Vec<(Destination, SocketAddr)>>>,
}
#[async_trait]
impl vole::outbound::OutboundConnector for IpBoundary {
    async fn connect_stream(
        &self,
        session: vole::session::StreamSession,
        context: &EstablishContext,
    ) -> Result<vole::outbound::ConnectedStream, vole::dispatch::DispatchError> {
        let effective = context.resolve_ip(&session.destination).await?;
        self.seen
            .lock()
            .unwrap()
            .push((session.destination, effective));
        let (stream, _) = tokio::io::duplex(1);
        Ok(vole::outbound::ConnectedStream {
            io: Box::new(stream),
            effective_peer: Destination::Ip(effective),
        })
    }
    async fn open_datagram(
        &self,
        _: vole::outbound::DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn vole::dispatch::DatagramTransport>, vole::dispatch::DispatchError> {
        unreachable!()
    }
}

#[tokio::test]
async fn measurement_domain_resolution_reaches_both_final_and_upstream_ip_boundaries() {
    use vole::{
        dispatch::Dispatcher,
        outbound::{ConnectorDispatcher, UpstreamPath},
        session::{InboundKind, StreamSession},
    };
    let bootstrap = Arc::new(Bootstrap(AtomicUsize::new(0)));
    let resolution = ResolutionContext::measurement(bootstrap.clone(), false);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let connector = Arc::new(IpBoundary { seen: seen.clone() });
    let dispatcher =
        ConnectorDispatcher::new(connector.clone()).with_resolution(resolution.clone());
    let target = Destination::domain("controlled.example", 443).unwrap();
    let session = StreamSession {
        metadata: Default::default(),
        inbound: InboundKind::InternalMeasure,
        source: "127.0.0.1:0".parse().unwrap(),
        destination: target.clone(),
        sniffed_domain: None,
    };
    dispatcher.connect_tcp(session.clone()).await.unwrap();
    let upstream_target = Destination::domain("controlled.example", 8443).unwrap();
    UpstreamPath::proxy(connector)
        .connect_server(
            session,
            &upstream_target,
            &EstablishContext::with_resolution(Duration::from_secs(10), resolution.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            (target, "192.0.2.1:443".parse().unwrap()),
            (upstream_target, "192.0.2.1:8443".parse().unwrap())
        ]
    );
    assert_eq!(bootstrap.0.load(Ordering::Relaxed), 2);
    resolution.close();
}

struct ChainedBootstrap(Arc<AtomicUsize>);
#[async_trait]
impl Resolver for ChainedBootstrap {
    async fn resolve(&self, _: &str, port: u16) -> io::Result<ResolvedEndpoint> {
        let depth = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        let resolution = ResolutionContext::measurement(Arc::new(Self(self.0.clone())), true);
        resolution
            .resolve_ip(
                &Destination::domain(format!("level-{depth}.example"), port).unwrap(),
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await
            .map_err(|_| io::Error::other("bounded dependency rejected"))?;
        unreachable!()
    }
}

#[tokio::test]
async fn resolver_dependency_depth_is_bounded_independently_of_concurrent_lookups() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolution =
        ResolutionContext::measurement(Arc::new(ChainedBootstrap(calls.clone())), true);
    let context = EstablishContext::with_resolution(Duration::from_secs(1), resolution);
    assert!(
        context
            .resolve_ip(&Destination::domain("level-0.example", 443).unwrap())
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 32);
}
#[async_trait]
impl Resolver for Bootstrap {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<ResolvedEndpoint> {
        self.0.fetch_add(1, Ordering::Relaxed);
        assert_eq!(host, "controlled.example");
        Ok(ResolvedEndpoint {
            logical_host: host.into(),
            port,
            addresses: vec![
                SocketAddr::new("2001:db8::1".parse().unwrap(), port),
                SocketAddr::new("192.0.2.1".parse().unwrap(), port),
            ],
        })
    }
}

#[tokio::test]
async fn runtime_uses_configured_dns_and_weak_binding_releases_owner() {
    use vole::{
        config::{DnsConfig, DnsNameserver, DnsRoute, DnsTransport},
        dialer::Dialer,
        dns::runtime::RuntimeDns,
        outbound::DirectOutbound,
    };
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = peer.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut packet = [0; 4096];
        let (length, source) = peer.recv_from(&mut packet).await.unwrap();
        assert_eq!(
            vole::dns::parse_query(&packet[..length])
                .unwrap()
                .question
                .name,
            "controlled.example"
        );
        let mut response = packet[..length].to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 11]);
        peer.send_to(&response, source).await.unwrap();
    });
    let config = DnsConfig {
        enable: true,
        ipv6: false,
        nameservers: vec![DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport: DnsTransport::Udp,
            address: address.ip().into(),
            port: address.port(),
            route: DnsRoute::Direct,
        }],
        nameserver_policies: vec![],
        ..DnsConfig::default()
    };
    let dns = Arc::new(RuntimeDns::new(
        &config,
        Arc::new(DirectOutbound::new(Dialer::default())),
    ));
    let weak = Arc::downgrade(&dns);
    let resolution = ResolutionContext::runtime(true);
    resolution.bind_runtime(Some(&dns)).unwrap();
    assert_eq!(Arc::strong_count(&dns), 1);
    let context = EstablishContext::with_resolution(Duration::from_secs(1), resolution);
    assert_eq!(
        context
            .resolve_ip(&Destination::domain("controlled.example", 8443).unwrap())
            .await
            .unwrap(),
        "203.0.113.11:8443".parse().unwrap()
    );
    responder.await.unwrap();
    drop(dns);
    assert!(weak.upgrade().is_none());
    assert!(
        context
            .resolve_ip(&Destination::domain("controlled.example", 8443).unwrap())
            .await
            .is_err()
    );
}

struct RecursiveEgress {
    resolution: ResolutionContext,
    rejected: Arc<AtomicUsize>,
}
#[async_trait]
impl vole::dispatch::Dispatcher for RecursiveEgress {
    async fn connect_tcp(
        &self,
        _: vole::session::StreamSession,
    ) -> Result<vole::dispatch::BoxStream, vole::dispatch::DispatchError> {
        unreachable!()
    }
    async fn open_datagram(
        &self,
        _: vole::session::DatagramSession,
    ) -> Result<Box<dyn vole::dispatch::DatagramTransport>, vole::dispatch::DispatchError> {
        let context =
            EstablishContext::with_resolution(Duration::from_secs(10), self.resolution.clone());
        let error = context
            .resolve_ip(&Destination::domain("controlled.example", 53).unwrap())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("recursive DNS dependency"));
        self.rejected.fetch_add(1, Ordering::Relaxed);
        Err(error)
    }
}

#[tokio::test]
async fn recursive_dns_dependency_fails_before_connecting_or_joining_its_own_flight() {
    use vole::{
        config::{DnsConfig, DnsNameserver, DnsRoute, DnsTransport},
        dns::runtime::RuntimeDns,
    };
    let resolution = ResolutionContext::runtime(true);
    let rejected = Arc::new(AtomicUsize::new(0));
    let egress = Arc::new(RecursiveEgress {
        resolution: resolution.clone(),
        rejected: rejected.clone(),
    });
    let config = DnsConfig {
        enable: true,
        ipv6: false,
        nameservers: vec![DnsNameserver {
            path: None,
            http_auth: None,
            options: Default::default(),
            transport: DnsTransport::Udp,
            address: "192.0.2.1".parse().unwrap(),
            port: 53,
            route: DnsRoute::Direct,
        }],
        nameserver_policies: vec![],
        ..DnsConfig::default()
    };
    let dns = Arc::new(RuntimeDns::new(&config, egress));
    resolution.bind_runtime(Some(&dns)).unwrap();
    let context = EstablishContext::with_resolution(Duration::from_secs(10), resolution);
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        context.resolve_ip(&Destination::domain("controlled.example", 443).unwrap()),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(rejected.load(Ordering::Relaxed), 1);
}

struct PendingBootstrap {
    active: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
}
struct LookupGuard(Arc<AtomicUsize>);
impl Drop for LookupGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
#[async_trait]
impl Resolver for PendingBootstrap {
    async fn resolve(&self, _: &str, _: u16) -> io::Result<ResolvedEndpoint> {
        self.active.fetch_add(1, Ordering::Relaxed);
        let _guard = LookupGuard(self.active.clone());
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn lookup_deadline_and_stop_cancel_pending_resolver_without_retaining_waiters() {
    let active = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let resolution = ResolutionContext::measurement(
        Arc::new(PendingBootstrap {
            active: active.clone(),
            entered: entered.clone(),
        }),
        true,
    );
    let target = Destination::domain("controlled.example", 443).unwrap();
    let context = EstablishContext::with_resolution(Duration::from_millis(10), resolution.clone());
    assert!(matches!(
        context.resolve_ip(&target).await,
        Err(vole::dispatch::DispatchError::TimedOut)
    ));
    assert_eq!(active.load(Ordering::Relaxed), 0);
    // Consume the first lookup's notification before observing the second.
    entered.notified().await;
    let context = EstablishContext::with_resolution(Duration::from_secs(10), resolution.clone());
    let task = tokio::spawn(async move { context.resolve_ip(&target).await });
    entered.notified().await;
    assert_eq!(active.load(Ordering::Relaxed), 1);
    resolution.close();
    assert!(task.await.unwrap().is_err());
    assert_eq!(active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn standalone_measurement_resolves_only_at_ip_boundary_with_address_policy_and_stop() {
    let bootstrap = Arc::new(Bootstrap(AtomicUsize::new(0)));
    let resolution = ResolutionContext::measurement(bootstrap.clone(), false);
    let context = EstablishContext::with_resolution(Duration::from_secs(10), resolution.clone());
    let target = Destination::domain("controlled.example", 443).unwrap();
    assert_eq!(bootstrap.0.load(Ordering::Relaxed), 0);
    assert_eq!(
        context.resolve_ip(&target).await.unwrap(),
        "192.0.2.1:443".parse().unwrap()
    );
    assert_eq!(
        target,
        Destination::domain("controlled.example", 443).unwrap()
    );
    assert_eq!(bootstrap.0.load(Ordering::Relaxed), 1);
    resolution.close();
    assert!(context.resolve_ip(&target).await.is_err());
    assert_eq!(bootstrap.0.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn unbound_and_disabled_runtime_resolution_never_fall_back_to_system_dns() {
    let resolution = ResolutionContext::runtime(false);
    let context = EstablishContext::with_resolution(Duration::from_secs(10), resolution.clone());
    let target = Destination::domain("localhost", 443).unwrap();
    assert!(context.resolve_ip(&target).await.is_err());
    resolution.bind_runtime(None).unwrap();
    assert!(context.resolve_ip(&target).await.is_err());
    assert!(resolution.bind_runtime(None).is_err());
    assert_eq!(
        context
            .resolve_ip(&Destination::Ip("192.0.2.5:443".parse().unwrap()))
            .await
            .unwrap(),
        "192.0.2.5:443".parse().unwrap()
    );
    assert!(
        context
            .resolve_ip(&Destination::Ip("[2001:db8::1]:443".parse().unwrap()))
            .await
            .is_err()
    );
}
