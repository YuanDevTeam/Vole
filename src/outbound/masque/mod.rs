//! Cloudflare MASQUE CONNECT-IP and L4 CONNECT over controlled transports.
mod datagram;
mod ip;
mod packet;
mod resolver;
use crate::{
    config::{MasqueNetwork, MasqueOutboundConfig},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        server_destination,
    },
    security::{SecurityContext, masque::MasqueTls},
    session::{DatagramSession, Destination, StreamSession},
    transport::{GrpcPool, h3_connect, quiche_h3},
};
use async_trait::async_trait;
use std::{
    io,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(super) struct ConnectionFactory {
    server: Destination,
    server_name: String,
    upstream: UpstreamPath,
    tls: MasqueTls,
    udp_receive_buffer_size: Option<usize>,
}
impl ConnectionFactory {
    /// This concrete factory owns parsed immutable SPKI/client ECDSA material.
    /// Prove the actual carrier: H2 TCP graph or H3 physical UDP first hop.
    #[cfg(feature = "inbound-http")]
    fn permits_static_http_reuse(&self, network: MasqueNetwork) -> bool {
        match network {
            MasqueNetwork::H2 => self.upstream.permits_static_http_reuse(&self.server),
            MasqueNetwork::Quic | MasqueNetwork::H3L4Proxy => {
                self.upstream.permits_static_direct_http_reuse(&self.server)
            }
        }
    }

    pub(super) async fn connect_h2(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<crate::dispatch::BoxStream> {
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await
            .map_err(io::Error::other)?;
        let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid MASQUE SNI"))?;
        let io = context
            .run_io(
                "MASQUE H2 TLS",
                tokio_rustls::TlsConnector::from(self.tls.config(false)?).connect(name, raw.io),
            )
            .await
            .map_err(io::Error::other)?;
        if io.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MASQUE requires H2 ALPN",
            ));
        }
        Ok(Box::new(io))
    }
    pub(super) async fn connect(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<h3_connect::QuicTransport> {
        self.connect_inner(session, context, cfg!(target_os = "macos"))
            .await
    }
    #[cfg(target_os = "macos")]
    pub(super) async fn connect_ip(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> io::Result<h3_connect::QuicTransport> {
        self.connect_inner(session, context, true).await
    }
    async fn connect_inner(
        &self,
        session: StreamSession,
        context: &EstablishContext,
        fixed_peer: bool,
    ) -> io::Result<h3_connect::QuicTransport> {
        let tls = self.tls.quiche_config(self.server_name.clone())?;
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
        let request = if let Some(size) = self.udp_receive_buffer_size {
            request.with_udp_receive_buffer_size(size)
        } else {
            request
        };
        #[cfg(target_os = "macos")]
        let transport = if fixed_peer {
            self.upstream
                .open_fixed_peer_datagram(request, peer, context)
                .await
        } else {
            self.upstream.open_datagram(request, context).await
        };
        #[cfg(not(target_os = "macos"))]
        let transport = {
            let _ = fixed_peer;
            self.upstream.open_datagram(request, context).await
        };
        let transport = transport.map_err(io::Error::other)?;
        Ok(h3_connect::QuicTransport {
            transport,
            peer,
            budget,
            tls,
            server_name: self.server_name.clone(),
        })
    }
}

pub struct MasqueOutbound {
    connection: Arc<ConnectionFactory>,
    pool: Arc<h3_connect::Pool>,
    h2_pool: Arc<GrpcPool>,
    config: Arc<MasqueOutboundConfig>,
    security: SecurityContext,
    remote: OnceLock<Arc<crate::dns::runtime::RuntimeDns>>,
    current: AsyncMutex<Option<Arc<ip::Engine>>>,
    cancel: CancellationToken,
    admission: Mutex<()>,
    retired: TaskTracker,
}
impl MasqueOutbound {
    pub(crate) fn with_shared_security(
        config: &MasqueOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
    ) -> io::Result<Self> {
        let tls = MasqueTls::new(
            &config.private_key,
            &config.public_key,
            config.skip_cert_verify,
            security,
        )?;
        let congestion = (config.network != MasqueNetwork::H2)
            .then(|| quiche_h3::congestion_controller(&config.congestion_controller))
            .flatten();
        let pool = if config.network == MasqueNetwork::H3L4Proxy {
            h3_connect::Pool::masque_l4(congestion)
        } else {
            h3_connect::Pool::masque_ip(congestion)
        };
        Ok(Self {
            connection: Arc::new(ConnectionFactory {
                server: server_destination(&config.address, config.port)?,
                server_name: config.server_name.clone(),
                upstream,
                tls,
                udp_receive_buffer_size: (config.network == MasqueNetwork::Quic)
                    .then_some(512 * 1024),
            }),
            pool: Arc::new(pool),
            h2_pool: Arc::new(GrpcPool::masque_ip()),
            config: Arc::new(config.clone()),
            security: security.clone(),
            remote: OnceLock::new(),
            current: AsyncMutex::new(None),
            cancel: CancellationToken::new(),
            admission: Mutex::new(()),
            retired: TaskTracker::new(),
        })
    }
    async fn engine(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<Arc<ip::Engine>, DispatchError> {
        let (engine, created) = tokio::select! { biased;
            ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
            result=context.run("MASQUE IP initialize",async {
                let mut current=self.current.lock().await;
                let _admission=self.admission.lock().unwrap();
                if self.cancel.is_cancelled() { return Err(DispatchError::NotAllowed); }
                if let Some(engine)=current.as_ref().filter(|engine|!engine.cancel.is_cancelled()) {return Ok((engine.clone(),false));}
                if let Some(old)=current.take() {self.retired.spawn(crate::resources::observation::task(async move{old.stop().await;}));}
                let setup = context.clone().with_metadata(&session.metadata);
                let setup = if self.config.handshake_timeout > 0 {
                    setup.masque_handshake(self.config.handshake_timeout)
                } else { setup };
                let engine=ip::Engine::start(self.config.clone(),self.connection.clone(),self.pool.clone(),self.h2_pool.clone(),self.security.clone(),session,setup,self.cancel.child_token())?;
                *current=Some(engine.clone());
                Ok((engine,true))
            })=>result?,
        };
        let mut creator = CreationGuard {
            engine: &engine,
            armed: created && self.config.handshake_timeout == 0,
        };
        engine.wait_ready(context).await?;
        creator.armed = false;
        drop(creator);
        Ok(engine)
    }
}

struct CreationGuard<'a> {
    engine: &'a ip::Engine,
    armed: bool,
}
impl Drop for CreationGuard<'_> {
    fn drop(&mut self) {
        if self.armed && self.engine.initializing() {
            self.engine.cancel.cancel();
        }
    }
}

pub(super) async fn connect_l4_literal(
    factory: Arc<ConnectionFactory>,
    pool: Arc<h3_connect::Pool>,
    session: StreamSession,
    context: &EstablishContext,
) -> Result<crate::dispatch::BoxStream, DispatchError> {
    if !matches!(session.destination, Destination::Ip(_)) {
        return Err(DispatchError::HostUnreachable);
    }
    let request = connect_request(&session.destination)?;
    let setup = context.clone();
    context
        .run_io(
            "MASQUE L4 CONNECT",
            pool.open_connect(request, context.deadline(), None, move || async move {
                factory.connect(session, &setup).await
            }),
        )
        .await
}

fn connect_request(target: &Destination) -> io::Result<http::Request<()>> {
    let authority = match target {
        Destination::Ip(address) => address.to_string(),
        Destination::Domain { host, port } => format!("{host}:{port}"),
    };
    let uri = http::Uri::builder()
        .authority(authority)
        .build()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid MASQUE CONNECT authority",
            )
        })?;
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .body(())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid MASQUE CONNECT request",
            )
        })
}

#[async_trait]
impl OutboundConnector for MasqueOutbound {
    #[cfg(feature = "inbound-http")]
    fn permits_http_tcp_reuse(&self) -> bool {
        !self.cancel.is_cancelled()
            && self
                .connection
                .permits_static_http_reuse(self.config.network)
    }

    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        if self.config.network != MasqueNetwork::H3L4Proxy {
            let engine = self.engine(session.clone(), context).await?;
            let remote = engine
                .resolve(
                    &session.destination,
                    &context.resolution(),
                    context.deadline(),
                )
                .await?;
            let io = tokio::select! {biased;
                ()=engine.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),
                result=context.run_io("MASQUE IP TCP",engine.tcp.connect(remote,context.deadline()))=>result?,
            };
            return Ok(ConnectedStream {
                io: Box::new(crate::outbound::owned_stream::OwnedStream::new(
                    Box::new(io),
                    engine.cancel.child_token(),
                )),
                effective_peer: Destination::Ip(remote),
            });
        }
        let resolution = context.resolution();
        let remote = resolver::resolve_l4(
            resolver::L4DnsContext {
                remote: &self.remote,
                nameservers: &self.config.dns,
                factory: &self.connection,
                pool: &self.pool,
                cancel: &self.cancel,
                security: &self.security,
                bootstrap: &resolution,
            },
            &session.destination,
            context.deadline(),
        )
        .await?;
        let target = Destination::Ip(remote);
        let mut session = session;
        session.destination = target.clone();
        let io = tokio::select! { biased;
            ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
            io=connect_l4_literal(self.connection.clone(),self.pool.clone(),session,context)=>io?,
        };
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
        if self.config.network == MasqueNetwork::H3L4Proxy || !self.config.udp {
            return Err(DispatchError::NotAllowed);
        }
        let session = StreamSession {
            metadata: request.session.metadata.clone(),
            inbound: request.session.inbound,
            source: request.session.source,
            destination: self.connection.server.clone(),
            sniffed_domain: None,
        };
        let engine = self.engine(session, context).await?;
        Ok(Box::new(datagram::Datagrams::new(
            engine,
            request.budget(),
            context.resolution(),
        )?))
    }
    fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.retired.close();
        self.pool.begin_shutdown();
        self.h2_pool.begin_shutdown();
        if let Some(remote) = self.remote.get() {
            remote.begin_shutdown();
        }
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        if let Some(remote) = self.remote.get() {
            remote.shutdown().await;
        }
        self.retired.wait().await;
        let mut current = self.current.lock().await;
        if let Some(engine) = current.as_ref() {
            engine.stop().await;
        }
        current.take();
        self.pool.shutdown().await;
        self.h2_pool.shutdown().await;
    }
}
impl Drop for MasqueOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.pool.begin_shutdown();
        self.h2_pool.begin_shutdown();
        if let Some(remote) = self.remote.get() {
            remote.begin_shutdown();
        }
    }
}

#[cfg(all(test, feature = "inbound-http"))]
mod http_reuse_memory_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{Duration, Instant};

    #[derive(Default)]
    struct PendingUpstream {
        entered: tokio::sync::Notify,
        calls: AtomicUsize,
        deadline: Mutex<Option<Instant>>,
        datagram_requests: Mutex<Vec<(DatagramBudget, Option<usize>)>>,
        reject_stream: bool,
    }
    #[async_trait]
    impl OutboundConnector for PendingUpstream {
        async fn connect_stream(
            &self,
            _session: StreamSession,
            context: &EstablishContext,
        ) -> Result<ConnectedStream, DispatchError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            *self.deadline.lock().unwrap() = Some(context.deadline());
            self.entered.notify_one();
            if self.reject_stream {
                return Err(DispatchError::NotAllowed);
            }
            std::future::pending().await
        }
        async fn open_datagram(
            &self,
            request: DatagramRequest,
            _context: &EstablishContext,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.datagram_requests.lock().unwrap().push((
                request.budget(),
                request.udp_socket_options().receive_buffer,
            ));
            Err(DispatchError::NotAllowed)
        }
    }
    fn outbound(seconds: i64, upstream: Arc<PendingUpstream>) -> MasqueOutbound {
        outbound_network(seconds, upstream, MasqueNetwork::H2)
    }
    fn outbound_network(
        seconds: i64,
        upstream: Arc<PendingUpstream>,
        network: MasqueNetwork,
    ) -> MasqueOutbound {
        use base64::Engine;
        let group =
            boring::ec::EcGroup::from_curve_name(boring::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = boring::ec::EcKey::generate(&group).unwrap();
        let public = boring::pkey::PKey::from_ec_key(key.clone()).unwrap();
        let mut config = (*ip::tests::test_config()).clone();
        config.private_key =
            base64::engine::general_purpose::STANDARD.encode(key.private_key_to_der().unwrap());
        config.public_key =
            base64::engine::general_purpose::STANDARD.encode(public.public_key_to_der().unwrap());
        config.handshake_timeout = seconds;
        config.network = network;
        MasqueOutbound::with_shared_security(
            &config,
            UpstreamPath::proxy(upstream),
            &SecurityContext::default(),
        )
        .unwrap()
    }
    fn session() -> StreamSession {
        StreamSession {
            inbound: crate::session::InboundKind::Socks5,
            source: "192.0.2.1:1000".parse().unwrap(),
            destination: Destination::Ip("192.0.2.10:443".parse().unwrap()),
            sniffed_domain: None,
            metadata: Default::default(),
        }
    }
    #[tokio::test]
    async fn masque_memory_physical_receive_hint_is_ip_only_on_real_upstream_request() {
        for (network, hint) in [
            (MasqueNetwork::Quic, Some(512 * 1024)),
            (MasqueNetwork::H3L4Proxy, None),
            (MasqueNetwork::H2, None),
        ] {
            let upstream = Arc::new(PendingUpstream {
                reject_stream: true,
                ..Default::default()
            });
            let mut outbound = outbound_network(0, upstream.clone(), network);
            let factory = Arc::get_mut(&mut outbound.connection).unwrap();
            // Keep endpoint resolution pure memory; the mock rejects acquisition.
            factory.server = Destination::Ip("192.0.2.10:443".parse().unwrap());
            let context = EstablishContext::default();
            let rejected = if network == MasqueNetwork::H2 {
                factory.connect_h2(session(), &context).await.is_err()
            } else {
                factory.connect(session(), &context).await.is_err()
            };
            assert!(rejected);
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
            if network == MasqueNetwork::H2 {
                assert!(upstream.datagram_requests.lock().unwrap().is_empty());
            } else {
                assert_eq!(
                    *upstream.datagram_requests.lock().unwrap(),
                    vec![(DatagramBudget::new(1400, 1400), hint)]
                );
            }
            outbound.shutdown().await;
        }
    }
    #[tokio::test]
    async fn masque_memory_invalid_quic_tls_does_not_acquire_upstream() {
        let upstream = Arc::new(PendingUpstream::default());
        let mut outbound = outbound(0, upstream.clone());
        let factory = Arc::get_mut(&mut outbound.connection).unwrap();
        factory.server = Destination::Ip("192.0.2.10:443".parse().unwrap());
        // Config host validation permits this name, while the native TLS
        // policy rejects an all-numeric final DNS label.
        factory.server_name = "abc.123".into();
        assert!(
            factory
                .connect(session(), &EstablishContext::default())
                .await
                .is_err()
        );
        assert_eq!(upstream.calls.load(Ordering::Relaxed), 0);
        outbound.shutdown().await;
    }
    #[tokio::test(start_paused = true)]
    async fn masque_shared_creation_cancellation_has_one_owned_attempt() {
        for seconds in [0, 5] {
            let upstream = Arc::new(PendingUpstream::default());
            let outbound = outbound(seconds, upstream.clone());
            let context = EstablishContext::with_timeout(Duration::from_millis(10));
            let waiting = EstablishContext::with_timeout(Duration::from_secs(10));
            let mut creator = Box::pin(outbound.engine(session(), &context));
            assert!(futures_util::poll!(creator.as_mut()).is_pending());
            upstream.entered.notified().await;
            let engine = outbound.current.lock().await.as_ref().unwrap().clone();
            let mut waiter = Box::pin(outbound.engine(session(), &waiting));
            assert!(futures_util::poll!(waiter.as_mut()).is_pending());
            assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
            if seconds == 0 {
                drop(waiter);
                assert!(!engine.cancel.is_cancelled());
                drop(creator);
                assert!(engine.cancel.is_cancelled());
            } else {
                drop(creator);
                tokio::time::advance(Duration::from_millis(50)).await;
                assert!(!engine.cancel.is_cancelled());
                assert!(futures_util::poll!(waiter.as_mut()).is_pending());
                assert!(*upstream.deadline.lock().unwrap().as_ref().unwrap() > context.deadline());
                drop(waiter);
                tokio::time::advance(Duration::from_secs(5)).await;
                assert!(engine.wait_ready(&waiting).await.is_err());
                assert!(engine.cancel.is_cancelled());
            }
            outbound.shutdown().await;
            assert!(engine.cancel.is_cancelled());
            assert!(engine.job_is_joined().await);
            assert!(outbound.current.lock().await.is_none());
        }
    }
    #[cfg(target_os = "macos")]
    fn fixed_factory_memory_outbound(
        network: MasqueNetwork,
        upstream: UpstreamPath,
        peer: std::net::SocketAddr,
    ) -> MasqueOutbound {
        let mut outbound = outbound_network(0, Arc::new(PendingUpstream::default()), network);
        let factory = Arc::get_mut(&mut outbound.connection).unwrap();
        factory.server = Destination::Ip(peer);
        factory.upstream = upstream;
        outbound
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn masque_h3_fixed_factory_memory_l4_acquires_direct_and_lazy_fixed_peers() {
        use crate::{
            dialer::{Dialer, ResolvedEndpoint},
            session::Datagram,
        };
        use bytes::Bytes;
        use std::net::{SocketAddr, SocketAddrV6};

        let ipv6 = SocketAddr::V6(SocketAddrV6::new("fe80::10".parse().unwrap(), 443, 123, 7));
        for peer in ["192.0.2.10:443".parse().unwrap(), ipv6] {
            for prepared in [false, true] {
                let path = if prepared {
                    UpstreamPath::direct(
                        ResolvedEndpoint {
                            logical_host: peer.ip().to_string(),
                            port: peer.port(),
                            addresses: vec![peer],
                        },
                        Dialer::default(),
                    )
                } else {
                    UpstreamPath::LazyDirect {
                        dialer: Dialer::default(),
                    }
                };
                let outbound = fixed_factory_memory_outbound(MasqueNetwork::H3L4Proxy, path, peer);
                let mut acquired = outbound
                    .connection
                    .connect(session(), &EstablishContext::default())
                    .await
                    .unwrap();
                assert_eq!(acquired.peer, peer);
                assert_eq!(acquired.budget, DatagramBudget::new(1400, 1400));
                assert_eq!(
                    acquired.transport.payload_budget(&Destination::Ip(peer)),
                    DatagramBudget::new(1400, 1400)
                );
                // This observes the real returned transport before any send.
                // The old unconnected factory fails here without opening IO.
                assert!(
                    !acquired.transport.supports_shared_destinations(),
                    "H3 L4 must acquire one fixed physical peer"
                );
                let packet = |remote| Datagram {
                    remote: Destination::Ip(remote),
                    payload: Bytes::from_static(b"whole"),
                    sniffed_domain: None,
                };
                let mut other = peer;
                other.set_port(444);
                let mut rejected = vec![other];
                if let SocketAddr::V6(address) = peer {
                    let mut flow = address;
                    flow.set_flowinfo(address.flowinfo() + 1);
                    rejected.push(SocketAddr::V6(flow));
                    let mut scope = address;
                    scope.set_scope_id(address.scope_id() + 1);
                    rejected.push(SocketAddr::V6(scope));
                }
                for other in rejected {
                    assert!(matches!(
                        acquired.transport.send(packet(other)).await,
                        Err(DispatchError::NotAllowed)
                    ));
                    let returned = acquired.transport.send_owned(packet(other)).err().unwrap();
                    assert_eq!(returned.remote, Destination::Ip(other));
                    assert_eq!(returned.payload, Bytes::from_static(b"whole"));
                    let returned = acquired
                        .transport
                        .send_batch_owned(vec![packet(other), packet(other)])
                        .err()
                        .unwrap();
                    assert_eq!(returned.len(), 2);
                    assert!(returned.iter().all(|item| {
                        item.remote == Destination::Ip(other)
                            && item.payload == Bytes::from_static(b"whole")
                    }));
                }
                assert!(
                    acquired.transport.send_owned(packet(peer)).is_err(),
                    "factory acquisition must leave the exact peer unopened"
                );
                acquired.transport.close().await.unwrap();
                assert!(matches!(
                    acquired.transport.send(packet(peer)).await,
                    Err(DispatchError::NotAllowed)
                ));
                drop(acquired);
                outbound.shutdown().await;
                assert!(outbound.current.lock().await.is_none());
                assert!(outbound.remote.get().is_none());
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn masque_h3_fixed_factory_memory_preserves_ip_group_snapshot_and_proxy() {
        use crate::{
            dialer::Dialer,
            outbound::{SelectUpstream, SelectUpstreamMember},
            routing::GroupSelection,
        };

        let peer = "192.0.2.10:443".parse().unwrap();
        let ip = fixed_factory_memory_outbound(
            MasqueNetwork::Quic,
            UpstreamPath::LazyDirect {
                dialer: Dialer::default(),
            },
            peer,
        );
        let mut acquired = ip
            .connection
            .connect_ip(session(), &EstablishContext::default())
            .await
            .unwrap();
        assert_eq!(acquired.peer, peer);
        assert!(!acquired.transport.supports_shared_destinations());
        acquired.transport.close().await.unwrap();
        drop(acquired);
        ip.shutdown().await;

        let selection = Arc::new(GroupSelection::new(0));
        let group = fixed_factory_memory_outbound(
            MasqueNetwork::H3L4Proxy,
            UpstreamPath::Group {
                server: Destination::Ip(peer),
                group: Arc::new(SelectUpstream::new(
                    selection.clone(),
                    vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
                )),
                endpoint: None,
                dialer: Dialer::default(),
            },
            peer,
        );
        let context = EstablishContext::default();
        let mut first = group.connection.connect(session(), &context).await.unwrap();
        assert!(first.transport.supports_shared_destinations());
        selection.store(1, Ordering::Release);
        let mut pinned = group.connection.connect(session(), &context).await.unwrap();
        assert!(pinned.transport.supports_shared_destinations());
        assert!(
            group
                .connection
                .connect(session(), &EstablishContext::default())
                .await
                .is_err()
        );
        first.transport.close().await.unwrap();
        pinned.transport.close().await.unwrap();
        drop((first, pinned));
        group.shutdown().await;

        let upstream = Arc::new(PendingUpstream::default());
        let mut proxy = outbound_network(0, upstream.clone(), MasqueNetwork::H3L4Proxy);
        Arc::get_mut(&mut proxy.connection).unwrap().server = Destination::Ip(peer);
        assert!(
            proxy
                .connection
                .connect(session(), &EstablishContext::default())
                .await
                .is_err()
        );
        assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            *upstream.datagram_requests.lock().unwrap(),
            vec![(DatagramBudget::new(1400, 1400), None)]
        );
        proxy.shutdown().await;
    }

    #[test]
    fn masque_handshake_duration_wrap_is_expired_not_a_new_schema_rejection() {
        let context = EstablishContext::with_timeout(Duration::from_millis(1));
        assert!(context.masque_handshake(i64::MAX).deadline() <= Instant::now());
        assert!(context.masque_handshake(5).deadline() > context.deadline());
    }
}
