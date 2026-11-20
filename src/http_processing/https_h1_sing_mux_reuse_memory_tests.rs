//! Real sing-mux carrier plus the existing in-memory HTTPS/H1 origin.
use super::*;
use crate::{
    config::{SingMuxConfig, SingMuxProtocol},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, SingMuxConnector,
    },
    resources::observation::{ResourceKind, ResourceProbe},
};
use sha2::{Digest as _, Sha256};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

struct Carrier {
    origin: MemoryTls,
    proven: bool,
    physical: AtomicUsize,
    logical: Arc<AtomicUsize>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    relays: Arc<Mutex<Vec<JoinHandle<()>>>>,
    probe: ResourceProbe,
}
#[async_trait]
impl OutboundConnector for Carrier {
    fn permits_http_tcp_reuse(&self) -> bool {
        self.proven
    }

    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        self.physical.fetch_add(1, Ordering::SeqCst);
        let effective_peer = session.destination.clone();
        let (client, mut peer) = tokio::io::duplex(65536);
        let origin = self.origin.clone();
        let logical = self.logical.clone();
        let relays = self.relays.clone();
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            let mut prefix = [0; 2];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, [0, 1], "real sing-mux yamux bootstrap");
            let mut connection = yamux::Connection::new(
                peer.compat(),
                yamux::Config::default(),
                yamux::Mode::Server,
            );
            while let Some(next) = std::future::poll_fn(|cx| connection.poll_next_inbound(cx)).await
            {
                let stream = match next {
                    Ok(stream) => stream,
                    Err(_) => break, // Owned physical cancellation closes its streams.
                };
                logical.fetch_add(1, Ordering::SeqCst);
                let origin = origin.clone();
                let mut target_session = session.clone();
                relays.lock().unwrap().push(tokio::spawn(async move {
                    let mut stream = stream.compat();
                    // This fixed test target is IPv4; decode its real wire
                    // address with the production codec rather than inventing it.
                    let mut request = [0; 9];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request[..2], &[0, 0]);
                    let (target, consumed) = crate::socks5::decode_address(&request[2..]).unwrap();
                    assert_eq!(consumed, 7);
                    assert_eq!(target, Destination::Ip("203.0.113.1:443".parse().unwrap()));
                    target_session.destination = target;
                    target_session.sniffed_domain = Some("a.test".into());
                    stream.write_all(&[0]).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut tls_peer = origin.open(target_session).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tls_peer).await;
                }));
            }
            // The shared registry keeps relay handles through parent cancellation.
            drop(connection);
        }));
        Ok(ConnectedStream {
            io: Box::new(client),
            effective_peer,
        })
    }

    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }

    async fn shutdown(&self) {
        let mux_driver_finished = self.probe.snapshot().current(ResourceKind::Task) == 0;
        let owners = std::mem::take(&mut *self.tasks.lock().unwrap());
        let mut failures = Vec::new();
        for owner in owners {
            if let Err(error) = joined(owner).await {
                failures.push(error);
            }
        }
        let relays = std::mem::take(&mut *self.relays.lock().unwrap());
        for relay in relays {
            if let Err(error) = joined(relay).await {
                failures.push(error);
            }
        }
        let tls_peers = std::mem::take(&mut *self.origin.0.peers.lock().unwrap());
        for peer in tls_peers {
            if let Err(error) = joined(peer).await {
                failures.push(error);
            }
        }
        assert!(
            failures.is_empty(),
            "real mux peers did not join: {failures:?}"
        );
        assert!(
            mux_driver_finished,
            "inner shutdown preceded the actual mux driver"
        );
    }
}

struct RoutedMux {
    node: Arc<SingMuxConnector>,
    scope: Arc<()>,
    probe: ResourceProbe,
}
struct MuxPlan {
    node: Arc<SingMuxConnector>,
    session: StreamSession,
    key: Option<HttpTcpReuseKey>,
    probe: ResourceProbe,
}
#[async_trait]
impl HttpTcpPlan for MuxPlan {
    fn reuse_key(&self) -> Option<&HttpTcpReuseKey> {
        self.key.as_ref()
    }
    async fn connect(self: Box<Self>) -> Result<BoxStream, DispatchError> {
        let Self {
            node,
            session,
            probe,
            ..
        } = *self;
        probe
            .scope(node.connect_stream(session, &EstablishContext::default()))
            .await
            .map(|stream| stream.io)
    }
}
#[async_trait]
impl Dispatcher for RoutedMux {
    async fn prepare_http_tcp(
        &self,
        session: StreamSession,
    ) -> Result<Option<Box<dyn HttpTcpPlan>>, DispatchError> {
        let key = self.node.permits_http_tcp_reuse().then(|| {
            HttpTcpReuseKey::new(Identity {
                scope: self.scope.clone(),
                session: session.clone(),
            })
        });
        Ok(Some(Box::new(MuxPlan {
            node: self.node.clone(),
            session,
            key,
            probe: self.probe.clone(),
        })))
    }
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.node
            .connect_stream(session, &EstablishContext::default())
            .await
            .map(|stream| stream.io)
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[tokio::test]
async fn proven_sing_mux_keeps_one_real_logical_tls_stream_for_two_http_requests() {
    let probe = ResourceProbe::default();
    probe
        .scope(async {
            let mut fixture = fixture(Some(b"http/1.1"), Reply::Persistent, false, "");
            let carrier = Arc::new(Carrier {
                origin: fixture.origin.clone(),
                proven: true,
                physical: AtomicUsize::new(0),
                logical: Arc::new(AtomicUsize::new(0)),
                tasks: Mutex::new(Vec::new()),
                relays: Arc::new(Mutex::new(Vec::new())),
                probe: probe.clone(),
            });
            let node = Arc::new(SingMuxConnector::new(
                carrier.clone(),
                SingMuxConfig {
                    enabled: true,
                    protocol: SingMuxProtocol::Yamux,
                    max_connections: 1,
                    ..Default::default()
                },
            ));
            let route = Arc::new(RoutedMux {
                node: node.clone(),
                scope: fixture.origin.0.scope.clone(),
                probe: probe.clone(),
            });
            fixture.context.dispatcher = observe_sessions_with_stats(
                observe_handshakes_with_stats(route, fixture.stats.clone()),
                fixture.stats.clone(),
            );
            let mut running = start(&fixture);
            let first = request(&mut running, "a.test", "/one").await;
            let second = request(&mut running, "a.test", "/two").await;
            let hashes: Vec<_> = [&first, &second]
                .into_iter()
                .map(|response| {
                    response
                        .as_ref()
                        .ok()
                        .map(|(_, body)| Sha256::digest(body).to_vec())
                })
                .collect();
            let physical = carrier.physical.load(Ordering::SeqCst);
            let logical = carrier.logical.load(Ordering::SeqCst);
            let tls_opens = fixture.origin.count(&fixture.origin.0.opens);
            let tls_accepts = fixture.origin.count(&fixture.origin.0.accepts);
            let idle_live = fixture.origin.count(&fixture.origin.0.live);
            let idle_tcp = fixture.stats.snapshot().tcp_current;
            let idle_pool = probe.snapshot().current(ResourceKind::Pool);
            let idle_tasks = probe.snapshot().current(ResourceKind::Task);
            // Keep the downstream open: cancellation, rather than client EOF,
            // must destroy the retained TLS/logical lease before node Stop joins.
            running.cancellation.cancel();
            let serving = joined(running.serving).await;
            node.shutdown().await;
            let cancelled_proof = node.permits_http_tcp_reuse();
            let peers = std::mem::take(&mut *fixture.origin.0.peers.lock().unwrap());
            let mut failures = Vec::new();
            for peer in peers {
                if let Err(error) = joined(peer).await {
                    failures.push(error);
                }
            }
            drop(running.client);
            let heads = fixture.origin.0.heads.lock().unwrap().clone();
            let live = fixture.origin.count(&fixture.origin.0.live);
            let stats = fixture.stats.snapshot();
            let idle = probe.snapshot().is_idle();
            // A cancelled outer owner and an unproven inner owner must both deny
            // the capability. These controls create no additional wire owners.
            let denied = SingMuxConnector::new(
                Arc::new(Carrier {
                    origin: fixture.origin.clone(),
                    proven: false,
                    physical: AtomicUsize::new(0),
                    logical: Arc::new(AtomicUsize::new(0)),
                    tasks: Mutex::new(Vec::new()),
                    relays: Arc::new(Mutex::new(Vec::new())),
                    probe: probe.clone(),
                }),
                SingMuxConfig {
                    enabled: true,
                    ..Default::default()
                },
            );
            let inner_denied = !denied.permits_http_tcp_reuse();
            drop(denied);

            assert!(
                failures.is_empty(),
                "real TLS peers failed to join: {failures:?}"
            );
            serving.unwrap().unwrap();
            native_response(first, b"origin");
            native_response(second, b"origin");
            assert_eq!(hashes, vec![Some(Sha256::digest(b"origin").to_vec()); 2]);
            assert_eq!(heads.len(), 2);
            assert!(heads[0].starts_with("GET /one "));
            assert!(heads[1].starts_with("GET /two "));
            assert_eq!(physical, 1);
            assert_eq!(logical, 1, "HTTP reopened a real mux logical stream");
            assert_eq!((tls_opens, tls_accepts), (1, 1), "HTTP repeated origin TLS");
            assert_eq!((idle_live, idle_tcp, idle_pool, idle_tasks), (1, 1, 1, 1));
            assert!(!cancelled_proof && inner_denied);
            assert_eq!(live, 0);
            assert_eq!(stats.tcp_current, 0);
            assert_eq!(stats.handshake_current, 0);
            assert!(idle);
        })
        .await;
}
