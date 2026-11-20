//! Actual WG endpoint/transport acquisition; no host socket or Noise worker.
use super::*;
use crate::{
    dialer::{Dialer, ResolvedEndpoint},
    outbound::{ConnectedStream, OutboundConnector, SelectUpstream, SelectUpstreamMember},
    resources::observation::ResourceProbe,
    routing::GroupSelection,
    session::{InboundKind, StreamSession},
};
use std::sync::atomic::Ordering;
use vole_netstack::{ClientAddresses, ClientNetStackParts, NetStack, NetStackConfig};

fn factory(peer: SocketAddr, upstream: UpstreamPath) -> (Driver, ClientNetStackParts) {
    let mut config = super::super::tests::config();
    config.address = peer.ip().to_string();
    config.port = peer.port();
    config.peers[0].address = config.address.clone();
    config.peers[0].port = peer.port();
    let config = Arc::new(config);
    let stack = NetStack::start_client(
        NetStackConfig {
            mtu: usize::from(config.mtu),
            packet_queue: 32,
            ..Default::default()
        },
        ClientAddresses {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
        },
    )
    .unwrap();
    let (ready, _) = watch::channel(Ready::Waiting);
    let driver = Driver {
        routes: Arc::new(Routes::new(&config)),
        config,
        index: 0,
        upstream,
        session: DatagramSession::new(InboundKind::Tun, "192.0.2.1:20000".parse().unwrap()),
        cancel: CancellationToken::new(),
        ready,
        sink: stack.packet_sink.clone(),
        registry: Arc::new(Registry::default()),
        updated: Arc::new(Mutex::new(Instant::now())),
        pending_probe: None,
    };
    (driver, stack)
}

async fn stop_factory(driver: Driver, stack: ClientNetStackParts) -> bool {
    driver.cancel.cancel();
    drop(driver);
    tokio::time::timeout(Duration::from_secs(1), stack.control.stop())
        .await
        .expect("factory's real netstack must join");
    let stopped = stack.control.is_stopped();
    drop(stack);
    stopped
}

#[tokio::test(flavor = "current_thread")]
async fn wireguard_connected_factory_memory_direct_and_lazy_pin_actual_endpoint() {
    let probe = ResourceProbe::default();
    let observations = probe
        .scope(async {
            let mut observations = Vec::new();
            for peer in [
                "198.51.100.1:51820".parse::<SocketAddr>().unwrap(),
                "[2001:db8::10]:51820".parse::<SocketAddr>().unwrap(),
            ] {
                for prepared in [false, true] {
                    let upstream = if prepared {
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
                    let (driver, stack) = factory(peer, upstream);
                    let context = EstablishContext::default();
                    let (endpoint, path) = driver.endpoint(&context, false).await.unwrap();
                    let mut transport = driver.transport(endpoint, &path, &context).await.unwrap();
                    let actual_peer = endpoint == peer;
                    let budget = transport.payload_budget(&Destination::Ip(endpoint));
                    let size = driver.config.mtu + 32;
                    let exclusive = !transport.supports_shared_destinations();
                    let mut guards = true;
                    // Only the fixed branch can reject without socket acquisition.
                    // Old source records its real capability, then closes/joins
                    // every owner before the final semantic RED assertion.
                    if exclusive {
                        let packet = |remote| Datagram {
                            remote: Destination::Ip(remote),
                            payload: Bytes::from_static(b"whole"),
                            sniffed_domain: None,
                        };
                        let mut other = endpoint;
                        other.set_port(other.port() + 1);
                        let mut rejected = vec![other];
                        if let SocketAddr::V6(address) = endpoint {
                            let mut flow = address;
                            flow.set_flowinfo(address.flowinfo() + 1);
                            rejected.push(SocketAddr::V6(flow));
                            let mut scope = address;
                            scope.set_scope_id(address.scope_id() + 1);
                            rejected.push(SocketAddr::V6(scope));
                        }
                        for other in rejected {
                            guards &= matches!(
                                transport.send(packet(other)).await,
                                Err(DispatchError::NotAllowed)
                            );
                            let returned = transport.send_owned(packet(other)).err();
                            guards &= returned.is_some_and(|item| {
                                item.remote == Destination::Ip(other)
                                    && item.payload == Bytes::from_static(b"whole")
                            });
                            let returned = transport
                                .send_batch_owned(vec![packet(other), packet(other)])
                                .err();
                            guards &= returned.is_some_and(|items| {
                                items.len() == 2
                                    && items.iter().all(|item| {
                                        item.remote == Destination::Ip(other)
                                            && item.payload == Bytes::from_static(b"whole")
                                    })
                            });
                        }
                        guards &= transport.send_owned(packet(endpoint)).is_err();
                    }
                    let closed = transport.close().await.is_ok();
                    let after_close = transport
                        .send(Datagram {
                            remote: Destination::Ip(endpoint),
                            payload: Bytes::from_static(b"after-close"),
                            sniffed_domain: None,
                        })
                        .await
                        .is_err();
                    drop(transport);
                    let stopped = stop_factory(driver, stack).await;
                    observations.push((
                        actual_peer,
                        budget == DatagramBudget::new(size, size),
                        exclusive,
                        guards,
                        closed && after_close && stopped,
                    ));
                }
            }
            observations
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert_eq!(observations.len(), 4);
    for (peer, budget, exclusive, guards, closed) in observations {
        assert!(
            peer && budget && closed,
            "actual WG factory and owner controls"
        );
        assert!(
            exclusive,
            "WireGuard factory must acquire one fixed physical peer"
        );
        assert!(
            guards,
            "actual fixed transport must reject every wrong peer before IO"
        );
    }
}

#[derive(Default)]
struct RejectProxy {
    requests: Mutex<Vec<(DatagramBudget, Option<usize>)>>,
}
#[async_trait::async_trait]
impl OutboundConnector for RejectProxy {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.requests.lock().unwrap().push((
            request.budget(),
            request.udp_socket_options().receive_buffer,
        ));
        Err(DispatchError::NotAllowed)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wireguard_connected_factory_memory_groups_and_proxies_keep_original_scope() {
    let probe = ResourceProbe::default();
    let observed = probe
        .scope(async {
            let peer = "198.51.100.1:51820".parse().unwrap();
            let selection = Arc::new(GroupSelection::new(0));
            let upstream = UpstreamPath::Group {
                server: Destination::Ip(peer),
                group: Arc::new(SelectUpstream::new(
                    selection.clone(),
                    vec![SelectUpstreamMember::Direct, SelectUpstreamMember::Reject],
                )),
                endpoint: None,
                dialer: Dialer::default(),
            };
            let (driver, stack) = factory(peer, upstream);
            let context = EstablishContext::default();
            let (endpoint, path) = driver.endpoint(&context, false).await.unwrap();
            let mut first = driver.transport(endpoint, &path, &context).await.unwrap();
            let ordinary = first.supports_shared_destinations();
            selection.store(1, Ordering::Release);
            let (same_endpoint, path) = driver.endpoint(&context, true).await.unwrap();
            let mut pinned = driver
                .transport(same_endpoint, &path, &context)
                .await
                .unwrap();
            let pinned_original =
                same_endpoint == endpoint && pinned.supports_shared_destinations();
            let rejects_new_context = driver
                .endpoint(&EstablishContext::default(), true)
                .await
                .is_err();
            let closes = first.close().await.is_ok() && pinned.close().await.is_ok();
            drop((first, pinned));
            let group_stopped = stop_factory(driver, stack).await;

            let proxy = Arc::new(RejectProxy::default());
            let (driver, stack) = factory(peer, UpstreamPath::proxy(proxy.clone()));
            let (endpoint, path) = driver.endpoint(&context, false).await.unwrap();
            let refused = matches!(
                driver.transport(endpoint, &path, &context).await,
                Err(DispatchError::NotAllowed)
            );
            let requests = proxy.requests.lock().unwrap().clone();
            let proxy_stopped = stop_factory(driver, stack).await;
            (
                ordinary && pinned_original && rejects_new_context,
                closes && group_stopped && proxy_stopped,
                refused,
                requests,
            )
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(observed.0 && observed.1 && observed.2);
    assert_eq!(
        observed.3,
        [(DatagramBudget::new(1440, 1440), Some(512 * 1024))]
    );
}
