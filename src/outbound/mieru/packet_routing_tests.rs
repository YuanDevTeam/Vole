//! Real Mieru packet receivers selected by the managed router; memory IO only.
use super::{
    MieruOutbound,
    tests::{Peer, config, session},
};
use crate::{
    config::{Config, MieruHandshake},
    connections::Registry,
    dispatch::{
        BoxStream, DatagramBudget, DatagramTransport, DispatchError, Dispatcher,
        observe_sessions_with_stats,
    },
    outbound::{ConnectorDispatcher, OutboundConnector, UpstreamPath},
    resources::{RuntimeResourceStats, observation::ResourceProbe},
    routing::{
        EmptyGeoMatcher, ProxyDispatchers, RoutingDispatcher, RuleSet, diagnostics::Diagnostics,
    },
    session::{Datagram, DatagramSession, Destination, StreamSession},
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::task::ArcWake;
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

const STEP: Duration = Duration::from_secs(2);
type DispatchFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, DispatchError>> + Send + 'a>>;

#[derive(Default)]
struct Counts {
    async_created: AtomicUsize,
    async_polls: AtomicUsize,
    receiver_polls: AtomicUsize,
    pending_polls: AtomicUsize,
    closes: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
struct CountSnapshot {
    async_created: usize,
    async_polls: usize,
    receiver_polls: usize,
    pending_polls: usize,
    closes: usize,
}

impl Counts {
    fn snapshot(&self) -> CountSnapshot {
        CountSnapshot {
            async_created: self.async_created.load(Ordering::Relaxed),
            async_polls: self.async_polls.load(Ordering::Relaxed),
            receiver_polls: self.receiver_polls.load(Ordering::Relaxed),
            pending_polls: self.pending_polls.load(Ordering::Relaxed),
            closes: self.closes.load(Ordering::Relaxed),
        }
    }
}

fn snapshots(counts: &Mutex<Vec<Arc<Counts>>>) -> Vec<CountSnapshot> {
    counts
        .lock()
        .unwrap()
        .iter()
        .map(|entry| entry.snapshot())
        .collect()
}

struct CountedReceive<'a> {
    inner: DispatchFuture<'a, Datagram>,
    counts: Arc<Counts>,
}

impl Future for CountedReceive<'_> {
    type Output = Result<Datagram, DispatchError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.counts.async_polls.fetch_add(1, Ordering::Relaxed);
        this.inner.as_mut().poll(cx)
    }
}

struct CountedTransport {
    inner: Box<dyn DatagramTransport>,
    counts: Arc<Counts>,
}

// Spell out the async_trait ABI so creation is counted before the returned
// receive future is first polled. Every operation delegates to the real IO.
impl DatagramTransport for CountedTransport {
    fn supports_poll_receive(&self) -> bool {
        self.inner.supports_poll_receive()
    }

    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        scratch: &mut Vec<u8>,
    ) -> Poll<Result<Datagram, DispatchError>> {
        self.counts.receiver_polls.fetch_add(1, Ordering::Relaxed);
        let result = self.inner.poll_receive(cx, scratch);
        if result.is_pending() {
            self.counts.pending_polls.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn payload_budget(&self, remote: &Destination) -> DatagramBudget {
        self.inner.payload_budget(remote)
    }

    fn send<'life0, 'async_trait>(
        &'life0 mut self,
        datagram: Datagram,
    ) -> DispatchFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.send(datagram)
    }

    fn receive<'life0, 'async_trait>(&'life0 mut self) -> DispatchFuture<'async_trait, Datagram>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.counts.async_created.fetch_add(1, Ordering::Relaxed);
        Box::pin(CountedReceive {
            inner: self.inner.receive(),
            counts: self.counts.clone(),
        })
    }

    fn close<'life0, 'async_trait>(&'life0 mut self) -> DispatchFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let closing = self.inner.close();
        let counts = self.counts.clone();
        Box::pin(async move {
            closing.await?;
            counts.closes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

struct CountedDispatcher {
    inner: Arc<dyn Dispatcher>,
    counts: Arc<Mutex<Vec<Arc<Counts>>>>,
}

#[async_trait]
impl Dispatcher for CountedDispatcher {
    fn supports_udp(&self) -> bool {
        self.inner.supports_udp()
    }

    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.inner.connect_tcp(session).await
    }

    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let inner = self.inner.open_datagram(session).await?;
        let counts = Arc::new(Counts::default());
        self.counts.lock().unwrap().push(counts.clone());
        Ok(Box::new(CountedTransport { inner, counts }))
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl ArcWake for WakeCount {
    fn wake_by_ref(owner: &Arc<Self>) {
        owner.0.fetch_add(1, Ordering::Relaxed);
    }
}

async fn bounded<T>(future: impl Future<Output = Result<T, DispatchError>>) -> Result<T, String> {
    tokio::time::timeout(STEP, future)
        .await
        .map_err(|_| "memory IO timed out".to_owned())?
        .map_err(|error| error.to_string())
}

async fn echo(
    transport: &mut dyn DatagramTransport,
    remote: SocketAddr,
    body: &'static [u8],
) -> Result<(), String> {
    bounded(transport.send(Datagram {
        remote: Destination::Ip(remote),
        payload: Bytes::from_static(body),
        sniffed_domain: None,
    }))
    .await?;
    let response = bounded(transport.receive()).await?;
    if response.remote != Destination::Ip(remote) || response.payload.as_ref() != body {
        return Err("Mieru routed datagram payload or source differs".into());
    }
    Ok(())
}

struct Evidence {
    prime_pending: bool,
    before_hot: Vec<CountSnapshot>,
    after_hot: Vec<CountSnapshot>,
    controller_pending: bool,
    controller_wakes: usize,
    remaining_after_cancel: usize,
}

#[tokio::test]
async fn mieru_udp_routing_poll_visits_only_ready_targets_and_preserves_cancelled_siblings() {
    let probe = ResourceProbe::default();
    let (business, closed, joined, peer_joined, final_counts, remaining, udp_current) = probe.scope(async {
        let parsed = Config::parse_yaml(br#"
proxies: [{name: edge, type: mieru, server: memory.invalid, port: 2000, username: vole, password: fixture-password, transport: TCP, udp: true, multiplexing: MULTIPLEXING_HIGH}]
rules: ["MATCH,edge"]
"#).unwrap();
        let peer = Peer::new(false);
        let node = Arc::new(MieruOutbound::new(
            &config(MieruHandshake::Standard), UpstreamPath::proxy(peer.clone()), 1024,
        ).unwrap());
        let counts = Arc::new(Mutex::new(Vec::new()));
        let counted: Arc<dyn Dispatcher> = Arc::new(CountedDispatcher {
            inner: Arc::new(ConnectorDispatcher::new(node.clone())),
            counts: counts.clone(),
        });
        let stats = RuntimeResourceStats::new("mieru_packet_router");
        let leaf = observe_sessions_with_stats(counted, stats.clone());
        // An accidental DIRECT route cannot open UDP through the memory Peer.
        let direct: Arc<dyn Dispatcher> = Arc::new(ConnectorDispatcher::new(peer.clone()));
        let rules = RuleSet::compile(parsed.rules.clone()).unwrap();
        let registry = Arc::new(Registry::default());
        let diagnostics = Arc::new(Diagnostics::new(&parsed, &rules, registry.clone()));
        let router = RoutingDispatcher::new(
            ProxyDispatchers::new(vec![leaf.clone()]).unwrap(), direct, None, rules, Arc::new(EmptyGeoMatcher),
        ).with_diagnostics(diagnostics);
        let mut association = None;
        let business = tokio::time::timeout(Duration::from_secs(10), async {
            association = Some(bounded(router.open_datagram(DatagramSession::for_tun(
                session().source, 1500,
            ))).await?);
            let transport = association.as_mut().unwrap();
            let targets: [SocketAddr; 3] = [
                "198.51.100.1:11000".parse().unwrap(),
                "198.51.100.1:11001".parse().unwrap(),
                "198.51.100.1:11002".parse().unwrap(),
            ];
            for remote in targets {
                echo(transport.as_mut(), remote, b"prime").await?;
            }
            // Consume each ready requeue and register the actual empty receivers.
            let prime_pending = {
                let mut receive = transport.receive();
                futures_util::poll!(receive.as_mut()).is_pending()
            };
            let before_hot = snapshots(&counts);
            echo(transport.as_mut(), targets[0], b"hot").await?;
            let after_hot = snapshots(&counts);

            let snapshot = serde_json::to_value(registry.snapshot()).map_err(|error| error.to_string())?;
            let cold_port = targets[1].port().to_string();
            let id = snapshot["connections"].as_array().ok_or("connections missing")?
                .iter().find(|entry| entry["metadata"]["destinationPort"].as_str() == Some(cold_port.as_str()))
                .and_then(|entry| entry["id"].as_str()).ok_or("cold connection missing")?.to_owned();
            let cold = counts.lock().unwrap().get(1).cloned().ok_or("cold receiver missing")?;
            let wakes = Arc::new(WakeCount::default());
            let mut waiting = transport.receive();
            let controller_pending = {
                let waker = futures_util::task::waker(wakes.clone());
                waiting.as_mut().poll(&mut Context::from_waker(&waker)).is_pending()
            };
            registry.close(&id);
            let controller_wakes = wakes.0.load(Ordering::Relaxed);
            // Keep this receive alive while its cancellation path joins the
            // actual reader. Drop only after close has completed and it is idle.
            bounded(poll_fn(|cx| {
                match waiting.as_mut().poll(cx) {
                    Poll::Ready(_) => Poll::Ready(Err(DispatchError::Other("unexpected receive during cancellation".into()))),
                    Poll::Pending if cold.closes.load(Ordering::Relaxed) == 1 => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                }
            })).await?;
            drop(waiting);
            let snapshot = serde_json::to_value(registry.snapshot()).map_err(|error| error.to_string())?;
            let remaining_after_cancel = snapshot["connections"].as_array().ok_or("connections missing")?.len();
            echo(transport.as_mut(), targets[0], b"sibling-after-cancel").await?;
            Ok::<_, String>(Evidence {
                prime_pending, before_hot, after_hot, controller_pending,
                controller_wakes, remaining_after_cancel,
            })
        }).await.map_err(|_| "routed memory scenario timed out".to_owned()).and_then(|result| result);

        // Complete every owner before asserting counters, including the old RED.
        let closed = if let Some(mut transport) = association.take() {
            let result = bounded(transport.close()).await;
            drop(transport);
            result
        } else {
            Err("association was not opened".into())
        };
        let joined = tokio::time::timeout(STEP, node.shutdown()).await.is_ok();
        let peer_joined = tokio::time::timeout(STEP, peer.stop()).await.is_ok();
        drop((router, leaf, node, peer));
        let remaining = serde_json::to_value(registry.snapshot()).unwrap()["connections"].as_array().unwrap().len();
        (business, closed, joined, peer_joined, snapshots(&counts), remaining, stats.snapshot().udp_current)
    }).await;

    assert!(probe.snapshot().is_idle());
    assert!(closed.is_ok(), "association close: {closed:?}");
    assert!(joined && peer_joined, "Mieru or memory peer did not join");
    assert_eq!(remaining, 0);
    assert_eq!(udp_current, 0);
    let evidence = business.unwrap();
    assert!(evidence.prime_pending && evidence.controller_pending);
    assert!(
        evidence.controller_wakes > 0,
        "Controller close did not wake the pending router"
    );
    assert_eq!(evidence.remaining_after_cancel, 2);
    assert_eq!(evidence.before_hot.len(), 3);
    assert_eq!(evidence.after_hot.len(), 3);
    assert_eq!(final_counts.len(), 3);
    for (index, counts) in final_counts.iter().enumerate() {
        assert_eq!(
            counts.async_created, 0,
            "receiver {index} used asynchronous fanout: {counts:?}"
        );
        assert_eq!(
            counts.async_polls, 0,
            "receiver {index} polled asynchronous receive"
        );
        assert_eq!(
            counts.closes, 1,
            "receiver {index} did not close exactly once"
        );
        assert!(
            evidence.before_hot[index].pending_polls > 0,
            "receiver {index} was never primed to Pending"
        );
        if index == 0 {
            assert!(
                evidence.after_hot[index].receiver_polls
                    > evidence.before_hot[index].receiver_polls
            );
        } else {
            assert_eq!(
                evidence.after_hot[index].receiver_polls, evidence.before_hot[index].receiver_polls,
                "idle receiver {index} was polled for its hot sibling"
            );
        }
    }
}
