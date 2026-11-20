//! Interoperability-only access to the unchanged private association entry.
//! The caller polls and closes the real future; no relay or mock transport runs here.
use super::*;
use std::{future::Future, pin::Pin};

pub struct InteropTunRoutingRegistry {
    registry: Arc<crate::connections::Registry>,
}

impl InteropTunRoutingRegistry {
    pub fn close(self) -> bool {
        let empty = serde_json::to_value(self.registry.snapshot())
            .ok()
            .and_then(|value| value["connections"].as_array().map(Vec::is_empty))
            .unwrap_or(false);
        self.registry.shutdown();
        empty
    }
}

pub fn interop_tracked_tun_router(
    router: crate::routing::RoutingDispatcher,
    config: &crate::config::Config,
    rules: &crate::routing::RuleSet,
) -> (crate::routing::RoutingDispatcher, InteropTunRoutingRegistry) {
    let registry = Arc::new(crate::connections::Registry::default());
    let diagnostics = Arc::new(crate::routing::diagnostics::Diagnostics::new(
        config,
        rules,
        registry.clone(),
    ));
    (
        router.with_diagnostics(diagnostics),
        InteropTunRoutingRegistry { registry },
    )
}

pub type InteropTunUdpTask = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

pub struct InteropTunUdpReplies {
    inner: mpsc::Receiver<QueuedUdpResponse>,
}

impl InteropTunUdpReplies {
    pub async fn receive(&mut self) -> Option<UdpDatagram> {
        self.inner.recv().await.map(|response| response.datagram)
    }
}

pub fn interop_tun_udp_association(
    dispatcher: Arc<dyn Dispatcher>,
    source: SocketAddr,
) -> (
    mpsc::Sender<UdpDatagram>,
    InteropTunUdpReplies,
    CancellationToken,
    InteropTunUdpTask,
) {
    let stats = RuntimeResourceStats::new("interop_tun_udp_association");
    let dispatcher = crate::dispatch::observe_sessions_with_stats(dispatcher, stats.clone());
    let activity = stats.begin(ResourceActivity::UdpAssociation);
    // A one-entry input exposes consumption through the sender's existing capacity API.
    let (input, inbound) = mpsc::channel(1);
    let (responses, replies) = mpsc::channel(1);
    let cancellation = CancellationToken::new();
    let context = UdpAssociationTaskContext {
        association_id: 1,
        source,
        responses,
        dispatcher,
        resource_stats: stats,
        association_clock: AssociationClock::realtime(),
        last_activity: Arc::new(AtomicU64::new(0)),
        tun_mtu: 1_500,
        udp_timeout: Duration::from_secs(30),
        sniffer: None,
        cancellation: cancellation.clone(),
    };
    let task = Box::pin(observation::task(async move {
        run_udp_association(inbound, activity, context).await.2
    }));
    (
        input,
        InteropTunUdpReplies { inner: replies },
        cancellation,
        task,
    )
}
