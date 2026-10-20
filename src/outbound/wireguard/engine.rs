use super::{channel::Channel, datagram::Registry, peer, routes::Routes};
use crate::{
    config::WireGuardOutboundConfig,
    dispatch::DispatchError,
    dns::resolution::ResolutionContext,
    outbound::{EstablishContext, UpstreamPath},
    resources::observation,
    session::DatagramSession,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, OnceLock},
};
use tokio::{sync::Mutex as AsyncMutex, task::JoinHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use vole_netstack::{
    ClientAddresses, ClientNetStackParts, NetStack, NetStackConfig, NetStackControl, PacketSink,
    PacketStream, TcpConnector,
};
#[derive(Default)]
struct PeerSlot {
    gate: AsyncMutex<()>,
    current: Mutex<Option<Arc<Channel>>>,
}
pub(super) struct Engine {
    pub security: crate::security::SecurityContext,
    pub cancel: CancellationToken,
    pub tcp: TcpConnector,
    pub registry: Arc<Registry>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: usize,
    pub resolution: ResolutionContext,
    pub remote: OnceLock<Arc<crate::dns::runtime::RuntimeDns>>,
    pub config: Arc<WireGuardOutboundConfig>,
    routes: Arc<Routes>,
    upstream: UpstreamPath,
    slots: Arc<[PeerSlot]>,
    sink: PacketSink,
    control: NetStackControl,
    router: Mutex<Option<JoinHandle<()>>>,
    retired: TaskTracker,
    admission: Mutex<()>,
    stop: AsyncMutex<()>,
}
impl Engine {
    pub fn start(
        config: Arc<WireGuardOutboundConfig>,
        upstream: UpstreamPath,
        context: EstablishContext,
        cancel: CancellationToken,
        security: crate::security::SecurityContext,
    ) -> Result<Arc<Self>, DispatchError> {
        let ClientNetStackParts {
            packet_sink,
            packet_stream,
            tcp_connector,
            control,
            ..
        } = NetStack::start_client(
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
        .map_err(|_| DispatchError::Other("WireGuard stack initialization failed".into()))?;
        let routes = Arc::new(Routes::new(&config));
        let slots: Arc<[PeerSlot]> = (0..config.peers.len())
            .map(|_| PeerSlot::default())
            .collect();
        let engine = Arc::new(Self {
            security,
            cancel: cancel.clone(),
            tcp: tcp_connector,
            registry: Arc::new(Registry::default()),
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            mtu: usize::from(config.mtu),
            resolution: context.resolution(),
            remote: OnceLock::new(),
            config,
            routes: routes.clone(),
            upstream,
            slots: slots.clone(),
            sink: packet_sink,
            control,
            router: Mutex::new(None),
            retired: TaskTracker::new(),
            admission: Mutex::new(()),
            stop: AsyncMutex::new(()),
        });
        *engine.router.lock().unwrap() = Some(observation::spawn(pump_output(
            packet_stream,
            slots,
            routes,
            cancel,
        )));
        Ok(engine)
    }
    pub fn local(&self, ip: IpAddr) -> Result<IpAddr, DispatchError> {
        match ip {
            IpAddr::V4(_) => self.ipv4.map(IpAddr::V4),
            IpAddr::V6(_) => self.ipv6.map(IpAddr::V6),
        }
        .ok_or(DispatchError::HostUnreachable)
    }
    pub async fn peer(
        &self,
        ip: IpAddr,
        session: DatagramSession,
        context: &EstablishContext,
    ) -> Result<Arc<Channel>, DispatchError> {
        self.local(ip)?;
        let index = self
            .routes
            .select(ip)
            .ok_or(DispatchError::HostUnreachable)?;
        let slot = &self.slots[index];
        let channel = tokio::select! {biased;()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),result=context.run("WireGuard peer initialize",async{
            let _gate=slot.gate.lock().await;let mut current=slot.current.lock().unwrap();
            if let Some(channel)=current.as_ref().filter(|c|!c.cancel.is_cancelled()){return Ok(channel.clone());}
            let _admission=self.admission.lock().unwrap();if self.cancel.is_cancelled(){return Err(DispatchError::NotAllowed);}
            if let Some(old)=current.take(){self.retired.spawn(observation::task(async move{old.stop().await;}));}
            let channel=Channel::start(self.config.clone(),index,self.upstream.clone(),session,context.clone(),self.cancel.child_token(),self.sink.clone(),self.registry.clone(),self.routes.clone());
            *current=Some(channel.clone());Ok(channel)
        })=>result?};
        channel.wait_ready(context).await?;
        self.refresh_active(context).await;
        channel.wait_ready(context).await?;
        Ok(channel)
    }
    async fn refresh_active(&self, context: &EstablishContext) {
        let interval = self.config.refresh_server_ip_interval;
        if interval == 0 {
            return;
        }
        // A business call can refresh every live peer, including one whose
        // route has not recently carried traffic. Unused peers stay lazy.
        let channels = self
            .slots
            .iter()
            .filter_map(|slot| {
                slot.current
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|channel| channel.is_ready())
                    .cloned()
            })
            .collect::<Vec<_>>();
        futures_util::future::join_all(
            channels
                .iter()
                .map(|channel| channel.refresh_if_due(interval, context)),
        )
        .await;
    }

    pub async fn stop(&self) {
        let _stop = self.stop.lock().await;
        {
            let _admission = self.admission.lock().unwrap();
            self.cancel.cancel();
            self.retired.close();
        }
        if let Some(remote) = self.remote.get() {
            remote.shutdown().await;
        }
        let channels = self
            .slots
            .iter()
            .filter_map(|slot| slot.current.lock().unwrap().take())
            .collect::<Vec<_>>();
        for channel in channels {
            channel.stop().await;
        }
        self.retired.wait().await;
        let router = self.router.lock().unwrap().take();
        if let Some(router) = router {
            let _ = router.await;
        }
        self.control.stop().await;
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(remote) = self.remote.get() {
            remote.begin_shutdown();
        }
        self.cancel.cancel();
        self.control.cancel();
        if let Some(router) = self.router.get_mut().unwrap().take() {
            router.abort();
        }
    }
}
async fn pump_output(
    mut packets: PacketStream,
    slots: Arc<[PeerSlot]>,
    routes: Arc<Routes>,
    cancel: CancellationToken,
) {
    loop {
        let packet = tokio::select! {biased;()=cancel.cancelled()=>break,packet=packets.recv()=>match packet{Some(p)=>p,None=>break}};
        let Some((_, dst)) = peer::addresses(packet.data()) else {
            continue;
        };
        let Some(index) = routes.select(dst) else {
            continue;
        };
        if let Some(channel) = slots[index]
            .current
            .lock()
            .unwrap()
            .as_ref()
            .filter(|c| c.is_ready())
        {
            let _ = channel.tx.try_send(packet);
        }
    }
    cancel.cancel();
}
