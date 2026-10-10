use super::{datagram::Registry, peer};
use crate::{
    config::WireGuardOutboundConfig,
    dispatch::DispatchError,
    outbound::{EstablishContext, UpstreamPath},
    resources::observation,
    session::{DatagramSession, Destination},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{
    ClientAddresses, ClientNetStackParts, NetStack, NetStackConfig, NetStackControl, Packet,
    PacketStream, TcpConnector,
};

#[derive(Clone, Copy)]
pub(super) enum Ready {
    Waiting,
    Established,
    Failed,
}

pub(super) struct Engine {
    pub cancel: CancellationToken,
    pub tcp: TcpConnector,
    pub registry: Arc<Registry>,
    pub tx: mpsc::Sender<Packet>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: usize,
    ready: watch::Receiver<Ready>,
    control: NetStackControl,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    stop: AsyncMutex<()>,
}
impl Engine {
    pub fn start(
        config: Arc<WireGuardOutboundConfig>,
        server: Destination,
        upstream: UpstreamPath,
        session: DatagramSession,
        context: EstablishContext,
        cancel: CancellationToken,
    ) -> Result<Arc<Self>, DispatchError> {
        let addresses = ClientAddresses {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
        };
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
            addresses,
        )
        .map_err(|_| DispatchError::Other("WireGuard stack initialization failed".into()))?;
        let (tx, rx) = mpsc::channel(32);
        let (ready, state) = watch::channel(Ready::Waiting);
        let registry = Arc::new(Registry::default());
        let engine = Arc::new(Self {
            cancel: cancel.clone(),
            tcp: tcp_connector,
            registry: registry.clone(),
            tx: tx.clone(),
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            mtu: usize::from(config.mtu),
            ready: state,
            control,
            tasks: Mutex::new(Vec::new()),
            stop: AsyncMutex::new(()),
        });
        let router = observation::spawn(pump_output(packet_stream, tx, cancel.clone()));
        let peer = observation::spawn(peer::drive(
            config,
            server,
            upstream,
            session,
            context,
            cancel,
            rx,
            ready,
            packet_sink,
            registry,
        ));
        *engine.tasks.lock().unwrap() = vec![router, peer];
        Ok(engine)
    }
    pub fn local(&self, ip: IpAddr) -> Result<IpAddr, DispatchError> {
        match ip {
            IpAddr::V4(_) => self.ipv4.map(IpAddr::V4),
            IpAddr::V6(_) => self.ipv6.map(IpAddr::V6),
        }
        .ok_or(DispatchError::HostUnreachable)
    }
    pub async fn wait_ready(&self, context: &EstablishContext) -> Result<(), DispatchError> {
        let mut ready = self.ready.clone();
        context.run("WireGuard handshake",async {
            loop {
                match *ready.borrow_and_update() {Ready::Established=>return Ok(()),Ready::Failed=>return Err(DispatchError::ConnectionRefused),Ready::Waiting=>{}}
                tokio::select! {biased;()=self.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),result=ready.changed()=>if result.is_err(){return Err(DispatchError::ConnectionRefused);}}
            }
        }).await
    }
    pub async fn stop(&self) {
        let _stop = self.stop.lock().await;
        self.cancel.cancel();
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            let _ = task.await;
        }
        self.control.stop().await;
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.control.cancel();
        for task in self.tasks.get_mut().unwrap().drain(..) {
            task.abort();
        }
    }
}

async fn pump_output(
    mut packets: PacketStream,
    tx: mpsc::Sender<Packet>,
    cancel: CancellationToken,
) {
    loop {
        let packet = tokio::select! {biased;()=cancel.cancelled()=>break,packet=packets.recv()=>match packet {Some(packet)=>packet,None=>break}};
        // This single-peer route seam becomes longest-prefix peer selection in
        // the multi-peer extension. All flows share the same active stack.
        tokio::select! {biased;()=cancel.cancelled()=>break,result=tx.send(packet)=>if result.is_err(){break;}}
    }
    cancel.cancel();
}
