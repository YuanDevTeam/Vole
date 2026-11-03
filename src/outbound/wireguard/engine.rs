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
                tcp_send_buffer: 64 * 1024,
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
        let pending = {
            let current = slots[index].current.lock().unwrap();
            let Some(channel) = current.as_ref().filter(|c| c.is_ready()) else {
                continue;
            };
            match channel.tx.try_send(packet) {
                Err(tokio::sync::mpsc::error::TrySendError::Full(packet)) => {
                    Some((channel.clone(), packet))
                }
                _ => None,
            }
        };
        if let Some((channel, packet)) = pending {
            // Keep only this Full packet and its original peer generation.
            // One peer can wait for space; multiple peers get one cooperative
            // handoff so a full peer cannot block a sibling.
            let offer = async {
                let send = channel.tx.send(packet);
                if slots.len() == 1 {
                    let _ = send.await;
                    return;
                }
                tokio::pin!(send);
                if futures_util::poll!(send.as_mut()).is_ready() {
                    return;
                }
                tokio::task::yield_now().await;
                let _ = futures_util::poll!(send.as_mut());
            };
            tokio::select! { biased;
                () = cancel.cancelled() => break,
                () = channel.cancel.cancelled() => {},
                () = offer => {},
            }
        }
    }
    cancel.cancel();
}

#[cfg(test)]
mod full_handoff_memory_tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::task::noop_waker;
    use std::{
        future::Future,
        net::SocketAddr,
        task::{Context, Poll, Wake, Waker},
        time::Duration,
    };
    use tokio::sync::Notify;
    use vole_netstack::Packet;

    #[derive(Default)]
    struct PumpWake(Notify);
    impl Wake for PumpWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.notify_one();
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Case {
        Release,
        StillFull,
        PeerStop,
        GlobalStop,
    }

    fn is_syn(packet: &Packet, destination: SocketAddr) -> bool {
        let bytes = packet.data();
        if bytes.len() < 40 || bytes[0] >> 4 != 4 || bytes[9] != 6 {
            return false;
        }
        let offset = usize::from(bytes[0] & 15) * 4;
        offset >= 20
            && bytes.len() >= offset + 20
            && peer::addresses(bytes).is_some_and(|(_, dst)| dst == destination.ip())
            && u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) == destination.port()
            && bytes[offset + 13] & 0x17 == 2
    }

    async fn exercise(case: Case, single_peer: bool) -> usize {
        let first: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let other: SocketAddr = "10.1.0.1:443".parse().unwrap();
        let mut config = super::super::tests::config();
        config.routes = vec![
            (
                crate::config::IpCidr {
                    network: first.ip(),
                    prefix_len: 32,
                },
                0,
            ),
            (
                crate::config::IpCidr {
                    network: other.ip(),
                    prefix_len: 32,
                },
                1,
            ),
        ];
        if single_peer {
            config.routes.truncate(1);
        }
        let routes = Arc::new(Routes::new(&config));
        assert_eq!(routes.select(first.ip()), Some(0));
        assert_eq!(routes.select(other.ip()), (!single_peer).then_some(1));
        let cancel = CancellationToken::new();
        let (a, mut a_rx) = Channel::memory_ready(cancel.child_token());
        let (b, mut b_rx) = Channel::memory_ready(cancel.child_token());
        let slots: Arc<[PeerSlot]> = if single_peer {
            vec![PeerSlot::default()].into()
        } else {
            vec![PeerSlot::default(), PeerSlot::default()].into()
        };
        *slots[0].current.lock().unwrap() = Some(a.clone());
        if !single_peer {
            *slots[1].current.lock().unwrap() = Some(b.clone());
        }
        let filler = Packet::new(Bytes::from_static(b"existing-queued-packet"));
        for _ in 0..32 {
            a.tx.try_send(filler.clone()).unwrap();
        }
        assert!(a.is_ready() && b.is_ready());
        assert_eq!(
            a.tx.capacity(),
            0,
            "fixture did not fill the actual 32-slot peer"
        );
        let ClientNetStackParts {
            packet_sink,
            packet_stream,
            tcp_connector,
            control,
            stats,
        } = NetStack::start_client(
            NetStackConfig {
                mtu: 1408,
                packet_queue: 32,
                ..Default::default()
            },
            ClientAddresses {
                ipv4: config.ipv4,
                ipv6: None,
            },
        )
        .unwrap();
        let wake = Arc::new(PumpWake::default());
        let waker = Waker::from(wake.clone());
        let mut cx = Context::from_waker(&waker);
        let caller = noop_waker();
        let mut caller_cx = Context::from_waker(&caller);
        let mut pump = Box::pin(pump_output(
            packet_stream,
            slots.clone(),
            routes,
            cancel.clone(),
        ));
        assert!(
            pump.as_mut().poll(&mut cx).is_pending(),
            "fixture empty pump ended"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut connect = Box::pin(tcp_connector.connect(first, deadline));
        let mut connect_other = Box::pin(tcp_connector.connect(other, deadline));
        assert!(
            connect.as_mut().poll(&mut caller_cx).is_pending(),
            "fixture TCP connect did not pend"
        );
        tokio::time::timeout(Duration::from_secs(2), wake.0.notified())
            .await
            .expect("fixture never emitted the first SYN into PacketStream");

        // Current-thread runtime: no await from the packet-ready barrier through
        // the captured result. The netstack cannot run again to retransmit here.
        let single_socket = stats.snapshot().active_tcp == 1;
        let first_pending = pump.as_mut().poll(&mut cx).is_pending();
        // Keep the actual queue Full across more polls than the multi-peer
        // cooperative offer permits. No await can let TCP retransmit the SYN.
        let retained_pending =
            !single_peer || (0..3).all(|_| pump.as_mut().poll(&mut cx).is_pending());
        let slot_unlocked = slots[0].current.try_lock().is_ok();
        let release_slot = case != Case::StillFull && (!single_peer || case == Case::Release);
        if release_slot {
            assert_eq!(a_rx.try_recv().unwrap(), filler);
        }
        if case == Case::PeerStop {
            a.cancel.cancel();
        }
        if case == Case::GlobalStop {
            cancel.cancel();
        }
        let after = if first_pending {
            pump.as_mut().poll(&mut cx)
        } else {
            Poll::Ready(())
        };
        let already_joined = after.is_ready();
        let continuing = case == Case::GlobalStop || after.is_pending();
        let global_joined = case != Case::GlobalStop || already_joined;
        let mut seen = Vec::new();
        while let Ok(packet) = a_rx.try_recv() {
            seen.push(packet);
        }
        let admitted = seen.iter().filter(|packet| is_syn(packet, first)).count();
        let fifo = seen.iter().take_while(|packet| **packet == filler).count()
            == if release_slot { 31 } else { 32 };
        let exact_packets = seen
            .iter()
            .all(|packet| *packet == filler || is_syn(packet, first));
        // Do not free a Full peer and accidentally admit A while testing B.
        if case == Case::StillFull && !single_peer {
            for packet in seen.iter().cloned() {
                a.tx.try_send(packet).unwrap();
            }
        }
        let mut other_progress = true;
        if !single_peer && matches!(case, Case::StillFull | Case::PeerStop) {
            // Re-arm PacketStream with a fresh waker after A's offer ended;
            // an old deferred yield wake cannot impersonate B's output barrier.
            let sibling_wake = Arc::new(PumpWake::default());
            let sibling_waker = Waker::from(sibling_wake.clone());
            let mut sibling_cx = Context::from_waker(&sibling_waker);
            assert!(
                pump.as_mut().poll(&mut sibling_cx).is_pending(),
                "fixture sibling re-arm ended pump"
            );
            assert!(
                connect_other.as_mut().poll(&mut caller_cx).is_pending(),
                "fixture sibling connect did not pend"
            );
            tokio::time::timeout(Duration::from_secs(2), sibling_wake.0.notified())
                .await
                .expect("fixture never emitted the sibling SYN");
            for _ in 0..4 {
                let _ = pump.as_mut().poll(&mut sibling_cx);
            }
            let mut sibling = Vec::new();
            while let Ok(packet) = b_rx.try_recv() {
                sibling.push(packet);
            }
            other_progress = sibling.iter().any(|packet| is_syn(packet, other));
        }
        cancel.cancel();
        let joined = already_joined || pump.as_mut().poll(&mut cx).is_ready();
        drop((pump, connect, connect_other));
        a.stop().await;
        b.stop().await;
        control.stop().await;
        let sockets_released = stats.snapshot().active_tcp == 0;
        drop((a_rx, b_rx, slots, a, b, tcp_connector, packet_sink));
        assert!(
            joined && global_joined && sockets_released,
            "fixture did not join/release: {case:?}"
        );
        assert!(
            single_socket
                && first_pending
                && retained_pending
                && continuing
                && slot_unlocked
                && fifo
                && exact_packets,
            "fixture/lock/FIFO boundary failed: {case:?}"
        );
        assert!(
            other_progress,
            "still-full/stopped peer blocked a sibling: {case:?}"
        );
        if case != Case::Release {
            assert_eq!(
                admitted, 0,
                "full/cancelled peer unexpectedly admitted A: {case:?}"
            );
        }
        admitted
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_packet_gets_one_cooperative_handoff_without_blocking_stop_or_sibling() {
        let admitted = exercise(Case::Release, false).await;
        for case in [Case::StillFull, Case::PeerStop, Case::GlobalStop] {
            exercise(case, false).await;
        }
        assert_eq!(
            admitted, 1,
            "a ready WireGuard peer must retain its Full SYN for one cooperative handoff when one slot opens"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn single_peer_full_packet_waits_for_space_without_blocking_cancel_or_release() {
        let admitted = exercise(Case::Release, true).await;
        for case in [Case::StillFull, Case::PeerStop, Case::GlobalStop] {
            exercise(case, true).await;
        }
        assert_eq!(
            admitted, 1,
            "a single WireGuard peer must retain the original Full SYN until a slot opens"
        );
    }
}
