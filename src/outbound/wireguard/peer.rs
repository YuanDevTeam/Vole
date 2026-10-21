use super::{
    channel::{Ready, Refresh},
    datagram::{Registry, local_destination},
    routes::Routes,
};
use crate::{
    config::{WireGuardOutboundConfig, WireGuardPeerConfig},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        DEFAULT_ESTABLISH_TIMEOUT, DatagramRequest, EstablishContext, UpstreamPath,
        server_destination,
    },
    session::{Datagram, DatagramSession, Destination},
};
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519,
};
use bytes::Bytes;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{Packet, PacketSink, parse_udp_packet_view};
struct Driver {
    config: Arc<WireGuardOutboundConfig>,
    index: usize,
    upstream: UpstreamPath,
    session: DatagramSession,
    cancel: CancellationToken,
    ready: watch::Sender<Ready>,
    sink: PacketSink,
    registry: Arc<Registry>,
    routes: Arc<Routes>,
    updated: Arc<Mutex<Instant>>,
}
impl Driver {
    fn peer(&self) -> &WireGuardPeerConfig {
        &self.config.peers[self.index]
    }
    async fn endpoint(
        &self,
        context: &EstablishContext,
        refresh: bool,
    ) -> Result<(SocketAddr, UpstreamPath), DispatchError> {
        let server = server_destination(&self.peer().address, self.peer().port)
            .map_err(|_| DispatchError::HostUnreachable)?;
        let path = self.upstream.for_server(&server, refresh);
        let server = path.ip4p_datagram_server(&server, context).await?;
        let endpoint = context
            .resolution()
            .resolve_proxy(&server, context.deadline())
            .await?
            .addresses
            .into_iter()
            .next()
            .ok_or(DispatchError::HostUnreachable)?;
        Ok((endpoint, path))
    }
    async fn transport(
        &self,
        endpoint: SocketAddr,
        path: &UpstreamPath,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let size = self.config.mtu + 32;
        let request =
            DatagramRequest::new(self.session.clone()).with_budget(DatagramBudget::new(size, size));
        let mut transport = path.open_datagram(request, context).await?;
        let budget = transport.payload_budget(&Destination::Ip(endpoint));
        if budget.transmit() < size || budget.receive() < size {
            let _ = tokio::time::timeout(Duration::from_secs(1), transport.close()).await;
            return Err(DispatchError::Other(
                "WireGuard MTU exceeds upstream UDP budget".into(),
            ));
        }
        Ok(transport)
    }
    async fn handle(
        &self,
        result: TunnResult<'_>,
        endpoint: SocketAddr,
        transport: &mut dyn DatagramTransport,
        deadline: Instant,
    ) -> Result<(), DispatchError> {
        match result {
            TunnResult::Done => Ok(()),
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                Err(DispatchError::ConnectionRefused)
            }
            TunnResult::Err(_) => Ok(()),
            TunnResult::WriteToNetwork(packet) => {
                let mut wire = packet.to_vec();
                wire[1..4].copy_from_slice(&self.peer().reserved);
                let datagram = Datagram {
                    remote: Destination::Ip(endpoint),
                    payload: Bytes::from(wire),
                    sniffed_domain: None,
                };
                tokio::select! {biased;()=self.cancel.cancelled()=>Err(DispatchError::ConnectionRefused),result=tokio::time::timeout_at(deadline,transport.send(datagram))=>result.map_err(|_|DispatchError::TimedOut)?}
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                let Some((src, dst)) = addresses(packet) else {
                    return Ok(());
                };
                if !local_destination(&self.config, dst)
                    || src.is_ipv4() != dst.is_ipv4()
                    || self.routes.select(src) != Some(self.index)
                {
                    return Ok(());
                }
                if let Some(udp) = parse_udp_packet_view(packet) {
                    self.registry
                        .deliver(udp.source, udp.destination, udp.payload);
                } else {
                    let _ = self
                        .sink
                        .try_send(Packet::new(Bytes::copy_from_slice(packet)));
                }
                Ok(())
            }
        }
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn drive(
    config: Arc<WireGuardOutboundConfig>,
    index: usize,
    upstream: UpstreamPath,
    session: DatagramSession,
    context: EstablishContext,
    cancel: CancellationToken,
    mut packets: mpsc::Receiver<Packet>,
    mut commands: mpsc::Receiver<Refresh>,
    ready: watch::Sender<Ready>,
    sink: PacketSink,
    registry: Arc<Registry>,
    routes: Arc<Routes>,
    updated: Arc<Mutex<Instant>>,
) {
    let driver = Driver {
        config,
        index,
        upstream,
        session,
        cancel,
        ready,
        sink,
        registry,
        routes,
        updated,
    };
    let setup = async {
        let (endpoint, path) = driver.endpoint(&context, false).await?;
        Ok((endpoint, driver.transport(endpoint, &path, &context).await?))
    };
    let result = tokio::select! {biased;()=driver.cancel.cancelled()=>Err(DispatchError::NotAllowed),result=context.run("WireGuard outer UDP",setup)=>result};
    if let Ok((endpoint, mut transport)) = result {
        *driver.updated.lock().unwrap() = Instant::now();
        let mut tunn = Tunn::new(
            x25519::StaticSecret::from(driver.config.private_key.bytes()),
            x25519::PublicKey::from(driver.peer().public_key.bytes()),
            driver.peer().pre_shared_key.as_ref().map(|key| key.bytes()),
            Some(driver.config.persistent_keepalive),
            rand::random::<u32>() >> 8,
            None,
        );
        let size = usize::from(driver.config.mtu + 32).max(148);
        let mut scratch = vec![0; size];
        let mut network = vec![0; size];
        let first = tunn.format_handshake_initiation(&mut scratch, true);
        if driver
            .handle(first, endpoint, transport.as_mut(), context.deadline())
            .await
            .is_ok()
        {
            let _ = run_peer(
                &driver,
                &mut tunn,
                endpoint,
                &mut transport,
                &context,
                &mut packets,
                &mut commands,
                &mut scratch,
                &mut network,
            )
            .await;
        }
        driver.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), transport.close()).await;
    }
    driver.ready.send_replace(Ready::Failed);
    driver.cancel.cancel();
}
#[allow(clippy::too_many_arguments)]
async fn run_peer(
    driver: &Driver,
    tunn: &mut Tunn,
    mut endpoint: SocketAddr,
    transport: &mut Box<dyn DatagramTransport>,
    context: &EstablishContext,
    packets: &mut mpsc::Receiver<Packet>,
    commands: &mut mpsc::Receiver<Refresh>,
    scratch: &mut [u8],
    network: &mut [u8],
) -> Result<(), DispatchError> {
    enum Event {
        Datagram(Result<Datagram, DispatchError>),
        Packet(Option<Packet>),
        Command(Option<Refresh>),
        Timer,
    }
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut established = false;
    let mut handshake_deadline = context.deadline();
    loop {
        let deadline = if established {
            Instant::now() + DEFAULT_ESTABLISH_TIMEOUT
        } else {
            handshake_deadline
        };
        // Cancellation and the original handshake deadline stay ahead of all
        // work. Ready network input must not starve output, refresh or timers.
        let event = tokio::select! {biased;
            ()=driver.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),
            ()=tokio::time::sleep_until(handshake_deadline),if !established=>return Err(DispatchError::TimedOut),
            event=async {
                tokio::select! {
                    datagram=transport.receive()=>Event::Datagram(datagram),
                    packet=packets.recv(),if established=>Event::Packet(packet),
                    command=commands.recv(),if established=>Event::Command(command),
                    _=timer.tick()=>Event::Timer,
                }
            }=>event,
        };
        match event {
            Event::Datagram(datagram) => {
                let datagram = datagram?;
                let len = datagram.payload.len();
                if datagram.remote != Destination::Ip(endpoint)
                    || !(4..=network.len()).contains(&len)
                {
                    continue;
                }
                network[..len].copy_from_slice(&datagram.payload);
                network[1..4].fill(0);
                let result = tunn.decapsulate(Some(endpoint.ip()), &network[..len], scratch);
                let authenticated = matches!(network[0], 1 | 2)
                    && matches!(result, TunnResult::WriteToNetwork(_))
                    && tunn.time_since_last_handshake().is_some();
                driver
                    .handle(result, endpoint, transport.as_mut(), deadline)
                    .await?;
                loop {
                    let result = tunn.decapsulate(None, &[], scratch);
                    if matches!(result, TunnResult::Done) {
                        break;
                    }
                    driver
                        .handle(result, endpoint, transport.as_mut(), deadline)
                        .await?;
                }
                if !established && authenticated {
                    established = true;
                    driver.ready.send_replace(Ready::Established);
                    tracing::debug!("WireGuard handshake ready");
                }
            }
            Event::Packet(packet) => {
                let packet = packet.ok_or(DispatchError::ConnectionRefused)?;
                driver
                    .handle(
                        tunn.encapsulate(packet.data(), scratch),
                        endpoint,
                        transport.as_mut(),
                        deadline,
                    )
                    .await?;
            }
            Event::Command(command) => {
                let Some(command) = command else {
                    return Err(DispatchError::ConnectionRefused);
                };
                let refresh = async {
                    let (next, path) = driver.endpoint(&command.context, true).await?;
                    if next == endpoint {
                        return Ok(None);
                    }
                    Ok(Some((
                        next,
                        driver.transport(next, &path, &command.context).await?,
                    )))
                };
                let update = tokio::select! {biased;()=driver.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),result=command.context.run("WireGuard refresh",refresh)=>result};
                if let Ok(next) = update {
                    *driver.updated.lock().unwrap() = Instant::now();
                    if let Some((next, new)) = next {
                        let mut old = std::mem::replace(transport, new);
                        endpoint = next;
                        established = false;
                        handshake_deadline = command.context.deadline();
                        driver.ready.send_replace(Ready::Waiting);
                        let _ = tokio::time::timeout(Duration::from_secs(1), old.close()).await;
                        driver
                            .handle(
                                tunn.format_handshake_initiation(scratch, true),
                                endpoint,
                                transport.as_mut(),
                                handshake_deadline,
                            )
                            .await?;
                    }
                }
                // DNS/setup failure retains the old endpoint and is retried by
                // a later business call, as in reference updateServerAddr.
                let _ = command.reply.send(());
            }
            Event::Timer => {
                driver
                    .handle(
                        tunn.update_timers(scratch),
                        endpoint,
                        transport.as_mut(),
                        deadline,
                    )
                    .await?;
            }
        }
    }
}
pub(super) fn addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some((
            IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?),
            IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?),
        )),
        6 if packet.len() >= 40 => Some((
            IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?),
            IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?),
        )),
        _ => None,
    }
}
