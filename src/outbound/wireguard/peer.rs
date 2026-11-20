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
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{NetStackError, Packet, PacketSink, parse_udp_packet_view};

// One already validated packet, never a second queue or a spawned task. Losing
// a select branch drops only the short await wrapper, not this admission future.
struct PendingIngress {
    admission: Pin<Box<dyn Future<Output = Result<(), NetStackError>> + Send>>,
    #[cfg(test)]
    disposition: PendingDisposition,
    #[cfg(test)]
    probe: Option<Arc<Mutex<PendingMemoryCounts>>>,
}
impl PendingIngress {
    fn new(
        sink: &PacketSink,
        packet: Packet,
        #[cfg(test)] probe: Option<Arc<Mutex<PendingMemoryCounts>>>,
    ) -> Self {
        let sink = sink.clone();
        #[cfg(test)]
        if let Some(probe) = &probe {
            let mut counts = probe.lock().unwrap();
            counts.created += 1;
            counts.current += 1;
            counts.peak = counts.peak.max(counts.current);
        }
        Self {
            admission: Box::pin(async move { sink.send(packet).await }),
            #[cfg(test)]
            disposition: PendingDisposition::Abandoned,
            #[cfg(test)]
            probe,
        }
    }
    async fn admit(&mut self) -> Result<(), NetStackError> {
        let result = self.admission.as_mut().await;
        #[cfg(test)]
        {
            self.disposition = if result.is_ok() {
                PendingDisposition::Admitted
            } else {
                PendingDisposition::Failed
            };
        }
        result
    }
}
struct PeerState {
    timer: tokio::time::Interval,
    established: bool,
    handshake_deadline: Instant,
    ingress: Option<PendingIngress>,
}
impl PeerState {
    fn new(handshake_deadline: Instant, ingress: Option<PendingIngress>) -> Self {
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Self {
            timer,
            established: false,
            handshake_deadline,
            ingress,
        }
    }
    fn discard_for_timer(&mut self) {
        if let Some(pending) = self.ingress.take() {
            #[cfg(test)]
            let pending = {
                let mut pending = pending;
                pending.disposition = PendingDisposition::Timer;
                pending
            };
            drop(pending);
        }
    }
    fn discard_for_refresh(&mut self) {
        if let Some(pending) = self.ingress.take() {
            #[cfg(test)]
            let pending = {
                let mut pending = pending;
                pending.disposition = PendingDisposition::Refresh;
                pending
            };
            drop(pending);
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum PendingDisposition {
    Admitted,
    Failed,
    Timer,
    Refresh,
    Abandoned,
}
#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct PendingMemoryCounts {
    created: usize,
    current: usize,
    peak: usize,
    admitted: usize,
    failed: usize,
    timer: usize,
    refresh: usize,
    abandoned: usize,
}
#[cfg(test)]
impl Drop for PendingIngress {
    fn drop(&mut self) {
        if let Some(probe) = &self.probe {
            let mut counts = probe.lock().unwrap();
            counts.current -= 1;
            match self.disposition {
                PendingDisposition::Admitted => counts.admitted += 1,
                PendingDisposition::Failed => counts.failed += 1,
                PendingDisposition::Timer => counts.timer += 1,
                PendingDisposition::Refresh => counts.refresh += 1,
                PendingDisposition::Abandoned => counts.abandoned += 1,
            }
        }
    }
}

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
    #[cfg(test)]
    pending_probe: Option<Arc<Mutex<PendingMemoryCounts>>>,
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
        let request = DatagramRequest::new(self.session.clone())
            .with_budget(DatagramBudget::new(size, size))
            .with_udp_receive_buffer_size(512 * 1024);
        #[cfg(target_os = "macos")]
        let mut transport = path
            .open_fixed_peer_datagram(request, endpoint, context)
            .await?;
        #[cfg(not(target_os = "macos"))]
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
    fn network_datagram(&self, packet: &[u8], endpoint: SocketAddr) -> Datagram {
        let mut wire = packet.to_vec();
        wire[1..4].copy_from_slice(&self.peer().reserved);
        Datagram {
            remote: Destination::Ip(endpoint),
            payload: Bytes::from(wire),
            sniffed_domain: None,
        }
    }
    #[cfg(target_os = "macos")]
    async fn send_network_batch(
        &self,
        mut packets: Vec<Datagram>,
        transport: &mut dyn DatagramTransport,
        deadline: Instant,
    ) -> Result<(), DispatchError> {
        if packets.len() >= 2 {
            // Keep the original ciphertext FIFO until a positive physical
            // completion confirms its prefix. Clone only Bytes handles.
            if let Ok(operation) = transport.send_batch_owned(packets.clone()) {
                let accepted = tokio::select! {biased;
                    () = self.cancel.cancelled() => return Err(DispatchError::ConnectionRefused),
                    result = tokio::time::timeout_at(deadline, operation) => {
                        result.map_err(|_| DispatchError::TimedOut)?.map_err(DispatchError::from)?
                    }
                };
                if accepted == 0 || accepted > packets.len() {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into());
                }
                drop(packets.drain(..accepted));
            }
        }
        // Unsupported admission performs no IO. A short success sends only
        // its untouched suffix here; an IO error above is never replayed.
        for datagram in packets {
            tokio::select! {biased;
                () = self.cancel.cancelled() => return Err(DispatchError::ConnectionRefused),
                result = tokio::time::timeout_at(deadline, transport.send(datagram)) => {
                    result.map_err(|_| DispatchError::TimedOut)??;
                }
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    #[allow(clippy::too_many_arguments)]
    async fn send_ready_data_batch(
        &self,
        first: Datagram,
        tunn: &mut Tunn,
        endpoint: SocketAddr,
        transport: &mut dyn DatagramTransport,
        deadline: Instant,
        pending: &mut Option<PendingIngress>,
        packets: &mut mpsc::Receiver<Packet>,
        scratch: &mut [u8],
    ) -> Result<(), DispatchError> {
        let mut batch = Vec::with_capacity(crate::dispatch::DATAGRAM_SEND_BATCH_LIMIT);
        batch.push(first);
        while batch.len() < crate::dispatch::DATAGRAM_SEND_BATCH_LIMIT {
            if self.cancel.is_cancelled() {
                return Err(DispatchError::ConnectionRefused);
            }
            let Ok(packet) = packets.try_recv() else {
                break;
            };
            match tunn.encapsulate(packet.data(), scratch) {
                TunnResult::WriteToNetwork(wire) if wire.first() == Some(&4) => {
                    batch.push(self.network_datagram(wire, endpoint));
                }
                other => {
                    // Rekey/control, Done and errors keep their original
                    // handling after every preceding data ciphertext is sent.
                    // Never re-encapsulate a dequeued packet or wait to fill.
                    self.send_network_batch(batch, transport, deadline).await?;
                    return self
                        .handle(other, endpoint, transport, deadline, pending)
                        .await;
                }
            }
        }
        self.send_network_batch(batch, transport, deadline).await
    }
    async fn handle(
        &self,
        result: TunnResult<'_>,
        endpoint: SocketAddr,
        transport: &mut dyn DatagramTransport,
        deadline: Instant,
        pending: &mut Option<PendingIngress>,
    ) -> Result<(), DispatchError> {
        match result {
            TunnResult::Done => Ok(()),
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                Err(DispatchError::ConnectionRefused)
            }
            TunnResult::Err(_) => Ok(()),
            TunnResult::WriteToNetwork(packet) => {
                let datagram = self.network_datagram(packet, endpoint);
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
                    // No second plaintext allocation while one packet is owned.
                    if pending.is_none() {
                        let packet = Packet::new(Bytes::copy_from_slice(packet));
                        if let Err((NetStackError::Backpressure, packet)) =
                            self.sink.try_send_recover(packet)
                        {
                            // Active sinks can accept more than the send MTU;
                            // only a bounded in-MTU Full packet is retained.
                            if packet.len() <= usize::from(self.config.mtu) {
                                *pending = Some(PendingIngress::new(
                                    &self.sink,
                                    packet,
                                    #[cfg(test)]
                                    self.pending_probe.clone(),
                                ));
                            }
                        }
                    }
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
        #[cfg(test)]
        pending_probe: None,
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
        let mut ingress = None;
        let first = tunn.format_handshake_initiation(&mut scratch, true);
        if driver
            .handle(
                first,
                endpoint,
                transport.as_mut(),
                context.deadline(),
                &mut ingress,
            )
            .await
            .is_ok()
        {
            let _ = run_peer(
                &driver,
                &mut tunn,
                endpoint,
                &mut transport,
                PeerState::new(context.deadline(), ingress),
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
async fn handle_peer_datagram(
    driver: &Driver,
    tunn: &mut Tunn,
    endpoint: SocketAddr,
    transport: &mut Box<dyn DatagramTransport>,
    state: &mut PeerState,
    deadline: Instant,
    scratch: &mut [u8],
    network: &mut [u8],
    datagram: Datagram,
) -> Result<(), DispatchError> {
    #[cfg(target_os = "macos")]
    if driver.cancel.is_cancelled() {
        return Err(DispatchError::ConnectionRefused);
    }
    let len = datagram.payload.len();
    if datagram.remote != Destination::Ip(endpoint) || !(4..=network.len()).contains(&len) {
        return Ok(());
    }
    // Standard packets already have zero reserved bytes. BoringTun
    // borrows its input and returns only scratch-backed output.
    let input: &[u8] = if datagram.payload[1..4] == [0, 0, 0] {
        datagram.payload.as_ref()
    } else {
        // Preserve compatibility with a peer's nonzero reserved
        // bytes using the same existing normalization buffer.
        network[..len].copy_from_slice(&datagram.payload);
        network[1..4].fill(0);
        &network[..len]
    };
    let result = tunn.decapsulate(Some(endpoint.ip()), input, scratch);
    let authenticated = matches!(input[0], 1 | 2)
        && matches!(result, TunnResult::WriteToNetwork(_))
        && tunn.time_since_last_handshake().is_some();
    driver
        .handle(
            result,
            endpoint,
            transport.as_mut(),
            deadline,
            &mut state.ingress,
        )
        .await?;
    loop {
        let result = tunn.decapsulate(None, &[], scratch);
        if matches!(result, TunnResult::Done) {
            break;
        }
        driver
            .handle(
                result,
                endpoint,
                transport.as_mut(),
                deadline,
                &mut state.ingress,
            )
            .await?;
    }
    if !state.established && authenticated {
        state.established = true;
        driver.ready.send_replace(Ready::Established);
        tracing::debug!("WireGuard handshake ready");
    }

    Ok(())
}

#[cfg(target_os = "macos")]
async fn poll_ready_datagram(
    transport: &mut Box<dyn DatagramTransport>,
) -> std::task::Poll<Result<Datagram, DispatchError>> {
    // Exactly one poll with the caller's real Context. Pending drops only the
    // cancellation-safe receive wrapper, then returns to the original select.
    let mut receive = std::pin::pin!(transport.receive());
    std::future::poll_fn(|context| std::task::Poll::Ready(receive.as_mut().poll(context))).await
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
async fn drain_ready_datagrams(
    driver: &Driver,
    tunn: &mut Tunn,
    endpoint: SocketAddr,
    transport: &mut Box<dyn DatagramTransport>,
    state: &mut PeerState,
    deadline: Instant,
    scratch: &mut [u8],
    network: &mut [u8],
) -> Result<(), DispatchError> {
    // The selected packet was already processed. Every complete extra outer
    // datagram, including invalid input and keepalives, consumes one of three.
    for _ in 0..3 {
        if driver.cancel.is_cancelled() {
            return Err(DispatchError::ConnectionRefused);
        }
        if !state.established || state.ingress.is_some() {
            break;
        }
        let std::task::Poll::Ready(datagram) = poll_ready_datagram(transport).await else {
            break;
        };
        handle_peer_datagram(
            driver, tunn, endpoint, transport, state, deadline, scratch, network, datagram?,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_peer(
    driver: &Driver,
    tunn: &mut Tunn,
    mut endpoint: SocketAddr,
    transport: &mut Box<dyn DatagramTransport>,
    mut state: PeerState,
    packets: &mut mpsc::Receiver<Packet>,
    commands: &mut mpsc::Receiver<Refresh>,
    scratch: &mut [u8],
    network: &mut [u8],
) -> Result<(), DispatchError> {
    enum Event {
        Datagram(Result<Datagram, DispatchError>),
        Packet(Option<Packet>),
        Command(Option<Refresh>),
        Ingress(Result<(), NetStackError>),
        Timer,
    }
    loop {
        let deadline = if state.established {
            Instant::now() + DEFAULT_ESTABLISH_TIMEOUT
        } else {
            state.handshake_deadline
        };
        // Cancellation and the original handshake deadline stay ahead of all
        // work. Ready network input must not starve output, refresh or timers.
        let has_pending = state.ingress.is_some();
        let event = tokio::select! {biased;
            ()=driver.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),
            ()=tokio::time::sleep_until(state.handshake_deadline),if !state.established=>return Err(DispatchError::TimedOut),
            event=async {
                tokio::select! {
                    datagram=async { transport.receive().await },if !has_pending=>Event::Datagram(datagram),
                    result=async { state.ingress.as_mut().expect("pending ingress branch").admit().await },if has_pending=>Event::Ingress(result),
                    packet=packets.recv(),if state.established=>Event::Packet(packet),
                    command=commands.recv(),if state.established=>Event::Command(command),
                    _=state.timer.tick()=>Event::Timer,
                }
            }=>event,
        };
        match event {
            Event::Datagram(datagram) => {
                #[cfg(target_os = "macos")]
                let was_established = state.established;
                handle_peer_datagram(
                    driver, tunn, endpoint, transport, &mut state, deadline, scratch, network,
                    datagram?,
                )
                .await?;
                #[cfg(target_os = "macos")]
                if was_established {
                    drain_ready_datagrams(
                        driver, tunn, endpoint, transport, &mut state, deadline, scratch, network,
                    )
                    .await?;
                }
            }
            Event::Packet(packet) => {
                let packet = packet.ok_or(DispatchError::ConnectionRefused)?;
                let result = tunn.encapsulate(packet.data(), scratch);
                #[cfg(target_os = "macos")]
                let result = match result {
                    TunnResult::WriteToNetwork(wire)
                        if state.established
                            && usize::from(driver.config.mtu) + 32
                                <= crate::dispatch::DATAGRAM_SEND_BATCH_BYTES
                                    / crate::dispatch::DATAGRAM_SEND_BATCH_LIMIT
                            && wire.first() == Some(&4) =>
                    {
                        // Only the existing ready FIFO is drained, at most
                        // four MTU-bounded ciphertexts and 8 KiB. RX/control
                        // selection and every original deadline stay outside.
                        let first = driver.network_datagram(wire, endpoint);
                        driver
                            .send_ready_data_batch(
                                first,
                                tunn,
                                endpoint,
                                transport.as_mut(),
                                deadline,
                                &mut state.ingress,
                                packets,
                                scratch,
                            )
                            .await?;
                        continue;
                    }
                    other => other,
                };
                driver
                    .handle(
                        result,
                        endpoint,
                        transport.as_mut(),
                        deadline,
                        &mut state.ingress,
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
                        state.discard_for_refresh();
                        let mut old = std::mem::replace(transport, new);
                        endpoint = next;
                        state.established = false;
                        state.handshake_deadline = command.context.deadline();
                        driver.ready.send_replace(Ready::Waiting);
                        let _ = tokio::time::timeout(Duration::from_secs(1), old.close()).await;
                        driver
                            .handle(
                                tunn.format_handshake_initiation(scratch, true),
                                endpoint,
                                transport.as_mut(),
                                state.handshake_deadline,
                                &mut state.ingress,
                            )
                            .await?;
                    }
                }
                // DNS/setup failure retains the old endpoint and is retried by
                // a later business call, as in reference updateServerAddr.
                let _ = command.reply.send(());
            }
            Event::Ingress(result) => {
                // A completed admission owns the only commit; errors keep the
                // previous local-drop semantics. The persistent waiter ends here.
                let _ = result;
                state.ingress = None;
            }
            Event::Timer => {
                // Bound RX suspension by a selected existing timer, not a new
                // timer or a wall-time promise. Resume control/UDP RX on fallback.
                state.discard_for_timer();
                driver
                    .handle(
                        tunn.update_timers(scratch),
                        endpoint,
                        transport.as_mut(),
                        deadline,
                        &mut state.ingress,
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

#[cfg(test)]
#[path = "pending_ingress_memory_tests.rs"]
mod pending_ingress_memory_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "connected_factory_memory_tests.rs"]
mod connected_factory_memory_tests;
