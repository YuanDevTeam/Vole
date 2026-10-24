use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    io::AsyncWriteExt as _,
    sync::mpsc,
    task::JoinSet,
    time::{Instant as TokioInstant, MissedTickBehavior, interval_at, timeout},
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{
    NetStack, NetStackConfig, NetStackError, NetStackStats, Packet, PacketSink, PacketStream,
    TcpListener, TcpStream, UdpDatagram, UdpPacketView, encode_udp_packet_into,
    parse_udp_packet_view,
};

use crate::{
    ResourceLimits, VoleError,
    config::{SnifferConfig, TunConfig},
    dispatch::{DatagramTransport, DispatchError, Dispatcher},
    dns::{
        classify_query,
        runtime::{DnsQueryPermit, RuntimeDns},
    },
    platform::{TUN_PACKET_BATCH_SIZE, TunIo},
    quic_sniffer::QuicSniffer,
    resources::{
        ResourceActivity, ResourceActivityGuard, ResourceQueue, RuntimeResourceStats, observation,
    },
    session::{Datagram, DatagramSession, Destination, InboundKind, StreamSession},
    traffic::TunTrafficStats,
};

#[cfg(target_os = "linux")]
#[path = "tun_echo.rs"]
mod echo;
#[cfg(target_os = "linux")]
use echo::EchoIngress;
#[cfg(not(target_os = "linux"))]
struct EchoIngress;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EchoOffer {
    NotEcho,
    LocalSynthetic,
    Consumed,
}
#[cfg(not(target_os = "linux"))]
impl EchoIngress {
    fn offer(&self, _: &[u8]) -> EchoOffer {
        EchoOffer::NotEcho
    }
}
struct QueuedEchoResponse {
    packet: Packet,
    permit: tokio::sync::OwnedSemaphorePermit,
}
fn closed_echo_lane() -> mpsc::Receiver<QueuedEchoResponse> {
    let (sender, receiver) = mpsc::channel(1);
    drop(sender);
    receiver
}

#[cfg(test)]
use crate::dns::{ClassifiedDnsQuery, synthesize_servfail_response};
#[cfg(test)]
use crate::{
    quic_sniffer::{QuicSniffOutcome, quic_connection_key, quic_has_unsupported_version},
    tcp_sniffer::SniffProtocol,
};

#[cfg(test)]
const TUN_MTU: usize = 1_500;
const TCP_RELAY_BUFFER: usize = 4 * 1024;
const OUTBOUND_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
const UDP_IDLE_TIMEOUT_SECONDS: u64 = 30;
const UDP_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const UDP_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const TUN_NETSTACK_STATS_INTERVAL: Duration = Duration::from_secs(30);
const TUN_NETSTACK_STATS_PERIODIC_EVENT: &str = "tun_netstack_stats_periodic";
const TUN_NETSTACK_STATS_FINAL_EVENT: &str = "tun_netstack_stats_final";

static NEXT_DIAGNOSTIC_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn effective_tun_mtu(limits: ResourceLimits) -> usize {
    limits.tun_max_datagram_size
}

fn tun_netstack_config(limits: ResourceLimits, fake_icmp_echo: bool) -> NetStackConfig {
    NetStackConfig {
        mtu: effective_tun_mtu(limits),
        packet_queue: limits.packet_queue_capacity,
        tcp_accept_queue: limits.event_queue_capacity,
        tcp_recv_buffer: limits.tcp_buffer_per_direction,
        tcp_send_buffer: limits.tcp_buffer_per_direction,
        fake_icmp_echo,
        ..NetStackConfig::default()
    }
}

pub(crate) struct TunRuntime {
    tun: Arc<TunIo>,
    limits: ResourceLimits,
    config: TunConfig,
    dispatcher: Arc<dyn Dispatcher>,
    dns: Option<Arc<RuntimeDns>>,
    resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
    ipv6: bool,
    fake_icmp_echo: bool,
    sniffer: Option<Arc<SnifferConfig>>,
    traffic_stats: Arc<TunTrafficStats>,
    #[cfg(target_os = "linux")]
    echo_options: Option<echo::EchoOptions>,
}

impl TunRuntime {
    #[cfg(all(test, unix))]
    pub(crate) fn new(
        tun: TunIo,
        limits: ResourceLimits,
        dispatcher: Arc<dyn Dispatcher>,
        dns: Option<Arc<RuntimeDns>>,
        ipv6: bool,
        fake_icmp_echo: bool,
        sniffer: Option<Arc<SnifferConfig>>,
    ) -> io::Result<Self> {
        Self::new_with_stats(
            tun,
            limits,
            &TunConfig {
                mtu: u16::try_from(limits.tun_max_datagram_size)
                    .map_err(|_| io::ErrorKind::InvalidInput)?,
                udp_timeout: Duration::from_secs(UDP_IDLE_TIMEOUT_SECONDS),
                ..TunConfig::default()
            },
            dispatcher,
            dns,
            ipv6,
            fake_icmp_echo,
            sniffer,
            Arc::new(TunTrafficStats::default()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_stats(
        tun: TunIo,
        limits: ResourceLimits,
        config: &TunConfig,
        dispatcher: Arc<dyn Dispatcher>,
        dns: Option<Arc<RuntimeDns>>,
        ipv6: bool,
        fake_icmp_echo: bool,
        sniffer: Option<Arc<SnifferConfig>>,
        traffic_stats: Arc<TunTrafficStats>,
    ) -> io::Result<Self> {
        limits
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if limits.tun_max_datagram_size != usize::from(config.mtu) || config.mtu < 1_280 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN resource MTU must match tun.mtu",
            ));
        }
        Ok(Self {
            tun: Arc::new(tun),
            limits,
            config: config.clone(),
            dispatcher,
            dns: dns.filter(|dns| dns.is_enabled()),
            resources: None,
            ipv6,
            fake_icmp_echo,
            sniffer,
            traffic_stats,
            #[cfg(target_os = "linux")]
            echo_options: None,
        })
    }

    pub(crate) fn with_resources(
        mut self,
        resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
    ) -> Self {
        // The provider graph owns the live policy, including a disabled one.
        // A startup fallback would otherwise revive sniffing after a reload.
        if resources.is_some() {
            self.sniffer = None;
        }
        self.resources = resources;
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn with_real_echo(
        mut self,
        dialer: crate::dialer::Dialer,
        fake_ranges: [Option<crate::config::IpCidr>; 2],
        timeout: Duration,
        disabled: bool,
    ) -> io::Result<Self> {
        self.echo_options = Some(
            echo::EchoOptions::prepare(dialer, self.tun.clone(), fake_ranges, timeout, disabled)
                .await?,
        );
        Ok(self)
    }

    pub(crate) async fn run(self, cancellation: CancellationToken) -> io::Result<()> {
        let config = tun_netstack_config(self.limits, self.fake_icmp_echo);
        let resource_stats = RuntimeResourceStats::new("tun_runtime");
        tracing::info!(
            mtu = config.mtu,
            packet_queue = self.limits.packet_queue_capacity,
            event_queue = self.limits.event_queue_capacity,
            tun_udp_association_queue_capacity = self.limits.tun_udp_association_queue_capacity,
            tun_udp_response_queue_capacity = self.limits.tun_udp_response_queue_capacity,
            dns_hijack = self.dns.is_some(),
            ipv6 = self.ipv6,
            fake_icmp_echo = self.fake_icmp_echo,
            "TUN runtime starting"
        );
        let parts = NetStack::start_tcp(config).map_err(netstack_to_io)?;
        let control = parts.control.clone();
        let netstack_stats = parts.stats.clone();
        let mut tasks = JoinSet::new();
        #[cfg(target_os = "linux")]
        let (echo, echo_responses) = if let Some(options) = self.echo_options {
            let (ingress, responses, driver) =
                echo::channel(options, effective_tun_mtu(self.limits));
            tasks.spawn(observation::task(driver.run(cancellation.clone())));
            (Some(ingress), responses)
        } else {
            (None, closed_echo_lane())
        };
        #[cfg(not(target_os = "linux"))]
        let (echo, echo_responses): (Option<EchoIngress>, _) = (None, closed_echo_lane());
        let (udp, responses, dns_responses) = UdpIngress::new(
            UdpIngressContext {
                dispatcher: self.dispatcher.clone(),
                dns: self.dns,
                resources: self.resources,
                sniffer: self.sniffer.clone(),
                limits: self.limits,
                config: self.config.clone(),
                resource_stats: resource_stats.clone(),
            },
            cancellation.clone(),
        );

        tasks.spawn(observation::task(netstack_stats_loop(
            netstack_stats.clone(),
            cancellation.clone(),
        )));
        tasks.spawn(observation::task(
            self.traffic_stats
                .clone()
                .run_rate_clock(cancellation.clone()),
        ));
        tasks.spawn(observation::task(tun_read_loop_with_echo(
            self.tun.clone(),
            parts.packet_sink,
            self.ipv6,
            udp,
            echo,
            self.traffic_stats.clone(),
            cancellation.clone(),
        )));
        tasks.spawn(observation::task(tun_write_loop_with_echo(
            self.tun,
            parts.packet_stream,
            responses,
            dns_responses,
            echo_responses,
            effective_tun_mtu(self.limits),
            self.traffic_stats,
            cancellation.clone(),
        )));
        let sniffer = self.sniffer;
        tasks.spawn(observation::task(tcp_loop(
            parts.tcp_listener,
            self.dispatcher.clone(),
            sniffer.clone(),
            resource_stats.clone(),
            cancellation.clone(),
        )));

        let mut first_error = tokio::select! {
            biased;
            () = cancellation.cancelled() => None,
            joined = tasks.join_next() => joined.and_then(join_result),
        };

        cancellation.cancel();
        control.stop().await;
        while let Some(joined) = tasks.join_next().await {
            if first_error.is_none() {
                first_error = join_result(joined);
            }
        }
        log_netstack_stats(TUN_NETSTACK_STATS_FINAL_EVENT, &netstack_stats);
        resource_stats.log_final();
        first_error.map_or(Ok(()), Err)
    }
}

async fn netstack_stats_loop(
    stats: NetStackStats,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut telemetry = interval_at(
        TokioInstant::now() + TUN_NETSTACK_STATS_INTERVAL,
        TUN_NETSTACK_STATS_INTERVAL,
    );
    telemetry.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            _ = telemetry.tick() => {
                log_netstack_stats(TUN_NETSTACK_STATS_PERIODIC_EVENT, &stats);
            }
        }
    }
}

fn log_netstack_stats(event: &'static str, stats: &NetStackStats) {
    let snapshot = stats.snapshot();
    tracing::info!(
        event,
        scope = "tun_netstack",
        active_tcp_current = snapshot.active_tcp,
        active_tcp_peak = snapshot.active_tcp_peak,
        half_open_tcp_current = snapshot.half_open_tcp,
        half_open_tcp_peak = snapshot.half_open_tcp_peak,
        rejected_tcp = snapshot.rejected_tcp,
        udp_drops = snapshot.dropped_udp,
        invalid_packets = snapshot.invalid_packets,
        icmp_replied = snapshot.icmp_replied,
        icmp_dropped = snapshot.icmp_dropped,
        "TUN netstack resource statistics"
    );
}

fn join_result(result: Result<io::Result<()>, tokio::task::JoinError>) -> Option<io::Error> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => None,
        Ok(Err(error)) => Some(error),
        Err(error) if error.is_cancelled() => None,
        Err(error) => Some(io::Error::other(error)),
    }
}

fn next_diagnostic_session_id() -> u64 {
    loop {
        let id = NEXT_DIAGNOSTIC_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

fn packet_ip_version(packet: &[u8]) -> u8 {
    packet.first().map_or(0, |byte| byte >> 4)
}

fn tun_ingress_allowed(ipv6: bool, packet: &[u8]) -> bool {
    ipv6 || packet_ip_version(packet) != 6
}

#[cfg(test)]
async fn tun_read_loop(
    tun: Arc<TunIo>,
    packet_sink: PacketSink,
    ipv6: bool,
    udp: UdpIngress,
    traffic_stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    tun_read_loop_with_echo(
        tun,
        packet_sink,
        ipv6,
        udp,
        None,
        traffic_stats,
        cancellation,
    )
    .await
}

async fn tun_read_loop_with_echo(
    tun: Arc<TunIo>,
    packet_sink: PacketSink,
    ipv6: bool,
    mut udp: UdpIngress,
    echo: Option<EchoIngress>,
    traffic_stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let result = tun_read_inner(
        tun,
        packet_sink,
        ipv6,
        &mut udp,
        echo.as_ref(),
        traffic_stats,
        cancellation,
    )
    .await;
    // The reader owns all associations and DNS queries. EOF, error and
    // cancellation all join them without cancelling the caller's token.
    udp.stop().await;
    result
}

async fn tun_read_inner(
    tun: Arc<TunIo>,
    packet_sink: PacketSink,
    ipv6: bool,
    udp: &mut UdpIngress,
    echo: Option<&EchoIngress>,
    traffic_stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mtu = effective_tun_mtu(udp.context.limits);
    let mut packets: [Vec<u8>; TUN_PACKET_BATCH_SIZE] =
        std::array::from_fn(|_| Vec::with_capacity(mtu));
    let mut outcomes = Vec::with_capacity(TUN_PACKET_BATCH_SIZE);
    let cleanup_interval = UDP_CLEANUP_INTERVAL.min(udp.context.config.udp_timeout);
    let mut cleanup = interval_at(TokioInstant::now() + cleanup_interval, cleanup_interval);
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut first_read_logged = false;
    let mut first_ingress_logged = false;
    loop {
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => None,
            _ = cleanup.tick() => {
                udp.cleanup();
                continue;
            }
            joined = udp.tasks.join_next(), if !udp.tasks.is_empty() => {
                udp.complete_association(joined);
                continue;
            }
            joined = udp.dns_tasks.join_next(), if !udp.dns_tasks.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(
                        cancelled = error.is_cancelled(),
                        panicked = error.is_panic(),
                        "TUN DNS query task failed"
                    );
                }
                continue;
            }
            result = tun.read_packets(&mut packets, &mut outcomes) => Some(result),
        };
        // Progress is outside the cancellable future: account for every valid
        // consumed packet, even an EOF/cancelled batch's completed prefix.
        let up_bytes = packets
            .iter()
            .zip(&outcomes)
            .fold(0usize, |bytes, (packet, outcome)| {
                if outcome.is_ok() {
                    bytes.saturating_add(packet.len())
                } else {
                    bytes
                }
            });
        if up_bytes != 0 {
            traffic_stats.record_up(up_bytes);
        }
        let Some(result) = result else {
            return Ok(());
        };
        let processed = outcomes.len();
        for (packet, outcome) in packets.iter().zip(outcomes.drain(..)) {
            match outcome {
                Ok(_) => {}
                Err(VoleError::InvalidPacket(reason)) => {
                    tracing::debug!(%reason, "dropping invalid packet read from TUN");
                    continue;
                }
                Err(error) => return Err(vole_to_io(error)),
            }
            if cancellation.is_cancelled() {
                return Ok(());
            }
            if !first_read_logged {
                tracing::info!(
                    packet_bytes = packet.len(),
                    ip_version = packet_ip_version(packet),
                    "TUN received first packet"
                );
                first_read_logged = true;
            }
            if !tun_ingress_allowed(ipv6, packet) {
                continue;
            }
            // UDP bypasses PacketSink, so retain the same effective MTU check
            // before creating an association or admitting a DNS query.
            if packet.len() > mtu {
                tracing::debug!(
                    packet_bytes = packet.len(),
                    mtu,
                    "dropping TUN packet exceeding effective MTU"
                );
                continue;
            }
            if echo.is_some_and(|echo| echo.offer(packet) == EchoOffer::Consumed) {
                continue;
            }
            if let Some(datagram) = parse_udp_packet_view(packet) {
                udp.offer(datagram);
                continue;
            }
            // Give a transiently full handoff one scheduling turn to drain.
            // Persistent pressure still drops this packet, keeping unrelated
            // UDP and DNS ingress independent of TCP capacity.
            match offer_netstack_packet(
                &packet_sink,
                Packet::new(Bytes::copy_from_slice(packet)),
                &cancellation,
            )
            .await
            {
                Ok(()) => {
                    if !first_ingress_logged {
                        tracing::info!("netstack accepted first TUN packet");
                        first_ingress_logged = true;
                    }
                }
                Err(NetStackError::Stopped) => return Ok(()),
                Err(
                    error @ (NetStackError::EmptyPacket
                    | NetStackError::InvalidIpVersion
                    | NetStackError::MtuExceeded { .. }
                    | NetStackError::Backpressure),
                ) => {
                    if matches!(error, NetStackError::Backpressure) {
                        udp.context.resource_stats.queue_drop(
                            ResourceQueue::Packet,
                            udp.context.limits.packet_queue_capacity,
                        );
                    }
                    tracing::debug!(
                        error_code = ?error, "dropping packet rejected by netstack ingress"
                    );
                }
                Err(error) => return Err(netstack_to_io(error)),
            }
        }
        result.map_err(vole_to_io)?;
        // Fast-path packet and borrowed UDP offers have no channel await.
        // Charge every packet, including drops, after each <=8 batch.
        for _ in 0..processed {
            tokio::task::consume_budget().await;
        }
    }
}

async fn offer_netstack_packet(
    sink: &PacketSink,
    packet: Packet,
    cancellation: &CancellationToken,
) -> Result<(), NetStackError> {
    if cancellation.is_cancelled() {
        return Err(NetStackError::Stopped);
    }
    match sink.try_send(packet.clone()) {
        Err(NetStackError::Backpressure) => {}
        result => return result,
    }
    // Reserve the next available slot without waiting indefinitely. Holding
    // this one packet across a yield does not create another ingress queue.
    let send = sink.send(packet);
    tokio::pin!(send);
    if let std::task::Poll::Ready(result) = futures_util::poll!(send.as_mut()) {
        return result;
    }
    tokio::task::yield_now().await;
    if cancellation.is_cancelled() {
        return Err(NetStackError::Stopped);
    }
    match futures_util::poll!(send.as_mut()) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => Err(NetStackError::Backpressure),
    }
}

enum TunOutput {
    Raw(Packet),
    Udp(QueuedUdpResponse),
    Echo(QueuedEchoResponse),
}

/// One bounded scheduling owner, not another packet queue. The cursor persists
/// across batches and closed lanes never prevent the remaining lanes draining.
struct TunOutputMux {
    raw: PacketStream,
    ordinary: mpsc::Receiver<QueuedUdpResponse>,
    dns: mpsc::Receiver<QueuedUdpResponse>,
    echo: mpsc::Receiver<QueuedEchoResponse>,
    open: [bool; 4],
    next_lane: usize,
}

impl TunOutputMux {
    fn new(
        raw: PacketStream,
        ordinary: mpsc::Receiver<QueuedUdpResponse>,
        dns: mpsc::Receiver<QueuedUdpResponse>,
        echo: mpsc::Receiver<QueuedEchoResponse>,
    ) -> Self {
        Self {
            raw,
            ordinary,
            dns,
            echo,
            open: [true; 4],
            next_lane: 0,
        }
    }

    fn try_next(&mut self) -> Option<TunOutput> {
        for offset in 0..4 {
            let lane = (self.next_lane + offset) % 4;
            if !self.open[lane] {
                continue;
            }
            let result = match lane {
                0 => self.raw.try_recv().map(TunOutput::Raw),
                1 => self.ordinary.try_recv().map(TunOutput::Udp),
                2 => self.dns.try_recv().map(TunOutput::Udp),
                _ => self.echo.try_recv().map(TunOutput::Echo),
            };
            match result {
                Ok(output) => {
                    self.next_lane = (lane + 1) % 4;
                    return Some(output);
                }
                Err(mpsc::error::TryRecvError::Disconnected) => self.open[lane] = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
        None
    }

    async fn recv(&mut self) -> Option<TunOutput> {
        loop {
            if let Some(output) = self.try_next() {
                return Some(output);
            }
            if !self.open.iter().any(|open| *open) {
                return None;
            }
            let (lane, output) = tokio::select! {
                packet = self.raw.recv(), if self.open[0] => (0, packet.map(TunOutput::Raw)),
                response = self.ordinary.recv(), if self.open[1] => (1, response.map(TunOutput::Udp)),
                response = self.dns.recv(), if self.open[2] => (2, response.map(TunOutput::Udp)),
                response = self.echo.recv(), if self.open[3] => (3, response.map(TunOutput::Echo)),
            };
            if let Some(output) = output {
                self.next_lane = (lane + 1) % 4;
                return Some(output);
            }
            self.open[lane] = false;
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn tun_write_loop(
    tun: Arc<TunIo>,
    packet_stream: PacketStream,
    responses: mpsc::Receiver<QueuedUdpResponse>,
    dns_responses: mpsc::Receiver<QueuedUdpResponse>,
    mtu: usize,
    traffic_stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    tun_write_loop_with_echo(
        tun,
        packet_stream,
        responses,
        dns_responses,
        closed_echo_lane(),
        mtu,
        traffic_stats,
        cancellation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn tun_write_loop_with_echo(
    tun: Arc<TunIo>,
    packet_stream: PacketStream,
    responses: mpsc::Receiver<QueuedUdpResponse>,
    dns_responses: mpsc::Receiver<QueuedUdpResponse>,
    echo_responses: mpsc::Receiver<QueuedEchoResponse>,
    mtu: usize,
    traffic_stats: Arc<TunTrafficStats>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut mux = TunOutputMux::new(packet_stream, responses, dns_responses, echo_responses);
    let mut first_write_logged = false;
    let mut frames: [Vec<u8>; TUN_PACKET_BATCH_SIZE] =
        std::array::from_fn(|_| Vec::with_capacity(mtu));
    let mut raw: [Option<Packet>; TUN_PACKET_BATCH_SIZE] = std::array::from_fn(|_| None);
    let mut permits: [Option<DnsQueryPermit>; TUN_PACKET_BATCH_SIZE] =
        std::array::from_fn(|_| None);
    let mut echo_permits: [Option<tokio::sync::OwnedSemaphorePermit>; TUN_PACKET_BATCH_SIZE] =
        std::array::from_fn(|_| None);
    let mut outcomes = Vec::with_capacity(TUN_PACKET_BATCH_SIZE);
    loop {
        let first = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            output = mux.recv() => output,
        };
        let Some(first) = first else {
            return Ok(());
        };
        let mut first = Some(first);
        let mut count = 0;
        let mut processed = 0;
        // Invalid UDP output also consumes work budget. A malformed producer
        // cannot keep us in an unlimited ready-drain loop.
        for _ in 0..TUN_PACKET_BATCH_SIZE {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            let Some(output) = first.take().or_else(|| mux.try_next()) else {
                break;
            };
            processed += 1;
            match output {
                TunOutput::Raw(packet) => raw[count] = Some(packet),
                TunOutput::Echo(QueuedEchoResponse { packet, permit }) => {
                    raw[count] = Some(packet);
                    echo_permits[count] = Some(permit);
                }
                TunOutput::Udp(QueuedUdpResponse {
                    datagram,
                    dns_permit,
                }) => {
                    if let Err(error) = encode_udp_packet_into(&datagram, mtu, &mut frames[count]) {
                        tracing::debug!(
                            error_code = ?error, "dropping UDP response that cannot be emitted to TUN"
                        );
                        continue;
                    }
                    permits[count] = dns_permit;
                }
            }
            count += 1;
        }
        if count != 0 {
            let slices: [&[u8]; TUN_PACKET_BATCH_SIZE] = std::array::from_fn(|index| {
                raw[index]
                    .as_ref()
                    .map_or(frames[index].as_slice(), Packet::data)
            });
            let result = tokio::select! {
                biased;
                () = cancellation.cancelled() => None,
                result = tun.write_packets(&slices[..count], &mut outcomes) => Some(result),
            };
            // Platform completion is the ownership boundary for each DNS
            // permit. Unaccepted suffixes stay owned until error/cancel/drop.
            let mut down_bytes = 0usize;
            for (index, outcome) in outcomes.drain(..).enumerate() {
                permits[index].take();
                echo_permits[index].take();
                match outcome {
                    Ok(_) => {
                        down_bytes = down_bytes.saturating_add(slices[index].len());
                        if !first_write_logged {
                            tracing::info!(
                                packet_bytes = slices[index].len(),
                                ip_version = packet_ip_version(slices[index]),
                                "TUN emitted first packet"
                            );
                            first_write_logged = true;
                        }
                    }
                    Err(VoleError::InvalidPacket(reason)) => {
                        tracing::debug!(%reason, "dropping invalid packet emitted by netstack");
                    }
                    Err(error) => {
                        traffic_stats.record_down(down_bytes);
                        return Err(vole_to_io(error));
                    }
                }
            }
            if down_bytes != 0 {
                traffic_stats.record_down(down_bytes);
            }
            let Some(result) = result else {
                return Ok(());
            };
            result.map_err(vole_to_io)?;
        }
        for index in 0..count {
            raw[index] = None;
            permits[index] = None;
            echo_permits[index] = None;
        }
        for _ in 0..processed {
            tokio::task::consume_budget().await;
        }
    }
}

async fn tcp_loop(
    mut listener: TcpListener,
    dispatcher: Arc<dyn Dispatcher>,
    sniffer: Option<Arc<SnifferConfig>>,
    resource_stats: RuntimeResourceStats,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(
                        cancelled = error.is_cancelled(),
                        panicked = error.is_panic(),
                        "TUN TCP relay task failed"
                    );
                }
            }
            stream = listener.accept() => {
                let Some(stream) = stream else { break; };
                let session_id = next_diagnostic_session_id();
                let destination = stream.destination_addr();
                tracing::debug!(
                    session_id,
                    ip_version = if destination.is_ipv4() { 4 } else { 6 },
                    destination_port = destination.port(),
                    "TUN TCP session accepted"
                );
                let activity = resource_stats.begin(ResourceActivity::TcpSession);
                sessions.spawn(observation::task(relay_tcp(
                    session_id,
                    stream,
                    dispatcher.clone(),
                    sniffer.clone(),
                    activity,
                    cancellation.clone(),
                )));
            }
        }
    }
    while sessions.join_next().await.is_some() {}
    Ok(())
}

async fn relay_tcp(
    session_id: u64,
    mut inbound: TcpStream,
    dispatcher: Arc<dyn Dispatcher>,
    sniffer: Option<Arc<SnifferConfig>>,
    _activity: ResourceActivityGuard,
    cancellation: CancellationToken,
) {
    let destination = inbound.destination_addr();
    let destination_port = destination.port();
    let ip_version = if destination.is_ipv4() { 4 } else { 6 };
    let mut session = StreamSession {
        metadata: crate::session::InboundMetadata::new(destination_port),
        inbound: InboundKind::Tun,
        source: inbound.source_addr(),
        destination: Destination::Ip(destination),
        sniffed_domain: None,
    };
    #[cfg(feature = "inbound-http")]
    let (mut inbound, dispatcher) = {
        let mut prefix = Vec::new();
        let mut selected = dispatcher;
        if let Some(http) = selected.http_context()
            && http.candidate_port(destination_port)
        {
            match http
                .try_intercept(&mut inbound, session.clone(), cancellation.clone())
                .await
            {
                Ok(crate::http_processing::Intercept::Handled) => return,
                Ok(crate::http_processing::Intercept::Transparent { prefix: bytes }) => {
                    prefix = bytes;
                    selected = http.dispatcher().clone();
                }
                Err(_) => return,
            }
        }
        (
            crate::http_processing::io::Replay::new(prefix, inbound),
            selected,
        )
    };
    let plan = match dispatcher
        .sniff_plan(session.source, &session.destination)
        .await
    {
        Ok(plan) => plan,
        Err(_) => return,
    }
    .or_else(|| sniffer.map(|config| crate::sniffing::Plan::standalone(config, destination_port)));
    let prefetched = if let Some(plan) = plan {
        let plan = plan.with_cancellation(cancellation.clone());
        tokio::select! { biased; () = cancellation.cancelled() => return,
        bytes = plan.sniff(&mut inbound, &mut session) => match bytes { Ok(bytes) => bytes, Err(_) => return } }
    } else {
        Vec::new()
    };
    let connected = tokio::select! {
        biased;
        () = cancellation.cancelled() => return,
        connected = timeout(OUTBOUND_OPEN_TIMEOUT, dispatcher.connect_tcp(session)) => connected,
    };
    let mut outbound = match connected {
        Ok(Ok(outbound)) => {
            tracing::debug!(
                session_id,
                ip_version,
                destination_port,
                "TUN TCP outbound connected"
            );
            outbound
        }
        Ok(Err(error)) => {
            tracing::warn!(
                session_id,
                ip_version,
                destination_port,
                error_code = error.diagnostic_code(),
                "TUN TCP outbound connect failed"
            );
            return;
        }
        Err(_) => {
            tracing::warn!(
                session_id,
                ip_version,
                destination_port,
                timeout_seconds = OUTBOUND_OPEN_TIMEOUT.as_secs(),
                "TUN TCP outbound connect timed out"
            );
            return;
        }
    };
    let prefetched_bytes = u64::try_from(prefetched.len()).unwrap_or(u64::MAX);
    if !prefetched.is_empty() {
        let replayed = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            replayed = timeout(OUTBOUND_SEND_TIMEOUT, outbound.write_all(&prefetched)) => replayed,
        };
        match replayed {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(
                    session_id,
                    error_kind = ?error.kind(),
                    prefetched_bytes,
                    "TUN TCP sniffed prefix replay failed"
                );
                return;
            }
            Err(_) => {
                tracing::warn!(
                    session_id,
                    prefetched_bytes,
                    timeout_seconds = OUTBOUND_SEND_TIMEOUT.as_secs(),
                    "TUN TCP sniffed prefix replay timed out"
                );
                return;
            }
        }
    }
    drop(prefetched);
    let relayed = tokio::select! {
        biased;
        () = cancellation.cancelled() => Ok((0, 0)),
        copied = tokio::io::copy_bidirectional_with_sizes(
            &mut inbound,
            &mut outbound,
            TCP_RELAY_BUFFER,
            TCP_RELAY_BUFFER,
        ) => copied,
    };
    match relayed {
        Ok((uploaded_bytes, downloaded_bytes)) => tracing::debug!(
            session_id,
            uploaded_bytes = uploaded_bytes.saturating_add(prefetched_bytes),
            downloaded_bytes,
            "TUN TCP relay finished"
        ),
        Err(error) => tracing::warn!(
            session_id,
            error_kind = ?error.kind(),
            error = %error,
            "TUN TCP relay failed"
        ),
    }
}

#[cfg(test)]
fn configured_sniff_protocol(config: &SnifferConfig, port: u16) -> Option<SniffProtocol> {
    if config.matches_http_port(port) {
        Some(SniffProtocol::Http)
    } else if config.matches_tls_port(port) {
        Some(SniffProtocol::Tls)
    } else {
        None
    }
}

fn configured_quic_sniffing(config: Option<&SnifferConfig>, port: u16) -> bool {
    config.is_some_and(|config| config.matches_quic_port(port))
}

#[derive(Clone)]
struct AssociationClock {
    started: TokioInstant,
    #[cfg(test)]
    injected_tick: Option<Arc<AtomicU64>>,
}

impl AssociationClock {
    fn realtime() -> Self {
        Self {
            started: TokioInstant::now(),
            #[cfg(test)]
            injected_tick: None,
        }
    }

    #[cfg(test)]
    fn injected(tick: Arc<AtomicU64>) -> Self {
        Self {
            started: TokioInstant::now(),
            injected_tick: Some(tick),
        }
    }

    fn now(&self) -> u64 {
        #[cfg(test)]
        if let Some(tick) = &self.injected_tick {
            return tick.load(Ordering::Acquire);
        }
        self.started.elapsed().as_secs()
    }
}

struct UdpAssociation {
    generation: u64,
    sender: mpsc::Sender<UdpDatagram>,
    cancellation: CancellationToken,
    last_activity: Arc<AtomicU64>,
}

impl UdpAssociation {
    fn touch(&self, tick: u64) {
        self.last_activity.store(tick, Ordering::Release);
    }

    fn idle_seconds(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_activity.load(Ordering::Acquire))
    }
}

fn remove_completed_association(
    associations: &mut HashMap<SocketAddr, UdpAssociation>,
    source: SocketAddr,
    generation: u64,
) -> Option<UdpAssociation> {
    if associations
        .get(&source)
        .is_some_and(|association| association.generation == generation)
    {
        associations.remove(&source)
    } else {
        None
    }
}

fn take_expired_or_closed_associations(
    associations: &mut HashMap<SocketAddr, UdpAssociation>,
    now: u64,
    idle_timeout: Duration,
) -> Vec<(SocketAddr, UdpAssociation)> {
    let sources = associations
        .iter()
        .filter_map(|(source, association)| {
            (association.sender.is_closed()
                || association.idle_seconds(now) >= idle_timeout.as_secs())
            .then_some(*source)
        })
        .collect::<Vec<_>>();
    sources
        .into_iter()
        .filter_map(|source| {
            associations
                .remove(&source)
                .map(|association| (source, association))
        })
        .collect()
}

fn cancel_removed_associations(removed: Vec<(SocketAddr, UdpAssociation)>) {
    for (_source, association) in removed {
        tracing::debug!(
            association_id = association.generation,
            "TUN UDP association cleaned up"
        );
        // The map entry has already been removed, so a stale completion can
        // never delete a replacement generation for the same source.
        association.cancellation.cancel();
    }
}

enum AssociationInputResult {
    Queued,
    Full,
    Closed,
}

fn try_queue_association_input(
    association: &UdpAssociation,
    datagram: UdpPacketView<'_>,
    now: u64,
    association_queue: usize,
    resource_stats: &RuntimeResourceStats,
) -> AssociationInputResult {
    match association.sender.try_reserve() {
        Ok(permit) => {
            permit.send(UdpDatagram::new(
                datagram.source,
                datagram.destination,
                Bytes::copy_from_slice(datagram.payload),
            ));
            association.touch(now);
            AssociationInputResult::Queued
        }
        Err(mpsc::error::TrySendError::Full(())) => {
            resource_stats.queue_drop(ResourceQueue::UdpAssociation, association_queue);
            AssociationInputResult::Full
        }
        Err(mpsc::error::TrySendError::Closed(())) => AssociationInputResult::Closed,
    }
}

struct UdpIngressContext {
    dispatcher: Arc<dyn Dispatcher>,
    dns: Option<Arc<RuntimeDns>>,
    resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
    sniffer: Option<Arc<SnifferConfig>>,
    limits: ResourceLimits,
    config: TunConfig,
    resource_stats: RuntimeResourceStats,
}

type UdpAssociationCompletion = (SocketAddr, u64, io::Result<()>);

/// Owned by the TUN reader; there is no all-source UDP handoff.
struct UdpIngress {
    context: UdpIngressContext,
    associations: HashMap<SocketAddr, UdpAssociation>,
    tasks: JoinSet<UdpAssociationCompletion>,
    dns_tasks: JoinSet<()>,
    responses: mpsc::Sender<QueuedUdpResponse>,
    dns_responses: mpsc::Sender<QueuedUdpResponse>,
    cancellation: CancellationToken,
    association_clock: AssociationClock,
}

impl UdpIngress {
    fn new(
        context: UdpIngressContext,
        cancellation: CancellationToken,
    ) -> (
        Self,
        mpsc::Receiver<QueuedUdpResponse>,
        mpsc::Receiver<QueuedUdpResponse>,
    ) {
        let (responses, response_rx) =
            mpsc::channel(context.limits.tun_udp_response_queue_capacity);
        let (dns_responses, dns_rx) = mpsc::channel(context.limits.tun_dns_response_queue_capacity);
        (
            Self {
                context,
                associations: HashMap::new(),
                tasks: JoinSet::new(),
                dns_tasks: JoinSet::new(),
                responses,
                dns_responses,
                cancellation: cancellation.child_token(),
                association_clock: AssociationClock::realtime(),
            },
            response_rx,
            dns_rx,
        )
    }

    fn offer(&mut self, datagram: UdpPacketView<'_>) {
        if self.cancellation.is_cancelled() {
            return;
        }
        if self.context.config.hijacks_dns(datagram.destination)
            && let Some(snapshot) = self
                .context
                .resources
                .as_ref()
                .and_then(|resources| resources.dns())
                .or_else(|| {
                    self.context
                        .dns
                        .clone()
                        .map(|dns| crate::resource::control::DnsSnapshot {
                            dns,
                            _generation: None,
                        })
                })
            && snapshot.dns.is_enabled()
        {
            let dns = snapshot.dns.clone();
            if let Err(error) = classify_query(datagram.payload) {
                tracing::debug!(%error, "dropping invalid TUN DNS datagram");
                return;
            }
            let permit = dns
                .begin_query()
                .with_cancellation(self.cancellation.clone());
            let request = UdpDatagram::new(
                datagram.source,
                datagram.destination,
                Bytes::copy_from_slice(datagram.payload),
            );
            self.dns_tasks.spawn(observation::task(run_tun_dns_snapshot(
                snapshot,
                permit,
                request,
                self.dns_responses.clone(),
                effective_tun_mtu(self.context.limits),
                self.context.resource_stats.clone(),
                self.cancellation.clone(),
            )));
            return;
        }
        let source = datagram.source;
        if let Entry::Vacant(entry) = self.associations.entry(source) {
            let association_id = next_diagnostic_session_id();
            tracing::debug!(association_id, "TUN UDP association created");
            let (sender, receiver) =
                mpsc::channel(self.context.limits.tun_udp_association_queue_capacity);
            let child_cancellation = self.cancellation.child_token();
            let last_activity = Arc::new(AtomicU64::new(self.association_clock.now()));
            entry.insert(UdpAssociation {
                generation: association_id,
                sender,
                cancellation: child_cancellation.clone(),
                last_activity: last_activity.clone(),
            });
            let activity = self
                .context
                .resource_stats
                .begin(ResourceActivity::UdpAssociation);
            self.tasks.spawn(observation::task(run_udp_association(
                receiver,
                activity,
                UdpAssociationTaskContext {
                    association_id,
                    source,
                    responses: self.responses.clone(),
                    dispatcher: self.context.dispatcher.clone(),
                    resource_stats: self.context.resource_stats.clone(),
                    association_clock: self.association_clock.clone(),
                    last_activity,
                    tun_mtu: effective_tun_mtu(self.context.limits),
                    udp_timeout: self.context.config.udp_timeout,
                    sniffer: self.context.sniffer.clone(),
                    cancellation: child_cancellation,
                },
            )));
        }
        let Some(association) = self.associations.get(&source) else {
            return;
        };
        let generation = association.generation;
        match try_queue_association_input(
            association,
            datagram,
            self.association_clock.now(),
            self.context.limits.tun_udp_association_queue_capacity,
            &self.context.resource_stats,
        ) {
            AssociationInputResult::Queued | AssociationInputResult::Full => {}
            AssociationInputResult::Closed => {
                if let Some(association) =
                    remove_completed_association(&mut self.associations, source, generation)
                {
                    association.cancellation.cancel();
                }
                // Do not retry this packet against a replacement generation.
                tracing::debug!("dropping TUN UDP datagram for a closing association");
            }
        }
    }

    fn cleanup(&mut self) {
        cancel_removed_associations(take_expired_or_closed_associations(
            &mut self.associations,
            self.association_clock.now(),
            self.context.config.udp_timeout,
        ));
    }

    fn complete_association(
        &mut self,
        joined: Option<Result<UdpAssociationCompletion, tokio::task::JoinError>>,
    ) {
        match joined {
            Some(Ok((source, association_id, result))) => {
                remove_completed_association(&mut self.associations, source, association_id);
                match result {
                    Ok(()) => tracing::debug!(association_id, "TUN UDP association closed"),
                    Err(error) => tracing::warn!(
                        association_id, error_kind = ?error.kind(), "TUN UDP association failed"
                    ),
                }
            }
            Some(Err(error)) => tracing::warn!(
                cancelled = error.is_cancelled(),
                panicked = error.is_panic(),
                "TUN UDP association task failed"
            ),
            None => {}
        }
    }

    async fn stop(&mut self) {
        self.cancellation.cancel();
        self.dns_tasks.abort_all();
        while self.dns_tasks.join_next().await.is_some() {}
        for (_, association) in self.associations.drain() {
            association.cancellation.cancel();
        }
        while self.tasks.join_next().await.is_some() {}
    }
}

impl Drop for UdpIngress {
    fn drop(&mut self) {
        self.cancellation.cancel();
        // Only a cancellation fallback: normal stop explicitly joins children.
        self.tasks.abort_all();
        self.dns_tasks.abort_all();
    }
}

struct QueuedUdpResponse {
    datagram: UdpDatagram,
    dns_permit: Option<DnsQueryPermit>,
}

impl QueuedUdpResponse {
    fn ordinary(datagram: UdpDatagram) -> Self {
        Self {
            datagram,
            dns_permit: None,
        }
    }

    fn dns(datagram: UdpDatagram, permit: DnsQueryPermit) -> Self {
        Self {
            datagram,
            dns_permit: Some(permit),
        }
    }
}

impl Deref for QueuedUdpResponse {
    type Target = UdpDatagram;

    fn deref(&self) -> &Self::Target {
        &self.datagram
    }
}

async fn run_tun_dns_snapshot(
    snapshot: crate::resource::control::DnsSnapshot,
    permit: DnsQueryPermit,
    request: UdpDatagram,
    responses: mpsc::Sender<QueuedUdpResponse>,
    tun_mtu: usize,
    resource_stats: RuntimeResourceStats,
    cancellation: CancellationToken,
) {
    let _generation = snapshot._generation;
    run_tun_dns_query(
        snapshot.dns,
        permit,
        request,
        responses,
        tun_mtu,
        resource_stats,
        cancellation,
    )
    .await;
}

async fn run_tun_dns_query(
    dns: Arc<RuntimeDns>,
    permit: DnsQueryPermit,
    request: UdpDatagram,
    responses: mpsc::Sender<QueuedUdpResponse>,
    tun_mtu: usize,
    resource_stats: RuntimeResourceStats,
    cancellation: CancellationToken,
) {
    let response = tokio::select! {
        biased;
        () = cancellation.cancelled() => return,
        response = dns.exchange_admitted(&request.payload, &permit) => match response {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(%error, "dropping invalid TUN DNS datagram");
                return;
            }
        },
    };
    if let Some(response) = complete_tun_dns_response(&request, response, tun_mtu) {
        try_queue_tun_dns_response(&responses, response, Some(permit), &resource_stats);
    }
}

fn try_queue_tun_dns_response(
    responses: &mpsc::Sender<QueuedUdpResponse>,
    response: UdpDatagram,
    permit: Option<DnsQueryPermit>,
    resource_stats: &RuntimeResourceStats,
) {
    let response = match permit {
        Some(permit) => QueuedUdpResponse::dns(response, permit),
        None => QueuedUdpResponse::ordinary(response),
    };
    match responses.try_send(response) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            resource_stats.queue_drop(ResourceQueue::Dns, responses.max_capacity());
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("dropping TUN DNS response because the response queue is closed");
        }
    }
}

enum ResponseQueueResult {
    Queued,
    Pending(UdpDatagram),
    Closed,
}

fn try_queue_tun_udp_response(
    responses: &mpsc::Sender<QueuedUdpResponse>,
    response: UdpDatagram,
    last_activity: &AtomicU64,
    now: u64,
) -> ResponseQueueResult {
    match responses.try_send(QueuedUdpResponse::ordinary(response)) {
        Ok(()) => {
            last_activity.store(now, Ordering::Release);
            ResponseQueueResult::Queued
        }
        Err(mpsc::error::TrySendError::Full(response)) => {
            ResponseQueueResult::Pending(response.datagram)
        }
        Err(mpsc::error::TrySendError::Closed(_)) => ResponseQueueResult::Closed,
    }
}

fn complete_tun_dns_response(
    request: &UdpDatagram,
    response: Vec<u8>,
    tun_mtu: usize,
) -> Option<UdpDatagram> {
    if response.len()
        > usize::from(DatagramSession::for_tun(request.source, tun_mtu).max_response_payload_size())
    {
        tracing::debug!(
            response_bytes = response.len(),
            "dropping oversized TUN DNS UDP response"
        );
        return None;
    }
    Some(UdpDatagram::new(
        request.destination,
        request.source,
        response,
    ))
}

#[cfg(test)]
fn tun_dns_servfail_response(request: &UdpDatagram, query: &ClassifiedDnsQuery) -> UdpDatagram {
    UdpDatagram::new(
        request.destination,
        request.source,
        synthesize_servfail_response(query),
    )
}

enum AssociationEvent<'a> {
    Cancelled,
    SniffDeadline,
    ReadySend,
    Inbound(Option<UdpDatagram>),
    Outbound(Result<Datagram, DispatchError>),
    ResponseCapacity(Result<mpsc::Permit<'a, QueuedUdpResponse>, mpsc::error::SendError<()>>),
}

#[cfg(test)]
use crate::udp_sniffing::{
    QUIC_SNIFF_FLOW_MAX, QUIC_SNIFF_PENDING_BYTES_MAX, QUIC_SNIFF_PENDING_DATAGRAM_MAX,
    QUIC_SNIFF_TIMEOUT,
};
use crate::udp_sniffing::{QUIC_SNIFF_READY_DATAGRAM_MAX, QuicSniffEngine};
type PreparedTunUdpDatagram = crate::udp_sniffing::PreparedDatagram<UdpDatagram>;
type QuicIngressResult = crate::udp_sniffing::IngressResult<UdpDatagram>;
type UdpQuicSniffState<S, F> = crate::udp_sniffing::SniffState<S, F, UdpDatagram>;

struct UdpAssociationTaskContext {
    association_id: u64,
    source: SocketAddr,
    responses: mpsc::Sender<QueuedUdpResponse>,
    dispatcher: Arc<dyn Dispatcher>,
    resource_stats: RuntimeResourceStats,
    association_clock: AssociationClock,
    last_activity: Arc<AtomicU64>,
    tun_mtu: usize,
    udp_timeout: Duration,
    sniffer: Option<Arc<SnifferConfig>>,
    cancellation: CancellationToken,
}

// One uncommitted response per source, with no additional queue or task.
// Cancellation discards it rather than waiting for a stopped TUN writer.
struct PendingUdpResponse<'a> {
    datagram: Option<UdpDatagram>,
    context: &'a UdpAssociationTaskContext,
}

impl Drop for PendingUdpResponse<'_> {
    fn drop(&mut self) {
        if self.datagram.is_some() {
            self.context.resource_stats.queue_drop(
                ResourceQueue::UdpResponse,
                self.context.responses.max_capacity(),
            );
        }
    }
}

async fn run_udp_association(
    mut inbound: mpsc::Receiver<UdpDatagram>,
    _activity: ResourceActivityGuard,
    context: UdpAssociationTaskContext,
) -> (SocketAddr, u64, io::Result<()>) {
    let result = run_udp_association_inner(&mut inbound, &context).await;
    (context.source, context.association_id, result)
}

async fn run_udp_association_inner(
    inbound: &mut mpsc::Receiver<UdpDatagram>,
    context: &UdpAssociationTaskContext,
) -> io::Result<()> {
    run_udp_association_inner_with_quic_factory(inbound, context, QuicSniffer::new).await
}

async fn wait_for_quic_sniff_deadline(deadline: Option<TokioInstant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

async fn send_tun_udp_datagram(
    transport: &mut dyn DatagramTransport,
    prepared: PreparedTunUdpDatagram,
    context: &UdpAssociationTaskContext,
) -> io::Result<bool> {
    let PreparedTunUdpDatagram {
        datagram,
        mut sniffed_domain,
        flow_id,
    } = prepared;
    if let Some(plan) = context
        .dispatcher
        .sniff_plan(context.source, &Destination::Ip(datagram.destination))
        .await
        .map_err(dispatch_to_io)?
        .or_else(|| {
            context.sniffer.clone().map(|config| {
                crate::sniffing::Plan::standalone(config, datagram.destination.port())
            })
        })
        && let Some(host) = sniffed_domain.as_ref()
        && !plan.accepts(host).map_err(io::Error::other)?
    {
        sniffed_domain = None;
    }
    let datagram = Datagram {
        remote: Destination::Ip(datagram.destination),
        payload: datagram.payload,
        sniffed_domain,
    };
    let send_datagram = async {
        match flow_id {
            Some(flow_id) => {
                transport
                    .send_with_flow_id(datagram, &flow_id.routing_identity())
                    .await
            }
            None => transport.send(datagram).await,
        }
    };
    let send = tokio::select! {
        biased;
        () = context.cancellation.cancelled() => return Ok(false),
        result = timeout(OUTBOUND_SEND_TIMEOUT, send_datagram) => result,
    };
    match send {
        Ok(Ok(())) => Ok(true),
        Ok(Err(error)) => Err(dispatch_to_io(error)),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TUN UDP outbound send timed out",
        )),
    }
}

fn append_ready_datagrams(
    ready: &mut VecDeque<PreparedTunUdpDatagram>,
    mut datagrams: VecDeque<PreparedTunUdpDatagram>,
) -> io::Result<()> {
    if ready
        .len()
        .checked_add(datagrams.len())
        .is_none_or(|total| total > QUIC_SNIFF_READY_DATAGRAM_MAX)
    {
        return Err(io::Error::other(
            "TUN UDP QUIC replay queue exceeded its fixed capacity",
        ));
    }
    ready.append(&mut datagrams);
    Ok(())
}

async fn run_udp_association_inner_with_quic_factory<S, F>(
    inbound: &mut mpsc::Receiver<UdpDatagram>,
    context: &UdpAssociationTaskContext,
    new_sniffer: F,
) -> io::Result<()>
where
    S: QuicSniffEngine,
    F: FnMut() -> S,
{
    let association_id = context.association_id;
    let source = context.source;
    let session = DatagramSession::for_tun(source, context.tun_mtu);
    let opened = tokio::select! {
        biased;
        () = context.cancellation.cancelled() => return Ok(()),
        opened = timeout(
            OUTBOUND_OPEN_TIMEOUT,
            context.dispatcher.open_datagram(session),
        ) => opened,
    };
    let mut transport = match opened {
        Ok(Ok(transport)) => {
            tracing::debug!(association_id, "TUN UDP outbound opened");
            transport
        }
        Ok(Err(error)) => return Err(dispatch_to_io(error)),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TUN UDP outbound open timed out",
            ));
        }
    };

    let mut quic_sniff = UdpQuicSniffState::with_idle_timeout(new_sniffer, context.udp_timeout);
    // Ordinary UDP needs only one pending send, not an allocated replay queue.
    // The deque grows only for actual QUIC replay and keeps its existing bound.
    let mut ready = VecDeque::new();
    let mut pending_send = None;
    let mut pending_response = PendingUdpResponse {
        datagram: None,
        context,
    };
    let mut first_response_logged = false;
    let mut received_in_burst = 0;
    loop {
        let sniff_deadline = quic_sniff.next_deadline();
        let event = tokio::select! {
            biased;
            () = context.cancellation.cancelled() => AssociationEvent::Cancelled,
            () = wait_for_quic_sniff_deadline(sniff_deadline), if sniff_deadline.is_some() => {
                AssociationEvent::SniffDeadline
            }
            // Drain a ready response before accepting another datagram from
            // this same source. Fairness between the ordinary and DNS TUN
            // response queues is handled independently by the sole TUN writer.
            permit = context.responses.reserve(), if pending_response.datagram.is_some() => {
                AssociationEvent::ResponseCapacity(permit)
            }
            datagram = async { transport.receive().await }, if pending_response.datagram.is_none() => AssociationEvent::Outbound(datagram),
            () = std::future::ready(()), if pending_send.is_some() || !ready.is_empty() => AssociationEvent::ReadySend,
            datagram = inbound.recv() => AssociationEvent::Inbound(datagram),
        };
        match event {
            AssociationEvent::Cancelled | AssociationEvent::Inbound(None) => break,
            AssociationEvent::ResponseCapacity(Ok(permit)) => {
                let response = pending_response
                    .datagram
                    .take()
                    .expect("pending UDP response");
                permit.send(QueuedUdpResponse::ordinary(response));
                context
                    .last_activity
                    .store(context.association_clock.now(), Ordering::Release);
            }
            AssociationEvent::ResponseCapacity(Err(_)) => break,
            AssociationEvent::SniffDeadline => {
                append_ready_datagrams(&mut ready, quic_sniff.expire(TokioInstant::now()))?;
            }
            AssociationEvent::ReadySend => {
                let prepared = pending_send
                    .take()
                    .or_else(|| ready.pop_front())
                    .expect("ready-send event requires a queued datagram");
                if !send_tun_udp_datagram(transport.as_mut(), prepared, context).await? {
                    break;
                }
            }
            AssociationEvent::Inbound(Some(datagram)) => {
                let sniff_quic = if let Some(plan) = context
                    .dispatcher
                    .sniff_plan(context.source, &Destination::Ip(datagram.destination))
                    .await
                    .map_err(dispatch_to_io)?
                {
                    plan.quic_enabled()
                } else {
                    configured_quic_sniffing(
                        context.sniffer.as_deref(),
                        datagram.destination.port(),
                    )
                };
                let result = if sniff_quic {
                    quic_sniff.ingest_datagram(datagram, TokioInstant::now())
                } else {
                    QuicIngressResult::Forward(PreparedTunUdpDatagram::without_domain(datagram))
                };
                match result {
                    QuicIngressResult::Buffered => {}
                    QuicIngressResult::Forward(prepared) => {
                        debug_assert!(pending_send.is_none());
                        pending_send = Some(prepared);
                    }
                    QuicIngressResult::Replay(replay) => {
                        append_ready_datagrams(&mut ready, replay)?
                    }
                }
            }
            AssociationEvent::Outbound(Err(error)) => {
                return Err(dispatch_to_io(error));
            }
            AssociationEvent::Outbound(Ok(datagram)) => {
                if !first_response_logged {
                    tracing::debug!(association_id, "TUN UDP received first outbound response");
                    first_response_logged = true;
                }
                let Destination::Ip(remote) = datagram.remote else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TUN XUDP response contained a domain source",
                    ));
                };
                let response = UdpDatagram::new(remote, source, datagram.payload);
                match try_queue_tun_udp_response(
                    &context.responses,
                    response,
                    &context.last_activity,
                    context.association_clock.now(),
                ) {
                    ResponseQueueResult::Queued => {}
                    ResponseQueueResult::Pending(response) => {
                        pending_response.datagram = Some(response);
                    }
                    ResponseQueueResult::Closed => {
                        tracing::debug!(association_id, "TUN UDP response channel closed");
                        break;
                    }
                }
                received_in_burst += 1;
                let capacity = context.responses.max_capacity();
                let writer_backlog =
                    context.responses.capacity() <= capacity - capacity.div_ceil(4);
                if writer_backlog || received_in_burst == crate::limits::IO_POLL_BUDGET {
                    received_in_burst = 0;
                    // Nonblocking response handoff must give the sole writer
                    // a turn before many ready sources fill its shared queue.
                    tokio::task::yield_now().await;
                }
            }
        }
    }
    match timeout(UDP_CLOSE_TIMEOUT, transport.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(
                association_id,
                error_code = error.diagnostic_code(),
                "TUN UDP outbound close failed"
            );
        }
        Err(_) => {
            tracing::warn!(
                association_id,
                error_code = "timed_out",
                "TUN UDP outbound close failed"
            );
        }
    }
    Ok(())
}

fn vole_to_io(error: VoleError) -> io::Error {
    match error {
        VoleError::Io(error) => error,
        error => io::Error::other(error),
    }
}

fn netstack_to_io(error: NetStackError) -> io::Error {
    match error {
        NetStackError::Stopped => io::Error::new(io::ErrorKind::Interrupted, error),
        NetStackError::Backpressure => io::Error::new(io::ErrorKind::WouldBlock, error),
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn dispatch_to_io(error: DispatchError) -> io::Error {
    match error {
        DispatchError::NotAllowed => io::Error::from(io::ErrorKind::PermissionDenied),
        DispatchError::NetworkUnreachable => io::Error::from(io::ErrorKind::NetworkUnreachable),
        DispatchError::HostUnreachable => io::Error::from(io::ErrorKind::HostUnreachable),
        DispatchError::ConnectionRefused => io::Error::from(io::ErrorKind::ConnectionRefused),
        DispatchError::TimedOut => io::Error::from(io::ErrorKind::TimedOut),
        DispatchError::Other(message) => io::Error::other(message),
        DispatchError::RuleEvaluation(failure) => io::Error::other(failure),
    }
}

#[cfg(all(test, unix))]
mod tests;
