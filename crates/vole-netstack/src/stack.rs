use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    socket::tcp,
    time::Instant,
    wire::{
        HardwareAddress, IpCidr, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use thiserror::Error;
use tokio::sync::{Notify, mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    ClientConfig, NetStackConfig, Packet,
    config::ConfigError,
    device::RawIpDevice,
    icmp::{IcmpIngress, classify as classify_icmp},
    pmtu::parse_path_mtu_hint,
    tcp::{
        ClientRequest, ConnectRequest, FlowKey, InitialMtuRequest, TcpConnector, TcpListener,
        TcpStream, TcpStreamHandle, connect_stopped, connect_timeout,
    },
    udp::{UdpDatagram, UdpSocket, parse_udp_packet},
};

const RAW_INGRESS_BATCH: usize = 8;
const TCP_CONNECT_QUEUE: usize = 32;
const EPHEMERAL_PORT_START: u16 = 49_152;

/// Running stack and all of its application-facing endpoints.
pub struct NetStack {
    parts: NetStackParts,
}

/// Endpoints produced by [`NetStack::into_parts`].
pub struct NetStackParts {
    pub packet_sink: PacketSink,
    pub packet_stream: PacketStream,
    pub tcp_listener: TcpListener,
    pub udp_socket: UdpSocket,
    pub control: NetStackControl,
    pub stats: NetStackStats,
}

/// TCP/ICMP endpoints without allocating a shared UDP ingress queue.
pub struct TcpNetStackParts {
    pub packet_sink: PacketSink,
    pub packet_stream: PacketStream,
    pub tcp_listener: TcpListener,
    pub control: NetStackControl,
    pub stats: NetStackStats,
}

/// Active TCP endpoints with configured sources and no passive accept/UDP queue.
pub struct ClientNetStackParts {
    pub packet_sink: PacketSink,
    pub packet_stream: PacketStream,
    pub tcp_connector: TcpConnector,
    pub control: NetStackControl,
    pub stats: NetStackStats,
}

struct DriverParts {
    packet_sink: PacketSink,
    packet_stream: PacketStream,
    tcp_listener: Option<TcpListener>,
    tcp_connector: Option<TcpConnector>,
    udp_socket: Option<UdpSocket>,
    control: NetStackControl,
    stats: NetStackStats,
}

impl DriverParts {
    fn into_stack(self) -> NetStack {
        NetStack {
            parts: NetStackParts {
                packet_sink: self.packet_sink,
                packet_stream: self.packet_stream,
                tcp_listener: self.tcp_listener.expect("passive endpoints requested"),
                udp_socket: self.udp_socket.expect("UDP endpoints requested"),
                control: self.control,
                stats: self.stats,
            },
        }
    }

    fn into_tcp(self) -> TcpNetStackParts {
        TcpNetStackParts {
            packet_sink: self.packet_sink,
            packet_stream: self.packet_stream,
            tcp_listener: self.tcp_listener.expect("passive endpoints requested"),
            control: self.control,
            stats: self.stats,
        }
    }

    fn into_client(self) -> ClientNetStackParts {
        ClientNetStackParts {
            packet_sink: self.packet_sink,
            packet_stream: self.packet_stream,
            tcp_connector: self.tcp_connector.expect("active endpoints requested"),
            control: self.control,
            stats: self.stats,
        }
    }
}

impl NetStack {
    /// Starts one netstack driver on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns [`NetStackError::Config`] for inconsistent bounds and
    /// [`NetStackError::NoRuntime`] when called outside a Tokio runtime.
    pub fn start(config: NetStackConfig) -> Result<Self, NetStackError> {
        Self::start_parts(config, true, None).map(DriverParts::into_stack)
    }

    /// Starts only the TCP/ICMP driver; callers handle UDP with the pure codec.
    ///
    /// # Errors
    ///
    /// Returns the same configuration and runtime errors as [`Self::start`].
    pub fn start_tcp(config: NetStackConfig) -> Result<TcpNetStackParts, NetStackError> {
        Self::start_parts(config, false, None).map(DriverParts::into_tcp)
    }

    /// Starts active TCP using only the supplied local IP addresses.
    ///
    /// UDP remains caller-owned through the pure packet codec. Unsolicited
    /// incoming TCP flows are discarded; passive TUN behavior is unchanged.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::start`] and a configuration error when
    /// no local address is supplied or a supplied address is not unicast.
    pub fn start_client(
        config: NetStackConfig,
        addresses: impl Into<ClientConfig>,
    ) -> Result<ClientNetStackParts, NetStackError> {
        let addresses = addresses.into().validate(config.mtu)?;
        Self::start_parts(config, false, Some(addresses)).map(DriverParts::into_client)
    }

    fn start_parts(
        config: NetStackConfig,
        with_udp: bool,
        addresses: Option<ClientConfig>,
    ) -> Result<DriverParts, NetStackError> {
        if let Some(client) = &addresses {
            config.validate_client(client)?;
        } else {
            config.validate()?;
        }
        tokio::runtime::Handle::try_current().map_err(|_| NetStackError::NoRuntime)?;

        let cancellation = CancellationToken::new();
        let notify = Arc::new(Notify::new());
        let stats = NetStackStats::default();
        let (raw_inbound_tx, raw_inbound_rx) = mpsc::channel(config.packet_queue);
        let (raw_outbound_tx, raw_outbound_rx) = mpsc::channel(config.packet_queue);
        let (tcp_accept_tx, tcp_listener, client, tcp_connector) =
            if let Some(addresses) = addresses {
                let (sender, receiver) = mpsc::channel(TCP_CONNECT_QUEUE);
                (
                    None,
                    None,
                    Some(ClientDriver {
                        addresses,
                        requests: receiver,
                        next_port: EPHEMERAL_PORT_START,
                    }),
                    Some(TcpConnector {
                        sender,
                        addresses,
                        cancellation: cancellation.clone(),
                        notify: notify.clone(),
                    }),
                )
            } else {
                let (sender, receiver) = mpsc::channel(config.tcp_accept_queue);
                (
                    Some(sender),
                    Some(TcpListener {
                        receiver,
                        cancellation: cancellation.clone(),
                    }),
                    None,
                    None,
                )
            };
        let (udp_tx, udp_socket) = if with_udp {
            let (sender, receiver) = mpsc::channel(config.udp_queue);
            (
                Some(sender),
                Some(UdpSocket {
                    receiver,
                    raw_outbound: raw_outbound_tx.clone(),
                    cancellation: cancellation.clone(),
                    mtu: config.mtu,
                }),
            )
        } else {
            (None, None)
        };
        let (stopped_tx, stopped_rx) = watch::channel(false);

        let receive_packet_limit =
            addresses.map_or(config.mtu, |client| client.receive_packet_limit);
        let mut driver = Driver::new(
            config,
            raw_inbound_rx,
            raw_outbound_tx.clone(),
            tcp_accept_tx,
            udp_tx,
            cancellation.clone(),
            notify.clone(),
            stats.clone(),
            stopped_tx,
        );
        if let Some(client) = client {
            driver.configure_client(&client.addresses);
            driver.client = Some(client);
        }
        tokio::spawn(driver.run());

        Ok(DriverParts {
            packet_sink: PacketSink {
                sender: raw_inbound_tx,
                cancellation: cancellation.clone(),
                mtu: receive_packet_limit,
            },
            packet_stream: PacketStream {
                receiver: raw_outbound_rx,
                cancellation: cancellation.clone(),
                notify,
            },
            tcp_listener,
            tcp_connector,
            udp_socket,
            control: NetStackControl {
                cancellation,
                stopped: stopped_rx,
            },
            stats,
        })
    }

    #[must_use]
    pub fn into_parts(self) -> NetStackParts {
        self.parts
    }
}

/// Bounded TUN-to-stack packet endpoint.
#[derive(Clone)]
pub struct PacketSink {
    sender: mpsc::Sender<Packet>,
    cancellation: CancellationToken,
    mtu: usize,
}

impl PacketSink {
    /// Applies backpressure once the configured raw ingress queue is full.
    ///
    /// # Errors
    ///
    /// Returns an input validation error for malformed or oversized packets,
    /// or [`NetStackError::Stopped`] once shutdown begins.
    pub async fn send(&self, packet: impl Into<Packet>) -> Result<(), NetStackError> {
        let packet = packet.into();
        validate_raw_packet(&packet, self.mtu)?;
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => Err(NetStackError::Stopped),
            result = self.sender.send(packet) => {
                result.map_err(|_| NetStackError::Stopped)
            }
        }
    }

    /// Non-blocking ingress used by edge-triggered TUN adapters.
    ///
    /// # Errors
    ///
    /// Returns [`NetStackError::Backpressure`] when the ingress queue is full,
    /// [`NetStackError::Stopped`] during shutdown, or an input validation error.
    pub fn try_send(&self, packet: impl Into<Packet>) -> Result<(), NetStackError> {
        if self.cancellation.is_cancelled() {
            return Err(NetStackError::Stopped);
        }
        let packet = packet.into();
        validate_raw_packet(&packet, self.mtu)?;
        self.sender.try_send(packet).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => NetStackError::Backpressure,
            mpsc::error::TrySendError::Closed(_) => NetStackError::Stopped,
        })
    }
}

/// Bounded stack-to-TUN packet endpoint.
pub struct PacketStream {
    receiver: mpsc::Receiver<Packet>,
    cancellation: CancellationToken,
    notify: Arc<Notify>,
}

impl PacketStream {
    pub async fn recv(&mut self) -> Option<Packet> {
        let packet = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => None,
            packet = self.receiver.recv() => packet,
        };
        if packet.is_some() {
            self.notify.notify_one();
        }
        packet
    }

    /// Takes an already-ready packet and wakes the driver when capacity returns.
    ///
    /// # Errors
    ///
    /// Returns `Empty` when no packet is ready, or `Disconnected` after stop
    /// begins or the output channel closes. Stop never consumes queued packets.
    pub fn try_recv(&mut self) -> Result<Packet, mpsc::error::TryRecvError> {
        if self.cancellation.is_cancelled() {
            return Err(mpsc::error::TryRecvError::Disconnected);
        }
        let packet = self.receiver.try_recv()?;
        self.notify.notify_one();
        Ok(packet)
    }

    /// Waits for one packet, then drains only packets that are already ready.
    ///
    /// Reuses and clears `packets` without creating another queue. A closed
    /// queue returns any received prefix; cancellation discards that prefix
    /// and returns zero because no more packets may cross the stopping TUN.
    /// Dropping this future while waiting for the first packet is cancel-safe.
    ///
    /// # Panics
    ///
    /// Panics if `max_packets` is zero.
    pub async fn recv_batch(&mut self, packets: &mut Vec<Packet>, max_packets: usize) -> usize {
        assert!(max_packets > 0, "packet batch limit must be positive");
        packets.clear();
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => {}
            _ = self.receiver.recv_many(packets, max_packets) => {}
        }
        if !packets.is_empty() {
            self.notify.notify_one();
        }
        if self.cancellation.is_cancelled() {
            packets.clear();
        }
        packets.len()
    }
}

impl Drop for PacketStream {
    fn drop(&mut self) {
        // Receiver closure has no remaining consumer to return capacity.
        // Wake the driver so it observes the closed output immediately.
        self.receiver.close();
        self.notify.notify_one();
    }
}

/// Cancellation handle with a completion barrier.
#[derive(Clone)]
pub struct NetStackControl {
    cancellation: CancellationToken,
    stopped: watch::Receiver<bool>,
}

impl NetStackControl {
    /// Requests cancellation without waiting for cleanup.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Requests cancellation and returns only after all sockets are released.
    pub async fn stop(&self) {
        self.cancel();
        self.wait_stopped().await;
    }

    /// Waits for a stop requested by any owner.
    pub async fn wait_stopped(&self) {
        let mut stopped = self.stopped.clone();
        while !*stopped.borrow() {
            if stopped.changed().await.is_err() {
                break;
            }
        }
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        *self.stopped.borrow()
    }
}

#[derive(Clone, Default)]
pub struct NetStackStats(Arc<Counters>);

#[derive(Default)]
struct Counters {
    active_tcp: AtomicUsize,
    active_tcp_peak: AtomicUsize,
    half_open_tcp: AtomicUsize,
    half_open_tcp_peak: AtomicUsize,
    rejected_tcp: AtomicUsize,
    dropped_udp: AtomicUsize,
    invalid_packets: AtomicUsize,
    icmp_replied: AtomicUsize,
    icmp_dropped: AtomicUsize,
}

impl NetStackStats {
    #[must_use]
    pub fn snapshot(&self) -> ResourceSnapshot {
        ResourceSnapshot {
            active_tcp: self.0.active_tcp.load(Ordering::Acquire),
            active_tcp_peak: self.0.active_tcp_peak.load(Ordering::Acquire),
            half_open_tcp: self.0.half_open_tcp.load(Ordering::Acquire),
            half_open_tcp_peak: self.0.half_open_tcp_peak.load(Ordering::Acquire),
            rejected_tcp: self.0.rejected_tcp.load(Ordering::Acquire),
            dropped_udp: self.0.dropped_udp.load(Ordering::Acquire),
            invalid_packets: self.0.invalid_packets.load(Ordering::Acquire),
            icmp_replied: self.0.icmp_replied.load(Ordering::Acquire),
            icmp_dropped: self.0.icmp_dropped.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceSnapshot {
    pub active_tcp: usize,
    pub active_tcp_peak: usize,
    pub half_open_tcp: usize,
    pub half_open_tcp_peak: usize,
    pub rejected_tcp: usize,
    pub dropped_udp: usize,
    pub invalid_packets: usize,
    pub icmp_replied: usize,
    pub icmp_dropped: usize,
}

#[derive(Debug, Error)]
pub enum NetStackError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("NetStack::start must run inside a Tokio runtime")]
    NoRuntime,
    #[error("raw packet is empty")]
    EmptyPacket,
    #[error("raw packet is not IPv4 or IPv6")]
    InvalidIpVersion,
    #[error("raw packet length {packet_size} exceeds configured MTU {mtu}")]
    MtuExceeded { packet_size: usize, mtu: usize },
    #[error("bounded packet queue is full")]
    Backpressure,
    #[error("netstack is stopping or stopped")]
    Stopped,
}

fn validate_raw_packet(packet: &Packet, mtu: usize) -> Result<(), NetStackError> {
    if packet.is_empty() {
        return Err(NetStackError::EmptyPacket);
    }
    if packet.len() > mtu {
        return Err(NetStackError::MtuExceeded {
            packet_size: packet.len(),
            mtu,
        });
    }
    if !matches!(packet.data()[0] >> 4, 4 | 6) {
        return Err(NetStackError::InvalidIpVersion);
    }
    Ok(())
}

struct TcpEntry {
    socket: SocketHandle,
    handle: Arc<TcpStreamHandle>,
    connecting: Option<ConnectRequest>,
    connect_cancellation: Option<CancellationToken>,
}

struct ClientDriver {
    addresses: ClientConfig,
    requests: mpsc::Receiver<ClientRequest>,
    next_port: u16,
}

struct Driver {
    config: NetStackConfig,
    raw_inbound: mpsc::Receiver<Packet>,
    raw_outbound: mpsc::Sender<Packet>,
    tcp_accept: Option<mpsc::Sender<TcpStream>>,
    client: Option<ClientDriver>,
    udp_outbound: Option<mpsc::Sender<UdpDatagram>>,
    cancellation: CancellationToken,
    notify: Arc<Notify>,
    stats: NetStackStats,
    stopped: watch::Sender<bool>,
    interface: Interface,
    device: RawIpDevice,
    sockets: SocketSet<'static>,
    tcp_entries: HashMap<FlowKey, TcpEntry>,
    half_open: HashSet<FlowKey>,
}

impl Driver {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: NetStackConfig,
        raw_inbound: mpsc::Receiver<Packet>,
        raw_outbound: mpsc::Sender<Packet>,
        tcp_accept: Option<mpsc::Sender<TcpStream>>,
        udp_outbound: Option<mpsc::Sender<UdpDatagram>>,
        cancellation: CancellationToken,
        notify: Arc<Notify>,
        stats: NetStackStats,
        stopped: watch::Sender<bool>,
    ) -> Self {
        let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        interface_config.random_seed = 0x4f_6e_65_56_43_6f_72_65;
        let mut device = RawIpDevice::new(config.mtu, raw_outbound.clone());
        // Passive TUN TCP uses the same bounded, body-free PMTU metadata as
        // IP-carrier clients. A quote still needs the exact live socket and
        // an emitted, unacknowledged sequence before it can lower its budget.
        device.enable_path_mtu();
        let mut interface = Interface::new(interface_config, &mut device, Instant::now());
        interface.set_any_ip(true);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(Ipv4Address::new(10, 0, 0, 1).into(), 24))
                .expect("smoltcp IP address capacity");
            addresses
                .push(IpCidr::new(
                    Ipv6Address::new(0xfd00, 0x5643, 0x6f72, 0x6500, 0, 0, 0, 1).into(),
                    64,
                ))
                .expect("smoltcp IP address capacity");
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
            .expect("smoltcp IPv4 route capacity");
        interface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfd00, 0x5643, 0x6f72, 0x6500, 0, 0, 0, 1))
            .expect("smoltcp IPv6 route capacity");

        Self {
            config,
            raw_inbound,
            raw_outbound,
            tcp_accept,
            client: None,
            udp_outbound,
            cancellation,
            notify,
            stats,
            stopped,
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_entries: HashMap::new(),
            half_open: HashSet::new(),
        }
    }

    fn configure_client(&mut self, addresses: &ClientConfig) {
        if !addresses.path_mtu_discovery {
            self.device.disable_path_mtu();
        }
        self.interface.set_any_ip(false);
        self.interface.update_ip_addrs(|configured| {
            configured.clear();
            for prefix in addresses.prefixes() {
                configured
                    .push(IpCidr::new(prefix.address.into(), prefix.prefix_len))
                    .expect("client IP address capacity");
            }
        });
        self.interface.routes_mut().remove_default_ipv4_route();
        self.interface.routes_mut().remove_default_ipv6_route();
        // The IP-medium device emits every destination into the caller's
        // packet path; these routes never configure a system interface.
        if let Some(ip) = addresses
            .prefixes()
            .find_map(|prefix| match prefix.address {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
        {
            self.interface
                .routes_mut()
                .add_default_ipv4_route(ip)
                .expect("IPv4 route capacity");
        }
        if let Some(ip) = addresses
            .prefixes()
            .find_map(|prefix| match prefix.address {
                IpAddr::V6(ip) => Some(ip),
                IpAddr::V4(_) => None,
            })
        {
            self.interface
                .routes_mut()
                .add_default_ipv6_route(ip)
                .expect("IPv6 route capacity");
        }
    }

    async fn next_request(client: &mut Option<ClientDriver>) -> Option<ClientRequest> {
        match client {
            Some(client) => client.requests.recv().await,
            None => std::future::pending().await,
        }
    }

    async fn run(mut self) {
        loop {
            self.drive();
            if self.cancellation.is_cancelled() || !self.wait_for_work().await {
                break;
            }
        }
    }

    async fn wait_for_work(&mut self) -> bool {
        let delay = self.next_delay();
        let has_connect_requests = self
            .client
            .as_ref()
            .is_some_and(|client| !client.requests.is_closed());
        tokio::select! {
            biased;
            () = self.cancellation.cancelled() => false,
            // A full output still allows one ingress classification:
            // low-priority ICMP drops immediately, while TCP retains its
            // one pending packet until output capacity returns.
            packet = self.raw_inbound.recv(), if self.device.rx_is_empty() => {
                let Some(packet) = packet else { return false; };
                let batch_count = self.handle_packet_batch(packet);
                // recv() already charges the first packet. try_recv()
                // does not, so retain the old per-packet cooperative
                // accounting without repeating socket maintenance.
                for _ in 1..batch_count {
                    tokio::task::consume_budget().await;
                }
                true
            }
            // Socket maintenance runs before this wait on every iteration.
            // Its own notifications must not outrank an already-ready packet,
            // especially TCP ACKs which release the relay's bounded buffers.
            () = self.notify.notified() => true,
            request = Self::next_request(&mut self.client), if has_connect_requests => {
                if let Some(request) = request {
                    self.handle_client_request(request);
                    tokio::task::consume_budget().await;
                }
                true
            }
            () = tokio::time::sleep(delay) => true,
        }
    }

    fn handle_packet_batch(&mut self, first: Packet) -> usize {
        let mut packet = first;
        let mut count = 0;
        loop {
            if self.cancellation.is_cancelled() {
                break;
            }
            self.handle_packet(packet);
            count += 1;
            // TCP still enters smoltcp one packet at a time: the next SYN
            // must see the previous socket's bound remote endpoint. This also
            // keeps queued TCP ingress from spuriously suppressing ICMP echo.
            // Socket/app-buffer maintenance and egress polling stay in drive().
            if !self.device.rx_is_empty() {
                self.interface.poll_ingress_single(
                    Instant::now(),
                    &mut self.device,
                    &mut self.sockets,
                );
            }
            if count == RAW_INGRESS_BATCH
                || self.cancellation.is_cancelled()
                || self.device.tx_is_full()
                || !self.device.rx_is_empty()
            {
                break;
            }
            // Never prefetch a suffix that might need another queue when TX
            // fills. Empty or disconnected ends this batch, not the driver;
            // the accepted prefix still receives the next maintenance pass.
            let Ok(next) = self.raw_inbound.try_recv() else {
                break;
            };
            packet = next;
        }
        count
    }

    fn handle_packet(&mut self, packet: Packet) {
        if self
            .client
            .as_ref()
            .is_none_or(|client| client.addresses.path_mtu_discovery)
            && let Some(hint) = parse_path_mtu_hint(packet.data())
        {
            let local_address = self
                .client
                .as_ref()
                .is_none_or(|client| client.addresses.contains_address(hint.local.ip()));
            if hint.outer_destination == hint.local.ip()
                && local_address
                && self.tcp_entries.contains_key(&FlowKey {
                    source: hint.remote,
                    destination: hint.local,
                })
            {
                self.device.apply_path_mtu(hint);
            }
            return;
        }
        if self.config.fake_icmp_echo {
            match classify_icmp(&packet) {
                IcmpIngress::NotIcmp => {}
                IcmpIngress::Dropped => {
                    self.stats.0.icmp_dropped.fetch_add(1, Ordering::AcqRel);
                    return;
                }
                IcmpIngress::Smoltcp => {
                    self.handle_icmp_packet(packet);
                    return;
                }
            }
        }
        match packet_protocol(&packet) {
            Some(IpProtocol::Tcp) => self.handle_tcp_packet(packet),
            Some(IpProtocol::Udp) => {
                let Some(udp_outbound) = &self.udp_outbound else {
                    return;
                };
                if let Some(datagram) = parse_udp_packet(&packet) {
                    if udp_outbound.try_send(datagram).is_err() {
                        self.stats.0.dropped_udp.fetch_add(1, Ordering::AcqRel);
                    }
                } else {
                    self.stats.0.invalid_packets.fetch_add(1, Ordering::AcqRel);
                }
            }
            Some(_) => {}
            None => {
                self.stats.0.invalid_packets.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    fn handle_icmp_packet(&mut self, packet: Packet) {
        if packet.len() > self.config.mtu || !self.device.rx_is_empty() || self.device.tx_is_full()
        {
            self.stats.0.icmp_dropped.fetch_add(1, Ordering::AcqRel);
            return;
        }

        // Echo remains low priority: one immediate poll, no retained response
        // when a concurrent sender consumes the last output slot.
        let emitted = self.device.emitted();
        if self.device.push_rx(packet).is_err() {
            self.stats.0.icmp_dropped.fetch_add(1, Ordering::AcqRel);
            return;
        }
        self.interface
            .poll_ingress_single(Instant::now(), &mut self.device, &mut self.sockets);
        self.device.discard_rx();
        let replied = self.device.emitted() != emitted;
        let counter = if replied {
            &self.stats.0.icmp_replied
        } else {
            &self.stats.0.icmp_dropped
        };
        counter.fetch_add(1, Ordering::AcqRel);
    }

    fn handle_tcp_packet(&mut self, packet: Packet) {
        let Some((flow, syn, ack)) = parse_tcp_flow(&packet) else {
            self.stats.0.invalid_packets.fetch_add(1, Ordering::AcqRel);
            return;
        };

        if !self.tcp_entries.contains_key(&flow) {
            if self.client.is_some() {
                if syn && !ack {
                    self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
                }
                return;
            }
            if !syn || ack || !self.admit_tcp(flow) {
                return;
            }
        }
        self.device.acknowledge(&packet);
        if self.device.push_rx(packet).is_err() {
            // A pending ingress packet must never be overwritten.
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn admit_tcp(&mut self, flow: FlowKey) -> bool {
        let Some(accept) = self.tcp_accept.as_ref() else {
            return false;
        };
        if accept.capacity() == 0 {
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
            return false;
        }

        let mut socket = self.new_tcp_socket();
        if socket.listen(flow.destination).is_err() {
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
            return false;
        }

        let handle = Arc::new(TcpStreamHandle::new(
            self.config.recv_layer_buffer_size(),
            self.config.send_layer_buffer_size(),
            self.notify.clone(),
        ));
        let socket_handle = self.sockets.add(socket);
        let stream = TcpStream::new(flow, handle.clone());
        if accept.try_send(stream).is_err() {
            self.sockets.remove(socket_handle);
            self.stats.0.rejected_tcp.fetch_add(1, Ordering::AcqRel);
            return false;
        }
        self.tcp_entries.insert(
            flow,
            TcpEntry {
                socket: socket_handle,
                handle,
                connecting: None,
                connect_cancellation: None,
            },
        );
        self.half_open.insert(flow);
        self.update_flow_stats();
        true
    }

    fn new_tcp_socket(&self) -> tcp::Socket<'static> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.recv_layer_buffer_size()]),
            tcp::SocketBuffer::new(vec![0; self.config.send_layer_buffer_size()]),
        );
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));
        socket.set_timeout(Some(self.config.tcp_idle_timeout.into()));
        socket.set_ack_delay(Some(smoltcp::time::Duration::from_millis(10)));
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        if self.client.is_some() {
            // The initial SYN timeout stays unchanged; RTT samples set the lower floor.
            socket.set_min_rto(smoltcp::time::Duration::from_millis(200));
        }
        socket
    }

    fn connect_tcp(&mut self, request: ConnectRequest) {
        if request.cancellation.is_cancelled() || request.response.is_closed() {
            return;
        }
        if self.cancellation.is_cancelled() {
            let _ = request.response.send(Err(connect_stopped()));
            return;
        }
        if tokio::time::Instant::now() >= request.deadline {
            let _ = request.response.send(Err(connect_timeout()));
            return;
        }
        let client = self.client.as_mut().expect("active request has a driver");
        let source = match client.addresses.source_for(request.destination.ip()) {
            Ok(source) => source,
            Err(error) => {
                let _ = request.response.send(Err(error));
                return;
            }
        };
        let mut selected = None;
        for _ in EPHEMERAL_PORT_START..=u16::MAX {
            let port = client.next_port;
            client.next_port = if port == u16::MAX {
                EPHEMERAL_PORT_START
            } else {
                port + 1
            };
            let incoming = FlowKey {
                source: request.destination,
                destination: SocketAddr::new(source, port),
            };
            if !self.tcp_entries.contains_key(&incoming) {
                selected = Some(incoming);
                break;
            }
        }
        let Some(flow) = selected else {
            let _ = request.response.send(Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "active TCP source ports exhausted for peer",
            )));
            return;
        };
        let mut socket = self.new_tcp_socket();
        if socket
            .connect(self.interface.context(), flow.source, flow.destination)
            .is_err()
        {
            let _ = request.response.send(Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "active TCP endpoint is unavailable",
            )));
            return;
        }
        let handle = Arc::new(TcpStreamHandle::new(
            self.config.recv_layer_buffer_size(),
            self.config.send_layer_buffer_size(),
            self.notify.clone(),
        ));
        let socket = self.sockets.add(socket);
        let connect_cancellation = Some(request.cancellation.clone());
        self.tcp_entries.insert(
            flow,
            TcpEntry {
                socket,
                handle,
                connecting: Some(request),
                connect_cancellation,
            },
        );
        self.half_open.insert(flow);
        self.update_flow_stats();
    }

    fn handle_client_request(&mut self, request: ClientRequest) {
        match request {
            ClientRequest::Connect(request) => self.connect_tcp(request),
            ClientRequest::InitialMtu(request) => self.set_initial_mtu(request),
        }
    }

    fn set_initial_mtu(&mut self, request: InitialMtuRequest) {
        if request.response.is_closed() {
            return;
        }
        let result = if self.cancellation.is_cancelled() {
            Err(connect_stopped())
        } else if tokio::time::Instant::now() >= request.deadline {
            Err(connect_timeout())
        } else if !self.tcp_entries.is_empty() || self.device.emitted() != 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "initial TCP MTU is already in use",
            ))
        } else {
            let addresses = self
                .client
                .as_ref()
                .expect("active command has a client")
                .addresses;
            if request.mtu > self.config.mtu || addresses.validate(request.mtu).is_err() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid initial TCP packet budget",
                ))
            } else {
                self.config.mtu = request.mtu;
                self.device.set_initial_mtu(request.mtu);
                // smoltcp snapshots DeviceCapabilities when Interface is
                // created. Before the first flow, rebuild that snapshot and
                // restore the same sources/routes without replacing sockets.
                let mut config = InterfaceConfig::new(HardwareAddress::Ip);
                config.random_seed = 0x4f_6e_65_56_43_6f_72_65;
                self.interface = Interface::new(config, &mut self.device, Instant::now());
                self.configure_client(&addresses);
                Ok(())
            }
        };
        let _ = request.response.send(result);
    }

    fn drive(&mut self) {
        if self.raw_outbound.is_closed() {
            self.cancellation.cancel();
            return;
        }
        self.device.flush_pending();
        // Busy packet traffic must not starve command admission. The same
        // bounded prefix as raw ingress avoids draining an unbounded burst.
        for _ in 0..RAW_INGRESS_BATCH {
            let request = self
                .client
                .as_mut()
                .and_then(|client| client.requests.try_recv().ok());
            let Some(request) = request else {
                break;
            };
            self.handle_client_request(request);
        }
        if !self.device.tx_is_full() {
            self.interface
                .poll(Instant::now(), &mut self.device, &mut self.sockets);
        } else if !self.device.rx_is_empty() {
            // ACK/window progress must not wait for outbound DATA capacity.
            // Device::receive allows only a pure ACK on this path and keeps
            // any immediate response in the same existing pending slot.
            self.interface
                .poll_ingress_single(Instant::now(), &mut self.device, &mut self.sockets);
        }
        self.drive_tcp_sockets();
        self.device.flush_pending();
        if !self.device.tx_is_full() {
            self.interface
                .poll(Instant::now(), &mut self.device, &mut self.sockets);
        }
        self.device.flush_pending();
    }

    fn drive_tcp_sockets(&mut self) {
        let pending_flow = self
            .device
            .pending_rx()
            .and_then(parse_tcp_flow)
            .map(|(flow, _, _)| flow);
        let mut inactive = Vec::new();
        for (flow, entry) in &mut self.tcp_entries {
            let socket = self.sockets.get_mut::<tcp::Socket>(entry.socket);
            Self::finish_connect(*flow, entry, socket);
            let handle = &entry.handle;

            let mut received = false;
            while socket.can_recv() {
                match socket.recv(|bytes| {
                    let count = handle.app_recv.write(bytes);
                    (count, count)
                }) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => received = true,
                }
            }
            if received {
                handle.recv_waker.wake();
            }

            let mut sent = false;
            while socket.can_send() {
                match socket.send(|bytes| {
                    let count = handle.app_send.read(bytes);
                    (count, count)
                }) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => sent = true,
                }
            }
            if sent {
                handle.send_waker.wake();
            }

            let past_handshake = !matches!(
                socket.state(),
                tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
            );
            if past_handshake && !self.half_open.is_empty() {
                self.half_open.remove(flow);
            }
            if past_handshake && !socket.may_recv() && !socket.can_recv() {
                handle.read_closed.store(true, Ordering::Release);
                handle.recv_waker.wake();
            }
            if past_handshake && !socket.may_send() {
                handle.write_closed.store(true, Ordering::Release);
                handle.send_waker.wake();
            }

            if handle.dropped.load(Ordering::Acquire) && !past_handshake {
                // The dispatcher rejected the flow before the handshake
                // completed. Abort immediately instead of retaining a
                // half-open socket until the idle timeout.
                socket.abort();
            } else if (handle.write_shutdown.load(Ordering::Acquire)
                || handle.dropped.load(Ordering::Acquire))
                && handle.app_send.is_empty()
                && socket.may_send()
            {
                socket.close();
            }
            // smoltcp's abort enters Closed before dispatching RST. Its remote
            // endpoint is cleared only once that packet reaches our bounded
            // output queue. Keep it until then, including TX backpressure.
            let reset_pending =
                socket.state() == tcp::State::Closed && socket.remote_endpoint().is_some();
            // A SYN admitted while output is full still awaits device.receive
            // and has not transitioned from Listen. Retain only that flow;
            // a consumed/invalid SYN must not leave a dormant listener behind.
            let ingress_pending = socket.state() == tcp::State::Listen
                && pending_flow == Some(*flow)
                && !handle.dropped.load(Ordering::Acquire)
                && !self.cancellation.is_cancelled();
            if !socket.is_active() && !reset_pending && !ingress_pending {
                inactive.push(*flow);
            }
        }

        for flow in inactive {
            if let Some(entry) = self.tcp_entries.remove(&flow) {
                self.device.forget_flow(flow);
                self.sockets.remove(entry.socket);
                self.half_open.remove(&flow);
                entry.handle.socket_closed.store(true, Ordering::Release);
                entry.handle.write_closed.store(true, Ordering::Release);
                entry.handle.wake_all();
            }
        }
        self.update_flow_stats();
    }

    fn finish_connect(incoming: FlowKey, entry: &mut TcpEntry, socket: &mut tcp::Socket<'_>) {
        let handle = &entry.handle;
        if entry
            .connect_cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            // Covers cancellation after the response was queued but before
            // the caller accepted its stream, including an established race.
            socket.abort();
            handle.dropped.store(true, Ordering::Release);
        }
        let request = entry.connecting.take_if(|request| {
            request.response.is_closed()
                || request.cancellation.is_cancelled()
                || tokio::time::Instant::now() >= request.deadline
                || matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait | tcp::State::Closed
                )
        });
        let Some(request) = request else {
            return;
        };
        let result = if request.response.is_closed() || request.cancellation.is_cancelled() {
            Err(connect_stopped())
        } else if tokio::time::Instant::now() >= request.deadline {
            Err(connect_timeout())
        } else if socket.state() == tcp::State::Closed {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "active TCP handshake was closed",
            ))
        } else {
            Ok(TcpStream::new(
                FlowKey {
                    source: incoming.destination,
                    destination: incoming.source,
                },
                handle.clone(),
            ))
        };
        if result.is_err() {
            socket.abort();
            handle.dropped.store(true, Ordering::Release);
        }
        let _ = request.response.send(result);
    }

    fn next_delay(&mut self) -> Duration {
        let smoltcp_delay = self
            .interface
            .poll_delay(Instant::now(), &self.sockets)
            .map_or(self.config.max_poll_interval, Into::into);
        // A ready egress timer cannot make progress while output is full.
        // PacketStream notifies on capacity recovery; retain a bounded timer
        // for lifecycle maintenance instead of repeatedly sleeping for zero.
        let delay = if smoltcp_delay.is_zero() && self.device.tx_is_full() {
            self.config.max_poll_interval
        } else {
            smoltcp_delay.min(self.config.max_poll_interval)
        };
        self.tcp_entries
            .values()
            .filter_map(|entry| entry.connecting.as_ref())
            .fold(delay, |delay, request| {
                delay.min(
                    request
                        .deadline
                        .saturating_duration_since(tokio::time::Instant::now()),
                )
            })
    }

    fn update_flow_stats(&self) {
        let active_tcp = self.tcp_entries.len();
        let half_open_tcp = self.half_open.len();
        self.stats
            .0
            .active_tcp_peak
            .fetch_max(active_tcp, Ordering::AcqRel);
        self.stats.0.active_tcp.store(active_tcp, Ordering::Release);
        self.stats
            .0
            .half_open_tcp_peak
            .fetch_max(half_open_tcp, Ordering::AcqRel);
        self.stats
            .0
            .half_open_tcp
            .store(half_open_tcp, Ordering::Release);
    }

    fn shutdown(&mut self) {
        self.cancellation.cancel();
        self.device.clear();
        if let Some(client) = &mut self.client {
            client.requests.close();
            while let Ok(request) = client.requests.try_recv() {
                match request {
                    ClientRequest::Connect(request) => {
                        let _ = request.response.send(Err(connect_stopped()));
                    }
                    ClientRequest::InitialMtu(request) => {
                        let _ = request.response.send(Err(connect_stopped()));
                    }
                }
            }
        }
        for entry in self.tcp_entries.values_mut() {
            entry.handle.mark_stopped();
            if let Some(request) = entry.connecting.take() {
                let _ = request.response.send(Err(connect_stopped()));
            }
        }
        self.tcp_entries.clear();
        self.half_open.clear();
        self.sockets = SocketSet::new(Vec::new());
        self.update_flow_stats();
        let _ = self.stopped.send(true);
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn packet_protocol(packet: &Packet) -> Option<IpProtocol> {
    match IpVersion::of_packet(packet.data()).ok()? {
        IpVersion::Ipv4 => Some(Ipv4Packet::new_checked(packet.data()).ok()?.next_header()),
        IpVersion::Ipv6 => Some(Ipv6Packet::new_checked(packet.data()).ok()?.next_header()),
    }
}

fn parse_tcp_flow(packet: &Packet) -> Option<(FlowKey, bool, bool)> {
    let (source_ip, destination_ip, payload) = match IpVersion::of_packet(packet.data()).ok()? {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(packet.data()).ok()?;
            (
                IpAddr::from(ip.src_addr()),
                IpAddr::from(ip.dst_addr()),
                ip.payload(),
            )
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(packet.data()).ok()?;
            (
                IpAddr::from(ip.src_addr()),
                IpAddr::from(ip.dst_addr()),
                ip.payload(),
            )
        }
    };
    let tcp = TcpPacket::new_checked(payload).ok()?;
    Some((
        FlowKey {
            source: SocketAddr::new(source_ip, tcp.src_port()),
            destination: SocketAddr::new(destination_ip, tcp.dst_port()),
        },
        tcp.syn(),
        tcp.ack(),
    ))
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt;

    use super::*;

    fn packet_stream() -> (mpsc::Sender<Packet>, PacketStream, CancellationToken) {
        let (sender, receiver) = mpsc::channel(8);
        let cancellation = CancellationToken::new();
        let stream = PacketStream {
            receiver,
            cancellation: cancellation.clone(),
            notify: Arc::new(Notify::new()),
        };
        (sender, stream, cancellation)
    }

    fn packet(id: u8) -> Packet {
        Packet::new(vec![0x45, id])
    }

    fn tcp_handshake_packet(sequence: i32, acknowledgement: Option<i32>) -> Packet {
        let source = Ipv4Address::new(10, 0, 0, 2);
        let destination = Ipv4Address::new(192, 0, 2, 1);
        let mut ip = Ipv4Packet::new_unchecked(vec![0_u8; 40]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(source);
        ip.set_dst_addr(destination);
        {
            let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
            tcp.set_src_port(12_000);
            tcp.set_dst_port(12_001);
            tcp.set_header_len(20);
            tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(sequence));
            tcp.set_syn(acknowledgement.is_none());
            if let Some(number) = acknowledgement {
                tcp.set_ack(true);
                tcp.set_ack_number(smoltcp::wire::TcpSeqNumber(number));
            }
            tcp.set_window_len(u16::MAX);
            tcp.fill_checksum(&source.into(), &destination.into());
        }
        ip.fill_checksum();
        Packet::new(ip.into_inner())
    }

    // Keep both real handshakes and the failed-emit timeline in one regression.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn failed_fast_retransmit_survives_another_socket_filling_tx() {
        use crate::segmentation::tests::tcp_packet;
        use tokio::io::AsyncWriteExt;
        let config = NetStackConfig {
            packet_queue: 1,
            ..NetStackConfig::default()
        };
        let (_inbound, receiver) = mpsc::channel(config.packet_queue);
        let (outbound, mut packets) = mpsc::channel(config.packet_queue);
        let (accept, mut streams) = mpsc::channel(config.tcp_accept_queue);
        let (stopped, _) = watch::channel(false);
        let mut driver = Driver::new(
            config,
            receiver,
            outbound,
            Some(accept),
            None,
            CancellationToken::new(),
            Arc::new(Notify::new()),
            NetStackStats::default(),
            stopped,
        );
        let flows = [
            FlowKey {
                source: "10.0.0.2:12000".parse().unwrap(),
                destination: "192.0.2.1:12001".parse().unwrap(),
            },
            FlowKey {
                source: "10.0.0.3:12002".parse().unwrap(),
                destination: "192.0.2.1:12001".parse().unwrap(),
            },
        ];
        let mut sequences = [0; 2];
        for (index, flow) in flows.into_iter().enumerate() {
            let remote_sequence = 100 + u32::try_from(index).unwrap() * 100;
            driver.handle_packet_batch(tcp_packet(flow, remote_sequence, 0, 2, 0));
            driver.drive();
            let syn_ack = packets.try_recv().expect("actual SYN-ACK missing");
            let ip = Ipv4Packet::new_checked(syn_ack.data()).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.syn() && tcp.ack());
            sequences[index] =
                u32::from_be_bytes(ip.payload()[4..8].try_into().unwrap()).wrapping_add(1);
            driver.handle_packet_batch(tcp_packet(
                flow,
                remote_sequence + 1,
                sequences[index],
                16,
                0,
            ));
            driver.drive();
            assert!(packets.try_recv().is_err());
        }
        let mut first_stream = streams.try_recv().unwrap();
        let mut retry_stream = streams.try_recv().unwrap();
        let first_handle = driver.tcp_entries[&flows[0]].socket;
        let retry_handle = driver.tcp_entries[&flows[1]].socket;
        let handles: Vec<_> = driver.sockets.iter().map(|(handle, _)| handle).collect();
        assert!(
            handles
                .iter()
                .position(|handle| *handle == first_handle)
                .unwrap()
                < handles
                    .iter()
                    .position(|handle| *handle == retry_handle)
                    .unwrap(),
            "fixture requires the output-filling socket before the retry socket"
        );

        let lost = b"actual-unacknowledged-DATA";
        retry_stream.write_all(lost).await.unwrap();
        driver.drive_tcp_sockets();
        let now = Instant::now();
        driver
            .interface
            .poll_egress(now, &mut driver.device, &mut driver.sockets);
        let original = packets.try_recv().expect("actual original DATA missing");
        let ip = Ipv4Packet::new_checked(original.data()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(tcp.dst_port(), flows[1].source.port());
        assert_eq!(tcp.payload(), lost);
        let original_sequence = tcp.seq_number();
        assert_eq!(
            driver.sockets.get::<tcp::Socket>(retry_handle).send_queue(),
            lost.len()
        );

        // The actual TCP ACK parser schedules fast retransmit. Do not poll
        // egress until the earlier socket has an ordinary DATA packet ready.
        let ack_at = now + smoltcp::time::Duration::from_millis(1);
        for _ in 0..3 {
            driver.handle_packet(tcp_packet(flows[1], 201, sequences[1], 16, 0));
            driver
                .interface
                .poll_ingress_single(ack_at, &mut driver.device, &mut driver.sockets);
            assert!(driver.device.rx_is_empty());
        }
        let filling = b"earlier-socket-occupies-the-only-output-slot";
        first_stream.write_all(filling).await.unwrap();
        driver.drive_tcp_sockets();
        driver.interface.poll_egress(
            now + smoltcp::time::Duration::from_millis(2),
            &mut driver.device,
            &mut driver.sockets,
        );
        let occupied = packets
            .try_recv()
            .expect("earlier socket did not emit DATA");
        let ip = Ipv4Packet::new_checked(occupied.data()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(tcp.dst_port(), flows[0].source.port());
        assert_eq!(tcp.payload(), filling);
        assert!(!driver.device.tx_is_full());

        // Capacity is now free. No new peer ACK, application write or real-time
        // wait follows the failed emit; only one public egress poll at +1ms.
        driver.interface.poll_egress(
            now + smoltcp::time::Duration::from_millis(3),
            &mut driver.device,
            &mut driver.sockets,
        );
        let retried = packets.try_recv().ok().is_some_and(|packet| {
            let ip = Ipv4Packet::new_checked(packet.data()).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            tcp.dst_port() == flows[1].source.port()
                && tcp.seq_number() == original_sequence
                && tcp.payload() == lost
                && !tcp.syn()
                && !tcp.fin()
                && !tcp.rst()
        });
        driver.shutdown();
        drop((first_stream, retry_stream));
        assert!(driver.cancellation.is_cancelled());
        assert!(driver.tcp_entries.is_empty());
        assert_eq!(driver.sockets.iter().count(), 0);
        assert!(
            retried,
            "failed fast retransmit must remain immediately retryable after TX capacity returns"
        );
    }

    #[tokio::test]
    async fn full_tx_pure_ack_releases_actual_smoltcp_send_queue() {
        use tokio::io::AsyncWriteExt;
        let config = NetStackConfig {
            packet_queue: 1,
            ..NetStackConfig::default()
        };
        let (_sender, inbound) = mpsc::channel(config.packet_queue);
        let (outbound, mut packets) = mpsc::channel(config.packet_queue);
        let (accept, mut streams) = mpsc::channel(config.tcp_accept_queue);
        let (stopped, _) = watch::channel(false);
        let mut driver = Driver::new(
            config,
            inbound,
            outbound,
            Some(accept),
            None,
            CancellationToken::new(),
            Arc::new(Notify::new()),
            NetStackStats::default(),
            stopped,
        );
        driver.handle_packet_batch(tcp_handshake_packet(100, None));
        driver.drive();
        let syn_ack = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(syn_ack.data()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let acknowledged = tcp.seq_number().0.wrapping_add(1);
        driver.handle_packet_batch(tcp_handshake_packet(101, Some(acknowledged)));
        driver.drive();
        let mut stream = streams.try_recv().unwrap();
        let payload = b"unacknowledged-before-full-output";
        stream.write_all(payload).await.unwrap();
        driver.drive();
        let data = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(data.data()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(tcp.payload(), payload);
        let ack = tcp
            .seq_number()
            .0
            .wrapping_add(i32::try_from(payload.len()).unwrap());
        assert_eq!(
            driver
                .sockets
                .get::<tcp::Socket>(driver.tcp_entries.values().next().unwrap().socket)
                .send_queue(),
            payload.len()
        );
        driver.raw_outbound.try_send(packet(99)).unwrap();
        assert!(driver.device.tx_is_full());
        // A real ACK must reach the live smoltcp socket while the downstream
        // packet consumer is blocked; no fabricated socket-state observation.
        driver.handle_packet_batch(tcp_handshake_packet(101, Some(ack)));
        assert!(
            driver.device.rx_is_empty(),
            "ACK remained blocked behind full TX"
        );
        assert_eq!(
            driver
                .sockets
                .get::<tcp::Socket>(driver.tcp_entries.values().next().unwrap().socket)
                .send_queue(),
            0
        );
        assert_eq!(packets.try_recv().unwrap(), packet(99));
        driver.shutdown();
        assert!(driver.cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn full_tx_smoltcp_immediate_reset_is_retained_until_capacity_returns() {
        let config = NetStackConfig {
            packet_queue: 1,
            ..NetStackConfig::default()
        };
        let (_sender, inbound) = mpsc::channel(config.packet_queue);
        let (outbound, mut packets) = mpsc::channel(config.packet_queue);
        let (accept, _streams) = mpsc::channel(config.tcp_accept_queue);
        let (stopped, _) = watch::channel(false);
        let mut driver = Driver::new(
            config,
            inbound,
            outbound,
            Some(accept),
            None,
            CancellationToken::new(),
            Arc::new(Notify::new()),
            NetStackStats::default(),
            stopped,
        );
        driver.handle_packet_batch(tcp_handshake_packet(100, None));
        driver.drive();
        let syn_ack = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(syn_ack.data()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let wrong_ack = tcp.seq_number().0.wrapping_add(2);
        driver.raw_outbound.try_send(packet(99)).unwrap();
        driver.handle_packet_batch(tcp_handshake_packet(101, Some(wrong_ack)));
        assert!(
            driver.device.rx_is_empty(),
            "full TX blocked the invalid-ACK response path"
        );
        assert_eq!(packets.try_recv().unwrap(), packet(99));
        driver.drive();
        let reset = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(reset.data()).unwrap();
        assert!(TcpPacket::new_checked(ip.payload()).unwrap().rst());
        assert!(packets.try_recv().is_err());
        driver.shutdown();
        assert!(driver.device.rx_is_empty());
        assert!(driver.cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn ready_ingress_progresses_before_repeated_app_notifications() {
        for cancelled in [false, true] {
            let config = NetStackConfig::default();
            let (sender, inbound) = mpsc::channel(config.packet_queue);
            let (outbound, _packets) = mpsc::channel(config.packet_queue);
            let (accept, _streams) = mpsc::channel(config.tcp_accept_queue);
            let (stopped, _) = watch::channel(false);
            let cancellation = CancellationToken::new();
            let notify = Arc::new(Notify::new());
            let mut driver = Driver::new(
                config,
                inbound,
                outbound,
                Some(accept),
                None,
                cancellation.clone(),
                notify.clone(),
                NetStackStats::default(),
                stopped,
            );
            sender.try_send(tcp_handshake_packet(100, None)).unwrap();
            // Application writes and output capacity recovery can make this
            // notification ready on every iteration of a busy duplex relay.
            for _ in 0..3 {
                notify.notify_one();
                if cancelled {
                    cancellation.cancel();
                }
                let running = driver.wait_for_work().await;
                assert_eq!(running, !cancelled);
                if cancelled {
                    assert_eq!(driver.raw_inbound.len(), 1);
                    assert!(driver.tcp_entries.is_empty());
                    break;
                }
                assert!(
                    driver.raw_inbound.is_empty(),
                    "ready IP input lost to app notification"
                );
                assert_eq!(driver.tcp_entries.len(), 1);
                sender.try_send(tcp_handshake_packet(100, None)).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn driver_batch_preserves_queued_suffix_when_tcp_ingress_fills_tx() {
        let config = NetStackConfig {
            packet_queue: 1,
            ..NetStackConfig::default()
        };
        let (sender, inbound) = mpsc::channel(config.packet_queue);
        let (outbound, mut packets) = mpsc::channel(config.packet_queue);
        let (accept, _streams) = mpsc::channel(config.tcp_accept_queue);
        let (udp, mut datagrams) = mpsc::channel(config.udp_queue);
        let (stopped, _) = watch::channel(false);
        let mut driver = Driver::new(
            config,
            inbound,
            outbound,
            Some(accept),
            Some(udp),
            CancellationToken::new(),
            Arc::new(Notify::new()),
            NetStackStats::default(),
            stopped,
        );

        sender.try_send(tcp_handshake_packet(100, None)).unwrap();
        let syn = driver.raw_inbound.try_recv().unwrap();
        assert_eq!(driver.handle_packet_batch(syn), 1);
        driver.drive();
        let syn_ack = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(syn_ack.data()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
        // A wrong SYN-ACK acknowledgement produces an immediate ingress RST,
        // unlike the initial SYN, whose response requires an egress poll.
        let wrong_ack = tcp.seq_number().0.wrapping_add(2);
        sender
            .try_send(tcp_handshake_packet(101, Some(wrong_ack)))
            .unwrap();
        let first = driver.raw_inbound.try_recv().unwrap();
        let witness = UdpDatagram::new(
            "10.0.0.2:12000".parse().unwrap(),
            "192.0.2.1:12001".parse().unwrap(),
            b"retained-suffix".as_slice(),
        );
        sender
            .try_send(crate::udp::build_udp_packet(&witness, 1_500).unwrap())
            .unwrap();
        assert!(!driver.device.tx_is_full());

        assert_eq!(driver.handle_packet_batch(first), 1);
        assert!(driver.device.tx_is_full());
        assert!(driver.device.rx_is_empty());
        assert_eq!(driver.raw_inbound.len(), 1);
        assert!(datagrams.try_recv().is_err());

        driver.drive();
        let reset = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(reset.data()).unwrap();
        assert!(TcpPacket::new_checked(ip.payload()).unwrap().rst());
        assert!(!driver.device.tx_is_full());
        let suffix = driver.raw_inbound.try_recv().unwrap();
        assert_eq!(driver.handle_packet_batch(suffix), 1);
        assert_eq!(datagrams.try_recv().unwrap(), witness);
        driver.drive();
        assert!(datagrams.try_recv().is_err());
        assert!(driver.raw_inbound.is_empty());
        assert!(packets.try_recv().is_err());
        assert_eq!(driver.stats.snapshot().invalid_packets, 0);
        assert_eq!(driver.stats.snapshot().rejected_tcp, 0);
    }

    #[tokio::test]
    async fn driver_batch_drains_a_bounded_ready_prefix_in_order() {
        let config = NetStackConfig {
            packet_queue: 16,
            ..NetStackConfig::default()
        };
        let (sender, inbound) = mpsc::channel(config.packet_queue);
        let (outbound, _packets) = mpsc::channel(config.packet_queue);
        let (accept, _streams) = mpsc::channel(config.tcp_accept_queue);
        let (udp, mut datagrams) = mpsc::channel(config.udp_queue);
        let (stopped, _) = watch::channel(false);
        let mut driver = Driver::new(
            config,
            inbound,
            outbound,
            Some(accept),
            Some(udp),
            CancellationToken::new(),
            Arc::new(Notify::new()),
            NetStackStats::default(),
            stopped,
        );
        for id in 0..10_u8 {
            let datagram = UdpDatagram::new(
                "10.0.0.2:12000".parse().unwrap(),
                "192.0.2.1:12001".parse().unwrap(),
                vec![id],
            );
            sender
                .try_send(crate::udp::build_udp_packet(&datagram, 1_500).unwrap())
                .unwrap();
        }
        let first = driver.raw_inbound.try_recv().unwrap();
        assert_eq!(driver.handle_packet_batch(first), 8);
        assert_eq!(driver.raw_inbound.len(), 2);
        assert!(driver.device.rx_is_empty());
        for id in 0..8_u8 {
            assert_eq!(datagrams.try_recv().unwrap().payload.as_ref(), &[id]);
        }
        assert!(datagrams.try_recv().is_err());

        let first = driver.raw_inbound.try_recv().unwrap();
        assert_eq!(driver.handle_packet_batch(first), 2);
        assert!(driver.raw_inbound.is_empty());
        for id in 8..10_u8 {
            assert_eq!(datagrams.try_recv().unwrap().payload.as_ref(), &[id]);
        }

        // Closed input still has to deliver its ready prefix before exit.
        sender.try_send(packet(20)).unwrap();
        drop(sender);
        let first = driver.raw_inbound.try_recv().unwrap();
        assert_eq!(driver.handle_packet_batch(first), 1);
        assert_eq!(driver.stats.snapshot().invalid_packets, 1);

        // Full output must not prefetch the batch suffix, even for UDP.
        for _ in 0..16 {
            driver.raw_outbound.try_send(packet(30)).unwrap();
        }
        let (sender, receiver) = mpsc::channel(1);
        driver.raw_inbound = receiver;
        sender.try_send(packet(31)).unwrap();
        assert_eq!(driver.handle_packet_batch(packet(32)), 1);
        assert_eq!(driver.raw_inbound.len(), 1);
        assert_eq!(driver.stats.snapshot().invalid_packets, 2);

        driver.cancellation.cancel();
        assert_eq!(driver.handle_packet_batch(packet(33)), 0);
        assert_eq!(driver.raw_inbound.len(), 1);
        assert_eq!(driver.stats.snapshot().invalid_packets, 2);
    }

    #[tokio::test]
    async fn full_output_defers_an_immediate_reset_timer_without_losing_the_reset() {
        let config = NetStackConfig {
            packet_queue: 1,
            max_poll_interval: Duration::from_secs(5),
            ..NetStackConfig::default()
        };
        let (_sender, inbound) = mpsc::channel(config.packet_queue);
        let (outbound, mut packets) = mpsc::channel(config.packet_queue);
        let (accept, mut streams) = mpsc::channel(config.tcp_accept_queue);
        let (stopped, _) = watch::channel(false);
        let mut driver = Driver::new(
            config,
            inbound,
            outbound,
            Some(accept),
            None,
            CancellationToken::new(),
            Arc::new(Notify::new()),
            NetStackStats::default(),
            stopped,
        );
        assert_eq!(
            driver.handle_packet_batch(tcp_handshake_packet(100, None)),
            1
        );
        driver.drive();
        packets.try_recv().unwrap();
        let stream = streams.try_recv().unwrap();
        driver.raw_outbound.try_send(packet(0)).unwrap();
        drop(stream);
        driver.drive();
        assert!(driver.device.tx_is_full());
        assert_eq!(driver.stats.snapshot().active_tcp, 1);
        assert_eq!(driver.next_delay(), driver.config.max_poll_interval);

        assert_eq!(packets.try_recv().unwrap(), packet(0));
        driver.drive();
        let reset = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(reset.data()).unwrap();
        assert!(TcpPacket::new_checked(ip.payload()).unwrap().rst());
        driver.drive();
        assert_eq!(driver.stats.snapshot().active_tcp, 0);
        assert!(packets.try_recv().is_err());
    }

    #[tokio::test]
    async fn packet_batch_drains_ready_packets_in_order_and_reuses_storage() {
        let (sender, mut stream, _) = packet_stream();
        for id in 0..3 {
            sender.try_send(packet(id)).unwrap();
        }
        let mut packets = Vec::with_capacity(8);
        packets.push(packet(99));
        let storage = packets.as_ptr();

        assert_eq!(stream.recv_batch(&mut packets, 8).now_or_never(), Some(3));
        assert_eq!(packets, vec![packet(0), packet(1), packet(2)]);
        assert_eq!(packets.as_ptr(), storage);
    }

    #[tokio::test]
    async fn packet_batch_returns_one_ready_packet_without_waiting_to_fill() {
        let (sender, mut stream, _) = packet_stream();
        sender.try_send(packet(0)).unwrap();
        let mut packets = Vec::new();

        assert_eq!(stream.recv_batch(&mut packets, 8).now_or_never(), Some(1));
        assert_eq!(packets, vec![packet(0)]);
    }

    #[tokio::test]
    async fn packet_batch_respects_the_callers_limit() {
        let (sender, mut stream, _) = packet_stream();
        for id in 0..4 {
            sender.try_send(packet(id)).unwrap();
        }
        let mut packets = Vec::new();

        assert_eq!(stream.recv_batch(&mut packets, 2).await, 2);
        assert_eq!(packets, vec![packet(0), packet(1)]);
        assert_eq!(stream.recv_batch(&mut packets, 2).await, 2);
        assert_eq!(packets, vec![packet(2), packet(3)]);
    }

    #[tokio::test]
    async fn packet_batch_returns_a_ready_prefix_when_the_queue_closes() {
        let (sender, mut stream, _) = packet_stream();
        sender.try_send(packet(0)).unwrap();
        sender.try_send(packet(1)).unwrap();
        drop(sender);
        let mut packets = Vec::new();

        assert_eq!(stream.recv_batch(&mut packets, 8).await, 2);
        assert_eq!(packets, vec![packet(0), packet(1)]);
        assert_eq!(stream.recv_batch(&mut packets, 8).await, 0);
        assert_eq!(packets, Vec::<Packet>::new());
    }

    #[tokio::test]
    async fn packet_batch_cancellation_takes_priority_over_queued_packets() {
        let (sender, mut stream, cancellation) = packet_stream();
        sender.try_send(packet(0)).unwrap();
        cancellation.cancel();
        let mut packets = vec![packet(99)];

        assert_eq!(stream.recv_batch(&mut packets, 8).await, 0);
        assert_eq!(packets, Vec::<Packet>::new());
        assert_eq!(stream.receiver.len(), 1);
    }

    #[tokio::test]
    async fn dropping_an_empty_packet_batch_receive_does_not_consume_a_later_packet() {
        let (sender, mut stream, _) = packet_stream();
        let mut packets = Vec::new();
        assert!(stream.recv_batch(&mut packets, 8).now_or_never().is_none());

        sender.try_send(packet(0)).unwrap();
        assert_eq!(stream.recv_batch(&mut packets, 8).await, 1);
        assert_eq!(packets, vec![packet(0)]);
    }

    #[tokio::test]
    async fn cancellation_wakes_an_empty_packet_batch_receive() {
        let (_sender, mut stream, cancellation) = packet_stream();
        let mut packets = Vec::new();
        let mut receive = Box::pin(stream.recv_batch(&mut packets, 8));
        assert!(futures_util::poll!(receive.as_mut()).is_pending());

        cancellation.cancel();
        assert_eq!(receive.await, 0);
        assert_eq!(packets, Vec::<Packet>::new());
    }

    #[tokio::test]
    async fn every_output_receive_api_notifies_capacity_recovery() {
        let (sender, mut stream, _) = packet_stream();
        let notify = stream.notify.clone();
        assert!(notify.notified().now_or_never().is_none());
        assert_eq!(stream.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        assert!(notify.notified().now_or_never().is_none());

        sender.try_send(packet(0)).unwrap();
        assert_eq!(stream.try_recv().unwrap(), packet(0));
        assert_eq!(notify.notified().now_or_never(), Some(()));

        sender.try_send(packet(1)).unwrap();
        assert_eq!(stream.recv().await, Some(packet(1)));
        assert_eq!(notify.notified().now_or_never(), Some(()));

        sender.try_send(packet(2)).unwrap();
        let mut packets = Vec::new();
        assert_eq!(stream.recv_batch(&mut packets, 8).await, 1);
        assert_eq!(packets, vec![packet(2)]);
        assert_eq!(notify.notified().now_or_never(), Some(()));
    }

    #[tokio::test]
    async fn output_try_receive_respects_stop_without_consuming_queued_packets() {
        let (sender, mut stream, cancellation) = packet_stream();
        sender.try_send(packet(0)).unwrap();
        cancellation.cancel();
        assert_eq!(
            stream.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        assert_eq!(stream.receiver.len(), 1);
        assert!(stream.notify.notified().now_or_never().is_none());
    }

    #[tokio::test]
    async fn output_receiver_drop_closes_capacity_and_wakes_the_driver() {
        let (sender, stream, _) = packet_stream();
        let notify = stream.notify.clone();
        drop(stream);
        assert!(sender.is_closed());
        assert_eq!(notify.notified().now_or_never(), Some(()));
    }

    #[test]
    fn validates_raw_packet_bounds() {
        assert!(matches!(
            validate_raw_packet(&Packet::new(Vec::new()), 1_500),
            Err(NetStackError::EmptyPacket)
        ));
        assert!(matches!(
            validate_raw_packet(&Packet::new(vec![0x70]), 1_500),
            Err(NetStackError::InvalidIpVersion)
        ));
        assert!(matches!(
            validate_raw_packet(&Packet::new(vec![0x45; 1_501]), 1_500),
            Err(NetStackError::MtuExceeded { .. })
        ));
    }
}
