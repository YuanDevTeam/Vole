//! Real Noise and netstack queues; no host sockets or fake raw-RX consumer.
use super::*;
use crate::session::InboundKind;
use futures_util::{future::BoxFuture, task::noop_waker};
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use vole_netstack::{
    ClientAddresses, ClientNetStackParts, NetStack, NetStackConfig, TcpConnector, TcpStream,
    UdpDatagram, encode_udp_packet_into,
};

fn network(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
        _ => panic!("real Noise output required"),
    }
}
fn noise_pair() -> (Tunn, Tunn) {
    let mut client = Tunn::new(
        x25519::StaticSecret::from([1; 32]),
        x25519::PublicKey::from(&x25519::StaticSecret::from([2; 32])),
        None,
        None,
        1,
        None,
    );
    let mut server = Tunn::new(
        x25519::StaticSecret::from([2; 32]),
        x25519::PublicKey::from(&x25519::StaticSecret::from([1; 32])),
        None,
        None,
        2,
        None,
    );
    let mut scratch = vec![0; 1440];
    let first = network(client.format_handshake_initiation(&mut scratch, true));
    let response = network(server.decapsulate(None, &first, &mut scratch));
    let keepalive = network(client.decapsulate(None, &response, &mut scratch));
    assert!(matches!(
        server.decapsulate(None, &keepalive, &mut scratch),
        TunnResult::Done
    ));
    assert!(client.time_since_last_handshake().is_some());
    (client, server)
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap()
}
fn syn_ack(syn: &Packet) -> Packet {
    let syn = syn.data();
    let offset = usize::from(syn[0] & 15) * 4;
    assert_eq!(syn[9], 6);
    assert_eq!(syn[offset + 13] & 0x17, 2);
    let mut bytes = vec![0; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40_u16.to_be_bytes());
    bytes[4..6].copy_from_slice(&0xbeef_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&syn[16..20]);
    bytes[16..20].copy_from_slice(&syn[12..16]);
    bytes[20..22].copy_from_slice(&syn[offset + 2..offset + 4]);
    bytes[22..24].copy_from_slice(&syn[offset..offset + 2]);
    bytes[24..28].copy_from_slice(&42_u32.to_be_bytes());
    let sequence = u32::from_be_bytes(syn[offset + 4..offset + 8].try_into().unwrap());
    bytes[28..32].copy_from_slice(&sequence.wrapping_add(1).to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x12;
    bytes[34..36].copy_from_slice(&u16::MAX.to_be_bytes());
    let ip_sum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let mut pseudo = bytes[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&bytes[20..]);
    let tcp_sum = checksum(&pseudo);
    bytes[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    Packet::new(bytes)
}
fn connect(tcp: TcpConnector) -> BoxFuture<'static, std::io::Result<TcpStream>> {
    Box::pin(async move {
        tcp.connect(
            "10.0.0.1:443".parse().unwrap(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
    })
}
async fn until(mut predicate: impl FnMut() -> bool) {
    // Predicate is the phase barrier. This finite harness guard prevents a
    // paused-time regression from auto-advancing or hanging on a bad fixture.
    for _ in 0..4096 {
        if predicate() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("real queue phase did not become ready");
}

async fn stop(control: &vole_netstack::NetStackControl) {
    tokio::time::timeout(Duration::from_secs(1), control.stop())
        .await
        .expect("real stack Stop did not join");
    assert!(control.is_stopped());
}

struct WirePeer {
    server: Tunn,
    endpoint: SocketAddr,
    incoming: VecDeque<Datagram>,
    sent: Arc<AtomicUsize>,
    received: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl DatagramTransport for WirePeer {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1440, 1440)
    }
    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        assert_eq!(datagram.remote, Destination::Ip(self.endpoint));
        let mut scratch = vec![0; 1440];
        match self
            .server
            .decapsulate(None, &datagram.payload, &mut scratch)
        {
            TunnResult::Done
            | TunnResult::WriteToTunnelV4(..)
            | TunnResult::WriteToTunnelV6(..) => {}
            _ => panic!("TX must reach the same authenticated Noise peer"),
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.received.fetch_add(1, Ordering::Relaxed);
        match self.incoming.pop_front() {
            Some(datagram) => Ok(datagram),
            None => std::future::pending().await,
        }
    }
}
struct Saturated {
    driver: Driver,
    client: Tunn,
    transport: Box<dyn DatagramTransport>,
    state: PeerState,
    packets: mpsc::Receiver<Packet>,
    commands: mpsc::Receiver<Refresh>,
    _command_owner: mpsc::Sender<Refresh>,
    pump: Pin<Box<dyn Future<Output = ()> + Send>>,
    connects: Vec<BoxFuture<'static, std::io::Result<TcpStream>>>,
    control: vole_netstack::NetStackControl,
    cancel: CancellationToken,
    sent: Arc<AtomicUsize>,
    received: Arc<AtomicUsize>,
    probe: Arc<Mutex<PendingMemoryCounts>>,
    _udp_slot: Arc<super::super::datagram::Slot>,
    udp: mpsc::Receiver<Datagram>,
}
async fn saturated() -> Saturated {
    let config = Arc::new(super::super::tests::config());
    let routes = Arc::new(Routes::new(&config));
    let ClientNetStackParts {
        packet_sink,
        mut packet_stream,
        tcp_connector,
        control,
        stats,
    } = NetStack::start_client(
        NetStackConfig {
            mtu: 1408,
            packet_queue: 32,
            tcp_send_buffer: 64 * 1024,
            ..Default::default()
        },
        ClientAddresses {
            ipv4: config.ipv4,
            ipv6: None,
        },
    )
    .unwrap();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut connects = vec![connect(tcp_connector.clone())];
    assert!(connects[0].as_mut().poll(&mut cx).is_pending());
    let first_syn = tokio::time::timeout(Duration::from_secs(1), packet_stream.recv())
        .await
        .expect("real stack emitted no initial SYN")
        .unwrap();
    let ingress = syn_ack(&first_syn);
    for _ in 0..32 {
        let mut request = connect(tcp_connector.clone());
        assert!(request.as_mut().poll(&mut cx).is_pending());
        connects.push(request);
    }
    until(|| stats.snapshot().active_tcp == 33).await;

    let cancel = CancellationToken::new();
    let (channel, packets) = super::super::channel::Channel::memory_ready(cancel.child_token());
    let mut raw = Vec::new();
    encode_udp_packet_into(
        &UdpDatagram::new(
            "10.0.0.2:20000".parse().unwrap(),
            "10.0.0.1:53".parse().unwrap(),
            Bytes::from_static(b"tx"),
        ),
        1408,
        &mut raw,
    )
    .unwrap();
    for _ in 0..32 {
        channel.tx.try_send(Packet::new(raw.clone())).unwrap();
    }
    assert_eq!(channel.tx.capacity(), 0);
    let mut pump = Box::pin(super::super::engine::pending_memory_pump(
        packet_stream,
        channel.clone(),
        routes.clone(),
        cancel.clone(),
    ));
    assert!(pump.as_mut().poll(&mut cx).is_pending());
    // Replace the one output slot the blocked pump took, before priming RX.
    let mut request = connect(tcp_connector);
    assert!(request.as_mut().poll(&mut cx).is_pending());
    connects.push(request);
    until(|| stats.snapshot().active_tcp == 34).await;
    // One non-pure-ACK waits in RawIpDevice with TX full; the real raw queue
    // then admits exactly another 32. No fake receiver clears that queue.
    let mut accepted = 0;
    until(|| {
        while accepted < 33 {
            match packet_sink.try_send_recover(ingress.clone()) {
                Ok(()) => accepted += 1,
                Err((NetStackError::Backpressure, _)) => break,
                Err((error, _)) => panic!("unexpected fixture admission: {error}"),
            }
        }
        accepted == 33
    })
    .await;
    assert!(matches!(
        packet_sink.try_send_recover(ingress.clone()),
        Err((NetStackError::Backpressure, _))
    ));

    let (outbound, _, _) = super::super::tests::outbound(false);
    let registry = Arc::new(Registry::default());
    let (udp_slot, udp) = registry.memory_open(1200).unwrap();
    let probe = Arc::new(Mutex::new(PendingMemoryCounts::default()));
    let (ready, _) = watch::channel(Ready::Established);
    let driver = Driver {
        config,
        index: 0,
        upstream: outbound.upstream.clone(),
        session: DatagramSession::new(InboundKind::Tun, "192.0.2.1:20000".parse().unwrap()),
        cancel: channel.cancel.clone(),
        ready,
        sink: packet_sink,
        registry,
        routes,
        updated: Arc::new(Mutex::new(Instant::now())),
        pending_probe: Some(probe.clone()),
    };
    let (mut client, mut server) = noise_pair();
    let mut scratch = vec![0; 1440];
    let encrypted = network(server.encapsulate(ingress.data(), &mut scratch));
    let decoded = client.decapsulate(None, &encrypted, &mut scratch);
    assert!(matches!(&decoded, TunnResult::WriteToTunnelV4(..)));
    let context = EstablishContext::with_timeout(Duration::from_secs(10));
    let mut state = PeerState::new(context.deadline(), None);
    state.established = true;
    // Consume the pre-existing immediate initial tick before the staged Full;
    // production creates this same interval only after its initial send.
    state.timer.tick().await;
    let endpoint = "198.51.100.1:51820".parse().unwrap();
    let sent = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(AtomicUsize::new(0));
    let mut udp_raw = Vec::new();
    encode_udp_packet_into(
        &UdpDatagram::new(
            "10.0.0.1:53".parse().unwrap(),
            SocketAddr::new("10.0.0.2".parse().unwrap(), udp_slot.port),
            Bytes::from_static(b"udp-after-pending"),
        ),
        1408,
        &mut udp_raw,
    )
    .unwrap();
    let encrypted_udp = network(server.encapsulate(&udp_raw, &mut vec![0; 1440]));
    let mut transport: Box<dyn DatagramTransport> = Box::new(WirePeer {
        server,
        endpoint,
        incoming: VecDeque::from([Datagram {
            remote: Destination::Ip(endpoint),
            payload: Bytes::from(encrypted_udp),
            sniffed_domain: None,
        }]),
        sent: sent.clone(),
        received: received.clone(),
    });
    let mut handoff = Box::pin(driver.handle(
        decoded,
        endpoint,
        transport.as_mut(),
        context.deadline(),
        &mut state.ingress,
    ));
    assert!(
        matches!(handoff.as_mut().poll(&mut cx), Poll::Ready(Ok(()))),
        "Full handoff must not await stack capacity"
    );
    drop(handoff);
    assert!(state.ingress.is_some());
    assert_eq!(probe.lock().unwrap().created, 1);
    let (command_owner, commands) = mpsc::channel(1);
    Saturated {
        driver,
        client,
        transport,
        state,
        packets,
        commands,
        _command_owner: command_owner,
        pump,
        connects,
        control,
        cancel,
        sent,
        received,
        probe,
        _udp_slot: udp_slot,
        udp,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pending_ingress_real_noise_cycle_keeps_tx_progress_and_admits_once() {
    let Saturated {
        driver,
        mut client,
        mut transport,
        state,
        mut packets,
        mut commands,
        _command_owner,
        mut pump,
        connects,
        control,
        cancel,
        sent,
        received,
        probe,
        _udp_slot,
        mut udp,
    } = saturated().await;
    let mut scratch = vec![0; 1440];
    let mut normalization = vec![0; 1440];
    let mut worker = Box::pin(run_peer(
        &driver,
        &mut client,
        "198.51.100.1:51820".parse().unwrap(),
        &mut transport,
        state,
        &mut packets,
        &mut commands,
        &mut scratch,
        &mut normalization,
    ));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(worker.as_mut().poll(&mut cx).is_pending());
    assert!(
        sent.load(Ordering::Relaxed) > 0,
        "real peer TX must run while ingress is still Full"
    );
    assert_eq!(probe.lock().unwrap().current, 1);
    assert_eq!(probe.lock().unwrap().admitted, 0);
    assert_eq!(
        received.load(Ordering::Relaxed),
        0,
        "outer RX is paused, not dropped or falsely delivered"
    );
    let mut resumed = None;
    until(|| {
        assert!(pump.as_mut().poll(&mut cx).is_pending());
        assert!(worker.as_mut().poll(&mut cx).is_pending());
        if resumed.is_none() {
            resumed = udp.try_recv().ok();
        }
        probe.lock().unwrap().admitted == 1 && resumed.is_some()
    })
    .await;
    assert_eq!(probe.lock().unwrap().peak, 1);
    assert_eq!(probe.lock().unwrap().current, 0);
    assert_eq!(resumed.unwrap().payload.as_ref(), b"udp-after-pending");
    cancel.cancel();
    assert!(worker.as_mut().poll(&mut cx).is_ready());
    drop(worker);
    assert!(pump.as_mut().poll(&mut cx).is_ready());
    drop(pump);
    drop(connects);
    stop(&control).await;
    assert_eq!(probe.lock().unwrap().admitted, 1);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pending_ingress_original_timer_fallback_resumes_udp_and_stop_releases() {
    let Saturated {
        driver,
        mut client,
        mut transport,
        state,
        mut packets,
        mut commands,
        _command_owner,
        pump,
        connects,
        control,
        cancel,
        sent: _,
        received,
        probe,
        _udp_slot,
        mut udp,
    } = saturated().await;
    let mut scratch = vec![0; 1440];
    let mut normalization = vec![0; 1440];
    let mut worker = Box::pin(run_peer(
        &driver,
        &mut client,
        "198.51.100.1:51820".parse().unwrap(),
        &mut transport,
        state,
        &mut packets,
        &mut commands,
        &mut scratch,
        &mut normalization,
    ));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(worker.as_mut().poll(&mut cx).is_pending());
    assert_eq!(probe.lock().unwrap().current, 1);
    assert_eq!(received.load(Ordering::Relaxed), 0);
    // Leave the real pump parked: TX stays full and raw RX cannot drain.
    tokio::time::advance(Duration::from_millis(250)).await;
    let mut resumed = None;
    until(|| {
        assert!(worker.as_mut().poll(&mut cx).is_pending());
        if resumed.is_none() {
            resumed = udp.try_recv().ok();
        }
        probe.lock().unwrap().timer == 1 && resumed.is_some()
    })
    .await;
    assert_eq!(probe.lock().unwrap().current, 0);
    assert_eq!(probe.lock().unwrap().admitted, 0);
    assert_eq!(resumed.unwrap().payload.as_ref(), b"udp-after-pending");
    cancel.cancel();
    assert!(worker.as_mut().poll(&mut cx).is_ready());
    drop(worker);
    drop(pump);
    drop(connects);
    stop(&control).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pending_ingress_cancel_ready_precedes_tx_and_discards_owned_waiter() {
    let Saturated {
        driver,
        mut client,
        mut transport,
        state,
        mut packets,
        mut commands,
        _command_owner,
        pump,
        connects,
        control,
        cancel,
        sent,
        received,
        probe,
        _udp_slot,
        udp: _,
    } = saturated().await;
    let mut scratch = vec![0; 1440];
    let mut normalization = vec![0; 1440];
    let mut worker = Box::pin(run_peer(
        &driver,
        &mut client,
        "198.51.100.1:51820".parse().unwrap(),
        &mut transport,
        state,
        &mut packets,
        &mut commands,
        &mut scratch,
        &mut normalization,
    ));
    cancel.cancel();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(worker.as_mut().poll(&mut cx).is_ready());
    drop(worker);
    assert_eq!(sent.load(Ordering::Relaxed), 0);
    assert_eq!(received.load(Ordering::Relaxed), 0);
    assert_eq!(probe.lock().unwrap().current, 0);
    assert_eq!(probe.lock().unwrap().abandoned, 1);
    drop(pump);
    drop(connects);
    stop(&control).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pending_ingress_same_endpoint_refresh_keeps_original_waiter() {
    let Saturated {
        driver,
        mut client,
        mut transport,
        state,
        mut packets,
        mut commands,
        _command_owner: command_owner,
        pump,
        connects,
        control,
        cancel,
        sent: _,
        received,
        probe,
        _udp_slot,
        udp: _,
    } = saturated().await;
    let (reply, mut done) = tokio::sync::oneshot::channel();
    command_owner
        .try_send(Refresh {
            context: EstablishContext::with_timeout(Duration::from_secs(10)),
            reply,
        })
        .unwrap();
    let mut scratch = vec![0; 1440];
    let mut normalization = vec![0; 1440];
    let mut worker = Box::pin(run_peer(
        &driver,
        &mut client,
        "198.51.100.1:51820".parse().unwrap(),
        &mut transport,
        state,
        &mut packets,
        &mut commands,
        &mut scratch,
        &mut normalization,
    ));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    until(|| {
        assert!(worker.as_mut().poll(&mut cx).is_pending());
        done.try_recv().is_ok()
    })
    .await;
    assert_eq!(probe.lock().unwrap().current, 1);
    assert_eq!(probe.lock().unwrap().refresh, 0);
    assert_eq!(received.load(Ordering::Relaxed), 0);
    cancel.cancel();
    assert!(worker.as_mut().poll(&mut cx).is_ready());
    drop(worker);
    assert_eq!(probe.lock().unwrap().current, 0);
    assert_eq!(probe.lock().unwrap().abandoned, 1);
    drop(pump);
    drop(connects);
    stop(&control).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pending_ingress_full_packet_above_configured_mtu_keeps_old_drop_policy() {
    let Saturated {
        driver,
        client: _,
        mut transport,
        state,
        packets: _,
        commands: _,
        _command_owner,
        pump,
        connects,
        control,
        cancel,
        sent: _,
        received: _,
        probe,
        _udp_slot,
        udp: _,
    } = saturated().await;
    let mut oversized = vec![0; usize::from(driver.config.mtu) + 1];
    oversized[0] = 0x45;
    oversized[12..16].copy_from_slice(&[10, 0, 0, 1]);
    oversized[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let mut other = None;
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut handoff = Box::pin(driver.handle(
        TunnResult::WriteToTunnelV4(&mut oversized, "10.0.0.1".parse().unwrap()),
        "198.51.100.1:51820".parse().unwrap(),
        transport.as_mut(),
        Instant::now() + Duration::from_secs(10),
        &mut other,
    ));
    assert!(matches!(
        handoff.as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    drop(handoff);
    assert!(other.is_none());
    assert_eq!(probe.lock().unwrap().created, 1);
    // Actual replacement uses this same cleanup before transport swap. The
    // literal no-op path is exercised separately through the real command.
    let mut state = state;
    state.discard_for_refresh();
    assert_eq!(probe.lock().unwrap().current, 0);
    assert_eq!(probe.lock().unwrap().refresh, 1);
    cancel.cancel();
    drop(state);
    drop(pump);
    drop(connects);
    stop(&control).await;
}

// Established authenticated data; legacy send must finish before semantic RED.
#[cfg(target_vendor = "apple")]
mod ready_data_batch_memory_tests {
    use super::*;
    use crate::resources::observation::ResourceProbe;

    struct PhysicalState {
        server: Tunn,
        emitted: Vec<u8>,
        singles: usize,
        batches: usize,
        active: usize,
        peak: usize,
        close_active: usize,
        closes: usize,
        invalid: usize,
    }
    impl PhysicalState {
        fn emit(&mut self, packet: Datagram, endpoint: SocketAddr) -> Result<(), DispatchError> {
            if packet.remote != Destination::Ip(endpoint) {
                self.invalid += 1;
                return Err(DispatchError::NotAllowed);
            }
            let mut scratch = [0_u8; 1440];
            let result = self.server.decapsulate(None, &packet.payload, &mut scratch);
            let raw = match result {
                TunnResult::WriteToTunnelV4(raw, _) => raw,
                _ => {
                    self.invalid += 1;
                    return Err(DispatchError::NotAllowed);
                }
            };
            let Some(udp) = parse_udp_packet_view(raw) else {
                self.invalid += 1;
                return Err(DispatchError::NotAllowed);
            };
            if udp.payload.len() != 1 {
                self.invalid += 1;
                return Err(DispatchError::NotAllowed);
            }
            self.emitted.push(udp.payload[0]);
            Ok(())
        }
    }
    struct SendLease(Arc<Mutex<PhysicalState>>);
    impl Drop for SendLease {
        fn drop(&mut self) {
            self.0.lock().unwrap().active -= 1;
        }
    }
    struct Physical {
        shared: Arc<Mutex<PhysicalState>>,
        endpoint: SocketAddr,
    }
    #[async_trait::async_trait]
    impl DatagramTransport for Physical {
        fn supports_shared_destinations(&self) -> bool {
            false
        }
        fn payload_budget(&self, _: &Destination) -> DatagramBudget {
            DatagramBudget::new(1440, 1440)
        }
        fn send_batch_owned(
            &mut self,
            packets: Vec<Datagram>,
        ) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
            if packets.len() < 2
                || packets.len() > crate::dispatch::DATAGRAM_SEND_BATCH_LIMIT
                || packets.iter().map(|p| p.payload.len()).sum::<usize>()
                    > crate::dispatch::DATAGRAM_SEND_BATCH_BYTES
            {
                return Err(packets);
            }
            let shared = self.shared.clone();
            {
                let mut state = shared.lock().unwrap();
                state.active += 1;
                state.peak = state.peak.max(state.active);
            }
            let lease = SendLease(shared.clone());
            let endpoint = self.endpoint;
            Ok(Box::pin(async move {
                let _lease = lease;
                let count = packets.len();
                let mut state = shared.lock().unwrap();
                state.batches += 1;
                for packet in packets {
                    state.emit(packet, endpoint).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "memory Noise packet")
                    })?;
                }
                Ok(count)
            }))
        }
        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            let mut state = self.shared.lock().unwrap();
            state.singles += 1;
            // Required old path: authenticate and deliver, never panic for not batching.
            state.emit(packet, self.endpoint)
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            let mut state = self.shared.lock().unwrap();
            state.close_active = state.active;
            state.closes += 1;
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wireguard_memory_ready_data_uses_authenticated_batch_after_stop() {
        let probe = ResourceProbe::default();
        let observed = probe
            .scope(async {
                let config = Arc::new(super::super::super::tests::config());
                let routes = Arc::new(Routes::new(&config));
                let ClientNetStackParts {
                    packet_sink,
                    packet_stream,
                    control,
                    ..
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
                let cancel = CancellationToken::new();
                let (packets_tx, mut packets) = mpsc::channel(32);
                let (commands_tx, mut commands) = mpsc::channel(1);
                let (ready, _ready_rx) = watch::channel(Ready::Established);
                let (outbound, _, _) = super::super::super::tests::outbound(false);
                let driver = Driver {
                    config,
                    index: 0,
                    upstream: outbound.upstream.clone(),
                    session: DatagramSession::new(
                        InboundKind::Tun,
                        "192.0.2.1:20000".parse().unwrap(),
                    ),
                    cancel: cancel.clone(),
                    ready,
                    sink: packet_sink,
                    registry: Arc::new(Registry::default()),
                    routes,
                    updated: Arc::new(Mutex::new(Instant::now())),
                    pending_probe: None,
                };
                let (mut client, server) = noise_pair();
                let shared = Arc::new(Mutex::new(PhysicalState {
                    server,
                    emitted: Vec::new(),
                    singles: 0,
                    batches: 0,
                    active: 0,
                    peak: 0,
                    close_active: 0,
                    closes: 0,
                    invalid: 0,
                }));
                let endpoint = "198.51.100.1:51820".parse().unwrap();
                let mut transport: Box<dyn DatagramTransport> = Box::new(Physical {
                    shared: shared.clone(),
                    endpoint,
                });
                // The four raw data packets are already ready, not supplied by a fill timer.
                for sequence in 0_u8..4 {
                    let mut raw = Vec::new();
                    encode_udp_packet_into(
                        &UdpDatagram::new(
                            "10.0.0.2:20000".parse().unwrap(),
                            "10.0.0.1:53".parse().unwrap(),
                            Bytes::copy_from_slice(&[sequence]),
                        ),
                        1408,
                        &mut raw,
                    )
                    .unwrap();
                    packets_tx.try_send(Packet::new(raw)).unwrap();
                }
                let mut state = PeerState::new(Instant::now() + Duration::from_secs(10), None);
                state.established = true; // Both real Noise endpoints completed noise_pair().
                state.timer.tick().await;
                let mut scratch = [0_u8; 1440];
                let mut normalization = [0_u8; 1440];
                let mut worker = Box::pin(run_peer(
                    &driver,
                    &mut client,
                    endpoint,
                    &mut transport,
                    state,
                    &mut packets,
                    &mut commands,
                    &mut scratch,
                    &mut normalization,
                ));
                let waker = noop_waker();
                let mut cx = Context::from_waker(&waker);
                let mut ended = false;
                for _ in 0..64 {
                    if worker.as_mut().poll(&mut cx).is_ready() {
                        ended = true;
                        break;
                    }
                    if shared.lock().unwrap().emitted.len() == 4 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                cancel.cancel();
                let cancelled = ended || worker.as_mut().poll(&mut cx).is_ready();
                drop(worker); // Drop all owned sends before physical close.
                let close_ok = transport.close().await.is_ok();
                drop(transport);
                drop(driver);
                drop(packets_tx);
                drop(commands_tx);
                drop(packet_stream);
                drop(outbound);
                stop(&control).await;
                let state = shared.lock().unwrap();
                (
                    state.emitted.clone(),
                    state.singles,
                    state.batches,
                    state.active,
                    state.peak,
                    state.close_active,
                    state.closes,
                    state.invalid,
                    cancelled,
                    close_ok,
                )
            })
            .await;
        // All semantic assertions follow cancellation, physical close and real stack Stop/join.
        assert!(probe.snapshot().is_idle());
        assert!(observed.8 && observed.9);
        assert_eq!(
            (observed.3, observed.5, observed.6, observed.7),
            (0, 0, 1, 0)
        );
        assert_eq!(
            observed.0,
            [0, 1, 2, 3],
            "real authenticated data must arrive once in FIFO order"
        );
        assert!(observed.4 <= 1, "at most one physical send owner");
        assert!(
            observed.2 > 0,
            "already-ready established data never used the existing batch path"
        );
        assert_eq!(
            observed.1, 0,
            "a fully confirmed ready batch needs no ordinary retransmission"
        );
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ControlCase {
        Short,
        Unsupported,
        ErrorAfterPrefix,
        Cancel,
        Deadline,
        HighMtu,
        Control,
        Single,
    }
    #[derive(Default)]
    struct ControlFacts {
        attempts: usize,
        submitted: Vec<(u64, usize)>,
        ordinary: Vec<(u64, usize)>,
        submitted_bytes: Vec<Vec<u8>>,
        ordinary_bytes: Vec<Vec<u8>>,
        controls: usize,
    }
    struct Controlled {
        physical: Physical,
        case: ControlCase,
        facts: Arc<Mutex<ControlFacts>>,
    }
    fn wire_id(packet: &Datagram) -> (u64, usize) {
        let counter = packet
            .payload
            .get(8..16)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(u64::MAX);
        (counter, packet.payload.as_ptr() as usize)
    }
    #[async_trait::async_trait]
    impl DatagramTransport for Controlled {
        fn supports_shared_destinations(&self) -> bool {
            false
        }
        fn payload_budget(&self, _: &Destination) -> DatagramBudget {
            DatagramBudget::new(4096, 4096)
        }
        fn send_batch_owned(
            &mut self,
            packets: Vec<Datagram>,
        ) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
            self.facts.lock().unwrap().attempts += 1;
            if self.case == ControlCase::Unsupported {
                return Err(packets);
            }
            let shared = self.physical.shared.clone();
            {
                let mut state = shared.lock().unwrap();
                state.active += 1;
                state.peak = state.peak.max(state.active);
            }
            let lease = SendLease(shared.clone());
            let facts = self.facts.clone();
            let endpoint = self.physical.endpoint;
            let case = self.case;
            Ok(Box::pin(async move {
                let _lease = lease;
                if !(2..=crate::dispatch::DATAGRAM_SEND_BATCH_LIMIT).contains(&packets.len())
                    || packets.iter().map(|p| p.payload.len()).sum::<usize>()
                        > crate::dispatch::DATAGRAM_SEND_BATCH_BYTES
                {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                {
                    let mut recorded = facts.lock().unwrap();
                    if recorded.submitted.len() + packets.len() > 16 {
                        return Err(std::io::ErrorKind::InvalidData.into());
                    }
                    recorded.submitted.extend(packets.iter().map(wire_id));
                    recorded
                        .submitted_bytes
                        .extend(packets.iter().map(|p| p.payload.to_vec()));
                }
                shared.lock().unwrap().batches += 1;
                if matches!(case, ControlCase::Cancel | ControlCase::Deadline) {
                    std::future::pending::<()>().await;
                }
                let count = if matches!(case, ControlCase::Short | ControlCase::ErrorAfterPrefix) {
                    packets.len().min(2)
                } else {
                    packets.len()
                };
                let mut state = shared.lock().unwrap();
                for packet in packets.into_iter().take(count) {
                    state.emit(packet, endpoint).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "memory Noise packet")
                    })?;
                }
                if case == ControlCase::ErrorAfterPrefix {
                    // Physical acceptance happened, but no successful prefix is reported.
                    return Err(std::io::ErrorKind::Other.into());
                }
                Ok(count)
            }))
        }
        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            if packet.payload.first() != Some(&4) {
                let mut state = self.physical.shared.lock().unwrap();
                let mut scratch = [0_u8; 1440];
                let accepted = matches!(
                    state.server.decapsulate(None, &packet.payload, &mut scratch),
                    TunnResult::WriteToNetwork(reply) if reply.first() == Some(&2)
                );
                state.singles += 1;
                if !accepted {
                    state.invalid += 1;
                    return Err(DispatchError::NotAllowed);
                }
                self.facts.lock().unwrap().controls += 1;
                return Ok(());
            }
            {
                let mut facts = self.facts.lock().unwrap();
                if facts.ordinary.len() >= 16 {
                    return Err(DispatchError::NotAllowed);
                }
                facts.ordinary.push(wire_id(&packet));
                facts.ordinary_bytes.push(packet.payload.to_vec());
            }
            self.physical.send(packet).await
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.physical.close().await
        }
    }
    struct ControlResult {
        emitted: Vec<u8>,
        singles: usize,
        batches: usize,
        before_stop: usize,
        ended_before_cancel: bool,
        timed_out: bool,
        attempts: usize,
        submitted: Vec<(u64, usize)>,
        ordinary: Vec<(u64, usize)>,
        submitted_bytes: Vec<Vec<u8>>,
        ordinary_bytes: Vec<Vec<u8>>,
        controls: usize,
    }
    async fn controlled_case(case: ControlCase) -> ControlResult {
        let probe = ResourceProbe::default();
        let result = probe
            .scope(async {
                let mut raw_config = super::super::super::tests::config();
                if case == ControlCase::HighMtu {
                    raw_config.mtu = 2017;
                }
                let mtu = usize::from(raw_config.mtu);
                let config = Arc::new(raw_config);
                let routes = Arc::new(Routes::new(&config));
                let ClientNetStackParts {
                    packet_sink,
                    packet_stream,
                    control,
                    ..
                } = NetStack::start_client(
                    NetStackConfig {
                        mtu,
                        packet_queue: 32,
                        ..Default::default()
                    },
                    ClientAddresses {
                        ipv4: config.ipv4,
                        ipv6: None,
                    },
                )
                .unwrap();
                let cancel = CancellationToken::new();
                let (packets_tx, mut packets) = mpsc::channel(32);
                let (commands_tx, mut commands) = mpsc::channel(1);
                let (ready, _ready_rx) = watch::channel(Ready::Established);
                let (outbound, _, _) = super::super::super::tests::outbound(false);
                let driver = Driver {
                    config,
                    index: 0,
                    upstream: outbound.upstream.clone(),
                    session: DatagramSession::new(
                        InboundKind::Tun,
                        "192.0.2.1:20000".parse().unwrap(),
                    ),
                    cancel: cancel.clone(),
                    ready,
                    sink: packet_sink,
                    registry: Arc::new(Registry::default()),
                    routes,
                    updated: Arc::new(Mutex::new(Instant::now())),
                    pending_probe: None,
                };
                let (mut client, server) = noise_pair();
                let shared = Arc::new(Mutex::new(PhysicalState {
                    server,
                    emitted: Vec::new(),
                    singles: 0,
                    batches: 0,
                    active: 0,
                    peak: 0,
                    close_active: 0,
                    closes: 0,
                    invalid: 0,
                }));
                let facts = Arc::new(Mutex::new(ControlFacts::default()));
                let endpoint = "198.51.100.1:51820".parse().unwrap();
                let mut transport: Box<dyn DatagramTransport> = Box::new(Controlled {
                    physical: Physical {
                        shared: shared.clone(),
                        endpoint,
                    },
                    case,
                    facts: facts.clone(),
                });
                let count = if case == ControlCase::Single { 1 } else { 4 };
                let mut scratch = vec![0_u8; mtu + 32];
                let mut normalization = vec![0_u8; mtu + 32];
                let mut ended_before_cancel = false;
                let mut timed_out = false;
                let before_stop;
                let cancelled;
                if case == ControlCase::Control {
                    // Real authenticated peer accepts a forced Noise initiation.
                    // It is the existing direct control path, not a fake DATA tag.
                    let result = driver
                        .handle(
                            client.format_handshake_initiation(&mut scratch, true),
                            endpoint,
                            transport.as_mut(),
                            Instant::now() + DEFAULT_ESTABLISH_TIMEOUT,
                            &mut None,
                        )
                        .await;
                    ended_before_cancel = result.is_err();
                    before_stop = shared.lock().unwrap().active;
                    cancel.cancel();
                    cancelled = true;
                } else {
                    for sequence in 0_u8..count {
                        let mut raw = Vec::new();
                        encode_udp_packet_into(
                            &UdpDatagram::new(
                                "10.0.0.2:20000".parse().unwrap(),
                                "10.0.0.1:53".parse().unwrap(),
                                Bytes::copy_from_slice(&[sequence]),
                            ),
                            mtu,
                            &mut raw,
                        )
                        .unwrap();
                        packets_tx.try_send(Packet::new(raw)).unwrap();
                    }
                    let mut state = PeerState::new(Instant::now() + Duration::from_secs(10), None);
                    state.established = true;
                    state.timer.tick().await;
                    let mut worker = Box::pin(run_peer(
                        &driver,
                        &mut client,
                        endpoint,
                        &mut transport,
                        state,
                        &mut packets,
                        &mut commands,
                        &mut scratch,
                        &mut normalization,
                    ));
                    let waker = noop_waker();
                    let mut cx = Context::from_waker(&waker);
                    for _ in 0..64 {
                        if let Poll::Ready(result) = worker.as_mut().poll(&mut cx) {
                            ended_before_cancel = true;
                            timed_out = matches!(result, Err(DispatchError::TimedOut));
                            break;
                        }
                        let ready = {
                            let state = shared.lock().unwrap();
                            state.emitted.len() == usize::from(count)
                                || (matches!(case, ControlCase::Cancel | ControlCase::Deadline)
                                    && state.active == 1
                                    && state.batches > 0)
                        };
                        if ready {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    before_stop = shared.lock().unwrap().active;
                    if case == ControlCase::Deadline && !ended_before_cancel {
                        tokio::time::advance(DEFAULT_ESTABLISH_TIMEOUT + Duration::from_millis(1))
                            .await;
                        for _ in 0..64 {
                            if let Poll::Ready(result) = worker.as_mut().poll(&mut cx) {
                                ended_before_cancel = true;
                                timed_out = matches!(result, Err(DispatchError::TimedOut));
                                break;
                            }
                            tokio::task::yield_now().await;
                        }
                    }
                    cancel.cancel();
                    cancelled = ended_before_cancel || worker.as_mut().poll(&mut cx).is_ready();
                    drop(worker);
                }
                let close_ok = transport.close().await.is_ok();
                drop(transport);
                drop(driver);
                drop(packets_tx);
                drop(commands_tx);
                drop(packet_stream);
                drop(outbound);
                stop(&control).await;
                let state = shared.lock().unwrap();
                let facts = facts.lock().unwrap();
                let observed = ControlResult {
                    emitted: state.emitted.clone(),
                    singles: state.singles,
                    batches: state.batches,
                    before_stop,
                    ended_before_cancel,
                    timed_out,
                    attempts: facts.attempts,
                    submitted: facts.submitted.clone(),
                    ordinary: facts.ordinary.clone(),
                    submitted_bytes: facts.submitted_bytes.clone(),
                    ordinary_bytes: facts.ordinary_bytes.clone(),
                    controls: facts.controls,
                };
                (
                    observed,
                    (
                        state.active,
                        state.peak,
                        state.close_active,
                        state.closes,
                        state.invalid,
                    ),
                    cancelled,
                    close_ok,
                )
            })
            .await;
        // Every branch drops the actual operation, closes carrier and joins stack first.
        assert!(probe.snapshot().is_idle());
        assert!(result.2 && result.3);
        assert_eq!(
            (result.1.0, result.1.2, result.1.3, result.1.4),
            (0, 0, 1, 0)
        );
        assert!(result.1.1 <= 1);
        result.0
    }
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wireguard_memory_ready_batch_short_prefix_keeps_original_ciphertext_suffix() {
        let got = controlled_case(ControlCase::Short).await;
        assert_eq!(got.emitted, [0, 1, 2, 3]);
        assert_eq!((got.batches, got.singles), (1, 2));
        assert_eq!(got.submitted.len(), 4);
        assert_eq!(
            got.ordinary,
            got.submitted[2..],
            "unsent suffix was copied or re-encapsulated"
        );
        assert_eq!(
            got.ordinary_bytes,
            got.submitted_bytes[2..],
            "original ciphertext suffix bytes changed"
        );
    }
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wireguard_memory_ready_batch_unsupported_and_single_keep_ordinary_fifo() {
        let unsupported = controlled_case(ControlCase::Unsupported).await;
        let single = controlled_case(ControlCase::Single).await;
        assert_eq!(unsupported.emitted, [0, 1, 2, 3]);
        assert_eq!(
            (
                unsupported.attempts,
                unsupported.batches,
                unsupported.singles
            ),
            (1, 0, 4)
        );
        assert_eq!(single.emitted, [0]);
        assert_eq!((single.attempts, single.batches, single.singles), (0, 0, 1));
    }
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wireguard_memory_ready_batch_error_after_physical_prefix_never_replays() {
        let got = controlled_case(ControlCase::ErrorAfterPrefix).await;
        assert!(got.ended_before_cancel && !got.timed_out);
        assert_eq!(got.emitted, [0, 1]);
        assert_eq!((got.batches, got.singles, got.ordinary.len()), (1, 0, 0));
    }
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wireguard_memory_ready_batch_cancel_and_deadline_drop_owner_before_close() {
        let cancelled = controlled_case(ControlCase::Cancel).await;
        let deadline = controlled_case(ControlCase::Deadline).await;
        assert_eq!((cancelled.before_stop, deadline.before_stop), (1, 1));
        assert!(cancelled.emitted.is_empty() && deadline.emitted.is_empty());
        assert_eq!(
            (
                cancelled.batches,
                deadline.batches,
                cancelled.singles,
                deadline.singles
            ),
            (1, 1, 0, 0)
        );
        assert!(deadline.ended_before_cancel && deadline.timed_out);
    }
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wireguard_memory_ready_batch_large_mtu_and_control_are_never_batched() {
        let large = controlled_case(ControlCase::HighMtu).await;
        let control = controlled_case(ControlCase::Control).await;
        assert_eq!(large.emitted, [0, 1, 2, 3]);
        assert_eq!((large.attempts, large.batches, large.singles), (0, 0, 4));
        assert!(!control.ended_before_cancel && control.emitted.is_empty());
        assert_eq!(
            (
                control.attempts,
                control.batches,
                control.singles,
                control.controls
            ),
            (0, 0, 1, 1)
        );
    }
}

#[cfg(target_vendor = "apple")]
#[path = "ready_receive_memory_tests.rs"]
mod ready_receive_memory_tests;
